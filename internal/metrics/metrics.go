// Package metrics is the server's Prometheus instrumentation, served on its
// own listener (LICENSEFORGE_METRICS_ADDR), never on the public one.
//
// Label values come from fixed sets only: route patterns, status classes,
// outcomes, pool names. Never tenant IDs, user IDs, license keys or raw
// paths: they would leak data and make cardinality unbounded. High-volume
// events (activations, refreshes, unknown keys) are counted here instead of
// audited (ADR-0027, ADR-0034).
package metrics

import (
	"database/sql"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Registry is private: libraries registering into the global default
// registry don't end up on /metrics.
var Registry = prometheus.NewRegistry()

// Outcome is a counter's outcome label; only these values exist.
type Outcome string

const (
	Success Outcome = "success"
	Denied  Outcome = "denied"  // refused by policy (disabled user, revoked license, seat limit)
	Failure Outcome = "failure" // invalid input or an error
)

// OutcomeCounter counts events by Outcome.
type OutcomeCounter struct{ v *prometheus.CounterVec }

// Inc counts one event.
func (c OutcomeCounter) Inc(o Outcome) { c.v.WithLabelValues(string(o)).Inc() }

func outcomeCounter(name, help string) OutcomeCounter {
	v := prometheus.NewCounterVec(prometheus.CounterOpts{Name: name, Help: help}, []string{"outcome"})
	for _, o := range []Outcome{Success, Denied, Failure} {
		v.WithLabelValues(string(o)) // export zeros, so rate() works from the first event
	}
	Registry.MustRegister(v)
	return OutcomeCounter{v}
}

var (
	// Logins counts dashboard logins (weblogin callback).
	Logins = outcomeCounter("licenseforge_logins_total", "Dashboard logins by outcome.")
	// Activations, LeaseRefreshes and UnknownLicenseKeys are for the
	// activation API (ADR-0034); nothing calls them until it lands.
	Activations        = outcomeCounter("licenseforge_activations_total", "License activations by outcome.")
	LeaseRefreshes     = outcomeCounter("licenseforge_lease_refreshes_total", "Online lease refreshes by outcome.")
	UnknownLicenseKeys = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "licenseforge_unknown_license_keys_total", Help: "Requests with a license key that doesn't exist (not audited, ADR-0034).",
	})

	requests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "licenseforge_http_requests_total", Help: "HTTP requests by route pattern and status class.",
	}, []string{"route", "code"})
	duration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "licenseforge_http_request_duration_seconds", Help: "HTTP request duration by route pattern.",
		Buckets: prometheus.DefBuckets,
	}, []string{"route"})
)

func init() {
	Registry.MustRegister(UnknownLicenseKeys, requests, duration, poolCollector{},
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
}

// Handler serves the registry. Mount it on the metrics listener only.
func Handler() http.Handler { return promhttp.HandlerFor(Registry, promhttp.HandlerOpts{}) }

// Instrument counts requests to mux by the pattern that matched ("GET
// /healthz"), never the raw path; requests no pattern matched count as
// "unmatched".
func Instrument(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
		mux.ServeHTTP(sw, r) // sets r.Pattern
		route := r.Pattern
		if route == "" {
			route = "unmatched"
		}
		requests.WithLabelValues(route, strconv.Itoa(sw.code/100)+"xx").Inc()
		duration.WithLabelValues(route).Observe(time.Since(start).Seconds())
	})
}

type statusWriter struct {
	http.ResponseWriter
	code    int
	written bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.written && code >= 200 { // 1xx (e.g. 103 Early Hints) is not the final status
		w.code, w.written = code, true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	w.written = true
	return w.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach Flush and deadlines.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// SetPools sets where connection pool stats come from (store.DB.Stats),
// exported labelled by pool name. Replaces an earlier source.
func SetPools(stats func() map[string]sql.DBStats) { pools.Store(&stats) }

var pools atomic.Pointer[func() map[string]sql.DBStats]

type poolCollector struct{}

var (
	poolOpen    = prometheus.NewDesc("licenseforge_db_pool_open_connections", "Open connections.", []string{"pool"}, nil)
	poolInUse   = prometheus.NewDesc("licenseforge_db_pool_in_use_connections", "Connections in use.", []string{"pool"}, nil)
	poolIdle    = prometheus.NewDesc("licenseforge_db_pool_idle_connections", "Idle connections.", []string{"pool"}, nil)
	poolMax     = prometheus.NewDesc("licenseforge_db_pool_max_open_connections", "Maximum open connections (0: unlimited).", []string{"pool"}, nil)
	poolWaits   = prometheus.NewDesc("licenseforge_db_pool_waits_total", "Waits for a free connection.", []string{"pool"}, nil)
	poolWaitSec = prometheus.NewDesc("licenseforge_db_pool_wait_seconds_total", "Time spent waiting for a free connection.", []string{"pool"}, nil)
)

func (poolCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{poolOpen, poolInUse, poolIdle, poolMax, poolWaits, poolWaitSec} {
		ch <- d
	}
}

func (poolCollector) Collect(ch chan<- prometheus.Metric) {
	stats := pools.Load()
	if stats == nil {
		return
	}
	for name, s := range (*stats)() {
		ch <- prometheus.MustNewConstMetric(poolOpen, prometheus.GaugeValue, float64(s.OpenConnections), name)
		ch <- prometheus.MustNewConstMetric(poolInUse, prometheus.GaugeValue, float64(s.InUse), name)
		ch <- prometheus.MustNewConstMetric(poolIdle, prometheus.GaugeValue, float64(s.Idle), name)
		ch <- prometheus.MustNewConstMetric(poolMax, prometheus.GaugeValue, float64(s.MaxOpenConnections), name)
		ch <- prometheus.MustNewConstMetric(poolWaits, prometheus.CounterValue, float64(s.WaitCount), name)
		ch <- prometheus.MustNewConstMetric(poolWaitSec, prometheus.CounterValue, s.WaitDuration.Seconds(), name)
	}
}
