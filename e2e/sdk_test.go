//go:build e2e

package e2e

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The TypeScript and Java SDKs against the deployed server: the license
// journey's customer app, one process per step (driver.mjs, Driver.java).
// "current" is a restart without the network: the saved lease alone. Then
// the offline journey's air-gapped machine with each SDK's OfflineClient.
// Needs sdk/ts built and sdk/java compiled (make e2e does both).
func TestSDKJourneys(t *testing.T) {
	e := loadEnv(t)
	b, tn := owner(t, e)
	api := "/api/v1/tenants/" + tn.Slug
	var keys []map[string]string
	for _, k := range trustedKeys(t, b, tn.Slug) {
		keys = append(keys, map[string]string{"kid": k.KID, "alg": k.Alg, "public_key": base64.RawURLEncoding.EncodeToString(k.Key)})
	}
	keySet, _ := json.Marshal(keys) // the dashboard's key set JSON
	for _, k := range keys {        // the same kids, other keys
		other, _, _ := ed25519.GenerateKey(nil)
		k["public_key"] = base64.RawURLEncoding.EncodeToString(other)
	}
	wrongKeys, _ := json.Marshal(keys)

	kubeRun := strings.ToLower(rand.Text()[:8])
	kubeNames := map[string]string{}
	var configMaps, secrets []string
	for _, n := range []string{"typescript", "java"} {
		kubeNames[n+"-configmap"] = "e2e-lease-" + n + "-" + kubeRun
		kubeNames[n+"-secret"] = "e2e-lease-" + n + "-" + kubeRun
		configMaps = append(configMaps, kubeNames[n+"-configmap"])
		secrets = append(secrets, kubeNames[n+"-secret"])
	}
	missing := "e2e-lease-missing-" + kubeRun // in the Role, never created
	kubeEnv := kubeLeaseStores(t, e, kubeRun, configMaps, secrets, []string{missing})

	for _, sdk := range []struct {
		name, version string // version: the sdk_version prefix
		cmd           func(t *testing.T) []string
	}{
		{"typescript", "ts", func(*testing.T) []string { return []string{"node", "--import", "./sdk/nip.mjs", "sdk/driver.mjs"} }},
		{"java", "java", func(t *testing.T) []string {
			// The JVM trusts the environment's CA through its trust store, as a
			// vendor's app would be set up for a private CA.
			store := filepath.Join(t.TempDir(), "ca.p12")
			if out, err := exec.Command("keytool", "-importcert", "-noprompt", "-alias", "e2e", "-file", e.CAFile, "-keystore", store, "-storetype", "PKCS12", "-storepass", "e2e-pass").CombinedOutput(); err != nil {
				t.Fatalf("keytool: %v\n%s", err, out)
			}
			java := []string{"java"}
			// <ip>.nip.io resolves without DNS, as in the Go journeys (nip.mjs).
			if host := mustURL(t, e.BaseURL).Hostname(); nipIP.MatchString(host) {
				hosts := filepath.Join(t.TempDir(), "hosts")
				if err := os.WriteFile(hosts, []byte(nipIP.FindStringSubmatch(host)[1]+" "+host+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				java = append(java, "-Djdk.net.hosts.file="+hosts)
			}
			return append(java, "-Djavax.net.ssl.trustStore="+store, "-Djavax.net.ssl.trustStorePassword=e2e-pass", "-cp", "../sdk/java/target/classes", "sdk/Driver.java")
		}},
	} {
		t.Run(sdk.name, func(t *testing.T) {
			cmd := sdk.cmd(t)
			product, lic, run := newLicense(t, b, tn, nil)
			dir := t.TempDir()
			type result struct {
				OK                         bool
				Code, Lid, Tenant, Product string
				Plan, Status, Detail, Text string
				Iat                        string
				HTTP                       int
				SSO, Nope, Forgot          bool
				Seats                      int64
				Warnings                   []string
			}
			// run is one step of machine's app on license l of product p; extra
			// is more environment (LF_FILE).
			run1 := func(p catalog, l issued, machine, op string, keys []byte, extra ...string) result {
				t.Helper()
				c := exec.Command(cmd[0], append(cmd[1:], op)...)
				c.Env = append(append(os.Environ(),
					"LF_BASE_URL="+e.BaseURL, "LF_TENANT_ID="+tn.ID, "LF_PRODUCT="+p.Slug, "LF_LICENSE_KEY="+l.Key,
					"LF_KEYS="+string(keys), "LF_MACHINE="+machine, "LF_STORE="+filepath.Join(dir, machine+".lease"),
					"NODE_EXTRA_CA_CERTS="+e.CAFile), extra...)
				out, err := c.Output()
				var r result
				if err != nil || json.Unmarshal(out, &r) != nil {
					stderr := ""
					if x, ok := err.(*exec.ExitError); ok {
						stderr = string(x.Stderr)
					}
					t.Fatalf("%s %s: %v\n%s%s", machine, op, err, out, stderr)
				}
				// A store that failed or a stored lease that didn't verify is
				// only a warning to the app: none is expected with the right keys.
				if len(r.Warnings) > 0 && string(keys) == string(keySet) && !slices.Contains(extra, "LF_EXPECT_WARNINGS=1") {
					t.Fatalf("%s %s: warnings %q", machine, op, r.Warnings)
				}
				return r
			}
			step := func(machine, op string, keys []byte) result { t.Helper(); return run1(product, lic, machine, op, keys) }
			ok := func(machine, op string) result {
				t.Helper()
				r := step(machine, op, keySet)
				if !r.OK {
					t.Fatalf("%s %s: %s (%s)", machine, op, r.Code, r.Detail)
				}
				return r
			}
			// http is the server's status (run() forgets the lease on 403
			// license_revoked and 404 not_activated only); 0 for the SDK's own
			// refusals, which aren't checked.
			refusedWith := func(keys []byte, machine, op, code string, http int) {
				t.Helper()
				if r := step(machine, op, keys); r.OK || r.Code != code || (http != 0 && r.HTTP != http) {
					t.Fatalf("%s %s: %+v, want %s (HTTP %d)", machine, op, r, code, http)
				}
			}
			refused := func(machine, op, code string, http int) { t.Helper(); refusedWith(keySet, machine, op, code, http) }
			m1, m2 := "e2e-"+sdk.name+"-1-"+run, "e2e-"+sdk.name+"-2-"+run

			r := ok(m1, "activate")
			if r.Lid != lic.ID || r.Tenant != tn.ID || r.Product != product.Slug || r.Plan != "pro" || r.Status != "valid" || !r.SSO || r.Nope || r.Seats != 25 {
				t.Errorf("lease claims %+v", r)
			}
			if c := ok(m1, "current"); fmt.Sprint(c) != fmt.Sprint(r) {
				t.Errorf("after a restart: %+v, want %+v", c, r)
			}
			refused(m2, "activate", "activation_limit_reached", 409) // one seat
			refused(m2, "current", "no_lease", 0)
			ok(m1, "refresh")
			// A lease the trusted keys don't verify is refused, never used (the
			// stored one doesn't verify either: a warning).
			refusedWith(wrongKeys, m1, "refresh", "bad_lease", 0)

			// Suspension holds refreshes until the license is reinstated.
			b.do("POST", api+"/licenses/"+lic.ID+"/suspend", nil, 200, nil)
			refused(m1, "refresh", "license_suspended", 403)
			b.do("POST", api+"/licenses/"+lic.ID+"/reinstate", nil, 200, nil)
			ok(m1, "refresh")

			ok(m1, "deactivate")
			refused(m1, "refresh", "not_activated", 404)
			ok(m2, "activate") // the freed seat

			// The dashboard sees both machines as the SDK reported them.
			var acts struct {
				Items []struct {
					Hostname      string
					AppVersion    string  `json:"app_version"`
					SDKVersion    string  `json:"sdk_version"`
					DeactivatedAt *string `json:"deactivated_at"`
				}
			}
			b.do("GET", api+"/licenses/"+lic.ID+"/activations", nil, 200, &acts)
			seen := map[string]bool{}
			for _, a := range acts.Items {
				seen[a.Hostname] = a.DeactivatedAt == nil
				if a.AppVersion != "1.0.0" || !strings.HasPrefix(a.SDKVersion, sdk.version+"/") {
					t.Errorf("activation %+v", a)
				}
			}
			if len(acts.Items) != 2 || seen[m1] || !seen[m2] {
				t.Errorf("activations %+v", acts.Items)
			}

			b.do("POST", api+"/licenses/"+lic.ID+"/revoke", nil, 200, nil)
			refused(m2, "refresh", "license_revoked", 403)

			// run(), the background loop most apps use, on short leases so that
			// refresh_after (half the lease) comes soon; its scheduling is
			// unit-tested. A wrong license key stops it at refresh_after without
			// forgetting the lease; the next run, past refresh_after (it relies on
			// that order), renews at once, and is stopped 3 s later. The renewed
			// 20 s lease then outlives the restart step's JVM start by far.
			{
				rp, rl, _ := newLicense(t, b, tn, map[string]any{"lease_seconds": 20})
				mr := "e2e-" + sdk.name + "-run-renews-" + run
				first := run1(rp, rl, mr, "activate", keySet)
				if !first.OK {
					t.Fatalf("activate: %+v", first)
				}
				if r := run1(rp, issued{ID: rl.ID, Key: "LF-WRONG-WRONG-WRONG"}, mr, "run", keySet); r.OK || r.Code != "unauthenticated" || r.HTTP != 401 || r.Forgot {
					t.Errorf("run with a wrong key: %+v, want unauthenticated (401), the lease kept", r)
				}
				renewed := run1(rp, rl, mr, "run", keySet, "LF_RUN_MS=3000")
				if !renewed.OK || renewed.Iat <= first.Iat || renewed.Lid != rl.ID {
					t.Errorf("run for 3 s: %+v, want a lease issued after %s", renewed, first.Iat)
				}
				if r := run1(rp, rl, mr, "current", keySet); !r.OK || r.Iat != renewed.Iat {
					t.Errorf("after a restart: %+v, want the renewed lease (%s) from the store", r, renewed.Iat)
				}
			}
			// It stops, forgetting the lease, when the vendor revokes the
			// license, and when the vendor deactivates the machine from the dashboard.
			for _, c := range []struct {
				name, code string
				http       int
			}{{"revoked", "license_revoked", 403}, {"deactivated", "not_activated", 404}} {
				rp, rl, _ := newLicense(t, b, tn, map[string]any{"lease_seconds": 4})
				mr := "e2e-" + sdk.name + "-run-" + c.name + "-" + run
				if r := run1(rp, rl, mr, "activate", keySet); !r.OK {
					t.Fatalf("%s activate: %+v", c.name, r)
				}
				if c.name == "revoked" {
					b.do("POST", api+"/licenses/"+rl.ID+"/revoke", nil, 200, nil)
				} else {
					var acts struct{ Items []struct{ ID string } }
					b.do("GET", api+"/licenses/"+rl.ID+"/activations", nil, 200, &acts)
					if len(acts.Items) != 1 {
						t.Fatalf("activations %+v", acts.Items)
					}
					b.do("POST", api+"/licenses/"+rl.ID+"/activations/"+acts.Items[0].ID+"/deactivate", nil, 200, nil)
				}
				if r := run1(rp, rl, mr, "run", keySet); r.OK || r.Code != c.code || r.HTTP != c.http || !r.Forgot {
					t.Errorf("run after the license was %s: %+v, want %s and the lease forgotten", c.name, r, c.code)
				}
				if r := run1(rp, rl, mr, "current", keySet); r.OK || r.Code != "no_lease" {
					t.Errorf("after run stopped (%s): %+v, want no_lease (the stored lease was forgotten too)", c.name, r)
				}
			}

			// The Kubernetes lease stores against the cluster's real API server,
			// with only the RBAC the READMEs ask for (get and update on the named,
			// pre-created ConfigMap or Secret): the lease lands in the object, a
			// restart reads it from there, deactivate removes it; an object the
			// Role doesn't name can't be written (a warning, the lease still in use).
			for _, kind := range []string{"configmap", "secret"} {
				kp, kl, _ := newLicense(t, b, tn, map[string]any{"max_activations": 3}) // this machine and the two refused stores
				mk := "e2e-" + sdk.name + "-" + kind + "-" + run
				store := []string{"LF_K8S_STORE=" + kind, "LF_K8S_NAME=" + kubeNames[sdk.name+"-"+kind]}
				k8s := append(append([]string{}, kubeEnv...), store...)
				first := run1(kp, kl, mk, "activate", keySet, k8s...)
				if !first.OK || first.Lid != kl.ID {
					t.Fatalf("%s activate: %+v", kind, first)
				}
				if v := kubeValue(t, e, kind, kubeNames[sdk.name+"-"+kind], "lease"); !strings.Contains(v, "\nlf1.") { // the lease as the server armored it
					t.Errorf("%s holds %q, want the lease", kind, v)
				}
				if r := run1(kp, kl, mk, "current", keySet, k8s...); !r.OK || r.Iat != first.Iat {
					t.Errorf("%s: after a restart: %+v, want the stored lease", kind, r)
				}
				if r := run1(kp, kl, mk, "deactivate", keySet, k8s...); !r.OK {
					t.Fatalf("%s deactivate: %+v", kind, r)
				}
				if v := kubeValue(t, e, kind, kubeNames[sdk.name+"-"+kind], "lease"); v != "" {
					t.Errorf("%s still holds %q after deactivate", kind, v)
				}
				// Refused writes are warnings: the lease stays in use. An object the
				// Role doesn't name is refused at get; one it names but nobody
				// created, at create, which it can't grant by name: hence "create it
				// beforehand".
				for _, c := range []struct{ name, why string }{{"e2e-not-allowed-" + run, "cannot get"}, {missing, "cannot create"}} {
					denied := append(append([]string{}, kubeEnv...), "LF_K8S_STORE="+kind, "LF_K8S_NAME="+c.name, "LF_EXPECT_WARNINGS=1")
					r := run1(kp, kl, mk+"-"+c.why[7:], "activate", keySet, denied...)
					if w := strings.Join(r.Warnings, " "); !r.OK || r.Lid != kl.ID || !strings.Contains(w, "forbidden") || !strings.Contains(w, c.why) {
						t.Errorf("%s %s: %+v, want activated with a warning that the store %s", kind, c.name, r, c.why)
					}
				}
			}

			// Offline (ADR-0043): request, the vendor's answer, install, a
			// restart, a renewal and the older file, the receipt, the returned file.
			offProduct, ol, _ := newLicense(t, b, tn, map[string]any{"offline_allowed": true, "max_offline_seconds": 30 * 86400})
			mo := "e2e-" + sdk.name + "-offline-" + run
			off := func(op2 string, extra ...string) result {
				t.Helper()
				return run1(offProduct, ol, mo, op2, keySet, extra...)
			}
			offOK := func(op2 string, extra ...string) result {
				t.Helper()
				r := off(op2, extra...)
				if !r.OK {
					t.Fatalf("%s: %s (%s)", op2, r.Code, r.Detail)
				}
				return r
			}
			offRefused := func(code, op2 string, extra ...string) {
				t.Helper()
				if r := off(op2, extra...); r.OK || r.Code != code {
					t.Fatalf("%s: %+v, want %s", op2, r, code)
				}
			}
			answer := func(request string) (a struct {
				LicenseFile  string `json:"license_file"`
				ActivationID string `json:"activation_id"`
			}) {
				t.Helper()
				b.do("POST", api+"/activation-requests", map[string]string{"request": request}, 201, &a)
				return a
			}
			offRefused("no_license", "offline-current")
			first := answer(offOK("offline-request").Text)
			// The file is for this machine and these keys only.
			if r := run1(offProduct, ol, mo+"-other", "offline-install", keySet, "LF_FILE="+first.LicenseFile); r.OK || r.Code != "bad_file" {
				t.Errorf("another machine installing the file: %+v, want bad_file", r)
			}
			if r := run1(offProduct, ol, mo, "offline-install", wrongKeys, "LF_FILE="+first.LicenseFile); r.OK || r.Code != "bad_file" {
				t.Errorf("the file under other keys: %+v, want bad_file", r)
			}
			in := offOK("offline-install", "LF_FILE="+first.LicenseFile)
			if in.Lid != ol.ID || in.Tenant != tn.ID || in.Product != offProduct.Slug || in.Plan != "pro" || in.Status != "valid" || !in.SSO || in.Nope || in.Seats != 25 {
				t.Errorf("installed claims %+v", in)
			}
			if c := offOK("offline-current"); fmt.Sprint(c) != fmt.Sprint(in) {
				t.Errorf("after a restart: %+v, want %+v", c, in)
			}
			renewed := answer(offOK("offline-request").Text)
			if renewed.ActivationID != first.ActivationID {
				t.Errorf("the renewal took another seat: %s, want %s", renewed.ActivationID, first.ActivationID)
			}
			offOK("offline-install", "LF_FILE="+renewed.LicenseFile)
			offRefused("older_file", "offline-install", "LF_FILE="+first.LicenseFile)
			receipt := offOK("offline-deactivate").Text
			var act struct {
				ID, Mode, Hostname string
				AppVersion         string  `json:"app_version"`
				SDKVersion         string  `json:"sdk_version"`
				DeactivatedAt      *string `json:"deactivated_at"`
			}
			b.do("POST", api+"/deactivation-receipts", map[string]string{"receipt": receipt}, 200, &act)
			// The seat carries what the SDK's request said about the machine.
			if act.ID != first.ActivationID || act.Mode != "offline" || act.DeactivatedAt == nil || act.Hostname != mo || act.AppVersion != "1.0.0" || !strings.HasPrefix(act.SDKVersion, sdk.version+"/") {
				t.Errorf("returned seat %+v", act)
			}
			offRefused("no_license", "offline-current")
			offRefused("returned", "offline-install", "LF_FILE="+renewed.LicenseFile)
		})
	}
}
