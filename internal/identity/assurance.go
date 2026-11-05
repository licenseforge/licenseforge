package identity

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"licenseforge.io/licenseforge/internal/authz"
)

// AssurancePolicy maps the ID token's authentication claims to a session's
// assurance level (ADR-0038). A session is phishing-resistant if its amr
// contains one of PhishingResistantAMR, or its acr (or one of Entra's acrs)
// is in PhishingResistantACR; MFA likewise with the MFA sets (which include
// the phishing-resistant ones); otherwise none. Missing, malformed or
// unknown claims mean none: fail closed.
type AssurancePolicy struct {
	MFAAMR, PhishingResistantAMR []string
	MFAACR, PhishingResistantACR []string
	// StepUp*ACR are the acr_values a step-up login to that level asks for
	// (default none: max_age=0 only). Asking is not getting: the session's
	// level still comes from the returned claims.
	StepUpMFAACR, StepUpPhishingResistantACR []string
}

// StepUpACR is the acr_values a step-up to level asks for, if any.
func (p AssurancePolicy) StepUpACR(level authz.Assurance) []string {
	switch level {
	case authz.AssuranceMFA:
		return p.StepUpMFAACR
	case authz.AssurancePhishingResistant:
		return p.StepUpPhishingResistantACR
	}
	return nil
}

// DefaultAssurancePolicy is ADR-0038's default (RFC 8176 values): hwk, sc
// and pop are phishing-resistant; mfa, otp and swk are MFA. pwd, sms and
// tel never count. ACR values are IdP-specific, so none by default.
func DefaultAssurancePolicy() AssurancePolicy {
	return AssurancePolicy{
		PhishingResistantAMR: []string{"hwk", "sc", "pop"},
		MFAAMR:               []string{"mfa", "otp", "swk"},
	}
}

// never are amr values that never count as a factor of MFA (ADR-0038), even
// if configured, in any case.
var never = []string{"pwd", "sms", "tel"}

func isNever(v string) bool {
	return slices.ContainsFunc(never, func(n string) bool { return strings.EqualFold(n, v) })
}

// The environment variables of an AssurancePolicy (comma-separated values;
// unset or empty keeps the default set; "none" in an AMR variable disables
// amr counting for that level, e.g. on Entra, where only configured acrs
// values count).
const (
	EnvMFAAMR               = "LICENSEFORGE_OIDC_MFA_AMR"
	EnvPhishingResistantAMR = "LICENSEFORGE_OIDC_PHISHING_RESISTANT_AMR"
	EnvMFAACR               = "LICENSEFORGE_OIDC_MFA_ACR"
	EnvPhishingResistantACR = "LICENSEFORGE_OIDC_PHISHING_RESISTANT_ACR"

	EnvStepUpMFAACR               = "LICENSEFORGE_OIDC_STEP_UP_MFA_ACR"
	EnvStepUpPhishingResistantACR = "LICENSEFORGE_OIDC_STEP_UP_PHISHING_RESISTANT_ACR"
)

var (
	amrRE = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`) // RFC 8176 values and custom tokens
	acrRE = regexp.MustCompile(`^[!-~]{1,255}$`)          // printable ASCII, no spaces (URIs, LoA names, Entra c1…c99)
)

// AssurancePolicyFromEnv reads the policy from getenv (os.Getenv), refusing
// malformed values and amr values that never count (pwd, sms, tel).
func AssurancePolicyFromEnv(getenv func(string) string) (AssurancePolicy, error) {
	p := DefaultAssurancePolicy()
	for _, v := range []struct {
		env  string
		set  *[]string
		re   *regexp.Regexp
		isAM bool
	}{
		{EnvMFAAMR, &p.MFAAMR, amrRE, true}, {EnvPhishingResistantAMR, &p.PhishingResistantAMR, amrRE, true},
		{EnvMFAACR, &p.MFAACR, acrRE, false}, {EnvPhishingResistantACR, &p.PhishingResistantACR, acrRE, false},
		{EnvStepUpMFAACR, &p.StepUpMFAACR, acrRE, false}, {EnvStepUpPhishingResistantACR, &p.StepUpPhishingResistantACR, acrRE, false},
	} {
		raw := strings.TrimSpace(getenv(v.env))
		if raw == "" {
			continue
		}
		if v.isAM && raw == "none" {
			*v.set = []string{}
			continue
		}
		var vals []string
		for _, x := range strings.Split(raw, ",") {
			x = strings.TrimSpace(x)
			if !v.re.MatchString(x) {
				return AssurancePolicy{}, fmt.Errorf("%s: malformed value %q", v.env, x)
			}
			if v.isAM && x == "none" {
				return AssurancePolicy{}, fmt.Errorf("%s: none stands alone (it disables amr counting)", v.env)
			}
			if v.isAM && isNever(x) {
				return AssurancePolicy{}, fmt.Errorf("%s: %q never counts as MFA (ADR-0038)", v.env, x)
			}
			vals = append(vals, x)
		}
		*v.set = vals
	}
	return p, nil
}

// SessionAuth is how a login authenticated, stored with its session and in
// its audit entry: the level and the claims it came from (cleaned).
type SessionAuth struct {
	Assurance authz.Assurance
	AMR       []string
	ACR       string
	ACRs      []string
	AuthTime  *time.Time
}

// maxValues bounds the amr and acrs lists kept (and evaluated).
const maxValues = 16

// Assess computes c's session authentication under p. Values that don't
// look like amr/acr values are dropped, and only the first maxValues of a
// list are kept, so a hostile IdP response can't bloat the session row.
func (p AssurancePolicy) Assess(c Claims) SessionAuth {
	a := SessionAuth{AMR: keep(c.AMR, amrRE), ACRs: keep(c.ACRs, acrRE)}
	if acrRE.MatchString(c.ACR) {
		a.ACR = c.ACR
	}
	if !c.AuthTime.IsZero() {
		t := c.AuthTime.UTC()
		a.AuthTime = &t
	}
	acrs := append([]string{a.ACR}, a.ACRs...)
	hit := func(amrSet, acrSet []string) bool {
		for _, v := range a.AMR {
			if slices.Contains(amrSet, v) && !isNever(v) {
				return true
			}
		}
		for _, v := range acrs {
			if v != "" && slices.Contains(acrSet, v) {
				return true
			}
		}
		return false
	}
	switch {
	case hit(p.PhishingResistantAMR, p.PhishingResistantACR):
		a.Assurance = authz.AssurancePhishingResistant
	case hit(p.MFAAMR, p.MFAACR):
		a.Assurance = authz.AssuranceMFA
	default:
		a.Assurance = authz.AssuranceNone
	}
	return a
}

func keep(vals []string, re *regexp.Regexp) []string {
	var out []string
	for _, v := range vals {
		if len(out) == maxValues {
			break
		}
		if re.MatchString(v) && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}
