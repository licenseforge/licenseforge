package identity

import (
	"strings"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/authz"
)

func TestAssess(t *testing.T) {
	def := DefaultAssurancePolicy()
	okta := def
	okta.PhishingResistantACR = []string{"phr", "phrh"}
	okta.MFAACR = []string{"urn:okta:loa:2fa:any"}
	entra := def
	entra.PhishingResistantACR = []string{"c1"}
	none, mfa, pr := authz.AssuranceNone, authz.AssuranceMFA, authz.AssurancePhishingResistant
	for _, tc := range []struct {
		name string
		p    AssurancePolicy
		c    Claims
		want authz.Assurance
	}{
		{"no claims", def, Claims{}, none},
		{"password", def, Claims{AMR: []string{"pwd"}}, none},
		{"sms", def, Claims{AMR: []string{"pwd", "sms"}}, none},
		{"tel", def, Claims{AMR: []string{"pwd", "tel"}}, none},
		{"kba, fpt", def, Claims{AMR: []string{"kba", "fpt", "face"}}, none},
		{"mfa", def, Claims{AMR: []string{"pwd", "mfa"}}, mfa},
		{"otp", def, Claims{AMR: []string{"pwd", "otp"}}, mfa},
		{"swk", def, Claims{AMR: []string{"swk"}}, mfa},
		{"hwk", def, Claims{AMR: []string{"hwk"}}, pr},
		{"smart card", def, Claims{AMR: []string{"sc", "pin"}}, pr},
		{"pop", def, Claims{AMR: []string{"pop"}}, pr},
		{"case matters", def, Claims{AMR: []string{"HWK", "MFA"}}, none},
		{"acr ignored without config", def, Claims{ACR: "phr"}, none},
		{"okta phr", okta, Claims{AMR: []string{"pwd"}, ACR: "phr"}, pr},
		{"okta 2fa", okta, Claims{ACR: "urn:okta:loa:2fa:any"}, mfa},
		{"entra acrs", entra, Claims{AMR: []string{"pwd"}, ACRs: []string{"c2", "c1"}}, pr},
		{"entra other context", entra, Claims{ACRs: []string{"c2"}}, none},
		{"malformed amr dropped", def, Claims{AMR: []string{"hw k", strings.Repeat("h", 65), ""}}, none},
		{"beyond 16 values", def, Claims{AMR: append(make16("x"), "hwk")}, none},
		{"empty acr never matches an empty set entry", AssurancePolicy{MFAACR: []string{""}}, Claims{}, none},
		{"pwd, sms, tel never count, even if configured", AssurancePolicy{MFAAMR: []string{"pwd", "sms", "tel"}, PhishingResistantAMR: []string{"sms"}}, Claims{AMR: []string{"pwd", "sms", "tel"}}, none},
	} {
		if got := tc.p.Assess(tc.c).Assurance; got != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, got, tc.want)
		}
	}
	// What is kept: cleaned values, auth_time in UTC.
	at := time.Date(2026, 11, 5, 10, 0, 0, 0, time.FixedZone("x", 3600))
	a := def.Assess(Claims{AMR: []string{"pwd", "pwd", "bad value", "hwk"}, ACR: "a b", ACRs: []string{"c1"}, AuthTime: at})
	if strings.Join(a.AMR, ",") != "pwd,hwk" || a.ACR != "" || len(a.ACRs) != 1 || a.AuthTime == nil || !a.AuthTime.Equal(at) || a.AuthTime.Location() != time.UTC {
		t.Errorf("kept %+v", a)
	}
}

func make16(v string) []string {
	out := make([]string, 16)
	for i := range out {
		out[i] = v + string(rune('a'+i))
	}
	return out
}

func TestAssurancePolicyFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	p, err := AssurancePolicyFromEnv(env(nil))
	if err != nil || strings.Join(p.PhishingResistantAMR, ",") != "hwk,sc,pop" || strings.Join(p.MFAAMR, ",") != "mfa,otp,swk" {
		t.Fatalf("defaults %+v %v", p, err)
	}
	p, err = AssurancePolicyFromEnv(env(map[string]string{EnvPhishingResistantAMR: " hwk, swk ", EnvPhishingResistantACR: "phr,phrh", EnvMFAACR: "urn:okta:loa:2fa:any"}))
	if err != nil || strings.Join(p.PhishingResistantAMR, ",") != "hwk,swk" || len(p.PhishingResistantACR) != 2 || p.MFAACR[0] != "urn:okta:loa:2fa:any" {
		t.Fatalf("custom %+v %v", p, err)
	}
	for name, m := range map[string]map[string]string{
		"sms counted":    {EnvMFAAMR: "mfa,sms"},
		"pwd counted":    {EnvPhishingResistantAMR: "pwd"},
		"tel counted":    {EnvMFAAMR: "tel"},
		"empty entry":    {EnvMFAAMR: "mfa,,otp"},
		"space in acr":   {EnvMFAACR: "a b"},
		"control in amr": {EnvMFAAMR: "m\x01fa"},
		"too long amr":   {EnvMFAAMR: strings.Repeat("a", 65)},
		"non-ASCII acr":  {EnvPhishingResistantACR: "phré"},
	} {
		if _, err := AssurancePolicyFromEnv(env(m)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
