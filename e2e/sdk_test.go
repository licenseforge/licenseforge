//go:build e2e

package e2e

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The TypeScript and Java SDKs against the deployed server: the license
// journey's customer app, one process per step (driver.mjs, Driver.java).
// "current" is a restart without the network: the saved lease alone. Needs
// sdk/ts built and sdk/java compiled (make e2e does both).
func TestSDKJourneys(t *testing.T) {
	e := loadEnv(t)
	b, tn := owner(t, e)
	api := "/api/v1/tenants/" + tn.Slug
	var keys []map[string]string
	for _, k := range trustedKeys(t, b, tn.Slug) {
		keys = append(keys, map[string]string{"kid": k.KID, "alg": k.Alg, "public_key": base64.RawURLEncoding.EncodeToString(k.Key)})
	}
	keySet, _ := json.Marshal(keys) // the dashboard's key set JSON

	for _, sdk := range []struct {
		name string
		cmd  func(t *testing.T) []string
	}{
		{"typescript", func(*testing.T) []string { return []string{"node", "--import", "./sdk/nip.mjs", "sdk/driver.mjs"} }},
		{"java", func(t *testing.T) []string {
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
			product, lic, run := newLicense(t, b, tn)
			dir := t.TempDir()
			type result struct {
				OK                         bool
				Code, Lid, Tenant, Product string
				Plan, Status, Detail       string
				SSO                        bool
				Seats                      int64
			}
			step := func(machine, op string) result {
				t.Helper()
				c := exec.Command(cmd[0], append(cmd[1:], op)...)
				c.Env = append(os.Environ(),
					"LF_BASE_URL="+e.BaseURL, "LF_TENANT_ID="+tn.ID, "LF_PRODUCT="+product.Slug, "LF_LICENSE_KEY="+lic.Key,
					"LF_KEYS="+string(keySet), "LF_MACHINE="+machine, "LF_STORE="+filepath.Join(dir, machine+".lease"),
					"NODE_EXTRA_CA_CERTS="+e.CAFile)
				out, err := c.Output()
				var r result
				if err != nil || json.Unmarshal(out, &r) != nil {
					stderr := ""
					if x, ok := err.(*exec.ExitError); ok {
						stderr = string(x.Stderr)
					}
					t.Fatalf("%s %s: %v\n%s%s", machine, op, err, out, stderr)
				}
				return r
			}
			ok := func(machine, op string) result {
				t.Helper()
				r := step(machine, op)
				if !r.OK {
					t.Fatalf("%s %s: %s (%s)", machine, op, r.Code, r.Detail)
				}
				return r
			}
			refused := func(machine, op, code string) {
				t.Helper()
				if r := step(machine, op); r.OK || r.Code != code {
					t.Fatalf("%s %s: %+v, want %s", machine, op, r, code)
				}
			}
			m1, m2 := "e2e-"+sdk.name+"-1-"+run, "e2e-"+sdk.name+"-2-"+run

			r := ok(m1, "activate")
			if r.Lid != lic.ID || r.Tenant != tn.ID || r.Product != product.Slug || r.Plan != "pro" || r.Status != "valid" || !r.SSO || r.Seats != 25 {
				t.Errorf("lease claims %+v", r)
			}
			if c := ok(m1, "current"); c != r {
				t.Errorf("after a restart: %+v, want %+v", c, r)
			}
			refused(m2, "activate", "activation_limit_reached") // one seat
			refused(m2, "current", "no_lease")
			ok(m1, "refresh")

			// Suspension holds refreshes until the license is reinstated.
			b.do("POST", api+"/licenses/"+lic.ID+"/suspend", nil, 200, nil)
			refused(m1, "refresh", "license_suspended")
			b.do("POST", api+"/licenses/"+lic.ID+"/reinstate", nil, 200, nil)
			ok(m1, "refresh")

			ok(m1, "deactivate")
			ok(m2, "activate") // the freed seat
			b.do("POST", api+"/licenses/"+lic.ID+"/revoke", nil, 200, nil)
			refused(m2, "refresh", "license_revoked")
		})
	}
}
