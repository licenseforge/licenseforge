#!/usr/bin/env bash
# The e2e environment (ADR-0041): LicenseForge on minikube with PostgreSQL 17,
# Keycloak (OIDC) and HTTPS ingresses on nip.io hostnames signed by a local
# CA. Local only: every secret here is a dev value. Re-runnable.
#
#   e2e/env/up.sh --local              chart and image built from this checkout (default)
#   e2e/env/up.sh --release VERSION    a published release, e.g. 0.1.0-alpha.1
#
# Needs minikube started with the ingress addon:
#   minikube start --driver=docker --cpus=4 --memory=6g --addons=ingress
set -euo pipefail
ENV_DIR=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$ENV_DIR/../.." && pwd)
STATE=$ENV_DIR/.state
MODE=local VERSION=""
case "${1:-}" in
  ""|--local) ;;
  --release) MODE=release VERSION=${2:?--release needs a version, e.g. 0.1.0-alpha.1} ;;
  *) echo "usage: $0 [--local | --release VERSION]" >&2; exit 2 ;;
esac
# Its own namespace and hostnames, so a demo install next to it is untouched.
NS=licenseforge-e2e
IP=$(minikube ip)
LF=lf-e2e.$IP.nip.io KC=kc-e2e.$IP.nip.io
render() { sed "s/__NS__/$NS/g; s/__LF__/$LF/g; s/__KC__/$KC/g" "$ENV_DIR/$1"; }
mkdir -p "$STATE"
# Wildcard DNS isn't reliable here: resolvers with DNS-rebinding protection
# drop nip.io answers that point at private addresses. So nothing depends on
# it: curl pins the names, pods get them from CoreDNS's hosts block, and the
# journeys dial the IP the name carries.
CURL=(curl -sf --cacert "$STATE/ca.crt" --resolve "$LF:443:$IP" --resolve "$KC:443:$IP")
COREFILE=$(kubectl -n kube-system get configmap coredns -o jsonpath='{.data.Corefile}')
if ! grep -q " $KC\b" <<<"$COREFILE"; then
  NEW=$(sed "s/^\( *\)hosts {/&\n\1   $IP $LF\n\1   $IP $KC/" <<<"$COREFILE")
  [ "$NEW" != "$COREFILE" ] || { echo "CoreDNS has no hosts block to add $LF and $KC to" >&2; exit 1; }
  kubectl -n kube-system create configmap coredns --from-literal=Corefile="$NEW" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl -n kube-system rollout restart deployment/coredns >/dev/null
  kubectl -n kube-system rollout status deployment/coredns --timeout=120s >/dev/null
fi

# 1. A local CA and one certificate for both hosts, kept across runs.
if [ ! -f "$STATE/ca.crt" ]; then
  openssl req -x509 -newkey rsa:3072 -nodes -days 825 -subj "/CN=LicenseForge e2e CA" \
    -keyout "$STATE/ca.key" -out "$STATE/ca.crt" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" 2>/dev/null
fi
if [ ! -f "$STATE/tls.crt" ] || ! openssl x509 -in "$STATE/tls.crt" -noout -ext subjectAltName | grep -q "$LF"; then
  openssl req -newkey rsa:2048 -nodes -subj "/CN=$LF" -keyout "$STATE/tls.key" -out "$STATE/tls.csr" 2>/dev/null
  openssl x509 -req -in "$STATE/tls.csr" -CA "$STATE/ca.crt" -CAkey "$STATE/ca.key" -CAcreateserial -days 397 -out "$STATE/tls.crt" \
    -extfile <(printf "subjectAltName=DNS:%s,DNS:%s\nextendedKeyUsage=serverAuth\n" "$LF" "$KC") 2>/dev/null
fi

kubectl get ns $NS >/dev/null 2>&1 || kubectl create ns $NS >/dev/null
apply() { kubectl -n $NS "$@" --dry-run=client -o yaml | kubectl apply -f - >/dev/null; }
apply create secret tls local-tls --cert="$STATE/tls.crt" --key="$STATE/tls.key"
apply create secret generic local-ca --from-file=ca.crt="$STATE/ca.crt"

# 2. PostgreSQL with the repo's one-time setup, and Keycloak with the realm,
#    the client and two users (admin, viewer; password licenseforge).
apply create configmap db-setup --from-file=setup.sql="$REPO/deploy/database-setup.sql"
render postgres.yaml | kubectl apply -f - >/dev/null
apply create configmap keycloak-realm --from-file=licenseforge-realm.json=<(render realm.json)
render keycloak.yaml | kubectl apply -f - >/dev/null
render ingress.yaml | kubectl apply -f - >/dev/null

# 3. LicenseForge's Secrets: the database logins of database-setup.sql, a
#    master key (kept, so license keys stay decryptable across runs), the
#    OIDC client secret.
DB="db.$NS.svc.cluster.local:5432/licenseforge?sslmode=disable"
[ -f "$STATE/master-key" ] || head -c 32 /dev/urandom | base64 -w0 > "$STATE/master-key"
apply create secret generic lf-server \
  --from-literal=database-url="postgres://licenseforge_api:change-me-api@$DB" \
  --from-literal=platform-database-url="postgres://licenseforge_admin:change-me-admin@$DB" \
  --from-literal=identity-database-url="postgres://licenseforge_login:change-me-login@$DB" \
  --from-literal=master-keys="e2e=$(cat "$STATE/master-key")"
apply create secret generic lf-migrate --from-literal=owner-database-url="postgres://licenseforge_owner:change-me-owner@$DB"
apply create secret generic lf-oidc --from-literal=client-secret=dev-client-secret

echo "waiting for PostgreSQL and Keycloak..."
kubectl -n $NS rollout status statefulset/db --timeout=300s >/dev/null
kubectl -n $NS rollout status deployment/keycloak --timeout=600s >/dev/null
for _ in $(seq 60); do
  "${CURL[@]}" "https://$KC/realms/licenseforge/.well-known/openid-configuration" >/dev/null && break
  sleep 5
done
"${CURL[@]}" "https://$KC/realms/licenseforge/.well-known/openid-configuration" >/dev/null \
  || { echo "Keycloak isn't reachable at https://$KC" >&2; exit 1; }

# 4. LicenseForge: the published chart, or the checkout's chart with an image
#    built in minikube's Docker.
if [ $MODE = release ]; then
  CHART=(oci://ghcr.io/licenseforge/charts/licenseforge --version "$VERSION")
  IMAGE=()
else
  echo "building the image in minikube from $REPO..."
  minikube image build -t licenseforge:e2e "$REPO" >/dev/null 2>&1 || { echo "image build failed: minikube image build -t licenseforge:e2e $REPO" >&2; exit 1; }
  CHART=("$REPO/deploy/helm/licenseforge")
  IMAGE=(--set image.repository=licenseforge --set image.tag=e2e --set image.pullPolicy=Never)
fi
helm upgrade --install licenseforge "${CHART[@]}" -n $NS -f <(render values.yaml) "${IMAGE[@]}" >/dev/null
# ponytail: the chart can't trust an extra CA yet, so the server trusts the
# local CA through this patch (SSL_CERT_FILE replaces the system roots; the
# only TLS peer here is Keycloak). Upgrade path: a chart value for an OIDC CA.
kubectl -n $NS patch deployment licenseforge --type strategic -p '{"spec":{"template":{"spec":{
  "volumes":[{"name":"local-ca","secret":{"secretName":"local-ca"}}],
  "containers":[{"name":"server","env":[{"name":"SSL_CERT_FILE","value":"/etc/local-ca/ca.crt"}],
    "volumeMounts":[{"name":"local-ca","mountPath":"/etc/local-ca","readOnly":true}]}]}}}}' >/dev/null
# A local image keeps its tag: restart, so the pod runs the image just built.
[ $MODE = local ] && kubectl -n $NS rollout restart deployment/licenseforge >/dev/null
kubectl -n $NS rollout status deployment/licenseforge --timeout=300s >/dev/null

# 5. The test tenant, until tenants can be created through the product
#    (ADR-0041): tenant "acme" and an owner invitation for
#    admin@licenseforge.local, whose link token goes to .state/invite-token.
#    Journeys accept it on their first login. Once only.
if [ ! -f "$STATE/invite-token" ]; then
  python3 - "$STATE/invite-token" > "$STATE/seed.sql" <<'PY'
import base64, hashlib, secrets, sys
b32 = lambda n: base64.b32encode(secrets.token_bytes(n)).decode().rstrip("=")
rid = lambda p: p + "_" + b32(20).lower()[:26]
token = b32(20)[:26]                  # like Go's rand.Text
open(sys.argv[1] + ".new", "w").write(token)
tnt, inv = rid("tnt"), rid("inv")
print(f"""BEGIN;
INSERT INTO tenants (id, created_at, updated_at, slug, name) VALUES ('{tnt}', now(), now(), 'acme', 'Acme');
INSERT INTO invitations (id, created_at, updated_at, email, role, scope_all, token_hash, expires_at, tenant_id)
  VALUES ('{inv}', now(), now(), 'admin@licenseforge.local', 'owner', true, decode('{hashlib.sha256(token.encode()).hexdigest()}', 'hex'), now() + interval '30 days', '{tnt}');
COMMIT;""")
PY
  kubectl -n $NS exec -i db-0 -- psql -q -v ON_ERROR_STOP=1 -U postgres -d licenseforge < "$STATE/seed.sql"
  mv "$STATE/invite-token.new" "$STATE/invite-token"
fi

for _ in $(seq 30); do "${CURL[@]}" "https://$LF/readyz" >/dev/null && break; sleep 2; done
"${CURL[@]}" "https://$LF/readyz" >/dev/null || { echo "LicenseForge isn't ready at https://$LF" >&2; exit 1; }
cat > "$STATE/env" <<EOF
E2E_BASE_URL=https://$LF
E2E_CA_FILE=$STATE/ca.crt
E2E_TENANT=acme
E2E_INVITE_TOKEN_FILE=$STATE/invite-token
EOF
cat <<EOF

LicenseForge is up ($MODE${VERSION:+ $VERSION}):
  Dashboard  https://$LF        (admin / licenseforge, viewer / licenseforge)
  Keycloak   https://$KC/admin  (admin / admin)
  Local CA   $STATE/ca.crt  (import it in your browser to avoid certificate warnings)
If your browser can't resolve these names (DNS-rebinding protection), add to /etc/hosts:
  $IP $LF $KC
Run the journeys with: make e2e
EOF
