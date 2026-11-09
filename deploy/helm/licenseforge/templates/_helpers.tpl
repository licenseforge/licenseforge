{{- define "licenseforge.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "licenseforge.selectorLabels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* Server pods only (not the migration Job): Deployment, Service, PDB. */}}
{{- define "licenseforge.serverSelectorLabels" -}}
{{ include "licenseforge.selectorLabels" . }}
app.kubernetes.io/component: server
{{- end -}}

{{- define "licenseforge.labels" -}}
{{ include "licenseforge.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "licenseforge.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}
{{- end -}}

{{/* Pod Security Standard "restricted" (ADR-0005). */}}
{{- define "licenseforge.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
fsGroup: 65532
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "licenseforge.containerSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: [ALL]
{{- end -}}

{{/* metrics.port, nil-safe: values reused from a release older than metrics.* have no metrics key (the server's default then). */}}
{{- define "licenseforge.metricsPort" -}}
{{- dig "port" 9090 (.Values.metrics | default dict) | int -}}
{{- end -}}

{{/* audit.export.syslog, nil-safe (values reused from older releases). */}}
{{- define "licenseforge.syslog" -}}
{{- toYaml (dig "export" "syslog" dict (.Values.audit | default dict)) -}}
{{- end -}}

{{/* host:port, an IPv6 host in brackets. */}}
{{- define "licenseforge.hostPort" -}}
{{- $h := index . 0 -}}{{- if contains ":" $h -}}[{{ $h }}]{{- else -}}{{ $h }}{{- end -}}:{{ index . 1 | int }}
{{- end -}}

{{/* audit.export.otlp, nil-safe (values reused from older releases). */}}
{{- define "licenseforge.otlp" -}}
{{- toYaml (dig "export" "otlp" dict (.Values.audit | default dict)) -}}
{{- end -}}

{{/* extraCA for the Jobs that connect to the database (sslmode=verify-full
     with a private CA); the Deployment mounts it with its other Secrets.
     Each takes (list . indent). */}}
{{- define "licenseforge.extraCAEnv" -}}
{{- $root := index . 0 }}{{- with ($root.Values.extraCA | default dict).secretName }}
{{ printf "- name: SSL_CERT_DIR\n  value: /etc/licenseforge/extra-ca" | indent (index $ 1) }}
{{- end }}
{{- end -}}
{{/* LICENSEFORGE_DATABASE_ALLOW_PLAINTEXT for databaseAllowPlaintext: development
clusters only (the server otherwise refuses database URLs that don't verify
the server, unless local). */}}
{{- define "licenseforge.dbPlaintextEnv" -}}
{{- $root := index . 0 }}{{- if $root.Values.databaseAllowPlaintext }}
{{ printf "- name: LICENSEFORGE_DATABASE_ALLOW_PLAINTEXT\n  value: \"true\"" | indent (index $ 1) }}
{{- end }}
{{- end -}}
{{- define "licenseforge.extraCAMounts" -}}
{{- $root := index . 0 }}{{- with ($root.Values.extraCA | default dict).secretName }}
{{ printf "volumeMounts:\n  - {name: extra-ca, mountPath: /etc/licenseforge/extra-ca, readOnly: true}" | indent (index $ 1) }}
{{- end }}
{{- end -}}
{{- define "licenseforge.extraCAVolumes" -}}
{{- $root := index . 0 }}{{- $ca := $root.Values.extraCA | default dict }}{{- with $ca.secretName }}
{{ printf "volumes:\n  - name: extra-ca\n    secret: {secretName: %s, items: [{key: %s, path: ca.crt}]}" (quote .) (quote $ca.key) | indent (index $ 1) }}
{{- end }}
{{- end -}}
