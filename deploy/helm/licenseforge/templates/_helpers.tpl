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
