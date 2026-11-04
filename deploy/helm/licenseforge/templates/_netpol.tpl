{{/* Egress shared by the server and the migration Job: DNS and the database only. */}}
{{- define "licenseforge.egress" -}}
{{- if not .Values.networkPolicy.dns.ports }}{{ fail "networkPolicy.dns.ports must not be empty (an empty rule would allow all egress)" }}{{ end }}
- ports:
    {{- range .Values.networkPolicy.dns.ports }}
    {{- if not (regexMatch "^[0-9]+$" (toString .)) }}{{ fail "networkPolicy.dns.ports must be port numbers" }}{{ end }}
    - {port: {{ . }}, protocol: UDP}
    - {port: {{ . }}, protocol: TCP}
    {{- end }}
  {{- with .Values.networkPolicy.dns.to }}
  to: {{- toYaml . | nindent 4 }}
  {{- end }}
- ports: [{port: {{ .Values.networkPolicy.databasePort }}, protocol: TCP}]
  {{- with .Values.networkPolicy.databaseTo }}
  to: {{- toYaml . | nindent 4 }}
  {{- end }}
{{- end -}}
