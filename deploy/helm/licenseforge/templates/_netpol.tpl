{{/* Egress shared by the server and the migration Job: DNS and the database only. */}}
{{- define "licenseforge.egress" -}}
- ports:
    {{- range .Values.networkPolicy.dns.ports }}
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
