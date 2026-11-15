{{- /* G020 shared-engine qualification: the profile ConfigMap's name and the
agent path it is mounted at, used by the ConfigMap, the daemonset volume and
mount, and the agent configuration. */}}
{{- define "nodeAgent.sandboxSharedProfile.name" -}}
{{ .Values.nodeAgent.name }}-sandbox-shared-profile
{{- end }}
{{- define "nodeAgent.sandboxSharedProfile.path" -}}
/etc/config/sandbox-shared-profile.json
{{- end }}
