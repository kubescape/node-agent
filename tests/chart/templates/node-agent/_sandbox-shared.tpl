{{- /* G020 shared-engine qualification: the profile ConfigMap's name and the
agent path it is mounted at, used by the ConfigMap, the daemonset volume and
mount, and the agent configuration. */}}
{{- define "nodeAgent.sandboxSharedProfile.name" -}}
{{ .Values.nodeAgent.name }}-sandbox-shared-profile
{{- end }}
{{- define "nodeAgent.sandboxSharedProfile.path" -}}
/etc/config/sandbox-shared-profile.json
{{- end }}
{{- /* G020 product shared engine: the per-kernel image map
(nodeAgent.config.sandboxPolicy.sharedImages, keyed by kernel BTF sha256).
The profiles ConfigMap's name, the agent directory it is mounted at, and the
sandboxPolicySharedImages JSON the agent configuration carries. */}}
{{- define "nodeAgent.sandboxSharedImages.name" -}}
{{ .Values.nodeAgent.name }}-sandbox-shared-profiles
{{- end }}
{{- define "nodeAgent.sandboxSharedImages.dir" -}}
/etc/sandbox-shared-profiles
{{- end }}
{{- define "nodeAgent.sandboxSharedImages.config" -}}
{{- $dir := include "nodeAgent.sandboxSharedImages.dir" . }}
{{- $images := dict }}
{{- range $btf, $entry := .Values.nodeAgent.config.sandboxPolicy.sharedImages }}
{{- $_ := required (printf "nodeAgent.config.sandboxPolicy.sharedImages[%s].profile is required" $btf) $entry.profile }}
{{- $_ := set $images $btf (dict "image" (required (printf "nodeAgent.config.sandboxPolicy.sharedImages[%s].image is required" $btf) $entry.image) "manifestDigest" (required (printf "nodeAgent.config.sandboxPolicy.sharedImages[%s].manifestDigest is required" $btf) $entry.manifestDigest) "profileFile" (printf "%s/%s.json" $dir $btf)) }}
{{- end }}
{{- $images | toJson }}
{{- end }}
