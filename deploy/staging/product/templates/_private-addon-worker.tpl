{{- define "zasp.privateAddonWorker.origin" -}}
{{- $cfg := .Values.privateAddonWorker -}}
{{- if and (hasKey $cfg "retained") (not (kindIs "bool" $cfg.retained)) -}}{{- fail "privateAddonWorker.retained must be boolean" -}}{{- end -}}
{{- if or $cfg.origin $cfg.scope $cfg.resultCredentialID $cfg.retained -}}
  {{- $id := `pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}` -}}
  {{- $dns := `(https://)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(:[1-9][0-9]{0,4})?` -}}
  {{- if not (regexMatch (printf "^%s$" $dns) $cfg.origin) -}}{{- fail "privateAddonWorker.origin must be an exact HTTPS DNS origin" -}}{{- end -}}
  {{- $port := regexFind `:[0-9]+$` $cfg.origin -}}
  {{- if and $port (gt (int (trimPrefix ":" $port)) 65535) -}}{{- fail "invalid privateAddonWorker port" -}}{{- end -}}
  {{- if not (regexMatch (printf "^%s/%s/%s$" $id $id $id) $cfg.scope) -}}{{- fail "privateAddonWorker.scope must name one Environment" -}}{{- end -}}
  {{- if and $cfg.resultCredentialID (not (regexMatch (printf "^%s$" $id) $cfg.resultCredentialID)) -}}{{- fail "privateAddonWorker.resultCredentialID must be a product ID" -}}{{- end -}}
  {{- $cfg.origin -}}
{{- end -}}
{{- end -}}
