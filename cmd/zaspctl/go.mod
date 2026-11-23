module github.com/zasp-ai/zasp-sec/cmd/zaspctl

go 1.26.0

require gopkg.in/yaml.v3 v3.0.1

require golang.org/x/sys v0.47.0

require github.com/zasp-ai/zasp-sec/services/platform v0.0.0

replace github.com/zasp-ai/zasp-sec/services/platform => ../../services/platform
