module github.com/zasp-ai/zasp-sec/services/sensor-agent

go 1.25.0

require (
	github.com/zasp-ai/zasp-sec/services/health v0.0.0
	github.com/zasp-ai/zasp-sec/services/platform v0.0.0
)

replace github.com/zasp-ai/zasp-sec/services/health => ../health

replace github.com/zasp-ai/zasp-sec/services/platform => ../platform
