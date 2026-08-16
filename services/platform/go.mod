module github.com/zasp-ai/zasp-sec/services/platform

go 1.25.0

require (
	github.com/neo4j/neo4j-go-driver/v6 v6.2.0
	github.com/zasp-ai/zasp-sec/services/health v0.0.0
)

replace github.com/zasp-ai/zasp-sec/services/health => ../health
