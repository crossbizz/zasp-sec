module github.com/zasp-ai/zasp-sec/proofs/neo4j-graphstore

go 1.25.4

require (
	github.com/neo4j/neo4j-go-driver/v6 v6.2.0
	github.com/zasp-ai/zasp-sec/services/platform v0.0.0
)

replace github.com/zasp-ai/zasp-sec/services/platform => ../../services/platform

replace github.com/zasp-ai/zasp-sec/services/health => ../../services/health
