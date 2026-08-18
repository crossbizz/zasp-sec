module github.com/zasp-ai/zasp-sec/services/platform

go 1.25.0

require (
	github.com/aws/aws-sdk-go-v2 v1.43.6
	github.com/aws/aws-sdk-go-v2/service/kms v1.55.6
	github.com/aws/aws-sdk-go-v2/service/opensearch v1.75.6
	github.com/aws/aws-sdk-go-v2/service/s3 v1.107.2
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.44.6
	github.com/aws/aws-sdk-go-v2/service/sqs v1.46.6
	github.com/neo4j/neo4j-go-driver/v6 v6.2.0
	github.com/zasp-ai/zasp-sec/services/health v0.0.0
)

require (
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.18 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.37 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.37 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.38 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.17 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.9.30 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.37 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.19.38 // indirect
	github.com/aws/smithy-go v1.27.8 // indirect
)

replace github.com/zasp-ai/zasp-sec/services/health => ../health
