module github.com/zasp-ai/zasp-sec/cmd/agentsecctl

go 1.26.0

require github.com/zasp-ai/zasp-sec/services/platform v0.0.0

require (
	github.com/aws/aws-sdk-go-v2 v1.43.7 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.18 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.38 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.38 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.38 // indirect
	github.com/aws/aws-sdk-go-v2/service/eks v1.92.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/iam v1.59.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.17 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.9.30 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.38 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.19.38 // indirect
	github.com/aws/aws-sdk-go-v2/service/kms v1.55.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/opensearch v1.75.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/s3 v1.107.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.44.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/sqs v1.46.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.41.6 // indirect
	github.com/aws/smithy-go v1.27.8 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/pgx/v5 v5.10.0 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/text v0.41.0 // indirect
)

replace github.com/zasp-ai/zasp-sec/services/platform => ../../services/platform

replace github.com/zasp-ai/zasp-sec/services/health => ../../services/health
