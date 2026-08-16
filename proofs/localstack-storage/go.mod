module github.com/zasp-ai/zasp-sec/proofs/localstack-storage

go 1.25.0

toolchain go1.26.5

require (
	github.com/aws/aws-sdk-go-v2 v1.43.5
	github.com/aws/aws-sdk-go-v2/service/kms v1.55.5
	github.com/aws/aws-sdk-go-v2/service/s3 v1.107.1
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.44.5
	github.com/aws/smithy-go v1.27.7
	github.com/zasp-ai/zasp-sec/services/platform v0.0.0
)

replace github.com/zasp-ai/zasp-sec/services/platform => ../../services/platform

require (
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.17 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.36 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.36 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.37 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.16 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.9.29 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.36 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.19.37 // indirect
)
