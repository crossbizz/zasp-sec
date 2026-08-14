module github.com/zasp-ai/zasp-sec/proofs/localstack-iam-compat

go 1.25.0

toolchain go1.26.5

require (
	github.com/aws/aws-sdk-go-v2 v1.43.5
	github.com/aws/aws-sdk-go-v2/service/iam v1.59.0
	github.com/aws/aws-sdk-go-v2/service/sts v1.45.5
	github.com/aws/smithy-go v1.27.7
)

require (
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.36 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.36 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.37 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.16 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.36 // indirect
)
