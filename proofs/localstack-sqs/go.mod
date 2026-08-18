module github.com/zasp-ai/zasp-sec/proofs/localstack-sqs

go 1.25.0

toolchain go1.26.5

require (
	github.com/aws/aws-sdk-go-v2 v1.43.6
	github.com/aws/aws-sdk-go-v2/service/sqs v1.46.6
	github.com/zasp-ai/zasp-sec/services/platform v0.0.0
)

replace github.com/zasp-ai/zasp-sec/services/platform => ../../services/platform

require (
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.37 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.37 // indirect
	github.com/aws/smithy-go v1.27.8 // indirect
)
