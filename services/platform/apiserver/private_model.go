package apiserver

import "github.com/zasp-ai/zasp-sec/services/platform/aigateway"

func configuredPrivateModel(p aigateway.Purpose, bedrockPrefix string) *analystChat {
	model := aigateway.ConfiguredPrivateModel(p, bedrockPrefix)
	if model == nil {
		return nil
	}
	return &analystChat{driver: model.Driver, binding: model.Binding}
}
