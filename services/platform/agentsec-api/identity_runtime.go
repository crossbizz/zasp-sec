package main

import "github.com/zasp-ai/zasp-sec/services/platform/authorization"

func runtimeIdentityDeployment(c RuntimeConfig) authorization.IdentityDeployment {
	return authorization.IdentityDeployment{PublicOrigin: c.PublicOrigin, ProviderBaseURL: c.StytchBaseURL, ProjectID: c.StytchProjectID, ConfiguredOrganization: c.StytchOrganizationID, Mode: c.DeploymentMode, OrganizationID: c.OrganizationID}
}
