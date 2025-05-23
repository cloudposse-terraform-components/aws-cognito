package test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/cloudposse/test-helpers/pkg/atmos"
	helper "github.com/cloudposse/test-helpers/pkg/atmos/component-helper"
	"github.com/gruntwork-io/terratest/modules/random"
	"github.com/stretchr/testify/assert"
)

type ComponentSuite struct {
	helper.TestSuite
}

func (s *ComponentSuite) TestCognito() {
	const component = "cognito/basic"
	const stack = "default-test"
	const awsRegion = "us-east-2"

	subdomain := strings.ToLower(random.UniqueId())
	cognitoDomain := fmt.Sprintf("%s-components-cptest", subdomain)
	fullDomain := fmt.Sprintf("%s.components.cptest.app", subdomain)

	inputs := map[string]any{
		"domain":                      cognitoDomain,
		"client_default_redirect_uri": fmt.Sprintf("https://%s", fullDomain),
		"client_callback_urls": []string{
			fmt.Sprintf("https://%s", fullDomain),
			fmt.Sprintf("https://%s/v1/callback", fullDomain),
		},
	}

	defer s.DestroyAtmosComponent(s.T(), component, stack, &inputs)
	options, _ := s.DeployAtmosComponent(s.T(), component, stack, &inputs)
	assert.NotNil(s.T(), options)

	userPoolID := atmos.Output(s.T(), options, "id")
	assert.True(s.T(), strings.HasPrefix(userPoolID, "us-east-2"))

	userPoolArn := atmos.Output(s.T(), options, "arn")
	assert.Contains(s.T(), userPoolArn, userPoolID)

	endpoint := atmos.Output(s.T(), options, "endpoint")
	assert.Contains(s.T(), endpoint, "cognito-idp."+awsRegion+".amazonaws.com/")

	creationDate := atmos.Output(s.T(), options, "creation_date")
	assert.NotEmpty(s.T(), creationDate)

	lastModifiedDate := atmos.Output(s.T(), options, "last_modified_date")
	assert.NotEmpty(s.T(), lastModifiedDate)

	domainCFArn := atmos.Output(s.T(), options, "domain_cloudfront_distribution_arn")
	assert.Contains(s.T(), domainCFArn, ".cloudfront.")

	clientIDs := atmos.OutputList(s.T(), options, "client_ids")
	assert.Greater(s.T(), len(clientIDs), 0)

	clientIDMap := atmos.OutputMap(s.T(), options, "client_ids_map")
	assert.Greater(s.T(), len(clientIDMap), 0)

	scopeIdentifiers := atmos.OutputList(s.T(), options, "resource_servers_scope_identifiers")
	assert.GreaterOrEqual(s.T(), len(scopeIdentifiers), 0)

	s.DriftTest(component, stack, &inputs)
}

func (s *ComponentSuite) TestEnabledFlag() {
	const component = "cognito/disabled"
	const stack = "default-test"
	s.VerifyEnabledFlag(component, stack, nil)
}

func TestRunSuite(t *testing.T) {
	suite := new(ComponentSuite)
	helper.Run(t, suite)
}
