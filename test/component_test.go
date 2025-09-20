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

// Test case for empty/no risk configuration
func (s *ComponentSuite) TestRiskConfigurationEmpty() {
	const component = "cognito/risk-config-empty"
	const stack = "default-test"

	subdomain := strings.ToLower(random.UniqueId())
	cognitoDomain := fmt.Sprintf("%s-risk-empty-cptest", subdomain)
	fullDomain := fmt.Sprintf("%s.risk-empty.cptest.app", subdomain)

	inputs := map[string]any{
		"domain":                      cognitoDomain,
		"client_default_redirect_uri": fmt.Sprintf("https://%s", fullDomain),
		"client_callback_urls": []string{
			fmt.Sprintf("https://%s", fullDomain),
		},
	}

	defer s.DestroyAtmosComponent(s.T(), component, stack, &inputs)
	options, _ := s.DeployAtmosComponent(s.T(), component, stack, &inputs)
	assert.NotNil(s.T(), options)

	// Verify basic cognito functionality works
	userPoolID := atmos.Output(s.T(), options, "id")
	assert.True(s.T(), strings.HasPrefix(userPoolID, "us-east-2"))

	// Verify risk configuration outputs are null/empty when no configuration provided
	riskConfigIDs := atmos.OutputList(s.T(), options, "risk_configuration_ids")
	assert.Equal(s.T(), 0, len(riskConfigIDs))

	s.DriftTest(component, stack, &inputs)
}

// Test case for account takeover risk configuration only
func (s *ComponentSuite) TestRiskConfigurationAccountTakeover() {
	const component = "cognito/risk-config-account-takeover"
	const stack = "default-test"

	subdomain := strings.ToLower(random.UniqueId())
	cognitoDomain := fmt.Sprintf("%s-risk-at-cptest", subdomain)
	fullDomain := fmt.Sprintf("%s.risk-at.cptest.app", subdomain)

	inputs := map[string]any{
		"domain":                      cognitoDomain,
		"client_default_redirect_uri": fmt.Sprintf("https://%s", fullDomain),
		"client_callback_urls": []string{
			fmt.Sprintf("https://%s", fullDomain),
		},
	}

	defer s.DestroyAtmosComponent(s.T(), component, stack, &inputs)
	options, _ := s.DeployAtmosComponent(s.T(), component, stack, &inputs)
	assert.NotNil(s.T(), options)

	// Verify basic cognito functionality works
	userPoolID := atmos.Output(s.T(), options, "id")
	assert.True(s.T(), strings.HasPrefix(userPoolID, "us-east-2"))

	// Verify risk configuration is created
	riskConfigIDs := atmos.OutputList(s.T(), options, "risk_configuration_ids")
	assert.Equal(s.T(), 1, len(riskConfigIDs))
	assert.NotEmpty(s.T(), riskConfigIDs[0])

	// Verify risk configuration map output
	riskConfigIDsMap := atmos.OutputMap(s.T(), options, "risk_configuration_ids_map")
	assert.Equal(s.T(), 1, len(riskConfigIDsMap))
	assert.Contains(s.T(), riskConfigIDsMap, "global")

	s.DriftTest(component, stack, &inputs)
}

// Test case for compromised credentials risk configuration only
func (s *ComponentSuite) TestRiskConfigurationCompromisedCredentials() {
	const component = "cognito/risk-config-compromised-credentials"
	const stack = "default-test"

	subdomain := strings.ToLower(random.UniqueId())
	cognitoDomain := fmt.Sprintf("%s-risk-cc-cptest", subdomain)
	fullDomain := fmt.Sprintf("%s.risk-cc.cptest.app", subdomain)

	inputs := map[string]any{
		"domain":                      cognitoDomain,
		"client_default_redirect_uri": fmt.Sprintf("https://%s", fullDomain),
		"client_callback_urls": []string{
			fmt.Sprintf("https://%s", fullDomain),
		},
	}

	defer s.DestroyAtmosComponent(s.T(), component, stack, &inputs)
	options, _ := s.DeployAtmosComponent(s.T(), component, stack, &inputs)
	assert.NotNil(s.T(), options)

	// Verify basic cognito functionality works
	userPoolID := atmos.Output(s.T(), options, "id")
	assert.True(s.T(), strings.HasPrefix(userPoolID, "us-east-2"))

	// Verify risk configuration is created
	riskConfigIDs := atmos.OutputList(s.T(), options, "risk_configuration_ids")
	assert.Equal(s.T(), 1, len(riskConfigIDs))
	assert.NotEmpty(s.T(), riskConfigIDs[0])

	// Verify risk configuration map output
	riskConfigIDsMap := atmos.OutputMap(s.T(), options, "risk_configuration_ids_map")
	assert.Equal(s.T(), 1, len(riskConfigIDsMap))
	assert.Contains(s.T(), riskConfigIDsMap, "global")

	s.DriftTest(component, stack, &inputs)
}

// Test case for risk exception configuration only
func (s *ComponentSuite) TestRiskConfigurationRiskException() {
	const component = "cognito/risk-config-risk-exception"
	const stack = "default-test"

	subdomain := strings.ToLower(random.UniqueId())
	cognitoDomain := fmt.Sprintf("%s-risk-re-cptest", subdomain)
	fullDomain := fmt.Sprintf("%s.risk-re.cptest.app", subdomain)

	inputs := map[string]any{
		"domain":                      cognitoDomain,
		"client_default_redirect_uri": fmt.Sprintf("https://%s", fullDomain),
		"client_callback_urls": []string{
			fmt.Sprintf("https://%s", fullDomain),
		},
	}

	defer s.DestroyAtmosComponent(s.T(), component, stack, &inputs)
	options, _ := s.DeployAtmosComponent(s.T(), component, stack, &inputs)
	assert.NotNil(s.T(), options)

	// Verify basic cognito functionality works
	userPoolID := atmos.Output(s.T(), options, "id")
	assert.True(s.T(), strings.HasPrefix(userPoolID, "us-east-2"))

	// Verify risk configuration is created
	riskConfigIDs := atmos.OutputList(s.T(), options, "risk_configuration_ids")
	assert.Equal(s.T(), 1, len(riskConfigIDs))
	assert.NotEmpty(s.T(), riskConfigIDs[0])

	// Verify risk configuration map output
	riskConfigIDsMap := atmos.OutputMap(s.T(), options, "risk_configuration_ids_map")
	assert.Equal(s.T(), 1, len(riskConfigIDsMap))
	assert.Contains(s.T(), riskConfigIDsMap, "global")

	s.DriftTest(component, stack, &inputs)
}

// Test case for multiple risk configurations
func (s *ComponentSuite) TestRiskConfigurationMultiple() {
	const component = "cognito/risk-config-multiple"
	const stack = "default-test"

	subdomain := strings.ToLower(random.UniqueId())
	cognitoDomain := fmt.Sprintf("%s-risk-multi-cptest", subdomain)
	fullDomain := fmt.Sprintf("%s.risk-multi.cptest.app", subdomain)

	inputs := map[string]any{
		"domain":                      cognitoDomain,
		"client_default_redirect_uri": fmt.Sprintf("https://%s", fullDomain),
		"client_callback_urls": []string{
			fmt.Sprintf("https://%s", fullDomain),
		},
	}

	defer s.DestroyAtmosComponent(s.T(), component, stack, &inputs)
	options, _ := s.DeployAtmosComponent(s.T(), component, stack, &inputs)
	assert.NotNil(s.T(), options)

	// Verify basic cognito functionality works
	userPoolID := atmos.Output(s.T(), options, "id")
	assert.True(s.T(), strings.HasPrefix(userPoolID, "us-east-2"))

	// Verify risk configuration is created (should be 1 global configuration)
	riskConfigIDs := atmos.OutputList(s.T(), options, "risk_configuration_ids")
	assert.Equal(s.T(), 1, len(riskConfigIDs))
	assert.NotEmpty(s.T(), riskConfigIDs[0])

	// Verify risk configuration map output
	riskConfigIDsMap := atmos.OutputMap(s.T(), options, "risk_configuration_ids_map")
	assert.Equal(s.T(), 1, len(riskConfigIDsMap))
	assert.Contains(s.T(), riskConfigIDsMap, "global")

	s.DriftTest(component, stack, &inputs)
}

// Test case for client-specific risk configuration
func (s *ComponentSuite) TestRiskConfigurationClientSpecific() {
	const component = "cognito/risk-config-client-specific"
	const stack = "default-test"

	subdomain := strings.ToLower(random.UniqueId())
	cognitoDomain := fmt.Sprintf("%s-risk-client-cptest", subdomain)
	fullDomain := fmt.Sprintf("%s.risk-client.cptest.app", subdomain)

	inputs := map[string]any{
		"domain":                      cognitoDomain,
		"client_default_redirect_uri": fmt.Sprintf("https://%s", fullDomain),
		"client_callback_urls": []string{
			fmt.Sprintf("https://%s", fullDomain),
		},
	}

	defer s.DestroyAtmosComponent(s.T(), component, stack, &inputs)
	options, _ := s.DeployAtmosComponent(s.T(), component, stack, &inputs)
	assert.NotNil(s.T(), options)

	// Verify basic cognito functionality works
	userPoolID := atmos.Output(s.T(), options, "id")
	assert.True(s.T(), strings.HasPrefix(userPoolID, "us-east-2"))

	// Verify risk configuration is created
	riskConfigIDs := atmos.OutputList(s.T(), options, "risk_configuration_ids")
	assert.Equal(s.T(), 1, len(riskConfigIDs))
	assert.NotEmpty(s.T(), riskConfigIDs[0])

	// Verify risk configuration map output contains client-specific entry
	riskConfigIDsMap := atmos.OutputMap(s.T(), options, "risk_configuration_ids_map")
	assert.Equal(s.T(), 1, len(riskConfigIDsMap))
	assert.Contains(s.T(), riskConfigIDsMap, "test-client-id")

	s.DriftTest(component, stack, &inputs)
}

// Test case for disabled module with risk configuration
func (s *ComponentSuite) TestRiskConfigurationDisabled() {
	const component = "cognito/risk-config-disabled"
	const stack = "default-test"

	// Use VerifyEnabledFlag to test that resources are not created when disabled
	s.VerifyEnabledFlag(component, stack, nil)
}

func TestRunSuite(t *testing.T) {
	suite := new(ComponentSuite)
	helper.Run(t, suite)
}
