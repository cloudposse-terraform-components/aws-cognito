package test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/cloudposse/test-helpers/pkg/atmos"
	helper "github.com/cloudposse/test-helpers/pkg/atmos/component-helper"
	"github.com/gruntwork-io/terratest/modules/random"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	userPoolID := outputString(s.T(), options, "id")
	assert.True(s.T(), strings.HasPrefix(userPoolID, "us-east-2"))

	userPoolArn := outputString(s.T(), options, "arn")
	assert.Contains(s.T(), userPoolArn, userPoolID)

	endpoint := outputString(s.T(), options, "endpoint")
	assert.Contains(s.T(), endpoint, "cognito-idp."+awsRegion+".amazonaws.com/")

	creationDate := outputString(s.T(), options, "creation_date")
	assert.NotEmpty(s.T(), creationDate)

	lastModifiedDate := outputString(s.T(), options, "last_modified_date")
	assert.NotEmpty(s.T(), lastModifiedDate)

	domainCFArn := outputString(s.T(), options, "domain_cloudfront_distribution_arn")
	assert.Contains(s.T(), domainCFArn, ".cloudfront.")

	clientIDs := outputStringList(s.T(), options, "client_ids")
	assert.Greater(s.T(), len(clientIDs), 0)

	clientIDMap := outputStringMap(s.T(), options, "client_ids_map")
	assert.Greater(s.T(), len(clientIDMap), 0)

	scopeIdentifiers := outputStringList(s.T(), options, "resource_servers_scope_identifiers")
	assert.Empty(s.T(), scopeIdentifiers)

	s.DriftTest(component, stack, &inputs)
}

func (s *ComponentSuite) TestManagedLogin() {
	const component = "cognito/managed-login"
	const stack = "default-test"

	subdomain := strings.ToLower(random.UniqueId())
	cognitoDomain := fmt.Sprintf("%s-managed-login-cptest", subdomain)
	fullDomain := fmt.Sprintf("%s.managed-login.cptest.app", subdomain)

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

	userPoolID := outputString(s.T(), options, "id")
	assert.True(s.T(), strings.HasPrefix(userPoolID, "us-east-2"))

	domainCFArn := outputString(s.T(), options, "domain_cloudfront_distribution_arn")
	assert.Contains(s.T(), domainCFArn, ".cloudfront.")

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
	userPoolID := outputString(s.T(), options, "id")
	assert.True(s.T(), strings.HasPrefix(userPoolID, "us-east-2"))

	// Verify risk configuration outputs are null/empty when no configuration provided
	riskConfigIDs := outputStringList(s.T(), options, "risk_configuration_ids")
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
	userPoolID := outputString(s.T(), options, "id")
	assert.True(s.T(), strings.HasPrefix(userPoolID, "us-east-2"))

	// Verify risk configuration is created
	riskConfigIDs := outputStringList(s.T(), options, "risk_configuration_ids")
	assert.Equal(s.T(), 1, len(riskConfigIDs))
	assert.NotEmpty(s.T(), riskConfigIDs[0])

	// Verify risk configuration map output
	riskConfigIDsMap := outputStringMap(s.T(), options, "risk_configuration_ids_map")
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
	userPoolID := outputString(s.T(), options, "id")
	assert.True(s.T(), strings.HasPrefix(userPoolID, "us-east-2"))

	// Verify risk configuration is created
	riskConfigIDs := outputStringList(s.T(), options, "risk_configuration_ids")
	assert.Equal(s.T(), 1, len(riskConfigIDs))
	assert.NotEmpty(s.T(), riskConfigIDs[0])

	// Verify risk configuration map output
	riskConfigIDsMap := outputStringMap(s.T(), options, "risk_configuration_ids_map")
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
	userPoolID := outputString(s.T(), options, "id")
	assert.True(s.T(), strings.HasPrefix(userPoolID, "us-east-2"))

	// Verify risk configuration is created
	riskConfigIDs := outputStringList(s.T(), options, "risk_configuration_ids")
	assert.Equal(s.T(), 1, len(riskConfigIDs))
	assert.NotEmpty(s.T(), riskConfigIDs[0])

	// Verify risk configuration map output
	riskConfigIDsMap := outputStringMap(s.T(), options, "risk_configuration_ids_map")
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
	userPoolID := outputString(s.T(), options, "id")
	assert.True(s.T(), strings.HasPrefix(userPoolID, "us-east-2"))

	// Verify risk configuration is created (should be 1 global configuration)
	riskConfigIDs := outputStringList(s.T(), options, "risk_configuration_ids")
	assert.Equal(s.T(), 1, len(riskConfigIDs))
	assert.NotEmpty(s.T(), riskConfigIDs[0])

	// Verify risk configuration map output
	riskConfigIDsMap := outputStringMap(s.T(), options, "risk_configuration_ids_map")
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
	userPoolID := outputString(s.T(), options, "id")
	assert.True(s.T(), strings.HasPrefix(userPoolID, "us-east-2"))

	// Get the actual client ID from the outputs
	clientIDsMap := outputStringMap(s.T(), options, "client_ids_map")
	assert.Greater(s.T(), len(clientIDsMap), 0)

	// Get the actual client ID for "test-client" (from the fixture)
	actualClientID, exists := clientIDsMap["test-client"]
	assert.True(s.T(), exists, "test-client should exist in client_ids_map")
	assert.NotEmpty(s.T(), actualClientID)

	// Verify risk configuration is created
	riskConfigIDs := outputStringList(s.T(), options, "risk_configuration_ids")
	assert.Equal(s.T(), 1, len(riskConfigIDs))
	assert.NotEmpty(s.T(), riskConfigIDs[0])

	// Verify risk configuration map output contains client-specific entry with actual client ID
	riskConfigIDsMap := outputStringMap(s.T(), options, "risk_configuration_ids_map")
	assert.Equal(s.T(), 1, len(riskConfigIDsMap))
	assert.Contains(s.T(), riskConfigIDsMap, actualClientID)

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

func outputString(t *testing.T, options *atmos.Options, key string) string {
	value := outputValue(t, options, key)
	str, ok := value.(string)
	require.Truef(t, ok, "output %s should be a string, got %T", key, value)
	return str
}

func outputStringList(t *testing.T, options *atmos.Options, key string) []string {
	value := outputValue(t, options, key)
	values, ok := value.([]any)
	require.Truef(t, ok, "output %s should be a list, got %T", key, value)

	result := make([]string, 0, len(values))
	for _, item := range values {
		str, ok := item.(string)
		require.Truef(t, ok, "output %s should contain strings, got %T", key, item)
		result = append(result, str)
	}

	return result
}

func outputStringMap(t *testing.T, options *atmos.Options, key string) map[string]string {
	value := outputValue(t, options, key)
	values, ok := value.(map[string]any)
	require.Truef(t, ok, "output %s should be a map, got %T", key, value)

	result := make(map[string]string, len(values))
	for k, item := range values {
		str, ok := item.(string)
		require.Truef(t, ok, "output %s should contain string values, got %T", key, item)
		result[k] = str
	}

	return result
}

func outputValue(t *testing.T, options *atmos.Options, key string) any {
	outputs := outputAll(t, options)
	value, ok := outputs[key]
	require.Truef(t, ok, "output %s should exist", key)

	if wrapped, ok := value.(map[string]any); ok {
		if wrappedValue, ok := wrapped["value"]; ok {
			return wrappedValue
		}
	}

	return value
}

func outputAll(t *testing.T, options *atmos.Options) map[string]any {
	out, err := atmos.RunAtmosCommandAndGetStdoutE(t, options, "terraform", "output", options.Component, "--skip-init", "-s", options.Stack, "-json")
	require.NoError(t, err)

	start := strings.Index(out, "{")
	end := strings.LastIndex(out, "}")
	require.NotEqual(t, -1, start, "output should contain a JSON object")
	require.Greater(t, end, start, "output should contain a complete JSON object")

	var outputs map[string]any
	require.NoError(t, json.Unmarshal([]byte(out[start:end+1]), &outputs))
	return outputs
}
