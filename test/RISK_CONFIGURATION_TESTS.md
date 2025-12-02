# Risk Configuration Test Scenarios

This document describes the comprehensive test scenarios for the AWS Cognito Risk Configuration feature.

## Test Cases Overview

### 1. Empty/No Risk Configuration (`TestRiskConfigurationEmpty`)
- **Purpose**: Verify that the module works correctly when no risk configuration is provided
- **Configuration**: No risk configuration variables set
- **Expected Behavior**:
  - User Pool and clients are created successfully
  - No risk configuration resources are created
  - Risk configuration outputs return empty arrays/null values
- **Requirements Tested**: 4.1, 4.2, 4.3

### 2. Account Takeover Risk Configuration Only (`TestRiskConfigurationAccountTakeover`)
- **Purpose**: Test individual account takeover risk configuration
- **Configuration**: Only `account_takeover_risk_configuration` is set with full notify and actions configuration
- **Expected Behavior**:
  - One risk configuration resource is created
  - Configuration applies globally (no client_id specified)
  - Risk configuration outputs contain one entry mapped to "global"
- **Requirements Tested**: 1.1, 1.2, 1.3, 1.4, 4.1, 4.2

### 3. Compromised Credentials Risk Configuration Only (`TestRiskConfigurationCompromisedCredentials`)
- **Purpose**: Test individual compromised credentials risk configuration
- **Configuration**: Only `compromised_credentials_risk_configuration` is set with event filters and actions
- **Expected Behavior**:
  - One risk configuration resource is created
  - Configuration applies globally (no client_id specified)
  - Risk configuration outputs contain one entry mapped to "global"
- **Requirements Tested**: 2.1, 2.2, 2.3, 2.4, 4.1, 4.2

### 4. Risk Exception Configuration Only (`TestRiskConfigurationRiskException`)
- **Purpose**: Test individual risk exception configuration
- **Configuration**: Only `risk_exception_configuration` is set with blocked and skipped IP ranges
- **Expected Behavior**:
  - One risk configuration resource is created
  - Configuration applies globally (no client_id specified)
  - Risk configuration outputs contain one entry mapped to "global"
- **Requirements Tested**: 3.1, 3.2, 3.3, 3.4, 4.1, 4.2

### 5. Multiple Risk Configurations (`TestRiskConfigurationMultiple`)
- **Purpose**: Test object-style configuration with multiple risk types in a single configuration
- **Configuration**: Uses `risk_configurations` array with one object containing all three risk types
- **Expected Behavior**:
  - One risk configuration resource is created with all risk types
  - Configuration applies globally (no client_id specified)
  - Risk configuration outputs contain one entry mapped to "global"
- **Requirements Tested**: 4.1, 4.2, 5.1, 5.2

### 6. Client-Specific Risk Configuration (`TestRiskConfigurationClientSpecific`)
- **Purpose**: Test client-specific risk configuration using individual variables
- **Configuration**: Uses individual variables with `risk_configuration_client_id` set to target specific client
- **Expected Behavior**:
  - One risk configuration resource is created
  - Configuration applies to specific client only
  - Risk configuration outputs contain one entry mapped to the client ID
- **Requirements Tested**: 4.1, 4.2, 5.1, 5.2, 5.3

### 7. Disabled Module (`TestRiskConfigurationDisabled`)
- **Purpose**: Test that risk configuration resources are not created when module is disabled
- **Configuration**: Module `enabled` flag set to false, but risk configuration variables provided
- **Expected Behavior**:
  - No resources are created (including risk configuration)
  - All outputs return null/empty values
  - Uses the existing `VerifyEnabledFlag` test pattern
- **Requirements Tested**: 4.3, 5.4

## Test Infrastructure

### Test Fixtures
All test scenarios use dedicated YAML configuration files in `test/fixtures/stacks/catalog/usecase/`:
- `risk-config-empty.yaml`
- `risk-config-account-takeover.yaml`
- `risk-config-compromised-credentials.yaml`
- `risk-config-risk-exception.yaml`
- `risk-config-multiple.yaml`
- `risk-config-client-specific.yaml`
- `risk-config-disabled.yaml`

### Test Patterns
- Each test follows the standard module test pattern: deploy, verify, drift test, destroy
- Tests verify both basic Cognito functionality and risk configuration specific outputs
- Tests use unique domain names to avoid conflicts
- Tests include proper cleanup with defer statements

### Output Verification
Each test verifies:
- Basic User Pool creation and functionality
- Risk configuration resource creation (when expected)
- Risk configuration output arrays and maps
- Proper mapping of global vs client-specific configurations

## Running Tests

To run all risk configuration tests:
```bash
cd test
go test -v -timeout 30m
```

To run a specific test:
```bash
cd test
go test -v -timeout 30m -run TestRiskConfiguration
```

## Requirements Coverage

This test suite covers all requirements specified in the task:
- **4.1, 4.2**: Variable naming conventions and configuration patterns
- **4.3**: Global enabled flag respect
- **5.1, 5.2**: Global vs client-specific configurations
- **5.3**: Client-specific configuration scenarios
- **5.4**: Proper dependency management

The tests ensure that the risk configuration feature integrates seamlessly with the existing module while providing comprehensive security capabilities.
