locals {
  # Helper function to check if a configuration object has meaningful content
  has_account_takeover_config = length(var.account_takeover_risk_configuration) > 0 && (
    lookup(var.account_takeover_risk_configuration, "actions", null) != null ||
    lookup(var.account_takeover_risk_configuration, "notify_configuration", null) != null
  )

  has_compromised_credentials_config = length(var.compromised_credentials_risk_configuration) > 0 && (
    lookup(var.compromised_credentials_risk_configuration, "actions", null) != null ||
    lookup(var.compromised_credentials_risk_configuration, "event_filter", null) != null
  )

  has_risk_exception_config = length(var.risk_exception_configuration) > 0 && (
    (lookup(var.risk_exception_configuration, "blocked_ip_range_list", null) != null && length(lookup(var.risk_exception_configuration, "blocked_ip_range_list", [])) > 0) ||
    (lookup(var.risk_exception_configuration, "skipped_ip_range_list", null) != null && length(lookup(var.risk_exception_configuration, "skipped_ip_range_list", [])) > 0)
  )

  # Default configuration using individual variables (only if they have meaningful content)
  risk_configuration_default = local.has_account_takeover_config || local.has_compromised_credentials_config || local.has_risk_exception_config ? {
    client_id                                  = var.risk_configuration_client_id
    account_takeover_risk_configuration        = local.has_account_takeover_config ? var.account_takeover_risk_configuration : null
    compromised_credentials_risk_configuration = local.has_compromised_credentials_config ? var.compromised_credentials_risk_configuration : null
    risk_exception_configuration               = local.has_risk_exception_config ? var.risk_exception_configuration : null
  } : null

  # Process provided configurations - only include configurations that have meaningful content
  risk_configurations_provided = [for config in var.risk_configurations : {
    client_id                                  = lookup(config, "client_id", null)
    account_takeover_risk_configuration        = length(lookup(config, "account_takeover_risk_configuration", {})) > 0 ? lookup(config, "account_takeover_risk_configuration", {}) : null
    compromised_credentials_risk_configuration = length(lookup(config, "compromised_credentials_risk_configuration", {})) > 0 ? lookup(config, "compromised_credentials_risk_configuration", {}) : null
    risk_exception_configuration               = length(lookup(config, "risk_exception_configuration", {})) > 0 ? lookup(config, "risk_exception_configuration", {}) : null
    } if(
    length(lookup(config, "account_takeover_risk_configuration", {})) > 0 ||
    length(lookup(config, "compromised_credentials_risk_configuration", {})) > 0 ||
    length(lookup(config, "risk_exception_configuration", {})) > 0
  )]

  # Determine final configuration list
  risk_configurations = length(var.risk_configurations) == 0 && local.risk_configuration_default != null ? [local.risk_configuration_default] : local.risk_configurations_provided
}

resource "aws_cognito_risk_configuration" "risk_config" {
  count = local.enabled ? length(local.risk_configurations) : 0

  user_pool_id = join("", aws_cognito_user_pool.pool[*].id)
  client_id    = lookup(element(local.risk_configurations, count.index), "client_id", null)

  dynamic "account_takeover_risk_configuration" {
    for_each = lookup(element(local.risk_configurations, count.index), "account_takeover_risk_configuration", null) != null && length(lookup(element(local.risk_configurations, count.index), "account_takeover_risk_configuration", {})) > 0 ? [lookup(element(local.risk_configurations, count.index), "account_takeover_risk_configuration", {})] : []

    content {
      dynamic "notify_configuration" {
        # AWS requires notify_configuration when account_takeover_risk_configuration is present
        for_each = lookup(account_takeover_risk_configuration.value, "notify_configuration", null) != null ? [lookup(account_takeover_risk_configuration.value, "notify_configuration", {})] : []

        content {
          dynamic "block_email" {
            for_each = lookup(notify_configuration.value, "block_email", null) != null ? [lookup(notify_configuration.value, "block_email", {})] : []

            content {
              html_body = lookup(block_email.value, "html_body", null)
              subject   = lookup(block_email.value, "subject", null)
              text_body = lookup(block_email.value, "text_body", null)
            }
          }

          dynamic "mfa_email" {
            for_each = lookup(notify_configuration.value, "mfa_email", null) != null ? [lookup(notify_configuration.value, "mfa_email", {})] : []

            content {
              html_body = lookup(mfa_email.value, "html_body", null)
              subject   = lookup(mfa_email.value, "subject", null)
              text_body = lookup(mfa_email.value, "text_body", null)
            }
          }

          dynamic "no_action_email" {
            for_each = lookup(notify_configuration.value, "no_action_email", null) != null ? [lookup(notify_configuration.value, "no_action_email", {})] : []

            content {
              html_body = lookup(no_action_email.value, "html_body", null)
              subject   = lookup(no_action_email.value, "subject", null)
              text_body = lookup(no_action_email.value, "text_body", null)
            }
          }

          from       = lookup(notify_configuration.value, "from", null)
          reply_to   = lookup(notify_configuration.value, "reply_to", null)
          source_arn = lookup(notify_configuration.value, "source_arn", null)
        }
      }

      dynamic "actions" {
        # AWS requires actions when account_takeover_risk_configuration is present
        for_each = lookup(account_takeover_risk_configuration.value, "actions", null) != null ? [lookup(account_takeover_risk_configuration.value, "actions", {})] : []

        content {
          dynamic "high_action" {
            for_each = lookup(actions.value, "high_action", null) != null ? [lookup(actions.value, "high_action", {})] : []

            content {
              event_action = lookup(high_action.value, "event_action", null)
              notify       = lookup(high_action.value, "notify", null)
            }
          }

          dynamic "medium_action" {
            for_each = lookup(actions.value, "medium_action", null) != null ? [lookup(actions.value, "medium_action", {})] : []

            content {
              event_action = lookup(medium_action.value, "event_action", null)
              notify       = lookup(medium_action.value, "notify", null)
            }
          }

          dynamic "low_action" {
            for_each = lookup(actions.value, "low_action", null) != null ? [lookup(actions.value, "low_action", {})] : []

            content {
              event_action = lookup(low_action.value, "event_action", null)
              notify       = lookup(low_action.value, "notify", null)
            }
          }
        }
      }
    }
  }

  dynamic "compromised_credentials_risk_configuration" {
    for_each = lookup(element(local.risk_configurations, count.index), "compromised_credentials_risk_configuration", null) != null && length(lookup(element(local.risk_configurations, count.index), "compromised_credentials_risk_configuration", {})) > 0 ? [lookup(element(local.risk_configurations, count.index), "compromised_credentials_risk_configuration", {})] : []

    content {
      event_filter = lookup(compromised_credentials_risk_configuration.value, "event_filter", null)

      dynamic "actions" {
        # AWS requires actions when compromised_credentials_risk_configuration is present
        for_each = lookup(compromised_credentials_risk_configuration.value, "actions", null) != null ? [lookup(compromised_credentials_risk_configuration.value, "actions", {})] : []

        content {
          event_action = lookup(actions.value, "event_action", null)
        }
      }
    }
  }

  # Risk exception configuration for IP-based overrides
  # Supports blocked and skipped IP ranges in CIDR notation
  # AWS limits: Maximum 200 IP ranges per list
  # AWS requires at least one of blocked_ip_range_list or skipped_ip_range_list
  dynamic "risk_exception_configuration" {
    for_each = lookup(element(local.risk_configurations, count.index), "risk_exception_configuration", null) != null && length(lookup(element(local.risk_configurations, count.index), "risk_exception_configuration", {})) > 0 && (
      lookup(lookup(element(local.risk_configurations, count.index), "risk_exception_configuration", {}), "blocked_ip_range_list", null) != null ||
      lookup(lookup(element(local.risk_configurations, count.index), "risk_exception_configuration", {}), "skipped_ip_range_list", null) != null
    ) ? [lookup(element(local.risk_configurations, count.index), "risk_exception_configuration", {})] : []

    content {
      # IP ranges that should always be blocked (CIDR notation, max 200 items)
      # Example: ["192.168.1.0/24", "10.0.0.0/8"]
      blocked_ip_range_list = lookup(risk_exception_configuration.value, "blocked_ip_range_list", null)

      # IP ranges that should bypass risk detection (CIDR notation, max 200 items)
      # Example: ["203.0.113.0/24", "198.51.100.0/24"]
      skipped_ip_range_list = lookup(risk_exception_configuration.value, "skipped_ip_range_list", null)
    }
  }

  depends_on = [
    aws_cognito_user_pool.pool,
    aws_cognito_user_pool_client.client
  ]
}
