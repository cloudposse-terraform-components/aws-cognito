data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  # Helper function to check if a configuration object has meaningful content
  has_account_takeover_config = length(coalesce(var.account_takeover_risk_configuration, {})) > 0 && (
    lookup(var.account_takeover_risk_configuration, "actions", null) != null ||
    lookup(var.account_takeover_risk_configuration, "notify_configuration", null) != null
  )

  has_compromised_credentials_config = length(coalesce(var.compromised_credentials_risk_configuration, {})) > 0 && (
    lookup(var.compromised_credentials_risk_configuration, "actions", null) != null ||
    lookup(var.compromised_credentials_risk_configuration, "event_filter", null) != null
  )

  has_risk_exception_config = length(coalesce(var.risk_exception_configuration, {})) > 0 && (
    length(coalesce(lookup(var.risk_exception_configuration, "blocked_ip_range_list", null), [])) > 0 ||
    length(coalesce(lookup(var.risk_exception_configuration, "skipped_ip_range_list", null), [])) > 0
  )



  # Create a map of client names to client IDs for lookups
  client_name_to_id_map = local.enabled ? { for _, v in aws_cognito_user_pool_client.client : v.name => v.id } : {}

  # Default configuration using individual variables (only if they have meaningful content)
  risk_configuration_default = local.has_account_takeover_config || local.has_compromised_credentials_config || local.has_risk_exception_config ? {
    client_id                                  = var.risk_configuration_client_id
    client_name                                = null # Default config uses client_id directly
    account_takeover_risk_configuration        = local.has_account_takeover_config ? var.account_takeover_risk_configuration : null
    compromised_credentials_risk_configuration = local.has_compromised_credentials_config ? var.compromised_credentials_risk_configuration : null
    risk_exception_configuration               = local.has_risk_exception_config ? var.risk_exception_configuration : null
  } : null

  # Process provided configurations - only include configurations that have meaningful content
  # Store client_name alongside other config for later resolution in resource block
  risk_configurations_provided = [for config in var.risk_configurations : {
    client_id   = lookup(config, "client_id", null)
    client_name = lookup(config, "client_name", null)
    account_takeover_risk_configuration = try(
      length(coalesce(lookup(config, "account_takeover_risk_configuration", null), {})) > 0
      ? coalesce(lookup(config, "account_takeover_risk_configuration", null), {})
      : null,
      null
    )
    compromised_credentials_risk_configuration = try(
      length(coalesce(lookup(config, "compromised_credentials_risk_configuration", null), {})) > 0
      ? coalesce(lookup(config, "compromised_credentials_risk_configuration", null), {})
      : null,
      null
    )
    risk_exception_configuration = try(
      length(coalesce(lookup(config, "risk_exception_configuration", null), {})) > 0
      ? coalesce(lookup(config, "risk_exception_configuration", null), {})
      : null,
      null
    )
    } if(
    try(length(coalesce(lookup(config, "account_takeover_risk_configuration", null), {})) > 0, false) ||
    try(length(coalesce(lookup(config, "compromised_credentials_risk_configuration", null), {})) > 0, false) ||
    try(length(coalesce(lookup(config, "risk_exception_configuration", null), {})) > 0, false)
  )]

  # Determine final configuration list
  risk_configurations = length(var.risk_configurations) == 0 && local.risk_configuration_default != null ? [local.risk_configuration_default] : local.risk_configurations_provided
}

resource "aws_cognito_risk_configuration" "risk_config" {
  count = local.enabled ? length(local.risk_configurations) : 0

  user_pool_id = one(aws_cognito_user_pool.pool[*].id)
  # Resolve client_name to client_id if needed, otherwise use provided client_id
  # Returns null when resolution fails (zero or multiple matches) - lifecycle precondition validates correctness
  client_id = coalesce(
    lookup(element(local.risk_configurations, count.index), "client_id", null),
    try(
      lookup(
        local.client_name_to_id_map,
        lookup(element(local.risk_configurations, count.index), "client_name", null),
        null
      ),
      null
    )
  )

  # Validation for client_name resolution
  lifecycle {
    # Validate that if client_name is provided, it resolves to exactly one valid client_id
    precondition {
      condition = (
        lookup(element(local.risk_configurations, count.index), "client_name", null) == null ||
        lookup(element(local.risk_configurations, count.index), "client_id", null) != null ||
        length([
          for client in aws_cognito_user_pool_client.client :
          client.id if client.name == lookup(element(local.risk_configurations, count.index), "client_name", null)
        ]) == 1
      )
      error_message = "When client_name is specified in risk_configurations, it must match exactly one existing client name. Found ${length([for client in aws_cognito_user_pool_client.client : client.id if client.name == lookup(element(local.risk_configurations, count.index), "client_name", null)])} matches for client_name '${coalesce(lookup(element(local.risk_configurations, count.index), "client_name", null), "unknown")}', expected exactly 1."
    }

    # Validation for account takeover risk configuration
    precondition {
      condition = lookup(element(local.risk_configurations, count.index), "account_takeover_risk_configuration", null) == null || (
        # If account_takeover_risk_configuration is present, actions must be provided
        lookup(lookup(element(local.risk_configurations, count.index), "account_takeover_risk_configuration", {}), "actions", null) != null && (
          # At least one action must be defined
          lookup(lookup(lookup(element(local.risk_configurations, count.index), "account_takeover_risk_configuration", {}), "actions", {}), "high_action", null) != null ||
          lookup(lookup(lookup(element(local.risk_configurations, count.index), "account_takeover_risk_configuration", {}), "actions", {}), "medium_action", null) != null ||
          lookup(lookup(lookup(element(local.risk_configurations, count.index), "account_takeover_risk_configuration", {}), "actions", {}), "low_action", null) != null
          ) && (
          # Each defined action must have event_action and notify
          (lookup(lookup(lookup(element(local.risk_configurations, count.index), "account_takeover_risk_configuration", {}), "actions", {}), "high_action", null) == null || (
            lookup(lookup(lookup(lookup(element(local.risk_configurations, count.index), "account_takeover_risk_configuration", {}), "actions", {}), "high_action", {}), "event_action", null) != null &&
            lookup(lookup(lookup(lookup(element(local.risk_configurations, count.index), "account_takeover_risk_configuration", {}), "actions", {}), "high_action", {}), "notify", null) != null
          )) &&
          (lookup(lookup(lookup(element(local.risk_configurations, count.index), "account_takeover_risk_configuration", {}), "actions", {}), "medium_action", null) == null || (
            lookup(lookup(lookup(lookup(element(local.risk_configurations, count.index), "account_takeover_risk_configuration", {}), "actions", {}), "medium_action", {}), "event_action", null) != null &&
            lookup(lookup(lookup(lookup(element(local.risk_configurations, count.index), "account_takeover_risk_configuration", {}), "actions", {}), "medium_action", {}), "notify", null) != null
          )) &&
          (lookup(lookup(lookup(element(local.risk_configurations, count.index), "account_takeover_risk_configuration", {}), "actions", {}), "low_action", null) == null || (
            lookup(lookup(lookup(lookup(element(local.risk_configurations, count.index), "account_takeover_risk_configuration", {}), "actions", {}), "low_action", {}), "event_action", null) != null &&
            lookup(lookup(lookup(lookup(element(local.risk_configurations, count.index), "account_takeover_risk_configuration", {}), "actions", {}), "low_action", {}), "notify", null) != null
          ))
        )
      )
      error_message = "When account_takeover_risk_configuration is present, it must have an 'actions' block with at least one of high_action, medium_action, or low_action defined. Each action must include both 'event_action' and 'notify' fields."
    }

    precondition {
      condition = lookup(element(local.risk_configurations, count.index), "account_takeover_risk_configuration", null) == null || (
        # If any action has notify = true, notify_configuration must be provided with required fields
        !(
          lookup(lookup(lookup(lookup(element(local.risk_configurations, count.index), "account_takeover_risk_configuration", {}), "actions", {}), "high_action", {}), "notify", false) == true ||
          lookup(lookup(lookup(lookup(element(local.risk_configurations, count.index), "account_takeover_risk_configuration", {}), "actions", {}), "medium_action", {}), "notify", false) == true ||
          lookup(lookup(lookup(lookup(element(local.risk_configurations, count.index), "account_takeover_risk_configuration", {}), "actions", {}), "low_action", {}), "notify", false) == true
          ) || (
          # notify_configuration must be provided with source_arn when notifications are enabled
          lookup(lookup(element(local.risk_configurations, count.index), "account_takeover_risk_configuration", {}), "notify_configuration", null) != null &&
          lookup(lookup(lookup(element(local.risk_configurations, count.index), "account_takeover_risk_configuration", {}), "notify_configuration", {}), "source_arn", null) != null &&
          # enforce SES ARN belongs to this account & region
          can(regex(
            "^arn:[^:]*:ses:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:.+$",
            lookup(
              lookup(
                lookup(element(local.risk_configurations, count.index), "account_takeover_risk_configuration", {}),
                "notify_configuration", {}
              ),
              "source_arn", ""
            )
          ))
        )
      )
      error_message = "When any action has notify = true, notify_configuration must be provided with a valid SES source_arn in this account and region."
    }

    # Validation for compromised credentials risk configuration
    precondition {
      condition = lookup(element(local.risk_configurations, count.index), "compromised_credentials_risk_configuration", null) == null || (
        # If compromised_credentials_risk_configuration is present, actions must be provided with event_action
        lookup(lookup(element(local.risk_configurations, count.index), "compromised_credentials_risk_configuration", {}), "actions", null) != null &&
        lookup(lookup(lookup(element(local.risk_configurations, count.index), "compromised_credentials_risk_configuration", {}), "actions", {}), "event_action", null) != null
      )
      error_message = "When compromised_credentials_risk_configuration is present, an 'actions' block with 'event_action' is required. AWS requires this field to specify how to handle compromised credentials (BLOCK or NO_ACTION)."
    }

    # Validation for risk exception configuration
    precondition {
      condition = lookup(element(local.risk_configurations, count.index), "risk_exception_configuration", null) == null || (
        length(coalesce(lookup(lookup(element(local.risk_configurations, count.index), "risk_exception_configuration", {}), "blocked_ip_range_list", null), [])) > 0 ||
        length(coalesce(lookup(lookup(element(local.risk_configurations, count.index), "risk_exception_configuration", {}), "skipped_ip_range_list", null), [])) > 0
      )
      error_message = "When risk_exception_configuration is present, at least one of blocked_ip_range_list or skipped_ip_range_list must contain ≥1 CIDR."
    }

    precondition {
      condition = lookup(element(local.risk_configurations, count.index), "risk_exception_configuration", null) == null || (
        length(coalesce(lookup(lookup(element(local.risk_configurations, count.index), "risk_exception_configuration", {}), "blocked_ip_range_list", null), [])) <= 200 &&
        length(coalesce(lookup(lookup(element(local.risk_configurations, count.index), "risk_exception_configuration", {}), "skipped_ip_range_list", null), [])) <= 200
      )
      error_message = "AWS allows up to 200 CIDRs per list in risk_exception_configuration."
    }
  }

  dynamic "account_takeover_risk_configuration" {
    for_each = lookup(element(local.risk_configurations, count.index), "account_takeover_risk_configuration", null) != null && length(lookup(element(local.risk_configurations, count.index), "account_takeover_risk_configuration", {})) > 0 ? [lookup(element(local.risk_configurations, count.index), "account_takeover_risk_configuration", {})] : []

    content {
      dynamic "notify_configuration" {
        # AWS requires notify_configuration block when account_takeover_risk_configuration is present
        # Create it if provided in configuration
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

          # Since notify_configuration block only exists when notifications are enabled,
          # from and source_arn are always provided from the configuration
          from       = lookup(notify_configuration.value, "from", null)
          reply_to   = lookup(notify_configuration.value, "reply_to", null)
          source_arn = lookup(notify_configuration.value, "source_arn", null)
        }
      }

      dynamic "actions" {
        # AWS requires actions when account_takeover_risk_configuration is present
        # Always emit actions block, default to empty object if not provided
        for_each = [lookup(account_takeover_risk_configuration.value, "actions", {})]

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
