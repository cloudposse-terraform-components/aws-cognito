resource "aws_cognito_identity_provider" "identity_provider" {
  count = local.enabled ? length(var.identity_providers) : 0

  user_pool_id  = join("", aws_cognito_user_pool.pool[*].id)
  provider_name = lookup(element(var.identity_providers, count.index), "provider_name", null)
  provider_type = lookup(element(var.identity_providers, count.index), "provider_type", null)

  # Optional arguments
  attribute_mapping = lookup(element(var.identity_providers, count.index), "attribute_mapping", {})
  idp_identifiers   = lookup(element(var.identity_providers, count.index), "idp_identifiers", [])
  provider_details  = lookup(element(var.identity_providers, count.index), "provider_details", {})

  lifecycle {
    # For SAML providers configured via `MetadataURL`, Cognito derives and injects
    # additional `provider_details` keys that are returned by the API but are never
    # present in the input `provider_details` map: the active encryption certificate
    # and the SSO/SLO redirect binding URIs. Without ignoring them, every plan tries
    # to remove them and Cognito re-adds them, producing perpetual drift. Ignore only
    # these server-managed keys so genuine changes (e.g. `MetadataURL`) still apply.
    ignore_changes = [
      provider_details["ActiveEncryptionCertificate"],
      provider_details["SSORedirectBindingURI"],
      provider_details["SLORedirectBindingURI"],
    ]
  }
}
