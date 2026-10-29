# KOMBIT Context Handler as SAML identity provider. Its endpoints and
# certificates are read from the metadata KOMBIT publishes for brugervendte
# systemer, one file per environment in metadata/. When KOMBIT publishes new
# metadata (e.g. a new certificate), replace the file.

locals {
  idp_alias       = "context-handler"
  sp_metadata_url = "${var.keycloak_url}/realms/${keycloak_realm.this.realm}/broker/${local.idp_alias}/endpoint/descriptor"

  context_handler_metadata = file("${path.module}/metadata/${var.context_handler_environment}.xml")

  context_handler_sso_url = regex("<SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"([^\"]+)\"", local.context_handler_metadata)[0]
  context_handler_slo_url = regex("<SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"([^\"]+)\"", local.context_handler_metadata)[0]
  # During a certificate rollover the metadata lists both the old and the new
  # signing certificate, and Keycloak accepts a comma-separated list, so every
  # one is trusted until the old one is removed.
  context_handler_signing_certificates = join(",", distinct(flatten(
    regexall("use=\"signing\"(?s:.*?)<X509Certificate>([^<]+)</X509Certificate>", local.context_handler_metadata)
  )))
}

resource "keycloak_saml_identity_provider" "context_handler" {
  realm        = keycloak_realm.this.id
  alias        = local.idp_alias
  display_name = "KOMBIT Context Handler"

  # Our SP entityID. It is read from our metadata when the brugervendt system
  # is registered in Administrationsmodulet and can never be changed there.
  entity_id = "${var.keycloak_url}/realms/${keycloak_realm.this.realm}"

  single_sign_on_service_url = local.context_handler_sso_url
  single_logout_service_url  = local.context_handler_slo_url

  # The brugersystemtoken identifies the user by an X.509 DN NameID.
  name_id_policy_format = "X.509 Subject Name"

  # Context Handler requires signed AuthnRequests (RSA-SHA256), and signs and
  # encrypts its assertions.
  want_authn_requests_signed = true
  signature_algorithm        = "RSA_SHA256"
  validate_signature         = true
  signing_certificate        = local.context_handler_signing_certificates
  want_assertions_signed     = true
  want_assertions_encrypted  = true

  # Keycloak advertises the AssertionConsumerService with the AuthnRequest's
  # binding, and Context Handler needs HTTP-POST there. Logout stays Redirect.
  post_binding_authn_request = true
  post_binding_logout        = false
  post_binding_response      = true

  # Mappers update the user on every login, not only the first.
  sync_mode = "FORCE"
}
