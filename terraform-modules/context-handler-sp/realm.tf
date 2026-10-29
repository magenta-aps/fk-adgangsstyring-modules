# A realm that is a SAML SP for KOMBIT's Context Handler.

resource "keycloak_realm" "this" {
  realm        = var.realm
  enabled      = true
  display_name = coalesce(var.display_name, var.realm)
  ssl_required = "external"

  # Keycloak sets this on the realm, and clearing it doesn't stick. The login
  # page is skipped (see browser_flow.tf), so the theme is rarely seen.
  login_theme = "keycloak"
}
