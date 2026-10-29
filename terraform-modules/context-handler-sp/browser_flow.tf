# Context Handler is the only way in, so the browser flow skips Keycloak's
# login page: an existing session cookie is used if there is one, otherwise the
# Identity Provider Redirector sends the user straight to Context Handler.
resource "keycloak_authentication_flow" "browser" {
  realm_id    = keycloak_realm.this.id
  alias       = "browser-context-handler"
  description = "Browser flow that goes straight to KOMBIT Context Handler"
}

resource "keycloak_authentication_execution" "browser_cookie" {
  realm_id          = keycloak_realm.this.id
  parent_flow_alias = keycloak_authentication_flow.browser.alias
  authenticator     = "auth-cookie"
  requirement       = "ALTERNATIVE"
}

resource "keycloak_authentication_execution" "browser_idp_redirector" {
  realm_id          = keycloak_realm.this.id
  parent_flow_alias = keycloak_authentication_flow.browser.alias
  authenticator     = "identity-provider-redirector"
  requirement       = "ALTERNATIVE"

  # Executions are ordered by creation, and the cookie check must come first.
  depends_on = [keycloak_authentication_execution.browser_cookie]
}

resource "keycloak_authentication_execution_config" "browser_idp_redirector" {
  realm_id     = keycloak_realm.this.id
  execution_id = keycloak_authentication_execution.browser_idp_redirector.id
  alias        = "context-handler-redirector"
  config = {
    defaultProvider = keycloak_saml_identity_provider.context_handler.alias
  }
}

resource "keycloak_authentication_bindings" "this" {
  realm_id     = keycloak_realm.this.id
  browser_flow = keycloak_authentication_flow.browser.alias

  depends_on = [keycloak_authentication_execution_config.browser_idp_redirector]
}
