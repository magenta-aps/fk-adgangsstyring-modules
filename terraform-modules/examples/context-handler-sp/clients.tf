# Clients that sign users in through the realm. The module creates none; add
# one per application. Keep module.context_handler_sp.client_scope in each
# client's default scopes so it gets the PrivilegeList and Serial from Context
# Handler in the userinfo.

resource "keycloak_openid_client" "my_app" {
  realm_id  = module.context_handler_sp.realm_id
  client_id = "my-app"
  enabled   = true

  access_type           = "CONFIDENTIAL"
  standard_flow_enabled = true
  valid_redirect_uris   = ["https://my-app.example.dk/*"]
  web_origins           = ["+"]
}

# This replaces the client's default scopes, so list Keycloak's standard ones too.
resource "keycloak_openid_client_default_scopes" "my_app" {
  realm_id  = module.context_handler_sp.realm_id
  client_id = keycloak_openid_client.my_app.id
  default_scopes = [
    "basic",
    "profile",
    "email",
    "roles",
    "web-origins",
    module.context_handler_sp.client_scope,
  ]
}
