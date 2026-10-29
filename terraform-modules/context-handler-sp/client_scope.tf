# Applications authorize on the PrivilegeList Context Handler sent and identify
# the user by its Serial, so both are offered as a client scope that puts them
# in the userinfo. Each application's client, whatever its type, adds this
# scope to its default scopes.
resource "keycloak_openid_client_scope" "context_handler" {
  realm_id               = keycloak_realm.this.id
  name                   = "context-handler"
  description            = "PrivilegeList and Serial from KOMBIT Context Handler, in the ${var.privilege_list_attribute} and serial userinfo claims"
  include_in_token_scope = false
}

moved {
  from = keycloak_openid_client_scope.privilege_list
  to   = keycloak_openid_client_scope.context_handler
}

resource "keycloak_openid_user_attribute_protocol_mapper" "privilege_list" {
  realm_id        = keycloak_realm.this.id
  client_scope_id = keycloak_openid_client_scope.context_handler.id
  name            = var.privilege_list_attribute

  user_attribute      = var.privilege_list_attribute
  claim_name          = var.privilege_list_attribute
  claim_value_type    = "String"
  add_to_id_token     = false
  add_to_access_token = false
  add_to_userinfo     = true
}

resource "keycloak_openid_user_attribute_protocol_mapper" "serial" {
  realm_id        = keycloak_realm.this.id
  client_scope_id = keycloak_openid_client_scope.context_handler.id
  name            = "serial"

  user_attribute      = "serial"
  claim_name          = "serial"
  claim_value_type    = "String"
  add_to_id_token     = false
  add_to_access_token = false
  add_to_userinfo     = true
}
