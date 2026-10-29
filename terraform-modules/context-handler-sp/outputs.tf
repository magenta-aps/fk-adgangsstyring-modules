output "realm_id" {
  description = "ID of the realm, for resources added to it outside the module"
  value       = keycloak_realm.this.id
}

output "realm" {
  description = "Name of the realm"
  value       = keycloak_realm.this.realm
}

output "entity_id" {
  description = "SP entityID registered in Administrationsmodulet"
  value       = keycloak_saml_identity_provider.context_handler.entity_id
}

output "sp_metadata_url" {
  description = "SP metadata to upload to Administrationsmodulet"
  value       = local.sp_metadata_url
}

output "client_scope" {
  description = "Client scope that puts the PrivilegeList and Serial in the userinfo. Add it to each client's default scopes"
  value       = keycloak_openid_client_scope.context_handler.name
}
