# The KOMBIT Context Handler SP realm. Everything that makes it a Context
# Handler SP is in the context-handler-sp module; this file only sets what is
# particular to this realm.

module "context_handler_sp" {
  source = "../../context-handler-sp"

  # Part of the SP entityID, which can never be changed in Administrationsmodulet.
  realm        = "my-service"
  display_name = "My Service"

  # Which Context Handler to log in through; see context-handler-sp/metadata/.
  context_handler_environment = "exttest"

  # The OCES3 system certificate registered for the SP in Administrationsmodulet.
  sp_private_key = var.sp_private_key
  sp_certificate = var.sp_certificate

  # The module calls the admin API itself, so it needs the provider's login.
  keycloak_url           = var.keycloak_url
  keycloak_client_id     = var.keycloak_client_id
  keycloak_client_secret = var.keycloak_client_secret
}

# Upload this to Administrationsmodulet when registering the system.
output "sp_metadata_url" {
  value = module.context_handler_sp.sp_metadata_url
}
