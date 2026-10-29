# The Keycloak server the realm is created on, and the client in its master
# realm that Terraform logs in as (client credentials grant).

provider "keycloak" {
  url           = var.keycloak_url
  realm         = "master"
  client_id     = var.keycloak_client_id
  client_secret = var.keycloak_client_secret
}
