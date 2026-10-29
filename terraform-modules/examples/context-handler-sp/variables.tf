# Set these in terraform.tfvars (see terraform.tfvars.example) or through
# TF_VAR_ environment variables. Keep the secrets out of version control.

variable "keycloak_url" {
  type = string
}

variable "keycloak_client_id" {
  type = string
}

variable "keycloak_client_secret" {
  type      = string
  sensitive = true
}

variable "sp_private_key" {
  type      = string
  sensitive = true
}

variable "sp_certificate" {
  type = string
}
