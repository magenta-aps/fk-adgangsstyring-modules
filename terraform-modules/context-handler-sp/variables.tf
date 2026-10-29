variable "realm" {
  description = "Name of the realm. It is part of the SP entityID, which can never be changed in Administrationsmodulet once registered"
  type        = string
}

variable "display_name" {
  description = "Display name of the realm. Defaults to the realm name"
  type        = string
  default     = null
}

variable "keycloak_url" {
  description = "Base URL of the Keycloak instance, the same as the provider's"
  type        = string
}

variable "keycloak_client_id" {
  description = "Client in the master realm that Terraform logs in as, the same as the provider's"
  type        = string
}

variable "keycloak_client_secret" {
  description = "Secret of that client, the same as the provider's"
  type        = string
  sensitive   = true
}

variable "context_handler_environment" {
  description = "Context Handler environment to log in through, one of the metadata files in metadata/ (e.g. exttest)"
  type        = string

  validation {
    condition     = fileexists("${path.module}/metadata/${var.context_handler_environment}.xml")
    error_message = "No Context Handler metadata for this environment in the module's metadata/ directory."
  }
}

variable "sp_private_key" {
  description = "PEM private key of the OCES3 system certificate registered for this SP in Administrationsmodulet"
  type        = string
  sensitive   = true
}

variable "sp_certificate" {
  description = "PEM certificate of the OCES3 system certificate registered for this SP in Administrationsmodulet"
  type        = string
}

variable "privilege_list_attribute" {
  description = "User attribute the base64 OIO-BPP PrivilegeList is stored in"
  type        = string
  default     = "sso_privilege_list"
}
