# Users are created from Context Handler's brugersystemtoken. The mappers below
# come from the oiosaml3-mappers JAR (kombit-context-handler-keycloak-mappers-
# and-docs), which must be installed in Keycloak's providers/ directory.
# All run with sync mode FORCE so changes (e.g. a new name) arrive on every
# login, not only the first.

# subject-to-broker-id keys the identity-provider link, so a returning user is
# found by <CVR>_<Serial> and survives a change of name. Changing it orphans
# every existing link; delete or relink those users when it changes.
resource "keycloak_custom_identity_provider_mapper" "subject_to_broker_id" {
  realm                    = keycloak_realm.this.id
  identity_provider_alias  = keycloak_saml_identity_provider.context_handler.alias
  name                     = "subject-to-broker-id"
  identity_provider_mapper = "oiosaml3-subject-idp-mapper"
  extra_config = {
    syncMode = "FORCE"
    target   = "Broker user ID"
  }
}

resource "keycloak_custom_identity_provider_mapper" "subject_to_username" {
  realm                    = keycloak_realm.this.id
  identity_provider_alias  = keycloak_saml_identity_provider.context_handler.alias
  name                     = "subject-to-username"
  identity_provider_mapper = "oiosaml3-subject-idp-mapper"
  extra_config = {
    syncMode = "FORCE"
    target   = "Local username"
  }
}

resource "keycloak_custom_identity_provider_mapper" "cn_to_first_name" {
  realm                    = keycloak_realm.this.id
  identity_provider_alias  = keycloak_saml_identity_provider.context_handler.alias
  name                     = "cn-to-first-name"
  identity_provider_mapper = "oiosaml3-dn-idp-mapper"
  extra_config = {
    syncMode          = "FORCE"
    "dn.component"    = "CN"
    target            = "First name"
    "value.transform" = "First word"
  }
}

resource "keycloak_custom_identity_provider_mapper" "cn_to_last_name" {
  realm                    = keycloak_realm.this.id
  identity_provider_alias  = keycloak_saml_identity_provider.context_handler.alias
  name                     = "cn-to-last-name"
  identity_provider_mapper = "oiosaml3-dn-idp-mapper"
  extra_config = {
    syncMode          = "FORCE"
    "dn.component"    = "CN"
    target            = "Last name"
    "value.transform" = "All but first word"
  }
}

resource "keycloak_custom_identity_provider_mapper" "o_to_cvr" {
  realm                    = keycloak_realm.this.id
  identity_provider_alias  = keycloak_saml_identity_provider.context_handler.alias
  name                     = "o-to-cvr"
  identity_provider_mapper = "oiosaml3-dn-idp-mapper"
  extra_config = {
    syncMode         = "FORCE"
    "dn.component"   = "O"
    target           = "User attribute"
    "user.attribute" = "cvr"
  }
}

# Serial is the user's ID within the authority, unique only together with CVR.
resource "keycloak_custom_identity_provider_mapper" "serial_to_serial" {
  realm                    = keycloak_realm.this.id
  identity_provider_alias  = keycloak_saml_identity_provider.context_handler.alias
  name                     = "serial-to-serial"
  identity_provider_mapper = "oiosaml3-dn-idp-mapper"
  extra_config = {
    syncMode         = "FORCE"
    "dn.component"   = "Serial"
    target           = "User attribute"
    "user.attribute" = "serial"
  }
}

# The OIO-BPP PrivilegeList (user system roles per authority) is stored as is,
# base64 and all, for the application to decode and read scope and
# constraints from. Name format unspecified, as on the hand-configured realm
# where the import works.
resource "keycloak_attribute_importer_identity_provider_mapper" "privileges" {
  realm                   = keycloak_realm.this.id
  identity_provider_alias = keycloak_saml_identity_provider.context_handler.alias
  name                    = "privileges"
  attribute_name          = "https://data.gov.dk/model/core/eid/privilegesIntermediate"
  user_attribute          = var.privilege_list_attribute
  extra_config = {
    syncMode                = "FORCE"
    "attribute.name.format" = "ATTRIBUTE_FORMAT_UNSPECIFIED"
  }
}
