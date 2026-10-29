# Keycloak drops user attributes the user profile doesn't declare, so cvr, serial
# and the PrivilegeList attribute are declared here. Email is optional, as in the
# token profile; otherwise first broker login stops and asks the user for one.
resource "keycloak_realm_user_profile" "this" {
  realm_id = keycloak_realm.this.id

  attribute {
    name         = "username"
    display_name = "$${username}"
    permissions {
      view = ["admin", "user"]
      edit = ["admin", "user"]
    }
    validator {
      name   = "length"
      config = { min = "3", max = "255" }
    }
    validator { name = "username-prohibited-characters" }
    validator { name = "up-username-not-idn-homograph" }
  }

  attribute {
    name         = "email"
    display_name = "$${email}"
    permissions {
      view = ["admin", "user"]
      edit = ["admin", "user"]
    }
    validator { name = "email" }
    validator {
      name   = "length"
      config = { max = "255" }
    }
  }

  attribute {
    name         = "firstName"
    display_name = "$${firstName}"
    permissions {
      view = ["admin", "user"]
      edit = ["admin", "user"]
    }
    validator {
      name   = "length"
      config = { max = "255" }
    }
    validator { name = "person-name-prohibited-characters" }
  }

  attribute {
    name         = "lastName"
    display_name = "$${lastName}"
    permissions {
      view = ["admin", "user"]
      edit = ["admin", "user"]
    }
    validator {
      name   = "length"
      config = { max = "255" }
    }
    validator { name = "person-name-prohibited-characters" }
  }

  attribute {
    name         = "cvr"
    display_name = "CVR"
    permissions {
      view = ["admin"]
      edit = ["admin"]
    }
  }

  attribute {
    name         = "serial"
    display_name = "Serial"
    permissions {
      view = ["admin"]
      edit = ["admin"]
    }
  }

  attribute {
    name         = var.privilege_list_attribute
    display_name = "SSO PrivilegeList (Base64 encoded)"
    group        = "user-metadata"
    permissions {
      view = ["admin"]
      edit = ["admin"]
    }
  }

  group {
    name                = "user-metadata"
    display_header      = "User metadata"
    display_description = "Attributes, which refer to user metadata"
  }
}
