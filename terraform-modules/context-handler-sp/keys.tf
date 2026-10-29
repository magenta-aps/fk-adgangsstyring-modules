# The OCES3 system certificate registered for this SP in KOMBIT's
# Administrationsmodul. Keycloak puts it in the SP metadata, signs
# AuthnRequests with it and decrypts Context Handler's assertions with it.
# Priority is above the generated keys' 100 so these are the ones used.

resource "keycloak_realm_keystore_rsa" "signing" {
  name        = "kombit-sp-oces3-signing"
  realm_id    = keycloak_realm.this.id
  private_key = var.sp_private_key
  certificate = var.sp_certificate
  provider_id = "rsa"
  algorithm   = "RS256"
  priority    = 200
}

resource "keycloak_realm_keystore_rsa" "encryption" {
  name        = "kombit-sp-oces3-encryption"
  realm_id    = keycloak_realm.this.id
  private_key = var.sp_private_key
  certificate = var.sp_certificate
  provider_id = "rsa-enc"
  algorithm   = "RSA-OAEP"
  priority    = 200
}

# Keycloak creates rsa-generated and rsa-enc-generated keys with every realm
# and lists every enabled RSA key in the SP metadata. Administrationsmodulet
# rejects metadata with more than one signing and one encryption certificate,
# and the provider can't manage rsa-enc-generated, so they are deleted through
# the admin API. Matching on providerId (the key type), never the name, means
# our imported OCES3 keys ("rsa", "rsa-enc") can't be hit. Runs once per realm.

resource "terraform_data" "remove_generated_rsa_keys" {
  triggers_replace = [keycloak_realm.this.id]

  # Our keys must exist first, or Keycloak generates fallback keys again.
  depends_on = [
    keycloak_realm_keystore_rsa.signing,
    keycloak_realm_keystore_rsa.encryption,
  ]

  provisioner "local-exec" {
    interpreter = ["bash", "-c"]
    environment = {
      KC            = var.keycloak_url
      CLIENT_ID     = var.keycloak_client_id
      CLIENT_SECRET = var.keycloak_client_secret
      REALM         = keycloak_realm.this.realm
    }
    command = <<-EOT
      set -euo pipefail
      token=$(curl -sf "$KC/realms/master/protocol/openid-connect/token" \
        -d grant_type=client_credentials -d client_id="$CLIENT_ID" \
        --data-urlencode client_secret="$CLIENT_SECRET" | jq -er .access_token)
      ids=$(curl -sf -H "Authorization: Bearer $token" \
        "$KC/admin/realms/$REALM/components?type=org.keycloak.keys.KeyProvider" |
        jq -r '.[] | select(.providerId == "rsa-generated" or .providerId == "rsa-enc-generated") | .id')
      for id in $ids; do
        echo "Deleting generated RSA key provider $id"
        curl -sf -X DELETE -H "Authorization: Bearer $token" "$KC/admin/realms/$REALM/components/$id"
      done
    EOT
  }
}

# Warns on every plan if the SP metadata holds anything but our one signing
# and one encryption certificate, whatever put it there.
check "sp_metadata" {
  data "http" "sp_descriptor" {
    url = local.sp_metadata_url
  }

  assert {
    condition = (
      length(regexall("KeyDescriptor use=\"signing\"", data.http.sp_descriptor.response_body)) == 1 &&
      length(regexall("KeyDescriptor use=\"encryption\"", data.http.sp_descriptor.response_body)) == 1 &&
      strcontains(
        replace(data.http.sp_descriptor.response_body, "/\\s/", ""),
        replace(replace(var.sp_certificate, "/-----[A-Z ]+-----/", ""), "/\\s/", "")
      )
    )
    error_message = "The SP metadata of realm ${var.realm} must hold exactly one signing and one encryption certificate, both the OCES3 certificate. Administrationsmodulet rejects anything else."
  }
}
