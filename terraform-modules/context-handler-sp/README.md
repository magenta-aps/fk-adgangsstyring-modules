# context-handler-sp

A Terraform module that creates a Keycloak realm ready for KOMBIT's Context
Handler. The realm is a SAML service provider (SP) for Context Handler:
users log in through it, Keycloak creates them from the brugersystemtoken,
and applications in the realm read the user's PrivilegeList and Serial from
the userinfo.

One module call gives one realm. Your own configuration adds the clients for
your applications (see [Connect an application](#connect-an-application)).

```
 Application ──OIDC──► Keycloak realm (this module) ──SAML──► Context Handler
                       ├─ identity provider "context-handler"
                       ├─ OCES3 signing + encryption keys
                       ├─ browser flow straight to Context Handler
                       ├─ mappers: CN, O, Serial, PrivilegeList → user
                       └─ client scope "context-handler" → userinfo claims
```

## What it creates

| File                   | Creates                                                                                                                                                               |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `realm.tf`             | The realm                                                                                                                                                             |
| `identity_provider.tf` | The SAML identity provider `context-handler`, configured from the KOMBIT metadata in `metadata/`                                                                      |
| `keys.tf`              | Signing and encryption keys from your OCES3 system certificate. Removes Keycloak's generated RSA keys, and checks on every plan that the SP metadata holds only yours |
| `browser_flow.tf`      | A browser flow that skips Keycloak's login page and sends the user to Context Handler                                                                                 |
| `mappers.tf`           | Identity-provider mappers that set username, first and last name, `cvr`, `serial` and the PrivilegeList on the user                                                   |
| `user_profile.tf`      | The user profile, which declares `cvr`, `serial` and the PrivilegeList attribute so Keycloak keeps them                                                               |
| `client_scope.tf`      | The client scope `context-handler`, which puts the PrivilegeList and `serial` in the userinfo                                                                         |

## Prerequisites

- **The OIOSAML3 mappers JAR** installed in Keycloak's `providers/`
  directory. The mappers in `mappers.tf` come from it, and the apply fails
  without it. See [`oiosaml3-keycloak-mappers`](../../oiosaml3-keycloak-mappers/README.md#install-in-keycloak).
- **An OCES3 system certificate** (private key and certificate in PEM) for
  this SP. It's the certificate you register in Administrationsmodulet.
  OCES3 certificates come as a password-protected `.p12`; split it with
  [`scripts/split-p12.sh`](../../scripts/README.md#split-p12sh):
  ```sh
  scripts/split-p12.sh my-system.p12 secrets/oces3
  ```
  This writes `secrets/oces3.crt` and `secrets/oces3.key`, and checks that
  they belong together. Use the `.crt`, not `oces3.chain.crt` if one is
  written: the SP metadata must hold only the system certificate itself.
- **A Keycloak client Terraform can log in as**: a confidential client in the
  `master` realm with the service-account `admin` role. Both the `keycloak`
  provider and the module use it, since `keys.tf` calls the admin API
  directly.
- **`bash`, `curl` and `jq`** on the machine that runs Terraform, for the
  key cleanup in `keys.tf`.
- **Context Handler metadata** for your environment in `metadata/`. The
  module ships with `exttest.xml` (see
  [Add a Context Handler environment](#add-a-context-handler-environment)).

## Usage

Copy the `context-handler-sp/` folder, including `metadata/`, into your
Terraform project, for example as `modules/context-handler-sp/`. Then call
it:

```hcl
terraform {
  required_providers {
    keycloak = {
      source = "keycloak/keycloak"
    }
  }
}

provider "keycloak" {
  url           = var.keycloak_url
  realm         = "master"
  client_id     = var.keycloak_client_id
  client_secret = var.keycloak_client_secret
}

module "context_handler_sp" {
  source = "./modules/context-handler-sp"

  realm                       = "my-service"
  display_name                = "My Service"
  context_handler_environment = "exttest"

  # From scripts/split-p12.sh, see Prerequisites.
  sp_private_key = file("secrets/oces3.key")
  sp_certificate = file("secrets/oces3.crt")

  # The module calls the admin API itself, so it needs the provider's login.
  keycloak_url           = var.keycloak_url
  keycloak_client_id     = var.keycloak_client_id
  keycloak_client_secret = var.keycloak_client_secret
}
```

Keep the private key out of version control. Read it from a file that is
ignored, or pass it in through a `TF_VAR_` environment variable.

For a complete configuration with the provider, the module and a client, see
[`examples/context-handler-sp`](../examples/context-handler-sp/).

### Inputs

| Name                          | Required | Description                                                                                                                                                  |
| ----------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `realm`                       | yes      | Realm name. It becomes part of the SP entityID, which **can never be changed** in Administrationsmodulet once registered. Choose it carefully.             |
| `display_name`                | no       | Display name of the realm. Defaults to `realm`.                                                                                                              |
| `context_handler_environment` | yes      | Name of a file in `metadata/` without `.xml`, e.g. `exttest`.                                                                                                |
| `sp_private_key`              | yes      | PEM private key of the OCES3 system certificate: the `.key` from `scripts/split-p12.sh`.                                                                     |
| `sp_certificate`              | yes      | PEM certificate of the OCES3 system certificate: the `.crt` from `scripts/split-p12.sh`.                                                                     |
| `keycloak_url`                | yes      | Base URL of Keycloak, the same as the provider's `url`.                                                                                                      |
| `keycloak_client_id`          | yes      | The provider's `client_id`.                                                                                                                                  |
| `keycloak_client_secret`      | yes      | The provider's `client_secret`.                                                                                                                              |
| `privilege_list_attribute`    | no       | User attribute and userinfo claim that hold the base64 PrivilegeList. Defaults to `sso_privilege_list`.                                                      |

### Outputs

| Name              | Description                                                         |
| ----------------- | ------------------------------------------------------------------- |
| `realm_id`        | Realm ID, for resources you add to the realm yourself               |
| `realm`           | Realm name                                                          |
| `entity_id`       | SP entityID, as registered in Administrationsmodulet                |
| `sp_metadata_url` | URL of the SP metadata to upload to Administrationsmodulet          |
| `client_scope`    | Name of the client scope to add to each application's default scopes |

## Register the SP with KOMBIT

After the first `terraform apply`:

1. Download the SP metadata from the `sp_metadata_url` output
   (`terraform output -raw sp_metadata_url`).
2. Upload it when you create the brugervendt system in KOMBIT's
   Administrationsmodul. KOMBIT reads the entityID and the OCES3 certificate
   from it.

Administrationsmodulet rejects metadata with more than one signing and one
encryption certificate. The module removes Keycloak's generated keys for
that reason, and the `sp_metadata` check warns on every plan if the
metadata holds anything else.

## Connect an application

The module creates no clients. Add one for each application in your own
configuration, and give it the `client_scope` output as a default scope:

```hcl
resource "keycloak_openid_client" "my_app" {
  realm_id              = module.context_handler_sp.realm_id
  client_id             = "my-app"
  access_type           = "CONFIDENTIAL"
  standard_flow_enabled = true
  valid_redirect_uris   = ["https://my-app.example.dk/*"]
}

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
```

`keycloak_openid_client_default_scopes` replaces the client's default
scopes, so list Keycloak's standard ones too.

The application then gets two extra claims from the userinfo endpoint (not
in the ID or access token):

- `sso_privilege_list`: the OIO-BPP PrivilegeList, base64-encoded as Context
  Handler sent it. The application decodes it and reads the user system
  roles, scopes and constraints.
- `serial`: the user's ID within the authority. It's unique only together
  with the CVR number.

The Keycloak username is `<CVR>_<Serial>`.

## Add a Context Handler environment

KOMBIT publishes Context Handler metadata for brugervendte systemer per
environment. To add one, save its metadata as `metadata/<name>.xml` and set
`context_handler_environment = "<name>"`. The module reads the endpoints and
signing certificates from the file.

When KOMBIT publishes new metadata, e.g. for a certificate rollover, replace
the file and apply. During a rollover the metadata lists both certificates,
and the module trusts both until the old one is removed.

## Things to know

- **Changing `realm` creates a new SP.** The entityID changes, and the realm
  must be registered in Administrationsmodulet again.
- **Changing the OCES3 certificate** means uploading the SP metadata to
  Administrationsmodulet again.
- **The `subject-to-broker-id` mapper links returning users** by
  `<CVR>_<Serial>`. If you change it, existing users lose their link to
  Context Handler and must be deleted or relinked.
- **The mappers sync on every login** (sync mode `FORCE`), so a changed name
  or new privileges arrive the next time the user logs in.
