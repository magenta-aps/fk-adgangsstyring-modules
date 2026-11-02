# OIOSAML3 mappers for KOMBIT Context Handler

One Keycloak provider JAR with mappers for both sides of KOMBIT's Context
Handler: a protocol mapper for an authority's (myndighed's) IdP realm, and
identity-provider mappers for a supplier's (leverandør's) service realm (see
[Service side: identity-provider mappers](#service-side-identity-provider-mappers)).

On the IdP side, when Keycloak issues an assertion to Context Handler, the
**OIOSAML3 Job Function Roles to PrivilegeList** protocol mapper adds the
user's job function roles (jobfunktionsroller) as an OIO Basic Privilege
Profile (OIO-BPP) `PrivilegeList`. The list goes in the
`privilegesIntermediate` attribute. The NameID DN Context Handler requires
is sent with Keycloak's built-in mapper (see
[4. Send the NameID as a DN](#4-send-the-nameid-as-a-dn)).

```
 Keycloak (IdP realm)                         KOMBIT
 ┌──────────────────────────────┐            ┌──────────────────┐
 │ user ── member of ── groups  │            │                  │
 │            group attribute:  │  SAML      │  Context Handler │ ──► brugervendte
 │   oiosaml.jobrole = <URI>    │ ─────────► │                  │     systemer
 │                              │ assertion  │                  │
 │ this mapper ──► privileges-  │            └──────────────────┘
 │                 Intermediate │
 └──────────────────────────────┘
```

Context Handler translates the job function roles into user system roles
(brugersystemroller) for each service the user signs in to. The same JAR also
holds the service side: two identity-provider mappers for a Keycloak that
receives Context Handler's tokens. See
[Service side: identity-provider mappers](#service-side-identity-provider-mappers).

## How roles are assigned

Assignment works like an AD group in a municipality:

- A **Keycloak group** represents a job function role.
- The group's **`oiosaml.jobrole`** attribute holds the role's EntityId,
  exactly as shown in Fælleskommunalt Administrationsmodul, for example
  `http://kombit.dk/roles/jobrole/sagsbehandler/1`. The attribute can hold
  several values; each value becomes one role.
- **Adding a user to the group** assigns the role.
- Every role is scoped to the authority's CVR, which is set in the mapper
  config. A group can override this with **`oiosaml.scope_cvr`** for roles
  delegated by another authority.
- Roles on **parent groups** are included too, unless that is switched off.
- If the user ends up with no roles, the attribute is **left out entirely**,
  as OIO-BPP requires. It is never sent as an empty list.

A user in a group with `oiosaml.jobrole` = `…/sagsbehandler/1` and
`…/leder/1`, plus a delegated group (`oiosaml.scope_cvr` = `12345678`,
`oiosaml.jobrole` = `…/delegeret/1`), produces this list. It is base64-encoded
in the assertion and shown indented here; the real value has no whitespace:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<bpp:PrivilegeList xmlns:bpp="http://digst.dk/oiosaml/basic_privilege_profile"
                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <PrivilegeGroup Scope="urn:dk:gov:saml:cvrNumberIdentifier:29189846">
    <Privilege>http://kombit.dk/roles/jobrole/sagsbehandler/1</Privilege>
  </PrivilegeGroup>
  <PrivilegeGroup Scope="urn:dk:gov:saml:cvrNumberIdentifier:29189846">
    <Privilege>http://kombit.dk/roles/jobrole/leder/1</Privilege>
  </PrivilegeGroup>
  <PrivilegeGroup Scope="urn:dk:gov:saml:cvrNumberIdentifier:12345678">
    <Privilege>http://kombit.dk/roles/jobrole/delegeret/1</Privilege>
  </PrivilegeGroup>
</bpp:PrivilegeList>
```

Each role gets its own `PrivilegeGroup`, even when several roles share a
scope. KOMBIT requires this ("1 PrivilegeGroup = 1 jobfunktionsrolle" in
*Vejledning til Opsætning af Identity Provider*). OIO-BPP 1.2 itself allows
several privileges per group, but Context Handler rejects such a list with
"Duplicate privilege has been found on privilege group element".

## Files

```
pom.xml                                   Maven build; Keycloak version lives here
build.sh                                  Builds the JAR (runs the tests first)
src/main/java/dk/magenta/openstream/keycloak/oiosaml3/
  myndighed/                              IdP side: the authority's realm, sending to Context Handler
    OioSaml3PrivilegesProtocolMapper.java Job function roles to PrivilegeList
  leverandor/                             Service side: the supplier's realm, receiving from Context Handler
    OioSaml3SubjectMapper.java            <CVR>_<Serial> to broker ID / username
    OioSaml3DnMapper.java                 DN component to name / attribute
    SamlAssertions.java, Config.java      Assertion and mapper-config access
  shared_helpers/                         Not mappers: format helpers both sides use
    PrivilegeListBuilder.java             Builds and encodes the PrivilegeList XML
    PrivilegeList.java                    Parses the PrivilegeList XML
    DistinguishedName.java                Parses the NameID DN
src/main/resources/META-INF/services/
  org.keycloak.protocol.ProtocolMapper    Registers the myndighed mappers with Keycloak
  org.keycloak.broker.provider.IdentityProviderMapper  Registers the leverandor mappers
src/test/java/dk/magenta/openstream/keycloak/oiosaml3/
  myndighed/
    OioSaml3PrivilegesProtocolMapperTest.java  Config validation and the mapping itself
    Stubs.java                            Stand-ins for Keycloak's user/group/session
  leverandor/
    OioSaml3SubjectMapperTest.java        Subject key, failure on a bad NameID
    OioSaml3DnMapperTest.java             CN name split
    TestAssertions.java                   Builds brokered SAML assertions for the tests
  shared_helpers/
    PrivilegeListBuilderTest.java         XML format, escaping, validation, base64
    PrivilegeListTest.java                OIO-BPP 1.2 parsing, constraints, scopes, XXE
    DistinguishedNameTest.java            DN parsing and escaping
```

- **`OioSaml3PrivilegesProtocolMapper`** handles the Keycloak side:
  - It defines the settings shown in the admin console and rejects a config
    without a valid 8-digit CVR.
  - On each login it collects the user's groups (and their parents), reads
    the role and delegation attributes, and adds the encoded list to the
    assertion.
  - A misconfigured group is logged and skipped, so it can't remove the
    user's other roles or fail the login.
- **`PrivilegeListBuilder`** handles the OIO-BPP format. It has no Keycloak
  dependency, so it can be unit tested directly.
  - It writes one `PrivilegeGroup` per role, as KOMBIT requires, and drops
    a role that appears twice with the same scope.
  - It writes compact XML: only `PrivilegeList` is in the `bpp` namespace,
    and there is no whitespace between elements.
  - It escapes values, then base64-encodes the UTF-8 bytes.
- **`META-INF/services/org.keycloak.protocol.ProtocolMapper`** is a Java
  ServiceLoader file listing the mapper class. It's how Keycloak discovers
  the mapper when it scans `providers/`. Without it the class is ignored.

## Build

```sh
./build.sh
```

This runs the unit tests and writes
`target/oiosaml3-mappers.jar`. If `mvn` isn't installed,
the script runs Maven in a `maven:3.9-eclipse-temurin-21` container (Docker or
Podman) and uses `~/.m2` as the cache. Set `MAVEN_CACHE_DIR` to use a
different cache.

Extra arguments are passed to Maven:

```sh
./build.sh -DskipTests                      # skip the tests
./build.sh -Dkeycloak.version=26.4.0        # build against another Keycloak
PROVIDERS_DIR=/path/to/providers ./build.sh # also copy the JAR there
```

`keycloak.version` in `pom.xml` must match the Keycloak version the server
runs. It is currently 26.2.5, the version in
`magentaaps/openstream-keycloak:0.2.5`.

## Release

GitHub Actions (`.github/workflows/oiosaml3-mappers.yml` at the repo root)
builds and tests every push and pull request that touches this folder. To
publish a version:

1. Set `<version>` in `pom.xml`, e.g. `1.1.0`, and merge it to `main`.
2. Tag that commit `oiosaml3-mappers-v1.1.0` and push the tag. The workflow
   fails if the tag and the pom version differ.

The JAR is then attached to a GitHub release and can be downloaded without a
token:

```
https://github.com/<owner>/fk-adgangsstyring/releases/download/oiosaml3-mappers-v1.1.0/oiosaml3-mappers.jar
```

`target/` is not committed; projects use a release, not a local build.

## Install in Keycloak

Copy the JAR into Keycloak's `providers/` directory and rebuild or restart:

- **From a release** (pin the version):
  ```dockerfile
  FROM quay.io/keycloak/keycloak:26.2.5 AS builder
  # ADD from a URL creates the file with mode 600; Keycloak doesn't run as root.
  ADD --chmod=644 https://github.com/<owner>/fk-adgangsstyring/releases/download/oiosaml3-mappers-v1.0.1/oiosaml3-mappers.jar \
      /opt/keycloak/providers/
  RUN /opt/keycloak/bin/kc.sh build

  FROM quay.io/keycloak/keycloak:26.2.5
  COPY --from=builder /opt/keycloak/ /opt/keycloak/
  ```

- **Plain install:**
  ```sh
  cp target/oiosaml3-mappers.jar /opt/keycloak/providers/
  /opt/keycloak/bin/kc.sh build      # optimized/production setups
  /opt/keycloak/bin/kc.sh start ...
  ```
  In `start-dev`, a restart is enough; Keycloak notices the new provider and
  rebuilds itself.

- **Container image:**
  ```dockerfile
  FROM quay.io/keycloak/keycloak:26.2.5 AS builder
  COPY target/oiosaml3-mappers.jar /opt/keycloak/providers/
  RUN /opt/keycloak/bin/kc.sh build

  FROM quay.io/keycloak/keycloak:26.2.5
  COPY --from=builder /opt/keycloak/ /opt/keycloak/
  ```

- **Docker Compose:** bind-mount a directory containing the JAR onto
  `/opt/keycloak/providers` and run `docker compose restart keycloak`.

**Upgrading from `oiosaml3-privileges-protocol-mapper.jar`:** the JAR was
renamed to `oiosaml3-mappers.jar`. Delete the old file from `providers/`
before adding the new one, or Keycloak loads both and fails on duplicate
providers. Mapper IDs are unchanged, so configured mappers keep working.

To check that the mapper loaded, look for *OIOSAML3 Job Function Roles to
PrivilegeList* in the list of mapper types when you add a mapper (next
section). It is also listed under `protocol-mapper` as
`oiosaml3-privileges-saml-protocol-mapper` in the admin console's provider
info.

## Configure

These steps happen in the authority's IdP realm, where Context Handler is
registered as a SAML client from its metadata.

### 1. Create a group per job function role

**Groups → Create group**, for example `Sagsbehandler`. Then on the group's
**Attributes** tab:

| Key | Value |
| --- | --- |
| `oiosaml.jobrole` | The EntityId from Administrationsmodulet, e.g. `http://kombit.dk/roles/jobrole/sagsbehandler/1`. Add the key again for more roles. |
| `oiosaml.scope_cvr` | *Optional.* CVR of the delegating authority, for roles delegated by another authority. |

Groups can be nested; a user in a subgroup also gets the parent's roles. For
users synced from AD/LDAP, the *group-ldap-mapper* can import AD groups as
Keycloak groups, and you then set the attributes on the imported groups.

### 2. Add the users to the groups

**Users → user → Groups → Join group**, or via the LDAP sync.

### 3. Add the mapper to the Context Handler client

**Clients → *Context Handler client* → Client scopes → *…-dedicated* →
Configure a new mapper → OIOSAML3 Job Function Roles to PrivilegeList.**
To share the mapper between several clients, add it to a client scope
instead.

| Setting | Default | Notes |
| --- | --- | --- |
| Name | none | Anything, e.g. `privileges` |
| SAML Attribute Name | `https://data.gov.dk/model/core/eid/privilegesIntermediate` | OIOSAML 2: `dk:gov:saml:attribute:Privileges_intermediate` |
| SAML Attribute NameFormat | URI Reference | OIOSAML 2: Basic |
| Friendly Name | none | Optional |
| PrivilegeList Namespace | OIO-BPP 1.2 (digst.dk) | Use *Legacy (itst.dk)* only if Context Handler requires it for this IdP's profile |
| **Authority CVR** | none (**required**) | 8 digits. The default scope of every role. Must match the `O=` in the NameID and the CVR attribute. |
| Group Attribute With Role URI | `oiosaml.jobrole` | Clearing it falls back to the default |
| Group Attribute With Delegating CVR | `oiosaml.scope_cvr` | Clearing it **turns delegation off** |
| Include Parent Groups | on | Off: only the groups the user is a direct member of |

Keycloak refuses to save the mapper unless the Authority CVR is a valid
8-digit number.

### 4. Send the NameID as a DN

Context Handler identifies the user by a NameID in the form
`C=DK,O=<CVR>,CN=<name>,Serial=<id>` (attributprofil section 1.4.1). No
custom mapper builds it: each user carries the finished DN in the
`x509SubjectName` user attribute, and Keycloak's built-in mapper sends it.

- **Entra ID users:** an identity-provider mapper on the Entra ID provider
  imports the `x509SubjectName` claim into the attribute on each login, so
  Entra ID builds the whole DN.
- **Keycloak-only users:** an admin writes the DN by hand under *Users → user
  → Attributes → x509SubjectName*, for example
  `C=DK,O=29189846,CN=Hans Hansen,Serial=74c08b2b-212b-4f6d-9ce6-0fba1651087d`.
  Escape commas and other DN special characters in values with a backslash
  (`CN=Hansen\, Hans`).

**Clients → *Context Handler client* → Client scopes → *…-dedicated* →
Configure a new mapper → User Attribute Mapper For NameID**:

| Setting | Value |
| --- | --- |
| Name ID Format | `urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName` |
| User Attribute | `x509SubjectName` |

Then, on the client's **Settings** tab, set **Name ID format** to
`urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName` and turn on
**Force name ID format**. Keycloak only calls a NameID mapper whose format
equals the response's format exactly. Without the forced format it uses
whatever Context Handler's AuthnRequest asks for, and if that differs from
the mapper's format Keycloak silently sends the username instead. A user
without `x509SubjectName` also gets the username.

**`Serial` must not change for a user.** Context Handler and the services
behind it identify a user by `O` + `Serial`; a new Serial makes the user
arrive as a new identity. Don't base it on the optional
`professional/uuid/persistent` attribute, which not every user has. `O`
must match the Authority CVR of the privileges mapper.

## Verify and troubleshoot

- **See the attribute:** sign in through Context Handler with a browser SAML
  tracer extension and base64-decode the `privilegesIntermediate` value to get
  the XML. The debug log below shows the same XML without a tracer.
- **Debug logging:** start Keycloak with
  `--log-level=INFO,dk.magenta.openstream.keycloak.oiosaml3:DEBUG` to log the
  generated XML for each login, plus a line when a user has no roles.
- **Attribute missing:**
  - Check that the user is in a group (or subgroup) that has the role
    attribute, and that the attribute key matches the mapper config exactly.
  - If the user has no valid roles, the attribute is deliberately left out.
- **A role is missing:** look for a `WARN Skipping role …` line in the
  Keycloak log. It means that group's `oiosaml.scope_cvr` isn't 8 digits or
  the role value is blank. The user's other roles are still sent.
- **Username sent instead of the DN:** either the user has no
  `x509SubjectName`, or the NameID mapper wasn't called because the
  response's NameID format doesn't match the mapper's (see step 4).
- **Context Handler rejects the roles:**
  - Check that the EntityId matches Administrationsmodulet character for
    character. Context Handler compares exact strings.
  - Check that the Authority CVR matches the `O=` in the NameID.
  - Check that the role is actually assigned to this authority (or delegated
    from the `oiosaml.scope_cvr` authority) in Administrationsmodulet.

## Service side: identity-provider mappers

These are for the other direction: a Keycloak realm where Context Handler is
registered as a SAML **identity provider**, and the brugersystemtoken it sends
has to become a Keycloak user. They read only the NameID DN, which the KOMBIT
profile makes mandatory:

| Mapper type in the console | Reads | Does |
| --- | --- | --- |
| **OIOSAML3 Subject Identifier** | `O` and `Serial` from the NameID DN | Sets the broker user ID or the local username to `<CVR>_<Serial>` |
| **OIOSAML3 DN Component** | `C`, `O`, `CN` or `Serial` from the NameID DN | Copies it to the first name, last name or a user attribute |

### Why the key is `<CVR>_<Serial>`

The profile (section 1.4.1) only says `Serial` identifies the employee
uniquely *within the authority* in `O`. It need not be a UUID, and two
authorities may issue the same one. Context Handler is a single identity
provider for all of them, so a bare Serial would log the second person in to
the first person's account. With the CVR in front the key is unique, and it
still survives a change of name, which Keycloak's default (the whole DN, CN
included) does not. The separator is `_` because Keycloak's username
validator rejects `:`; the CVR is always 8 digits, so nothing is ambiguous.
A Serial that itself contains characters the validator rejects (whitespace,
`,`, `:`, `/` …) still works as the broker user ID, but not as the username.

The optional `professional/uuid/persistent` attribute is not used. The profile
doesn't tie it to the Serial, so mixing the two could switch the key between
logins.

A token without an X509SubjectName NameID holding an 8-digit `O` and a
`Serial` fails the login instead of silently falling back to another key.
The DN is only read from the NameID; the `oiosamlDN` attribute the mock IdP
adds is not part of the profile.

### Privileges are passed through, not mapped

There is no mapper that turns the privilege list into Keycloak roles. A role
would lose the `Scope` (which authority the user system role was granted
for, so the same role from two authorities would merge) and can't carry the
data constraints (KLE, følsomhed). Instead the base64 OIO-BPP 1.2 list from
`privilegesIntermediate` is passed on unchanged, and each SP application
decodes it and reads scope, constraints and privileges itself.

A group-based mapper, one group per (authority CVR, user system role) with
the constraints as group attributes, may replace this later.

### Recommended setup

*Identity providers → Context Handler → Mappers → Add mapper*. **Set sync
mode to Force on all of them.** With Import, a mapper only runs when the user
is first created, so name changes never arrive.

| Name | Type | Settings |
| --- | --- | --- |
| `subject-to-broker-id` | Subject Identifier | target `Broker user ID` |
| `subject-to-username` | Subject Identifier | target `Local username` |
| `cn-to-first-name` | DN Component | component `CN`, target `First name`, transform `First word` |
| `cn-to-last-name` | DN Component | component `CN`, target `Last name`, transform `All but first word` |
| `o-to-cvr` | DN Component | component `O`, target `User attribute`, attribute `cvr` |

**Add `subject-to-broker-id` before the provider's first login.** The broker
user ID is what finds a returning user. Changing what produces it later
orphans every existing link, and those users arrive as strangers. Delete or
relink them under *Users → … → Identity provider links*.

Email is optional in the profile, so these mappers don't set it. Keycloak's
default user profile requires an email, which makes first broker login stop
and ask for one. Make `email` not required in *Realm settings → User
profile* if users shouldn't see that form.

The other mandatory attributes (`specVersion`, `KombitSpecVer`, `cvr`,
`orgName`, and NSIS `loa` or `AssuranceLevel`) need no custom code. Use
Keycloak's built-in *Attribute Importer* if you want any of them on the
user.

## Tests

`./build.sh` runs them. They need no running Keycloak:

- **`PrivilegeListBuilderTest`** checks the exact XML output and that it is
  namespace-correct (via the JDK's DOM parser). It also covers one group
  per role and duplicates, trimming, escaping, CVR/URI validation, the legacy
  namespace, and the UTF-8/base64 round trip.
- **`OioSaml3PrivilegesProtocolMapperTest`** runs `transformAttributeStatement`
  against stubbed users and groups. It covers config validation,
  attribute name/format, multi-valued roles, de-duplication across groups,
  delegation, parent groups (on, off, shared ancestors), custom attribute
  names, the legacy namespace, skipping a bad group without losing the rest,
  and leaving the attribute out when there are no roles.
- **`PrivilegeListTest`** parses a value Context Handler actually sent, the
  profile's constraint example, the output of `PrivilegeListBuilder`, and
  rejects non-OIO-BPP roots and external entities.
- **`OioSaml3SubjectMapperTest`** checks the `<CVR>_<Serial>` key, that the
  same Serial in two authorities gives two keys, that `uuid/persistent` is
  ignored, and that a missing or malformed NameID fails the login.
