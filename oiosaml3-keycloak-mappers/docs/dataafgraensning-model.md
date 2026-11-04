# One job function role per system role, managed in Keycloak

This describes a simple way for an authority (myndighed) to grant access to
KOMBIT's user-facing systems (brugervendte systemer) from Keycloak, without a
separate role catalogue:

- **Administrationsmodulet** holds one job function role (jobfunktionsrolle)
  per user system role (brugersystemrolle), and every data constraint
  (dataafgrænsning) on it is **dynamic**.
- **Keycloak** decides who gets which role, and with which constraint
  values. A group stands for a role with a set of values, and membership
  grants it.

Once a role is set up, nothing in Administrationsmodulet changes when people
join, move or leave. The [README](../README.md#data-constraints-dataafgrænsninger)
covers the mapper settings; this document covers the model.

## Background: how a dynamic constraint works

Context Handler only accepts job function roles from an IdP (KOMBIT
attributprofil §1.5), never user system roles. It translates each job
function role into the user system roles attached to it in
Administrationsmodulet, and sends those to the system the user signs in to,
with their constraints (§1.6).

When a user system role is attached to a job function role, each of its
constraint types (KLE, følsomhed, organisatorisk enhed …) gets a value:

- **Static:** the value itself, e.g. `15*,17*,28*,32*`. Every user with the
  job function role gets the same value.
- **Dynamic** ("Dynamisk" ticked): a **parameter URI** chosen by the
  authority, e.g. `http://kommune.dk/KLE-SEK/1/parametric`. The value is
  supplied by the IdP at login.

KOMBIT's SAPA guide (section 5.5) puts it this way: *"Ved dynamisk
dataafgrænsning tildeles dataafgrænsningsværdien ikke på forhånd, men først
når medarbejderen er logget på. Den dynamiske dataafgrænsning indeholder en
reference til kommunens IdP (fx ADFS), en såkaldt parameter …"*

The IdP sends the value as a `Constraint` whose `Name` is the parameter URI,
inside the job function role's `PrivilegeGroup`:

```xml
<PrivilegeGroup Scope="urn:dk:gov:saml:cvrNumberIdentifier:29189846">
  <Privilege>http://kommune.dk/roles/jobrole/sapa-se-sag/1</Privilege>
  <Constraint Name="http://kommune.dk/constraint/sapa-se-sag/kle/1/parametric">25.*,27.10.*</Constraint>
</PrivilegeGroup>
```

Context Handler matches on the parameter URI, not on the constraint type, so
it always knows which user system role a value belongs to. KOMBIT's
documents don't show this format; it is taken from OS2rollekatalog
(`UserService.generateOIOBPP`), which sends it to Context Handler in
production. OS2rollekatalog gives every (user system role, constraint type)
in a job function role its own parameter URI, so one job function role can
carry different values for different system roles.

## Why one job function role per system role

A job function role normally bundles several system roles for a business
function ("Sagsbehandler, Jobcenter"), with the values fixed in
Administrationsmodulet. Then every new combination of roles or values means
a new job function role there, and access is split between two places: the
bundles in Administrationsmodulet and the membership in the IdP.

With one job function role per user system role and every constraint
dynamic, the job function role is only a name for the system role.
Administrationsmodulet holds a fixed mirror of the systems' roles that
rarely changes, and every decision is made in Keycloak:

| Question | Answered in |
| --- | --- |
| Which system roles exist, and which constraint types they have | The system (via Administrationsmodulet) |
| Which job function role stands for which system role, with which parameter URIs | Administrationsmodulet, set up once per role |
| Who gets which role, with which constraint values | Keycloak groups |

This is close to letting the IdP send system roles directly, which Context
Handler doesn't support.

## Setting up a role

### Naming

Pick a fixed pattern, so the URIs in Keycloak can be written without looking
them up. For a user system role `<rolle>` in system `<system>`:

| What | Pattern | Example |
| --- | --- | --- |
| Job function role EntityId | `http://<domæne>/roles/jobrole/<system>-<rolle>/1` | `http://kommune.dk/roles/jobrole/sapa-se-sag/1` |
| Parameter URI per constraint type | `http://<domæne>/constraint/<system>-<rolle>/<type>/1/parametric` | `http://kommune.dk/constraint/sapa-se-sag/kle/1/parametric` |

`<type>` is a short name for the constraint type: `kle`, `foelsomhed`,
`orgenhed`, `itsystem`. The `/1/parametric` ending follows KOMBIT's example.
Context Handler compares exact strings, so any pattern works as long as
Administrationsmodulet and Keycloak use the same one.

### 1. Administrationsmodulet

For each user system role the authority uses:

1. Create a job function role with the EntityId from the pattern.
2. Attach exactly that one user system role.
3. For each constraint type on the role, tick it, tick **Dynamisk**, and
   enter the parameter URI as the value.

Steps 1–3 are manual in the web interface. They can also be done with the
Administrationsmodul API (SF1518, `POST /stsadmin/xapi/jobfunktionsroller`)
using an OCES certificate registered on the authority. That is how
OS2rollekatalog creates its roles. This repository doesn't automate it yet.

### 2. Keycloak

One group per job function role and set of values. The role and its values
are set together on the group:

| Key | Value |
| --- | --- |
| `oiosaml.jobrole` | `http://kommune.dk/roles/jobrole/sapa-se-sag/1` |
| `oiosaml.constraint` | `http://kommune.dk/constraint/sapa-se-sag/kle/1/parametric=25.*,27.10.*` |
| `oiosaml.constraint` | `http://kommune.dk/constraint/sapa-se-sag/foelsomhed/1/parametric=Medium` |

Adding a user to the group grants the role with those values. Every
constraint type that is dynamic on the role in Administrationsmodulet needs
an `oiosaml.constraint` entry.

### Different values for different users

When users need the same role with different values, put the role on a
parent group and each value on a subgroup, and add users to the subgroups:

```
OWP site user          oiosaml.jobrole    = http://magenta.dk/roles/jobrole/owp-test-site-user/1
 ├─ magenta-test-2     oiosaml.constraint = http://magenta.dk/owp-site-user/1/parametric=magenta-test-2
 └─ magenta-test-3     oiosaml.constraint = http://magenta.dk/owp-site-user/1/parametric=magenta-test-3
OWP site admin         oiosaml.jobrole    = http://magenta.dk/roles/jobrole/owp-test-site-admin/1
 └─ magenta-test-2     oiosaml.constraint = http://magenta.dk/owp-site-admin/1/parametric=magenta-test-2
```

Joining a subgroup grants the parent's role with the subgroup's value, so
access is effectively given per user, per role, per value, without user
attributes. A user in both `magenta-test-2` and `magenta-test-3` under *OWP
site user* gets the role once, with `magenta-test-2,magenta-test-3`. Values
are only ever added this way, never narrowed. Roles that use the same kind
of value (`site_user`, `site_admin`) stay apart because each has its own
tree and parameter URI.

Keep a single role on each parent group: a subgroup's constraints apply to
every role above it. A user placed directly in the parent group gets the
role without a value, which Context Handler rejects. *Include Parent
Groups* must be on (the default).

Role and value on the same group (one group per role and value) works too,
and is the only option before version 1.2.0.

If a value is the same for every user of the role, it can be made static in
Administrationsmodulet instead and left out of Keycloak.

## What to watch out for

- **Number of roles.** The authority needs a job function role for every
  user system role it uses, across all KOMBIT systems. That can be hundreds.
  Doing it by hand is realistic for a few systems; beyond that, automating
  with the API above is worth it.
- **Missing values.** If a group leaves out a dynamic constraint, or its
  entry is malformed, the mapper sends the role without that `Constraint`
  (malformed entries log a warning). Context Handler then **rejects the
  whole login** (confirmed in ExtTest): *"Login kan ikke gennemføres, fordi
  der mangler en obligatorisk dataafgrænsningsværdi med ID'et ' -
  <parameter URI> '"*. One badly configured group locks the user out of all
  their roles.
- **Exact strings.** A parameter URI that differs by one character from
  Administrationsmodulet is silently ignored by Context Handler. Copy them,
  don't type them.
- **Value format.** Values are comma-separated lists, as in KOMBIT's
  examples. Context Handler passes them on; each system interprets them
  (KLE wildcards, organisation UUIDs …). Check the format each system expects
  in *Fælleskommunale dataafgrænsningsværdier*.
- **Delegated roles.** OS2rollekatalog never sends dynamic constraints on a
  role delegated by another authority ("delegated roles cannot be
  constrained dynamically"). Use static values for delegated roles.
- **Overview.** Administrationsmodulet's reports show only the mirror roles,
  not who has them or with which values. That overview is in Keycloak.

## Alternatives

- **Business-function roles.** Bundle the system roles of a function into
  one job function role, with dynamic constraints only where users differ.
  Fewer roles, and the bundling is visible in Administrationsmodulet. The
  mapper supports this the same way; give each system role in the bundle its
  own parameter URI.
- **OS2rollekatalog.** A role catalogue that creates the job function roles
  in KOMBIT through the API and computes the constraint values from the
  organisation. The IdP fetches the finished list from
  `GET /api/user/{username}/roles?system=KOMBIT`. Choose it when the
  authority wants a full role-management tool rather than Keycloak groups.

## Confirmed in ExtTest

- The parameter URI is entered in the value field when *Dynamisk* is ticked
  in Administrationsmodulet, and the IdP sends it as the `Constraint` `Name`
  in the job function role's `PrivilegeGroup`.
- Context Handler rejects the login when a dynamic constraint has no value
  (see above).

## Still to confirm

- That Context Handler accepts one job function role per system role at
  scale (no limit on roles per user or token size).

## Sources

- KOMBIT, *SAPA Guide til jobfunktionsroller*, v1.0 (2019), section 5.5:
  <https://cdn.kombit.dk/kombit/Media/638321935259177585/Guide%20til%20jobfunktionsroller%20SAPA.pdf>
- KOMBIT, *Brugervejledning til Administrationsmodulerne for myndigheder*,
  p. 32 ("Dynamisk"):
  <https://digitaliseringskataloget.dk/files/integration-files/101120221045/Brugervejledning%20til%20Administrationsmodulerne%20for%20myndigheder.pdf>
- KOMBIT, *Fælleskommunal OIOSAML 3 attributprofil*, §1.5–1.6
  (`kombit-docs/` in this repository).
- KOMBIT, *Vejledning til Administrationsmodulets API* (STS admin – XApi),
  sections 3–4:
  <https://digitaliseringskataloget.dk/files/integration-files/240320211622/Vejledning%20til%20Administrationsmodulets%20API.pdf>
- OS2rollekatalog, `UserService.generateOIOBPP`, `IdentifierGenerator`,
  `KOMBITService.mapRoleAssignments`:
  <https://github.com/OS2rollekatalog/OS2rollekatalog>
