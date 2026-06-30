# Security, users, and access control

Graphus authenticates every connection and authorizes every operation against a
fine-grained, role-based access-control (RBAC) model. The model is **deny-by-default**:
a principal can do only what it has been explicitly granted. The security catalog is
durable and crash-safe, and it is shared by all three interfaces (REST, Bolt-over-TCP,
Bolt-over-UDS).

This guide covers credentials, user management, roles and privileges, and how each
interface authenticates. For the REST login flow specifically, see
[rest-api.md](rest-api.md); for the Bolt interfaces, see [bolt.md](bolt.md).

---

## 1. The bootstrap administrator and credentials

On a **fresh** store, Graphus seeds an initial administrator from the `[auth]` section
of the configuration file (see [configuration.md](configuration.md)):

```toml
[auth]
admin_user     = "graphus"          # initial administrator username
admin_password = "graphus-local"    # initial administrator password (change it!)
# admin_uid    = 1000               # optional: map an OS uid to the admin user for UDS (see §5)

# Optionally seed extra non-admin users, each granted READ + WRITE:
# [[auth.users]]
# name     = "app"
# password = "a-strong-password"
```

The JWT signing secret used for REST Bearer tokens is **not** in the config file; it is
supplied out of band as an environment variable (or auto-generated on first boot by the
Docker entrypoint and persisted under `/data`):

```sh
GRAPHUS_JWT_SECRET="<at least 32 bytes>"
```

> **The quickstart credentials `graphus` / `graphus-local` are local-sandbox defaults
> only.** Before any non-sandbox use, set a strong `admin_password`, a real
> `GRAPHUS_JWT_SECRET`, and a CA-issued TLS certificate. See
> [the README's Production / TLS section](../README.md#production--tls).

### The security catalog is authoritative after first boot

The first time the server starts, it seeds the catalog from `[auth]` and **persists it**
to `<store_path>/security.toml`. On every subsequent boot that file is **authoritative**:
the `[auth]` bootstrap is ignored, so users, roles, and grants created at runtime survive
restarts. Properties of the catalog:

- **Passwords are never stored in clear text** — only Argon2id hashes. The plaintext is
  never logged. The minimum password length is 8 characters.
- **Fail-closed**: if `security.toml` is corrupt, the server refuses to start rather than
  resetting to defaults (an operator must repair or remove the file deliberately).
- **Atomic + durable**: every mutation is written through a temp-file + fsync + rename
  protocol, and the file is owner-only (`0600`).
- **Live**: a runtime `CREATE USER` / password change / `DROP USER` takes effect for
  authentication immediately, with no reboot.

---

## 2. Running administrative statements

User, role, privilege, and database statements are **administrative statements**. You run
them like a query, over **any** interface (the Bolt CLI, a Bolt driver, or a REST query),
while authenticated as a principal that holds the global **`ADMIN`** privilege (the
bootstrap administrator does).

Properties of the admin surface:

- Keywords are **case-insensitive**; one optional trailing `;` is tolerated.
- A `<name>` is a bare word (`[a-z][a-z0-9_-]{0,62}`, also `_`/`-`/`.`) or a
  `` `backtick-quoted` `` name.
- Admin statements are **not transactional**: they are rejected inside an explicit,
  client-managed transaction, and on the REST auto-commit endpoint they execute
  immediately.
- A non-admin principal gets a permission-denied error and **no side effects**.

For example, over the Bolt CLI (see [bolt.md](bolt.md)) or any driver:

```cypher
CREATE USER analyst SET PASSWORD 'a-strong-password'
```

Over REST (see [rest-api.md](rest-api.md)), send it as a statement to the auto-commit
endpoint:

```sh
curl -k -X POST https://localhost:7474/db/graphus/tx/commit \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"statements":[{"statement":"CREATE USER analyst SET PASSWORD '\''a-strong-password'\''"}]}'
```

---

## 3. Managing users

```cypher
CREATE USER <name> [SET PASSWORD '<password>'] [IF NOT EXISTS]
DROP   USER <name> [IF EXISTS]
SHOW   USERS
```

Examples:

```cypher
CREATE USER alice SET PASSWORD 'initial-password'
CREATE USER bob   SET PASSWORD 'another-password' IF NOT EXISTS
SHOW USERS
DROP USER alice IF EXISTS
```

- `SHOW USERS` lists each user with its roles and whether it has a password set.
- A password must be at least 8 characters; it is Argon2id-hashed before storage.
- **Changing a password:** there is currently no `ALTER USER` statement. To rotate a
  password, `DROP USER` then `CREATE USER` again (re-granting its roles, §4). Changing or
  dropping a user immediately invalidates that user's outstanding REST Bearer tokens (the
  credential epoch is bumped).

---

## 4. Roles and privileges (RBAC)

Privileges are granted to **roles**, and roles are granted to **users**. A user's
effective privileges are the union of its roles' privileges.

```cypher
CREATE ROLE <name> [IF NOT EXISTS]
DROP   ROLE <name> [IF EXISTS]
SHOW   ROLES

GRANT  ROLE <role> TO   <user>
REVOKE ROLE <role> FROM <user>

GRANT  <action> ON <scope> TO   <role>
REVOKE <action> ON <scope> FROM <role>
SHOW   PRIVILEGES
```

### Actions

An **action** is what may be done. Actions are graded — a stronger action implies the
weaker ones over the same resource:

| Action     | Grants                                                              |
| ---------- | ------------------------------------------------------------------ |
| `TRAVERSE` | see that a node/relationship exists (identity + labels/type), **no property values** |
| `READ`     | read property values (implies `TRAVERSE`)                          |
| `WRITE`    | create/update/delete data (implies `READ`, `TRAVERSE`)             |
| `SCHEMA`   | manage indexes and constraints (DDL); orthogonal to read/write     |
| `ADMIN`    | the super-action; over `DATABASE` it is the **global root** grant  |

### Scopes (resources)

A **scope** is what the action applies to. Scopes nest, from the whole server down to a
single property, and **never cross a database boundary**:

| Scope syntax                          | Covers                                              |
| ------------------------------------- | --------------------------------------------------- |
| `DATABASE`                            | the whole server — every database                   |
| `GRAPH <db>`                          | one whole named database                            |
| `LABEL <db>.<label>`                  | all nodes of one label in one database              |
| `RELATIONSHIP <db>.<rel_type>`        | all relationships of one type in one database       |
| `PROPERTY <db>.<label>.<property>`    | one property of one label's nodes in one database   |

A broader grant covers the narrower ones it contains: `GRANT READ ON DATABASE` lets a role
read everything; `GRANT READ ON GRAPH social` lets it read only the `social` database; and
`GRANT ADMIN ON DATABASE` is the global administrator grant.

### Worked example

Give an analyst read-only access to the `social` database:

```cypher
-- 1. A role with a single, scoped privilege.
CREATE ROLE analyst
GRANT READ ON GRAPH social TO analyst

-- 2. A user, assigned that role.
CREATE USER alice SET PASSWORD 'a-strong-password'
GRANT ROLE analyst TO alice

-- 3. Inspect.
SHOW PRIVILEGES
```

Now `alice` can read the `social` database but cannot write to it, cannot touch any other
database, and cannot run administrative statements:

```cypher
-- as alice: allowed
MATCH (p:Person) RETURN p.name

-- as alice: denied (no WRITE grant) -> permission error, no side effect
CREATE (:Person {name: 'Bob'})
```

Revoking is symmetric (`FROM` instead of `TO`):

```cypher
REVOKE ROLE analyst FROM alice
REVOKE READ ON GRAPH social FROM analyst
```

### Lock-out safeguard

The bootstrap administrator cannot be stripped of its global `ADMIN` privilege: a mutation
that would lock the last administrator out is rejected. You cannot accidentally lock
yourself out of the server.

---

## 5. Authentication by interface

| Interface     | Scheme                          | Credential                         |
| ------------- | ------------------------------- | ---------------------------------- |
| REST          | `Authorization: Bearer <JWT>`   | a JWT obtained from `POST /auth/login` (HS256) |
| Bolt over TCP | Bolt `LOGON` (`basic` scheme)   | username + password (Argon2-verified) |
| Bolt over UDS | OS peer-credential **and** `LOGON` | mapped uid **and** username + password |

### REST — Bearer JWT

A REST client authenticates with `POST /auth/login` (username + password), receives a
short-lived HS256 JWT, and presents it as `Authorization: Bearer <token>` on every
subsequent request. The full flow, request/response shapes, and token lifetime are in
[rest-api.md](rest-api.md).

### Bolt over TCP — LOGON

A Bolt driver sends `HELLO` then `LOGON` with the `basic` scheme (principal +
credentials); the password is verified against the stored Argon2 hash. TLS is mandatory on
TCP. See [bolt.md](bolt.md).

### Bolt over UDS — peer-credential **plus** LOGON (two gates)

The Unix-domain-socket interface has **two** gates, both of which must pass:

1. **Peer-credential gate (kernel-level).** At accept time the server reads the connecting
   process's OS uid and resolves it to a Graphus user. If the uid is **not** mapped, the
   socket is closed *before any Bolt bytes flow*. Map a uid to the administrator with
   `admin_uid` in `[auth]`:

   ```toml
   [auth]
   admin_uid = 1000     # the OS uid permitted to connect over UDS, mapped to admin_user
   ```

2. **Bolt `LOGON`.** After admission, the session still authenticates with a username +
   password exactly as over TCP.

This makes UDS a kernel-protected local trust domain: only processes running under a mapped
uid can even open the socket, and they still authenticate normally. See [bolt.md](bolt.md)
and the [Go UDS example](../examples/clients-go/bolt-uds).

---

## 6. Multiple databases

Graphus is multi-database. The default database is **`graphus`** (configurable via
`default_database` / `GRAPHUS_DEFAULT_DATABASE`). Administrators manage databases with:

```cypher
CREATE DATABASE <name> [IF NOT EXISTS]
DROP   DATABASE <name> [IF EXISTS]      -- must be STOPped first; the default cannot be dropped
START  DATABASE <name>
STOP   DATABASE <name>
SHOW   DATABASES
SHOW   DATABASE <name>
```

Because privilege scopes carry a database name (`GRAPH <db>`, `LABEL <db>.<label>`, …), a
grant on one database never leaks into another. A role with `READ ON GRAPH social` has zero
access to a `sales` database unless separately granted.

---

## 7. Checklist for production

- [ ] Change `admin_password` from the sandbox default to a strong secret.
- [ ] Set a real `GRAPHUS_JWT_SECRET` (≥ 32 bytes, high-entropy).
- [ ] Supply a CA-issued TLS certificate (`bolt+s://`, plain `https://`) instead of the
      self-signed quickstart pair.
- [ ] Create per-application users with **least-privilege** roles rather than sharing the
      administrator.
- [ ] Restrict UDS access with `admin_uid` (and OS file permissions on the socket).
- [ ] Keep `security.toml` on durable, backed-up storage; never world-readable.

See also: [getting-started.md](getting-started.md) · [rest-api.md](rest-api.md) ·
[bolt.md](bolt.md) · [configuration.md](configuration.md).
