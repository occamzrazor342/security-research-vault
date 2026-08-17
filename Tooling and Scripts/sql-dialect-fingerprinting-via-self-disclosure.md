# SQL Dialect Fingerprinting via Self-Disclosed Terminology

When an app (or, increasingly, an LLM tool-calling agent describing its own
tools) self-discloses SQL-adjacent vocabulary in plain conversation or error
text, the specific terms used name the backend dialect almost as reliably as
a version banner would — worth checking passively before ever touching an
exec surface. Each dialect has its own procedural-language name, dummy/
catalog table, version function, and identifier-quoting convention that
essentially never appears outside that one product.

## Dialect cheat sheet

| Dialect | Procedural language | Version call | Catalog / dummy table | Identifier quoting | Distinctive clauses |
|---|---|---|---|---|---|
| **SQL Server** | T-SQL | `@@VERSION` | `sys.databases`, `sys.configurations`, `sys.servers` | `[brackets]` | `TOP n` (not `LIMIT`), `IDENTITY`, `GO` batch separator |
| **MySQL/MariaDB** | (none named) | `VERSION()` / `@@version` | `information_schema` | `` `backticks` `` | `LIMIT n`, `AUTO_INCREMENT`, `GROUP_CONCAT`, `ON DUPLICATE KEY UPDATE` |
| **PostgreSQL** | PL/pgSQL | `SELECT version()` | `pg_catalog`, `pg_tables`, `pg_stat_activity` | `"double quotes"` | `RETURNING`, `ILIKE`, `SERIAL`, sequences (`nextval`/`currval`), `psql` `\dt`/`\d` |
| **Oracle** | PL/SQL | `v$version` | `DUAL`, `all_tables`/`user_tables` | `"double quotes"` | `ROWNUM`, `CONNECT BY`, `.NEXTVAL`/`.CURRVAL`, `sqlplus`/`tnsnames.ora` |
| **SQLite** | none (file-based, no server) | n/a | `sqlite_master` | n/a | `PRAGMA` statements, `ROWID` |
| **Snowflake** | Snowflake Scripting | — | `INFORMATION_SCHEMA` | | `SHOW WAREHOUSES`, `COPY INTO` |
| **BigQuery** | — | — | — | `` `project.dataset.table` `` | "standard SQL" |
| **DB2** | SQL PL | — | `SYSIBM.SYSDUMMY1` | | `db2` CLP client |

The single highest-signal term is the **procedural-language name** — "T-SQL"
and "PL/SQL" in particular are unambiguous, vendor-exclusive nouns a model or
app has no reason to use unless that's genuinely what's running underneath.

## RCE/exec-primitive equivalents, once dialect is confirmed

Useful for immediately knowing which raw-execution primitive to reach for
instead of rediscovering it live:

- **SQL Server**: `xp_cmdshell` (needs `sysadmin`/rights + the option enabled,
  see [[OSAI+ - Final Capstone - Megacorp One AI]] for a live case where it
  was already on); `sp_OACreate` as an older fallback if `xp_cmdshell` is
  disabled.
- **PostgreSQL**: `COPY ... FROM PROGRAM` (needs superuser); `plpython3u`/
  `dblink` extension abuse as alternates.
- **MySQL/MariaDB**: no direct OS-command equivalent — `INTO OUTFILE`/
  `LOAD_FILE()` for file read/write, or UDF (user-defined function) abuse for
  code execution.
- **Oracle**: `UTL_HTTP`/`UTL_FILE` packages (SSRF/file I/O), Java stored
  procedures via `DBMS_JAVA`.
- **SQLite**: no server process, no OS-command primitive at all.

## Fast independent confirmation

Once a dialect is suspected from vocabulary alone, a single dialect-exclusive
function call proves or disproves it cleanly without waiting on further
self-disclosure — e.g. for SQL Server specifically, `SELECT DB_NAME()` or
querying `sys.configurations` fails outright on every other dialect above,
giving a clean yes/no independent of whatever the model *says* about itself.

## Seen on

- [[OSAI+ - Final Capstone - Megacorp One AI]] — an MCP-style tool-calling
  chatbot self-disclosed a `SQLTest` tool description mentioning "single-
  batch T-SQL commands," which named the backend as SQL Server well before
  any exec attempt; confirmed independently via `@@VERSION` once `SQLTest`
  was actually invoked.
