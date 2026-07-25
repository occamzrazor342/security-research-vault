# Insecure Pickle Deserialization in AI/ML Data Pipelines

A recurring shape on boxes with an "AI/ML" theme: somewhere in the
pipeline — a document/model/cache loader, not necessarily anything that
calls itself a "model file" — there's a `pickle.loads()`/`torch.load()`-
style call sitting on data an attacker can influence, with no integrity
check tying the bytes back to a trusted source. Python's `pickle` format
runs arbitrary code via any object's `__reduce__`/`__reduce_ex__` the
moment `loads()` touches it — deserializing untrusted pickle data is
equivalent to handing over code execution outright, not a bug specific to
any one library. [Python's own docs say this explicitly](https://docs.python.org/3/library/pickle.html):
*"The pickle module is not secure. Only unpickle data you trust."*

## Where this shows up beyond the obvious "upload a .pkl file" case

Pickle-based deserialization hides inside data formats that don't look
like classic serialized objects at all:

- **Font/CMap caches** (pdfminer.six's `CMapDB`) — a PDF's own font
  resource can name which cache file to load. See [[CVE-2025-64512]].
- **ML model checkpoints** (`torch.save`/`torch.load`, `joblib.dump`/
  `.load`, `numpy.save`/`.load(allow_pickle=True)`) — training/inference
  pipelines that auto-load "the newest checkpoint" out of a shared
  directory are a direct RCE primitive if that directory is writable by
  anything less trusted than the process loading from it.
- **MLflow's `pyfunc` custom-model flavor** — the "model" a registry
  serves is a raw (cloud)pickled Python object graph by design, loaded via
  `mlflow.pyfunc.load_model()`. Here the untrusted-write path isn't a
  shared filesystem directory but MLflow's own REST artifact-proxy `PUT`
  endpoint — same underlying pickle-RCE mechanism, reached over HTTP
  instead of a bind mount. Generalized in
  [[mlflow-model-registry-artifact-proxy-pickle-rce]].
- Any "resume from cache" / "restore session" feature that silently picks
  up a file by name/mtime convention rather than an explicit,
  integrity-checked reference.

## The `torch.load(weights_only=False)` case specifically

Since PyTorch 2.6, `torch.load()`'s own *default* is the safer
`weights_only=True` — a restricted unpickler that only reconstructs
tensors and a small allowlist of primitive types, refusing to import
arbitrary classes or call arbitrary callables. But `weights_only=True`
can't handle a full training-state checkpoint (optimizer state, custom
objects) — so any framework that wants that capability has to explicitly
opt back into `weights_only=False`, opting back into full pickle
deserialization along with it. [PyTorch's own docs](https://docs.pytorch.org/docs/stable/generated/torch.load.html)
carry the same warning as the stdlib pickle docs: *"Never load data from
an untrusted source."*

MONAI's `CheckpointLoader` (`monai.handlers.CheckpointLoader.__call__`)
does exactly this — `torch.load(self.load_path, ..., weights_only=False)`,
unconditionally, by design, because it needs to restore optimizer objects
alongside tensors. This isn't a version-specific CVE to patch-diff; it's a
design choice that becomes an RCE primitive the instant an attacker can
place an untrusted file in whatever directory the loader trusts.

## The `os.path.join` absolute-path gotcha that shows up alongside path checks

A related, independently-useful gotcha found in the pdfminer.six case:
Python's `os.path.join(a, b)` **silently discards `a` entirely if `b` is
itself an absolute path** — `os.path.join("/usr/share/pdfminer/",
"/etc/passwd")` returns `/etc/passwd`, not an error and not a joined,
contained path. Any code that builds a path this way and then checks
`os.path.exists()`/opens it, assuming the join keeps the result under the
first argument, has an unintended absolute-path escape hatch the instant
the second component is attacker-controlled and not first validated as
relative. [Python docs, `os.path.join`](https://docs.python.org/3/library/os.path.html#os.path.join)
document this behavior plainly, but it's easy to miss when skimming code
that "looks like" it's building a contained path. The fix is the same
shape every time: resolve to a canonical absolute path with
`os.path.realpath()` and then check it actually starts with the intended
directory's own realpath — not just that the join *looked* safe.

## Checklist for a box with this theme

- Any file-upload/dataset-ingestion feature feeding an "AI training" or
  "document processing" pipeline: check the exact library + pinned
  version against CVE Watch/advisories for that library's deserialization
  history, not just the obvious top-level framework.
- Any background watcher/cron that auto-processes newly dropped files:
  find its exact trigger condition (glob pattern, polling interval) —
  it's often unauthenticated and running continuously.
- Any "load the latest checkpoint/model/cache" logic: check what
  directory it reads from and who can write there — a shared bind mount
  between a low-privilege foothold and a privileged loader is a complete
  RCE chain even without any actual code vulnerability in the loader
  itself, since the intended feature (auto-load newest file) is being
  used exactly as designed.
- If the app wraps a real ML platform (MLflow, Kubeflow, etc.) rather than
  hand-rolling its own model storage, fuzz for a separate management vhost
  fronting that platform's own tracking/registry API — it's often reachable
  independently of the app's own auth, gated only by the platform's own
  (frequently default) credentials. See
  [[mlflow-model-registry-artifact-proxy-pickle-rce]].

## Seen on

- [[bedside#Foothold|bedside]] — [[CVE-2025-64512]], pdfminer.six CMapDB
  pickle RCE via a PDF font's `/Encoding` path, popped through an
  unauthenticated upload-and-watch pipeline.
- [[bedside#Privesc|bedside]] — MONAI `CheckpointLoader`'s
  `torch.load(weights_only=False)` on the newest `*.pt` in a
  foothold-writable, sudo-trusted directory, weaponized as the box's
  second, unrelated privesc vector. See also
  [[cross-foothold-bind-mount-bridging]] for how two separate limited
  footholds combined to actually reach and trigger this.
- [[smarthire#Foothold|smarthire]] — MLflow model registry `pyfunc` flavor,
  reached via a separate `models.<host>` vhost gated only by MLflow's
  documented default `admin`/`password` basic-auth account; the artifact
  proxy's write API let the registered model's `python_model.pkl` be
  overwritten directly, triggered through the app's own authenticated
  prediction endpoint. Full mechanism in
  [[mlflow-model-registry-artifact-proxy-pickle-rce]].
