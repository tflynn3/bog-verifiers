# Release acceptance journeys

Each release in the Slipway delivery model defines outcomes, and each outcome has one or more
acceptance journeys: a user's steps and the expected result. This directory holds their executable
form. Journeys are written once per release, when the release plan is frozen at G1, and the verifier
image digest is pinned for the release. They change again only for the next release.

## Contract

- `index.json` maps a journey ID to a script path relative to this directory:
  `{"bog/0.1/O1/J1": "0.1/o1_j1.py"}`.
- A script runs as `python3 -B <script> --bog <binary> --workdir <dir> --corpus <dir> --journey <id>`
  inside the verifier image (non-root, standard library only, no network beyond loopback).
- Exit 0 when the journey passes. Exit 1 when the observed behavior differs from the journey spec,
  printing one line: `expected <spec behavior>; observed <what happened>`. Any other exit status is a
  harness error, not a product failure.
- Use `lib.py` (`Bog`, `expect`, `run`) to start Bog with a private data directory, ingest, query,
  page through results, crash it with SIGKILL and restart it.
- Test only behavior a user can observe through the documented CLI and HTTP API. Never read Bog's
  source or rely on internal files other than the documented data-directory layout.
- Each journey must finish within 180 seconds (`SLIPWAY_PARAM_JOURNEY_TIMEOUT`).
- **Unprivileged container sandbox (strict)**: Slipway runs verifier Pods as non-root `65532:65532` with
  `Capabilities.Drop: ["ALL"]`, `AllowPrivilegeEscalation: false`, read-only `/sys/fs/cgroup`, and a `1 GiB`
  pod memory limit. Never call `mount(2)`, `umount(2)`, `chroot`, `sudo`, or write to `/sys/fs/cgroup`.
  - For full-disk (`ENOSPC`) journeys, create a `TemporaryDirectory` on `os.environ.get("SLIPWAY_PARAM_ENOSPC_MOUNT") or "/dev/shm"` (a private writable `tmpfs` mount already present in every verifier Pod) and fill a sibling filler file until `write()` returns `errno.ENOSPC`.
  - For memory-budget journeys, read `/proc/<pid>/status` (`VmHWM` / `VmRSS`) continuously during ingest and queries so an unbounded binary is rejected (`exit 1`) as soon as it crosses the target ceiling rather than OOMKilling the `1 GiB` verifier Pod.

## Running

The verifier runs the journeys for one or more outcomes with:

```sh
SLIPWAY_PARAM_MODE=journeys \
SLIPWAY_PARAM_JOURNEYS=bog/0.1/O1/J1,bog/0.1/O1/J2 \
SLIPWAY_PARAM_REPOSITORY=https://github.com/tflynn3/bog.git \
SLIPWAY_PARAM_BRANCH=main SLIPWAY_PARAM_COMMIT=<sha> /verifier/verify.sh
```

A failure reports `<journey ID>: expected ...; observed ...` and never test source. bog-conductor
turns that into the outcome's status and the builders' brief.

The 0.2 journeys require Linux and have a 120-second budget each. For O1/J1, use local storage for
the journey work directory and delegate a writable cgroup v2 parent with the memory controller
enabled for its children. Set `SLIPWAY_PARAM_JOURNEY_CGROUP_PARENT` if the delegated parent is
outside the verifier's current cgroup ancestry. For O2/J1, the verifier needs mount privileges in
its mount namespace so it can mount and unmount a private 8 MiB tmpfs under the work directory.
