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
