# bog-verifiers

Independent black-box and end-to-end verifier suites for bog.
Built into immutable digest-pinned images for Slipway verify Jobs so
implementation builders cannot edit the tests they are verified against.

## Slipway Verifier Contract
- Env vars provided by Slipway:
  - Candidate mode: SLIPWAY_REPOSITORY, SLIPWAY_TARGET_BRANCH, SLIPWAY_BASE_COMMIT,
    SLIPWAY_CANDIDATE_BRANCH, SLIPWAY_CANDIDATE_COMMIT
  - General mode: SLIPWAY_INPUTS, SLIPWAY_PARAM_*, SLIPWAY_INPUT_*
- Exit 0: verification passed.
- Exit 1: candidate/inputs rejected; write concise diagnostic to /dev/termination-log.
- Exit >1: infrastructure error (retried by Slipway).
