# Paging qualification handoff

Apply `release-verifier.patch` through the #61 owner's existing
`verify/release` lease with `git apply --unidiff-zero`. Its base is
`9ba7a366c96f3257050dc8484382e57d9c0b9cf3`, which already validates successful
pages with the production Go client and exercises HTTP framing on the wire.
The patch adds a tied walk that starts at limit two and resumes at one,
alongside the existing byte-trimmed sparse walk. Both bisect the issuing
budget and finish on the process that issued their cursor. An independent
HTTP diagnostic distinguishes the certification runtime from the legacy
runtime so other tracks keep the existing release coverage.

On a composed #53/#59 release candidate, look for
`work_budget.fixed_budget_walk.tied_smaller_resume` and `sparse_walk` in the
existing admission evidence. Each records four rows across three pages and
the budget that first issued a cursor. The sparse first page requests four
rows and fits two within its byte cap. The budget search checks the exact
rejection body and requires the cursor header to be absent.

Apply `server-expiry.patch` through the #59 HTTP owner. Its base is
`4bfaae81e4709c8208cc74ca5be74d2ae15647dc`. The controlled-clock test verifies
that a valid cursor still reaches its terminal page just before expiry, the
server releases the capture at the deadline, and authenticated retries
return HTTP 410. It observes the pin release at the server's `PageSource`
seam. Malformed, tampered, filter-mismatched, and foreign-issuer cursors
still return HTTP 400.

The active corruption-gate owner retains workflow wiring. These patches sit
outside the legacy workflow's `release/*.patch` glob.
