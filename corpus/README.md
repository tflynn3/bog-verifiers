# Replay fixtures

These excerpts come from Bog QA's controlled loopback workloads. The captures
use QA-controlled paths, inputs, exceptions, and client identifiers. The
fixtures can be copied and redistributed under CC0-1.0.

| Fixture | Origin | SHA-256 |
| --- | --- | --- |
| `apache-access.log` | 256 verbatim Combined Log Format records from Apache HTTP Server 2.4.67. GET and HEAD requests returned 200, 403, and 404. | `29e286fd748b06450152c4efcfe9c4f2a668a8b3223720f7fba052ffd902b14e` |
| `git-daemon.log` | 203 stderr records from Git daemon 2.54.0 (Apple Git-157). The loopback workload ran 40 serial `git ls-remote` requests, with 37 successful reads of a disposable repository and three requests for missing repositories. | `8dcd8aba73ae74db1bc3adb9c32b2a06feee7aa92386ec61005b0d3dd3c07704` |
| `replay.ndjson` | 513 Apache access records, 36 proxy errors, and 1,009 Python HTTP application records captured during loopback requests, plus 1,000 seeded records. The archive stores timestamps and capture IDs with the original event text, including Python tracebacks. | `7b79f2ac83692126019934e6a7738524aaa55f3e2151237d8421cae0539aff72` |

The Git capture used `git daemon --verbose --export-all --log-destination=stderr`
with a loopback listener and a temporary base path. The recorder prepended a
UTC capture timestamp and tab, and replaced the temporary base path in error
messages with `/srv/qa-origins`. The fixture retains the other daemon text,
including the loopback addresses, ports, and process IDs.

All digests are checked before replay. Each NDJSON record is framed on the LF
byte before decoding UTF-8, so Unicode line separators inside JSON strings
stay part of the event. The archived record bytes are sent unchanged.
