# Replay fixtures

These excerpts come from Bog QA's controlled loopback workloads. The captures
use QA-controlled paths, inputs, exceptions, and client identifiers. The
fixtures can be copied and redistributed under CC0-1.0.

| Fixture | Origin | SHA-256 |
| --- | --- | --- |
| `apache-access.log` | 256 verbatim Combined Log Format records from Apache HTTP Server 2.4.67. GET and HEAD requests returned 200, 403, and 404. | `29e286fd748b06450152c4efcfe9c4f2a668a8b3223720f7fba052ffd902b14e` |
| `replay.ndjson` | 513 Apache access records, 36 proxy errors, and 1,009 Python HTTP application records captured during loopback requests, plus 1,000 seeded records. The archive stores timestamps and capture IDs with the original event text, including Python tracebacks. | `7b79f2ac83692126019934e6a7738524aaa55f3e2151237d8421cae0539aff72` |

Both digests are checked before replay. Each NDJSON record is framed on the LF
byte before decoding UTF-8, so Unicode line separators inside JSON strings
stay part of the event. The archived record bytes are sent unchanged.
