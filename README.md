# SlopShield

SlopShield audits Python dependency **names before installation** using PyPI metadata. It highlights missing names, names similar to a small built-in list of popular projects, and latest releases uploaded less than seven days ago. It can save an AES-GCM encrypted Protocol Buffers report.

## Install and run

Python 3.11 or newer is required. Run these commands from the repository root:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python code/main.py requests numpy
python code/main.py --file examples/requirements.txt
```

`requirements.txt` contains the tool's dependencies. `examples/requirements.txt` contains intentionally suspicious demonstration inputs; **do not install it**. The legacy `code/requirements.txt` now also installs the tool's dependencies.

The scanner queries the public PyPI JSON API; it never installs the packages being audited. Requirement names, extras, version constraints and environment markers use the [PyPA requirement syntax](https://packaging.pypa.io/en/stable/requirements.html). Equivalent spellings such as `scikit.learn`, `scikit_learn` and `scikit-learn` are [normalized](https://packaging.python.org/en/latest/specifications/name-normalization/) and queried once.

Files support one requirement per line, blank lines, comments and inline comments preceded by whitespace. Marked dependencies are all audited, even when their marker does not match the current machine. Version constraints are parsed, but the scan checks the project name and **latest release**, not the pinned version or its vulnerabilities.

Nested requirements (`-r`), pip options, hashes, line continuations, editable/local packages and direct URLs are currently unsupported. They cause an input error with a file and line number rather than being silently skipped. The tool audits explicit inputs only; it does not resolve transitive dependencies or support npm/Cargo yet.

## Use as a CI gate

| Exit code | Meaning |
| --- | --- |
| `0` | All lookups completed and no name/age heuristic raised an alert. |
| `1` | Review needed: missing name, potential typo, fresh release, or unknown release age. |
| `2` | Audit incomplete: invalid/empty input, registry/network error, missing report password, or report write failure. |

Operational errors take precedence over risk alerts. The scan continues after an individual registry error, records it as a `Registry Error` alert with severity `ERROR`, and still saves the partial report if requested. A network failure is never classified as a missing package. Because the existing protobuf `exists_in_registry` field has no unknown state, consumers must check `Registry Error` alerts before interpreting a false value as absence.

For a dependency file containing supported requirements, place the audit before the install command in your CI job:

```sh
python -m pip install -r requirements.txt       # install SlopShield itself
python code/main.py --file path/to/app-requirements.txt
python -m pip install -r path/to/app-requirements.txt  # runs only if the audit passes
```

Use a shell/CI runner that stops the job on nonzero exit codes. Warnings deliberately block the gate and need human review. `LOW` means these limited heuristics did not flag the name; it does **not** establish that the package is safe. Similar names and fresh releases can be legitimate. No package source, reputation/download statistics or CVE database is checked. The typo reference list currently contains 20 names, not a complete allowlist.

## Encrypted reports

Supply a password through the environment to avoid including it in command arguments:

```sh
# Set SLOPSHIELD_PASSWORD through your shell or CI secret manager first.
python code/main.py requests --save audit.gsbom
```

`--password` is also supported and takes precedence over `SLOPSHIELD_PASSWORD`. Missing passwords are rejected before any network request. Saving a report preserves the audit's exit code; a successfully saved report may contain risk alerts or incomplete lookups.

Read a report locally using the same environment variable:

```sh
PYTHONPATH=code python - <<'PY'
import os
from google.protobuf.json_format import MessageToJson
from protos.audit_schema_pb2 import AuditReport
from secure_logger import SecureLogger

payload = SecureLogger(os.environ['SLOPSHIELD_PASSWORD']).load('audit.gsbom')
print(MessageToJson(AuditReport.FromString(payload)))
PY
```

The password derives a 256-bit key with scrypt. AES-GCM authenticates the ciphertext; the format is a 16-byte salt, 12-byte nonce and ciphertext including its authentication tag. An incorrect password or modified ciphertext fails decryption. Keep the password separate from the report. Anyone who knows the password can create a valid replacement; encryption is not a publisher signature.

## Development

```sh
python -m unittest discover -s tests -v
python -m compileall -q code tests
```

The tests use simulated registry responses and require no network access or API keys. They cover CI exit codes, strict input parsing, normalized names, malformed/unavailable registry data, release timestamps, report persistence, password errors and ciphertext tampering. GitHub Actions runs the suite on Python 3.11 and 3.13.

The generated protobuf module is checked in, so normal installation does not require `protoc`. If the schema changes, regenerate it from `code/` with a compatible compiler:

```sh
protoc --python_out=. protos/audit_schema.proto
```
