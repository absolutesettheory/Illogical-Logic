#!/usr/bin/env bash

# Create a content-integrity certificate for a source file.
# A SHA-256 digest can show that content has not changed; it does not prove
# authorship, identity, legal ownership, or the validity of a research claim.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
AUTHOR="${AUTHOR:-Christopher Thomas Ronio}"
FRAMEWORK="${FRAMEWORK:-Relational Boundary Framework}"
INPUT_FILE="${1:-${REPO_ROOT}/Algebraic.md}"
OUTPUT_FILE="${2:-${PWD}/rpa_certificate.json}"

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 is required." >&2
    exit 1
fi

python3 - "${INPUT_FILE}" "${OUTPUT_FILE}" "${REPO_ROOT}" "${AUTHOR}" "${FRAMEWORK}" <<'PY'
import hashlib
import json
import os
import pathlib
import sys
import tempfile
from datetime import datetime, timezone

input_arg, output_arg, repo_root_arg, author, framework = sys.argv[1:]
repo_root = pathlib.Path(repo_root_arg).resolve()


def resolve_input(value: str) -> pathlib.Path:
    path = pathlib.Path(value).expanduser()
    if path.is_absolute():
        return path.resolve()
    cwd_path = path.resolve()
    if cwd_path.is_file():
        return cwd_path
    return (repo_root / path).resolve()


input_file = resolve_input(input_arg)
output_file = pathlib.Path(output_arg).expanduser()
if not output_file.is_absolute():
    output_file = (pathlib.Path.cwd() / output_file).resolve()
else:
    output_file = output_file.resolve()

if not input_file.is_file():
    raise SystemExit(f"Error: input file not found: {input_file}")
if input_file == output_file:
    raise SystemExit("Error: output file must not overwrite the input file")

try:
    source_bytes = input_file.read_bytes()
except OSError as exc:
    raise SystemExit(f"Error: cannot read input file: {exc}") from exc

source_hash = hashlib.sha256(source_bytes).hexdigest()

# The available RPA example produces a salted receipt; it does not implement
# the F(X) classification described in the README. Do not claim that it did.
certificate = {
    "certificate_type": "CONTENT_INTEGRITY_CERTIFICATE",
    "certificate_version": "1.1",
    "author_claim": author,
    "framework": framework,
    "source": {
        "file": input_file.name,
        "sha256": source_hash,
    },
    "framework_evaluation": {
        "status": "NOT_PERFORMED",
        "reason": (
            "The available RPA example generates a salted receipt and does "
            "not implement or validate the proposed F(X) classification."
        ),
    },
    "created_at_utc": datetime.now(timezone.utc).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z"),
    "verification": {
        "hash_algorithm": "SHA-256",
        "canonicalization": "JSON sorted keys, UTF-8, compact separators",
        "commitment_scope": "Complete certificate payload with commitment=null",
        "limitations": (
            "The digest can detect content changes when compared with a "
            "trusted copy. It does not independently establish authorship, "
            "identity, legal ownership, or scientific validity."
        ),
    },
    "commitment": None,
}

canonical_bytes = json.dumps(
    certificate,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=False,
).encode("utf-8")
certificate_hash = hashlib.sha256(canonical_bytes).hexdigest()
certificate["commitment"] = {
    "algorithm": "SHA-256",
    "digest": certificate_hash,
}

try:
    output_file.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        newline="\n",
        dir=output_file.parent,
        prefix=f".{output_file.name}.",
        suffix=".tmp",
        delete=False,
    ) as temporary:
        temporary_path = pathlib.Path(temporary.name)
        json.dump(certificate, temporary, indent=2, sort_keys=True, ensure_ascii=False)
        temporary.write("\n")
        temporary.flush()
        os.fsync(temporary.fileno())
    os.replace(temporary_path, output_file)
except OSError as exc:
    if temporary_path is not None:
        try:
            temporary_path.unlink(missing_ok=True)
        except OSError:
            pass
    raise SystemExit(f"Error: cannot write certificate: {exc}") from exc

print("Content-integrity certificate generated.")
print(f"  Source SHA-256: {source_hash}")
print(f"  Commitment:     {certificate_hash}")
print(f"  Output:         {output_file}")
print("  Note: SHA-256 does not prove authorship or legal ownership.")
PY
