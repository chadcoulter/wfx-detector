#!/usr/bin/env python3
"""Koppa-backed deterministic source manifest gate for WFX builds.

Seal: snapshot the Git-tracked build inputs, encode a canonical manifest, and
store the digest as a Koppa FunctionToken outside the framed artifact.
Verify: check the token, framing, manifest, and actual source tree again.

This is an integrity check, not a signature or proof of trusted provenance.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import subprocess
import tempfile
from pathlib import Path

from koppa import FunctionToken, fixed_point_digest, seal, verify

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "build" / "koppa"
MANIFEST_NAME = "manifest.koppa"
TOKEN_NAME = "manifest.token"
ARTIFACT_DIGEST_NAME = "manifest.sha256"


def tracked_files() -> list[str]:
    result = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-z", "--cached"],
        check=True,
        stdout=subprocess.PIPE,
    )
    names = [os.fsdecode(item) for item in result.stdout.split(b"\x00") if item]
    return sorted(names)


def source_records() -> list[dict[str, str | int]]:
    records: list[dict[str, str | int]] = []
    for name in tracked_files():
        path = ROOT / name
        if not path.is_file() or path.is_symlink():
            raise RuntimeError(f"Tracked source must be a regular file: {name}")
        data = path.read_bytes()
        records.append({"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    return records


def manifest_payload() -> bytes:
    # Stable encoding: independent of locale, platform line endings and timestamps.
    value = {"schema": "wfx-koppa-build-v1", "files": source_records()}
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def seal_build(output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    payload = manifest_payload()
    artifact, token, _ = seal(payload)
    if not verify(artifact, token):
        raise RuntimeError("Koppa seal self-check failed")
    # Exercise both negative controls before publishing the integrity envelope.
    wrong = FunctionToken.from_digest(hashlib.sha256(b"wrong-token").digest())
    if verify(artifact, wrong) or verify(artifact + b"tampered", token):
        raise RuntimeError("Koppa tampering negative control failed")
    (output / MANIFEST_NAME).write_bytes(artifact)
    (output / TOKEN_NAME).write_text(token.serialize() + "\n", encoding="utf-8")
    (output / ARTIFACT_DIGEST_NAME).write_text(fixed_point_digest(payload, token).hex() + "\n", encoding="ascii")


def verify_build(output: Path) -> None:
    artifact = (output / MANIFEST_NAME).read_bytes()
    token = FunctionToken.parse((output / TOKEN_NAME).read_text(encoding="utf-8").strip())
    if not verify(artifact, token):
        raise RuntimeError("Koppa manifest digest verification failed")
    expected = (output / ARTIFACT_DIGEST_NAME).read_text(encoding="ascii").strip()
    actual = hashlib.sha256(artifact).hexdigest()
    if not hmac.compare_digest(expected, actual):
        raise RuntimeError("Koppa framed artifact digest mismatch")
    from koppa import HANDLE

    frame = b"\n" + HANDLE + b"\n"
    if not artifact.endswith(frame):
        raise RuntimeError("Koppa artifact framing missing")
    payload = artifact[: -len(frame)]
    # Compare the manifest bytes to a fresh, canonical, Git-tracked source inventory.
    if payload != manifest_payload():
        raise RuntimeError("Build input changed after Koppa sealing")
    parsed = json.loads(payload)
    if parsed.get("schema") != "wfx-koppa-build-v1":
        raise RuntimeError("Unsupported Koppa manifest schema")


def selftest() -> None:
    """Validate actual on-disk artifact tampering and source-change detection."""
    with tempfile.TemporaryDirectory(prefix="wfx-koppa-") as temporary:
        output = Path(temporary)
        seal_build(output)
        verify_build(output)
        good = (output / MANIFEST_NAME).read_bytes()
        (output / MANIFEST_NAME).write_bytes(good.replace(b"wfx-koppa-build-v1", b"wfx-koppa-build-v0"))
        try:
            verify_build(output)
        except RuntimeError:
            pass
        else:
            raise RuntimeError("Tampered artifact was not rejected")
        (output / MANIFEST_NAME).write_bytes(good)
        token_path = output / TOKEN_NAME
        token_path.write_text(
            FunctionToken.from_digest(hashlib.sha256(b"incorrect").digest()).serialize() + "\n",
            encoding="utf-8",
        )
        try:
            verify_build(output)
        except RuntimeError:
            pass
        else:
            raise RuntimeError("Wrong token was not rejected")
        seal_build(output)
        original_payload = manifest_payload
        try:
            globals()["manifest_payload"] = lambda: original_payload() + b"changed"
            try:
                verify_build(output)
            except RuntimeError:
                pass
            else:
                raise RuntimeError("Changed source was not rejected")
        finally:
            globals()["manifest_payload"] = original_payload



def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["seal", "verify", "selftest"])
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    if args.command == "seal":
        seal_build(args.output)
    elif args.command == "verify":
        verify_build(args.output)
    else:
        selftest()
    print(f"Koppa build integrity {args.command}: OK")


if __name__ == "__main__":
    main()
