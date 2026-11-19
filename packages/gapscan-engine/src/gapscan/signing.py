"""Signed local-run reports.

A local install signs the results of an offline run with its own ed25519 key; the workspace admin
registers that key's public half, and the workspace verifies every imported report against it. A
report carries findings and their evidence only: no SBOM, no raw scanner output, no local path.

The signature covers the exact bytes of `payload` (a JSON string), so the workspace verifies what
was signed before it parses anything, and no re-serialization can change the signed content.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, Field

from .core.version import __version__
from .models import ScanResult

FORMAT = "gapscan-local-run/1"
KEY_FILE = "install-key.pem"


class SignatureError(ValueError):
    """A report that is not signed by the key it names, or is not a local-run report."""


# --- install keys ---------------------------------------------------------------------------------


def create_key(path: Path) -> Ed25519PrivateKey:
    """A new install key, written only readable by its owner. Refuses to replace an existing one:
    the workspace would no longer accept this install's reports."""
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())  # fmt: skip
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    return key


def load_key(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SignatureError(f"{path} is not an ed25519 key")
    return key


def public_key_text(key: Ed25519PrivateKey | Ed25519PublicKey) -> str:
    """The public key as the admin registers it: base64 of the 32 raw bytes."""
    pub = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def parse_public_key(text: str) -> Ed25519PublicKey:
    try:
        raw = base64.b64decode(text.strip(), validate=True)
        return Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as exc:
        raise SignatureError("not an ed25519 public key (base64 of 32 bytes)") from exc


def fingerprint(public_key: str) -> str:
    """A short, stable name for a public key, for people to compare."""
    raw = base64.b64decode(public_key.strip())
    return "SHA256:" + hashlib.sha256(raw).hexdigest()[:32]


# --- reports --------------------------------------------------------------------------------------


class LocalRunReport(BaseModel):
    """What a local install sends: one offline run, bound to the workspace project it is for."""

    format: str = FORMAT
    project_id: str  # the workspace project; the signature stops a replay into another project
    created_at: str
    gapscan_version: str = __version__
    key_fingerprint: str
    scan: ScanResult


class SignedReport(BaseModel):
    payload: str  # the LocalRunReport as JSON, exactly as signed
    signature: str  # base64 ed25519 signature of payload's UTF-8 bytes
    key_fingerprint: str = Field(description="which registered key signed it")


def findings_and_evidence(scan: ScanResult) -> ScanResult:
    """The scan without what a local run keeps to itself: raw scanner output, the SBOM and the
    local folder path (only its name is kept)."""
    findings = [f.model_copy(update={"raw": {}}) for f in scan.findings]
    return scan.model_copy(update={"findings": findings, "sbom": None, "package_groups": [],
                                   "target": Path(scan.target).name})  # fmt: skip


def sign_report(scan: ScanResult, project_id: str, key: Ed25519PrivateKey) -> SignedReport:
    fp = fingerprint(public_key_text(key))
    # The scan's own time, not the signing time: signing the same run twice gives the same
    # report, which the workspace then refuses as already imported.
    created = scan.created_at or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    report = LocalRunReport(project_id=project_id, key_fingerprint=fp, created_at=created,
                            scan=findings_and_evidence(scan))  # fmt: skip
    payload = report.model_dump_json()
    signature = base64.b64encode(key.sign(payload.encode("utf-8"))).decode()
    return SignedReport(payload=payload, signature=signature, key_fingerprint=fp)


def verify_report(signed: SignedReport, public_key: str) -> LocalRunReport:
    """The report, if `public_key` signed exactly this payload; SignatureError otherwise."""
    try:
        parse_public_key(public_key).verify(
            base64.b64decode(signed.signature, validate=True), signed.payload.encode("utf-8")
        )
    except (InvalidSignature, ValueError) as exc:
        raise SignatureError("the signature does not match the registered key") from exc
    try:
        report = LocalRunReport.model_validate(json.loads(signed.payload))
    except ValueError as exc:
        raise SignatureError("the signed payload is not a local-run report") from exc
    if report.format != FORMAT:
        raise SignatureError(f"unsupported report format {report.format!r}")
    if report.key_fingerprint != fingerprint(public_key):
        raise SignatureError("the report names another key than the one that signed it")
    return report


def report_digest(signed: SignedReport) -> str:
    """Identifies one signed report, so the same report cannot be imported twice."""
    return hashlib.sha256(signed.payload.encode("utf-8")).hexdigest()
