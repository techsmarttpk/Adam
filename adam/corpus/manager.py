"""
adam/corpus/manager.py

Corpus manager handling encrypted-at-rest sample blobs and manifest integrity.
Never writes decrypted sample bytes to host disk -- streams in-memory directly
to the guest VM transfer pipeline.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
from pathlib import Path
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class SampleMetadata(BaseModel):
    sha256: str = Field(min_length=64, max_length=64)
    md5: str = Field(min_length=32, max_length=32)
    filename: str
    size_bytes: int = Field(ge=0)
    file_type: str = "PE32 executable"
    family_label: Optional[str] = None
    acquisition_source: Optional[str] = None
    acquisition_date: Optional[str] = None
    handling_notes: Optional[str] = None
    encrypted_blob_path: str


class CorpusManifest(BaseModel):
    corpus_version: str = "1.0"
    description: str = "ADAM Benchmark Corpus"
    samples: List[SampleMetadata] = Field(default_factory=list)


def _derive_key(passphrase: str | bytes, salt: bytes = b"adam_corpus_salt_2026") -> bytes:
    if isinstance(passphrase, str):
        passphrase = passphrase.encode("utf-8")
    return hashlib.pbkdf2_hmac("sha256", passphrase, salt, 100_000, 32)


def _xor_cipher(data: bytes, key: bytes) -> bytes:
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


class CorpusManager:
    """
    Manages encrypted sample blobs and manifest integrity.
    Enforces the invariant: decrypted sample bytes exist ONLY in memory
    and are never written to any host file.
    """

    def __init__(self, manifest_path: str | Path, secret_key: str | bytes = "adam_default_key") -> None:
        self.manifest_path = Path(manifest_path)
        self.secret_key = _derive_key(secret_key)
        self._samples_by_sha: Dict[str, SampleMetadata] = {}
        self._manifest: CorpusManifest | None = None
        self.load_manifest()

    def load_manifest(self) -> CorpusManifest:
        if not self.manifest_path.exists():
            raise FileNotFoundError(f"Manifest not found at '{self.manifest_path}'")

        raw_data = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        self._manifest = CorpusManifest.model_validate(raw_data)
        self._samples_by_sha = {s.sha256.lower(): s for s in self._manifest.samples}
        return self._manifest

    @property
    def samples(self) -> List[SampleMetadata]:
        return list(self._samples_by_sha.values())

    def get_metadata(self, sha256: str) -> SampleMetadata:
        sha_lower = sha256.lower()
        if sha_lower not in self._samples_by_sha:
            raise KeyError(f"Sample with SHA256 '{sha256}' not found in manifest")
        return self._samples_by_sha[sha_lower]

    def decrypt_in_memory(self, sha256: str) -> bytes:
        """
        Decrypts sample blob straight into memory (bytes).
        Strictly guarantees NO unencrypted payload is written to host disk.
        """
        meta = self.get_metadata(sha256)
        blob_path = Path(meta.encrypted_blob_path)
        if not blob_path.is_absolute():
            blob_path = self.manifest_path.parent / blob_path

        if not blob_path.exists():
            raise FileNotFoundError(f"Encrypted blob not found at '{blob_path}'")

        encrypted_bytes = blob_path.read_bytes()
        decrypted_bytes = _xor_cipher(encrypted_bytes, self.secret_key)

        # Integrity verification against manifest metadata
        computed_sha = hashlib.sha256(decrypted_bytes).hexdigest()
        computed_md5 = hashlib.md5(decrypted_bytes).hexdigest()

        if computed_sha.lower() != meta.sha256.lower():
            raise ValueError(
                f"SHA256 mismatch for sample {meta.filename}: expected {meta.sha256}, got {computed_sha}"
            )
        if computed_md5.lower() != meta.md5.lower():
            raise ValueError(
                f"MD5 mismatch for sample {meta.filename}: expected {meta.md5}, got {computed_md5}"
            )

        return decrypted_bytes

    def verify_all(self) -> dict[str, bool]:
        """Verify all samples in manifest decrypt and match checksums."""
        results = {}
        for sample in self.samples:
            try:
                self.decrypt_in_memory(sample.sha256)
                results[sample.sha256] = True
            except Exception:
                results[sample.sha256] = False
        return results

    @classmethod
    def create_encrypted_blob(
        cls,
        raw_bytes: bytes,
        output_blob_path: Path | str,
        filename: str,
        secret_key: str | bytes = "adam_default_key",
        family_label: str | None = None,
        handling_notes: str | None = None,
    ) -> SampleMetadata:
        """Helper to create an encrypted sample blob and return its manifest metadata."""
        out_path = Path(output_blob_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        key = _derive_key(secret_key)
        encrypted = _xor_cipher(raw_bytes, key)
        out_path.write_bytes(encrypted)

        sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
        md5_hash = hashlib.md5(raw_bytes).hexdigest()

        return SampleMetadata(
            sha256=sha256_hash,
            md5=md5_hash,
            filename=filename,
            size_bytes=len(raw_bytes),
            file_type="PE32 executable",
            family_label=family_label,
            acquisition_source="Synthetic Demo Corpus",
            acquisition_date="2026-08-08",
            handling_notes=handling_notes,
            encrypted_blob_path=str(out_path),
        )
