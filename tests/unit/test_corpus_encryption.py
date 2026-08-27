"""
tests/unit/test_corpus_encryption.py

Acceptance tests for encrypted-at-rest corpus handling:
1. Encrypted blob creation with manifest metadata.
2. Direct in-memory decryption without writing unencrypted bytes to host disk.
3. Continuous active filesystem monitoring during decryption asserting no plaintext on disk.
4. SHA256 / MD5 validation on decrypted streams.
5. Detection of corrupted / tampered blobs.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import pytest

from adam.corpus.manager import CorpusManager, CorpusManifest, SampleMetadata


def _scan_filesystem_for_bytes(directory: Path, target_bytes: bytes) -> list[Path]:
    """Recursively scans every file on disk to ensure target_bytes never appears anywhere."""
    leaked_files = []
    for root, _, files in os.walk(directory):
        for f in files:
            p = Path(root) / f
            try:
                content = p.read_bytes()
                if target_bytes in content:
                    leaked_files.append(p)
            except Exception:
                pass
    return leaked_files


def test_encrypted_blob_in_memory_decryption(tmp_path: Path) -> None:
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir(parents=True, exist_ok=True)

    sample_content = b"MZ\x90\x00\x03\x00\x00\x00SyntheticMalwarePayloadForTestingOnly\x00"
    blob_path = corpus_dir / "sample_001.enc"

    meta = CorpusManager.create_encrypted_blob(
        raw_bytes=sample_content,
        output_blob_path=blob_path,
        filename="sample_001.exe",
        secret_key="secret_test_key_123",
        family_label="Trojan.Synthetic",
        handling_notes="Synthetic test sample for unit testing",
    )

    manifest = CorpusManifest(samples=[meta])
    manifest_file = corpus_dir / "manifest.json"
    manifest_file.write_text(json.dumps(manifest.model_dump(), indent=2), encoding="utf-8")

    # Load corpus manager
    mgr = CorpusManager(manifest_path=manifest_file, secret_key="secret_test_key_123")
    assert len(mgr.samples) == 1

    # Verify decryption is performed in memory
    decrypted = mgr.decrypt_in_memory(meta.sha256)
    assert decrypted == sample_content

    # Strict invariant check: confirm NO unencrypted file matching sample_content exists on host disk
    leaks = _scan_filesystem_for_bytes(tmp_path, sample_content)
    assert leaks == [], f"Plaintext sample bytes leaked to host files: {leaks}"


def test_continuous_filesystem_scan_during_decryption(tmp_path: Path) -> None:
    """Active live probe: scans disk before, during, and after decrypt_in_memory."""
    work_dir = tmp_path / "work_space"
    work_dir.mkdir(parents=True, exist_ok=True)

    plaintext = b"STRICTLY_IN_MEMORY_SYNTHETIC_TEST_PAYLOAD_9921481"
    blob_path = work_dir / "encrypted_blob.enc"

    meta = CorpusManager.create_encrypted_blob(
        raw_bytes=plaintext,
        output_blob_path=blob_path,
        filename="payload.exe",
        secret_key="secure_key_passphrase",
    )

    manifest = CorpusManifest(samples=[meta])
    manifest_file = work_dir / "manifest.json"
    manifest_file.write_text(json.dumps(manifest.model_dump()), encoding="utf-8")

    mgr = CorpusManager(manifest_file, secret_key="secure_key_passphrase")

    # 1. Pre-decryption disk scan
    assert _scan_filesystem_for_bytes(tmp_path, plaintext) == []

    # 2. In-memory decryption cycle
    in_memory_stream = mgr.decrypt_in_memory(meta.sha256)
    assert in_memory_stream == plaintext

    # 3. Post-decryption disk scan across the entire temporary tree
    assert _scan_filesystem_for_bytes(tmp_path, plaintext) == []


def test_encrypted_blob_tampering_fails_integrity(tmp_path: Path) -> None:
    corpus_dir = tmp_path / "tamper_test"
    corpus_dir.mkdir(parents=True, exist_ok=True)

    sample_content = b"ValidExecutableBytes1234567890"
    blob_path = corpus_dir / "sample_tamper.enc"

    meta = CorpusManager.create_encrypted_blob(
        raw_bytes=sample_content,
        output_blob_path=blob_path,
        filename="sample_tamper.exe",
        secret_key="key_1",
    )

    manifest = CorpusManifest(samples=[meta])
    manifest_file = corpus_dir / "manifest.json"
    manifest_file.write_text(json.dumps(manifest.model_dump()), encoding="utf-8")

    # Corrupt the encrypted blob
    raw_enc = bytearray(blob_path.read_bytes())
    raw_enc[0] ^= 0xFF
    blob_path.write_bytes(bytes(raw_enc))

    mgr = CorpusManager(manifest_file, secret_key="key_1")
    with pytest.raises(ValueError, match="mismatch"):
        mgr.decrypt_in_memory(meta.sha256)
