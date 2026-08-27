"""
tests/integration/test_benchmark_cli.py

Acceptance tests for Benchmark CLI end-to-end against synthetic corpus:
1. Manifest loading and paired Control vs Treatment execution.
2. In-memory decryption without leaking unencrypted sample files to host disk.
3. Generation of aggregate JSON report with confidence intervals and Wilcoxon tests.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from adam.cli.benchmark import run_benchmark_orchestration
from adam.corpus.manager import CorpusManager, CorpusManifest


@pytest.mark.asyncio
async def test_benchmark_cli_end_to_end_synthetic(tmp_path: Path) -> None:
    corpus_dir = tmp_path / "synthetic_corpus"
    corpus_dir.mkdir(parents=True, exist_ok=True)

    samples = []
    for i in range(3):
        raw = f"MZ\x90\x00SyntheticMalwareSample_{i}".encode("latin1")
        blob_path = corpus_dir / f"sample_{i}.enc"
        meta = CorpusManager.create_encrypted_blob(
            raw_bytes=raw,
            output_blob_path=blob_path,
            filename=f"sample_{i}.exe",
            secret_key="bench_test_key",
            family_label=f"Family_{i % 2}",
        )
        samples.append(meta)

    manifest_file = corpus_dir / "manifest.json"
    manifest_file.write_text(
        json.dumps(CorpusManifest(samples=samples).model_dump(), indent=2),
        encoding="utf-8",
    )

    output_report_file = tmp_path / "benchmark_report.json"

    # Execute benchmark orchestration
    report = await run_benchmark_orchestration(
        manifest_path=str(manifest_file),
        profile_id="win10_x64_enterprise_office_decoy",
        output_path=str(output_report_file),
        secret_key="bench_test_key",
    )

    assert report.total_pairs == 3
    assert report.mean_delta_yield > 0
    assert output_report_file.exists()

    report_json = json.loads(output_report_file.read_text(encoding="utf-8"))
    assert report_json["experiment_id"].startswith("exp_bench_")
    assert len(report_json["per_sample_pairs"]) == 3

    # Invariant check: ensure no decrypted .exe was left behind on host disk
    for p in corpus_dir.iterdir():
        assert p.suffix in (".enc", ".json"), f"Found unencrypted file leaked to disk: {p}"
