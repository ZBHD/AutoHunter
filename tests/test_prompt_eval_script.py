from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from scripts.evaluate_prompts import evaluate_profiles, load_cases, main


ROOT = Path(__file__).resolve().parents[1]


def test_prompt_eval_fixture_contains_five_distinct_cases() -> None:
    cases = load_cases()

    assert len(cases) == 5
    assert len({case["id"] for case in cases}) == 5


def test_prompt_eval_compares_five_runs_per_profile() -> None:
    report = evaluate_profiles(repeat=5)

    assert report["case_count"] == 5
    assert set(report["profiles"]) == {"legacy", "current"}
    assert len(report["profiles"]["legacy"]["runs"]) == 5
    assert len(report["profiles"]["current"]["runs"]) == 5
    assert report["profiles"]["current"]["aggregate"]["mean_score"] > report["profiles"]["legacy"]["aggregate"]["mean_score"]
    assert report["profiles"]["current"]["aggregate"]["estimated_tokens"] < report["profiles"]["legacy"]["aggregate"]["estimated_tokens"]


def test_prompt_eval_cli_writes_deterministic_json(tmp_path) -> None:
    output = tmp_path / "prompt-eval.json"

    assert main(["--repeat", "5", "--json-out", str(output)]) == 0

    report = json.loads(output.read_text(encoding="utf-8"))
    for profile in ("legacy", "current"):
        aggregate = report["profiles"][profile]["aggregate"]
        assert 0 <= aggregate["mean_score"] <= 1
        assert 0 <= aggregate["pass_rate"] <= 1
        assert aggregate["score_stddev"] == 0


def test_prompt_eval_script_runs_directly_from_repository_root(tmp_path) -> None:
    output = tmp_path / "direct.json"
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "evaluate_prompts.py"),
            "--repeat",
            "5",
            "--json-out",
            str(output),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert output.is_file()
