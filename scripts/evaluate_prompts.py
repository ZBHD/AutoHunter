"""Deterministic offline comparison for the legacy and current Worker prompts."""
from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
from pathlib import Path
from typing import Any, Sequence

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CASES = ROOT / "tests" / "fixtures" / "prompt_eval_cases.json"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.agents.prompts import worker_system_prompt


def load_cases(path: str | Path | None = None) -> list[dict[str, Any]]:
    source = Path(path) if path else DEFAULT_CASES
    data = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(data, list) or not data:
        raise ValueError("prompt evaluation cases must be a non-empty list")
    ids = [str(case.get("id") or "") for case in data if isinstance(case, dict)]
    if len(ids) != len(data) or any(not case_id for case_id in ids):
        raise ValueError("every prompt evaluation case must have an id")
    if len(set(ids)) != len(ids):
        raise ValueError("prompt evaluation case ids must be unique")
    return data


def estimate_tokens(text: str) -> int:
    cjk = sum(1 for char in text if "\u3400" <= char <= "\u9fff")
    non_cjk = len(text) - cjk
    return cjk + math.ceil(non_cjk / 4)


def _evaluate_case(prompt: str, case: dict[str, Any]) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    for marker in case.get("required_all", []):
        checks.append({"marker": marker, "expected": "present", "passed": marker in prompt})
    for marker in case.get("forbidden_any", []):
        checks.append({"marker": marker, "expected": "absent", "passed": marker not in prompt})
    if not checks:
        raise ValueError(f"case {case['id']} has no assertions")
    passed_count = sum(1 for check in checks if check["passed"])
    return {
        "id": case["id"],
        "name": case.get("name") or case["id"],
        "passed": passed_count == len(checks),
        "score": round(passed_count / len(checks), 4),
        "checks": checks,
    }


def evaluate_profiles(*, repeat: int = 5, cases_path: str | Path | None = None) -> dict[str, Any]:
    if repeat < 1:
        raise ValueError("repeat must be positive")
    cases = load_cases(cases_path)
    profiles: dict[str, Any] = {}
    for profile in ("legacy", "current"):
        prompt = worker_system_prompt("edusrc", profile)
        runs: list[dict[str, Any]] = []
        for run_number in range(1, repeat + 1):
            results = [_evaluate_case(prompt, case) for case in cases]
            runs.append({
                "run": run_number,
                "mean_score": round(statistics.fmean(result["score"] for result in results), 4),
                "pass_rate": round(sum(result["passed"] for result in results) / len(results), 4),
                "cases": results,
            })
        scores = [run["mean_score"] for run in runs]
        pass_rates = [run["pass_rate"] for run in runs]
        profiles[profile] = {
            "runs": runs,
            "aggregate": {
                "mean_score": round(statistics.fmean(scores), 4),
                "pass_rate": round(statistics.fmean(pass_rates), 4),
                "score_stddev": round(statistics.pstdev(scores), 4),
                "prompt_characters": len(prompt),
                "estimated_tokens": estimate_tokens(prompt),
            },
        }
    return {
        "evaluation": "offline_prompt_contract",
        "case_count": len(cases),
        "repeat": repeat,
        "profiles": profiles,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeat", type=int, default=5)
    parser.add_argument("--cases", default=str(DEFAULT_CASES))
    parser.add_argument("--json-out")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    report = evaluate_profiles(repeat=args.repeat, cases_path=args.cases)
    if args.json_out:
        output = Path(args.json_out)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for profile, data in report["profiles"].items():
        aggregate = data["aggregate"]
        print(
            f"{profile}: score={aggregate['mean_score']:.2%} "
            f"pass={aggregate['pass_rate']:.2%} chars={aggregate['prompt_characters']} "
            f"est_tokens={aggregate['estimated_tokens']} stddev={aggregate['score_stddev']:.4f}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
