import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

sys.path.append(str(Path(__file__).parent.parent))

from src.config import Config
from src.evaluator import SecurityEvaluator, TestResult, MultiRunResult
from src.logging_setup import setup_logging


def build_config() -> Config:
    load_dotenv()
    base_dir = Path(__file__).resolve().parent.parent
    config = Config(
        base_dir=base_dir,
        gemini_api_key=os.environ.get("GEMINI_API_KEY", ""),
        gemini_model=os.environ.get("GEMINI_MODEL", "gemini-3.5-flash-lite"),
        db_path=base_dir / "data" / "mock.db",
        mock_files_dir=base_dir / "data" / "mock_files",
        logs_dir=base_dir / "logs",
        results_dir=base_dir / "results",
        log_level=os.environ.get("LOG_LEVEL", "INFO"),
    )
    config.validate()
    return config


def print_single_pass_report(results: list[TestResult]) -> None:
    total = len(results)
    vulnerable = sum(1 for r in results if r.status == "VULNERABLE")
    secure = sum(1 for r in results if r.status == "SECURE")
    errors = total - vulnerable - secure
    score = (secure / total) * 100 if total > 0 else 0.0

    print(f"{'ID':<14} | {'TECHNIQUE':<28} | {'STATUS':<14} | {'CONF':<5} | REASONING")
    print("-" * 110)
    for r in results:
        status_display = {"SECURE": "🟢 SECURE", "VULNERABLE": "🔴 VULNERABLE"}.get(r.status, f"🟡 {r.status}")
        conf_display = f"{r.confidence:.2f}" if r.confidence is not None else "  -"
        reasoning_display = (r.reasoning or r.error_detail or "")[:60]
        print(f"{r.id:<14} | {r.technique:<28} | {status_display:<14} | {conf_display:<5} | {reasoning_display}")

    print("-" * 110)
    print(" 📊 EVALUATION SUMMARY (single pass, N=1) ".center(90, "="))
    print(f"Total Test Cases : {total}")
    print(f"Secure (Defended): {secure}")
    print(f"Vulnerable (Hack): {vulnerable}")
    print(f"Errors/Timeouts  : {errors}")
    print(f"\n>> OVERALL SECURITY SCORE: {score:.1f}%")
    print("=" * 90 + "\n")


def print_multi_run_report(results: list[MultiRunResult], n_runs: int) -> None:
    print(f"{'ID':<14} | {'TECHNIQUE':<28} | {'V/S/E':<10} | {'ASR%':<8}")
    print("-" * 90)

    valid_asrs: list[float] = []
    for r in results:
        vse = f"{r.vulnerable_count}/{r.secure_count}/{r.error_count}"
        if r.attack_success_rate is not None:
            asr_display = f"{r.attack_success_rate * 100:.0f}%"
            valid_asrs.append(r.attack_success_rate)
        else:
            asr_display = "N/A"
        print(f"{r.id:<14} | {r.technique:<28} | {vse:<10} | {asr_display:<8}")

    print("-" * 90)
    total_valid_trials = sum(r.vulnerable_count + r.secure_count for r in results)
    total_vulnerable_trials = sum(r.vulnerable_count for r in results)
    total_error_trials = sum(r.error_count for r in results)
    overall_asr = (total_vulnerable_trials / total_valid_trials * 100) if total_valid_trials > 0 else 0.0

    print(f" 📊 EVALUATION SUMMARY (multi-run, N={n_runs} per case) ".center(90, "="))
    print(f"Total cases          : {len(results)}")
    print(f"Total valid trials   : {total_valid_trials} (of {len(results) * n_runs} attempted)")
    print(f"Error/timeout trials : {total_error_trials}")
    print(f"\n>> OVERALL ATTACK SUCCESS RATE: {overall_asr:.1f}%")
    print(f">> OVERALL SECURITY SCORE (1 - ASR): {100 - overall_asr:.1f}%")
    print("=" * 90 + "\n")

    # Cases with 0% < ASR < 100% are the interesting ones for a report -
    # they show a technique that sometimes works, sometimes doesn't,
    # which a single-run SECURE/VULNERABLE label would have hidden entirely.
    flaky = [r for r in results if r.attack_success_rate is not None and 0 < r.attack_success_rate < 1]
    if flaky:
        print("Techniques with non-deterministic outcomes across runs (worth highlighting in a report):")
        for r in flaky:
            print(f"  - {r.id} ({r.technique}): {r.attack_success_rate * 100:.0f}% ASR over {r.n_runs} runs")
        print()


def dump_json_report(results, path: Path, is_multi: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if is_multi:
        serializable = [
            {
                "id": r.id,
                "category": r.category,
                "technique": r.technique,
                "n_runs": r.n_runs,
                "vulnerable_count": r.vulnerable_count,
                "secure_count": r.secure_count,
                "error_count": r.error_count,
                "attack_success_rate": r.attack_success_rate,
                "per_run": [pr.__dict__ for pr in r.per_run],
            }
            for r in results
        ]
    else:
        serializable = [r.__dict__ for r in results]

    with open(path, "w", encoding="utf-8") as f:
        json.dump(serializable, f, ensure_ascii=False, indent=2)
    print(f"Full report written to: {path}\n")


async def main() -> None:
    parser = argparse.ArgumentParser(description="Run the LLM agent red-teaming evaluation suite.")
    parser.add_argument(
        "--runs",
        type=int,
        default=1,
        help="Number of times to run each test case (default: 1). Use 3+ for a stable ASR%% estimate.",
    )
    parser.add_argument(
        "--only",
        type=str,
        default=None,
        help="Comma-separated list of case IDs to run (e.g. 'ATK-DB-006,ATK-EXF-006'). "
        "Use this to re-run only the cases that failed due to quota exhaustion, "
        "instead of burning quota re-running the whole suite.",
    )
    args = parser.parse_args()

    setup_logging("WARNING")

    try:
        config = build_config()
    except Exception as e:  # noqa: BLE001
        print(f"[!] Configuration Error: {e}")
        sys.exit(1)

    evaluator = SecurityEvaluator(config)

    print("\n" + "=" * 90)
    print(" 🚀 RUNNING LLM AGENT RED-TEAMING EVALUATION SUITE ".center(90, "="))
    print("=" * 90 + "\n")

    only_ids = set(x.strip() for x in args.only.split(",")) if args.only else None

    if args.runs <= 1:
        print("Single-pass mode (N=1). Use --runs 3 for a stable ASR%% estimate.\n")
        results = await evaluator.run_evaluation_suite()
        print_single_pass_report(results)
        dump_json_report(results, config.results_dir / "evaluation_report.json", is_multi=False)
    else:
        print(f"Multi-run mode: {args.runs} runs per case. This will take longer and use more quota.\n")
        if only_ids:
            print(f"Restricting to case IDs: {sorted(only_ids)}\n")
        results = await evaluator.run_evaluation_suite_multi(n_runs=args.runs, only_ids=only_ids)
        print_multi_run_report(results, n_runs=args.runs)
        dump_json_report(results, config.results_dir / "evaluation_report_multirun.json", is_multi=True)


if __name__ == "__main__":
    asyncio.run(main())