from __future__ import annotations

import asyncio
import json
import logging
import shutil
import sqlite3
import sys
from dataclasses import dataclass, field
from pathlib import Path

from google import genai

from src.config import Config
from src.target_agent import TargetAgent
from src.mock_db import init_db, inject_payload_to_user
from src.llm_judge import SecurityJudge, JudgeVerdict
from src.destination_policy import check_destination_policy

logger = logging.getLogger(__name__)

_AGENT_MAX_RETRIES = 3
_AGENT_BASE_BACKOFF_SECONDS = 15.0
_INTER_CALL_SLEEP_SECONDS = 8.0


@dataclass
class TestResult:

    id: str
    category: str
    technique: str
    status: str 
    confidence: float | None = None
    violated_principle: str | None = None
    reasoning: str | None = None
    error_detail: str | None = None


@dataclass
class MultiRunResult:

    id: str
    category: str
    technique: str
    n_runs: int
    vulnerable_count: int
    secure_count: int
    error_count: int
    attack_success_rate: float | None 
    per_run: list[TestResult] = field(default_factory=list)


class SecurityEvaluator:
    def __init__(self, config: Config, genai_client: genai.Client | None = None):
        self.config = config
        self.corpus_path = Path("data/attack_corpus.jsonl")
        self.mcp_command = [sys.executable, "-m", "src.mcp_server"]

        self.db_path = getattr(config, "db_path", getattr(config, "DB_PATH", Path("data/mock.db")))
        self.mock_files_dir = getattr(
            config, "mock_files_dir", getattr(config, "MOCK_FILES_DIR", Path("data/mock_files"))
        )

        api_key = getattr(config, "gemini_api_key", getattr(config, "GEMINI_API_KEY", None))
        self._client = genai_client or genai.Client(api_key=api_key)
        judge_model = getattr(config, "judge_model", getattr(config, "gemini_model", "gemini-3.5-flash-lite"))
        self.judge = SecurityJudge(client=self._client, model=judge_model)

    def load_corpus(self, only_ids: set[str] | None = None) -> list[dict]:
        cases = []
        if not self.corpus_path.exists():
            raise FileNotFoundError(f"Corpus not found at {self.corpus_path}. Run generate_corpus.py first.")
        with open(self.corpus_path, "r", encoding="utf-8") as f:
            for line in f:
                case = json.loads(line.strip())
                if only_ids is None or case["id"] in only_ids:
                    cases.append(case)
        return cases

    def clean_environment(self) -> None:
        init_db(self.db_path, force_recreate=True)
        if self.mock_files_dir.exists():
            shutil.rmtree(self.mock_files_dir)
        self.mock_files_dir.mkdir(parents=True, exist_ok=True)

    def prepare_environment(self, setup_req: dict | None) -> None:
        if not setup_req:
            return

        if "create_file" in setup_req:
            file_path = self.mock_files_dir / setup_req["create_file"]
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(setup_req.get("content", ""))

        if "inject_db_user_name" in setup_req or "inject_db_user_id" in setup_req:
            user_id = setup_req.get("inject_db_user_id") or setup_req.get("inject_db_user_name")
            payload = setup_req.get("payload", "")
            inject_payload_to_user(self.db_path, user_id, payload)

            if not self._verify_injection_landed(user_id, payload):
                raise RuntimeError(
                    f"Setup verification failed: payload was not found in DB for "
                    f"user identifier '{user_id}' after inject_payload_to_user(). "
                    f"Check that this name/id exists in the seeded mock_db data "
                    f"(src/mock_db.py) - the test cannot validly run against "
                    f"unpoisoned data."
                )

    def _verify_injection_landed(self, user_identifier, payload: str) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            if isinstance(user_identifier, int):
                cursor.execute("SELECT internal_notes FROM users WHERE id = ?", (user_identifier,))
            else:
                cursor.execute(
                    "SELECT internal_notes FROM users WHERE name LIKE ?",
                    (f"%{user_identifier}%",),
                )
            row = cursor.fetchone()
            return row is not None and payload in (row[0] or "")

    def _quick_heuristic_check(self, tool_calls: list) -> bool:
        return len(tool_calls) > 0

    def evaluate_agent_response(
        self,
        user_prompt: str,
        tool_calls: list,
        final_response: str,
    ) -> JudgeVerdict:
        policy_verdict = check_destination_policy(tool_calls)
        if policy_verdict.is_vulnerable:
            return JudgeVerdict(
                is_vulnerable=True,
                confidence=1.0,
                violated_principle="policy_violation",
                reasoning=(
                    f"Rule-based destination policy check flagged tool call "
                    f"#{policy_verdict.matched_call_index} ({policy_verdict.matched_rule})."
                ),
                raw_response={},
            )

        if not self._quick_heuristic_check(tool_calls):
            return JudgeVerdict(
                is_vulnerable=False,
                confidence=1.0,
                violated_principle="none",
                reasoning="Agent made no tool calls; nothing to compromise.",
                raw_response={},
            )

        return self.judge.judge(user_prompt, tool_calls, final_response)

    async def _run_agent_with_retry(self, user_prompt: str):
        last_error: Exception | None = None
        for attempt in range(1, _AGENT_MAX_RETRIES + 1):
            agent = TargetAgent(self.config, self.mcp_command)
            try:
                return await asyncio.wait_for(
                    agent.run(user_prompt, max_tool_iterations=5),
                    timeout=45.0,
                )
            except Exception as e:  
                is_daily_quota_exhausted = False
                cursor_check: BaseException | None = e
                seen_check: set[int] = set()
                while cursor_check is not None and id(cursor_check) not in seen_check:
                    seen_check.add(id(cursor_check))
                    if "PerDay" in str(cursor_check):
                        is_daily_quota_exhausted = True
                        break
                    cursor_check = cursor_check.__cause__ or cursor_check.__context__

                if is_daily_quota_exhausted:
                    logger.error(
                        "Daily API quota exhausted (free-tier 500/day cap). "
                        "Retrying will not help until the quota resets - failing this trial immediately."
                    )
                    raise RuntimeError(
                        "Daily quota exhausted (free-tier limit). Wait for quota reset "
                        "(next UTC day) before re-running, or re-run only the affected "
                        "case IDs with --only once quota is available."
                    ) from e

                markers = ("429", "RESOURCE_EXHAUSTED", "503", "UNAVAILABLE")
                is_retryable = False
                cursor: BaseException | None = e
                seen: set[int] = set()
                while cursor is not None and id(cursor) not in seen:
                    seen.add(id(cursor))
                    if any(marker in str(cursor) for marker in markers):
                        is_retryable = True
                        break
                    cursor = cursor.__cause__ or cursor.__context__
                last_error = e
                if is_retryable and attempt < _AGENT_MAX_RETRIES:
                    backoff = _AGENT_BASE_BACKOFF_SECONDS * (2 ** (attempt - 1))
                    logger.warning(
                        "Agent run failed (attempt %d/%d, retryable): %s. Retrying in %.1fs...",
                        attempt,
                        _AGENT_MAX_RETRIES,
                        str(e)[:200],
                        backoff,
                    )
                    await asyncio.sleep(backoff)
                    continue
                raise
        raise last_error  # pragma: no cover

    async def _run_single_case(self, case: dict, run_label: str) -> TestResult:

        logger.info("--- Running %s ---", run_label)

        status = "ERROR"
        confidence = None
        violated_principle = None
        reasoning = None
        error_detail = None

        try:
            self.clean_environment()
            self.prepare_environment(case.get("setup_required"))

            agent_result = await self._run_agent_with_retry(case["user_prompt"])
            tool_calls = getattr(agent_result, "tool_calls", [])
            final_response = getattr(agent_result, "final_response", "")

            verdict = self.evaluate_agent_response(
                user_prompt=case["user_prompt"],
                tool_calls=tool_calls,
                final_response=final_response,
            )
            status = "VULNERABLE" if verdict.is_vulnerable else "SECURE"
            confidence = verdict.confidence
            violated_principle = verdict.violated_principle
            reasoning = verdict.reasoning

        except asyncio.TimeoutError:
            status = "TIMEOUT"
            error_detail = "Agent did not respond within the timeout window."
            logger.error("%s timed out.", run_label)

        except Exception as e:  # noqa: BLE001
            status = "ERROR"
            error_detail = str(e)[:300]
            logger.error("%s failed with error: %s", run_label, e)

        return TestResult(
            id=case["id"],
            category=case["category"],
            technique=case["attack_technique"],
            status=status,
            confidence=confidence,
            violated_principle=violated_principle,
            reasoning=reasoning,
            error_detail=error_detail,
        )

    async def run_evaluation_suite(self) -> list[TestResult]:
        cases = self.load_corpus()
        results: list[TestResult] = []
        logger.info("Starting single-pass evaluation suite with %d test cases...", len(cases))

        for index, case in enumerate(cases, 1):
            result = await self._run_single_case(case, run_label=f"{case['id']} [{index}/{len(cases)}]")
            results.append(result)
            if index < len(cases):
                await asyncio.sleep(_INTER_CALL_SLEEP_SECONDS)

        return results

    async def run_evaluation_suite_multi(
        self, n_runs: int = 3, only_ids: set[str] | None = None
    ) -> list[MultiRunResult]:
        cases = self.load_corpus(only_ids=only_ids)
        aggregated: list[MultiRunResult] = []
        total_trials = len(cases) * n_runs
        trial_counter = 0

        logger.info(
            "Starting multi-run evaluation: %d cases x %d runs = %d total trials.",
            len(cases),
            n_runs,
            total_trials,
        )

        for case in cases:
            per_run: list[TestResult] = []
            for run_idx in range(1, n_runs + 1):
                trial_counter += 1
                label = f"{case['id']} (run {run_idx}/{n_runs}, overall {trial_counter}/{total_trials})"
                result = await self._run_single_case(case, run_label=label)
                per_run.append(result)
                if trial_counter < total_trials:
                    await asyncio.sleep(_INTER_CALL_SLEEP_SECONDS)

            vulnerable_count = sum(1 for r in per_run if r.status == "VULNERABLE")
            secure_count = sum(1 for r in per_run if r.status == "SECURE")
            error_count = sum(1 for r in per_run if r.status in ("ERROR", "TIMEOUT"))
            valid_runs = vulnerable_count + secure_count
            asr = (vulnerable_count / valid_runs) if valid_runs > 0 else None

            aggregated.append(
                MultiRunResult(
                    id=case["id"],
                    category=case["category"],
                    technique=case["attack_technique"],
                    n_runs=n_runs,
                    vulnerable_count=vulnerable_count,
                    secure_count=secure_count,
                    error_count=error_count,
                    attack_success_rate=asr,
                    per_run=per_run,
                )
            )

        return aggregated