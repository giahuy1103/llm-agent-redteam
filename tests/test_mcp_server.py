import json
from pathlib import Path
import pytest

from src.config import Config
from src.exceptions import ToolExecutionError
from src.mcp_server import (
    MOCK_URL_RESPONSES,
    execute_query_db,
    execute_read_file,
    execute_send_email,
    execute_web_fetch,
)


def test_read_file_success(test_config: Config) -> None:
    content = execute_read_file("sample_email_clean.txt", test_config)
    assert "Test clean email body content." in content


def test_read_file_path_traversal_blocked(test_config: Config) -> None:
    traversal_candidates = [
        "../../../etc/passwd",
        "../../config.py",
        "subdir/../../../../../../etc/shadow",
        "/etc/passwd",
    ]
    for bad_path in traversal_candidates:
        with pytest.raises(ToolExecutionError) as exc_info:
            execute_read_file(bad_path, test_config)
        assert "Access denied: path outside allowed directory" in str(exc_info.value)
        # Ensure system paths like /etc are not leaked in message
        assert "/etc/passwd" not in str(exc_info.value)


def test_read_file_missing_file_raises_error(test_config: Config) -> None:
    with pytest.raises(ToolExecutionError) as exc_info:
        execute_read_file("non_existent_file_12345.txt", test_config)
    assert "File not found" in str(exc_info.value)


def test_send_email_valid_appends_jsonl_log(tmp_results_dir: Path) -> None:
    recipient = "alice.research@internal-lab.net"
    subject = "Confidential Sync"
    body = "Please review the quarterly findings attached."

    confirmation = execute_send_email(
        to=recipient, subject=subject, content=body, results_dir=tmp_results_dir
    )

    assert "SIMULATED: Email would be sent to" in confirmation
    assert recipient in confirmation

    # Inspect JSONL log file
    log_file = tmp_results_dir / "sent_emails_log.jsonl"
    assert log_file.exists()

    lines = log_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1

    record = json.loads(lines[0])
    assert record["to"] == recipient
    assert record["subject"] == subject
    assert record["content"] == body
    assert record["simulated"] is True
    assert "timestamp" in record


def test_send_email_invalid_recipient_rejected(tmp_results_dir: Path) -> None:
    invalid_addresses = [
        "not-an-email",
        "user@",
        "@domain.com",
        "user@domain",
        "spaces in address@domain.com",
    ]
    for bad_addr in invalid_addresses:
        with pytest.raises(ToolExecutionError) as exc_info:
            execute_send_email(
                to=bad_addr,
                subject="Test",
                content="Test body",
                results_dir=tmp_results_dir,
            )
        assert "Invalid email address format" in str(exc_info.value)


def test_query_db_valid_select_returns_json(tmp_db_path: Path) -> None:
    result_str = execute_query_db(
        "SELECT id, name, email FROM users WHERE name LIKE 'Alice%'",
        db_path=tmp_db_path,
    )
    rows = json.loads(result_str)
    assert isinstance(rows, list)
    assert len(rows) >= 1
    assert rows[0]["name"].startswith("Alice")
    assert "email" in rows[0]


def test_query_db_rejects_non_select_statements(tmp_db_path: Path) -> None:
    forbidden_queries = [
        "DROP TABLE users",
        "DELETE FROM users WHERE id = 1",
        "INSERT INTO users (name, email, internal_notes) VALUES ('hacker', 'h@evil.com', 'hack')",
        "UPDATE users SET name = 'compromised'",
        "CREATE TABLE backdoor (cmd TEXT)",
    ]
    for query in forbidden_queries:
        with pytest.raises(ToolExecutionError) as exc_info:
            execute_query_db(query, db_path=tmp_db_path)
        assert (
            "Only SELECT queries are permitted" in str(exc_info.value)
            or "Forbidden SQL operation" in str(exc_info.value)
        )


def test_query_db_blocks_semicolon_chaining_injection(tmp_db_path: Path) -> None:
    chained_injections = [
        "SELECT 1; DROP TABLE users",
        "SELECT * FROM users; DELETE FROM users;",
        "SELECT id FROM users; INSERT INTO users VALUES (99, 'bad', 'bad', 'bad')",
    ]
    for chained in chained_injections:
        with pytest.raises(ToolExecutionError) as exc_info:
            execute_query_db(chained, db_path=tmp_db_path)
        assert "semicolon statement chaining is forbidden" in str(exc_info.value)


def test_web_fetch_known_urls_return_mock_data() -> None:
    for url, expected_substring in MOCK_URL_RESPONSES.items():
        content = execute_web_fetch(url)
        assert content == expected_substring


def test_web_fetch_unknown_url_returns_graceful_fallback() -> None:
    content = execute_web_fetch("https://unknown-domain.internal/page.html")
    assert content == "Mock content: no data available for this URL"
