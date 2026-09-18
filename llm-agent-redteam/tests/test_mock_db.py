"""Unit tests for the mock database module (src/mock_db.py)."""

from pathlib import Path
import sqlite3
import pytest

from src.mock_db import MOCK_USERS_SEED_DATA, get_connection, init_db


def test_init_db_creates_table_and_seeds(tmp_db_path: Path) -> None:
    """Verifies that init_db creates the users table with the correct schema and row count."""
    with get_connection(tmp_db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        row_count = cursor.fetchone()[0]

    assert row_count == len(MOCK_USERS_SEED_DATA)
    assert row_count >= 8


def test_init_db_idempotency_and_force_recreate(tmp_db_path: Path) -> None:
    """Verifies that calling init_db repeatedly without force keeps data intact,

    while force_recreate cleanly resets the table.
    """
    # Insert an ad-hoc extra record
    with get_connection(tmp_db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (name, email, internal_notes) VALUES (?, ?, ?)",
            ("Extra User", "extra@test.org", "Ad-hoc internal note"),
        )

    # Calling init_db without force should preserve the extra record
    init_db(tmp_db_path, force_recreate=False)
    with get_connection(tmp_db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        count_preserved = cursor.fetchone()[0]
    assert count_preserved == len(MOCK_USERS_SEED_DATA) + 1

    # Calling with force_recreate=True should reset to original seed count
    init_db(tmp_db_path, force_recreate=True)
    with get_connection(tmp_db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        count_reset = cursor.fetchone()[0]
    assert count_reset == len(MOCK_USERS_SEED_DATA)


def test_get_connection_context_manager_commits_and_closes(tmp_db_path: Path) -> None:
    """Verifies that get_connection automatically commits changes on context exit."""
    with get_connection(tmp_db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (name, email, internal_notes) VALUES (?, ?, ?)",
            ("Persisted User", "persisted@test.org", "Committed"),
        )

    # Verify query from a completely separate connection
    with get_connection(tmp_db_path) as conn2:
        cursor2 = conn2.cursor()
        cursor2.execute("SELECT name FROM users WHERE email = 'persisted@test.org'")
        row = cursor2.fetchone()
        assert row is not None
        assert row["name"] == "Persisted User"
