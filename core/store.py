import json
import os
import sqlite3
import time
from pathlib import Path

from core.models import Decision

_DEFAULT_DB_PATH = Path(".cache/warden.db")


def _db_path() -> Path:
    raw = os.environ.get("WARDEN_DB")
    return Path(raw) if raw else _DEFAULT_DB_PATH


def _connect() -> sqlite3.Connection:
    path = _db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS findings (
            cve TEXT NOT NULL,
            package TEXT NOT NULL,
            repo TEXT NOT NULL,
            action TEXT NOT NULL,
            reasons TEXT NOT NULL,
            auto_fixable INTEGER NOT NULL,
            PRIMARY KEY (cve, package, repo)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS snoozes (
            cve TEXT NOT NULL,
            repo TEXT NOT NULL,
            until_ts REAL NOT NULL,
            PRIMARY KEY (cve, repo)
        )
        """
    )
    return conn


def upsert_decisions(repo: str, decisions: list[Decision]) -> None:
    """Insert or update decisions for repo, deduped on (cve, package, repo)."""
    conn = _connect()
    try:
        with conn:
            for decision in decisions:
                conn.execute(
                    """
                    INSERT INTO findings (cve, package, repo, action, reasons, auto_fixable)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(cve, package, repo) DO UPDATE SET
                        action = excluded.action,
                        reasons = excluded.reasons,
                        auto_fixable = excluded.auto_fixable
                    """,
                    (
                        decision.cve,
                        decision.package,
                        repo,
                        decision.action.value,
                        json.dumps(decision.reasons),
                        int(decision.auto_fixable),
                    ),
                )
    finally:
        conn.close()


def snooze(cve: str, repo: str, until: float) -> None:
    """Snooze a finding for repo until a unix timestamp."""
    conn = _connect()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO snoozes (cve, repo, until_ts) VALUES (?, ?, ?)
                ON CONFLICT(cve, repo) DO UPDATE SET until_ts = excluded.until_ts
                """,
                (cve, repo, until),
            )
    finally:
        conn.close()


def is_snoozed(cve: str, repo: str) -> bool:
    """True if the finding has an unexpired snooze for repo."""
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT until_ts FROM snoozes WHERE cve = ? AND repo = ?", (cve, repo)
        ).fetchone()
    finally:
        conn.close()
    return row is not None and row[0] > time.time()


def get_decisions(repo: str, action: str | None = None) -> list[Decision]:
    """Return stored decisions for repo, excluding currently-snoozed findings."""
    query = """
        SELECT f.cve, f.package, f.action, f.reasons, f.auto_fixable
        FROM findings f
        LEFT JOIN snoozes s ON s.cve = f.cve AND s.repo = f.repo
        WHERE f.repo = ? AND (s.until_ts IS NULL OR s.until_ts <= ?)
    """
    params: list = [repo, time.time()]
    if action is not None:
        query += " AND f.action = ?"
        params.append(action)

    conn = _connect()
    try:
        rows = conn.execute(query, params).fetchall()
    finally:
        conn.close()

    return [
        Decision(
            cve=cve,
            package=package,
            action=action_,
            reasons=json.loads(reasons),
            auto_fixable=bool(auto_fixable),
        )
        for cve, package, action_, reasons, auto_fixable in rows
    ]
