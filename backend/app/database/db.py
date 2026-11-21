import sqlite3
import json
import os
from datetime import datetime
from typing import Dict, Any, List, Optional

# Database file location relative to backend app
DB_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(DB_DIR, "susignal.db")


def get_db_connection() -> sqlite3.Connection:
    """
    Establish and return a connection to the SQLite database.
    Row factory is set to sqlite3.Row for dict-like access.
    """
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """
    Initialize SQLite database tables for scans and findings.
    Keeps schema simple, robust, and extensible for future needs.
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        
        # Scans table: records file metadata, timestamp, summary stats
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT UNIQUE NOT NULL,
                filename TEXT NOT NULL,
                file_type TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                total_findings INTEGER DEFAULT 0,
                status TEXT NOT NULL,
                summary_json TEXT
            )
        """)

        # Findings table: records individual misconfigurations linked to scans
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT,
                description TEXT,
                remediation TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (scan_id) ON DELETE CASCADE
            )
        """)

        conn.commit()
    finally:
        conn.close()


def save_scan_record(
    scan_id: str,
    filename: str,
    file_type: str,
    summary: Dict[str, Any],
    findings: List[Dict[str, Any]],
    status: str = "COMPLETED"
) -> None:
    """
    Save a completed scan summary and its findings into SQLite.
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        scanned_at = datetime.utcnow().isoformat() + "Z"

        cursor.execute("""
            INSERT OR REPLACE INTO scans (
                scan_id, filename, file_type, scanned_at,
                critical_count, high_count, medium_count, low_count,
                total_findings, status, summary_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            filename,
            file_type,
            scanned_at,
            summary.get("critical", 0),
            summary.get("high", 0),
            summary.get("medium", 0),
            summary.get("low", 0),
            summary.get("total_findings", len(findings)),
            status,
            json.dumps(summary)
        ))

        # Insert findings
        for finding in findings:
            cursor.execute("""
                INSERT INTO findings (
                    scan_id, rule_id, title, severity, category, description, remediation
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                finding.get("rule_id", "UNKNOWN"),
                finding.get("title", ""),
                finding.get("severity", "LOW"),
                finding.get("category", "General"),
                finding.get("description", ""),
                finding.get("remediation", "")
            ))

        conn.commit()
    finally:
        conn.close()


def get_recent_scans(limit: int = 10) -> List[Dict[str, Any]]:
    """
    Retrieve recently executed scans.
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT scan_id, filename, file_type, scanned_at,
                   critical_count, high_count, medium_count, low_count,
                   total_findings, status
            FROM scans
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_scan_by_id(scan_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve full scan record and all associated findings by scan_id.
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT scan_id, filename, file_type, scanned_at,
                   critical_count, high_count, medium_count, low_count,
                   total_findings, status, summary_json
            FROM scans
            WHERE scan_id = ?
        """, (scan_id,))
        row = cursor.fetchone()
        if not row:
            return None

        scan_dict = dict(row)
        summary_raw = scan_dict.pop("summary_json", None)
        try:
            summary = json.loads(summary_raw) if summary_raw else {}
        except Exception:
            summary = {}

        cursor.execute("""
            SELECT rule_id, title, severity, category, description, remediation
            FROM findings
            WHERE scan_id = ?
            ORDER BY id ASC
        """, (scan_id,))
        findings_rows = cursor.fetchall()
        findings = [dict(f) for f in findings_rows]

        return {
            "scan_id": scan_dict["scan_id"],
            "filename": scan_dict["filename"],
            "file_type": scan_dict["file_type"],
            "scanned_at": scan_dict["scanned_at"],
            "status": scan_dict["status"],
            "summary": summary,
            "findings": findings
        }
    finally:
        conn.close()


def delete_scan_record(scan_id: str) -> bool:
    """
    Delete a scan record and its findings by scan_id.
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
        cursor.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def clear_scan_history() -> int:
    """
    Clear all scan history and findings from the database.
    Returns the count of deleted scan records.
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM scans")
        count = cursor.fetchone()[0]
        cursor.execute("DELETE FROM findings")
        cursor.execute("DELETE FROM scans")
        conn.commit()
        return count
    finally:
        conn.close()
