"""
Common database functions for toxicframe tests.
"""

import sqlite3
from pathlib import Path
from typing import Optional, Tuple

from config import DB_FILE, TEST_ITERATIONS


def init_database(db_file: Path = None) -> sqlite3.Connection:
    """Initialize database with test_results table."""
    db_file = db_file or DB_FILE
    conn = sqlite3.connect(str(db_file))
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS test_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            test_type TEXT NOT NULL,
            pattern_type TEXT,
            pattern_hex TEXT,
            pattern_desc TEXT,
            start_pos INTEGER,
            length INTEGER,
            end_pos INTEGER,
            data_hash TEXT,
            data_hex TEXT,
            successes INTEGER NOT NULL,
            failures INTEGER NOT NULL,
            probability REAL NOT NULL,
            classification TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(test_type, pattern_type, pattern_hex),
            UNIQUE(test_type, start_pos, length)
        )
    """)
    
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_type_class ON test_results(test_type, classification)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_pattern ON test_results(pattern_type)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_range ON test_results(start_pos, length)")
    
    conn.commit()
    return conn


# Aliases
init_pattern_variations_db = init_database
init_toxic_analysis_db = init_database


def save_pattern_variation(conn: sqlite3.Connection, pattern_type: str, pattern_data: bytes,
                           pattern_desc: str, successes: int, failures: int):
    """Save pattern variation test result."""
    from test_common import classify_result
    
    total = successes + failures
    probability = successes / total if total > 0 else 0.0
    classification = classify_result(successes, total)
    
    conn.execute("""
        INSERT OR REPLACE INTO test_results 
        (test_type, pattern_type, pattern_hex, pattern_desc, successes, failures, probability, classification)
        VALUES ('pattern_variation', ?, ?, ?, ?, ?, ?, ?)
    """, (pattern_type, pattern_data.hex(), pattern_desc, successes, failures, probability, classification))
    conn.commit()


def save_test_result(conn: sqlite3.Connection, start: int, end: int, successes: int,
                    failures: int, data: bytes):
    """Save range test result."""
    from test_common import classify_result
    import hashlib
    
    length = end - start + 1
    total = successes + failures
    probability = successes / total if total > 0 else 0.0
    classification = classify_result(successes, total)
    data_hash = hashlib.sha256(data).hexdigest()
    
    conn.execute("""
        INSERT OR REPLACE INTO test_results 
        (test_type, start_pos, length, end_pos, successes, failures, probability, classification, data_hash, data_hex)
        VALUES ('range_test', ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (start, length, end, successes, failures, probability, classification, data_hash, data.hex()))
    conn.commit()


def get_cached_result(conn: sqlite3.Connection, start: int, length: int,
                     db_type: str = "toxic_analysis") -> Optional[Tuple[int, int, str]]:
    """Get cached test result."""
    cursor = conn.cursor()
    
    if db_type == "toxic_analysis":
        cursor.execute("""
            SELECT successes, failures, data_hex 
            FROM test_results 
            WHERE test_type = 'range_test' AND start_pos = ? AND length = ?
        """, (start, length))
    else:
        return None
    
    return cursor.fetchone()
