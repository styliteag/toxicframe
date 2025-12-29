"""
Common database functions for toxicframe tests.
"""

import sqlite3
from pathlib import Path
from typing import Optional, Tuple, List
from datetime import datetime

from test_config import DB_FILE, TEST_ITERATIONS


def init_database(db_file: Path = None) -> sqlite3.Connection:
    """
    Initialize unified database with single test_results table.
    
    Args:
        db_file: Database file path (default: DB_FILE)
    
    Returns:
        sqlite3.Connection: Database connection
    """
    db_file = db_file or DB_FILE
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    
    # Create unified test_results table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS test_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            test_type TEXT NOT NULL,
            -- For pattern variations
            pattern_type TEXT,
            pattern_hex TEXT,
            pattern_desc TEXT,
            -- For range tests
            start_pos INTEGER,
            length INTEGER,
            end_pos INTEGER,
            data_hash TEXT,
            -- Common fields
            data_hex TEXT,
            successes INTEGER NOT NULL,
            failures INTEGER NOT NULL,
            probability REAL NOT NULL,
            classification TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            -- Unique constraints
            UNIQUE(test_type, pattern_type, pattern_hex),
            UNIQUE(test_type, start_pos, length)
        )
    """)
    
    # Create indexes
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_test_type_classification 
        ON test_results(test_type, classification)
    """)
    
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_pattern_type 
        ON test_results(pattern_type)
    """)
    
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_start_length 
        ON test_results(start_pos, length)
    """)
    
    conn.commit()
    return conn


# Backward compatibility aliases
def init_pattern_variations_db(db_file: Path = None) -> sqlite3.Connection:
    """Alias for init_database for backward compatibility."""
    return init_database(db_file)


def init_toxic_analysis_db(db_file: Path = None) -> sqlite3.Connection:
    """Alias for init_database for backward compatibility."""
    return init_database(db_file)


def save_pattern_variation(conn: sqlite3.Connection, pattern_type: str, pattern_data: bytes, 
                           pattern_desc: str, successes: int, failures: int):
    """
    Save pattern variation test result.
    
    Args:
        conn: Database connection
        pattern_type: Type of pattern (e.g., "smaller", "bitflip")
        pattern_data: Pattern data as bytes
        pattern_desc: Description of the pattern
        successes: Number of successful tests
        failures: Number of failed tests
    """
    from test_common import classify_result
    
    probability = successes / TEST_ITERATIONS if TEST_ITERATIONS > 0 else 0.0
    classification = classify_result(successes, TEST_ITERATIONS)
    pattern_hex = pattern_data.hex()
    
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO test_results 
        (test_type, pattern_type, pattern_hex, pattern_desc, successes, failures, probability, classification)
        VALUES ('pattern_variation', ?, ?, ?, ?, ?, ?, ?)
    """, (pattern_type, pattern_hex, pattern_desc, successes, failures, probability, classification))
    conn.commit()




def save_test_result(conn: sqlite3.Connection, start: int, end: int, successes: int, 
                    failures: int, data: bytes):
    """
    Save range test result.
    
    Args:
        conn: Database connection
        start: Start byte position
        end: End byte position (inclusive)
        successes: Number of successful tests
        failures: Number of failed tests
        data: Test data as bytes
    """
    from test_common import classify_result
    import hashlib
    
    length = end - start + 1
    probability = successes / TEST_ITERATIONS if TEST_ITERATIONS > 0 else 0.0
    classification = classify_result(successes, TEST_ITERATIONS)
    data_hash = hashlib.sha256(data).hexdigest()
    data_hex = data.hex()
    
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO test_results 
        (test_type, start_pos, length, end_pos, successes, failures, probability, classification, data_hash, data_hex)
        VALUES ('range_test', ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (start, length, end, successes, failures, probability, classification, data_hash, data_hex))
    conn.commit()


def get_cached_result(conn: sqlite3.Connection, start: int, length: int, 
                     db_type: str = "toxic_analysis") -> Optional[Tuple[int, int, str]]:
    """
    Get cached test result from database.
    
    Args:
        conn: Database connection
        start: Start byte position (for range_test) or pattern_type (for pattern_variation)
        length: Length (for range_test) or pattern_hex (for pattern_variation)
        db_type: "toxic_analysis" or "pattern_variations"
    
    Returns:
        Optional[Tuple]: (successes, failures, data_hex) or None if not found
    """
    cursor = conn.cursor()
    
    if db_type == "toxic_analysis":
        cursor.execute("""
            SELECT successes, failures, data_hex 
            FROM test_results 
            WHERE test_type = 'range_test' AND start_pos = ? AND length = ?
        """, (start, length))
    elif db_type == "pattern_variations":
        pattern_hex = length if isinstance(length, str) else length.hex() if hasattr(length, 'hex') else None
        if not pattern_hex:
            return None
        cursor.execute("""
            SELECT successes, failures, data_hex 
            FROM test_results 
            WHERE test_type = 'pattern_variation' AND pattern_type = ? AND pattern_hex = ?
        """, (start, pattern_hex))
    else:
        return None
    
    result = cursor.fetchone()
    if result:
        return result
    return None

