"""
Hash-based cache for non-toxic patterns.

Caches SAFE patterns to avoid re-testing them during brute force searches.
Uses SHA256 hash of payload as key for fast lookups.
"""

import hashlib
import sqlite3
import threading
from typing import Optional, Set
from pathlib import Path

from config import DB_FILE


class PatternCache:
    """Thread-safe cache for non-toxic patterns using hash-based lookups."""
    
    def __init__(self, db_file: Path = None):
        self.db_file = db_file or DB_FILE
        self._memory_cache: Set[str] = set()  # Set of hashes (fast lookup)
        self._lock = threading.Lock()
        self._conn: Optional[sqlite3.Connection] = None
        self._initialized = False
    
    def _init_db(self):
        """Initialize database table for cache."""
        if self._initialized:
            return
        
        self._conn = sqlite3.connect(str(self.db_file))
        cursor = self._conn.cursor()
        
        # Create cache table (only stores SAFE patterns)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS pattern_cache (
                pattern_hash TEXT PRIMARY KEY,
                pattern_hex TEXT NOT NULL,
                pattern_length INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Index for fast lookups
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_cache_hash ON pattern_cache(pattern_hash)
        """)
        
        self._conn.commit()
        self._initialized = True
    
    def _load_memory_cache(self, max_load: int = 100000):
        """Load cache hashes into memory for fast lookup."""
        if not self._initialized:
            self._init_db()
        
        cursor = self._conn.cursor()
        cursor.execute("SELECT pattern_hash FROM pattern_cache LIMIT ?", (max_load,))
        
        with self._lock:
            for (hash_val,) in cursor.fetchall():
                self._memory_cache.add(hash_val)
    
    def _hash_payload(self, payload: bytes) -> str:
        """Compute SHA256 hash of payload."""
        return hashlib.sha256(payload).hexdigest()
    
    def is_cached(self, payload: bytes) -> bool:
        """
        Check if payload is cached as SAFE (non-toxic).
        Returns True if cached, False if not cached or unknown.
        """
        pattern_hash = self._hash_payload(payload)
        
        # Fast in-memory check
        with self._lock:
            if pattern_hash in self._memory_cache:
                return True
        
        # Database check (if not in memory)
        if not self._initialized:
            self._init_db()
        
        cursor = self._conn.cursor()
        cursor.execute("SELECT 1 FROM pattern_cache WHERE pattern_hash = ? LIMIT 1", 
                      (pattern_hash,))
        result = cursor.fetchone()
        
        if result:
            # Add to memory cache for next time
            with self._lock:
                self._memory_cache.add(pattern_hash)
            return True
        
        return False
    
    def add_safe(self, payload: bytes):
        """
        Add a SAFE (non-toxic) pattern to cache.
        Only call this for patterns that are confirmed SAFE (100% success).
        """
        pattern_hash = self._hash_payload(payload)
        
        if not self._initialized:
            self._init_db()
        
        # Add to database
        try:
            self._conn.execute("""
                INSERT OR IGNORE INTO pattern_cache (pattern_hash, pattern_hex, pattern_length)
                VALUES (?, ?, ?)
            """, (pattern_hash, payload.hex(), len(payload)))
            self._conn.commit()
            
            # Add to memory cache
            with self._lock:
                self._memory_cache.add(pattern_hash)
        except sqlite3.IntegrityError:
            pass  # Already exists
    
    def add_batch_safe(self, payloads: list[bytes]):
        """Add multiple SAFE patterns to cache in batch."""
        if not payloads:
            return
        
        if not self._initialized:
            self._init_db()
        
        # Prepare batch data
        batch_data = []
        hashes_to_add = set()
        
        for payload in payloads:
            pattern_hash = self._hash_payload(payload)
            if pattern_hash not in self._memory_cache:
                batch_data.append((pattern_hash, payload.hex(), len(payload)))
                hashes_to_add.add(pattern_hash)
        
        if not batch_data:
            return
        
        # Batch insert
        try:
            self._conn.executemany("""
                INSERT OR IGNORE INTO pattern_cache (pattern_hash, pattern_hex, pattern_length)
                VALUES (?, ?, ?)
            """, batch_data)
            self._conn.commit()
            
            # Add to memory cache
            with self._lock:
                self._memory_cache.update(hashes_to_add)
        except sqlite3.IntegrityError:
            pass
    
    def get_stats(self) -> dict:
        """Get cache statistics."""
        if not self._initialized:
            self._init_db()
        
        cursor = self._conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM pattern_cache")
        db_count = cursor.fetchone()[0]
        
        with self._lock:
            memory_count = len(self._memory_cache)
        
        return {
            "memory_cached": memory_count,
            "database_cached": db_count,
            "total_cached": db_count  # DB is authoritative
        }
    
    def clear(self):
        """Clear all cached patterns (use with caution!)."""
        if not self._initialized:
            self._init_db()
        
        self._conn.execute("DELETE FROM pattern_cache")
        self._conn.commit()
        
        with self._lock:
            self._memory_cache.clear()
    
    def close(self):
        """Close database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None


# Global cache instance
_cache: Optional[PatternCache] = None
_cache_lock = threading.Lock()


def get_cache() -> PatternCache:
    """Get or create global pattern cache."""
    global _cache
    with _cache_lock:
        if _cache is None:
            _cache = PatternCache()
            # Load some hashes into memory for fast access
            _cache._load_memory_cache(max_load=50000)
        return _cache


def clear_cache():
    """Clear global cache."""
    global _cache
    with _cache_lock:
        if _cache:
            _cache.clear()
            _cache.close()
            _cache = None

