"""
AI SBC Security - Log File Watcher
Real-time monitoring of system log files using async file tailing.
Feeds lines into the IDS engine and Log Intelligence engine.
"""
import asyncio
import logging
import os
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Callable, Set

logger = logging.getLogger("ai_sbc.monitor.logs")

DEFAULT_LOG_PATHS = [
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/kern.log",
    "/var/log/fail2ban.log",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
]


class LogTailer:
    """Async file tailer — tracks file position and streams new lines."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self._pos = 0
        self._exists = False
        self._inode = None

    async def read_new_lines(self) -> List[str]:
        try:
            stat = os.stat(self.filepath)
            current_inode = stat.st_ino

            # File rotated?
            if self._inode and current_inode != self._inode:
                logger.info(f"Log rotated: {self.filepath}")
                self._pos = 0

            self._inode = current_inode
            self._exists = True

            if stat.st_size < self._pos:
                # File truncated
                self._pos = 0

            if stat.st_size == self._pos:
                return []

            lines = []
            with open(self.filepath, "r", encoding="utf-8", errors="replace") as f:
                f.seek(self._pos)
                chunk = f.read(65536)  # 64KB max per poll
                self._pos = f.tell()

            for line in chunk.splitlines():
                line = line.strip()
                if line:
                    lines.append(line)
            return lines

        except FileNotFoundError:
            if self._exists:
                logger.warning(f"Log file gone: {self.filepath}")
                self._exists = False
            return []
        except PermissionError:
            logger.warning(f"No permission to read: {self.filepath}")
            return []
        except Exception as e:
            logger.error(f"Log tail error {self.filepath}: {e}")
            return []

    def seek_to_end(self):
        """Skip existing content — only read new lines going forward."""
        try:
            self._pos = os.path.getsize(self.filepath)
            self._inode = os.stat(self.filepath).st_ino
            self._exists = True
        except:
            self._pos = 0


class LogWatcher:
    """
    Watches multiple log files and dispatches lines to registered processors.
    Each processor is an async callback: async def process(line, filepath) -> None
    """

    def __init__(self, paths: List[str] = None, poll_interval: float = 2.0):
        self.paths = paths or DEFAULT_LOG_PATHS
        self.poll_interval = poll_interval
        self.tailers: Dict[str, LogTailer] = {}
        self._processors: List[Callable] = []
        self._running = False
        self._lines_processed: int = 0
        self._lines_by_file: Dict[str, int] = defaultdict(int)
        self._active_files: Set[str] = set()

    def add_processor(self, fn: Callable):
        """Register async processor: async def fn(line: str, filepath: str)"""
        self._processors.append(fn)

    def add_path(self, path: str):
        if path not in self.paths:
            self.paths.append(path)

    async def _dispatch(self, line: str, filepath: str):
        for fn in self._processors:
            try:
                await fn(line, filepath)
            except Exception as e:
                logger.error(f"Log processor error: {e}")

    async def run(self):
        self._running = True
        logger.info(f"Log watcher started — watching {len(self.paths)} paths")

        # Initialize tailers, seek to end (don't re-process old logs)
        for path in self.paths:
            tailer = LogTailer(path)
            tailer.seek_to_end()
            self.tailers[path] = tailer

        while self._running:
            for path, tailer in self.tailers.items():
                new_lines = await tailer.read_new_lines()
                if new_lines:
                    self._active_files.add(path)
                    for line in new_lines:
                        await self._dispatch(line, path)
                        self._lines_processed += 1
                        self._lines_by_file[path] += 1
                elif path in self._active_files and not tailer._exists:
                    self._active_files.discard(path)

            # Dynamically discover new log files (e.g., app logs)
            await asyncio.sleep(self.poll_interval)

    def stop(self):
        self._running = False

    def get_stats(self) -> Dict:
        return {
            "watched_files": len(self.tailers),
            "active_files": len(self._active_files),
            "lines_processed": self._lines_processed,
            "lines_by_file": dict(self._lines_by_file),
        }


_watcher: Optional[LogWatcher] = None

def get_log_watcher() -> LogWatcher:
    global _watcher
    if _watcher is None:
        _watcher = LogWatcher()
    return _watcher
