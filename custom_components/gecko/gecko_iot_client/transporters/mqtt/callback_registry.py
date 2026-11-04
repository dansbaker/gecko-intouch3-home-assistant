"""Thread-safe callback registry."""

import threading
from typing import Any, Callable, Dict, Optional

from .utils import notify_callbacks_safely


class CallbackRegistry:
    """Thread-safe registry for managing callbacks by category."""

    def __init__(self):
        self._callbacks: Dict[str, list] = {}
        self._lock = threading.RLock()

    def register(self, category: str, callback: Callable) -> None:
        """Register a callback for a specific category."""
        with self._lock:
            if category not in self._callbacks:
                self._callbacks[category] = []
            if callback not in self._callbacks[category]:
                self._callbacks[category].append(callback)

    def get_callbacks(self, category: str) -> list:
        """Get all callbacks for a category (returns copy for thread safety)."""
        with self._lock:
            return self._callbacks.get(category, []).copy()

    def notify(self, category: str, data: Any) -> None:
        """Notify all callbacks in a category with data."""
        with self._lock:
            callbacks = self._callbacks.get(category, []).copy()
        notify_callbacks_safely(callbacks, data)

    def clear(self, category: Optional[str] = None) -> None:
        """Clear callbacks for a category or all categories."""
        with self._lock:
            if category:
                self._callbacks.pop(category, None)
            else:
                self._callbacks.clear()
