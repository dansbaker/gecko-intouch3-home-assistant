"""Reconnection handler with exponential backoff."""

from .constants import MAX_RECONNECT_ATTEMPTS, RECONNECT_BASE_DELAY, RECONNECT_MAX_DELAY


class ReconnectionHandler:
    """Manages reconnection attempts with exponential backoff."""

    def __init__(
        self,
        max_attempts: int = MAX_RECONNECT_ATTEMPTS,
        base_delay: float = RECONNECT_BASE_DELAY,
        max_delay: float = RECONNECT_MAX_DELAY,
    ):
        self._max_attempts = max_attempts
        self._base_delay = base_delay
        self._max_delay = max_delay
        self._attempts = 0

    def should_attempt(self) -> bool:
        """Check if another reconnection attempt should be made."""
        return self._attempts < self._max_attempts

    def get_delay(self) -> float:
        """Calculate delay for next reconnection attempt with exponential backoff."""
        return min(self._base_delay * (2**self._attempts), self._max_delay)

    def on_attempt(self) -> int:
        """Record a reconnection attempt and return attempt number."""
        self._attempts += 1
        return self._attempts

    def on_success(self) -> None:
        """Reset attempt counter after successful connection."""
        self._attempts = 0

    @property
    def attempts(self) -> int:
        """Get current number of attempts."""
        return self._attempts
