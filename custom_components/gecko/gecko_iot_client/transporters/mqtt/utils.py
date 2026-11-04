"""Utility functions for MQTT transporter."""

import json
import logging
from concurrent.futures import Future
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def parse_json_safely(payload: str) -> Optional[Dict[str, Any]]:
    """
    Safely parse JSON payload, returning None on error.

    Args:
        payload: JSON string to parse

    Returns:
        Parsed dictionary, empty dict for empty payload, or None on parse error
    """
    if not payload:
        return {}
    try:
        return json.loads(payload)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON: {e}")
        return None


def complete_future_safely(
    future: Optional[Future], result: Any = None, error: Optional[Exception] = None
) -> None:
    """
    Complete a future with result or exception if not already done.

    Args:
        future: Future to complete (can be None)
        result: Result value to set (default: None)
        error: Exception to set if provided
    """
    if future and not future.done():
        if error:
            future.set_exception(error)
        else:
            future.set_result(result)


def notify_callbacks_safely(callbacks: list, data: Any) -> None:
    """
    Notify all callbacks, catching and logging individual errors.

    Args:
        callbacks: List of callback functions to invoke
        data: Data to pass to each callback
    """
    for callback in callbacks:
        try:
            callback(data)
        except Exception as e:
            logger.error(f"Error in callback: {e}")
