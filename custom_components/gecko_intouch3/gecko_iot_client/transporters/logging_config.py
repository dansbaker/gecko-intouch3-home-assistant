"""
Logging configuration for MQTT transporter.
"""

import logging
import logging.handlers
import os
import sys
from datetime import datetime
from typing import Optional


class MqttTransporterLogger:
    """Custom logger configuration for MQTT transporter with structured logging."""

    def __init__(
        self,
        name: str = "gecko_iot_mqtt",
        level: int = logging.INFO,
        log_file: Optional[str] = None,
        max_file_size: int = 10 * 1024 * 1024,  # 10MB
        backup_count: int = 5,
        include_console: bool = True,
    ):
        """
        Initialize the logger configuration.

        Args:
            name: Logger name
            level: Logging level
            log_file: Path to log file (optional)
            max_file_size: Maximum size of log file before rotation
            backup_count: Number of backup files to keep
            include_console: Whether to include console logging
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)

        # Clear any existing handlers
        self.logger.handlers.clear()

        # Create formatter
        formatter = self._create_formatter()

        # Add console handler if requested
        if include_console:
            console_handler = self._create_console_handler(formatter)
            self.logger.addHandler(console_handler)

        # Add file handler if log file specified
        if log_file:
            file_handler = self._create_file_handler(
                log_file, formatter, max_file_size, backup_count
            )
            self.logger.addHandler(file_handler)

        # Prevent propagation to root logger to avoid duplicate messages
        self.logger.propagate = False

    def _create_formatter(self) -> logging.Formatter:
        """Create a structured log formatter."""
        return logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(funcName)s:%(lineno)d | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    def _create_console_handler(
        self, formatter: logging.Formatter
    ) -> logging.StreamHandler:
        """Create console handler with appropriate formatting."""
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(formatter)
        return handler

    def _create_file_handler(
        self,
        log_file: str,
        formatter: logging.Formatter,
        max_size: int,
        backup_count: int,
    ) -> logging.Handler:
        """Create rotating file handler."""
        # Ensure log directory exists
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)

        handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=max_size, backupCount=backup_count
        )
        handler.setFormatter(formatter)
        return handler

    def get_logger(self) -> logging.Logger:
        """Get the configured logger instance."""
        return self.logger

    def add_connection_context(self, client_id: str, broker_url: str):
        """Add connection context to all log messages."""
        # Create a custom adapter that adds connection context
        adapter = logging.LoggerAdapter(
            self.logger, {"client_id": client_id, "broker_url": broker_url}
        )
        return adapter


class ConnectionEventLogger:
    """Specialized logger for connection events with metrics tracking."""

    def __init__(self, base_logger: logging.Logger):
        self.logger = base_logger
        self.connection_attempts = 0
        self.successful_connections = 0
        self.failed_connections = 0
        self.disconnections = 0
        self.token_refreshes = 0
        self.start_time = datetime.now()

    def log_connection_attempt(self, broker_url: str, client_id: str):
        """Log a connection attempt."""
        self.connection_attempts += 1
        self.logger.info(
            f"Connection attempt #{self.connection_attempts} to {broker_url} with client ID: {client_id}"
        )

    def log_connection_success(self, client_id: str, duration_ms: float):
        """Log successful connection."""
        self.successful_connections += 1
        self.logger.info(
            f"Connection successful for {client_id} in {duration_ms:.2f}ms "
            f"(Success rate: {self.get_success_rate():.1f}%)"
        )

    def log_connection_failure(
        self, client_id: str, error: Exception, duration_ms: float
    ):
        """Log connection failure."""
        self.failed_connections += 1
        self.logger.error(
            f"Connection failed for {client_id} after {duration_ms:.2f}ms: {error} "
            f"(Success rate: {self.get_success_rate():.1f}%)"
        )

    def log_disconnection(self, client_id: str, reason: str):
        """Log disconnection event."""
        self.disconnections += 1
        self.logger.info(f"Disconnected {client_id}: {reason}")

    def log_token_refresh(self, success: bool, error: Optional[Exception] = None):
        """Log token refresh event."""
        self.token_refreshes += 1
        if success:
            self.logger.info(f"Token refresh #{self.token_refreshes} successful")
        else:
            self.logger.error(f"Token refresh #{self.token_refreshes} failed: {error}")

    def log_reconnection_attempt(self, attempt: int, max_attempts: int, delay: float):
        """Log reconnection attempt."""
        self.logger.info(
            f"Reconnection attempt {attempt}/{max_attempts} in {delay:.1f}s"
        )

    def get_success_rate(self) -> float:
        """Calculate connection success rate."""
        if self.connection_attempts == 0:
            return 0.0
        return (self.successful_connections / self.connection_attempts) * 100

    def get_connection_stats(self) -> dict:
        """Get connection statistics."""
        uptime = (datetime.now() - self.start_time).total_seconds()

        return {
            "uptime_seconds": uptime,
            "connection_attempts": self.connection_attempts,
            "successful_connections": self.successful_connections,
            "failed_connections": self.failed_connections,
            "disconnections": self.disconnections,
            "token_refreshes": self.token_refreshes,
            "success_rate": self.get_success_rate(),
        }

    def log_periodic_stats(self):
        """Log periodic connection statistics."""
        stats = self.get_connection_stats()
        self.logger.info(
            f"Connection Stats - Uptime: {stats['uptime_seconds']:.1f}s, "
            f"Attempts: {stats['connection_attempts']}, "
            f"Success Rate: {stats['success_rate']:.1f}%, "
            f"Token Refreshes: {stats['token_refreshes']}"
        )


def setup_mqtt_logging(
    log_level: str = "INFO", log_file: Optional[str] = None, enable_console: bool = True
) -> tuple[logging.Logger, ConnectionEventLogger]:
    """
    Setup logging for MQTT transporter.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional path to log file
        enable_console: Whether to enable console logging

    Returns:
        Tuple of (main_logger, event_logger)
    """
    # Convert string level to logging constant
    level = getattr(logging, log_level.upper(), logging.INFO)

    # Create main logger
    mqtt_logger = MqttTransporterLogger(
        name="gecko_iot_mqtt",
        level=level,
        log_file=log_file,
        include_console=enable_console,
    )

    main_logger = mqtt_logger.get_logger()

    # Create specialized event logger
    event_logger = ConnectionEventLogger(main_logger)

    # Log startup message
    main_logger.info("MQTT Transporter logging initialized")

    return main_logger, event_logger
