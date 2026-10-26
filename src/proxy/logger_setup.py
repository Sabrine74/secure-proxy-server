"""Application logger: writes to the console and to logs/proxy.log."""
from __future__ import annotations

import logging
from pathlib import Path


def setup_logger(log_dir: str | Path = "logs") -> logging.Logger:
    """Create (or return) the proxy's logger with two outputs."""
    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("secure_proxy")
    logger.setLevel(logging.INFO)

    # If already configured (called twice), don't add handlers again
    if logger.handlers:
        return logger

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    file_handler = logging.FileHandler(log_dir / "proxy.log")
    file_handler.setFormatter(fmt)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(fmt)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger
