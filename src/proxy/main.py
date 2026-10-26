"""Entry point: load config, set up logging, start both listeners."""
from __future__ import annotations
import asyncio

from .config_loader import load_config
from .logger_setup import setup_logger
from .tcp_relay import TcpRelay
from .http_health import start_health_listener


async def run() -> None:
    log = setup_logger()
    config = load_config("config/policies.yaml")
    log.info("=== Secure Proxy - Sprint 1-3 ===")

    relay = TcpRelay(config)
    https_server = await relay.start()
    health_server = await start_health_listener(config.listen_host, config.health_port)

    try:
        await asyncio.gather(
            https_server.serve_forever(),
            health_server.serve_forever(),
        )
    except asyncio.CancelledError:
        pass
    finally:
        https_server.close()
        health_server.close()
        await https_server.wait_closed()
        await health_server.wait_closed()
        log.info("=== Proxy stopped ===")


def main() -> None:
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
