"""
Tor network management.

Handles session creation (routing all traffic via SOCKS5) and periodic
circuit renewal via the Tor control protocol so crawl sessions remain
anonymous.
"""
from __future__ import annotations

import logging
import time
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# stem is imported lazily inside renew_circuit() so that the rest of the
# module (session creation, Tor verification) works even when stem's C
# extensions are unavailable (e.g. certain CI / sandbox environments).


class TorManager:
    """
    Manages a Tor-proxied requests session and circuit renewal.

    Example::

        manager = TorManager(control_password="secret")
        session = manager.create_session()
        resp = session.get("http://example.onion/", timeout=30)
    """

    def __init__(
        self,
        socks_host: str = "127.0.0.1",
        socks_port: int = 9050,
        control_host: str = "127.0.0.1",
        control_port: int = 9051,
        control_password: str = "",
        user_agent: str = (
            "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"
        ),
    ) -> None:
        self.socks_host = socks_host
        self.socks_port = socks_port
        self.control_host = control_host
        self.control_port = control_port
        self.control_password = control_password
        self.user_agent = user_agent
        self._circuits_renewed: int = 0

    # ── Public interface ──────────────────────────────────────────────────────

    @property
    def proxy_url(self) -> str:
        """SOCKS5h proxy URL (DNS resolved through Tor)."""
        return f"socks5h://{self.socks_host}:{self.socks_port}"

    def create_session(self) -> requests.Session:
        """
        Return a :class:`requests.Session` pre-configured to route all traffic
        through the Tor SOCKS5 proxy with privacy-friendly headers.
        """
        session = requests.Session()
        session.proxies = {
            "http": self.proxy_url,
            "https": self.proxy_url,
        }
        session.headers.update(
            {
                "User-Agent": self.user_agent,
                "Accept-Language": "en-US,en;q=0.9",
                "Accept": (
                    "text/html,application/xhtml+xml,application/xml;"
                    "q=0.9,image/webp,*/*;q=0.8"
                ),
                "Connection": "keep-alive",
                "Accept-Encoding": "gzip, deflate",
                "DNT": "1",
            }
        )
        return session

    def renew_circuit(self) -> bool:
        """
        Signal Tor to build a new circuit (new exit node / IP address).

        Returns:
            ``True`` if the circuit was successfully renewed, ``False`` otherwise.
        """
        if not self.control_password:
            logger.debug("No Tor control password set; skipping circuit renewal.")
            return False
        try:
            from stem import Signal  # lazy import — avoids C-extension load at startup
            from stem.control import Controller

            with Controller.from_port(
                address=self.control_host, port=self.control_port
            ) as ctrl:
                ctrl.authenticate(password=self.control_password)
                ctrl.signal(Signal.NEWNYM)
                self._circuits_renewed += 1
                logger.info(
                    "Tor circuit renewed (total renewals: %d).",
                    self._circuits_renewed,
                )
                # Allow time for the new circuit to be established
                time.sleep(5)
            return True
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to renew Tor identity: %s", exc)
            return False

    def verify_connection(self) -> bool:
        """
        Confirm that outbound traffic is actually routed through Tor.

        Returns:
            ``True`` if Tor is confirmed active, ``False`` otherwise.
        """
        session = self.create_session()
        try:
            resp = session.get(
                "https://check.torproject.org/api/ip",
                timeout=30,
            )
            resp.raise_for_status()
            data: dict = resp.json()
            is_tor: bool = bool(data.get("IsTor", False))
            if is_tor:
                logger.info(
                    "Tor connection verified. Exit IP: %s",
                    data.get("IP", "unknown"),
                )
            else:
                logger.warning(
                    "Traffic does NOT appear to be going through Tor! "
                    "Ensure Tor is running on %s:%d.",
                    self.socks_host,
                    self.socks_port,
                )
            return is_tor
        except Exception as exc:  # noqa: BLE001
            logger.error("Could not verify Tor connection: %s", exc)
            return False
