"""
Tor network management.

Handles session creation (routing all traffic via SOCKS5) and periodic
circuit renewal via the Tor control protocol so crawl sessions remain
anonymous.
"""
from __future__ import annotations

import logging
import random
import time
from typing import Optional

import requests
from requests.adapters import HTTPAdapter

logger = logging.getLogger(__name__)

# stem is imported lazily inside renew_circuit() so that the rest of the
# module (session creation, Tor verification) works even when stem's C
# extensions are unavailable (e.g. certain CI / sandbox environments).

# ---------------------------------------------------------------------------
# User-Agent pool — realistic browser strings rotated per session
# ---------------------------------------------------------------------------
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0",
    "Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
]

# Accept-Language variants to rotate
_ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.8",
    "en;q=0.9",
    "en-US,en;q=0.7,fr;q=0.3",
]


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
        user_agent: Optional[str] = None,
    ) -> None:
        self.socks_host = socks_host
        self.socks_port = socks_port
        self.control_host = control_host
        self.control_port = control_port
        self.control_password = control_password
        # None → pick randomly per session; explicit value → fixed (for tests)
        self._fixed_user_agent: Optional[str] = user_agent
        self._circuits_renewed: int = 0

    # ── Public interface ──────────────────────────────────────────────────────

    @property
    def proxy_url(self) -> str:
        """SOCKS5h proxy URL (DNS resolved through Tor)."""
        return f"socks5h://{self.socks_host}:{self.socks_port}"

    @property
    def user_agent(self) -> str:
        """Return the configured User-Agent (fixed or the first pool entry)."""
        return self._fixed_user_agent or _USER_AGENTS[0]

    def create_session(self) -> requests.Session:
        """
        Return a :class:`requests.Session` pre-configured to route all traffic
        through the Tor SOCKS5 proxy with randomized privacy-friendly headers
        and a connection pool to reuse sockets across requests.
        """
        session = requests.Session()

        # Connection pooling — reuse sockets within the same session
        adapter = HTTPAdapter(
            pool_connections=5,
            pool_maxsize=10,
            max_retries=0,  # retries handled by Crawler._fetch
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        session.proxies = {
            "http": self.proxy_url,
            "https": self.proxy_url,
        }

        ua = self._fixed_user_agent or random.choice(_USER_AGENTS)
        lang = random.choice(_ACCEPT_LANGUAGES)

        # Build header dict then shuffle order to avoid a fixed fingerprint
        headers = {
            "User-Agent": ua,
            "Accept-Language": lang,
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;"
                "q=0.9,image/webp,*/*;q=0.8"
            ),
            "Accept-Encoding": "gzip, deflate",
            "DNT": "1",
            "Connection": "keep-alive",
        }
        items = list(headers.items())
        random.shuffle(items)
        session.headers.update(dict(items))

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
            from stem import (  # noqa: F401
                SocketError,
                OperationFailed,
                ProtocolError,
            )

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
        except ImportError:
            logger.error("stem library not installed; cannot renew Tor circuit.")
            return False
        except OSError as exc:
            logger.error("Cannot connect to Tor control port: %s", exc)
            return False
        except Exception as exc:  # noqa: BLE001 — stem raises varied exceptions
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
        except requests.exceptions.Timeout:
            logger.error("Tor verification timed out.")
            return False
        except requests.exceptions.ConnectionError as exc:
            logger.error("Cannot reach Tor check endpoint: %s", exc)
            return False
        except requests.exceptions.RequestException as exc:
            logger.error("Could not verify Tor connection: %s", exc)
            return False
        except Exception as exc:  # noqa: BLE001 — defensive catch for unexpected errors
            logger.error("Unexpected error verifying Tor connection: %s", exc)
            return False
