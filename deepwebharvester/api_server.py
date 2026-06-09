"""Entry point for ``python -m deepwebharvester.api_server``."""
from __future__ import annotations
import argparse
from .api import serve


def main() -> None:
    parser = argparse.ArgumentParser(description="DeepWebHarvester API server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--metrics-port", type=int, default=9090)
    args = parser.parse_args()
    serve(host=args.host, port=args.port, metrics_port=args.metrics_port)


if __name__ == "__main__":
    main()
