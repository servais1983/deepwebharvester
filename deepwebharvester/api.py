"""
FastAPI REST API for DeepWebHarvester.

Provides programmatic access to crawl jobs, results, and IOC data.
Includes API-key authentication, Prometheus metrics middleware, and
structured JSON logging.

Endpoints:
  POST /v1/crawl           Submit a new crawl job
  GET  /v1/jobs/{job_id}   Poll job status and stats
  GET  /v1/jobs            List all jobs
  GET  /v1/results/{job_id} Paginated crawl results
  GET  /v1/iocs/{job_id}   Aggregated IOC report for a job
  GET  /health             Liveness check
  GET  /readyz             Readiness (Tor connectivity) check
  GET  /metrics            (delegated to prometheus_client)
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
import uuid
from typing import Any, Dict, List, Optional

try:
    from fastapi import Depends, FastAPI, HTTPException, Security, status
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.security.api_key import APIKeyHeader
    from pydantic import BaseModel, Field, field_validator
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

from .config import AppConfig, load_config
from .crawler import CrawlResult, CrawlStats
from .extractor import PageExtractor
from .intelligence import IntelligenceExtractor
from .metrics import Metrics, start_metrics_server
from .storage import StorageManager
from .tor_manager import TorManager

logger = logging.getLogger(__name__)

# ── Auth ──────────────────────────────────────────────────────────────────────

_API_KEY_NAME = "X-API-Key"

def _get_api_key() -> str:
    """Read API key from environment (never hard-coded)."""
    key = os.getenv("DWH_API_KEY", "")
    if not key:
        logger.warning("DWH_API_KEY not set — API is unauthenticated!")
    return key


# ── Pydantic models ───────────────────────────────────────────────────────────

class CrawlRequest(BaseModel):
    seed_urls: List[str] = Field(..., min_length=1, max_length=20,
                                  description="List of .onion seed URLs")
    max_depth: int = Field(default=2, ge=0, le=5)
    max_pages: int = Field(default=20, ge=1, le=500)
    crawl_delay: float = Field(default=7.0, ge=1.0, le=60.0)
    max_workers: int = Field(default=3, ge=1, le=10)
    use_async: bool = Field(default=False,
                             description="Use async crawler (requires aiohttp-socks)")

    @field_validator("seed_urls")
    @classmethod
    def validate_onion(cls, urls: List[str]) -> List[str]:
        import re
        pattern = re.compile(r"^https?://[a-z2-7]{56}\.onion", re.IGNORECASE)
        bad = [u for u in urls if not pattern.match(u)]
        if bad:
            raise ValueError(f"Non-.onion URLs not accepted: {bad}")
        return urls


class JobStatus(BaseModel):
    job_id: str
    status: str          # queued | running | completed | failed
    created_at: float
    finished_at: Optional[float]
    seed_urls: List[str]
    pages_crawled: int
    pages_failed: int
    elapsed_seconds: float
    error: Optional[str]


class CrawlResultOut(BaseModel):
    url: str
    title: str
    depth: int
    crawl_time: float
    links_found: int
    site: str
    risk_label: Optional[str]
    risk_score: Optional[float]
    categories: List[str]


class IOCReport(BaseModel):
    job_id: str
    total_pages: int
    ioc_summary: Dict[str, Any]


# ── In-memory job registry ────────────────────────────────────────────────────

class _Job:
    def __init__(self, job_id: str, req: "CrawlRequest") -> None:
        self.job_id = job_id
        self.req = req
        self.status = "queued"
        self.created_at = time.time()
        self.finished_at: Optional[float] = None
        self.stats = CrawlStats()
        self.results: List[CrawlResult] = []
        self.intel: List[Dict[str, Any]] = []
        self.error: Optional[str] = None
        self.task: Optional[asyncio.Task] = None

    def to_status(self) -> JobStatus:
        return JobStatus(
            job_id=self.job_id,
            status=self.status,
            created_at=self.created_at,
            finished_at=self.finished_at,
            seed_urls=self.req.seed_urls,
            pages_crawled=self.stats.pages_crawled,
            pages_failed=self.stats.pages_failed,
            elapsed_seconds=self.stats.elapsed,
            error=self.error,
        )


_JOBS: Dict[str, _Job] = {}


# ── App factory ───────────────────────────────────────────────────────────────

def create_app(config: Optional[AppConfig] = None) -> "FastAPI":
    """
    Build and return the FastAPI application.

    Call ``uvicorn.run(create_app(), ...)`` to serve it.
    """
    if not FASTAPI_AVAILABLE:
        raise ImportError(
            "fastapi and pydantic are required. Run: pip install fastapi uvicorn pydantic"
        )

    cfg = config or load_config()
    app = FastAPI(
        title="DeepWebHarvester API",
        version="2.0.0",
        description="OSINT dark web intelligence platform",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    api_key_header = APIKeyHeader(name=_API_KEY_NAME, auto_error=False)

    def require_key(key: Optional[str] = Security(api_key_header)) -> str:
        expected = _get_api_key()
        if expected and key != expected:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing API key",
                headers={"WWW-Authenticate": "ApiKey"},
            )
        return key or ""

    # ── Middleware: request timing + Prometheus ────────────────────────────────
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import Response

    class MetricsMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next) -> Response:
            t0 = time.time()
            response = await call_next(request)
            Metrics.api_requests.labels(
                endpoint=request.url.path,
                method=request.method,
                status=str(response.status_code),
            ).inc()
            return response

    app.add_middleware(MetricsMiddleware)

    # ── Background crawl worker ───────────────────────────────────────────────

    async def _run_job(job: _Job) -> None:
        job.status = "running"
        Metrics.active_jobs.inc()
        try:
            tor = TorManager(
                socks_host=cfg.tor.socks_host,
                socks_port=cfg.tor.socks_port,
                control_host=cfg.tor.control_host,
                control_port=cfg.tor.control_port,
                control_password=cfg.tor.control_password,
            )
            extractor = PageExtractor(
                blacklist_paths=cfg.crawler.blacklist_paths
            )
            intel_ext = IntelligenceExtractor()

            if job.req.use_async:
                from .async_crawler import AsyncCrawler, AsyncCrawlerConfig
                acfg = AsyncCrawlerConfig(
                    max_depth=job.req.max_depth,
                    max_pages=job.req.max_pages,
                    crawl_delay=job.req.crawl_delay,
                    max_concurrent_domains=job.req.max_workers,
                )
                async with AsyncCrawler(tor, extractor, acfg) as crawler:
                    async for result in crawler.crawl_all(job.req.seed_urls):
                        job.results.append(result)
                        job.stats = crawler.stats
                        intel = intel_ext.analyze(result.url, result.text)
                        job.intel.append(intel.as_dict())
                        Metrics.pages_crawled.inc()
                        Metrics.threats_classified.labels(
                            risk_label=intel.threat.risk_label).inc()
            else:
                from .crawler import Crawler
                from concurrent.futures import ThreadPoolExecutor
                loop = asyncio.get_event_loop()

                crawler_sync = Crawler(
                    tor_manager=tor,
                    extractor=extractor,
                    max_depth=job.req.max_depth,
                    max_pages=job.req.max_pages,
                    crawl_delay=job.req.crawl_delay,
                    max_workers=job.req.max_workers,
                )
                with ThreadPoolExecutor(max_workers=1) as pool:
                    results = await loop.run_in_executor(
                        pool,
                        lambda: crawler_sync.crawl_all(job.req.seed_urls),
                    )
                job.results = results
                job.stats = crawler_sync.stats
                for r in results:
                    intel = intel_ext.analyze(r.url, r.text)
                    job.intel.append(intel.as_dict())

            job.status = "completed"
        except Exception as exc:
            logger.exception("Job %s failed: %s", job.job_id, exc)
            job.status = "failed"
            job.error = str(exc)
        finally:
            job.finished_at = time.time()
            Metrics.active_jobs.dec()

    # ── Routes ────────────────────────────────────────────────────────────────

    @app.get("/health", tags=["ops"])
    async def health() -> Dict[str, str]:
        return {"status": "ok", "version": "2.0.0"}

    @app.get("/readyz", tags=["ops"])
    async def readyz() -> Dict[str, Any]:
        tor = TorManager(
            socks_host=cfg.tor.socks_host,
            socks_port=cfg.tor.socks_port,
        )
        loop = asyncio.get_event_loop()
        ok = await loop.run_in_executor(None, tor.verify_connection)
        Metrics.tor_verified.set(1 if ok else 0)
        if not ok:
            raise HTTPException(status_code=503, detail="Tor not reachable")
        return {"status": "ready", "tor": "connected"}

    @app.post("/v1/crawl", response_model=JobStatus,
              status_code=status.HTTP_202_ACCEPTED, tags=["crawl"])
    async def submit_crawl(
        req: CrawlRequest,
        _key: str = Depends(require_key),
    ) -> JobStatus:
        job_id = str(uuid.uuid4())
        job = _Job(job_id, req)
        _JOBS[job_id] = job
        job.task = asyncio.create_task(_run_job(job))
        logger.info("Job %s submitted: %s", job_id, req.seed_urls)
        return job.to_status()

    @app.get("/v1/jobs", response_model=List[JobStatus], tags=["crawl"])
    async def list_jobs(_key: str = Depends(require_key)) -> List[JobStatus]:
        return [j.to_status() for j in _JOBS.values()]

    @app.get("/v1/jobs/{job_id}", response_model=JobStatus, tags=["crawl"])
    async def get_job(job_id: str, _key: str = Depends(require_key)) -> JobStatus:
        job = _JOBS.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        return job.to_status()

    @app.get("/v1/results/{job_id}", response_model=List[CrawlResultOut], tags=["results"])
    async def get_results(
        job_id: str,
        skip: int = 0,
        limit: int = 100,
        _key: str = Depends(require_key),
    ) -> List[CrawlResultOut]:
        job = _JOBS.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        page = job.results[skip: skip + limit]
        intel_slice = job.intel[skip: skip + limit] if job.intel else []
        out = []
        for i, r in enumerate(page):
            threat = intel_slice[i]["threat"] if i < len(intel_slice) else {}
            out.append(CrawlResultOut(
                url=r.url,
                title=r.title,
                depth=r.depth,
                crawl_time=r.crawl_time,
                links_found=r.links_found,
                site=r.site,
                risk_label=threat.get("risk_label"),
                risk_score=threat.get("risk_score"),
                categories=threat.get("categories", []),
            ))
        return out

    @app.get("/v1/iocs/{job_id}", response_model=IOCReport, tags=["intelligence"])
    async def get_iocs(
        job_id: str,
        _key: str = Depends(require_key),
    ) -> IOCReport:
        job = _JOBS.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        # Aggregate IOCs across all pages
        aggregated: Dict[str, Any] = {
            "ipv4": set(), "emails": set(), "btc_addresses": set(),
            "xmr_addresses": set(), "cves": set(), "onion_addresses": set(),
            "domains": set(), "urls": set(), "pgp_present": False,
        }
        for intel in job.intel:
            iocs = intel.get("iocs", {})
            for k in ("ipv4", "emails", "btc_addresses", "xmr_addresses",
                      "cves", "onion_addresses", "domains", "urls"):
                aggregated[k].update(iocs.get(k, []))
            if iocs.get("pgp_present"):
                aggregated["pgp_present"] = True
        # Serialize sets to sorted lists
        serialized = {k: sorted(v) if isinstance(v, set) else v
                      for k, v in aggregated.items()}
        serialized["total_unique"] = sum(
            len(v) for v in serialized.values() if isinstance(v, list)
        )
        return IOCReport(
            job_id=job_id,
            total_pages=len(job.results),
            ioc_summary=serialized,
        )

    return app


def serve(host: str = "0.0.0.0", port: int = 8000,
          metrics_port: int = 9090) -> None:
    """Launch the API server (blocking)."""
    try:
        import uvicorn  # type: ignore[import]
    except ImportError:
        raise ImportError("uvicorn required: pip install uvicorn")
    start_metrics_server(port=metrics_port)
    app = create_app()
    uvicorn.run(app, host=host, port=port, log_level="info")
