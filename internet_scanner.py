"""
Internet-Wide Scanner — CIDR/ASN input, massive parallelism, streaming output.
Not a per-target VAPT agent. This is for authorized internet-wide scanning only.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import signal
import socket
import ssl
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncIterator, Optional, Set, TYPE_CHECKING, Any

if TYPE_CHECKING:
    import aiohttp
from urllib.parse import urlparse

try:
    import aiohttp
except ImportError:
    aiohttp = None

try:
    import orjson
except ImportError:
    import json as orjson

# asyncpg is optional - for database output
try:
    import asyncpg
except ImportError:
    asyncpg = None


def _safe_dumps(obj) -> bytes:
    """Serialize to bytes, handling both orjson and json fallback."""
    try:
        return orjson.dumps(obj)
    except (TypeError, AttributeError):
        # json.dumps returns str, encode to bytes
        return json.dumps(obj).encode('utf-8')


def _safe_loads(data: bytes) -> dict:
    """Deserialize from bytes, handling both orjson and json fallback."""
    try:
        return orjson.loads(data)
    except (TypeError, AttributeError):
        return json.loads(data.decode('utf-8'))


# ============================================================
# INPUT MODEL — CIDR/ASN/Port ranges, not single targets
# ============================================================

@dataclass(frozen=True)
class ScanTarget:
    """A single IP:port to scan."""
    ip: str
    port: int
    protocol: str = "tcp"  # tcp, udp
    
    def __str__(self) -> str:
        return f"{self.ip}:{self.port}/{self.protocol}"


@dataclass(frozen=True)
class ScanJob:
    """Internet-wide scan job definition."""
    job_id: str
    name: str
    cidrs: list[str]                    # ["1.2.3.0/24", "2001:db8::/32"]
    ports: list[int]                    # [80, 443, 8080, 8443]
    excluded_cidrs: list[str] = field(default_factory=list)
    rate_per_second: int = 10000        # Global packets/sec
    max_concurrent: int = 5000          # Max concurrent connections
    timeout_seconds: float = 5.0
    modules: list[str] = field(default_factory=lambda: ["http", "tls", "ssh", "rdp"])
    output_path: str = "./scan_results"
    resume: bool = False
    
    def expand_targets(self) -> AsyncIterator[ScanTarget]:
        """Expand CIDRs into individual IP:port targets."""
        for cidr_str in self.cidrs:
            network = ipaddress.ip_network(cidr_str, strict=False)
            for ip in network.hosts():
                ip_str = str(ip)
                # Check exclusions
                excluded = False
                for exc in self.excluded_cidrs:
                    if ipaddress.ip_address(ip) in ipaddress.ip_network(exc):
                        excluded = True
                        break
                if excluded:
                    continue
                for port in self.ports:
                    yield ScanTarget(ip=ip_str, port=port)


# ============================================================
# RESULT MODEL — Streaming, not per-target reports
# ============================================================

@dataclass
class ScanResult:
    """Single scan result - streamed immediately."""
    timestamp: str
    job_id: str
    target: ScanTarget
    module: str
    success: bool
    data: dict
    error: Optional[str] = None
    latency_ms: float = 0.0
    
    def to_json(self) -> bytes:
        return _safe_dumps({
            "ts": self.timestamp,
            "job": self.job_id,
            "ip": self.target.ip,
            "port": self.target.port,
            "proto": self.target.protocol,
            "module": self.module,
            "ok": self.success,
            "data": self.data,
            "err": self.error,
            "latency_ms": self.latency_ms,
        })


# ============================================================
# MODULE INTERFACE — Pluggable scanners
# ============================================================

class ScanModule(ABC):
    """Base class for scan modules."""
    
    name: str = "base"
    default_ports: list[int] = []
    
    @abstractmethod
    async def scan(self, target: ScanTarget, session: "aiohttp.ClientSession", 
                   timeout: float) -> ScanResult:
        pass


class HTTPModule(ScanModule):
    """HTTP/HTTPS banner grab + basic checks."""
    name = "http"
    default_ports = [80, 8080, 8000, 8888, 3000, 5000, 8008, 8880]
    
    async def scan(self, target: ScanTarget, session: Any,
                   timeout: float) -> ScanResult:
        start = time.perf_counter()
        scheme = "https" if target.port in (443, 8443, 9443) else "http"
        url = f"{scheme}://{target.ip}:{target.port}"
        
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout),
                                   ssl=False, allow_redirects=False) as resp:
                body = await resp.read()
                latency = (time.perf_counter() - start) * 1000
                
                # Extract headers
                headers = {k.lower(): v for k, v in resp.headers.items()}
                server = headers.get("server", "")
                powered_by = headers.get("x-powered-by", "")
                
                # Check for common tech
                tech = self._detect_tech(headers, body)
                
                return ScanResult(
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    job_id="",  # filled by runner
                    target=target,
                    module=self.name,
                    success=True,
                    data={
                        "status": resp.status,
                        "server": server[:200],
                        "powered_by": powered_by[:200],
                        "tech": tech,
                        "content_length": len(body),
                        "title": self._extract_title(body)[:200] if body else "",
                    },
                    latency_ms=latency,
                )
        except Exception as e:
            return ScanResult(
                timestamp=datetime.now(timezone.utc).isoformat(),
                job_id="",
                target=target,
                module=self.name,
                success=False,
                data={},
                error=str(e)[:500],
                latency_ms=(time.perf_counter() - start) * 1000,
            )
    
    def _detect_tech(self, headers: dict, body: bytes) -> list[str]:
        tech = []
        signals = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
        body_str = body[:5000].decode("utf-8", errors="ignore").lower()
        all_s = signals + " " + body_str
        
        signatures = {
            "nginx": ["nginx"],
            "apache": ["apache"],
            "iis": ["microsoft-iis", "iis"],
            "cloudflare": ["cloudflare"],
            "aws": ["aws", "amazon", "cloudfront"],
            "wordpress": ["wp-content", "wp-includes", "wordpress"],
            "drupal": ["drupal"],
            "django": ["django", "csrftoken"],
            "spring": ["spring", "spring boot"],
            "express": ["express"],
            "php": ["php/"],
            "jsp": ["jsp", "jsessionid"],
            "aspnet": ["asp.net", "aspnet"],
        }
        for tech_name, sigs in signatures.items():
            if any(s in all_s for s in sigs):
                tech.append(tech_name)
        return tech
    
    def _extract_title(self, body: bytes) -> str:
        try:
            body_str = body.decode("utf-8", errors="ignore")
            import re
            match = re.search(r"<title[^>]*>([^<]+)</title>", body_str, re.IGNORECASE)
            return match.group(1) if match else ""
        except Exception:
            return ""


class TLSModule(ScanModule):
    """TLS certificate grabber."""
    name = "tls"
    default_ports = [443, 8443, 9443, 993, 995, 587, 465]
    
    async def scan(self, target: ScanTarget, session: Any,
                   timeout: float) -> ScanResult:
        start = time.perf_counter()
        try:
            # Raw TCP + TLS handshake
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target.ip, target.port),
                timeout=timeout
            )
            
            # Wrap with TLS
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            
            tls_sock = ssl_ctx.wrap_socket(writer.get_extra_info("socket"), 
                                           server_hostname=target.ip)
            tls_sock.do_handshake()
            
            cert = tls_sock.getpeercert(binary_form=True)
            writer.close()
            await writer.wait_closed()
            
            latency = (time.perf_counter() - start) * 1000
            
            # Parse cert (simplified)
            import cryptography.x509 as x509
            from cryptography.hazmat.backends import default_backend
            
            cert_obj = x509.load_der_x509_certificate(cert, default_backend())
            subject = cert_obj.subject.rfc4514_string()
            issuer = cert_obj.issuer.rfc4514_string()
            san = []
            try:
                ext = cert_obj.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                san = ext.value.get_values_for_type(x509.DNSName)
            except Exception:
                pass
            
            return ScanResult(
                timestamp=datetime.now(timezone.utc).isoformat(),
                job_id="",
                target=target,
                module=self.name,
                success=True,
                data={
                    "subject": subject,
                    "issuer": issuer,
                    "san": san[:50],
                    "not_before": cert_obj.not_valid_before_utc.isoformat() if cert_obj.not_valid_before_utc else "",
                    "not_after": cert_obj.not_valid_after_utc.isoformat() if cert_obj.not_valid_after_utc else "",
                    "version": cert_obj.version.name,
                },
                latency_ms=latency,
            )
        except Exception as e:
            return ScanResult(
                timestamp=datetime.now(timezone.utc).isoformat(),
                job_id="",
                target=target,
                module=self.name,
                success=False,
                data={},
                error=str(e)[:500],
                latency_ms=(time.perf_counter() - start) * 1000,
            )


class SSHModule(ScanModule):
    """SSH banner grab."""
    name = "ssh"
    default_ports = [22, 2222]
    
    async def scan(self, target: ScanTarget, session: Any,
                   timeout: float) -> ScanResult:
        start = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target.ip, target.port),
                timeout=timeout
            )
            
            # Read SSH banner
            banner = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            writer.close()
            await writer.wait_closed()
            
            latency = (time.perf_counter() - start) * 1000
            banner_str = banner.decode("utf-8", errors="ignore").strip()
            
            return ScanResult(
                timestamp=datetime.now(timezone.utc).isoformat(),
                job_id="",
                target=target,
                module=self.name,
                success=True,
                data={"banner": banner_str[:500]},
                latency_ms=latency,
            )
        except Exception as e:
            return ScanResult(
                timestamp=datetime.now(timezone.utc).isoformat(),
                job_id="",
                target=target,
                module=self.name,
                success=False,
                data={},
                error=str(e)[:500],
                latency_ms=(time.perf_counter() - start) * 1000,
            )


class RDPModule(ScanModule):
    """RDP security check (NLA detection)."""
    name = "rdp"
    default_ports = [3389]
    
    async def scan(self, target: ScanTarget, session: Any,
                   timeout: float) -> ScanResult:
        start = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target.ip, target.port),
                timeout=timeout
            )
            
            # RDP negotiation request (TPKT + X.224 + RDP Negotiation)
            # Simplified - just check if port responds
            writer.write(bytes([
                0x03, 0x00, 0x00, 0x13,  # TPKT header
                0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00,  # X.224 CR
                0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00  # RDP Neg
            ]))
            await writer.drain()
            
            resp = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            writer.close()
            await writer.wait_closed()
            
            latency = (time.perf_counter() - start) * 1000
            
            # Check for NLA (CredSSP)
            has_nla = b"\x00\x00\x00\x00\x00\x00\x00" in resp  # Simplified
            
            return ScanResult(
                timestamp=datetime.now(timezone.utc).isoformat(),
                job_id="",
                target=target,
                module=self.name,
                success=True,
                data={
                    "nla_enabled": has_nla,
                    "response_length": len(resp),
                },
                latency_ms=latency,
            )
        except Exception as e:
            return ScanResult(
                timestamp=datetime.now(timezone.utc).isoformat(),
                job_id="",
                target=target,
                module=self.name,
                success=False,
                data={},
                error=str(e)[:500],
                latency_ms=(time.perf_counter() - start) * 1000,
            )


# Module registry
MODULES = {
    "http": HTTPModule(),
    "tls": TLSModule(),
    "ssh": SSHModule(),
    "rdp": RDPModule(),
}


# ============================================================
# EXECUTION LOOP — Token bucket + semaphore, streaming output
# ============================================================

class TokenBucket:
    """Global rate limiter."""
    def __init__(self, rate: int):
        self.rate = rate
        self.tokens = rate
        self.last = time.monotonic()
        self.lock = asyncio.Lock()
    
    async def take(self):
        async with self.lock:
            now = time.monotonic()
            elapsed = now - self.last
            self.tokens = min(self.rate, self.tokens + elapsed * self.rate)
            if self.tokens >= 1:
                self.tokens -= 1
                self.last = now
                return
            wait = (1 - self.tokens) / self.rate
            self.tokens = 0
            self.last = now + wait
        await asyncio.sleep(wait)


class InternetWideScanner:
    """Internet-wide scanner with streaming results and checkpointing."""
    
    def __init__(self, job: ScanJob):
        self.job = job
        self.bucket = TokenBucket(job.rate_per_second)
        self.sem = asyncio.Semaphore(job.max_concurrent)
        self.session: Optional[aiohttp.ClientSession] = None
        self.output_file: Optional[Path] = None
        self.checkpoint_file: Optional[Path] = None
        self.running = False
        self.stats = {
            "total": 0, "success": 0, "failed": 0,
            "by_module": {}, "start_time": time.time()
        }
        self._checkpoint_interval = 10000  # checkpoint every N results
        self._results_since_checkpoint = 0
    
    async def __aenter__(self):
        if aiohttp is None:
            raise RuntimeError("aiohttp is required for scanning. Install with: pip install aiohttp")
        
        # Setup output
        self.output_file = Path(self.job.output_path) / f"{self.job.job_id}.jsonl"
        self.output_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Setup checkpoint
        self.checkpoint_file = Path(self.job.output_path) / f"{self.job.job_id}.checkpoint.json"
        
        # HTTP session with connection pooling
        connector = aiohttp.TCPConnector(
            limit=self.job.max_concurrent,
            limit_per_host=100,
            ttl_dns_cache=300,
            enable_cleanup_closed=True,
        )
        self.session = aiohttp.ClientSession(connector=connector)
        
        # Load checkpoint if resuming
        if self.job.resume and self.checkpoint_file.exists():
            await self._load_checkpoint()
        
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def _load_checkpoint(self):
        try:
            data = _safe_loads(self.checkpoint_file.read_bytes())  # type: ignore[union-attr]
            self.completed_targets = set(data.get("completed", []))
            print(f"Resumed from checkpoint: {len(self.completed_targets)} targets completed")
        except Exception:
            self.completed_targets = set()
    
    async def _save_checkpoint(self):
        data = {"completed": list(self.completed_targets)}
        self.checkpoint_file.write_bytes(_safe_dumps(data))  # type: ignore[union-attr]
    
    def _target_key(self, target: ScanTarget) -> str:
        return f"{target.ip}:{target.port}"
    
    async def run(self) -> AsyncIterator[ScanResult]:
        """Main execution loop - streams results as they complete."""
        self.running = True
        self.completed_targets = getattr(self, 'completed_targets', set())
        
        # Get all modules for this job
        modules = [MODULES[m] for m in self.job.modules if m in MODULES]
        
        # Create tasks for all target/module combinations
        async def scan_target_module(target: ScanTarget, module: ScanModule):
            if not self.running:
                return None
            key = self._target_key(target)
            if key in self.completed_targets:
                return None
            
            await self.bucket.take()
            async with self.sem:
                if not self.running:
                    return None
                result = await module.scan(target, self.session, self.job.timeout_seconds)
                result.job_id = self.job.job_id
                
                # Stream result immediately
                self.output_file.write_bytes(result.to_json() + b"\n")  # type: ignore[union-attr]
                
                # Update stats
                self.stats["total"] += 1
                if result.success:
                    self.stats["success"] += 1
                else:
                    self.stats["failed"] += 1
                self.stats["by_module"][module.name] = \
                    self.stats["by_module"].get(module.name, 0) + 1
                
                self._results_since_checkpoint += 1
                if self._results_since_checkpoint >= self._checkpoint_interval:
                    self.completed_targets.add(key)
                    await self._save_checkpoint()
                    self._results_since_checkpoint = 0
                else:
                    self.completed_targets.add(key)
                
                return result
        
        # Stream targets and execute
        tasks = set()
        
        async for target in self.job.expand_targets():
            if not self.running:
                break
            
            for module in modules:
                if target.port not in module.default_ports and module.default_ports:
                    continue
                task = asyncio.create_task(scan_target_module(target, module))
                tasks.add(task)
                
                # Yield completed results
                while tasks:
                    done, pending = await asyncio.wait(tasks, timeout=0.1, 
                                                        return_when=asyncio.FIRST_COMPLETED)
                    for task in done:
                        result = task.result()
                        if result:
                            yield result
                        tasks.remove(task)
                    if not self.running:
                        break
            
            # Periodic stats
            if self.stats["total"] % 10000 == 0 and self.stats["total"] > 0:
                elapsed = time.time() - self.stats["start_time"]
                print(f"Progress: {self.stats['total']} total, "
                      f"{self.stats['success']} ok, {self.stats['failed']} failed, "
                      f"{self.stats['total']/elapsed:.0f} req/s")
        
        # Wait for remaining
        if tasks:
            for task in asyncio.as_completed(tasks):
                result = await task
                if result:
                    yield result
        
        # Final checkpoint
        await self._save_checkpoint()
        self.running = False
    
    def stop(self):
        self.running = False
    
    def get_stats(self) -> dict:
        elapsed = time.time() - self.stats["start_time"]
        return {
            **self.stats,
            "elapsed_seconds": elapsed,
            "rate_per_second": self.stats["total"] / elapsed if elapsed > 0 else 0,
        }


# ============================================================
# CLI ENTRY POINT
# ============================================================

async def run_scan(job: ScanJob):
    """Run a scan job and stream results."""
    async with InternetWideScanner(job) as scanner:
        async for result in scanner.run():
            # Results are already written to file, this is for monitoring
            pass
        return scanner.get_stats()


def main():
    import argparse
    import uuid
    
    parser = argparse.ArgumentParser(description="Internet-wide scanner (CIDR/ASN input)")
    parser.add_argument("--cidrs", required=True, help="Comma-separated CIDR ranges")
    parser.add_argument("--ports", default="80,443,8080,8443,22,3389", help="Comma-separated ports")
    parser.add_argument("--exclude", default="", help="Comma-separated CIDRs to exclude")
    parser.add_argument("--rate", type=int, default=10000, help="Global packets/second")
    parser.add_argument("--concurrent", type=int, default=5000, help="Max concurrent connections")
    parser.add_argument("--timeout", type=float, default=5.0, help="Timeout per connection")
    parser.add_argument("--modules", default="http,tls,ssh,rdp", help="Comma-separated modules")
    parser.add_argument("--output", default="./scan_results", help="Output directory")
    parser.add_argument("--job-id", default="", help="Job ID (auto-generated if empty)")
    parser.add_argument("--resume", action="store_true", help="Resume from checkpoint")
    parser.add_argument("--name", default="internet-scan", help="Job name")
    
    args = parser.parse_args()
    
    job = ScanJob(
        job_id=args.job_id or uuid.uuid4().hex[:12],
        name=args.name,
        cidrs=args.cidrs.split(","),
        ports=[int(p) for p in args.ports.split(",")],
        excluded_cidrs=args.exclude.split(",") if args.exclude else [],
        rate_per_second=args.rate,
        max_concurrent=args.concurrent,
        timeout_seconds=args.timeout,
        modules=args.modules.split(","),
        output_path=args.output,
        resume=args.resume,
    )
    
    print(f"Starting scan job: {job.job_id}")
    print(f"CIDRs: {job.cidrs}")
    print(f"Ports: {job.ports}")
    print(f"Rate: {job.rate_per_second}/sec, Concurrent: {job.max_concurrent}")
    print(f"Modules: {job.modules}")
    print(f"Output: {job.output_path}")
    
    # Handle signals
    loop = asyncio.get_event_loop()
    scanner_instance = None
    
    async def run():
        nonlocal scanner_instance
        async with InternetWideScanner(job) as scanner:
            scanner_instance = scanner
            await run_scan(job)
    
    def signal_handler(sig, frame):
        print("\nShutting down...")
        if scanner_instance:
            scanner_instance.stop()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        loop.run_until_complete(run())
    except KeyboardInterrupt:
        pass
    finally:
        if scanner_instance:
            stats = scanner_instance.get_stats()
            print(f"\nFinal stats: {stats}")


if __name__ == "__main__":
    main()