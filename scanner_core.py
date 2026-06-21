import asyncio
import socket
import time
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class PortResult:
    port: int
    is_open: bool
    service: str = ""
    banner: str = ""
    latency_ms: float = 0.0


COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 587: "SMTP-SUB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 2049: "NFS",
    2375: "Docker", 3000: "Node-Dev", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 5984: "CouchDB", 6379: "Redis",
    6443: "Kubernetes", 7001: "WebLogic", 8000: "HTTP-Alt", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 8888: "HTTP-Alt2", 9000: "PHP-FPM", 9092: "Kafka",
    9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
}

HTTP_PROBE = b"HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: VanguardNet/1.0\r\nConnection: close\r\n\r\n"


class AsyncPortScanner:
    def __init__(
        self,
        target: str,
        ports: list[int],
        concurrency: int = 500,
        timeout: float = 1.5,
        on_result: Optional[Callable[[PortResult], None]] = None,
        on_progress: Optional[Callable[[int, int], None]] = None,
    ):
        self.target = target
        self.ports = ports
        self.concurrency = concurrency
        self.timeout = timeout
        self.on_result = on_result
        self.on_progress = on_progress
        self._scanned = 0
        self._total = len(ports)
        self._stop_flag = False
        self._resolved_ip: Optional[str] = None

    def stop(self):
        self._stop_flag = True

    async def _resolve(self) -> str:
        if self._resolved_ip:
            return self._resolved_ip
        loop = asyncio.get_running_loop()
        try:
            info = await loop.getaddrinfo(self.target, None, family=socket.AF_INET)
            self._resolved_ip = info[0][4][0]
        except Exception:
            self._resolved_ip = self.target
        return self._resolved_ip

    HTTP_LIKE_PORTS = (80, 8000, 8080, 8888, 3000, 9000)
    KNOWN_PROBE_PORTS = (25, 21, 110, 143, 443, 8443)

    async def _grab_banner(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int) -> str:
        try:
            try:
                data = await asyncio.wait_for(reader.read(256), timeout=0.6)
                if data:
                    return self._decode(data)
            except asyncio.TimeoutError:
                pass

            if port in self.HTTP_LIKE_PORTS:
                return await self._try_http_probe(reader, writer)

            if port in (443, 8443):
                return "TLS/SSL handshake required"

            probe_map = {
                25: b"EHLO vanguard.local\r\n",
                21: b"\r\n",
                110: b"\r\n",
                143: b"\r\n",
            }
            probe = probe_map.get(port)
            if probe:
                writer.write(probe)
                await writer.drain()
                data = await asyncio.wait_for(reader.read(512), timeout=0.8)
                return self._decode(data)

            return await self._try_http_probe(reader, writer)

        except Exception:
            return ""
        return ""

    async def _try_http_probe(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> str:
        try:
            host_header = self.target.encode()
            writer.write(HTTP_PROBE % host_header)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
            return self._decode(data)
        except Exception:
            return ""

    @staticmethod
    def _decode(data: bytes) -> str:
        try:
            text = data.decode("utf-8", errors="ignore").strip()
        except Exception:
            text = repr(data)
        lines = [l.strip() for l in text.splitlines() if l.strip()]
        return " | ".join(lines[:3])[:300]

    async def _scan_port(self, ip: str, port: int, sem: asyncio.Semaphore):
        async with sem:
            if self._stop_flag:
                return
            start = time.perf_counter()
            result = PortResult(port=port, is_open=False, service=COMMON_SERVICES.get(port, "Unknown"))
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=self.timeout
                )
                result.is_open = True
                result.latency_ms = (time.perf_counter() - start) * 1000
                result.banner = await self._grab_banner(reader, writer, port)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
            except Exception:
                result.is_open = False
            finally:
                self._scanned += 1
                if self.on_progress:
                    self.on_progress(self._scanned, self._total)
                if result.is_open and self.on_result:
                    self.on_result(result)

    async def run(self):
        ip = await self._resolve()
        sem = asyncio.Semaphore(self.concurrency)
        tasks = [self._scan_port(ip, port, sem) for port in self.ports]
        await asyncio.gather(*tasks)


def parse_port_range(text: str) -> list[int]:
    text = text.strip()
    if not text:
        return list(range(1, 1025))
    ports: set[int] = set()
    chunks = text.split(",")
    for chunk in chunks:
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_s, end_s = chunk.split("-", 1)
            start, end = int(start_s.strip()), int(end_s.strip())
            if start > end:
                start, end = end, start
            start = max(1, start)
            end = min(65535, end)
            ports.update(range(start, end + 1))
        else:
            p = int(chunk)
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(ports)