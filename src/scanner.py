import asyncio
from typing import List, Dict

from src.fingerprint import fingerprint_service
from src.vuln import run_vuln_checks

class AsyncPortScanner:
    def __init__(self, target: str, ports: List[int], timeout: float = 1.0, concurrency: int = 500, check_vulns: bool = False):
        self.target = target
        self.ports = ports
        self.timeout = timeout
        self.check_vulns = check_vulns
        # Semaphore limits the number of simultaneous connections (avoids OS limits)
        self.semaphore = asyncio.Semaphore(concurrency)
        self.results: List[Dict] = []

    async def scan_port(self, port: int) -> None:
        """Scans a single port using a semaphore to limit concurrency."""
        async with self.semaphore:
            try:
                # Attempt to connect
                conn = asyncio.open_connection(self.target, port)
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)

                # If successful, fingerprint the service
                service = await fingerprint_service(reader, writer, timeout=self.timeout)

                writer.close()
                await writer.wait_closed()

                vulns = []
                if self.check_vulns:
                    vulns = await run_vuln_checks(self.target, port, service, timeout=self.timeout)

                self.results.append({
                    "port": port,
                    "status": "OPEN",
                    "service": service,
                    "vulns": vulns
                })

            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                # Port is closed or filtered; ignore
                pass
            except Exception:
                # Catch-all for other weird errors
                pass

    async def run(self):
        """Orchestrates the scan."""
        tasks = [self.scan_port(port) for port in self.ports]
        await asyncio.gather(*tasks)
        return self.results