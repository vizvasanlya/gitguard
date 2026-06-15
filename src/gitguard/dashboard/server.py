from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any

from gitguard.core.sbom import SBOMGenerator
from gitguard.core.scanner import SecurityScanner
from gitguard.utils.sarif import SARIFFormatter

_dashboard_server: DashboardServer | None = None


class DashboardServer:
    """Simple HTTP server for GitGuard dashboard."""

    def __init__(self, project_path: str | Path, port: int = 8080) -> None:
        self.project_path = Path(project_path).resolve()
        self.port = port
        self._results: dict[str, Any] | None = None

    def start(self) -> None:
        global _dashboard_server
        _dashboard_server = self

        try:
            from http.server import HTTPServer

            print(f"GitGuard Dashboard running at http://localhost:{self.port}")
            print(f"Scanning: {self.project_path}")
            print("Press Ctrl+C to stop")

            server = HTTPServer(("localhost", self.port), _DashboardHandler)
            server.serve_forever()

        except KeyboardInterrupt:
            print("\nDashboard stopped")

    def scan(self) -> dict[str, Any]:
        scanner = SecurityScanner(self.project_path)
        result = scanner.scan()

        self._results = {
            "total_findings": result.total_findings,
            "critical_count": result.critical_count,
            "high_count": result.high_count,
            "files_scanned": result.files_scanned,
            "lines_scanned": result.lines_scanned,
            "findings": [f.to_dict() for f in result.findings],
        }

        return self._results

    def get_results(self) -> dict[str, Any]:
        if self._results is None:
            return self.scan()
        return self._results

    def export_sarif(self) -> str:
        scanner = SecurityScanner(self.project_path)
        result = scanner.scan()
        formatter = SARIFFormatter()
        return formatter.format(result)

    def export_sbom(self) -> str:
        generator = SBOMGenerator(self.project_path)
        return generator.generate_cyclonedx()


class _DashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self: Any) -> None:
        server_ref = _dashboard_server
        if server_ref is None:
            self.send_error(500)
            return

        if self.path == "/" or self.path == "/index.html":
            dashboard_path = Path(__file__).parent.parent.parent.parent / ".gitguard-dashboard" / "index.html"
            if not dashboard_path.exists():
                dashboard_path = Path(__file__).parent.parent / "index.html"
            try:
                content = dashboard_path.read_text()
            except OSError:
                content = "<h1>GitGuard Dashboard</h1><p>index.html not found</p>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(content.encode())
        elif self.path == "/api/results":
            results = server_ref.get_results()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(results).encode())
        elif self.path == "/api/export/sarif":
            content = server_ref.export_sarif()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Disposition", "attachment; filename=gitguard.sarif")
            self.end_headers()
            self.wfile.write(content.encode())
        elif self.path == "/api/export/sbom":
            content = server_ref.export_sbom()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Disposition", "attachment; filename=sbom.json")
            self.end_headers()
            self.wfile.write(content.encode())
        else:
            self.send_error(404)

    def do_POST(self: Any) -> None:
        server_ref = _dashboard_server
        if server_ref is None:
            self.send_error(500)
            return

        if self.path == "/api/scan":
            results = server_ref.scan()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(results).encode())
        else:
            self.send_error(404)

    def log_message(self: Any, format: str, *args: Any) -> None:
        pass
