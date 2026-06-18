from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class PerfMetric:
    name: str
    duration_ms: float
    details: dict[str, Any] = field(default_factory=dict)


class PerfTracker:
    """Tracks performance metrics for scanning operations."""

    def __init__(self) -> None:
        self._metrics: list[PerfMetric] = []
        self._start_times: dict[str, float] = {}

    def start(self, name: str) -> None:
        self._start_times[name] = time.perf_counter()

    def stop(self, name: str, **details: Any) -> None:
        if name in self._start_times:
            duration = (time.perf_counter() - self._start_times.pop(name)) * 1000
            self._metrics.append(PerfMetric(name=name, duration_ms=duration, details=details))

    def get_metrics(self) -> list[PerfMetric]:
        return list(self._metrics)

    def get_total_ms(self) -> float:
        return sum(m.duration_ms for m in self._metrics)

    def get_summary(self) -> dict[str, Any]:
        return {
            "total_ms": round(self.get_total_ms(), 2),
            "metrics": [
                {"name": m.name, "ms": round(m.duration_ms, 2), **m.details}
                for m in self._metrics
            ],
        }

    def print_summary(self) -> None:
        total = self.get_total_ms()
        print(f"\n{'='*50}")
        print(f"Performance Summary ({total:.1f}ms total)")
        print(f"{'='*50}")
        for m in self._metrics:
            print(f"  {m.name}: {m.duration_ms:.1f}ms")
        print(f"{'='*50}\n")


def benchmark_scan(path: str, iterations: int = 3) -> dict[str, Any]:
    from gitguard.core.scanner import SecurityScanner

    times: list[float] = []

    for _ in range(iterations):
        start = time.perf_counter()
        scanner = SecurityScanner(path)
        scanner.scan()
        times.append((time.perf_counter() - start) * 1000)

    avg_ms = sum(times) / len(times)
    min_ms = min(times)
    max_ms = max(times)

    return {
        "path": path,
        "iterations": iterations,
        "avg_ms": round(avg_ms, 2),
        "min_ms": round(min_ms, 2),
        "max_ms": round(max_ms, 2),
    }
