"""
Assignment 11 — Audit Log.

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        # Bản ghi đang mở (đã có input, chưa có output), khóa = request_id hoặc user_id
        self._open: dict[str, dict] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Ghi câu hỏi + bấm đồng hồ bắt đầu."""
        key = request_id or user_id
        self._open[key] = {
            "timestamp": utc_now_iso(),
            "start": time.time(),
            "input": text,
        }

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Ghép với bản ghi input, tính độ trễ, đưa vào self.logs."""
        key = request_id or user_id
        opened = self._open.pop(key, None)   # lấy ra và xóa khỏi danh sách "đang mở"
        entry = {
            "request_id": request_id,
            "user_id": user_id,
            "timestamp": opened["timestamp"] if opened else utc_now_iso(),
            "input": opened["input"] if opened else None,
            "output": text,
            "blocked": blocked,
            "layer": layer,  # lớp nào chặn: rate_limiter / input_guardrail / output_guardrail / None
            "latency_ms": round((time.time() - opened["start"]) * 1000, 1) if opened else None,
        }
        self.logs.append(entry)
        return entry

    def export_json(self, filepath: str | None = None):
        """Ghi toàn bộ log ra file JSON (mặc định <repo>/outputs/audit_log.json)."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)   # tự tạo thư mục outputs/ nếu chưa có
        path.write_text(
            json.dumps(self.logs, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        return str(path)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()