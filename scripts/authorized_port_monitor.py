#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import signal
import socket
import ssl
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


DENY_SUFFIXES = (
    ".ngrok.io",
)

DENY_HOSTS = {
    "localhost",
    "127.0.0.1",
    "::1",
}

TEXT_RESULT_SERVICES = {
    "http",
    "https",
    "ssh",
    "smtp",
    "rdp",
    "mysql",
    "postgres",
    "redis",
    "unknown",
}

HTTP_PORT_HINTS = {80, 8080, 8000, 8008, 8888}
HTTPS_PORT_HINTS = {443, 8443, 9443}
MAX_WORKERS = 4


@dataclass
class ScanTarget:
    label: str
    host: str


class ProgressStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> dict:
        if not self.path.exists():
            return {}
        with self.path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def save(self, payload: dict) -> None:
        tmp_path = self.path.with_suffix(".tmp")
        with tmp_path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        tmp_path.replace(self.path)


class ResultWriter:
    def __init__(self, results_dir: Path) -> None:
        self.results_dir = results_dir
        self.results_dir.mkdir(parents=True, exist_ok=True)

    def write_result(self, service: str, payload: dict) -> None:
        line = self._format_line(payload)
        file_name = f"{service}.txt" if service in TEXT_RESULT_SERVICES else "unknown.txt"
        with (self.results_dir / file_name).open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

        with (self.results_dir / "all-open.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True) + "\n")

    def write_summary(self, summary: dict) -> None:
        with (self.results_dir / "summary.json").open("w", encoding="utf-8") as handle:
            json.dump(summary, handle, indent=2, sort_keys=True)
            handle.write("\n")

        lines = [
            f"更新时间: {summary['updated_at']}",
            f"是否完成: {summary['completed']}",
            f"当前目标: {summary['current_target']}",
            f"下一个端口: {summary['next_port']}",
            f"已处理端口数: {summary['processed_ports']}",
            f"发现开放端口数: {summary['open_ports_found']}",
            f"已完成批次数: {summary['batches_completed']}",
            "服务统计:",
        ]
        for service, count in sorted(summary["service_counts"].items()):
            lines.append(f"  {service}: {count}")
        with (self.results_dir / "summary.txt").open("w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")

    @staticmethod
    def _format_line(payload: dict) -> str:
        parts = [
            f"target={payload['target']}",
            f"host={payload['host']}",
            f"port={payload['port']}",
            f"service={payload['service']}",
        ]
        banner = payload.get("banner") or ""
        if banner:
            parts.append(f"banner={banner}")
        detail = payload.get("detail") or ""
        if detail:
            parts.append(f"detail={detail}")
        return " | ".join(parts)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="支持断点续跑的授权端口巡检工具。")
    parser.add_argument("--targets-file", required=True)
    parser.add_argument("--targets-input", default="")
    parser.add_argument("--port-start", type=int, required=True)
    parser.add_argument("--port-end", type=int, required=True)
    parser.add_argument("--duration-minutes", type=float, required=True)
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--connect-timeout-ms", type=int, default=700)
    parser.add_argument("--inter-probe-delay-ms", type=int, default=100)
    parser.add_argument("--batch-pause-ms", type=int, default=500)
    parser.add_argument("--max-workers", type=int, default=1)
    parser.add_argument("--results-dir", required=True)
    parser.add_argument("--state-dir", required=True)
    return parser.parse_args()


def normalize_host(raw: str) -> str:
    host = raw.strip()
    if not host or host.startswith("#"):
        return ""
    return host


def validate_host(host: str) -> None:
    lowered = host.lower()
    if lowered in DENY_HOSTS:
        raise ValueError(f"Target '{host}' is not allowed.")
    if lowered.endswith(DENY_SUFFIXES):
        raise ValueError(f"Target '{host}' is not allowed.")


def expand_target(raw: str) -> Iterable[ScanTarget]:
    value = normalize_host(raw)
    if not value:
        return []

    validate_host(value)

    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return [ScanTarget(label=value, host=value)]

    expanded: list[ScanTarget] = []
    for ip in network.hosts():
        host = str(ip)
        validate_host(host)
        expanded.append(ScanTarget(label=value, host=host))
    return expanded


def split_targets_input(raw: str) -> list[str]:
    normalized = raw.replace(",", "\n").replace(" ", "\n").replace("\t", "\n")
    return [item for item in normalized.splitlines() if item.strip()]


def load_targets(targets_file: Path, targets_input: str) -> list[ScanTarget]:
    targets: list[ScanTarget] = []
    if targets_input.strip():
        for item in split_targets_input(targets_input):
            targets.extend(expand_target(item))
    else:
        with targets_file.open("r", encoding="utf-8") as handle:
            for line in handle:
                targets.extend(expand_target(line))
    if not targets:
        raise ValueError("目标文件中没有可用目标。")
    return targets


def clamp_port(port: int, port_start: int, port_end: int) -> int:
    return max(port_start, min(port, port_end))


def detect_service(host: str, port: int, timeout_s: float) -> tuple[str, str, str]:
    for detector in (
        detect_http_like,
        detect_ssh,
        detect_smtp,
        detect_redis,
        detect_mysql,
        detect_postgres,
        detect_rdp,
    ):
        service, banner, detail = detector(host, port, timeout_s)
        if service:
            return service, banner, detail
    return "unknown", "", ""


def detect_http_like(host: str, port: int, timeout_s: float) -> tuple[str, str, str]:
    if port in HTTP_PORT_HINTS:
        response = try_http(host, port, timeout_s, tls=False)
        if response:
            return "http", response[0], response[1]

    if port in HTTPS_PORT_HINTS:
        response = try_http(host, port, timeout_s, tls=True)
        if response:
            return "https", response[0], response[1]

    response = try_http(host, port, timeout_s, tls=False)
    if response:
        return "http", response[0], response[1]

    response = try_http(host, port, timeout_s, tls=True)
    if response:
        return "https", response[0], response[1]

    return "", "", ""


def try_http(host: str, port: int, timeout_s: float, tls: bool) -> tuple[str, str] | None:
    request = (
        f"HEAD / HTTP/1.0\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: authorized-port-monitor/1.0\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("ascii", errors="ignore")
    try:
        with socket.create_connection((host, port), timeout=timeout_s) as sock:
            sock.settimeout(timeout_s)
            wrapped = sock
            if tls:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                wrapped = context.wrap_socket(sock, server_hostname=host)
            wrapped.sendall(request)
            data = wrapped.recv(512)
    except Exception:
        return None

    text = sanitize_banner(data)
    if text.startswith("HTTP/"):
        first_line = text.splitlines()[0]
        return first_line, first_line
    return None


def detect_ssh(host: str, port: int, timeout_s: float) -> tuple[str, str, str]:
    banner = read_banner(host, port, timeout_s)
    if banner.startswith("SSH-"):
        return "ssh", banner, ""
    return "", "", ""


def detect_smtp(host: str, port: int, timeout_s: float) -> tuple[str, str, str]:
    banner = read_banner(host, port, timeout_s)
    if banner.startswith("220") and "smtp" in banner.lower():
        return "smtp", banner, ""
    return "", "", ""


def detect_redis(host: str, port: int, timeout_s: float) -> tuple[str, str, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout_s) as sock:
            sock.settimeout(timeout_s)
            sock.sendall(b"PING\r\n")
            data = sock.recv(256)
    except Exception:
        return "", "", ""
    banner = sanitize_banner(data)
    if banner.startswith("+PONG") or "redis" in banner.lower():
        return "redis", banner, ""
    return "", "", ""


def detect_mysql(host: str, port: int, timeout_s: float) -> tuple[str, str, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout_s) as sock:
            sock.settimeout(timeout_s)
            data = sock.recv(256)
    except Exception:
        return "", "", ""
    banner = sanitize_banner(data)
    if "mysql_native_password" in banner.lower() or "mariadb" in banner.lower():
        return "mysql", banner, ""
    return "", "", ""


def detect_postgres(host: str, port: int, timeout_s: float) -> tuple[str, str, str]:
    message = b"\x00\x00\x00\x08\x04\xd2\x16\x2f"
    try:
        with socket.create_connection((host, port), timeout=timeout_s) as sock:
            sock.settimeout(timeout_s)
            sock.sendall(message)
            data = sock.recv(256)
    except Exception:
        return "", "", ""
    banner = sanitize_banner(data)
    if banner.startswith("N") or "postgres" in banner.lower():
        return "postgres", banner, ""
    return "", "", ""


def detect_rdp(host: str, port: int, timeout_s: float) -> tuple[str, str, str]:
    probe = bytes.fromhex("030000130ee000000000000100080003000000")
    try:
        with socket.create_connection((host, port), timeout=timeout_s) as sock:
            sock.settimeout(timeout_s)
            sock.sendall(probe)
            data = sock.recv(256)
    except Exception:
        return "", "", ""
    if data.startswith(b"\x03\x00"):
        return "rdp", sanitize_banner(data), ""
    return "", "", ""


def read_banner(host: str, port: int, timeout_s: float) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout_s) as sock:
            sock.settimeout(timeout_s)
            data = sock.recv(256)
    except Exception:
        return ""
    return sanitize_banner(data)


def sanitize_banner(data: bytes) -> str:
    if not data:
        return ""
    text = data.decode("utf-8", errors="replace")
    text = text.replace("\r", "\\r").replace("\n", "\\n")
    return text[:200]


def port_open(host: str, port: int, timeout_s: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            return True
    except Exception:
        return False


def scan_port(target: ScanTarget, port: int, timeout_s: float) -> dict | None:
    if not port_open(target.host, port, timeout_s):
        return None

    service, banner, detail = detect_service(target.host, port, timeout_s)
    return {
        "target": target.label,
        "host": target.host,
        "port": port,
        "service": service,
        "banner": banner,
        "detail": detail,
        "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def default_progress(port_start: int) -> dict:
    return {
        "target_index": 0,
        "next_port": port_start,
        "port_start": port_start,
        "port_end": port_start,
        "processed_ports": 0,
        "open_ports_found": 0,
        "service_counts": {},
        "batches_completed": 0,
        "completed": False,
        "updated_at": None,
    }


def update_summary(writer: ResultWriter, state: dict, targets: list[ScanTarget]) -> None:
    current_target = "done"
    if state["target_index"] < len(targets):
        current_target = targets[state["target_index"]].label

    summary = {
        "updated_at": state["updated_at"],
        "completed": state["completed"],
        "current_target": current_target,
        "next_port": state["next_port"],
        "processed_ports": state["processed_ports"],
        "open_ports_found": state["open_ports_found"],
        "batches_completed": state["batches_completed"],
        "service_counts": state["service_counts"],
    }
    writer.write_summary(summary)


def save_state(progress_store: ProgressStore, writer: ResultWriter, state: dict, targets: list[ScanTarget]) -> None:
    state["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    progress_store.save(state)
    update_summary(writer, state, targets)


def process_batch(
    target: ScanTarget,
    ports: list[int],
    timeout_s: float,
    max_workers: int,
    inter_probe_delay_s: float,
) -> tuple[int, list[dict]]:
    results: list[dict] = []

    if max_workers == 1:
        processed = 0
        for port in ports:
            payload = scan_port(target, port, timeout_s)
            processed += 1
            if payload:
                results.append(payload)
            if inter_probe_delay_s > 0:
                time.sleep(inter_probe_delay_s)
        return processed, results

    future_map: dict[concurrent.futures.Future, int] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        for port in ports:
            future = executor.submit(scan_port, target, port, timeout_s)
            future_map[future] = port
            if inter_probe_delay_s > 0:
                time.sleep(inter_probe_delay_s)

        for future in concurrent.futures.as_completed(future_map):
            payload = future.result()
            if payload:
                results.append(payload)

    results.sort(key=lambda item: item["port"])
    return len(ports), results


def main() -> int:
    args = parse_args()

    if not 0 <= args.port_start <= 65535 or not 0 <= args.port_end <= 65535:
        raise ValueError("端口必须在 0-65535 范围内。")
    if args.port_start > args.port_end:
        raise ValueError("port-start 必须小于或等于 port-end。")
    if args.duration_minutes <= 0:
        raise ValueError("duration-minutes 必须大于 0。")
    if args.batch_size <= 0:
        raise ValueError("batch-size 必须大于 0。")
    if args.connect_timeout_ms <= 0:
        raise ValueError("connect-timeout-ms 必须大于 0。")
    if args.inter_probe_delay_ms < 0 or args.batch_pause_ms < 0:
        raise ValueError("延迟参数不能小于 0。")
    if not 1 <= args.max_workers <= MAX_WORKERS:
        raise ValueError(f"max-workers 必须在 1 到 {MAX_WORKERS} 之间。")

    targets = load_targets(Path(args.targets_file), args.targets_input)
    writer = ResultWriter(Path(args.results_dir))
    progress_store = ProgressStore(Path(args.state_dir) / "progress.json")
    progress = default_progress(args.port_start)
    progress.update(progress_store.load())

    progress["port_start"] = args.port_start
    progress["port_end"] = args.port_end
    progress["target_index"] = min(max(int(progress.get("target_index", 0)), 0), len(targets) - 1)
    progress["next_port"] = clamp_port(int(progress.get("next_port", args.port_start)), args.port_start, args.port_end)
    progress["processed_ports"] = int(progress.get("processed_ports", 0))
    progress["open_ports_found"] = int(progress.get("open_ports_found", 0))
    progress["batches_completed"] = int(progress.get("batches_completed", 0))
    progress["service_counts"] = dict(progress.get("service_counts", {}))
    progress["completed"] = False

    deadline = time.time() + args.duration_minutes * 60
    timeout_s = args.connect_timeout_ms / 1000.0
    inter_probe_delay_s = args.inter_probe_delay_ms / 1000.0
    batch_pause_s = args.batch_pause_ms / 1000.0
    stop_flag = {"value": False}

    def request_stop(_signum: int, _frame: object) -> None:
        stop_flag["value"] = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    def should_stop() -> bool:
        return stop_flag["value"] or time.time() >= deadline

    total_targets = len(targets)

    while progress["target_index"] < total_targets:
        if should_stop():
            break

        target = targets[progress["target_index"]]
        current_port = progress["next_port"]
        remaining_ports = args.port_end - current_port + 1
        batch_count = min(args.batch_size, remaining_ports)
        ports = list(range(current_port, current_port + batch_count))

        processed_count, results = process_batch(
            target=target,
            ports=ports,
            timeout_s=timeout_s,
            max_workers=args.max_workers,
            inter_probe_delay_s=inter_probe_delay_s,
        )

        for payload in results:
            writer.write_result(payload["service"], payload)
            progress["open_ports_found"] += 1
            service = payload["service"]
            progress["service_counts"][service] = int(progress["service_counts"].get(service, 0)) + 1

        progress["processed_ports"] += processed_count
        progress["batches_completed"] += 1
        progress["next_port"] = current_port + processed_count

        if progress["next_port"] > args.port_end:
            progress["target_index"] += 1
            progress["next_port"] = args.port_start

        save_state(progress_store, writer, progress, targets)

        if should_stop():
            break

        if batch_pause_s > 0:
            time.sleep(batch_pause_s)

    progress["completed"] = progress["target_index"] >= total_targets
    save_state(progress_store, writer, progress, targets)

    if progress["completed"]:
        print("已完成所有目标与端口范围的巡检。")
    else:
        current_target = targets[progress["target_index"]].label if progress["target_index"] < total_targets else "done"
        print(
            f"本次暂停于 target_index={progress['target_index']} "
            f"target={current_target} next_port={progress['next_port']}"
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"错误: {exc}", file=sys.stderr)
        raise
