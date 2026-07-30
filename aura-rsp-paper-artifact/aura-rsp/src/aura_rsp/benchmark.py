from __future__ import annotations

import argparse
import hashlib
import json
import platform
import statistics
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

from .codec import load_json, save_json
from .ticket import issue_ticket


ROOT = Path(__file__).resolve().parents[2]
WORKSPACE = ROOT.parent
BASELINE = WORKSPACE / "rsp-baseline"


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def describe(values: list[float]) -> dict:
    return {
        "n": len(values),
        "mean_ms": round(statistics.mean(values), 3),
        "median_ms": round(statistics.median(values), 3),
        "stdev_ms": round(statistics.stdev(values), 3) if len(values) > 1 else 0,
        "min_ms": round(min(values), 3),
        "max_ms": round(max(values), 3),
        "p95_ms": round(percentile(values, 0.95), 3),
    }


def run_timed(command: list[str], cwd: Path) -> float:
    started = time.perf_counter()
    completed = subprocess.run(
        command,
        cwd=cwd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        timeout=240,
    )
    elapsed_ms = (time.perf_counter() - started) * 1000
    if completed.returncode != 0:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            + completed.stderr[-4000:]
        )
    return elapsed_ms


def run_benchmark(iterations: int, warmups: int) -> dict:
    profile = (ROOT / "runtime" / "profile.der").read_bytes()
    baseline_profile = (
        BASELINE
        / "third_party"
        / "pysim"
        / "smdpp-data"
        / "upp"
        / "TS48V2-SAIP2-1-NOBERTLV-UNIQUE.der"
    ).read_bytes()
    if profile != baseline_profile:
        raise RuntimeError("AURA and standard RSP are not using the same profile")

    baseline_cmd = ["bash", "scripts/run_software_demo.sh"]
    aura_cmd = ["bash", "scripts/run_demo.sh", "--reuse-ticket"]
    for _ in range(warmups):
        run_timed(baseline_cmd, BASELINE)
        issue_ticket(ROOT)
        run_timed(aura_cmd, ROOT)

    baseline_wall: list[float] = []
    aura_wall: list[float] = []
    aura_internal: list[float] = []
    proof_generate: list[float] = []
    proof_verify: list[float] = []
    relay_ms: list[float] = []
    for _ in range(iterations):
        baseline_wall.append(run_timed(baseline_cmd, BASELINE))
        issue_ticket(ROOT)
        aura_wall.append(run_timed(aura_cmd, ROOT))
        run_report = load_json(ROOT / "runtime" / "last-run.json")
        metrics = run_report["metrics"]
        aura_internal.append(float(metrics["total_ms"]))
        proof_generate.append(float(metrics["proof_generate_ms"]))
        proof_verify.append(float(metrics["proof_verify_ms"]))
        relay_ms.append(float(metrics["relay_accumulated_ms"]))

    baseline_stats = describe(baseline_wall)
    aura_stats = describe(aura_wall)
    aura_internal_stats = describe(aura_internal)
    factor = aura_stats["mean_ms"] / baseline_stats["mean_ms"]
    delta = aura_stats["mean_ms"] - baseline_stats["mean_ms"]
    report = {
        "status": "AURA_BASELINE_BENCHMARK_PASS",
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "iterations": iterations,
        "warmups": warmups,
        "scope": {
            "standard": "run_software_demo.sh: standard ES9+ download, BPP decode, install notification, artifact checks",
            "aura": "run_demo.sh --reuse-ticket: AURA online download, install notification, artifact checks; offline ticket issuance excluded",
            "service_startup_excluded": True,
            "tls_transport_included": True,
            "same_profile": True,
            "profile_bytes": len(profile),
            "profile_sha256": hashlib.sha256(profile).hexdigest(),
        },
        "host": {
            "platform": platform.platform(),
            "python": platform.python_version(),
        },
        "standard_rsp_wall": baseline_stats,
        "aura_rsp_wall": aura_stats,
        "aura_internal_online": aura_internal_stats,
        "aura_proof_generate": describe(proof_generate),
        "aura_proof_verify": describe(proof_verify),
        "aura_relay_accumulated": describe(relay_ms),
        "comparison": {
            "aura_minus_standard_mean_ms": round(delta, 3),
            "aura_over_standard_factor": round(factor, 3),
            "aura_overhead_percent": round((factor - 1) * 100, 2),
        },
        "raw_ms": {
            "standard_rsp_wall": [round(x, 3) for x in baseline_wall],
            "aura_rsp_wall": [round(x, 3) for x in aura_wall],
            "aura_internal_online": [round(x, 3) for x in aura_internal],
            "aura_proof_generate": [round(x, 3) for x in proof_generate],
            "aura_proof_verify": [round(x, 3) for x in proof_verify],
            "aura_relay_accumulated": [round(x, 3) for x in relay_ms],
        },
    }
    results = ROOT / "results"
    results.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    save_json(results / f"benchmark-{stamp}.json", report)
    save_json(results / "latest-benchmark.json", report)
    markdown = f"""# 标准 RSP 与 AURA-RSP 下载耗时

- 测量次数：{iterations}（预热 {warmups} 次，不计入结果）
- 同一 profile：{len(profile)} 字节，SHA-256 `{report["scope"]["profile_sha256"]}`
- 服务启动时间：不计入
- TLS、客户端进程、协议计算、下载通知和产物校验：计入
- AURA 离线票据发行：不计入

| 指标 | 标准 RSP | AURA-RSP |
|---|---:|---:|
| 平均端到端墙钟时间 | {baseline_stats["mean_ms"]:.3f} ms | {aura_stats["mean_ms"]:.3f} ms |
| 中位数 | {baseline_stats["median_ms"]:.3f} ms | {aura_stats["median_ms"]:.3f} ms |
| P95 | {baseline_stats["p95_ms"]:.3f} ms | {aura_stats["p95_ms"]:.3f} ms |
| 标准差 | {baseline_stats["stdev_ms"]:.3f} ms | {aura_stats["stdev_ms"]:.3f} ms |

AURA 平均增加 `{delta:.3f} ms`，为标准 RSP 的 `{factor:.3f}x`。

## AURA 主要开销

- 组合证明生成平均：{statistics.mean(proof_generate):.3f} ms
- 组合证明验证平均：{statistics.mean(proof_verify):.3f} ms
- 四次经过 Privacy Relay 的累计转发时间平均：{statistics.mean(relay_ms):.3f} ms

注意：`relay_ms` 包含后端处理等待时间，不能与证明验证时间直接相加；它用于表示客户端观察到的四次 PR 转发累计时长。
"""
    (results / "latest-benchmark.md").write_text(markdown, encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=10)
    parser.add_argument("--warmups", type=int, default=1)
    args = parser.parse_args()
    if args.iterations < 2:
        raise SystemExit("iterations must be at least 2")
    report = run_benchmark(args.iterations, args.warmups)
    print(json.dumps(report, indent=2, sort_keys=True))
    print(report["status"])


if __name__ == "__main__":
    main()
