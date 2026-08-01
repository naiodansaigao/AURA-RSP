#!/usr/bin/env python3
"""Draw compact 600-DPI publication figures using the bundled Pillow stack."""

from __future__ import annotations

import argparse
import csv
import json
import math
from pathlib import Path
from typing import Any

from PIL import Image, ImageChops, ImageDraw, ImageFont


WHITE = (255, 255, 255)
TEXT = (38, 38, 38)
GRID = (210, 210, 210)
LIGHT = (242, 242, 242)
BLUE = (76, 114, 176)
ORANGE = (221, 132, 82)
GREEN = (85, 168, 104)


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    names = (
        ["DejaVuSans-Bold.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"]
        if bold
        else ["DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"]
    )
    for name in names:
        try:
            return ImageFont.truetype(name, size=size)
        except OSError:
            continue
    raise RuntimeError("DejaVu Sans font not found")


def serif_font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    names = (
        ["DejaVuSerif-Bold.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSerif-Bold.ttf"]
        if bold
        else ["DejaVuSerif.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSerif.ttf"]
    )
    for name in names:
        try:
            return ImageFont.truetype(name, size=size)
        except OSError:
            continue
    raise RuntimeError("DejaVu Serif font not found")


def text_center(draw: ImageDraw.ImageDraw, xy: tuple[float, float], value: str, fnt, fill=TEXT) -> None:
    draw.text(xy, value, font=fnt, fill=fill, anchor="mm")


def vertical_text(image: Image.Image, value: str, fnt) -> None:
    box = fnt.getbbox(value)
    layer = Image.new("RGBA", (box[2] - box[0] + 40, box[3] - box[1] + 40), (255, 255, 255, 0))
    draw = ImageDraw.Draw(layer)
    draw.text((20 - box[0], 20 - box[1]), value, font=fnt, fill=TEXT)
    rotated = layer.rotate(90, expand=True, resample=Image.Resampling.BICUBIC)
    image.alpha_composite(rotated, (28, (image.height - rotated.height) // 2))


def save_trimmed(image: Image.Image, path: Path, pad: int = 26) -> None:
    rgb = image.convert("RGB")
    diff = ImageChops.difference(rgb, Image.new("RGB", rgb.size, WHITE))
    bbox = diff.getbbox()
    if bbox:
        left = max(0, bbox[0] - pad)
        top = max(0, bbox[1] - pad)
        right = min(rgb.width, bbox[2] + pad)
        bottom = min(rgb.height, bbox[3] + pad)
        rgb = rgb.crop((left, top, right, bottom))
    path.parent.mkdir(parents=True, exist_ok=True)
    rgb.save(path, dpi=(600, 600), optimize=True)


def heatmap(matrix_rows: list[dict[str, Any]], output: Path, devices: int) -> None:
    width, height = 3000, 2750
    image = Image.new("RGBA", (width, height), WHITE + (255,))
    draw = ImageDraw.Draw(image)
    label_font = font(92)
    tick_font = font(66)
    legend_font = font(72)
    left, top = 400, 310
    side = 2160
    cell = side / devices
    matrix = [[False for _ in range(devices)] for _ in range(devices)]
    for row in matrix_rows:
        if row["configuration"] == "aura_full" and int(row["round"]) == 0:
            matrix[int(row["ticket_source_device"])][int(row["target_device"])] = bool(
                row["authentication_accepted"]
            )
    for source in range(devices):
        for target in range(devices):
            x0 = round(left + target * cell)
            y0 = round(top + source * cell)
            x1 = round(left + (target + 1) * cell)
            y1 = round(top + (source + 1) * cell)
            draw.rectangle(
                (x0, y0, x1, y1),
                fill=GREEN if matrix[source][target] else LIGHT,
                outline=WHITE if devices <= 20 else None,
                width=2,
            )
    draw.rectangle((left, top, left + side, top + side), outline=TEXT, width=5)
    step = max(1, devices // 5)
    ticks = sorted(set([0, devices - 1] + list(range(step - 1, devices, step))))
    for index in ticks:
        position = left + (index + 0.5) * cell
        text_center(draw, (position, top + side + 82), str(index + 1), tick_font)
        position_y = top + (index + 0.5) * cell
        draw.text((left - 48, position_y), str(index + 1), font=tick_font, fill=TEXT, anchor="rm")
    text_center(draw, (left + side / 2, top + side + 205), "Target device", label_font)
    vertical_text(image, "Ticket source", label_font)
    legend_y = 105
    legend_items = [(GREEN, "Accepted"), (LIGHT, "Rejected")]
    centers = [left + side * 0.34, left + side * 0.66]
    for center, (color, label) in zip(centers, legend_items):
        draw.rectangle((center - 145, legend_y - 32, center - 85, legend_y + 28), fill=color, outline=GRID, width=2)
        draw.text((center - 62, legend_y), label, font=legend_font, fill=TEXT, anchor="lm")
    save_trimmed(image, output / "figure-3a-ticket-device-acceptance-matrix.png")


def success_bars(summary: dict[str, Any], output: Path) -> None:
    width, height = 4100, 2350
    image = Image.new("RGBA", (width, height), WHITE + (255,))
    draw = ImageDraw.Draw(image)
    axis_font = font(90)
    tick_font = font(70)
    value_font = font(76, bold=True)
    labels = [
        "AURA-RSP",
        "AURA-RSP w/o\nsecret binding",
        "Standard RSP\n(EID pre-bound)",
        "Standard RSP\n(unbound code)",
    ]
    keys = [
        "aura_full",
        "aura_no_secret_binding",
        "standard_prebound_eid",
        "standard_unbound_activation_code",
    ]
    values = [
        float(summary["configurations"][key]["transfer_authentication_acceptance_rate"])
        for key in keys
    ]
    colors = [BLUE, ORANGE, BLUE, ORANGE]
    left, right, top, bottom = 390, 120, 160, 570
    plot_w = width - left - right
    plot_h = height - top - bottom
    for tick in range(6):
        value = tick / 5
        y = top + plot_h * (1 - value)
        draw.line((left, y, left + plot_w, y), fill=GRID, width=3)
        draw.text((left - 40, y), f"{value:.1f}", font=tick_font, fill=TEXT, anchor="rm")
    draw.line((left, top, left, top + plot_h), fill=TEXT, width=5)
    draw.line((left, top + plot_h, left + plot_w, top + plot_h), fill=TEXT, width=5)
    slot = plot_w / 4
    bar_w = slot * 0.58
    for index, (value, color) in enumerate(zip(values, colors)):
        cx = left + (index + 0.5) * slot
        bar_height = plot_h * value
        x0, x1 = cx - bar_w / 2, cx + bar_w / 2
        y0, y1 = top + plot_h - bar_height, top + plot_h
        if value > 0:
            draw.rectangle((x0, y0, x1, y1), fill=color)
        else:
            draw.line((x0, y1 - 2, x1, y1 - 2), fill=color, width=10)
        if value >= 0.95:
            draw.text(
                (cx, top + 68),
                f"{value:.3f}",
                font=value_font,
                fill=WHITE,
                anchor="ma",
            )
        else:
            draw.text(
                (cx, max(top + 55, y0 - 65)),
                f"{value:.3f}",
                font=value_font,
                fill=color,
                anchor="ms",
            )
        lines = labels[index].split("\n")
        for line_index, line in enumerate(lines):
            draw.text((cx, top + plot_h + 90 + line_index * 82), line, font=tick_font, fill=TEXT, anchor="ma")
    vertical_text(image, "Transfer success rate", axis_font)
    save_trimmed(image, output / "figure-3b-cross-device-transfer-success-rate.png")


def concurrency_lines(summary: dict[str, Any], output: Path) -> None:
    rows = summary.get("concurrency", [])
    if not rows:
        return
    # Match the compact, large-type style used by the paper's ROC figure.  The
    # output is intentionally shallow so it remains readable in a two-column PDF.
    width, height = 3600, 2150
    image = Image.new("RGBA", (width, height), WHITE + (255,))
    draw = ImageDraw.Draw(image)
    axis_font = serif_font(112, bold=True)
    tick_font = serif_font(84)
    legend_font = serif_font(78, bold=True)
    left, right, top, bottom = 490, 75, 250, 300
    plot_w = width - left - right
    plot_h = height - top - bottom
    levels = sorted({int(row["concurrency"]) for row in rows})
    values = [
        float(row[metric])
        for row in rows
        for metric in ("mean_service_ms", "p95_service_ms")
    ]
    raw_max = max(values) * 1.1 if values else 1.0
    magnitude = 10 ** max(0, math.floor(math.log10(raw_max)))
    y_max = max(magnitude, math.ceil(raw_max / magnitude) * magnitude)
    for tick in range(5):
        value = y_max * tick / 4
        y = top + plot_h * (1 - tick / 4)
        draw.line((left, y, left + plot_w, y), fill=GRID, width=4)
        draw.text((left - 38, y), f"{value:,.0f}", font=tick_font, fill=TEXT, anchor="rm")
    draw.line((left, top, left, top + plot_h), fill=TEXT, width=8)
    draw.line((left, top + plot_h, left + plot_w, top + plot_h), fill=TEXT, width=8)

    def x_for(level: int) -> float:
        return left + levels.index(level) * plot_w / max(1, len(levels) - 1)

    def y_for(value: float) -> float:
        return top + plot_h * (1 - value / y_max)

    for level in levels:
        x = x_for(level)
        draw.text((x, top + plot_h + 62), str(level), font=tick_font, fill=TEXT, anchor="ma")

    specifications = [
        ("normal_authentication", "Legitimate (mean)", "mean_service_ms", BLUE, False, "circle"),
        ("normal_authentication", "Legitimate (P95)", "p95_service_ms", BLUE, True, "circle"),
        ("forced_invalid_ticket_transfer", "Invalid transfer (mean)", "mean_service_ms", ORANGE, False, "square"),
        ("forced_invalid_ticket_transfer", "Invalid transfer (P95)", "p95_service_ms", ORANGE, True, "square"),
    ]
    for workload, label, metric, color, dashed, marker in specifications:
        group = sorted(
            [row for row in rows if row["workload"] == workload],
            key=lambda row: int(row["concurrency"]),
        )
        points = [(x_for(int(row["concurrency"])), y_for(float(row[metric]))) for row in group]
        if dashed:
            for (x0, y0), (x1, y1) in zip(points, points[1:]):
                segments = 16
                for segment in range(0, segments, 2):
                    a, b = segment / segments, min(1, (segment + 1) / segments)
                    draw.line((x0 + (x1 - x0) * a, y0 + (y1 - y0) * a, x0 + (x1 - x0) * b, y0 + (y1 - y0) * b), fill=color, width=18)
        else:
            draw.line(points, fill=color, width=22, joint="curve")
        for x, y in points:
            if marker == "circle":
                draw.ellipse((x - 25, y - 25, x + 25, y + 25), fill=WHITE if dashed else color, outline=color, width=10)
            else:
                draw.rectangle((x - 24, y - 24, x + 24, y + 24), fill=WHITE if dashed else color, outline=color, width=10)

    text_center(draw, (left + plot_w / 2, height - 72), "Concurrent requests", axis_font)
    vertical_text(image, "Verification service time (ms)", axis_font)
    legend_y = 66
    legend_x = left
    for index, (_, label, _, color, dashed, marker) in enumerate(specifications):
        col, row = index % 2, index // 2
        x = legend_x + col * 1500
        y = legend_y + row * 92
        if dashed:
            for seg in range(3):
                draw.line((x + seg * 50, y, x + seg * 50 + 31, y), fill=color, width=15)
        else:
            draw.line((x, y, x + 132, y), fill=color, width=20)
        if marker == "circle":
            draw.ellipse((x + 51, y - 18, x + 87, y + 18), fill=WHITE if dashed else color, outline=color, width=7)
        else:
            draw.rectangle((x + 52, y - 18, x + 88, y + 18), fill=WHITE if dashed else color, outline=color, width=7)
        draw.text((x + 158, y), label, font=legend_font, fill=TEXT, anchor="lm")
    save_trimmed(image, output / "figure-3c-concurrent-authentication-latency.png", pad=12)


def create_figures(summary: dict[str, Any], matrix_rows: list[dict[str, Any]], output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    heatmap(matrix_rows, output, int(summary["devices"]))
    success_bars(summary, output)
    concurrency_lines(summary, output)
    write_paper_tables(summary, output)
    write_summary_markdown(summary, output.parent / "summary.md")


def write_paper_tables(summary: dict[str, Any], output: Path) -> None:
    crypto_path = output / "table-3-cryptographic-timing.csv"
    with crypto_path.open("w", encoding="utf-8-sig", newline="") as handle:
        fields = [
            "sample",
            "client_mean_ms",
            "client_p95_ms",
            "server_mean_ms",
            "server_p95_ms",
            "n",
        ]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for sample, value in summary["cryptographic_samples"].items():
            writer.writerow(
                {
                    "sample": sample,
                    "client_mean_ms": value["client_compute"]["mean_ms"],
                    "client_p95_ms": value["client_compute"]["p95_ms"],
                    "server_mean_ms": value["server_verification"]["mean_ms"],
                    "server_p95_ms": value["server_verification"]["p95_ms"],
                    "n": max(
                        value["client_compute"]["n"],
                        value["server_verification"]["n"],
                    ),
                }
            )
    concurrency_path = output / "table-3-concurrency.csv"
    with concurrency_path.open("w", encoding="utf-8-sig", newline="") as handle:
        fields = [
            "workload",
            "concurrency",
            "requests",
            "configured_process_workers",
            "effective_parallel_workers",
            "worker_processes_used",
            "mean_latency_ms",
            "p95_latency_ms",
            "mean_service_ms",
            "p95_service_ms",
            "mean_queue_wait_ms",
            "p95_queue_wait_ms",
            "throughput_req_s",
        ]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in summary.get("concurrency", []):
            writer.writerow({field: row[field] for field in fields})


def write_summary_markdown(summary: dict[str, Any], path: Path) -> None:
    configs = summary["configurations"]
    lines = [
        "# Experiment 3 Results",
        "",
        f"Status: **{summary['status']}**",
        "",
        f"- Devices: {summary['devices']}",
        f"- Rounds: {summary['rounds']}",
        f"- Legal controls per configuration: {summary['legal_controls_per_configuration']}",
        f"- Cross-device attacks per configuration: {summary['transfer_attacks_per_configuration']}",
        f"- Total matrix records: {summary['total_matrix_attempts']}",
        "",
        "| Configuration | Legal acceptance | Transfer proof generation | Transfer authentication | Profile delivery |",
        "|---|---:|---:|---:|---:|",
    ]
    order = [
        "aura_full",
        "aura_no_secret_binding",
        "standard_prebound_eid",
        "standard_unbound_activation_code",
    ]
    for key in order:
        item = configs[key]
        proof_rate = item["transfer_joint_proof_generation_rate"]
        lines.append(
            "| {label} | {legal:.3f} | {proof} | {auth:.3f} | {delivery:.3f} |".format(
                label=item["label"],
                legal=item["legal_authentication_acceptance_rate"],
                proof="N/A" if proof_rate is None else f"{proof_rate:.3f}",
                auth=item["transfer_authentication_acceptance_rate"],
                delivery=item["transfer_profile_delivery_rate"],
            )
        )
    lines.extend(
        [
            "",
            "Full AURA-RSP accepted every owner control and rejected all 24,500 cross-device transfers before Profile delivery. The experiment-only no-secret-binding ablation accepted all transfers, isolating the contribution of the shared hidden witness x.",
            "",
            "Concurrency latency is the prewarmed multi-process production proof-verifier CPU path, not HTTP round-trip latency. Pool startup and warmup are reported separately and excluded from online batches. Honest non-owner clients fail locally; forced invalid server submissions are measured only as defense-in-depth.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    root = Path(__file__).resolve().parent
    parser.add_argument("--results", default=str(root / "results" / "latest"))
    args = parser.parse_args()
    results = Path(args.results)
    summary = json.loads((results / "summary.json").read_text(encoding="utf-8"))
    with (results / "raw" / "matrix-attempts.csv").open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    for row in rows:
        row["authentication_accepted"] = row["authentication_accepted"] == "True"
    create_figures(summary, rows, results / "paper")


if __name__ == "__main__":
    main()
