"""Compact 600-DPI paper figures for Experiment 4."""

from __future__ import annotations

import csv
import argparse
import json
import math
from pathlib import Path
from typing import Any

from PIL import Image, ImageChops, ImageDraw, ImageFont


WHITE = (255, 255, 255)
TEXT = (38, 38, 38)
GRID = (210, 210, 210)
BLUE = (76, 114, 176)
ORANGE = (221, 132, 82)
GREEN = (85, 168, 104)
RED = (196, 78, 82)
PURPLE = (129, 114, 179)
GRAY = (145, 145, 145)


def font(size: int, bold: bool = False):
    names = (
        ["DejaVuSerif-Bold.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSerif-Bold.ttf"]
        if bold
        else ["DejaVuSerif.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSerif.ttf"]
    )
    for name in names:
        try:
            return ImageFont.truetype(name, size=size)
        except OSError:
            pass
    raise RuntimeError("DejaVu Serif is required")


def save_trimmed(image: Image.Image, path: Path, pad: int = 18) -> None:
    rgb = image.convert("RGB")
    diff = ImageChops.difference(rgb, Image.new("RGB", rgb.size, WHITE))
    bbox = diff.getbbox()
    if bbox:
        rgb = rgb.crop(
            (
                max(0, bbox[0] - pad),
                max(0, bbox[1] - pad),
                min(rgb.width, bbox[2] + pad),
                min(rgb.height, bbox[3] + pad),
            )
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    rgb.save(path, dpi=(600, 600), optimize=True)


def nice_upper(value: float) -> float:
    if value <= 0:
        return 1.0
    magnitude = 10 ** math.floor(math.log10(value))
    normalized = value / magnitude
    for candidate in (1.0, 1.5, 2.0, 2.5, 5.0, 10.0):
        if normalized <= candidate:
            return candidate * magnitude
    return 10.0 * magnitude


def power_label(exponent: int) -> str:
    superscript = str.maketrans("-0123456789", "⁻⁰¹²³⁴⁵⁶⁷⁸⁹")
    return "10" + str(exponent).translate(superscript)


def vertical_label(image: Image.Image, text: str, fnt) -> None:
    box = fnt.getbbox(text)
    layer = Image.new("RGBA", (box[2] - box[0] + 40, box[3] - box[1] + 40), (255, 255, 255, 0))
    draw = ImageDraw.Draw(layer)
    draw.text((20 - box[0], 20 - box[1]), text, font=fnt, fill=TEXT)
    rotated = layer.rotate(90, expand=True, resample=Image.Resampling.BICUBIC)
    image.alpha_composite(rotated, (22, (image.height - rotated.height) // 2))


def axes(image: Image.Image, y_max: float, y_label: str, x_label: str, y_formatter=None):
    draw = ImageDraw.Draw(image)
    width, height = image.size
    left, right, top, bottom = 480, 80, 220, 300
    plot_w, plot_h = width - left - right, height - top - bottom
    tick_font = font(78)
    label_font = font(102, bold=True)
    for tick in range(6):
        value = y_max * tick / 5
        y = top + plot_h * (1 - tick / 5)
        draw.line((left, y, left + plot_w, y), fill=GRID, width=4)
        label = y_formatter(value) if y_formatter else f"{value:.2f}"
        draw.text((left - 35, y), label, font=tick_font, fill=TEXT, anchor="rm")
    draw.line((left, top, left, top + plot_h), fill=TEXT, width=8)
    draw.line((left, top + plot_h, left + plot_w, top + plot_h), fill=TEXT, width=8)
    draw.text((left + plot_w / 2, height - 65), x_label, font=label_font, fill=TEXT, anchor="mm")
    vertical_label(image, y_label, label_font)
    return draw, left, top, plot_w, plot_h, tick_font


def figure_4a(summary: dict[str, Any], output: Path) -> None:
    rows = summary["database_scale"]
    values = [item["latency"][kind]["p95_ms"] for item in rows for kind in ("normal", "exact_replay", "double_spend")]
    y_max = nice_upper(max(values) * 1.12) if values else 1.0
    image = Image.new("RGBA", (3600, 2200), WHITE + (255,))
    draw, left, top, plot_w, plot_h, tick_font = axes(
        image, y_max, "P95 classification time (ms)", "UsedNullifier records"
    )
    labels = {100: "10²", 1000: "10³", 10000: "10⁴", 100000: "10⁵", 1000000: "10⁶"}
    for index, item in enumerate(rows):
        x = left + index * plot_w / max(1, len(rows) - 1)
        draw.text((x, top + plot_h + 60), labels.get(item["database_size"], f"{item['database_size']:,}"), font=tick_font, fill=TEXT, anchor="ma")
    specs = [
        ("normal", "New nullifier", BLUE, "circle"),
        ("exact_replay", "Exact replay", ORANGE, "square"),
        ("double_spend", "Double spend", GREEN, "triangle"),
    ]
    for kind, label, color, marker in specs:
        points = []
        for index, item in enumerate(rows):
            x = left + index * plot_w / max(1, len(rows) - 1)
            value = item["latency"][kind]["p95_ms"]
            y = top + plot_h * (1 - value / y_max)
            points.append((x, y))
        draw.line(points, fill=color, width=22, joint="curve")
        for x, y in points:
            if marker == "circle":
                draw.ellipse((x - 24, y - 24, x + 24, y + 24), fill=color)
            elif marker == "square":
                draw.rectangle((x - 23, y - 23, x + 23, y + 23), fill=color)
            else:
                draw.polygon([(x, y - 28), (x - 27, y + 22), (x + 27, y + 22)], fill=color)
    legend_font = font(72, bold=True)
    for index, (_, label, color, _) in enumerate(specs):
        x = left + index * 980
        y = 75
        draw.line((x, y, x + 120, y), fill=color, width=20)
        draw.text((x + 150, y), label, font=legend_font, fill=TEXT, anchor="lm")
    save_trimmed(image, output / "figure-4a-nullifier-scale-latency.png")


def figure_4b(mixed_rows: list[dict[str, Any]], output: Path) -> None:
    image = Image.new("RGBA", (3400, 2250), WHITE + (255,))
    draw, left, top, plot_w, plot_h, tick_font = axes(
        image, 100.0, "Outcome share (%)", "Request type", lambda value: f"{value:.0f}"
    )
    request_types = ["normal", "exact_replay", "double_spend"]
    labels = ["Normal", "Exact replay", "Double spend"]
    categories = [
        ("Executed", BLUE),
        ("Idempotent", ORANGE),
        ("Rejected + traced", GREEN),
        ("Rejected, trace cached", PURPLE),
        ("Erroneous trace", RED),
    ]
    shares: dict[str, list[float]] = {}
    for request_type in request_types:
        rows = [row for row in mixed_rows if row["request_type"] == request_type]
        total = max(1, len(rows))
        shares[request_type] = [
            100 * sum(bool(row["business_executed"]) for row in rows) / total,
            100 * sum(row["outcome"] == "exact_replay" for row in rows) / total,
            100 * sum(row["outcome"] == "double_spend" and bool(row["trace_triggered"]) for row in rows) / total,
            100 * sum(row["outcome"] == "double_spend" and not bool(row["trace_triggered"]) for row in rows) / total,
            100 * sum(bool(row["trace_triggered"]) and request_type != "double_spend" for row in rows) / total,
        ]
    bar_width = 500
    centers = [left + plot_w * (index + 0.5) / len(request_types) for index in range(len(request_types))]
    for center, request_type, label in zip(centers, request_types, labels):
        bottom_value = 0.0
        for value, (_, color) in zip(shares[request_type], categories):
            y1 = top + plot_h * (1 - (bottom_value + value) / 100)
            y0 = top + plot_h * (1 - bottom_value / 100)
            if value > 0:
                draw.rectangle((center - bar_width / 2, y1, center + bar_width / 2, y0), fill=color, outline=WHITE, width=5)
                if value >= 7:
                    draw.text((center, (y0 + y1) / 2), f"{value:.1f}%", font=font(64, bold=True), fill=WHITE, anchor="mm")
            bottom_value += value
        draw.text((center, top + plot_h + 60), label, font=tick_font, fill=TEXT, anchor="ma")
    legend_font = font(58, bold=True)
    for index, (label, color) in enumerate(categories):
        col, row = index % 3, index // 3
        x = left + col * 930
        y = 55 + row * 75
        draw.rectangle((x, y - 20, x + 52, y + 32), fill=color)
        draw.text((x + 72, y + 5), label, font=legend_font, fill=TEXT, anchor="lm")
    save_trimmed(image, output / "figure-4b-request-outcomes.png")


def figure_4c(scale_rows: list[dict[str, Any]], output: Path) -> None:
    values = [float(row["latency_ms"]) for row in scale_rows]
    y_max = nice_upper(max(values) * 1.08) if values else 1.0
    image = Image.new("RGBA", (3600, 2200), WHITE + (255,))
    draw, left, top, plot_w, plot_h, tick_font = axes(
        image, y_max, "Classification time (ms)", "UsedNullifier records"
    )
    sizes = sorted({int(row["baseline_size"]) for row in scale_rows})
    labels = {100: "10²", 1000: "10³", 10000: "10⁴", 100000: "10⁵", 1000000: "10⁶"}
    for index, size in enumerate(sizes):
        x = left + index * plot_w / max(1, len(sizes) - 1)
        draw.text((x, top + plot_h + 60), labels.get(size, f"{size:,}"), font=tick_font, fill=TEXT, anchor="ma")
    colors = {"normal": BLUE, "exact_replay": ORANGE, "double_spend": GREEN}
    offsets = {"normal": -26, "exact_replay": 0, "double_spend": 26}
    for row in scale_rows:
        index = sizes.index(int(row["baseline_size"]))
        jitter = ((int(row["sample"]) * 37) % 41 - 20) * 1.2
        x = left + index * plot_w / max(1, len(sizes) - 1) + offsets[row["request_type"]] + jitter
        y = top + plot_h * (1 - float(row["latency_ms"]) / y_max)
        color = colors[row["request_type"]]
        draw.ellipse((x - 8, y - 8, x + 8, y + 8), fill=color + (145,))
    legend_font = font(72, bold=True)
    legend = [("New nullifier", BLUE), ("Exact replay", ORANGE), ("Double spend", GREEN)]
    for index, (label, color) in enumerate(legend):
        x = left + index * 980
        y = 75
        draw.ellipse((x, y - 13, x + 28, y + 15), fill=color)
        draw.text((x + 52, y), label, font=legend_font, fill=TEXT, anchor="lm")
    save_trimmed(image, output / "figure-4c-nullifier-latency-scatter.png")


def figure_4d(summary: dict[str, Any], output: Path) -> None:
    trace = summary["trace_breakdown"]
    items = [
        ("Transcript\nverification", trace["two_transcript_verification"]["mean_ms"], BLUE),
        ("k recovery", trace["k_recovery"]["mean_ms"], ORANGE),
        ("Ltr lookup", trace["trace_index_lookup"]["mean_ms"], GREEN),
        ("EID check", trace["eid_result_check"]["mean_ms"], PURPLE),
    ]
    positive = [max(float(value), 1e-6) for _, value, _ in items]
    lower = math.floor(math.log10(min(positive)))
    upper = math.ceil(math.log10(max(positive)))
    image = Image.new("RGBA", (3600, 2250), WHITE + (255,))
    draw = ImageDraw.Draw(image)
    left, right, top, bottom = 490, 80, 190, 360
    plot_w, plot_h = image.width - left - right, image.height - top - bottom
    tick_font = font(76)
    label_font = font(102, bold=True)
    for exponent in range(lower, upper + 1):
        y = top + plot_h * (1 - (exponent - lower) / max(1, upper - lower))
        draw.line((left, y, left + plot_w, y), fill=GRID, width=4)
        draw.text((left - 35, y), power_label(exponent), font=tick_font, fill=TEXT, anchor="rm")
    draw.line((left, top, left, top + plot_h), fill=TEXT, width=8)
    draw.line((left, top + plot_h, left + plot_w, top + plot_h), fill=TEXT, width=8)
    centers = [left + plot_w * (index + 0.5) / len(items) for index in range(len(items))]
    bar_width = 450
    for center, (label, value, color) in zip(centers, items):
        safe = max(float(value), 1e-6)
        y = top + plot_h * (1 - (math.log10(safe) - lower) / max(1, upper - lower))
        draw.rectangle((center - bar_width / 2, y, center + bar_width / 2, top + plot_h), fill=color)
        formatted = f"{value:,.3f} ms" if value >= 0.001 else f"{value * 1000:,.3f} μs"
        draw.text((center, y - 35), formatted, font=font(62, bold=True), fill=TEXT, anchor="mb")
        first, *rest = label.split("\n")
        draw.text((center, top + plot_h + 55), first, font=font(72, bold=True), fill=TEXT, anchor="ma")
        if rest:
            draw.text((center, top + plot_h + 135), rest[0], font=font(72, bold=True), fill=TEXT, anchor="ma")
    vertical_label(image, "Mean time (ms, log scale)", label_font)
    save_trimmed(image, output / "figure-4d-tracing-breakdown.png")


def create_figures(summary: dict[str, Any], scale_rows: list[dict[str, Any]], mixed_rows: list[dict[str, Any]], output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    figure_4a(summary, output)
    figure_4b(mixed_rows, output)
    figure_4c(scale_rows, output)
    figure_4d(summary, output)
    table_rows = []
    for item in summary["mixed_load"]:
        table_rows.append({key: value for key, value in item.items() if key != "latency_by_request_type"})
    if table_rows:
        with (output / "table-4-mixed-load.csv").open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(table_rows[0]))
            writer.writeheader()
            writer.writerows(table_rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Redraw Experiment 4 paper figures from recorded data.")
    parser.add_argument("--results", type=Path, default=Path("results/latest"))
    args = parser.parse_args()
    results = args.results.resolve()
    summary = json.loads((results / "summary.json").read_text(encoding="utf-8"))
    with (results / "raw" / "scale-samples.csv").open(encoding="utf-8-sig", newline="") as handle:
        scale_rows = list(csv.DictReader(handle))
    with (results / "raw" / "mixed-events.jsonl").open(encoding="utf-8") as handle:
        mixed_rows = [json.loads(line) for line in handle if line.strip()]
    create_figures(summary, scale_rows, mixed_rows, results / "paper")
    print(f"FIGURES_READY={results / 'paper'}")


if __name__ == "__main__":
    main()
