#!/usr/bin/env python3
"""Generate a publication figure for Experiment 12 from recorded results."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


DPI = 600
WHITE = "#FFFFFF"
INK = "#1F2933"
MUTED = "#59636E"
GRID = "#D7DDE3"
PANEL = "#F7F9FB"
BLUE = "#386CB0"
BLUE_LIGHT = "#E4EDF7"
TEAL = "#238B8E"
TEAL_LIGHT = "#DFF1F0"
GREEN = "#3F7F5F"
GREEN_LIGHT = "#E1EFE7"
ORANGE = "#C47725"
ORANGE_LIGHT = "#F6E9D7"
RED = "#B54A4A"
RED_LIGHT = "#F4DDDD"


def font_path(bold: bool = False) -> str:
    roots = (Path("C:/Windows/Fonts"), Path("/mnt/c/Windows/Fonts"))
    root = next((candidate for candidate in roots if candidate.exists()), None)
    if root is None:
        raise FileNotFoundError("Windows font directory not found")
    path = root / ("timesbd.ttf" if bold else "times.ttf")
    if not path.exists():
        raise FileNotFoundError(path)
    return str(path)


def font(size: int, *, bold: bool = False) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(font_path(bold), size=size)


def text(
    draw: ImageDraw.ImageDraw,
    xy: tuple[float, float],
    value: str,
    size: int,
    *,
    bold: bool = False,
    fill: str = INK,
    anchor: str = "la",
    align: str = "left",
) -> None:
    draw.multiline_text(
        xy,
        value,
        font=font(size, bold=bold),
        fill=fill,
        anchor=anchor,
        align=align,
        spacing=12,
    )


def rounded_box(
    draw: ImageDraw.ImageDraw,
    box: tuple[int, int, int, int],
    heading: str,
    detail: str,
    *,
    color: str,
    light: str,
) -> None:
    x1, y1, x2, y2 = box
    draw.rounded_rectangle(box, radius=28, fill=light, outline=color, width=8)
    text(
        draw,
        ((x1 + x2) / 2, y1 + 92),
        heading,
        73,
        bold=True,
        fill=color,
        anchor="mm",
        align="center",
    )
    text(
        draw,
        ((x1 + x2) / 2, y1 + 205),
        detail,
        57,
        fill=INK,
        anchor="mm",
        align="center",
    )


def arrow(
    draw: ImageDraw.ImageDraw,
    start: tuple[int, int],
    end: tuple[int, int],
    *,
    color: str = MUTED,
    width: int = 11,
) -> None:
    draw.line((start, end), fill=color, width=width)
    x2, y2 = end
    x1, y1 = start
    if abs(x2 - x1) >= abs(y2 - y1):
        direction = 1 if x2 > x1 else -1
        points = [
            (x2, y2),
            (x2 - direction * 38, y2 - 24),
            (x2 - direction * 38, y2 + 24),
        ]
    else:
        direction = 1 if y2 > y1 else -1
        points = [
            (x2, y2),
            (x2 - 24, y2 - direction * 38),
            (x2 + 24, y2 - direction * 38),
        ]
    draw.polygon(points, fill=color)


def device_cloud(
    draw: ImageDraw.ImageDraw,
    box: tuple[int, int, int, int],
    *,
    count: int,
    color: str,
) -> None:
    x1, y1, x2, y2 = box
    draw.rounded_rectangle(box, radius=28, fill=PANEL, outline=GRID, width=7)
    cols, rows = 5, 3
    x_gap = (x2 - x1 - 190) / (cols - 1)
    y_gap = (y2 - y1 - 300) / (rows - 1)
    for row in range(rows):
        for col in range(cols):
            cx = int(x1 + 95 + col * x_gap)
            cy = int(y1 + 82 + row * y_gap)
            draw.rounded_rectangle(
                (cx - 34, cy - 47, cx + 34, cy + 47),
                radius=10,
                fill=WHITE,
                outline=color,
                width=6,
            )
            draw.ellipse((cx - 5, cy + 29, cx + 5, cy + 39), fill=color)
    text(
        draw,
        ((x1 + x2) / 2, y2 - 45),
        f"{count} eUICCs",
        62,
        bold=True,
        fill=color,
        anchor="mm",
    )


def metric_strip(
    draw: ImageDraw.ImageDraw,
    box: tuple[int, int, int, int],
    values: list[tuple[str, str]],
    *,
    color: str,
) -> None:
    x1, y1, x2, y2 = box
    draw.rounded_rectangle(box, radius=24, fill=WHITE, outline=GRID, width=6)
    segment = (x2 - x1) / len(values)
    for index, (label, value) in enumerate(values):
        cx = x1 + segment * (index + 0.5)
        if index:
            sx = int(x1 + segment * index)
            draw.line((sx, y1 + 28, sx, y2 - 28), fill=GRID, width=5)
        text(draw, (cx, y1 + 65), label, 47, fill=MUTED, anchor="mm", align="center")
        text(draw, (cx, y1 + 155), value, 76, bold=True, fill=color, anchor="mm")


def stacked_bar(
    draw: ImageDraw.ImageDraw,
    *,
    y: int,
    label: str,
    correct: int,
    incorrect: int,
    total: int,
    x1: int,
    x2: int,
) -> None:
    bar_h = 160
    text(draw, (x1, y - 84), label, 65, bold=True, anchor="la")
    width = x2 - x1
    correct_w = round(width * correct / total)
    draw.rounded_rectangle(
        (x1, y, x2, y + bar_h),
        radius=26,
        fill=RED_LIGHT,
        outline=GRID,
        width=5,
    )
    draw.rounded_rectangle(
        (x1, y, x1 + correct_w, y + bar_h),
        radius=26,
        fill=TEAL,
    )
    if correct_w < width:
        draw.rectangle(
            (x1 + correct_w - 26, y, x1 + correct_w, y + bar_h),
            fill=TEAL,
        )
    text(
        draw,
        (x1 + correct_w / 2, y + bar_h / 2),
        f"{correct} correct ({100 * correct / total:.1f}%)",
        58,
        bold=True,
        fill=WHITE,
        anchor="mm",
    )
    if incorrect and incorrect / total >= 0.08:
        text(
            draw,
            (x1 + correct_w + (width - correct_w) / 2, y + bar_h / 2),
            f"{incorrect}\n({100 * incorrect / total:.1f}%)",
            44,
            bold=True,
            fill=RED,
            anchor="mm",
            align="center",
        )
    elif incorrect:
        text(
            draw,
            (x2, y + bar_h + 48),
            f"{incorrect} incorrect ({100 * incorrect / total:.1f}%)",
            45,
            bold=True,
            fill=RED,
            anchor="ra",
        )


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def draw_figure(summary: dict, output: Path) -> dict:
    direct = summary["modes"]["12A_direct"]
    shared = summary["modes"]["12B_shared_pr"]
    collusion = summary["modes"]["12C_collusion"]
    time_only = collusion["time_only"]
    time_size = collusion["time_and_size"]

    width, height = 5600, 3200
    image = Image.new("RGB", (width, height), WHITE)
    draw = ImageDraw.Draw(image)

    # Panel labels and divider.
    text(draw, (115, 110), "A", 112, bold=True, anchor="la")
    text(draw, (3425, 110), "B", 112, bold=True, anchor="la")
    draw.line((3310, 110, 3310, 2990), fill=GRID, width=7)
    text(
        draw,
        (260, 145),
        "Source-address visibility",
        82,
        bold=True,
        anchor="la",
    )
    text(
        draw,
        (3570, 145),
        "PR–SM-DP+ collusion matching",
        82,
        bold=True,
        anchor="la",
    )

    # 12A: direct connection.
    text(draw, (220, 395), "12A  Direct connection", 72, bold=True, fill=BLUE)
    device_cloud(draw, (220, 500, 920, 1005), count=summary["devices"], color=BLUE)
    rounded_box(
        draw,
        (1280, 585, 1980, 925),
        "VISIBLE IPs",
        f"{direct['observed_source_addresses']} distinct addresses",
        color=BLUE,
        light=BLUE_LIGHT,
    )
    rounded_box(
        draw,
        (2350, 585, 3060, 925),
        "SM-DP+",
        "IP-assisted linkage",
        color=BLUE,
        light=BLUE_LIGHT,
    )
    arrow(draw, (920, 755), (1280, 755), color=BLUE)
    arrow(draw, (1980, 755), (2350, 755), color=BLUE)
    metric_strip(
        draw,
        (220, 1080, 3060, 1335),
        [
            ("IP pairwise ROC–AUC", f"{direct['ip_pairwise_roc_auc']:.3f}"),
            ("Mean anonymity set", f"{direct['mean_device_anonymity_set']:.0f}"),
            ("Exact history recovery", f"{100 * direct['exact_device_history_recovery']:.0f}%"),
        ],
        color=BLUE,
    )

    # 12B: shared relay.
    text(draw, (220, 1515), "12B  Shared Privacy Relay", 72, bold=True, fill=GREEN)
    device_cloud(draw, (220, 1620, 920, 2125), count=summary["devices"], color=GREEN)
    rounded_box(
        draw,
        (1150, 1705, 1810, 2045),
        "SHARED PR",
        "one common egress",
        color=GREEN,
        light=GREEN_LIGHT,
    )
    rounded_box(
        draw,
        (2080, 1705, 2680, 2045),
        "VISIBLE IP",
        f"{shared['observed_source_addresses']} address",
        color=GREEN,
        light=GREEN_LIGHT,
    )
    rounded_box(
        draw,
        (2820, 1705, 3220, 2045),
        "SM-DP+",
        "IP only",
        color=GREEN,
        light=GREEN_LIGHT,
    )
    arrow(draw, (920, 1875), (1150, 1875), color=GREEN)
    arrow(draw, (1810, 1875), (2080, 1875), color=GREEN)
    arrow(draw, (2680, 1875), (2820, 1875), color=GREEN)
    metric_strip(
        draw,
        (220, 2200, 3220, 2455),
        [
            ("IP pairwise ROC–AUC", f"{shared['ip_pairwise_roc_auc']:.3f}"),
            ("Mean anonymity set", f"{shared['mean_device_anonymity_set']:.0f}"),
            ("Exact history recovery", f"{100 * shared['exact_device_history_recovery']:.0f}%"),
            ("IP identification rate", f"{100 * shared['expected_ip_identification_rate']:.0f}%"),
        ],
        color=GREEN,
    )

    # 12C: collusion bars and recovery indicators.
    x1, x2 = 3580, 5360
    text(
        draw,
        (3580, 395),
        "Ingress and egress logs are matched by observable metadata",
        59,
        fill=MUTED,
    )
    stacked_bar(
        draw,
        y=690,
        label="Time only",
        correct=time_only["correct_matches"],
        incorrect=time_only["incorrect_matches"],
        total=time_only["matched_records"],
        x1=x1,
        x2=x2,
    )
    stacked_bar(
        draw,
        y=1140,
        label="Time + flow size",
        correct=time_size["correct_matches"],
        incorrect=time_size["incorrect_matches"],
        total=time_size["matched_records"],
        x1=x1,
        x2=x2,
    )
    text(draw, (3580, 1530), "Device-history recovery", 68, bold=True)
    axis_y = 1820
    draw.line((x1, axis_y, x2, axis_y), fill=GRID, width=8)
    for percent in (0, 25, 50, 75, 100):
        x = x1 + (x2 - x1) * percent / 100
        draw.line((x, axis_y - 24, x, axis_y + 24), fill=GRID, width=6)
        text(draw, (x, axis_y + 80), f"{percent}%", 45, fill=MUTED, anchor="mm")
    history_items = [
        ("Time only", 100 * time_only["full_device_history_recovery"], ORANGE, axis_y - 130),
        ("Time + size", 100 * time_size["full_device_history_recovery"], TEAL, axis_y + 190),
    ]
    for label, value, color, y in history_items:
        x = x1 + (x2 - x1) * value / 100
        draw.line((x1, y, x, y), fill=color, width=16)
        draw.ellipse((x - 29, y - 29, x + 29, y + 29), fill=color, outline=WHITE, width=5)
        text(draw, (x1, y - 65), label, 52, bold=True, fill=color)
        text(draw, (x + 48, y), f"{value:.0f}%", 58, bold=True, fill=color, anchor="lm")

    boundary_box = (3560, 2380, 5380, 2780)
    draw.rounded_rectangle(
        boundary_box,
        radius=28,
        fill=ORANGE_LIGHT,
        outline=ORANGE,
        width=8,
    )
    text(
        draw,
        ((boundary_box[0] + boundary_box[2]) / 2, 2485),
        "EXPECTED BOUNDARY FAILURE",
        77,
        bold=True,
        fill=ORANGE,
        anchor="mm",
    )
    text(
        draw,
        ((boundary_box[0] + boundary_box[2]) / 2, 2645),
        "A shared PR hides source IP from SM-DP+ alone,\n"
        "but not from PR–SM-DP+ collusion.",
        56,
        anchor="mm",
        align="center",
    )

    # Data provenance strip.
    draw.rectangle((150, 2950, 5450, 3125), fill=PANEL, outline=GRID, width=6)
    text(
        draw,
        (280, 3038),
        f"Recorded trace: {summary['devices']} devices  |  "
        f"{summary['transactions']} transactions  |  seed {summary['seed']}  |  "
        f"machine-checkable assertions {summary['assertions_passed']}/{summary['assertions_total']}",
        58,
        bold=True,
        fill=MUTED,
        anchor="lm",
    )

    output.parent.mkdir(parents=True, exist_ok=True)
    image.save(output, format="PNG", dpi=(DPI, DPI), optimize=True)
    return {
        "direct": {
            "observed_source_addresses": direct["observed_source_addresses"],
            "ip_pairwise_roc_auc": direct["ip_pairwise_roc_auc"],
            "mean_device_anonymity_set": direct["mean_device_anonymity_set"],
            "exact_device_history_recovery": direct["exact_device_history_recovery"],
        },
        "shared_pr": {
            "observed_source_addresses": shared["observed_source_addresses"],
            "ip_pairwise_roc_auc": shared["ip_pairwise_roc_auc"],
            "mean_device_anonymity_set": shared["mean_device_anonymity_set"],
            "exact_device_history_recovery": shared["exact_device_history_recovery"],
            "expected_ip_identification_rate": shared["expected_ip_identification_rate"],
        },
        "collusion": {
            "time_only": {
                "correct_matches": time_only["correct_matches"],
                "incorrect_matches": time_only["incorrect_matches"],
                "match_accuracy": time_only["match_accuracy"],
                "full_device_history_recovery": time_only["full_device_history_recovery"],
            },
            "time_and_size": {
                "correct_matches": time_size["correct_matches"],
                "incorrect_matches": time_size["incorrect_matches"],
                "match_accuracy": time_size["match_accuracy"],
                "full_device_history_recovery": time_size["full_device_history_recovery"],
            },
            "interpretation": collusion["interpretation"],
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path, default=Path("results/latest"))
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("results/latest/publication-professional"),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    summary_path = args.results / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    if summary.get("status") != "PASS":
        raise AssertionError("Experiment 12 result is not PASS")

    figure = args.output / "experiment12-pr-privacy-and-collusion-en-600dpi.png"
    plotted_data = draw_figure(summary, figure)
    audit = {
        "status": "PASS",
        "source": str(summary_path.resolve()),
        "source_sha256": sha256(summary_path),
        "figure": {
            "path": str(figure.resolve()),
            "sha256": sha256(figure),
            "width_px": 5600,
            "height_px": 3200,
            "dpi": DPI,
            "data": plotted_data,
        },
    }
    args.output.mkdir(parents=True, exist_ok=True)
    audit_path = args.output / "experiment12-professional-figure-data-audit.json"
    audit_path.write_text(
        json.dumps(audit, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "status": "PASS",
                "figure": str(figure.resolve()),
                "audit": str(audit_path.resolve()),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
