#!/usr/bin/env python3
"""Generate a single publication-style bar chart for Experiment 12."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


DPI = 600
WHITE = "#FFFFFF"
INK = "#20252B"
MUTED = "#626B73"
GRID = "#D9DEE3"
BLUE = "#3B6FB6"
GREEN = "#3F8667"
ORANGE = "#C77A27"
TEAL = "#278F91"


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


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def draw_bar(
    draw: ImageDraw.ImageDraw,
    *,
    label: str,
    value: float,
    color: str,
    y: int,
    x0: int,
    x1: int,
) -> None:
    bar_height = 118
    width = int((x1 - x0) * value / 100.0)
    text(draw, (x0 - 42, y + bar_height / 2), label, 57, fill=INK, anchor="rm")
    draw.rounded_rectangle(
        (x0, y, x0 + max(width, 5), y + bar_height),
        radius=18,
        fill=color,
    )
    label_text = f"{value:.1f}%"
    if width >= 360:
        text(
            draw,
            (x0 + width - 30, y + bar_height / 2),
            label_text,
            62,
            bold=True,
            fill=WHITE,
            anchor="rm",
        )
    else:
        text(
            draw,
            (x0 + width + 28, y + bar_height / 2),
            label_text,
            62,
            bold=True,
            fill=color,
            anchor="lm",
        )


def draw_figure(summary: dict, output: Path) -> dict:
    direct = summary["modes"]["12A_direct"]
    shared = summary["modes"]["12B_shared_pr"]
    time_only = summary["modes"]["12C_collusion"]["time_only"]
    time_size = summary["modes"]["12C_collusion"]["time_and_size"]

    width, height = 4700, 2850
    image = Image.new("RGB", (width, height), WHITE)
    draw = ImageDraw.Draw(image)

    x0, x1 = 1720, 4400
    plot_top, plot_bottom = 260, 2530

    # Shared horizontal scale.
    for tick in (0, 25, 50, 75, 100):
        x = x0 + (x1 - x0) * tick / 100
        draw.line((x, plot_top, x, plot_bottom), fill=GRID, width=5)
        text(draw, (x, plot_bottom + 85), str(tick), 51, fill=MUTED, anchor="mm")
    text(
        draw,
        ((x0 + x1) / 2, 2760),
        "Metric value (%)   —   ROC–AUC is shown as AUC × 100",
        60,
        fill=MUTED,
        anchor="mm",
    )

    # Section labels.
    text(draw, (140, 315), "SM-DP+ alone", 76, bold=True, fill=BLUE)
    text(
        draw,
        (140, 410),
        "Source-IP-based linkage",
        55,
        fill=MUTED,
    )
    text(draw, (140, 1465), "PR–SM-DP+ collusion", 76, bold=True, fill=ORANGE)
    text(
        draw,
        (140, 1560),
        "Ingress/egress metadata matching",
        55,
        fill=MUTED,
    )

    # Metric 1.
    text(draw, (1650, 565), "IP pairwise ROC–AUC", 70, bold=True, anchor="ra")
    draw_bar(
        draw,
        label="Direct",
        value=100 * direct["ip_pairwise_roc_auc"],
        color=BLUE,
        y=625,
        x0=x0,
        x1=x1,
    )
    draw_bar(
        draw,
        label="Shared PR",
        value=100 * shared["ip_pairwise_roc_auc"],
        color=GREEN,
        y=775,
        x0=x0,
        x1=x1,
    )

    # Metric 2.
    text(
        draw,
        (1650, 1030),
        "Exact device-history recovery",
        70,
        bold=True,
        anchor="ra",
    )
    draw_bar(
        draw,
        label="Direct",
        value=100 * direct["exact_device_history_recovery"],
        color=BLUE,
        y=1090,
        x0=x0,
        x1=x1,
    )
    draw_bar(
        draw,
        label="Shared PR",
        value=100 * shared["exact_device_history_recovery"],
        color=GREEN,
        y=1240,
        x0=x0,
        x1=x1,
    )

    # Separation between protection result and threat-model boundary.
    draw.line((140, 1400, 4480, 1400), fill=GRID, width=6)

    # Metric 3.
    text(draw, (1650, 1710), "Connection matching accuracy", 70, bold=True, anchor="ra")
    draw_bar(
        draw,
        label="Time only",
        value=100 * time_only["match_accuracy"],
        color=ORANGE,
        y=1770,
        x0=x0,
        x1=x1,
    )
    draw_bar(
        draw,
        label="Time + size",
        value=100 * time_size["match_accuracy"],
        color=TEAL,
        y=1920,
        x0=x0,
        x1=x1,
    )

    # Metric 4.
    text(
        draw,
        (1650, 2160),
        "Full device-history recovery",
        70,
        bold=True,
        anchor="ra",
    )
    draw_bar(
        draw,
        label="Time only",
        value=100 * time_only["full_device_history_recovery"],
        color=ORANGE,
        y=2220,
        x0=x0,
        x1=x1,
    )
    draw_bar(
        draw,
        label="Time + size",
        value=100 * time_size["full_device_history_recovery"],
        color=TEAL,
        y=2370,
        x0=x0,
        x1=x1,
    )

    output.parent.mkdir(parents=True, exist_ok=True)
    image.save(output, format="PNG", dpi=(DPI, DPI), optimize=True)
    return {
        "ip_pairwise_roc_auc_percent": {
            "direct": 100 * direct["ip_pairwise_roc_auc"],
            "shared_pr": 100 * shared["ip_pairwise_roc_auc"],
        },
        "exact_device_history_recovery_percent": {
            "direct": 100 * direct["exact_device_history_recovery"],
            "shared_pr": 100 * shared["exact_device_history_recovery"],
        },
        "connection_matching_accuracy_percent": {
            "time_only": 100 * time_only["match_accuracy"],
            "time_and_size": 100 * time_size["match_accuracy"],
        },
        "full_device_history_recovery_percent": {
            "time_only": 100 * time_only["full_device_history_recovery"],
            "time_and_size": 100 * time_size["full_device_history_recovery"],
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path, default=Path("results/latest"))
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("results/latest/publication-bar-chart"),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    summary_path = args.results / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    if summary.get("status") != "PASS":
        raise AssertionError("Experiment 12 result is not PASS")

    figure = args.output / "experiment12-results-grouped-bars-en-600dpi.png"
    plotted_data = draw_figure(summary, figure)
    audit = {
        "status": "PASS",
        "source": str(summary_path.resolve()),
        "source_sha256": sha256(summary_path),
        "figure": {
            "path": str(figure.resolve()),
            "sha256": sha256(figure),
            "width_px": 4700,
            "height_px": 2850,
            "dpi": DPI,
            "data": plotted_data,
        },
    }
    args.output.mkdir(parents=True, exist_ok=True)
    audit_path = args.output / "experiment12-bar-chart-data-audit.json"
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
