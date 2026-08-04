#!/usr/bin/env python3
"""Draw conventional paper figures for Experiment 1.

Inputs are the actual Experiment 1 output files:
  results/latest/summary.json
  results/latest/analysis/*_pair_predictions.csv

Outputs are two separate English 600-DPI PNG figures:
  Figure A: ROC curves only
  Figure B: grouped bar chart only
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path

import numpy as np
from PIL import Image, ImageChops, ImageDraw, ImageFont

from plot_paper_results import (
    auc_rank,
    read_predictions,
    roc_curve,
    step_points,
    stratified_bootstrap_auc,
)


DPI = 600
WIDTH = 3100
HEIGHT = 2050
STANDARD = "#4C72B0"
AURA = "#DD8452"
BLACK = "#202020"
GRAY = "#666666"
GRID = "#D9D9D9"
WHITE = "#FFFFFF"


def font_file(bold: bool = False) -> str:
    roots = (Path("C:/Windows/Fonts"), Path("/mnt/c/Windows/Fonts"))
    root = next((candidate for candidate in roots if candidate.exists()), None)
    if root is None:
        raise FileNotFoundError("Windows font directory not found")
    path = root / ("timesbd.ttf" if bold else "times.ttf")
    if not path.exists():
        raise FileNotFoundError(path)
    return str(path)


def font(size: int, *, bold: bool = False) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(font_file(bold), size=size)


def label(
    draw: ImageDraw.ImageDraw,
    xy: tuple[int, int],
    value: str,
    size: int,
    *,
    bold: bool = False,
    fill: str = BLACK,
    anchor: str = "la",
) -> None:
    draw.text(xy, value, font=font(size, bold=bold), fill=fill, anchor=anchor)


def dashed_line(
    draw: ImageDraw.ImageDraw,
    start: tuple[int, int],
    end: tuple[int, int],
    *,
    fill: str,
    width: int,
    dash: int = 34,
    gap: int = 24,
) -> None:
    x1, y1 = start
    x2, y2 = end
    length = float(np.hypot(x2 - x1, y2 - y1))
    if length == 0:
        return
    dx = (x2 - x1) / length
    dy = (y2 - y1) / length
    position = 0.0
    while position < length:
        finish = min(position + dash, length)
        draw.line(
            (
                round(x1 + dx * position),
                round(y1 + dy * position),
                round(x1 + dx * finish),
                round(y1 + dy * finish),
            ),
            fill=fill,
            width=width,
        )
        position += dash + gap


def save_tightly_cropped(image: Image.Image, output: Path) -> None:
    """Remove unused white canvas while retaining a minimal print-safe edge."""
    difference = ImageChops.difference(
        image, Image.new(image.mode, image.size, WHITE)
    )
    bbox = difference.getbbox()
    if bbox is None:
        raise RuntimeError("refusing to save an empty figure")
    padding = 24
    left = max(0, bbox[0] - padding)
    top = max(0, bbox[1] - padding)
    right = min(image.width, bbox[2] + padding)
    bottom = min(image.height, bbox[3] + padding)
    cropped = image.crop((left, top, right, bottom))
    output.parent.mkdir(parents=True, exist_ok=True)
    cropped.save(output, format="PNG", dpi=(DPI, DPI), optimize=True)


def draw_roc_figure(
    *,
    standard_points: list[tuple[float, float]],
    aura_points: list[tuple[float, float]],
    standard_auc: float,
    aura_auc: float,
    output: Path,
) -> None:
    image = Image.new("RGB", (WIDTH, HEIGHT), WHITE)
    draw = ImageDraw.Draw(image)
    left, right, top, bottom = 420, 3020, 260, 1640
    plot_width = right - left
    plot_height = bottom - top

    for tick in np.linspace(0.0, 1.0, 6):
        x = round(left + tick * plot_width)
        y = round(bottom - tick * plot_height)
        draw.line((x, top, x, bottom), fill=GRID, width=5)
        draw.line((left, y, right, y), fill=GRID, width=5)
        label(draw, (x, bottom + 74), f"{tick:.1f}", 94, fill=GRAY, anchor="ma")
        label(draw, (left - 58, y), f"{tick:.1f}", 94, fill=GRAY, anchor="ra")

    dashed_line(
        draw,
        (left, bottom),
        (right, top),
        fill="#8A8A8A",
        width=14,
        dash=44,
        gap=25,
    )
    standard_path = step_points(
        standard_points, left, top, plot_width, plot_height
    )
    aura_path = step_points(aura_points, left, top, plot_width, plot_height)
    draw.line(standard_path, fill=STANDARD, width=28, joint="curve")
    draw.line(aura_path, fill=AURA, width=28, joint="curve")

    draw.line((left, bottom, right, bottom), fill=BLACK, width=13)
    draw.line((left, top, left, bottom), fill=BLACK, width=13)
    label(
        draw,
        ((left + right) // 2, 1840),
        "False positive rate",
        126,
        bold=True,
        anchor="ma",
    )
    y_layer = Image.new("RGBA", (1040, 220), (255, 255, 255, 0))
    y_draw = ImageDraw.Draw(y_layer)
    label(
        y_draw,
        (520, 110),
        "True positive rate",
        126,
        bold=True,
        anchor="mm",
    )
    y_layer = y_layer.rotate(90, expand=True)
    image.paste(y_layer, (10, 450), y_layer)

    legend_y = 105
    draw.line((110, legend_y, 225, legend_y), fill=STANDARD, width=25)
    label(
        draw,
        (255, legend_y),
        f"Standard RSP (AUC {standard_auc:.3f})",
        88,
        bold=True,
        anchor="lm",
    )
    draw.line((1570, legend_y, 1685, legend_y), fill=AURA, width=25)
    label(
        draw,
        (1715, legend_y),
        f"AURA-RSP (AUC {aura_auc:.3f})",
        88,
        bold=True,
        anchor="lm",
    )
    label(
        draw,
        (2580, 430),
        "Random",
        86,
        fill=GRAY,
        anchor="mm",
    )

    save_tightly_cropped(image, output)


def draw_bar_figure(
    *,
    standard_values: list[float],
    aura_values: list[float],
    output: Path,
) -> None:
    image = Image.new("RGB", (WIDTH, HEIGHT), WHITE)
    draw = ImageDraw.Draw(image)
    left, right, top, bottom = 1030, 2990, 245, 1690
    plot_width = right - left
    plot_height = bottom - top
    y_max = 1.10

    for tick in np.linspace(0.0, 1.0, 6):
        x = round(left + (tick / y_max) * plot_width)
        draw.line((x, top, x, bottom), fill=GRID, width=5)
        label(draw, (x, bottom + 62), f"{tick:.1f}", 86, fill=GRAY, anchor="ma")
    draw.line((left, bottom, right, bottom), fill=BLACK, width=13)
    draw.line((left, top, left, bottom), fill=BLACK, width=13)

    categories = [
        "ROC-AUC",
        "Pairwise accuracy",
        "Exact device-history\nrecovery",
        "Direct cross-profile\nlinkage",
    ]
    centers = np.linspace(top + 0.13 * plot_height, bottom - 0.13 * plot_height, 4)
    bar_height = 112
    gap = 26
    for center, category, standard_value, aura_value in zip(
        centers, categories, standard_values, aura_values
    ):
        y_standard_1 = round(center - gap / 2 - bar_height)
        y_standard_2 = round(center - gap / 2)
        y_aura_1 = round(center + gap / 2)
        y_aura_2 = round(center + gap / 2 + bar_height)
        x_standard = round(left + (standard_value / y_max) * plot_width)
        x_aura = round(left + (aura_value / y_max) * plot_width)
        draw.rectangle(
            (left, y_standard_1, max(left + 2, x_standard), y_standard_2),
            fill=STANDARD,
        )
        draw.rectangle(
            (left, y_aura_1, max(left + 2, x_aura), y_aura_2),
            fill=AURA,
        )
        label(
            draw,
            (max(left + 28, x_standard + 24), (y_standard_1 + y_standard_2) // 2),
            f"{standard_value:.3f}",
            92,
            bold=True,
            fill=STANDARD,
            anchor="lm",
        )
        label(
            draw,
            (max(left + 28, x_aura + 24), (y_aura_1 + y_aura_2) // 2),
            f"{aura_value:.3f}",
            92,
            bold=True,
            fill=AURA,
            anchor="lm",
        )
        draw.multiline_text(
            (left - 70, round(center)),
            category,
            font=font(92, bold=True),
            fill=BLACK,
            spacing=10,
            anchor="rm",
            align="right",
        )

    legend_y = 105
    draw.rectangle((850, legend_y - 40, 930, legend_y + 40), fill=STANDARD)
    label(draw, (970, legend_y), "Standard RSP", 96, bold=True, anchor="lm")
    draw.rectangle((1920, legend_y - 40, 2000, legend_y + 40), fill=AURA)
    label(draw, (2040, legend_y), "AURA-RSP", 96, bold=True, anchor="lm")

    save_tightly_cropped(image, output)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def format4(value: float) -> str:
    return str(
        Decimal(f"{value:.12f}").quantize(
            Decimal("0.0001"), rounding=ROUND_HALF_UP
        )
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path, default=Path("results/latest"))
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("results/latest/publication-simple"),
    )
    parser.add_argument("--bootstrap-samples", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=20260729)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    summary_path = args.results / "summary.json"
    standard_path = (
        args.results / "analysis" / "standard_rsp_pair_predictions.csv"
    )
    aura_path = args.results / "analysis" / "aura_rsp_pair_predictions.csv"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    standard_labels, standard_scores = read_predictions(standard_path)
    aura_labels, aura_scores = read_predictions(aura_path)
    standard_auc = auc_rank(standard_labels, standard_scores)
    aura_auc = auc_rank(aura_labels, aura_scores)
    expected_standard_auc = summary["modes"]["standard_rsp"][
        "pairwise_classifier"
    ]["roc_auc"]
    expected_aura_auc = summary["modes"]["aura_rsp"]["pairwise_classifier"][
        "roc_auc"
    ]
    # summary.json stores ROC-AUC rounded to six decimal places; compare at
    # that serialization precision instead of requiring bit-identical floats.
    if not math.isclose(standard_auc, expected_standard_auc, abs_tol=1e-6):
        raise AssertionError("Standard RSP AUC mismatch")
    if not math.isclose(aura_auc, expected_aura_auc, abs_tol=1e-6):
        raise AssertionError("AURA-RSP AUC mismatch")

    standard_ci = stratified_bootstrap_auc(
        standard_labels,
        standard_scores,
        samples=args.bootstrap_samples,
        seed=args.seed,
    )
    aura_ci = stratified_bootstrap_auc(
        aura_labels,
        aura_scores,
        samples=args.bootstrap_samples,
        seed=args.seed + 1,
    )
    args.output.mkdir(parents=True, exist_ok=True)
    figure_a = args.output / "experiment1-figure-a-roc-en-600dpi.png"
    figure_b = args.output / "experiment1-figure-b-bars-en-600dpi.png"
    draw_roc_figure(
        standard_points=roc_curve(standard_labels, standard_scores),
        aura_points=roc_curve(aura_labels, aura_scores),
        standard_auc=standard_auc,
        aura_auc=aura_auc,
        output=figure_a,
    )
    std = summary["modes"]["standard_rsp"]
    aura = summary["modes"]["aura_rsp"]
    standard_values = [
        standard_auc,
        std["pairwise_classifier"]["pairwise_accuracy"],
        std["direct_stable_grouping"]["exact_device_recovery_rate"],
        std["direct_stable_grouping"]["cross_profile_link_rate"],
    ]
    aura_values = [
        aura_auc,
        aura["pairwise_classifier"]["pairwise_accuracy"],
        aura["direct_stable_grouping"]["exact_device_recovery_rate"],
        aura["direct_stable_grouping"]["cross_profile_link_rate"],
    ]
    draw_bar_figure(
        standard_values=standard_values,
        aura_values=aura_values,
        output=figure_b,
    )

    table_rows = [
        ["ROC-AUC", format4(standard_auc), format4(aura_auc)],
        [
            "ROC-AUC 95% CI",
            f"[{format4(standard_ci[0])}, {format4(standard_ci[1])}]",
            f"[{format4(aura_ci[0])}, {format4(aura_ci[1])}]",
        ],
        [
            "方向无关可利用AUC max(AUC, 1−AUC)",
            format4(max(standard_auc, 1.0 - standard_auc)),
            format4(max(aura_auc, 1.0 - aura_auc)),
        ],
        ["成对分类准确率", format4(standard_values[1]), format4(aura_values[1])],
        ["完整设备历史恢复率", format4(standard_values[2]), format4(aura_values[2])],
        ["跨Profile直接关联率", format4(standard_values[3]), format4(aura_values[3])],
        [
            "攻击者观察簇数量",
            str(std["direct_stable_grouping"]["cluster_count"]),
            str(aura["direct_stable_grouping"]["cluster_count"]),
        ],
    ]
    table_csv = args.output / "experiment1-results-table-zh.csv"
    with table_csv.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["指标", "Standard RSP", "AURA-RSP"])
        writer.writerows(table_rows)
    table_md = args.output / "experiment1-results-table-zh.md"
    table_md.write_text(
        "\n".join(
            [
                "| 指标 | Standard RSP | AURA-RSP |",
                "|---|---:|---:|",
                *[
                    f"| {metric} | {standard} | {aura_value} |"
                    for metric, standard, aura_value in table_rows
                ],
                "",
            ]
        ),
        encoding="utf-8",
    )

    audit = {
        "status": "PASS",
        "data_origin": "actual controlled software-simulation run",
        "not_real_hardware_or_full_network_download": True,
        "complete_network_downloads_executed": summary["design"][
            "complete_network_downloads_executed"
        ],
        "source_files": {
            "summary.json": sha256(summary_path),
            "standard_rsp_pair_predictions.csv": sha256(standard_path),
            "aura_rsp_pair_predictions.csv": sha256(aura_path),
        },
        "design": summary["design"],
        "metrics": {
            "standard_rsp": {
                "roc_auc": standard_auc,
                "roc_auc_95_ci": list(standard_ci),
                "pairwise_accuracy": standard_values[1],
                "exact_device_history_recovery": standard_values[2],
                "direct_cross_profile_linkage": standard_values[3],
            },
            "aura_rsp": {
                "roc_auc": aura_auc,
                "roc_auc_95_ci": list(aura_ci),
                "orientation_independent_auc": max(aura_auc, 1.0 - aura_auc),
                "pairwise_accuracy": aura_values[1],
                "exact_device_history_recovery": aura_values[2],
                "direct_cross_profile_linkage": aura_values[3],
            },
        },
        "figures": {
            figure_a.name: sha256(figure_a),
            figure_b.name: sha256(figure_b),
        },
        "result_tables": {
            table_csv.name: sha256(table_csv),
            table_md.name: sha256(table_md),
        },
    }
    (args.output / "experiment1-data-audit.json").write_text(
        json.dumps(audit, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "status": "PASS",
                "figure_a": str(figure_a.resolve()),
                "figure_b": str(figure_b.resolve()),
                "standard_auc": standard_auc,
                "aura_auc": aura_auc,
                "aura_auc_95_ci": [round(x, 6) for x in aura_ci],
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
