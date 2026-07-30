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
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFont

from plot_paper_results import (
    auc_rank,
    read_predictions,
    roc_curve,
    step_points,
    stratified_bootstrap_auc,
)


DPI = 600
WIDTH = 4200
HEIGHT = 3000
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
    left, right, top, bottom = 680, 3980, 520, 2390
    plot_width = right - left
    plot_height = bottom - top

    for tick in np.linspace(0.0, 1.0, 6):
        x = round(left + tick * plot_width)
        y = round(bottom - tick * plot_height)
        draw.line((x, top, x, bottom), fill=GRID, width=7)
        draw.line((left, y, right, y), fill=GRID, width=7)
        label(draw, (x, bottom + 95), f"{tick:.1f}", 104, fill=GRAY, anchor="ma")
        label(draw, (left - 75, y), f"{tick:.1f}", 104, fill=GRAY, anchor="ra")

    dashed_line(
        draw,
        (left, bottom),
        (right, top),
        fill="#8A8A8A",
        width=16,
        dash=52,
        gap=30,
    )
    standard_path = step_points(
        standard_points, left, top, plot_width, plot_height
    )
    aura_path = step_points(aura_points, left, top, plot_width, plot_height)
    draw.line(standard_path, fill=STANDARD, width=32, joint="curve")
    draw.line(aura_path, fill=AURA, width=32, joint="curve")

    draw.line((left, bottom, right, bottom), fill=BLACK, width=15)
    draw.line((left, top, left, bottom), fill=BLACK, width=15)
    label(
        draw,
        ((left + right) // 2, 2715),
        "False positive rate",
        126,
        anchor="ma",
    )
    y_layer = Image.new("RGBA", (1120, 220), (255, 255, 255, 0))
    y_draw = ImageDraw.Draw(y_layer)
    label(y_draw, (560, 110), "True positive rate", 126, anchor="mm")
    y_layer = y_layer.rotate(90, expand=True)
    image.paste(y_layer, (90, 900), y_layer)

    legend_y = 245
    draw.line((400, legend_y, 580, legend_y), fill=STANDARD, width=30)
    label(
        draw,
        (620, legend_y),
        f"Standard RSP (AUC = {standard_auc:.3f})",
        94,
        anchor="lm",
    )
    draw.line((2020, legend_y, 2200, legend_y), fill=AURA, width=30)
    label(
        draw,
        (2240, legend_y),
        f"AURA-RSP (AUC = {aura_auc:.3f})",
        94,
        anchor="lm",
    )
    dashed_line(
        draw,
        (3480, legend_y),
        (3660, legend_y),
        fill="#8A8A8A",
        width=16,
        dash=45,
        gap=24,
    )
    label(draw, (3700, legend_y), "Random", 94, fill=GRAY, anchor="lm")

    output.parent.mkdir(parents=True, exist_ok=True)
    image.save(output, format="PNG", dpi=(DPI, DPI), optimize=True)


def draw_bar_figure(
    *,
    standard_values: list[float],
    aura_values: list[float],
    output: Path,
) -> None:
    image = Image.new("RGB", (WIDTH, HEIGHT), WHITE)
    draw = ImageDraw.Draw(image)
    left, right, top, bottom = 620, 4010, 450, 2250
    plot_width = right - left
    plot_height = bottom - top
    y_max = 1.10

    for tick in np.linspace(0.0, 1.0, 6):
        y = round(bottom - (tick / y_max) * plot_height)
        draw.line((left, y, right, y), fill=GRID, width=7)
        label(draw, (left - 75, y), f"{tick:.1f}", 102, fill=GRAY, anchor="ra")
    draw.line((left, bottom, right, bottom), fill=BLACK, width=15)
    draw.line((left, top, left, bottom), fill=BLACK, width=15)

    categories = [
        "ROC-AUC",
        "Pairwise\naccuracy",
        "Exact device-history\nrecovery",
        "Direct cross-profile\nlinkage",
    ]
    centers = np.linspace(left + 0.13 * plot_width, right - 0.13 * plot_width, 4)
    bar_width = 290
    gap = 54
    for center, category, standard_value, aura_value in zip(
        centers, categories, standard_values, aura_values
    ):
        x_standard_1 = round(center - gap / 2 - bar_width)
        x_standard_2 = round(center - gap / 2)
        x_aura_1 = round(center + gap / 2)
        x_aura_2 = round(center + gap / 2 + bar_width)
        y_standard = round(bottom - (standard_value / y_max) * plot_height)
        y_aura = round(bottom - (aura_value / y_max) * plot_height)
        draw.rectangle(
            (x_standard_1, y_standard, x_standard_2, bottom),
            fill=STANDARD,
        )
        draw.rectangle((x_aura_1, y_aura, x_aura_2, bottom), fill=AURA)
        label(
            draw,
            ((x_standard_1 + x_standard_2) // 2, y_standard - 40),
            f"{standard_value:.3f}",
            94,
            bold=True,
            fill=STANDARD,
            anchor="ms",
        )
        label(
            draw,
            ((x_aura_1 + x_aura_2) // 2, y_aura - 40),
            f"{aura_value:.3f}",
            94,
            bold=True,
            fill=AURA,
            anchor="ms",
        )
        draw.multiline_text(
            (round(center), bottom + 95),
            category,
            font=font(96),
            fill=BLACK,
            spacing=14,
            anchor="ma",
            align="center",
        )

    y_layer = Image.new("RGBA", (1000, 220), (255, 255, 255, 0))
    y_draw = ImageDraw.Draw(y_layer)
    label(y_draw, (500, 110), "Metric value", 126, anchor="mm")
    y_layer = y_layer.rotate(90, expand=True)
    image.paste(y_layer, (75, 790), y_layer)

    legend_y = 220
    draw.rectangle((1240, legend_y - 60, 1370, legend_y + 60), fill=STANDARD)
    label(draw, (1420, legend_y), "Standard RSP", 108, anchor="lm")
    draw.rectangle((2540, legend_y - 60, 2670, legend_y + 60), fill=AURA)
    label(draw, (2720, legend_y), "AURA-RSP", 108, anchor="lm")

    output.parent.mkdir(parents=True, exist_ok=True)
    image.save(output, format="PNG", dpi=(DPI, DPI), optimize=True)


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
    if abs(standard_auc - expected_standard_auc) > 1e-9:
        raise AssertionError("Standard RSP AUC mismatch")
    if abs(aura_auc - expected_aura_auc) > 1e-9:
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
