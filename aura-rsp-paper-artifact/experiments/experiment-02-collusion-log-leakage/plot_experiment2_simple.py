#!/usr/bin/env python3
"""Generate conventional publication figures for Experiment 2.

All values are read from results/latest/summary.json. The script does not
generate, replace, or estimate experimental measurements.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFont


DPI = 600
WIDTH = 4200
HEIGHT = 2300
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
    draw.text(
        xy,
        value,
        font=font(size, bold=bold),
        fill=fill,
        anchor=anchor,
    )


def draw_vertical_axis_label(
    image: Image.Image,
    text: str,
    *,
    x: int,
    y: int,
    width: int = 1800,
) -> None:
    layer = Image.new("RGBA", (width, 220), (255, 255, 255, 0))
    layer_draw = ImageDraw.Draw(layer)
    label(layer_draw, (width // 2, 110), text, 108, anchor="mm")
    layer = layer.rotate(90, expand=True)
    image.paste(layer, (x, y), layer)


def draw_legend(draw: ImageDraw.ImageDraw, image_width: int) -> None:
    legend_y = 150
    first_x = image_width // 2 - 1050
    second_x = image_width // 2 + 250
    draw.rectangle(
        (first_x, legend_y - 60, first_x + 130, legend_y + 60),
        fill=STANDARD,
    )
    label(draw, (first_x + 180, legend_y), "Standard RSP", 108, anchor="lm")
    draw.rectangle(
        (second_x, legend_y - 60, second_x + 130, legend_y + 60),
        fill=AURA,
    )
    label(draw, (second_x + 180, legend_y), "AURA-RSP", 108, anchor="lm")


def draw_grouped_bars(
    *,
    categories: list[str],
    standard_values: list[float],
    aura_values: list[float],
    y_max: float,
    y_ticks: list[float],
    y_label: str,
    output: Path,
    value_decimals: int,
    image_width: int = WIDTH,
) -> None:
    image = Image.new("RGB", (image_width, HEIGHT), WHITE)
    draw = ImageDraw.Draw(image)
    if image_width == WIDTH:
        left, right = 620, image_width - 190
    else:
        left, right = 520, image_width - 160
    top, bottom = 340, 1700
    plot_width = right - left
    plot_height = bottom - top

    for tick in y_ticks:
        y = round(bottom - (tick / y_max) * plot_height)
        draw.line((left, y, right, y), fill=GRID, width=7)
        tick_text = f"{tick:.1f}"
        label(draw, (left - 75, y), tick_text, 102, fill=GRAY, anchor="ra")

    draw.line((left, bottom, right, bottom), fill=BLACK, width=15)
    draw.line((left, top, left, bottom), fill=BLACK, width=15)

    if len(categories) == 2:
        centers = np.linspace(
            left + 0.30 * plot_width,
            right - 0.30 * plot_width,
            len(categories),
        )
    else:
        centers = np.linspace(
            left + 0.13 * plot_width,
            right - 0.13 * plot_width,
            len(categories),
        )
    bar_width, gap = 290, 54

    for center, category, standard_value, aura_value in zip(
        centers,
        categories,
        standard_values,
        aura_values,
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
        draw.rectangle(
            (x_aura_1, y_aura, x_aura_2, bottom),
            fill=AURA,
        )

        value_format = f"{{:.{value_decimals}f}}"
        label(
            draw,
            ((x_standard_1 + x_standard_2) // 2, y_standard - 42),
            value_format.format(standard_value),
            94,
            bold=True,
            fill=STANDARD,
            anchor="ms",
        )
        label(
            draw,
            ((x_aura_1 + x_aura_2) // 2, y_aura - 42),
            value_format.format(aura_value),
            94,
            bold=True,
            fill=AURA,
            anchor="ms",
        )
        draw.multiline_text(
            (round(center), bottom + 75),
            category,
            font=font(96),
            fill=BLACK,
            spacing=14,
            anchor="ma",
            align="center",
        )

    draw_vertical_axis_label(image, y_label, x=75, y=250)
    draw_legend(draw, image_width)
    output.parent.mkdir(parents=True, exist_ok=True)
    image.save(output, format="PNG", dpi=(DPI, DPI), optimize=True)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_table(summary: dict, output_dir: Path) -> None:
    c_std = summary["subexperiment_2a_collusion"]["standard_rsp"]
    c_aura = summary["subexperiment_2a_collusion"]["aura_rsp"]
    l_std = summary["subexperiment_2b_log_leakage"]["standard_rsp"]
    l_aura = summary["subexperiment_2b_log_leakage"]["aura_rsp"]
    rows = [
        ("2A", "订单—下载记录连接率", c_std["order_join_rate"], c_aura["order_join_rate"]),
        (
            "2A",
            "跨MNO完整设备历史恢复率",
            c_std["exact_device_history_recovery_rate"],
            c_aura["exact_device_history_recovery_rate"],
        ),
        (
            "2A",
            "多MNO设备簇比例",
            c_std["multi_mno_cluster_rate"],
            c_aura["multi_mno_cluster_rate"],
        ),
        (
            "2A",
            "跨Profile关联率",
            c_std["cross_profile_pair_link_rate"],
            c_aura["cross_profile_pair_link_rate"],
        ),
        ("2B", "泄露下载记录数", l_std["leaked_download_records"], l_aura["leaked_download_records"]),
        (
            "2B",
            "攻击者观察到的簇数量",
            l_std["attacker_visible_cluster_count"],
            l_aura["attacker_visible_cluster_count"],
        ),
        (
            "2B",
            "平均每簇Profile数",
            l_std["mean_profiles_per_cluster"],
            l_aura["mean_profiles_per_cluster"],
        ),
        (
            "2B",
            "单簇最大Profile数",
            l_std["max_profiles_per_cluster"],
            l_aura["max_profiles_per_cluster"],
        ),
        (
            "2B",
            "完整设备历史恢复率",
            l_std["exact_device_history_recovery_rate"],
            l_aura["exact_device_history_recovery_rate"],
        ),
        (
            "2B",
            "同Profile生命周期连接率",
            l_std["within_profile_lifecycle_link_rate"],
            l_aura["within_profile_lifecycle_link_rate"],
        ),
    ]

    csv_path = output_dir / "experiment2-results-table-zh.csv"
    with csv_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("子实验", "指标", "Standard RSP", "AURA-RSP"))
        writer.writerows(rows)

    def display(value: float | int) -> str:
        if isinstance(value, int):
            return str(value)
        return f"{value:.4f}"

    md = [
        "| 子实验 | 指标 | Standard RSP | AURA-RSP |",
        "|---|---|---:|---:|",
    ]
    md.extend(
        f"| {sub} | {metric} | {display(std)} | {display(aura)} |"
        for sub, metric, std, aura in rows
    )
    (output_dir / "experiment2-results-table-zh.md").write_text(
        "\n".join(md) + "\n",
        encoding="utf-8",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path, default=Path("results/latest"))
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("results/latest/publication-simple"),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    summary_path = args.results / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    if summary.get("status") != "PASS":
        raise AssertionError("Experiment 2 result is not PASS")

    collusion = summary["subexperiment_2a_collusion"]
    standard_2a = collusion["standard_rsp"]
    aura_2a = collusion["aura_rsp"]
    figure_a = args.output / "experiment2-figure-a-collusion-en-600dpi.png"
    draw_grouped_bars(
        categories=[
            "Order-download\njoin rate",
            "Cross-MNO history\nrecovery",
            "Multi-MNO device\nclusters",
            "Cross-profile\nlinkage",
        ],
        standard_values=[
            standard_2a["order_join_rate"],
            standard_2a["exact_device_history_recovery_rate"],
            standard_2a["multi_mno_cluster_rate"],
            standard_2a["cross_profile_pair_link_rate"],
        ],
        aura_values=[
            aura_2a["order_join_rate"],
            aura_2a["exact_device_history_recovery_rate"],
            aura_2a["multi_mno_cluster_rate"],
            aura_2a["cross_profile_pair_link_rate"],
        ],
        y_max=1.10,
        y_ticks=[0.0, 0.2, 0.4, 0.6, 0.8, 1.0],
        y_label="Rate",
        output=figure_a,
        value_decimals=3,
    )

    leakage = summary["subexperiment_2b_log_leakage"]
    standard_2b = leakage["standard_rsp"]
    aura_2b = leakage["aura_rsp"]
    figure_b = args.output / "experiment2-figure-b-leakage-radius-en-600dpi.png"
    draw_grouped_bars(
        categories=[
            "Mean profiles per\nobserved cluster",
            "Maximum profiles per\nobserved cluster",
        ],
        standard_values=[
            standard_2b["mean_profiles_per_cluster"],
            standard_2b["max_profiles_per_cluster"],
        ],
        aura_values=[
            aura_2b["mean_profiles_per_cluster"],
            aura_2b["max_profiles_per_cluster"],
        ],
        y_max=4.5,
        y_ticks=[0, 1, 2, 3, 4],
        y_label="Profiles per cluster",
        output=figure_b,
        value_decimals=1,
        image_width=3000,
    )

    write_table(summary, args.output)
    audit = {
        "status": "PASS",
        "source": str(summary_path.resolve()),
        "source_sha256": sha256(summary_path),
        "method": summary["method"],
        "design": summary["design"],
        "figure_a_sha256": sha256(figure_a),
        "figure_b_sha256": sha256(figure_b),
    }
    (args.output / "experiment2-figure-data-audit.json").write_text(
        json.dumps(audit, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "status": "PASS",
                "figure_a": str(figure_a.resolve()),
                "figure_b": str(figure_b.resolve()),
                "source": str(summary_path.resolve()),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
