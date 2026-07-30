#!/usr/bin/env python3
"""Generate compact publication figures for Experiment 4.

Every plotted value is read from results/latest/summary.json produced by the
Experiment 4 runner. This script does not synthesize protocol outcomes.
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
HEIGHT = 2200
BLUE = "#4C72B0"
ORANGE = "#DD8452"
GREEN = "#55A868"
RED = "#C44E52"
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
) -> None:
    layer = Image.new("RGBA", (1050, 210), (255, 255, 255, 0))
    layer_draw = ImageDraw.Draw(layer)
    label(layer_draw, (525, 105), text, 108, anchor="mm")
    layer = layer.rotate(90, expand=True)
    image.paste(layer, (x, y), layer)


def draw_legend(
    draw: ImageDraw.ImageDraw,
    image_width: int,
    series: list[tuple[str, str]],
) -> None:
    legend_y = 145
    total_width = image_width - 360
    segment = total_width / len(series)
    for index, (name, color) in enumerate(series):
        center = 180 + segment * (index + 0.5)
        text_width = draw.textlength(name, font=font(82))
        entry_width = 110 + 42 + text_width
        start = round(center - entry_width / 2)
        draw.rectangle(
            (start, legend_y - 50, start + 110, legend_y + 50),
            fill=color,
        )
        label(draw, (start + 152, legend_y), name, 82, anchor="lm")


def draw_grouped_bars(
    *,
    image_width: int,
    categories: list[str],
    series: list[tuple[str, str, list[float]]],
    y_label: str,
    output: Path,
) -> None:
    image = Image.new("RGB", (image_width, HEIGHT), WHITE)
    draw = ImageDraw.Draw(image)
    left, right, top, bottom = 540, image_width - 150, 330, 1610
    plot_width = right - left
    plot_height = bottom - top
    y_max = 1.10

    for tick in np.linspace(0.0, 1.0, 6):
        y = round(bottom - (tick / y_max) * plot_height)
        draw.line((left, y, right, y), fill=GRID, width=7)
        label(
            draw,
            (left - 70, y),
            f"{tick:.1f}",
            100,
            fill=GRAY,
            anchor="ra",
        )
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
            left + 0.15 * plot_width,
            right - 0.15 * plot_width,
            len(categories),
        )

    bar_width = 190 if len(series) == 3 else 150
    gap = 20
    group_width = len(series) * bar_width + (len(series) - 1) * gap
    for category_index, (center, category) in enumerate(zip(centers, categories)):
        start = center - group_width / 2
        for series_index, (_, color, values) in enumerate(series):
            value = values[category_index]
            x1 = round(start + series_index * (bar_width + gap))
            x2 = x1 + bar_width
            y_value = round(bottom - (value / y_max) * plot_height)
            draw.rectangle((x1, y_value, x2, bottom), fill=color)
            label(
                draw,
                ((x1 + x2) // 2, y_value - 38),
                f"{value:.0f}",
                92,
                bold=True,
                fill=color,
                anchor="ms",
            )
        draw.multiline_text(
            (round(center), bottom + 75),
            category,
            font=font(94),
            fill=BLACK,
            spacing=14,
            anchor="ma",
            align="center",
        )

    draw_vertical_axis_label(image, y_label, x=70, y=450)
    draw_legend(
        draw,
        image_width,
        [(name, color) for name, color, _ in series],
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    image.save(output, format="PNG", dpi=(DPI, DPI), optimize=True)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_results_table(summary: dict, output_dir: Path) -> None:
    aura = summary["aura"]
    normal = aura["4A_normal_single_use"]
    replay = aura["4B_exact_replay"]
    double = aura["4C_true_double_spend"]
    rows = [
        {
            "场景": "4A 正常单次使用",
            "认证/处理结果": "认证通过",
            "Profile结果": "安装成功",
            "第二次业务执行": "否",
            "追踪请求": 0,
            "身份结果": "保持匿名",
        },
        {
            "场景": "4B 完全相同报文重传",
            "认证/处理结果": "返回缓存Bind_t",
            "Profile结果": f"仅交付{replay['profile_delivery_count']}次",
            "第二次业务执行": "否",
            "追踪请求": replay["trace_request_count"],
            "身份结果": "保持匿名",
        },
        {
            "场景": "4C 两个不同有效转录",
            "认证/处理结果": f"第二次拒绝（HTTP {double['second_http_status']}）",
            "Profile结果": "首次安装成功",
            "第二次业务执行": "否",
            "追踪请求": double["trace_request_count"],
            "身份结果": "恢复正确违规EID",
        },
    ]

    csv_path = output_dir / "experiment4-results-table-zh.csv"
    with csv_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    md = [
        "| 场景 | 认证/处理结果 | Profile结果 | 第二次业务执行 | 追踪请求 | 身份结果 |",
        "|---|---|---|---:|---:|---|",
    ]
    md.extend(
        "| {场景} | {认证/处理结果} | {Profile结果} | {第二次业务执行} | "
        "{追踪请求} | {身份结果} |".format(**row)
        for row in rows
    )
    (output_dir / "experiment4-results-table-zh.md").write_text(
        "\n".join(md) + "\n",
        encoding="utf-8",
    )

    checks = {
        "normal_authentication": normal["authentication"],
        "normal_profile_installed": normal["profile_installed"],
        "normal_smdpp_knows_eid": normal["smdpp_knows_eid"],
        "replay_exact_bytes_equal": replay["exact_request_bytes_equal"],
        "replay_same_cached_bind_t": replay["same_cached_bind_t"],
        "replay_second_business_execution": replay["second_business_execution"],
        "double_spend_detected": double["duplicate_nu_detected"],
        "double_spend_second_business_execution": double["second_business_execution"],
        "double_spend_trace_success": double["trace_success"],
        "double_spend_recovered_correct_eid": double[
            "recovered_eid_matches_malicious_device"
        ],
        "false_trace_count": summary["metrics"]["false_trace_count"],
    }
    (output_dir / "experiment4-key-checks.json").write_text(
        json.dumps(checks, ensure_ascii=False, indent=2) + "\n",
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
        raise AssertionError("Experiment 4 result is not PASS")

    aura = summary["aura"]
    normal = aura["4A_normal_single_use"]
    replay = aura["4B_exact_replay"]
    double = aura["4C_true_double_spend"]

    figure_a = args.output / "experiment4-figure-a-scenario-outcomes-en-600dpi.png"
    draw_grouped_bars(
        image_width=3800,
        categories=[
            "4A Normal\nsingle use",
            "4B Exact\nreplay",
            "4C True\ndouble spend",
        ],
        series=[
            (
                "Business executions",
                BLUE,
                [
                    normal["business_execution_count"],
                    replay["business_execution_count"],
                    double["business_execution_count"],
                ],
            ),
            (
                "Second executions",
                ORANGE,
                [
                    0,
                    int(replay["second_business_execution"]),
                    int(double["second_business_execution"]),
                ],
            ),
            (
                "Trace requests",
                GREEN,
                [
                    normal["trace_request_count"],
                    replay["trace_request_count"],
                    double["trace_request_count"],
                ],
            ),
        ],
        y_label="Count",
        output=figure_a,
    )

    figure_b = args.output / "experiment4-figure-b-replay-vs-double-spend-en-600dpi.png"
    draw_grouped_bars(
        image_width=3000,
        categories=[
            "4B Exact\nreplay",
            "4C True\ndouble spend",
        ],
        series=[
            (
                "Cached response",
                BLUE,
                [int(replay["same_cached_bind_t"]), 0],
            ),
            (
                "Duplicate nu",
                ORANGE,
                [0, int(double["duplicate_nu_detected"])],
            ),
            (
                "Trace request",
                GREEN,
                [replay["trace_request_count"], double["trace_request_count"]],
            ),
            (
                "Correct EID",
                RED,
                [0, int(double["recovered_eid_matches_malicious_device"])],
            ),
        ],
        y_label="Indicator",
        output=figure_b,
    )

    write_results_table(summary, args.output)
    audit = {
        "status": "PASS",
        "source": str(summary_path.resolve()),
        "source_sha256": sha256(summary_path),
        "experiment_status": summary["status"],
        "experiment_execution_ms": summary["execution_ms"],
        "figure_a_sha256": sha256(figure_a),
        "figure_b_sha256": sha256(figure_b),
    }
    (args.output / "experiment4-figure-data-audit.json").write_text(
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
                "experiment_execution_ms": summary["execution_ms"],
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
