#!/usr/bin/env python3
"""Generate compact publication figures for integrated Experiment 2 results.

Every plotted value is read from results/latest/summary.json.  The script does
not generate, replace, or estimate experimental measurements.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path

from PIL import Image, ImageChops, ImageDraw, ImageFont


DPI = 600
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


def save_tightly_cropped(image: Image.Image, output: Path) -> None:
    difference = ImageChops.difference(
        image, Image.new(image.mode, image.size, WHITE)
    )
    bbox = difference.getbbox()
    if bbox is None:
        raise RuntimeError("refusing to save an empty figure")
    padding = 24
    cropped = image.crop(
        (
            max(0, bbox[0] - padding),
            max(0, bbox[1] - padding),
            min(image.width, bbox[2] + padding),
            min(image.height, bbox[3] + padding),
        )
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    cropped.save(output, format="PNG", dpi=(DPI, DPI), optimize=True)


def draw_legend(
    draw: ImageDraw.ImageDraw,
    *,
    standard_x: int,
    aura_x: int,
    y: int = 105,
) -> None:
    draw.rectangle((standard_x, y - 40, standard_x + 80, y + 40), fill=STANDARD)
    label(
        draw,
        (standard_x + 120, y),
        "Standard RSP",
        96,
        bold=True,
        anchor="lm",
    )
    draw.rectangle((aura_x, y - 40, aura_x + 80, y + 40), fill=AURA)
    label(
        draw,
        (aura_x + 120, y),
        "AURA-RSP",
        96,
        bold=True,
        anchor="lm",
    )


def draw_exposure_figure(
    *,
    categories: list[str],
    standard_values: list[float],
    aura_values: list[float],
    output: Path,
) -> None:
    width, height = 4050, 2400
    image = Image.new("RGB", (width, height), WHITE)
    draw = ImageDraw.Draw(image)
    left, right, top, bottom = 520, 3970, 280, 1740
    plot_width = right - left
    plot_height = bottom - top
    y_max = 13.2

    for tick in (0, 3, 6, 9, 12):
        y = round(bottom - (tick / y_max) * plot_height)
        draw.line((left, y, right, y), fill=GRID, width=5)
        label(draw, (left - 58, y), str(tick), 94, fill=GRAY, anchor="ra")
    draw.line((left, bottom, right, bottom), fill=BLACK, width=13)
    draw.line((left, top, left, bottom), fill=BLACK, width=13)

    slot = plot_width / len(categories)
    bar_width = 285
    gap = 46
    for index, (category, standard, aura) in enumerate(
        zip(categories, standard_values, aura_values)
    ):
        center = left + (index + 0.5) * slot
        std_x1 = round(center - gap / 2 - bar_width)
        std_x2 = round(center - gap / 2)
        aura_x1 = round(center + gap / 2)
        aura_x2 = round(center + gap / 2 + bar_width)
        std_y = round(bottom - (standard / y_max) * plot_height)
        aura_y = round(bottom - (aura / y_max) * plot_height)
        draw.rectangle((std_x1, std_y, std_x2, bottom), fill=STANDARD)
        draw.rectangle((aura_x1, aura_y, aura_x2, bottom), fill=AURA)
        label(
            draw,
            ((std_x1 + std_x2) // 2, std_y - 32),
            f"{standard:.1f}",
            92,
            bold=True,
            fill=STANDARD,
            anchor="ms",
        )
        label(
            draw,
            ((aura_x1 + aura_x2) // 2, aura_y - 32),
            f"{aura:.1f}",
            92,
            bold=True,
            fill=AURA,
            anchor="ms",
        )
        draw.multiline_text(
            (round(center), bottom + 72),
            category,
            font=font(84, bold=True),
            fill=BLACK,
            spacing=9,
            anchor="ma",
            align="center",
        )

    axis_layer = Image.new("RGBA", (1600, 220), (255, 255, 255, 0))
    axis_draw = ImageDraw.Draw(axis_layer)
    label(
        axis_draw,
        (800, 110),
        "Exposure per observed cluster",
        126,
        bold=True,
        anchor="mm",
    )
    axis_layer = axis_layer.rotate(90, expand=True)
    image.paste(axis_layer, (0, 220), axis_layer)
    draw_legend(draw, standard_x=1180, aura_x=2470)
    save_tightly_cropped(image, output)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_tables(summary: dict, output_dir: Path) -> None:
    c_std = summary["subexperiment_2a_collusion"]["standard_rsp"]
    c_aura = summary["subexperiment_2a_collusion"]["aura_rsp"]
    l_std = summary["subexperiment_2b_log_leakage"]["standard_rsp"]
    l_aura = summary["subexperiment_2b_log_leakage"]["aura_rsp"]
    rows = [
        ("2A", "Order-to-download join rate", c_std["order_join_rate"], c_aura["order_join_rate"]),
        ("2A", "Cross-MNO exact history recovery", c_std["exact_device_history_recovery_rate"], c_aura["exact_device_history_recovery_rate"]),
        ("2A", "Multi-MNO device-cluster rate", c_std["multi_mno_cluster_rate"], c_aura["multi_mno_cluster_rate"]),
        ("2A", "Cross-profile link rate", c_std["cross_profile_pair_link_rate"], c_aura["cross_profile_pair_link_rate"]),
        ("2B", "Full device-history recovery", l_std["exact_device_history_recovery_rate"], l_aura["exact_device_history_recovery_rate"]),
        ("2B", "Within-profile lifecycle link rate", l_std["within_profile_lifecycle_link_rate"], l_aura["within_profile_lifecycle_link_rate"]),
        ("2B", "Mean download records per cluster", l_std["mean_download_records_per_cluster"], l_aura["mean_download_records_per_cluster"]),
        ("2B", "Mean profiles per cluster", l_std["mean_profiles_per_cluster"], l_aura["mean_profiles_per_cluster"]),
        ("2B", "Mean MNOs per cluster", l_std["mean_mnos_per_cluster"], l_aura["mean_mnos_per_cluster"]),
        ("2B", "Mean lifecycle records per cluster", l_std["mean_lifecycle_records_per_cluster"], l_aura["mean_lifecycle_records_per_cluster"]),
    ]
    output_dir.mkdir(parents=True, exist_ok=True)
    with (output_dir / "experiment2-results-table-en.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as handle:
        writer = csv.writer(handle)
        writer.writerow(("Subexperiment", "Metric", "Standard RSP", "AURA-RSP"))
        writer.writerows(rows)
    md = [
        "| Subexperiment | Metric | Standard RSP | AURA-RSP |",
        "|---|---|---:|---:|",
    ]
    md.extend(
        f"| {sub} | {metric} | {std:.4f} | {aura:.4f} |"
        for sub, metric, std, aura in rows
    )
    (output_dir / "experiment2-results-table-en.md").write_text(
        "\n".join(md) + "\n", encoding="utf-8"
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

    leakage = summary["subexperiment_2b_log_leakage"]
    l_std = leakage["standard_rsp"]
    l_aura = leakage["aura_rsp"]
    figure = args.output / "experiment2-log-leakage-radius-en-600dpi.png"
    exposure_categories = [
        "Download records\nper cluster",
        "Distinct profiles\nper cluster",
        "Distinct MNOs\nper cluster",
        "Lifecycle records\nper cluster",
    ]
    exposure_standard = [
        l_std["mean_download_records_per_cluster"],
        l_std["mean_profiles_per_cluster"],
        l_std["mean_mnos_per_cluster"],
        l_std["mean_lifecycle_records_per_cluster"],
    ]
    exposure_aura = [
        l_aura["mean_download_records_per_cluster"],
        l_aura["mean_profiles_per_cluster"],
        l_aura["mean_mnos_per_cluster"],
        l_aura["mean_lifecycle_records_per_cluster"],
    ]
    draw_exposure_figure(
        categories=exposure_categories,
        standard_values=exposure_standard,
        aura_values=exposure_aura,
        output=figure,
    )

    write_tables(summary, args.output)
    audit = {
        "status": "PASS",
        "source": str(summary_path.resolve()),
        "source_sha256": sha256(summary_path),
        "method": summary["method"],
        "design": summary["design"],
        "plotted_data": {
            "log_leakage_radius": {
                "categories": exposure_categories,
                "standard_rsp": exposure_standard,
                "aura_rsp": exposure_aura,
            },
        },
        "figure": {figure.name: sha256(figure)},
    }
    (args.output / "experiment2-figure-data-audit.json").write_text(
        json.dumps(audit, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "status": "PASS",
                "figure": str(figure.resolve()),
                "source": str(summary_path.resolve()),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
