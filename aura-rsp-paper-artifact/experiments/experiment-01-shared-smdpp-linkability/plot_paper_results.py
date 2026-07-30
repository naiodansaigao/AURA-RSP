#!/usr/bin/env python3
"""Generate publication figures for Experiment 1.

The script reads only the machine-generated Experiment 1 results. It does not
modify the experiment, retrain the classifier, or replace measured values.

Dependencies: Python 3.10+, Pillow, NumPy.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
from pathlib import Path
from typing import Iterable

import numpy as np
from PIL import Image, ImageDraw, ImageFont


STANDARD = "#D55E00"  # Okabe-Ito vermillion
AURA = "#0072B2"  # Okabe-Ito blue
FOREGROUND = "#17212B"
MUTED = "#647383"
GRID = "#D9E0E7"
PANEL = "#FFFFFF"
BACKGROUND = "#F6F8FA"
CHANCE = "#7A8793"

WIDTH = 4500
HEIGHT = 2820
DPI = 600


def load_font(path: str, size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(path, size=size)


def font_paths() -> dict[str, str]:
    font_roots = [Path("C:/Windows/Fonts"), Path("/mnt/c/Windows/Fonts")]
    windows_fonts = next((path for path in font_roots if path.exists()), None)
    if windows_fonts is None:
        raise FileNotFoundError(
            "Windows fonts were not found at C:/Windows/Fonts or "
            "/mnt/c/Windows/Fonts"
        )
    candidates = {
        "en_regular": windows_fonts / "times.ttf",
        "en_bold": windows_fonts / "timesbd.ttf",
        "zh_regular": windows_fonts / "msyh.ttc",
        "zh_bold": windows_fonts / "msyhbd.ttc",
    }
    missing = [name for name, path in candidates.items() if not path.exists()]
    if missing:
        raise FileNotFoundError(f"missing required fonts: {', '.join(missing)}")
    return {name: str(path) for name, path in candidates.items()}


def read_predictions(path: Path) -> tuple[np.ndarray, np.ndarray]:
    labels: list[int] = []
    scores: list[float] = []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            labels.append(int(row["label_same_device"]))
            scores.append(float(row["score_same_device"]))
    return np.asarray(labels, dtype=np.int8), np.asarray(scores, dtype=float)


def roc_curve(labels: np.ndarray, scores: np.ndarray) -> list[tuple[float, float]]:
    positives = int(labels.sum())
    negatives = int(len(labels) - positives)
    if positives == 0 or negatives == 0:
        raise ValueError("ROC requires both positive and negative samples")
    order = np.argsort(-scores, kind="stable")
    sorted_labels = labels[order]
    sorted_scores = scores[order]
    points: list[tuple[float, float]] = [(0.0, 0.0)]
    tp = fp = 0
    index = 0
    while index < len(sorted_labels):
        score = sorted_scores[index]
        end = index
        while end < len(sorted_labels) and sorted_scores[end] == score:
            if sorted_labels[end] == 1:
                tp += 1
            else:
                fp += 1
            end += 1
        points.append((fp / negatives, tp / positives))
        index = end
    if points[-1] != (1.0, 1.0):
        points.append((1.0, 1.0))
    return points


def auc_rank(labels: np.ndarray, scores: np.ndarray) -> float:
    positive = scores[labels == 1]
    negative = scores[labels == 0]
    comparisons = (positive[:, None] > negative[None, :]).sum()
    ties = (positive[:, None] == negative[None, :]).sum()
    return float((comparisons + 0.5 * ties) / (len(positive) * len(negative)))


def stratified_bootstrap_auc(
    labels: np.ndarray,
    scores: np.ndarray,
    *,
    samples: int,
    seed: int,
) -> tuple[float, float]:
    rng = np.random.default_rng(seed)
    positive = scores[labels == 1]
    negative = scores[labels == 0]
    aucs = np.empty(samples, dtype=float)
    for index in range(samples):
        pos_sample = rng.choice(positive, size=len(positive), replace=True)
        neg_sample = rng.choice(negative, size=len(negative), replace=True)
        comparisons = (pos_sample[:, None] > neg_sample[None, :]).sum()
        ties = (pos_sample[:, None] == neg_sample[None, :]).sum()
        aucs[index] = (comparisons + 0.5 * ties) / (
            len(pos_sample) * len(neg_sample)
        )
    low, high = np.percentile(aucs, [2.5, 97.5])
    return float(low), float(high)


def step_points(
    points: Iterable[tuple[float, float]],
    left: int,
    top: int,
    width: int,
    height: int,
) -> list[tuple[int, int]]:
    mapped: list[tuple[int, int]] = []
    previous: tuple[float, float] | None = None
    for fpr, tpr in points:
        if previous is not None:
            mapped.append(
                (
                    round(left + fpr * width),
                    round(top + (1.0 - previous[1]) * height),
                )
            )
        mapped.append(
            (
                round(left + fpr * width),
                round(top + (1.0 - tpr) * height),
            )
        )
        previous = (fpr, tpr)
    return mapped


def text(
    draw: ImageDraw.ImageDraw,
    xy: tuple[int, int],
    value: str,
    font: ImageFont.FreeTypeFont,
    fill: str = FOREGROUND,
    *,
    anchor: str = "la",
) -> None:
    draw.text(xy, value, font=font, fill=fill, anchor=anchor)


def diamond(
    draw: ImageDraw.ImageDraw, center: tuple[int, int], radius: int, fill: str
) -> None:
    x, y = center
    draw.polygon(
        [(x, y - radius), (x + radius, y), (x, y + radius), (x - radius, y)],
        fill=fill,
    )


def draw_figure(
    *,
    language: str,
    summary: dict,
    standard_curve: list[tuple[float, float]],
    aura_curve: list[tuple[float, float]],
    standard_ci: tuple[float, float],
    aura_ci: tuple[float, float],
    output: Path,
) -> None:
    paths = font_paths()
    regular_path = paths["zh_regular" if language == "zh" else "en_regular"]
    bold_path = paths["zh_bold" if language == "zh" else "en_bold"]
    fonts = {
        "title": load_font(bold_path, 116),
        "subtitle": load_font(regular_path, 60),
        "panel": load_font(bold_path, 72),
        "axis": load_font(regular_path, 58),
        "label": load_font(regular_path, 59),
        "label_bold": load_font(bold_path, 59),
        "small": load_font(regular_path, 49),
        "value": load_font(bold_path, 54),
    }
    tr = {
        "zh": {
            "title": "共享 SM-DP+ 下的跨 Profile 关联能力",
            "subtitle": "20 个 eUICC × 4 个 MNO；每种协议 80 次事务；仅使用 SM-DP+ 可见公开转录",
            "roc_panel": "(a) 成对关联 ROC 曲线",
            "metric_panel": "(b) 关联与设备历史恢复指标",
            "x_axis": "假阳性率",
            "y_axis": "真阳性率",
            "chance": "随机猜测",
            "standard": "Standard RSP",
            "aura": "AURA-RSP",
            "metrics": [
                "ROC-AUC",
                "成对分类准确率",
                "完整设备历史恢复率",
                "跨 Profile 直接关联率",
            ],
            "footer": "固定种子 20260729；5 折交叉验证；240 个平衡测试对；误差区间为 ROC-AUC 分层自助法 95% CI",
            "near_chance": "接近随机猜测",
        },
        "en": {
            "title": "Cross-Profile Linkability at a Shared SM-DP+",
            "subtitle": "20 eUICCs × 4 MNOs; 80 transactions per mode; public transcripts visible to the SM-DP+ only",
            "roc_panel": "(a) Pairwise linkage ROC curves",
            "metric_panel": "(b) Linkage and device-history recovery",
            "x_axis": "False positive rate",
            "y_axis": "True positive rate",
            "chance": "Random guess",
            "standard": "Standard RSP",
            "aura": "AURA-RSP",
            "metrics": [
                "ROC-AUC",
                "Pairwise accuracy",
                "Exact device-history\nrecovery",
                "Direct cross-profile\nlinkage",
            ],
            "footer": "Seed 20260729; 5-fold cross-validation; 240 balanced test pairs; error ranges are stratified-bootstrap 95% CIs for ROC-AUC",
            "near_chance": "near chance",
        },
    }[language]

    image = Image.new("RGB", (WIDTH, HEIGHT), BACKGROUND)
    draw = ImageDraw.Draw(image)
    text(draw, (2250, 145), tr["title"], fonts["title"], anchor="ma")
    text(draw, (2250, 280), tr["subtitle"], fonts["subtitle"], MUTED, anchor="ma")

    panel_top = 420
    panel_bottom = 2440
    left_panel = (210, panel_top, 2205, panel_bottom)
    right_panel = (2295, panel_top, 4290, panel_bottom)
    for panel in (left_panel, right_panel):
        draw.rounded_rectangle(panel, radius=34, fill=PANEL, outline=GRID, width=4)

    text(draw, (305, 535), tr["roc_panel"], fonts["panel"])
    plot_left, plot_top = 520, 690
    plot_width, plot_height = 1425, 1250
    for tick in np.linspace(0.0, 1.0, 5):
        x = round(plot_left + tick * plot_width)
        y = round(plot_top + (1.0 - tick) * plot_height)
        draw.line((x, plot_top, x, plot_top + plot_height), fill=GRID, width=3)
        draw.line((plot_left, y, plot_left + plot_width, y), fill=GRID, width=3)
        text(draw, (x, plot_top + plot_height + 55), f"{tick:.2f}", fonts["axis"], MUTED, anchor="ma")
        text(draw, (plot_left - 45, y), f"{tick:.2f}", fonts["axis"], MUTED, anchor="ra")
    draw.line(
        (plot_left, plot_top + plot_height, plot_left + plot_width, plot_top),
        fill=CHANCE,
        width=5,
    )
    text(
        draw,
        (plot_left + 0.63 * plot_width, plot_top + 0.34 * plot_height),
        tr["chance"],
        fonts["small"],
        CHANCE,
        anchor="ma",
    )
    standard_path = step_points(
        standard_curve, plot_left, plot_top, plot_width, plot_height
    )
    aura_path = step_points(aura_curve, plot_left, plot_top, plot_width, plot_height)
    draw.line(standard_path, fill=STANDARD, width=18, joint="curve")
    draw.line(aura_path, fill=AURA, width=18, joint="curve")
    draw.line(
        (plot_left, plot_top + plot_height, plot_left + plot_width, plot_top + plot_height),
        fill=FOREGROUND,
        width=6,
    )
    draw.line(
        (plot_left, plot_top, plot_left, plot_top + plot_height),
        fill=FOREGROUND,
        width=6,
    )
    text(
        draw,
        (plot_left + plot_width // 2, plot_top + plot_height + 150),
        tr["x_axis"],
        fonts["label"],
        anchor="ma",
    )
    y_label_layer = Image.new("RGBA", (900, 160), (255, 255, 255, 0))
    y_draw = ImageDraw.Draw(y_label_layer)
    text(y_draw, (450, 80), tr["y_axis"], fonts["label"], anchor="mm")
    y_label_layer = y_label_layer.rotate(90, expand=True)
    image.paste(y_label_layer, (72, 900), y_label_layer)

    standard_auc = summary["modes"]["standard_rsp"]["pairwise_classifier"]["roc_auc"]
    aura_auc = summary["modes"]["aura_rsp"]["pairwise_classifier"]["roc_auc"]
    legend_y = 2225
    draw.line((495, legend_y, 615, legend_y), fill=STANDARD, width=18)
    text(
        draw,
        (645, legend_y),
        f'{tr["standard"]}: AUC {standard_auc:.3f} [{standard_ci[0]:.3f}, {standard_ci[1]:.3f}]',
        fonts["small"],
        anchor="lm",
    )
    aura_legend_y = 2330
    draw.line((495, aura_legend_y, 615, aura_legend_y), fill=AURA, width=18)
    text(
        draw,
        (645, aura_legend_y),
        f'{tr["aura"]}: AUC {aura_auc:.3f} [{aura_ci[0]:.3f}, {aura_ci[1]:.3f}]',
        fonts["small"],
        anchor="lm",
    )

    text(draw, (2390, 535), tr["metric_panel"], fonts["panel"])
    axis_left, axis_right = 3050, 4120
    axis_top, axis_bottom = 720, 2020
    for tick in np.linspace(0.0, 1.0, 5):
        x = round(axis_left + tick * (axis_right - axis_left))
        draw.line((x, axis_top, x, axis_bottom), fill=GRID, width=3)
        text(draw, (x, axis_bottom + 64), f"{tick:.2f}", fonts["axis"], MUTED, anchor="ma")
    draw.line((axis_left, axis_bottom, axis_right, axis_bottom), fill=FOREGROUND, width=5)

    std = summary["modes"]["standard_rsp"]
    aura = summary["modes"]["aura_rsp"]
    standard_values = [
        std["pairwise_classifier"]["roc_auc"],
        std["pairwise_classifier"]["pairwise_accuracy"],
        std["direct_stable_grouping"]["exact_device_recovery_rate"],
        std["direct_stable_grouping"]["cross_profile_link_rate"],
    ]
    aura_values = [
        aura["pairwise_classifier"]["roc_auc"],
        aura["pairwise_classifier"]["pairwise_accuracy"],
        aura["direct_stable_grouping"]["exact_device_recovery_rate"],
        aura["direct_stable_grouping"]["cross_profile_link_rate"],
    ]
    row_y = [830, 1140, 1450, 1760]
    for index, (label, std_value, aura_value, y) in enumerate(
        zip(tr["metrics"], standard_values, aura_values, row_y)
    ):
        if "\n" in label:
            draw.multiline_text(
                (2420, y),
                label,
                font=fonts["label_bold"],
                fill=FOREGROUND,
                spacing=8,
                anchor="lm",
                align="left",
            )
        else:
            text(draw, (2420, y), label, fonts["label_bold"], anchor="lm")
        x_std = round(axis_left + std_value * (axis_right - axis_left))
        x_aura = round(axis_left + aura_value * (axis_right - axis_left))
        draw.line((x_aura, y, x_std, y), fill=GRID, width=12)
        draw.ellipse(
            (x_std - 30, y - 30, x_std + 30, y + 30),
            fill=STANDARD,
            outline=PANEL,
            width=5,
        )
        diamond(draw, (x_aura, y), 36, AURA)
        standard_anchor = "ra" if std_value > 0.86 else "la"
        standard_x = x_std - 52 if standard_anchor == "ra" else x_std + 52
        aura_anchor = "la" if aura_value < 0.14 else "ra"
        aura_x = x_aura + 52 if aura_anchor == "la" else x_aura - 52
        text(
            draw,
            (standard_x, y - 58),
            f"{std_value:.3f}",
            fonts["value"],
            STANDARD,
            anchor=standard_anchor,
        )
        text(
            draw,
            (aura_x, y + 62),
            f"{aura_value:.3f}",
            fonts["value"],
            AURA,
            anchor=aura_anchor,
        )
        if index < 2:
            chance_x = round(axis_left + 0.5 * (axis_right - axis_left))
            draw.line((chance_x, y - 57, chance_x, y + 57), fill=CHANCE, width=5)

    legend_metric_y = 2260
    draw.ellipse((2595, legend_metric_y - 25, 2645, legend_metric_y + 25), fill=STANDARD)
    text(draw, (2675, legend_metric_y), tr["standard"], fonts["small"], anchor="lm")
    diamond(draw, (3320, legend_metric_y), 30, AURA)
    text(draw, (3365, legend_metric_y), tr["aura"], fonts["small"], anchor="lm")
    chance_x = 3910
    draw.line((chance_x, legend_metric_y - 32, chance_x, legend_metric_y + 32), fill=CHANCE, width=5)
    text(draw, (3920, legend_metric_y), tr["near_chance"], fonts["small"], MUTED, anchor="lm")

    draw.line((260, 2570, 4240, 2570), fill=GRID, width=3)
    text(draw, (2250, 2660), tr["footer"], fonts["small"], MUTED, anchor="ma")

    output.parent.mkdir(parents=True, exist_ok=True)
    image.save(output, format="PNG", dpi=(DPI, DPI), optimize=True)


def write_table(
    *,
    language: str,
    summary: dict,
    standard_ci: tuple[float, float],
    aura_ci: tuple[float, float],
    output_dir: Path,
) -> None:
    std = summary["modes"]["standard_rsp"]
    aura = summary["modes"]["aura_rsp"]
    if language == "zh":
        headers = ["指标", "Standard RSP", "AURA-RSP"]
        rows = [
            ["ROC-AUC", f'{std["pairwise_classifier"]["roc_auc"]:.4f}', f'{aura["pairwise_classifier"]["roc_auc"]:.4f}'],
            ["ROC-AUC 95% CI", f"[{standard_ci[0]:.4f}, {standard_ci[1]:.4f}]", f"[{aura_ci[0]:.4f}, {aura_ci[1]:.4f}]"],
            ["方向无关可利用AUC max(AUC, 1−AUC)", f'{max(std["pairwise_classifier"]["roc_auc"], 1 - std["pairwise_classifier"]["roc_auc"]):.4f}', f'{max(aura["pairwise_classifier"]["roc_auc"], 1 - aura["pairwise_classifier"]["roc_auc"]):.4f}'],
            ["成对分类准确率", f'{std["pairwise_classifier"]["pairwise_accuracy"]:.4f}', f'{aura["pairwise_classifier"]["pairwise_accuracy"]:.4f}'],
            ["B³ F1（直接稳定标识分组）", f'{std["direct_stable_grouping"]["cluster_accuracy_b3_f1"]:.4f}', f'{aura["direct_stable_grouping"]["cluster_accuracy_b3_f1"]:.4f}'],
            ["调整兰德指数（ARI）", f'{std["direct_stable_grouping"]["adjusted_rand_index"]:.4f}', f'{aura["direct_stable_grouping"]["adjusted_rand_index"]:.4f}'],
            ["完整设备历史恢复率", f'{std["direct_stable_grouping"]["exact_device_recovery_rate"]:.4f}', f'{aura["direct_stable_grouping"]["exact_device_recovery_rate"]:.4f}'],
            ["跨 Profile 直接关联率", f'{std["direct_stable_grouping"]["cross_profile_link_rate"]:.4f}', f'{aura["direct_stable_grouping"]["cross_profile_link_rate"]:.4f}'],
            ["攻击者观察簇数量", str(std["direct_stable_grouping"]["cluster_count"]), str(aura["direct_stable_grouping"]["cluster_count"])],
        ]
        stem = "experiment1-results-table-zh"
    else:
        headers = ["Metric", "Standard RSP", "AURA-RSP"]
        rows = [
            ["ROC-AUC", f'{std["pairwise_classifier"]["roc_auc"]:.4f}', f'{aura["pairwise_classifier"]["roc_auc"]:.4f}'],
            ["ROC-AUC 95% CI", f"[{standard_ci[0]:.4f}, {standard_ci[1]:.4f}]", f"[{aura_ci[0]:.4f}, {aura_ci[1]:.4f}]"],
            ["Orientation-independent AUC max(AUC, 1−AUC)", f'{max(std["pairwise_classifier"]["roc_auc"], 1 - std["pairwise_classifier"]["roc_auc"]):.4f}', f'{max(aura["pairwise_classifier"]["roc_auc"], 1 - aura["pairwise_classifier"]["roc_auc"]):.4f}'],
            ["Pairwise accuracy", f'{std["pairwise_classifier"]["pairwise_accuracy"]:.4f}', f'{aura["pairwise_classifier"]["pairwise_accuracy"]:.4f}'],
            ["B³ F1 (direct stable-ID grouping)", f'{std["direct_stable_grouping"]["cluster_accuracy_b3_f1"]:.4f}', f'{aura["direct_stable_grouping"]["cluster_accuracy_b3_f1"]:.4f}'],
            ["Adjusted Rand index (ARI)", f'{std["direct_stable_grouping"]["adjusted_rand_index"]:.4f}', f'{aura["direct_stable_grouping"]["adjusted_rand_index"]:.4f}'],
            ["Exact device-history recovery", f'{std["direct_stable_grouping"]["exact_device_recovery_rate"]:.4f}', f'{aura["direct_stable_grouping"]["exact_device_recovery_rate"]:.4f}'],
            ["Direct cross-profile linkage", f'{std["direct_stable_grouping"]["cross_profile_link_rate"]:.4f}', f'{aura["direct_stable_grouping"]["cross_profile_link_rate"]:.4f}'],
            ["Attacker-observed clusters", str(std["direct_stable_grouping"]["cluster_count"]), str(aura["direct_stable_grouping"]["cluster_count"])],
        ]
        stem = "experiment1-results-table-en"

    output_dir.mkdir(parents=True, exist_ok=True)
    with (output_dir / f"{stem}.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(headers)
        writer.writerows(rows)
    markdown = [
        f"| {headers[0]} | {headers[1]} | {headers[2]} |",
        "|---|---:|---:|",
        *[f"| {row[0]} | {row[1]} | {row[2]} |" for row in rows],
        "",
    ]
    (output_dir / f"{stem}.md").write_text("\n".join(markdown), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path, default=Path("results/latest"))
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("results/latest/publication"),
    )
    parser.add_argument("--bootstrap-samples", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=20260729)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    summary = json.loads((args.results / "summary.json").read_text(encoding="utf-8"))
    standard_labels, standard_scores = read_predictions(
        args.results / "analysis" / "standard_rsp_pair_predictions.csv"
    )
    aura_labels, aura_scores = read_predictions(
        args.results / "analysis" / "aura_rsp_pair_predictions.csv"
    )
    standard_auc = auc_rank(standard_labels, standard_scores)
    aura_auc = auc_rank(aura_labels, aura_scores)
    if not math.isclose(
        standard_auc,
        summary["modes"]["standard_rsp"]["pairwise_classifier"]["roc_auc"],
        abs_tol=1e-6,
    ):
        raise AssertionError("recomputed Standard RSP ROC-AUC does not match summary")
    if not math.isclose(
        aura_auc,
        summary["modes"]["aura_rsp"]["pairwise_classifier"]["roc_auc"],
        abs_tol=1e-6,
    ):
        raise AssertionError("recomputed AURA-RSP ROC-AUC does not match summary")

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
    standard_curve = roc_curve(standard_labels, standard_scores)
    aura_curve = roc_curve(aura_labels, aura_scores)
    for language in ("zh", "en"):
        draw_figure(
            language=language,
            summary=summary,
            standard_curve=standard_curve,
            aura_curve=aura_curve,
            standard_ci=standard_ci,
            aura_ci=aura_ci,
            output=args.output
            / f"experiment1-cross-profile-linkability-{language}-600dpi.png",
        )
        write_table(
            language=language,
            summary=summary,
            standard_ci=standard_ci,
            aura_ci=aura_ci,
            output_dir=args.output,
        )

    figure_data = {
        "experiment": summary["experiment"],
        "source": str(args.results),
        "dpi": DPI,
        "pixel_size": [WIDTH, HEIGHT],
        "bootstrap_samples": args.bootstrap_samples,
        "seed": args.seed,
        "design": summary["design"],
        "standard_rsp": {
            "roc_auc": standard_auc,
            "roc_auc_95_ci": list(standard_ci),
            "orientation_independent_auc": max(standard_auc, 1.0 - standard_auc),
            "pairwise_accuracy": summary["modes"]["standard_rsp"]["pairwise_classifier"]["pairwise_accuracy"],
            "exact_device_history_recovery": summary["modes"]["standard_rsp"]["direct_stable_grouping"]["exact_device_recovery_rate"],
            "direct_cross_profile_linkage": summary["modes"]["standard_rsp"]["direct_stable_grouping"]["cross_profile_link_rate"],
        },
        "aura_rsp": {
            "roc_auc": aura_auc,
            "roc_auc_95_ci": list(aura_ci),
            "orientation_independent_auc": max(aura_auc, 1.0 - aura_auc),
            "pairwise_accuracy": summary["modes"]["aura_rsp"]["pairwise_classifier"]["pairwise_accuracy"],
            "exact_device_history_recovery": summary["modes"]["aura_rsp"]["direct_stable_grouping"]["exact_device_recovery_rate"],
            "direct_cross_profile_linkage": summary["modes"]["aura_rsp"]["direct_stable_grouping"]["cross_profile_link_rate"],
        },
    }
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "experiment1-figure-data.json").write_text(
        json.dumps(figure_data, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    zh_caption = f"""图X 共享SM-DP+下Standard RSP与AURA-RSP的跨Profile关联能力对比。
实验包含{summary["design"]["device_count"]}个eUICC，每个设备分别从{len(summary["design"]["mnos"])}个MNO获取独立Profile，每种协议产生{summary["design"]["transaction_count_per_mode"]}条受控公开转录。(a) Standard RSP基于稳定EID、证书和设备公钥得到ROC-AUC={standard_auc:.3f}；AURA-RSP的ROC-AUC={aura_auc:.3f}（分层自助法95% CI [{aura_ci[0]:.3f}, {aura_ci[1]:.3f}]）。由于AURA-RSP样本AUC低于0.5，若允许攻击者后验反转评分方向，其方向无关可利用AUC为{max(aura_auc, 1.0 - aura_auc):.3f}，仍接近随机基线并显著低于Standard RSP。(b) Standard RSP的完整设备历史恢复率和跨Profile直接关联率均为1.000，而AURA-RSP均为0。结果表明，稳定设备标识使共享SM-DP+能够重建Standard RSP中的跨MNO/Profile设备历史；在本实验受控公开转录中，AURA-RSP未提供可直接复用的设备级稳定标识。

边界：该结果针对协议可见字段，不覆盖PR与SM-DP+合谋、入口/出口流量联合观察或诚实eUICC端点秘密泄露。
"""
    en_caption = f"""Figure X. Cross-profile linkability of Standard RSP and AURA-RSP at a shared SM-DP+.
The experiment uses {summary["design"]["device_count"]} eUICCs, {len(summary["design"]["mnos"])} MNOs per device, and {summary["design"]["transaction_count_per_mode"]} controlled public transcripts per protocol mode. (a) Stable EIDs, certificates, and device public keys give Standard RSP an ROC-AUC of {standard_auc:.3f}; AURA-RSP obtains an ROC-AUC of {aura_auc:.3f} (stratified-bootstrap 95% CI [{aura_ci[0]:.3f}, {aura_ci[1]:.3f}]). Because the sampled AURA-RSP AUC is below 0.5, an analyst allowed to reverse the score direction post hoc obtains an orientation-independent AUC of {max(aura_auc, 1.0 - aura_auc):.3f}, which remains near chance and far below Standard RSP. (b) Exact device-history recovery and direct cross-profile linkage are both 1.000 for Standard RSP and 0 for AURA-RSP. The results show that stable device identifiers let a shared SM-DP+ reconstruct cross-MNO/profile histories in Standard RSP, whereas no directly reusable device-level stable identifier was observed in the controlled AURA-RSP public transcripts.

Scope: the result evaluates protocol-visible fields and does not cover PR–SM-DP+ collusion, joint ingress/egress traffic observation, or compromise of honest eUICC secrets.
"""
    (args.output / "experiment1-paper-caption-zh.txt").write_text(
        zh_caption, encoding="utf-8"
    )
    (args.output / "experiment1-paper-caption-en.txt").write_text(
        en_caption, encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "status": "PASS",
                "output": str(args.output.resolve()),
                "png_dpi": DPI,
                "pixel_size": [WIDTH, HEIGHT],
                "standard_roc_auc": round(standard_auc, 6),
                "aura_roc_auc": round(aura_auc, 6),
                "aura_roc_auc_95_ci": [round(x, 6) for x in aura_ci],
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
