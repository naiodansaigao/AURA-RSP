#!/usr/bin/env python3
"""Generate information-dense publication figures for Experiment 4.

All numeric values and protocol outcomes are read from
results/latest/summary.json. No synthetic measurements are introduced.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


DPI = 600
WHITE = "#FFFFFF"
INK = "#202124"
MUTED = "#5F6368"
GRID = "#D9DEE5"
LIGHT = "#F5F7FA"
BLUE = "#3B6FB6"
BLUE_LIGHT = "#DCE8F6"
TEAL = "#3A8D8A"
TEAL_LIGHT = "#D9EEEC"
GREEN = "#4E8A5B"
GREEN_LIGHT = "#DDEBDD"
ORANGE = "#C77C2B"
ORANGE_LIGHT = "#F5E6D2"
RED = "#B84A4A"
RED_LIGHT = "#F3DADA"


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
        spacing=16,
    )


def wrapped_lines(
    draw: ImageDraw.ImageDraw,
    value: str,
    *,
    size: int,
    max_width: int,
    bold: bool = False,
) -> str:
    words = value.split()
    lines: list[str] = []
    current = ""
    measure_font = font(size, bold=bold)
    for word in words:
        candidate = word if not current else f"{current} {word}"
        if draw.textlength(candidate, font=measure_font) <= max_width:
            current = candidate
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    return "\n".join(lines)


def arrow(
    draw: ImageDraw.ImageDraw,
    start: tuple[int, int],
    end: tuple[int, int],
    *,
    fill: str = MUTED,
    width: int = 12,
) -> None:
    draw.line((start, end), fill=fill, width=width)
    x, y = end
    draw.polygon(
        [(x, y), (x - 28, y - 42), (x + 28, y - 42)],
        fill=fill,
    )


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def draw_runtime_breakdown(summary: dict, output: Path) -> dict:
    aura = summary["aura"]
    normal = aura["4A_normal_single_use"]
    replay = aura["4B_exact_replay"]
    double = aura["4C_true_double_spend"]

    rows = [
        {
            "label": "4A  Normal single use",
            "segments": [
                ("Proof generation", normal["proof_generate_ms"], BLUE),
                ("Server authentication", normal["authentication_wall_ms"], ORANGE),
            ],
            "outcome": "Profile installed; no trace",
        },
        {
            "label": "4B  Exact replay",
            "segments": [
                ("Proof generation", replay["proof_generate_ms"], BLUE),
                ("Replay handling", replay["replay_wall_ms"], TEAL),
            ],
            "outcome": "Cached Bind_t; no re-execution",
        },
        {
            "label": "4C  True double spend",
            "segments": [
                ("First proof generation", double["proof_generate_first_ms"], BLUE),
                ("Second proof generation", double["proof_generate_second_ms"], TEAL),
                (
                    "Second authentication / trace path",
                    double["second_authentication_wall_ms"],
                    RED,
                ),
            ],
            "outcome": "HTTP 409; correct EID recovered",
        },
    ]

    width, height = 5000, 2920
    image = Image.new("RGB", (width, height), WHITE)
    draw = ImageDraw.Draw(image)

    left, right = 1220, 4190
    top, bottom = 410, 1930
    plot_width = right - left
    x_max = 4500.0
    row_y = [690, 1160, 1630]
    bar_height = 235

    for tick in range(0, 4501, 500):
        x = round(left + tick / x_max * plot_width)
        draw.line((x, top, x, bottom), fill=GRID, width=7)
        text(draw, (x, bottom + 95), f"{tick:,}", 82, fill=MUTED, anchor="ma")
    draw.line((left, bottom, right, bottom), fill=INK, width=14)
    text(draw, ((left + right) / 2, bottom + 250), "Instrumented stage time (ms)", 104, anchor="ma")

    for index, row in enumerate(rows):
        y = row_y[index]
        text(draw, (left - 80, y - 22), row["label"], 102, bold=True, anchor="ra")
        x = left
        total = 0.0
        for _, value, color in row["segments"]:
            segment_width = round(value / x_max * plot_width)
            draw.rectangle(
                (x, y - bar_height // 2, x + segment_width, y + bar_height // 2),
                fill=color,
            )
            if segment_width >= 530:
                text(
                    draw,
                    (x + segment_width / 2, y),
                    f"{value:,.1f}",
                    82,
                    bold=True,
                    fill=WHITE,
                    anchor="mm",
                )
            x += segment_width
            total += value
        text(draw, (x + 55, y), f"{total:,.1f} ms", 94, bold=True, anchor="lm")

    legend = [
        ("First / only proof generation", BLUE),
        ("Additional proof or replay handling", TEAL),
        ("Server authentication", ORANGE),
        ("Double-spend detection and trace path", RED),
    ]
    legend_positions = [
        (500, 2430),
        (2780, 2430),
        (500, 2700),
        (2780, 2700),
    ]
    for (label_value, color), (x, legend_y) in zip(legend, legend_positions):
        draw.rectangle((x, legend_y - 42, x + 115, legend_y + 42), fill=color)
        label_wrapped = wrapped_lines(draw, label_value, size=74, max_width=1850)
        text(draw, (x + 150, legend_y), label_wrapped, 74, anchor="lm")

    output.parent.mkdir(parents=True, exist_ok=True)
    image.save(output, format="PNG", dpi=(DPI, DPI), optimize=True)
    return {
        row["label"]: {
            "total_instrumented_ms": round(
                sum(value for _, value, _ in row["segments"]), 3
            ),
            "segments": {
                name: value for name, value, _ in row["segments"]
            },
            "outcome": row["outcome"],
        }
        for row in rows
    }


def draw_protocol_trace(summary: dict, output: Path) -> dict:
    aura = summary["aura"]
    normal = aura["4A_normal_single_use"]
    replay = aura["4B_exact_replay"]
    double = aura["4C_true_double_spend"]

    width, height = 5000, 3200
    image = Image.new("RGB", (width, height), WHITE)
    draw = ImageDraw.Draw(image)

    columns = [
        {
            "x1": 170,
            "x2": 1590,
            "heading": "4A  NORMAL SINGLE USE",
            "accent": GREEN,
            "light": GREEN_LIGHT,
            "steps": [
                ("eUICC", "Generate valid anonymous proof\n(ν, opid, ctxt₁, γ₁, c₁)"),
                ("SM-DP+", "Proof valid; ν not previously used"),
                ("SM-DP+", "Store one UsedNullifier[ν] record"),
                ("SM-DP+", "Deliver and install Profile once"),
            ],
            "outcome": "ANONYMOUS ACCEPT",
            "detail": (
                f"Trace requests = {normal['trace_request_count']}   |   "
                f"SM-DP+ knows EID = {'yes' if normal['smdpp_knows_eid'] else 'no'}"
            ),
        },
        {
            "x1": 1790,
            "x2": 3210,
            "heading": "4B  EXACT MESSAGE REPLAY",
            "accent": TEAL,
            "light": TEAL_LIGHT,
            "steps": [
                ("Proxy", "Replay byte-identical authentication request"),
                ("SM-DP+", "Request SHA-256 matches cached transaction"),
                ("SM-DP+", "Return the same cached Bind_t"),
                ("SM-DP+", "No Profile redelivery; no second execution"),
            ],
            "outcome": "IDEMPOTENT REPLAY",
            "detail": (
                f"HTTP {replay['replay_http_status']}   |   "
                f"Trace requests = {replay['trace_request_count']}"
            ),
        },
        {
            "x1": 3410,
            "x2": 4830,
            "heading": "4C  TRUE DOUBLE SPEND",
            "accent": RED,
            "light": RED_LIGHT,
            "steps": [
                ("Malicious eUICC", "Reuse same ticket and ν with ctxt₂ ≠ ctxt₁"),
                ("SM-DP+", "Both proofs valid; transcripts are distinct"),
                ("SM-DP+", "Detect duplicate ν; block second execution"),
                ("EUM", "Recover k from (c, γ), then query Ltr[k]"),
                ("SM-DP+", "Return HTTP 409; recover correct EID"),
            ],
            "outcome": "CONDITIONAL TRACE",
            "detail": (
                f"Trace success = {'yes' if double['trace_success'] else 'no'}   |   "
                f"Correct EID = {'yes' if double['recovered_eid_matches_malicious_device'] else 'no'}"
            ),
        },
    ]

    step_top = 520
    step_gap = 405
    box_height = 285
    for column in columns:
        x1, x2 = column["x1"], column["x2"]
        center = (x1 + x2) // 2
        draw.rectangle((x1, 120, x2, 350), fill=column["accent"])
        text(
            draw,
            (center, 235),
            column["heading"],
            93,
            bold=True,
            fill=WHITE,
            anchor="mm",
            align="center",
        )

        for index, (actor, action) in enumerate(column["steps"]):
            y1 = step_top + index * step_gap
            y2 = y1 + box_height
            draw.rounded_rectangle(
                (x1 + 45, y1, x2 - 45, y2),
                radius=28,
                fill=column["light"],
                outline=column["accent"],
                width=9,
            )
            text(
                draw,
                (x1 + 105, y1 + 52),
                actor,
                78,
                bold=True,
                fill=column["accent"],
                anchor="la",
            )
            action_wrapped = wrapped_lines(
                draw,
                action,
                size=62,
                max_width=(x2 - x1) - 210,
            )
            text(
                draw,
                (x1 + 105, y1 + 122),
                action_wrapped,
                62,
                anchor="la",
            )
            if index < len(column["steps"]) - 1:
                arrow(
                    draw,
                    (center, y2 + 22),
                    (center, y1 + step_gap - 25),
                    fill=column["accent"],
                    width=11,
                )

        outcome_y1 = 2660
        outcome_y2 = 3060
        draw.rectangle(
            (x1, outcome_y1, x2, outcome_y2),
            fill=LIGHT,
            outline=column["accent"],
            width=10,
        )
        text(
            draw,
            (center, outcome_y1 + 115),
            column["outcome"],
            92,
            bold=True,
            fill=column["accent"],
            anchor="mm",
        )
        detail_wrapped = wrapped_lines(
            draw,
            column["detail"],
            size=62,
            max_width=(x2 - x1) - 140,
        )
        text(
            draw,
            (center, outcome_y1 + 255),
            detail_wrapped,
            62,
            anchor="mm",
            align="center",
        )

    # Two separators make the three independent subtests visually explicit.
    for x in (1690, 3310):
        draw.line((x, 80, x, 3080), fill=GRID, width=7)

    output.parent.mkdir(parents=True, exist_ok=True)
    image.save(output, format="PNG", dpi=(DPI, DPI), optimize=True)
    return {
        "normal": {
            "authentication": normal["authentication"],
            "profile_installed": normal["profile_installed"],
            "trace_requests": normal["trace_request_count"],
            "smdpp_knows_eid": normal["smdpp_knows_eid"],
        },
        "exact_replay": {
            "request_bytes_equal": replay["exact_request_bytes_equal"],
            "same_cached_bind_t": replay["same_cached_bind_t"],
            "second_business_execution": replay["second_business_execution"],
            "trace_requests": replay["trace_request_count"],
        },
        "double_spend": {
            "same_nullifier": double["same_nullifier"],
            "different_context": double["different_context"],
            "both_proofs_valid": (
                double["first_proof_valid"] and double["second_proof_valid"]
            ),
            "second_http_status": double["second_http_status"],
            "second_business_execution": double["second_business_execution"],
            "trace_success": double["trace_success"],
            "correct_eid": double["recovered_eid_matches_malicious_device"],
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
        raise AssertionError("Experiment 4 result is not PASS")

    figure_a = (
        args.output
        / "experiment4-figure-a-runtime-breakdown-en-600dpi.png"
    )
    figure_b = (
        args.output
        / "experiment4-figure-b-protocol-decision-trace-en-600dpi.png"
    )
    timing_data = draw_runtime_breakdown(summary, figure_a)
    trace_data = draw_protocol_trace(summary, figure_b)

    audit = {
        "status": "PASS",
        "source": str(summary_path.resolve()),
        "source_sha256": sha256(summary_path),
        "experiment_status": summary["status"],
        "experiment_execution_ms": summary["execution_ms"],
        "figure_a": {
            "path": str(figure_a.resolve()),
            "sha256": sha256(figure_a),
            "data": timing_data,
        },
        "figure_b": {
            "path": str(figure_b.resolve()),
            "sha256": sha256(figure_b),
            "data": trace_data,
        },
    }
    args.output.mkdir(parents=True, exist_ok=True)
    audit_path = args.output / "experiment4-professional-figure-data-audit.json"
    audit_path.write_text(
        json.dumps(audit, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "status": "PASS",
                "figure_a": str(figure_a.resolve()),
                "figure_b": str(figure_b.resolve()),
                "audit": str(audit_path.resolve()),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
