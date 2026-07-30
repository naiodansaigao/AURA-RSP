#!/usr/bin/env python3
"""Generate publication figures for Experiment 6 from fresh summary data."""

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


def write(
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
        spacing=14,
    )


def wrapped(
    draw: ImageDraw.ImageDraw,
    value: str,
    *,
    size: int,
    max_width: int,
    bold: bool = False,
) -> str:
    words = value.split()
    lines: list[str] = []
    line = ""
    used_font = font(size, bold=bold)
    for word in words:
        candidate = word if not line else f"{line} {word}"
        if draw.textlength(candidate, font=used_font) <= max_width:
            line = candidate
        else:
            if line:
                lines.append(line)
            line = word
    if line:
        lines.append(line)
    return "\n".join(lines)


def node(
    draw: ImageDraw.ImageDraw,
    box: tuple[int, int, int, int],
    heading: str,
    detail: str,
    *,
    color: str,
    light: str,
    heading_size: int = 84,
    detail_size: int = 68,
) -> None:
    x1, y1, x2, y2 = box
    draw.rounded_rectangle(
        box,
        radius=30,
        fill=light,
        outline=color,
        width=10,
    )
    write(
        draw,
        ((x1 + x2) / 2, y1 + 85),
        heading,
        heading_size,
        bold=True,
        fill=color,
        anchor="mm",
        align="center",
    )
    detail_text = wrapped(
        draw,
        detail,
        size=detail_size,
        max_width=(x2 - x1) - 100,
    )
    write(
        draw,
        ((x1 + x2) / 2, y1 + 190),
        detail_text,
        detail_size,
        anchor="ma",
        align="center",
    )


def arrow(
    draw: ImageDraw.ImageDraw,
    start: tuple[int, int],
    end: tuple[int, int],
    *,
    color: str = MUTED,
    width: int = 13,
    dashed: bool = False,
) -> None:
    x1, y1 = start
    x2, y2 = end
    if dashed:
        segments = 11
        for index in range(segments):
            if index % 2 == 0:
                sx = x1 + (x2 - x1) * index / segments
                sy = y1 + (y2 - y1) * index / segments
                ex = x1 + (x2 - x1) * (index + 1) / segments
                ey = y1 + (y2 - y1) * (index + 1) / segments
                draw.line((sx, sy, ex, ey), fill=color, width=width)
    else:
        draw.line((start, end), fill=color, width=width)

    if abs(x2 - x1) >= abs(y2 - y1):
        sign = 1 if x2 > x1 else -1
        points = [(x2, y2), (x2 - sign * 44, y2 - 28), (x2 - sign * 44, y2 + 28)]
    else:
        sign = 1 if y2 > y1 else -1
        points = [(x2, y2), (x2 - 28, y2 - sign * 44), (x2 + 28, y2 - sign * 44)]
    draw.polygon(points, fill=color)


def badge(
    draw: ImageDraw.ImageDraw,
    center: tuple[int, int],
    value: str,
    *,
    color: str,
    light: str,
    width: int,
) -> None:
    x, y = center
    box = (x - width // 2, y - 80, x + width // 2, y + 80)
    draw.rounded_rectangle(box, radius=26, fill=light, outline=color, width=8)
    write(draw, center, value, 68, bold=True, fill=color, anchor="mm", align="center")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def draw_state_chain(summary: dict, output: Path) -> dict:
    subtests = {item["id"]: item for item in summary["aura"]["subtests"]}
    six_a = subtests["6A"]
    six_b = subtests["6B"]
    six_c = subtests["6C"]

    width, height = 5000, 3100
    image = Image.new("RGB", (width, height), WHITE)
    draw = ImageDraw.Draw(image)

    # 6A: authenticated state chain and replay handling.
    badge(draw, (760, 220), "6A  REPLAY CONTROL", color=BLUE, light=BLUE_LIGHT, width=1320)
    main_y1, main_y2 = 430, 830
    boxes = [
        (250, main_y1, 1450, main_y2),
        (1900, main_y1, 3100, main_y2),
        (3550, main_y1, 4750, main_y2),
    ]
    node(draw, boxes[0], "INSTALLED", "ctr = 1  |  predecessor hash h₁", color=BLUE, light=BLUE_LIGHT)
    node(draw, boxes[1], "ENABLED", "ctr = 2  |  authenticated successor", color=TEAL, light=TEAL_LIGHT)
    node(draw, boxes[2], "DISABLED", "ctr = 3  |  current server state", color=GREEN, light=GREEN_LIGHT)
    arrow(draw, (1450, 630), (1900, 630), color=BLUE)
    arrow(draw, (3100, 630), (3550, 630), color=TEAL)
    write(draw, (1675, 545), "valid receipt", 66, fill=MUTED, anchor="mm")
    write(draw, (3325, 545), "valid receipt", 66, fill=MUTED, anchor="mm")

    replay_box = (410, 1030, 2150, 1390)
    retry_box = (2850, 1030, 4590, 1390)
    node(
        draw,
        replay_box,
        "OLD RECEIPT REPLAY",
        "installed → enabled receipt submitted after ctr = 3",
        color=RED,
        light=RED_LIGHT,
        heading_size=76,
        detail_size=62,
    )
    node(
        draw,
        retry_box,
        "LATEST RECEIPT RETRY",
        "same disabled receipt submitted again",
        color=GREEN,
        light=GREEN_LIGHT,
        heading_size=76,
        detail_size=62,
    )
    arrow(draw, (3550, 840), (2060, 1020), color=RED, dashed=True)
    arrow(draw, (4150, 840), (3720, 1020), color=GREEN, dashed=True)
    badge(
        draw,
        (1280, 1510),
        six_a["stale_replay"]["reason"],
        color=RED,
        light=RED_LIGHT,
        width=1280,
    )
    badge(
        draw,
        (3720, 1510),
        f"IDEMPOTENT  |  ctr = {six_a['latest_replay']['response']['ctr']}",
        color=GREEN,
        light=GREEN_LIGHT,
        width=1280,
    )

    # 6C: competing transitions from the same predecessor.
    badge(draw, (810, 1810), "6C  ATOMIC FORK CONTROL", color=ORANGE, light=ORANGE_LIGHT, width=1420)
    node(
        draw,
        (240, 1980, 1400, 2370),
        "SAME PREDECESSOR",
        "installed, ctr = 1, last_hash = h₁",
        color=BLUE,
        light=BLUE_LIGHT,
        heading_size=72,
        detail_size=59,
    )
    node(
        draw,
        (1750, 1900, 2850, 2210),
        "ENABLE",
        "concurrent request",
        color=RED,
        light=RED_LIGHT,
        heading_size=72,
        detail_size=58,
    )
    node(
        draw,
        (1750, 2290, 2850, 2600),
        "DELETE",
        "concurrent request",
        color=GREEN,
        light=GREEN_LIGHT,
        heading_size=72,
        detail_size=58,
    )
    node(
        draw,
        (3310, 2090, 4700, 2490),
        "ATOMIC CAS",
        "BEGIN IMMEDIATE + conditional UPDATE",
        color=ORANGE,
        light=ORANGE_LIGHT,
        heading_size=78,
        detail_size=60,
    )
    arrow(draw, (1400, 2175), (1750, 2055), color=RED)
    arrow(draw, (1400, 2175), (1750, 2445), color=GREEN)
    arrow(draw, (2850, 2055), (3310, 2220), color=RED, dashed=True)
    arrow(draw, (2850, 2445), (3310, 2360), color=GREEN)
    write(draw, (3070, 2080), "rejected", 62, bold=True, fill=RED, anchor="mm")
    write(draw, (3070, 2510), "accepted", 62, bold=True, fill=GREEN, anchor="mm")
    badge(
        draw,
        (4005, 2650),
        f"ONE SUCCESSOR  |  {six_c['final']['state']}, ctr = {six_c['final']['ctr']}",
        color=GREEN,
        light=GREEN_LIGHT,
        width=1540,
    )

    # 6B: bottom invariant strip.
    strip_y1, strip_y2 = 2830, 3040
    draw.rectangle((150, strip_y1, 4850, strip_y2), fill=LIGHT, outline=GRID, width=8)
    fields = "st_old   st_new   ctr   last_hash   lph   rid   HMAC"
    write(draw, (420, 2910), fields, 68, bold=True, fill=MUTED, anchor="lm")
    write(
        draw,
        (4580, 2910),
        f"6B  {six_b['rejected_count']}/{six_b['tamper_count']} REJECTED  |  STATE UNCHANGED",
        74,
        bold=True,
        fill=RED,
        anchor="rm",
    )

    output.parent.mkdir(parents=True, exist_ok=True)
    image.save(output, format="PNG", dpi=(DPI, DPI), optimize=True)
    return {
        "old_receipt": six_a["stale_replay"],
        "latest_retry": six_a["latest_replay"],
        "tampering_rejected": six_b["rejected_count"],
        "tampering_total": six_b["tamper_count"],
        "concurrent_accepted_operation": six_c["accepted_operation"],
        "concurrent_rejected_operation": six_c["rejected_operation"],
        "successor_count": six_c["successor_count"],
        "final_state": six_c["final"],
    }


def draw_delete_recovery(summary: dict, output: Path) -> dict:
    subtests = {item["id"]: item for item in summary["aura"]["subtests"]}
    six_d = subtests["6D"]
    six_e = subtests["6E"]
    six_f = subtests["6F"]

    width, height = 5000, 3300
    image = Image.new("RGB", (width, height), WHITE)
    draw = ImageDraw.Draw(image)

    x_positions = [1050, 2150, 3250, 4350]
    headers = ["PERSISTED STATE", "INJECTED FAILURE", "RETRY / RECOVERY", "FINAL STATE"]
    for x, heading in zip(x_positions, headers):
        write(draw, (x, 180), heading, 78, bold=True, fill=MUTED, anchor="mm", align="center")
    for x in [1600, 2700, 3800]:
        draw.line((x, 300, x, 2960), fill=GRID, width=7)

    lanes = [
        {
            "id": "6D",
            "label": "Rprep response loss",
            "color": BLUE,
            "light": BLUE_LIGHT,
            "cells": [
                ("PENDING-DELETE", "ctr = 2; Rprep stored"),
                ("×  Rprep LOST", "server state retained"),
                ("RETRY PREPARE", "same Rprep returned"),
                ("PENDING-DELETE", "ctr remains 2"),
            ],
        },
        {
            "id": "6E-1",
            "label": "CommitReceipt loss",
            "color": TEAL,
            "light": TEAL_LIGHT,
            "cells": [
                ("PENDING-DELETE", "device deletes Profile"),
                ("×  COMMIT LOST", "server remains ctr = 2"),
                ("RETRY COMMIT", "receipt accepted once"),
                ("TOMBSTONE", "device/server converge; ctr = 3"),
            ],
        },
        {
            "id": "6E-2",
            "label": "Final acknowledgement loss",
            "color": GREEN,
            "light": GREEN_LIGHT,
            "cells": [
                ("TOMBSTONE", "commit already persisted"),
                ("×  ACK LOST", "device sees no response"),
                ("RETRY COMMIT", "idempotent final response"),
                ("TOMBSTONE", "ctr remains 3"),
            ],
        },
        {
            "id": "6F",
            "label": "Ticket expiry after prepare",
            "color": ORANGE,
            "light": ORANGE_LIGHT,
            "cells": [
                ("PENDING-DELETE", "valid Rprep retained"),
                ("TICKET EXPIRED", f"+{six_f['expired_by_seconds']} seconds"),
                ("COMMIT DELETE", "pending record authorizes recovery"),
                ("TOMBSTONE", "commit accepted; ctr = 3"),
            ],
        },
    ]

    lane_y = [600, 1210, 1820, 2430]
    box_width, box_height = 900, 350
    for lane, y in zip(lanes, lane_y):
        write(draw, (260, y), lane["id"], 88, bold=True, fill=lane["color"], anchor="mm")
        for index, ((heading, detail), x) in enumerate(zip(lane["cells"], x_positions)):
            box = (
                x - box_width // 2,
                y - box_height // 2,
                x + box_width // 2,
                y + box_height // 2,
            )
            is_failure = index == 1
            used_color = RED if is_failure and "EXPIRED" not in heading else lane["color"]
            used_light = RED_LIGHT if is_failure and "EXPIRED" not in heading else lane["light"]
            node(
                draw,
                box,
                heading,
                detail,
                color=used_color,
                light=used_light,
                heading_size=68,
                detail_size=56,
            )
            if index < 3:
                arrow(
                    draw,
                    (x + box_width // 2 + 10, y),
                    (x_positions[index + 1] - box_width // 2 - 10, y),
                    color=lane["color"],
                    width=11,
                )

    invariant_y1, invariant_y2 = 2990, 3220
    draw.rectangle((170, invariant_y1, 4830, invariant_y2), fill=LIGHT, outline=GRID, width=8)
    invariants = [
        ("Same Rprep", six_d["same_rprep_returned"]),
        ("No second ctr advance", not six_d["counter_advanced_again"]),
        ("Delete converged", summary["metrics"]["delete_recovery_converged"]),
        ("Expired-ticket commit", summary["metrics"]["expired_ticket_commit_completed"]),
    ]
    centers = [720, 1900, 3150, 4350]
    for (label_value, passed), x in zip(invariants, centers):
        mark = "PASS" if passed else "FAIL"
        write(draw, (x, 3070), label_value, 65, bold=True, anchor="mm")
        write(
            draw,
            (x, 3160),
            mark,
            68,
            bold=True,
            fill=GREEN if passed else RED,
            anchor="mm",
        )

    output.parent.mkdir(parents=True, exist_ok=True)
    image.save(output, format="PNG", dpi=(DPI, DPI), optimize=True)
    return {
        "same_rprep": six_d["same_rprep_returned"],
        "counter_advanced_again": six_d["counter_advanced_again"],
        "commit_message_loss_final": six_e["commit_message_loss"]["final"],
        "final_ack_loss_final": six_e["final_ack_loss"]["final"],
        "expired_by_seconds": six_f["expired_by_seconds"],
        "expired_ticket_commit": six_f["commit"],
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
        raise AssertionError("Experiment 6 result is not PASS")

    figure_a = args.output / "experiment6-figure-a-state-chain-resilience-en-600dpi.png"
    figure_b = args.output / "experiment6-figure-b-delete-recovery-paths-en-600dpi.png"
    state_data = draw_state_chain(summary, figure_a)
    recovery_data = draw_delete_recovery(summary, figure_b)

    audit = {
        "status": "PASS",
        "source": str(summary_path.resolve()),
        "source_sha256": sha256(summary_path),
        "figure_a": {
            "path": str(figure_a.resolve()),
            "sha256": sha256(figure_a),
            "data": state_data,
        },
        "figure_b": {
            "path": str(figure_b.resolve()),
            "sha256": sha256(figure_b),
            "data": recovery_data,
        },
    }
    args.output.mkdir(parents=True, exist_ok=True)
    audit_path = args.output / "experiment6-professional-figure-data-audit.json"
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
