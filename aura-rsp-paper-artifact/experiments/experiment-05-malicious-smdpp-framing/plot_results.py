#!/usr/bin/env python3
"""Render compact 600-DPI Experiment 5 paper figures with Pillow."""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from pathlib import Path

from PIL import Image, ImageChops, ImageDraw, ImageFont


WHITE = (255, 255, 255)
TEXT = (35, 35, 35)
GRID = (210, 210, 210)
BLUE = (76, 114, 176)
ORANGE = (221, 132, 82)
GREEN = (85, 168, 104)
RED = (196, 78, 82)
PURPLE = (129, 114, 179)


def font(size: int, bold: bool = False):
    mpl_fonts = Path(sys.prefix) / "Lib/site-packages/matplotlib/mpl-data/fonts/ttf"
    names = ["DejaVuSerif-Bold.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSerif-Bold.ttf", str(mpl_fonts / "DejaVuSerif-Bold.ttf"), "C:/Windows/Fonts/timesbd.ttf"] if bold else ["DejaVuSerif.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSerif.ttf", str(mpl_fonts / "DejaVuSerif.ttf"), "C:/Windows/Fonts/times.ttf"]
    for name in names:
        try: return ImageFont.truetype(name, size)
        except OSError: pass
    raise RuntimeError("DejaVu Serif font not found")


def save_trimmed(image: Image.Image, path: Path, pad: int = 18):
    rgb = image.convert("RGB"); diff = ImageChops.difference(rgb, Image.new("RGB", rgb.size, WHITE)); box = diff.getbbox()
    if box:
        rgb = rgb.crop((max(0,box[0]-pad), max(0,box[1]-pad), min(rgb.width,box[2]+pad), min(rgb.height,box[3]+pad)))
    path.parent.mkdir(parents=True, exist_ok=True); rgb.save(path, dpi=(600,600), optimize=True)


def vertical_label(image, text, fnt):
    box=fnt.getbbox(text); layer=Image.new("RGBA",(box[2]-box[0]+30,box[3]-box[1]+30),(255,255,255,0)); d=ImageDraw.Draw(layer)
    d.text((15-box[0],15-box[1]),text,font=fnt,fill=TEXT); layer=layer.rotate(90,expand=True,resample=Image.Resampling.BICUBIC)
    image.alpha_composite(layer,(18,(image.height-layer.height)//2))


def line_figure(rows, output, language):
    image=Image.new("RGBA",(3900,2450),WHITE+(255,)); d=ImageDraw.Draw(image)
    left,right,top,bottom=430,3800,270,2100; counts=sorted({int(r["malicious_challenges"]) for r in rows}); modes=["full_aura","without_local_ticket_log","key_only_cache_no_context_check"]
    labels={"full_aura":("完整 AURA-RSP" if language=="zh" else "Full AURA-RSP"),"without_local_ticket_log":("无 LocalTicketLog" if language=="zh" else "Without LocalTicketLog"),"key_only_cache_no_context_check":("仅按键缓存" if language=="zh" else "Key-only cache")}; colors=dict(zip(modes,(BLUE,ORANGE,GREEN)))
    max_y=max(int(r["distinct_valid_responses"]) for r in rows); y_ticks=[1,2,4,8,16,32,64,128]
    for value in y_ticks:
        y=bottom-(math.log2(value)/math.log2(max_y))*(bottom-top); d.line((left,y,right,y),fill=GRID,width=3); d.text((left-35,y),str(value),font=font(50),fill=TEXT,anchor="rm")
    d.line((left,top,left,bottom),fill=TEXT,width=7); d.line((left,bottom,right,bottom),fill=TEXT,width=7)
    xmap={value:left+i*(right-left)/(len(counts)-1) for i,value in enumerate(counts)}
    for value,x in xmap.items(): d.line((x,bottom,x,bottom+18),fill=TEXT,width=5); d.text((x,bottom+75),str(value),font=font(50),fill=TEXT,anchor="mm")
    by={(r["mode"],int(r["malicious_challenges"])):int(r["distinct_valid_responses"]) for r in rows}
    for mode in modes:
        points=[]
        for count in counts:
            value=by[(mode,count)]; y=bottom-(math.log2(value)/math.log2(max_y))*(bottom-top); points.append((xmap[count],y))
        line_width = 26 if mode == "full_aura" else 16 if mode == "without_local_ticket_log" else 10
        d.line(points,fill=colors[mode],width=line_width,joint="curve")
        for x,y in points:
            radius = 24 if mode == "full_aura" else 19 if mode == "without_local_ticket_log" else 13
            if mode == "full_aura":
                d.rectangle((x-radius,y-radius,x+radius,y+radius),fill=WHITE,outline=colors[mode],width=11)
            else:
                d.ellipse((x-radius,y-radius,x+radius,y+radius),fill=WHITE,outline=colors[mode],width=10 if mode == "without_local_ticket_log" else 7)
        if mode == "without_local_ticket_log":
            x,y=points[-1]; d.text((x-20,y-55),str(by[(mode,counts[-1])]),font=font(43,True),fill=colors[mode],anchor="rb")
    legend_y=105
    for i,mode in enumerate(modes):
        x=470+i*1110; d.line((x,legend_y,x+125,legend_y),fill=colors[mode],width=16); d.text((x+155,legend_y),labels[mode],font=font(52),fill=TEXT,anchor="lm")
    xlabel="同一票据的恶意挑战数" if language=="zh" else "Malicious challenges per ticket"; ylabel="不同有效响应数量（对数刻度）" if language=="zh" else "Distinct valid responses (log scale)"
    d.text(((left+right)//2,2315),xlabel,font=font(62,True),fill=TEXT,anchor="mm"); vertical_label(image,ylabel,font(62,True)); save_trimmed(image,output)


def stacked_figure(summary, output, language):
    # Figure 5(b) is intended for a narrow paper column.  Use shorter labels,
    # larger type, wider bars, and a compact canvas so it remains readable
    # after LaTeX scales it down to \columnwidth.
    image=Image.new("RGBA",(3400,2220),WHITE+(255,)); d=ImageDraw.Draw(image); left,right,top,bottom=430,3310,330,1810
    modes=["full_aura","without_local_ticket_log","key_only_cache_no_context_check"]
    mode_labels={"full_aura":("完整\nAURA-RSP" if language=="zh" else "Full\nAURA-RSP"),"without_local_ticket_log":("无\nLocalTicketLog" if language=="zh" else "Without\nLocalTicketLog"),"key_only_cache_no_context_check":("仅按键缓存" if language=="zh" else "Key-only\ncache")}
    cats=["local_context_conflict_abort","client_order_context_reject","mno_ticket_signature_reject","second_valid_response_false_trace","cached_response_invalid_for_modified_context"]
    cat_labels={"local_context_conflict_abort":("本地上下文终止" if language=="zh" else "Context abort"),"client_order_context_reject":("订单上下文拒绝" if language=="zh" else "Order reject"),"mno_ticket_signature_reject":("票据签名拒绝" if language=="zh" else "Ticket reject"),"second_valid_response_false_trace":("第二响应并误追踪" if language=="zh" else "New response + false trace"),"cached_response_invalid_for_modified_context":("缓存响应无效" if language=="zh" else "Invalid cached response")}; colors=dict(zip(cats,(BLUE,GREEN,PURPLE,RED,ORANGE)))
    for tick in range(0,101,20):
        y=bottom-tick/100*(bottom-top); d.line((left,y,right,y),fill=GRID,width=4); d.text((left-40,y),str(tick),font=font(62),fill=TEXT,anchor="rm")
    d.line((left,top,left,bottom),fill=TEXT,width=10); d.line((left,bottom,right,bottom),fill=TEXT,width=10)
    xcenters=[900,1870,2840]; width=570
    for x,mode in zip(xcenters,modes):
        aggregate=summary[mode]["outcomes"]; total=sum(aggregate.values()); y=bottom
        for cat in cats:
            count=int(aggregate.get(cat,0)); height=(count/total)*(bottom-top) if total else 0
            if height: d.rectangle((x-width/2,y-height,x+width/2,y),fill=colors[cat],outline=WHITE,width=7)
            y-=height
        d.multiline_text((x,bottom+65),mode_labels[mode],font=font(62,True),fill=TEXT,anchor="ma",align="center",spacing=4)
        rate=float(summary[mode]["false_trace_rate"]); d.text((x,top-55),f"False trace: {rate:.1%}",font=font(58,True),fill=RED if rate else TEXT,anchor="mm")
    legend_y=82
    positions=[(150,legend_y),(1080,legend_y),(1960,legend_y),(430,205),(1850,205)]
    for (x,y),cat in zip(positions,cats): d.rectangle((x,y-32,x+84,y+32),fill=colors[cat]); d.text((x+112,y),cat_labels[cat],font=font(50),fill=TEXT,anchor="lm")
    ylabel="攻击结果分布（%）" if language=="zh" else "Attack outcome distribution (%)"; vertical_label(image,ylabel,font(72,True)); save_trimmed(image,output,pad=10)


def main():
    p=argparse.ArgumentParser(); p.add_argument("--results",type=Path,required=True); p.add_argument("--language",choices=("en","zh","both"),default="both"); args=p.parse_args(); root=args.results; summary=json.loads((root/"summary.json").read_text(encoding="utf-8"))
    with (root/"raw/challenge-scaling.csv").open(encoding="utf-8-sig",newline="") as h: rows=list(csv.DictReader(h))
    languages=("en","zh") if args.language=="both" else (args.language,)
    for lang in languages:
        line_figure(rows,root/f"paper/figure-5a-challenge-scaling-{lang}-600dpi.png",lang)
        stacked_figure(summary["ablation_summary"],root/f"paper/figure-5b-ablation-outcomes-{lang}-600dpi.png",lang)
    print("EXPERIMENT05_PLOTS_PASS")


if __name__=="__main__": main()
