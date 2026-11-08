#!/usr/bin/env python3
"""
Demo Media Generator for vuln-scan-prioritizer.
Renders an animated terminal recording GIF (assets/demo.gif) and HD MP4 (assets/demo.mp4)
illustrating scanner ingestion, contextual prioritization, CISA KEV matching,
and unified patch ticket generation.
Zero emoji, enterprise aesthetic.
"""

import os
import subprocess
import sys
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

SKILL_ROOT = Path(__file__).resolve().parent.parent
ASSETS_DIR = SKILL_ROOT / "assets"
ASSETS_DIR.mkdir(parents=True, exist_ok=True)

WIDTH, HEIGHT = 900, 520
BG_COLOR = (15, 20, 25)
PANEL_HEADER = (25, 33, 44)
TEXT_COLOR = (220, 225, 230)
DIM_TEXT = (110, 120, 135)
GREEN_ACCENT = (50, 205, 120)
YELLOW_ACCENT = (245, 180, 50)
RED_ACCENT = (255, 80, 80)
BLUE_ACCENT = (70, 160, 245)
BORDER_COLOR = (40, 50, 65)


def get_font(size: int = 14):
    try:
        # Standard Windows fonts
        return ImageFont.truetype("consola.ttf", size)
    except IOError:
        try:
            return ImageFont.truetype("Courier New.ttf", size)
        except IOError:
            return ImageFont.load_default()


def create_terminal_base():
    img = Image.new("RGB", (WIDTH, HEIGHT), BG_COLOR)
    draw = ImageDraw.Draw(img)

    # Header bar
    draw.rectangle([0, 0, WIDTH, 36], fill=PANEL_HEADER)
    draw.line([0, 36, WIDTH, 36], fill=BORDER_COLOR, width=1)

    # Window control circles (muted gray/enterprise style)
    draw.ellipse([14, 12, 24, 22], fill=(60, 70, 85))
    draw.ellipse([32, 12, 42, 22], fill=(60, 70, 85))
    draw.ellipse([50, 12, 60, 22], fill=(60, 70, 85))

    font_title = get_font(12)
    title_text = "secops-analyst@enterprise-triage: ~/vuln-scan-prioritizer"
    draw.text((WIDTH // 2 - 190, 11), title_text, fill=DIM_TEXT, font=font_title)

    return img


def render_frames():
    font = get_font(13)
    frames = []

    script_lines = [
        ("secops@audit-node:~$ python scripts/vuln_prioritizer.py -i scan_export.csv --sanitize", TEXT_COLOR),
        ("================================================================================", BORDER_COLOR),
        ("VULNERABILITY SCAN PRIORITIZATION & REMEDIATION REPORT", TEXT_COLOR),
        ("================================================================================", BORDER_COLOR),
        ("Scanner Dialect Detected : NESSUS (Autodetected Column Schema)", BLUE_ACCENT),
        ("Total Raw CSV Rows       : 11 findings", TEXT_COLOR),
        ("Unified Patch Bundles    : 9 consolidated packages", TEXT_COLOR),
        ("Deduplication Efficiency : 18.2% reduction in ticket fatigue", GREEN_ACCENT),
        ("Active CISA KEV Exploits : 6 threats actively weaponized in wild", RED_ACCENT),
        ("--------------------------------------------------------------------------------", BORDER_COLOR),
        ("REMEDIATION SLA WAVES (UNIFIED ACTION BUNDLES):", YELLOW_ACCENT),
        ("  * Wave 1 (Emergency 24h)    :    6 action bundle(s)", RED_ACCENT),
        ("  * Wave 2 (Urgent 7d)        :    1 action bundle(s)", YELLOW_ACCENT),
        ("  * Wave 3 (Standard 30d)     :    0 action bundle(s)", DIM_TEXT),
        ("  * Wave 4 (Backlog / Info)   :    2 action bundle(s)", DIM_TEXT),
        ("--------------------------------------------------------------------------------", BORDER_COLOR),
        ("PRIORITY WAVE     SCORE  KEV   TARGET HOST            PACKAGE / SOLUTION", TEXT_COLOR),
        ("--------------------------------------------------------------------------------", BORDER_COLOR),
        ("#1       Wave 1   15.0   YES   host-8f4b.corp.example Apache Log4j2 Library", RED_ACCENT),
        ("#2       Wave 1   14.8   YES   host-8f4b.corp.example Spring Framework", RED_ACCENT),
        ("#3       Wave 1   14.8   YES   host-3a1c.corp.example cURL / libcurl", RED_ACCENT),
        ("#4       Wave 1   12.8   NO    host-9e2d.corp.example PostgreSQL Database", YELLOW_ACCENT),
        ("#5       Wave 1   12.5   YES   host-3a1c.corp.example HTTP/2 Web Server Stack", RED_ACCENT),
        ("================================================================================", BORDER_COLOR),
        ("[SUCCESS] Exported prioritized ITSM tickets to tickets-remediation.md", GREEN_ACCENT),
    ]

    # Progressive reveal
    for count in range(1, len(script_lines) + 1):
        frame = create_terminal_base()
        draw = ImageDraw.Draw(frame)

        y = 50
        for idx in range(count):
            line_text, line_color = script_lines[idx]
            draw.text((25, y), line_text, fill=line_color, font=font)
            y += 19

        # Blinking cursor on last line
        if count < len(script_lines):
            draw.rectangle([25, y, 33, y + 15], fill=GREEN_ACCENT)

        # Hold earlier frames for 1 tick, final frame for longer
        duration = 1 if count < len(script_lines) else 15
        for _ in range(duration):
            frames.append(frame)

    return frames


def build_media():
    print("Generating demo frames for vuln-scan-prioritizer...")
    frames = render_frames()
    gif_path = ASSETS_DIR / "demo.gif"
    mp4_path = ASSETS_DIR / "demo.mp4"

    # Save GIF
    frames[0].save(
        gif_path,
        save_all=True,
        append_images=frames[1:],
        duration=180,
        loop=0,
        optimize=True
    )
    print(f"Generated demo GIF: {gif_path} ({gif_path.stat().st_size / 1024:.1f} KB)")

    # Render MP4 via ffmpeg
    temp_dir = Path(__file__).parent / "_temp_frames"
    temp_dir.mkdir(parents=True, exist_ok=True)
    try:
        for idx, f in enumerate(frames):
            f.save(temp_dir / f"frame_{idx:04d}.png")

        cmd = [
            "ffmpeg", "-y",
            "-framerate", "5",
            "-i", str(temp_dir / "frame_%04d.png"),
            "-c:v", "libx264",
            "-pix_fmt", "yuv420p",
            "-crf", "18",
            str(mp4_path)
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0:
            print(f"Generated demo MP4: {mp4_path} ({mp4_path.stat().st_size / 1024:.1f} KB)")
        else:
            print(f"Warning: ffmpeg error: {res.stderr}")
    finally:
        for p in temp_dir.glob("*.png"):
            p.unlink()
        temp_dir.rmdir()


if __name__ == "__main__":
    build_media()
