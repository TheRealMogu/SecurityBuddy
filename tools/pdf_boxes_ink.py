#!/usr/bin/env python3
"""Pixel check: does the ink Poppler renders fall inside the rectangles we draw?

The word-box comparison in pdf_boxes_check.py asks Poppler's text layer where
the words are. This asks the renderer instead: it rasterises the page with
pdftoppm and counts dark pixels inside each drawn rectangle against the dark
pixels on the same scan lines outside every rectangle. Ink on a text line that
no rectangle covers is the failure this catches — a box that is too short leaves
its own last characters outside, and they show up here as escaped ink.

It also writes a PNG with the rectangles drawn on top, so the fit can be looked
at rather than only counted.

Usage: pdf_boxes_ink.py <fixture.pdf> <boxes.json> [--dpi 150] [--out marked.png]
"""
import argparse
import json
import subprocess
import sys
import zlib

DARK = 160          # 0-255; below this a pixel counts as ink
PAD_PT = 0.0        # no slack: the box is judged as drawn
FRINGE_PX = 24      # antialiasing along a right edge, not a clipped character


def read_pgm(data):
    """P5 greyscale, as pdftoppm -gray writes it."""
    fields, pos = [], 0
    while len(fields) < 4:
        while data[pos:pos + 1].isspace():
            pos += 1
        if data[pos:pos + 1] == b'#':
            pos = data.index(b'\n', pos) + 1
            continue
        start = pos
        while not data[pos:pos + 1].isspace():
            pos += 1
        fields.append(data[start:pos])
    pos += 1
    w, h = int(fields[1]), int(fields[2])
    return w, h, data[pos:pos + w * h]


def png(width, height, rgb):
    def chunk(tag, body):
        c = tag + body
        return len(body).to_bytes(4, 'big') + c + zlib.crc32(c).to_bytes(4, 'big')
    raw = b''.join(b'\x00' + rgb[y * width * 3:(y + 1) * width * 3] for y in range(height))
    return (b'\x89PNG\r\n\x1a\n'
            + chunk(b'IHDR', width.to_bytes(4, 'big') + height.to_bytes(4, 'big')
                    + bytes([8, 2, 0, 0, 0]))
            + chunk(b'IDAT', zlib.compress(raw, 6))
            + chunk(b'IEND', b''))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('pdf')
    ap.add_argument('boxes')
    ap.add_argument('--dpi', type=int, default=150)
    ap.add_argument('--out')
    args = ap.parse_args()

    data = json.load(open(args.boxes))
    page_no = data['pageIndex'] + 1
    scale = args.dpi / 72.0

    raw = subprocess.run(
        ['pdftoppm', '-gray', '-r', str(args.dpi), '-f', str(page_no), '-l', str(page_no),
         args.pdf], capture_output=True, check=True).stdout
    w, h, pix = read_pgm(raw)

    rects = []
    for box in data['boxes']:
        x0 = int((box['x'] - PAD_PT) * scale)
        x1 = int((box['x'] + box['width'] + PAD_PT) * scale + 0.5)
        # PDF y grows upward; the raster's first row is the top of the page.
        y0 = int((data['pageHeight'] - box['top'] - PAD_PT) * scale)
        y1 = int((data['pageHeight'] - box['bottom'] + PAD_PT) * scale + 0.5)
        rects.append((box, max(0, x0), min(w, x1), max(0, y0), min(h, y1)))

    covered = bytearray(w * h)
    for _, x0, x1, y0, y1 in rects:
        for y in range(y0, y1):
            base = y * w
            covered[base + x0:base + x1] = b'\x01' * max(0, x1 - x0)

    # An annotation paints its own frame and fill, often on the same scan lines
    # as the label beside it. That ink is not a character any box failed to
    # cover, so it is counted apart rather than blamed on the rectangles.
    annot = bytearray(w * h)
    for a in data.get('annotations', []):
        ax0 = max(0, int(a['x'] * scale))
        ax1 = min(w, int((a['x'] + a['width']) * scale + 0.5))
        ay0 = max(0, int((data['pageHeight'] - a['bottom'] - a['height']) * scale))
        ay1 = min(h, int((data['pageHeight'] - a['bottom']) * scale + 0.5))
        for y in range(ay0, ay1):
            base = y * w
            annot[base + ax0:base + ax1] = b'\x01' * max(0, ax1 - ax0)

    # Only the scan lines a box occupies are judged: ink elsewhere on the page
    # (images, rules, a paragraph nobody drew a box for) is not this check's
    # business.
    rows = set()
    for _, _, _, y0, y1 in rects:
        rows.update(range(y0, y1))

    inside = outside = in_annot = 0
    escaped_rows = {}
    for y in rows:
        base = y * w
        for x in range(w):
            if pix[base + x] >= DARK:
                continue
            if covered[base + x]:
                inside += 1
            elif annot[base + x]:
                in_annot += 1
            else:
                outside += 1
                escaped_rows[y] = escaped_rows.get(y, 0) + 1

    total = inside + outside
    print(f'{args.pdf}  page {page_no}  {args.dpi} dpi  {len(rects)} rectangle(s), '
          f'{len(data.get("annotations", []))} annotation(s)')
    print(f'  ink on box scan lines: {total}px  '
          f'inside {inside} ({100 * inside / total if total else 100:.2f}%)  '
          f'escaped {outside} ({100 * outside / total if total else 0:.2f}%)')
    if in_annot:
        print(f'  a further {in_annot}px on those lines is inside an annotation '
              f'rectangle — a widget\'s own frame and fill, not text')
    # Annotations are accounted for above, but a rule or an image crossing a
    # box's scan lines still counts as escaped ink without being a character
    # the box failed to cover. The per-box figure below is the precise one.
    if escaped_rows:
        worst = sorted(escaped_rows.items(), key=lambda kv: -kv[1])[:4]
        print('  rows with the most escaped ink: '
              + ', '.join(f'y={y} ({n}px, {y / scale:.1f}pt from top)' for y, n in worst))

    for box, x0, x1, y0, y1 in rects:
        box_ink = esc = 0
        for y in range(y0, y1):
            base = y * w
            for x in range(x0, x1):
                if pix[base + x] < DARK:
                    box_ink += 1
        # ink on this box's rows, to its right, that no rectangle covers
        for y in range(y0, y1):
            base = y * w
            for x in range(x1, min(w, x1 + int(40 * scale))):
                if pix[base + x] < DARK and not covered[base + x] and not annot[base + x]:
                    esc += 1
        # A few pixels past the right edge are the antialiased tail of the last
        # glyph. A clipped character costs hundreds.
        flag = 'FAIL' if esc > FRINGE_PX else 'PASS'
        print(f'  {flag} box {box["id"]:>2} {box["font"]:<22} '
              f'ink inside {box_ink:>6}px, escaping to the right {esc:>5}px  '
              f'{box["text"][:26]!r}')

    if args.out:
        rgb = bytearray()
        for y in range(h):
            for x in range(w):
                v = pix[y * w + x]
                rgb += bytes((v, v, v))
        for _, x0, x1, y0, y1 in rects:
            for x in range(x0, x1):
                for y in (y0, y1 - 1):
                    if 0 <= y < h:
                        i = (y * w + x) * 3
                        rgb[i:i + 3] = b'\xe0\x30\x30'
            for y in range(y0, y1):
                for x in (x0, x1 - 1):
                    if 0 <= x < w:
                        i = (y * w + x) * 3
                        rgb[i:i + 3] = b'\xe0\x30\x30'
        open(args.out, 'wb').write(png(w, h, bytes(rgb)))
        print(f'  wrote {args.out}')

    return 0


if __name__ == '__main__':
    sys.exit(main())
