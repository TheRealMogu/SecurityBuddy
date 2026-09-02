#!/usr/bin/env python3
"""Check the rectangles the PDF tools draw over recognised text against Poppler.

The boxes come from the code the browser paints with: readableRuns() picks the
runs, runBox() gives the geometry (tests/pdf/boxes.mjs prints them as JSON).
Poppler is an independent parser, so agreement here is evidence about the file
rather than about our own reading of it.

Words are attributed to a box by TEXT, not by position: a box is anchored on
the Poppler word sequence that spells the run out, on the run's own baseline.
Matching by an x-window instead would let a too-narrow box exclude the word it
fails to cover and then pass — the check would confirm itself. With the text as
the anchor, a box that stops short of its own last word fails.

  horizontal  the box must cover its words' ink, allowing TOL_PT of slack;
              overshoot is reported but not failed (an advance width legally
              exceeds the ink it ends with).
  vertical    every matched word's own box must sit inside the drawn box.

Usage: pdf_boxes_check.py <fixture.pdf> <boxes.json>
"""
import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

TOL_PT = 1.0            # rounding, not a wrong rectangle
ANCHOR_PT = 2.0         # how close a word must start to the run's left edge
OVERSHOOT_REPORT = 6.0  # wider than this and the box is worth looking at


def poppler_words(pdf, page_no):
    out = subprocess.run(
        ['pdftotext', '-bbox-layout', '-f', str(page_no), '-l', str(page_no), pdf, '-'],
        capture_output=True, text=True, check=True).stdout
    words = []
    for w in ET.fromstring(out).iter():
        if not w.tag.rpartition('}')[2] == 'word':
            continue
        words.append({
            'text': (w.text or '').strip(),
            'x0': float(w.get('xMin')), 'x1': float(w.get('xMax')),
            'y0': float(w.get('yMin')), 'y1': float(w.get('yMax')),
            'used': False,
        })
    return sorted(words, key=lambda w: (round(w['y1'], 1), w['x0']))


def squash(text):
    return re.sub(r'\s+', '', text)


def match_words(box, words, height):
    """The Poppler words that spell this run out, starting at its left edge."""
    top, bottom = height - box['top'], height - box['bottom']
    mid = (top + bottom) / 2
    want = squash(box['text'])
    if not want:
        return None

    line = [w for w in words if w['y0'] <= mid <= w['y1'] and not w['used']]
    starts = [i for i, w in enumerate(line) if abs(w['x0'] - box['x']) <= ANCHOR_PT]
    for start in starts:
        got, taken = '', []
        for w in line[start:]:
            got += squash(w['text'])
            taken.append(w)
            if got == want:
                for t in taken:
                    t['used'] = True
                return taken
            if not want.startswith(got):
                break
    return None


def main():
    pdf, boxes_json = sys.argv[1], sys.argv[2]
    data = json.load(open(boxes_json))
    height = data['pageHeight']
    page_no = data['pageIndex'] + 1
    words = poppler_words(pdf, page_no)

    print(f'{pdf}  page {page_no}  '
          f'{len(data["boxes"])} drawn box(es), {len(words)} Poppler word(s)')
    failures, unmatched, wide = 0, 0, 0

    for box in data['boxes']:
        hits = match_words(box, words, height)
        if not hits:
            unmatched += 1
            print(f'  ??   box {box["id"]:>2} {box["font"]:<22} '
                  f'no Poppler words spell {box["text"][:34]!r} '
                  f'at x={box["x"]:.1f} (invisible={box["invisible"]})')
            continue

        left, right = box['x'], box['x'] + box['width']
        top, bottom = height - box['top'], height - box['bottom']
        ink_l, ink_r = min(w['x0'] for w in hits), max(w['x1'] for w in hits)
        ink_t, ink_b = min(w['y0'] for w in hits), max(w['y1'] for w in hits)

        dl, dr = ink_l - left, right - ink_r
        dt, db = ink_t - top, bottom - ink_b
        ok = min(dl, dr, dt, db) >= -TOL_PT
        failures += 0 if ok else 1
        if ok and dr > OVERSHOOT_REPORT:
            wide += 1
        flag = 'PASS' if ok else 'FAIL'
        if ok and dr > OVERSHOOT_REPORT:
            flag = 'WIDE'
        print(f'  {flag} box {box["id"]:>2} {box["font"]:<22} {box["size"]:>6}pt  '
              f'box x[{left:7.1f},{right:7.1f}] ink x[{ink_l:7.1f},{ink_r:7.1f}]  '
              f'dx L{dl:+6.1f} R{dr:+6.1f}  dy T{dt:+5.1f} B{db:+5.1f}  '
              f'{box["text"][:26]!r}')

    stray = [w for w in words if not w['used']]
    print(f'  => {failures} box(es) cut off their own text; '
          f'{wide} more than {OVERSHOOT_REPORT:.0f}pt too wide; '
          f'{unmatched} box(es) unmatched; {len(stray)} Poppler word(s) under no box')
    if stray:
        print('     stray: ' + ', '.join(repr(w['text'][:14]) for w in stray[:8]))
    return 1 if failures or unmatched or stray else 0


if __name__ == '__main__':
    sys.exit(main())
