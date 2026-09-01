# PDF preservation tests

Synthetic tests for the fidelity core (`static/js/pdf/`). They run under Node
because the modules are plain ES modules; `shim.mjs` installs the vendored
pdf-lib bundle as the `window.PDFLib` global the browser would provide.

```bash
cd tests/pdf
node leak.mjs        # page-leak and content-stream identity checks
node merge.mjs       # two-document merge, collision reporting
node ocg.mjs         # optional-content groups survive extraction
node pagetype.mjs    # TYPE A / TYPE B classification vs the pypdf measurements
node fill.mjs        # form filling: original font, forced substitution, untouched fields
node roles.mjs       # baseline-first font lookup at a typographic role boundary
node overlay.mjs     # free text: original / SUBSTITUTE / ESTIMATED / DEFAULT / USER
```

Fixture builders, run once each before the tests that use them:
`mk-subset-form.mjs` (08), `mk-roles.mjs` (09), `mk-noocr.mjs` (10 — needs
`pdftoppm` output in the scratch directory).

`roles.mjs` covers the case a nearest-by-distance search gets wrong: a Times
heading sitting 10pt above a Courier code block. A click inside the codes is
geometrically closest to the heading's last word; the baseline-first rule picks
Courier. It also prints what a naive search would have answered, so the
difference is visible rather than asserted.

`overlay.mjs` checks the invariant that keeps the fidelity story intact while
adding content: every original content stream must survive byte-identical and
exactly one stream may be appended.

`mk-subset-form.mjs` builds `08-subset-font-form.pdf`, a form whose `/DA` points at the
DejaVuSans **subset** already embedded in `01-word-export.pdf`. That subset can write 41
characters and none of them is `V`, so filling it with "Verifica" is the forced-substitution
case. Run it once before `fill.mjs`.

No dependencies to install — everything comes from `static/vendor/`.

## What these cover

`mk.mjs` builds a document carrying an outline (nested, with open/closed
state), an AcroForm whose widgets sit on non-contiguous pages, named
destinations, page labels in two numbering styles, and document attributes.

`leak.mjs` is the important one. For each page selection it asserts:

1. **No unselected page reaches the output.** It hashes every source page's
   content stream, then hashes *every* `/Type /Page` object in the output —
   including ones outside the page tree — and fails if any of them matches a
   page that was not selected.
2. **Content streams are byte-identical.** The SHA-256 of each kept page's
   content stream must equal the source's. This is the block-1 exit criterion:
   a structural operation that alters a single content byte is wrong, however
   correct the output looks.

Check 1 exists because it caught a real defect: pdf-lib's page copier walks out
of a selected page through a form widget's `/Parent`, across the field tree, and
into a sibling widget's `/P` — pulling pages nobody selected into the output in
full. See `garbageCollect()` in `static/js/pdf/preserve.js`.

## What these do NOT cover

These are synthetic documents built by pdf-lib, so they exercise the logic but
not the real world: no Word export quirks, no OCR text layer, no CJK or CFF
subset fonts, no XFA, no digital signature, no encryption. Those need real
files — see "Fixture PDF per i test" in `DEVELOPMENT.md` for how to produce the
five reference documents, and use `tools/pdf_compare.py` against them.

Passing here means the logic is sound. It does not mean an operation is safe on
an arbitrary document.

## Known gap in the fixture set

`01-word-export.pdf` was produced with **LibreOffice, not Microsoft Word** — Word
was not available in the development environment. Word differs in font mapping,
in the XMP and `/Info` metadata it writes, and in how it generates the structure
tree, and all three are things the block-1 checks make claims about. Nothing
Word-specific has ever been exercised. If you have Word, regenerate that fixture
from a real export and re-run; see the warning in `DEVELOPMENT.md`.
