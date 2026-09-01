#!/usr/bin/env python3
"""Compare a PDF against another, or describe one, structure by structure.

This exists because "it opens and looks right" is not evidence. A structural
operation must leave the page content untouched; this reports whether it did,
in terms specific enough to fail on.

    python3 tools/pdf_compare.py FILE                 # describe one file
    python3 tools/pdf_compare.py INPUT OUTPUT         # compare
    python3 tools/pdf_compare.py INPUT OUTPUT --pages 0,2,4
    python3 tools/pdf_compare.py INPUT OUTPUT --json

Reported per document: page count; every page's size in points; embedded fonts
with name, subtype and subset flag; annotation count; form field count and
names; document metadata. Plus two hashes that catch what names cannot:

  * SHA-256 of each page's content stream — the raw, still-encoded bytes. A
    name and a subset flag can both stay identical while the bytes change.
  * SHA-256 of every embedded font program (/FontFile, /FontFile2, /FontFile3).

For a block-1 (structural) operation these hashes MUST match between input and
output. A mismatch means the operation rewrote page content or re-embedded a
font, which is wrong however good the result looks.

--pages maps output pages back to input pages for operations that select or
reorder: --pages 3,1 says output page 0 came from input page 3, output page 1
from input page 1. Without it a same-length 1:1 mapping is assumed.

Depends on pypdf, which is a DEVELOPMENT dependency only (see pyproject.toml).
It is deliberately not in requirements.txt and never runs on the server — the
PDF feature is entirely client-side. pypdf is also a deliberately independent
implementation: verifying pdf-lib's output with pdf-lib would share its blind
spots and pass a broken file.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

try:
    from pypdf import PdfReader
    from pypdf.generic import IndirectObject
except ImportError:  # pragma: no cover
    sys.exit(
        "pdf_compare.py needs pypdf, a development-only dependency.\n"
        "  pip install pypdf\n"
        "It is intentionally absent from requirements.txt: nothing on the "
        "server touches PDFs."
    )

FONT_FILE_KEYS = ("/FontFile", "/FontFile2", "/FontFile3")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def resolve(obj):
    return obj.get_object() if isinstance(obj, IndirectObject) else obj


def content_stream_hash(page) -> str:
    """Hash a page's raw content stream bytes.

    Deliberately the encoded bytes, not the decoded ones: decoding would mask a
    re-compression, and a structural operation has no business re-compressing
    anything.
    """
    contents = page.get("/Contents")
    if contents is None:
        return "(no content stream)"
    contents = resolve(contents)
    streams = contents if isinstance(contents, list) else [contents]
    digest = hashlib.sha256()
    for stream in streams:
        stream = resolve(stream)
        raw = getattr(stream, "_data", None)
        if raw is None:
            try:
                raw = stream.get_data()
            except Exception:  # noqa: BLE001
                raw = b""
        digest.update(raw)
    return digest.hexdigest()


def collect_fonts(reader: PdfReader) -> dict:
    """Every embedded font in the document, keyed by base font name.

    A PDF font name carries a six-letter subset prefix (ABCDEF+Helvetica) when
    the embedded program holds only the glyphs the document uses. That prefix is
    the subset flag, and it matters for block 2: you cannot write a character
    whose glyph is not in the subset.
    """
    fonts: dict[str, dict] = {}
    seen_descriptors: set[int] = set()

    for page_index, page in enumerate(reader.pages):
        try:
            resources = resolve(page.get("/Resources")) or {}
            font_dict = resolve(resources.get("/Font")) or {}
        except Exception:  # noqa: BLE001
            continue

        for font_ref in font_dict.values():
            font = resolve(font_ref)
            if not hasattr(font, "get"):
                continue
            base = str(font.get("/BaseFont", "(unnamed)")).lstrip("/")
            subtype = str(font.get("/Subtype", "?")).lstrip("/")

            descriptors = []
            descriptor = resolve(font.get("/FontDescriptor"))
            if descriptor is not None:
                descriptors.append(descriptor)
            # Type0 fonts keep the descriptor on the descendant CIDFont.
            for descendant in resolve(font.get("/DescendantFonts")) or []:
                descendant = resolve(descendant)
                if hasattr(descendant, "get"):
                    child = resolve(descendant.get("/FontDescriptor"))
                    if child is not None:
                        descriptors.append(child)

            entry = fonts.setdefault(base, {
                "name": base,
                "subtype": subtype,
                # The six-uppercase-letters-plus-'+' prefix is the subset marker.
                "subset": len(base) > 7 and base[6] == "+" and base[:6].isalpha()
                          and base[:6].isupper(),
                "embedded": False,
                "programs": [],
                "pages": [],
            })
            if page_index not in entry["pages"]:
                entry["pages"].append(page_index)

            for descriptor in descriptors:
                if id(descriptor) in seen_descriptors:
                    continue
                seen_descriptors.add(id(descriptor))
                for key in FONT_FILE_KEYS:
                    program = resolve(descriptor.get(key))
                    if program is None:
                        continue
                    entry["embedded"] = True
                    raw = getattr(program, "_data", None)
                    if raw is None:
                        try:
                            raw = program.get_data()
                        except Exception:  # noqa: BLE001
                            raw = b""
                    entry["programs"].append({
                        "key": key,
                        "bytes": len(raw),
                        "sha256": sha256(raw),
                    })

    return fonts


def collect_form_fields(reader: PdfReader) -> list[str]:
    """Fully qualified field names, in document order."""
    try:
        root = reader.trailer["/Root"]
        acro = resolve(root.get("/AcroForm"))
    except Exception:  # noqa: BLE001
        return []
    if acro is None:
        return []

    names: list[str] = []
    seen: set[int] = set()

    def walk(ref, prefix: str) -> None:
        field = resolve(ref)
        if not hasattr(field, "get") or id(field) in seen:
            return
        seen.add(id(field))
        partial = field.get("/T")
        name = f"{prefix}.{partial}" if prefix and partial else (partial or prefix)
        kids = resolve(field.get("/Kids")) or []
        # A kid that is a widget annotation is part of THIS field, not a child
        # field, so it must not add a level to the qualified name.
        child_fields = [k for k in kids
                        if hasattr(resolve(k), "get") and resolve(k).get("/T") is not None]
        if child_fields:
            for kid in child_fields:
                walk(kid, str(name) if name else "")
        elif name:
            names.append(str(name))

    for field in resolve(acro.get("/Fields")) or []:
        walk(field, "")
    return names


def count_annotations(reader: PdfReader) -> int:
    total = 0
    for page in reader.pages:
        annots = resolve(page.get("/Annots"))
        if annots:
            total += len(annots)
    return total


def describe(path: Path) -> dict:
    reader = PdfReader(str(path))

    if reader.is_encrypted:
        # Report rather than attempt: an empty-password decrypt would quietly
        # describe a document the tool itself refuses to open.
        return {
            "file": path.name,
            "encrypted": True,
            "note": "Encrypted. Not opened — see SECURITY note in the tool docs.",
        }

    pages = []
    for index, page in enumerate(reader.pages):
        box = page.mediabox
        annots = resolve(page.get("/Annots")) or []
        pages.append({
            "index": index,
            "width_pt": round(float(box.width), 3),
            "height_pt": round(float(box.height), 3),
            "rotation": int(page.get("/Rotate", 0) or 0),
            "annotations": len(annots),
            "content_sha256": content_stream_hash(page),
        })

    metadata = {}
    if reader.metadata:
        for key, value in reader.metadata.items():
            try:
                metadata[str(key).lstrip("/")] = str(value)
            except Exception:  # noqa: BLE001
                metadata[str(key).lstrip("/")] = "(unreadable)"

    root = reader.trailer["/Root"]
    fields = collect_form_fields(reader)

    return {
        "file": path.name,
        "encrypted": False,
        "page_count": len(reader.pages),
        "pages": pages,
        "fonts": collect_fonts(reader),
        "annotation_count": count_annotations(reader),
        "form_field_count": len(fields),
        "form_field_names": fields,
        "metadata": metadata,
        "has_outlines": "/Outlines" in root,
        "has_acroform": "/AcroForm" in root,
        "has_struct_tree": "/StructTreeRoot" in root,
        "has_ocproperties": "/OCProperties" in root,
        "has_xmp": "/Metadata" in root,
        "has_names": "/Names" in root,
        "has_page_labels": "/PageLabels" in root,
    }


# ── Reporting ────────────────────────────────────────────────────────────────

def print_description(info: dict) -> None:
    print(f"\n{'=' * 74}\n{info['file']}\n{'=' * 74}")
    if info.get("encrypted"):
        print(f"  ENCRYPTED — {info['note']}")
        return

    print(f"  pages            {info['page_count']}")
    print(f"  annotations      {info['annotation_count']}")
    print(f"  form fields      {info['form_field_count']}"
          + (f"  {info['form_field_names']}" if info["form_field_names"] else ""))
    flags = [k.replace("has_", "") for k, v in info.items()
             if k.startswith("has_") and v]
    print(f"  structures       {', '.join(flags) if flags else '(none)'}")

    print("\n  page  size (pt)          rot  annots  content sha256")
    for page in info["pages"]:
        print(f"  {page['index']:>4}  {page['width_pt']:>8.2f} x {page['height_pt']:<8.2f} "
              f"{page['rotation']:>3}  {page['annotations']:>6}  {page['content_sha256'][:32]}")

    if info["fonts"]:
        print("\n  embedded fonts")
        for font in info["fonts"].values():
            subset = "subset" if font["subset"] else "full  "
            embedded = "embedded" if font["embedded"] else "NOT embedded"
            print(f"    {font['name']:<34} {font['subtype']:<12} {subset}  {embedded}")
            for program in font["programs"]:
                print(f"      {program['key']:<12} {program['bytes']:>8,} bytes  "
                      f"{program['sha256'][:32]}")

    if info["metadata"]:
        print("\n  metadata")
        for key, value in info["metadata"].items():
            print(f"    {key:<16} {value[:60]}")


def compare(before: dict, after: dict, mapping: list[int] | None) -> list[str]:
    """Return a list of differences. Empty list means structurally identical."""
    problems: list[str] = []

    if before.get("encrypted") or after.get("encrypted"):
        return ["one of the documents is encrypted; cannot compare"]

    if mapping is None:
        if before["page_count"] != after["page_count"]:
            problems.append(
                f"page count {before['page_count']} -> {after['page_count']} "
                f"(pass --pages to describe an intentional selection)")
        mapping = list(range(min(before["page_count"], after["page_count"])))
    elif len(mapping) != after["page_count"]:
        problems.append(
            f"--pages lists {len(mapping)} page(s) but the output has "
            f"{after['page_count']}")

    # ── The exit criterion: page content must be byte-identical.
    for out_index, in_index in enumerate(mapping):
        if out_index >= after["page_count"] or in_index >= before["page_count"]:
            continue
        src = before["pages"][in_index]
        dst = after["pages"][out_index]

        if src["content_sha256"] != dst["content_sha256"]:
            problems.append(
                f"page content CHANGED: input page {in_index} -> output page "
                f"{out_index} ({src['content_sha256'][:16]} != "
                f"{dst['content_sha256'][:16]})")

        if (src["width_pt"], src["height_pt"]) != (dst["width_pt"], dst["height_pt"]):
            problems.append(
                f"page size changed: input {in_index} "
                f"{src['width_pt']}x{src['height_pt']} -> output {out_index} "
                f"{dst['width_pt']}x{dst['height_pt']}")

        if src["annotations"] != dst["annotations"]:
            problems.append(
                f"annotation count on page {in_index} -> {out_index}: "
                f"{src['annotations']} -> {dst['annotations']}")

    # ── Font programs must be the same bytes, not merely the same names.
    for name, font in before["fonts"].items():
        used_pages = set(font["pages"]) & set(mapping)
        if not used_pages:
            continue   # this font belonged only to pages that were not kept
        out_font = after["fonts"].get(name)
        if out_font is None:
            problems.append(f"embedded font missing from output: {name}")
            continue
        # Compare the SET of distinct programs, not the list.
        #
        # A document can legitimately embed the same font program more than
        # once — one copy per page is common in files assembled page by page,
        # and merging two documents that each carry a font gives two copies.
        # Those count changes are not fidelity failures: the bytes are the same
        # and each page still points at its own copy. What must never happen is
        # a program whose BYTES differ, or one that vanishes; both still fail
        # here, because a changed or missing program changes the set.
        src_hashes = {p["sha256"] for p in font["programs"]}
        dst_hashes = {p["sha256"] for p in out_font["programs"]}
        missing = src_hashes - dst_hashes
        if missing:
            problems.append(
                f"font program CHANGED for {name}: {len(missing)} embedded "
                f"program(s) from the input are not in the output, so the font "
                f"was re-embedded or re-subset")
        elif len(font["programs"]) != len(out_font["programs"]):
            problems.append(
                f"NOTE {name}: {len(font['programs'])} embedded cop(ies) in the "
                f"input, {len(out_font['programs'])} in the output — same bytes, "
                f"different number of copies")
        if font["subset"] != out_font["subset"]:
            problems.append(
                f"subset flag changed for {name}: {font['subset']} -> "
                f"{out_font['subset']}")

    # ── Metadata and structures: report, but only fail on loss.
    # Every key on either side, not just the ones the input had: metadata the
    # operation INVENTED matters as much as metadata it lost. A tool that writes
    # its own Title or Producer over the document's own is rewriting the file's
    # identity, which is the thing this whole exercise exists to prevent.
    for key in sorted(set(before["metadata"]) | set(after["metadata"])):
        old = before["metadata"].get(key)
        new = after["metadata"].get(key)
        if old == new:
            continue
        if old is None:
            problems.append(f"metadata /{key} ADDED by the operation: {new!r}")
        elif new is None:
            problems.append(f"metadata /{key} lost: was {old!r}")
        else:
            problems.append(f"metadata /{key}: {old!r} -> {new!r}")

    for key in ("has_outlines", "has_acroform", "has_ocproperties",
                "has_page_labels", "has_names", "has_xmp"):
        if before[key] and not after[key]:
            problems.append(f"{key.replace('has_', '')} present in input, absent in output")

    if before["has_struct_tree"] and not after["has_struct_tree"]:
        problems.append("NOTE struct_tree dropped (known pdf-lib limitation, "
                        "reported to the user by the tool)")

    return problems


def run_manifest(manifest_path: Path) -> int:
    """Compare every output a fixture run produced against its input."""
    entries = json.loads(manifest_path.read_text())
    root = manifest_path.parent.parent
    cache: dict[str, dict] = {}

    def load(rel: str) -> dict:
        if rel not in cache:
            cache[rel] = describe(root / rel)
        return cache[rel]

    total = failed = refused = 0
    print(f"{'operation':<46} {'result'}")
    print("-" * 74)

    for entry in entries:
        if entry.get("refused"):
            refused += 1
            print(f"{entry['input']:<46} refused at load: {entry['refused']}")
            continue
        if entry.get("error"):
            failed += 1
            print(f"{entry['input']} {entry['op']:<20} ERROR: {entry['error']}")
            continue
        if not entry.get("output"):
            continue

        total += 1
        before = load(entry["input"])
        after = load(entry["output"])
        problems = compare(before, after, entry.get("pages"))
        real = [p for p in problems if not p.startswith("NOTE")]
        label = f"{entry['input']} -> {entry['op']}"

        if not real:
            notes = f"  ({len(problems)} note)" if problems else ""
            print(f"{label:<46} OK{notes}")
        else:
            failed += 1
            print(f"{label:<46} {len(real)} DIFFERENCE(S)")
            for problem in real:
                print(f"    - {problem}")

    print("-" * 74)
    print(f"{total} comparison(s), {failed} with differences, "
          f"{refused} input(s) refused at load.")
    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("files", nargs="*", metavar="FILE",
                        help="one file to describe, or input and output to compare")
    parser.add_argument("--pages", help="output-to-input page mapping, e.g. 3,1,0")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--manifest", help="run every comparison listed in a "
                        "manifest.json written by tests/pdf/run_fixtures.mjs")
    args = parser.parse_args()

    if args.manifest:
        return run_manifest(Path(args.manifest))

    if len(args.files) > 2:
        parser.error("pass one file to describe, or two to compare")

    descriptions = [describe(Path(f)) for f in args.files]

    if args.json:
        print(json.dumps(descriptions if len(descriptions) > 1 else descriptions[0],
                         indent=2))
        return 0

    for info in descriptions:
        print_description(info)

    if len(descriptions) == 1:
        return 0

    mapping = None
    if args.pages:
        mapping = [int(x) for x in args.pages.split(",") if x.strip() != ""]

    problems = compare(descriptions[0], descriptions[1], mapping)
    print(f"\n{'=' * 74}\nCOMPARISON\n{'=' * 74}")
    if not problems:
        print("  No differences. Page content and font programs are byte-identical.")
        return 0

    real = [p for p in problems if not p.startswith("NOTE")]
    for problem in problems:
        print(f"  {'note:' if problem.startswith('NOTE') else 'DIFF:'} "
              f"{problem.removeprefix('NOTE ')}")
    print(f"\n  {len(real)} difference(s) that need explaining.")
    return 1 if real else 0


if __name__ == "__main__":
    sys.exit(main())
