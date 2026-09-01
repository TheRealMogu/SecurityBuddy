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


def content_stream_hashes(page) -> list[str]:
    """Each content stream of a page hashed separately.

    The combined hash cannot distinguish "the page was rewritten" from "a stream
    was appended". Overlay text is appended as an extra stream precisely so the
    original bytes survive, and that claim is only checkable per stream.
    """
    contents = page.get("/Contents")
    if contents is None:
        return []
    contents = resolve(contents)
    streams = contents if isinstance(contents, list) else [contents]
    out = []
    for stream in streams:
        stream = resolve(stream)
        raw = getattr(stream, "_data", None)
        if raw is None:
            try:
                raw = stream.get_data()
            except Exception:  # noqa: BLE001
                raw = b""
        out.append(sha256(raw or b""))
    return out


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


def field_fingerprints(reader: PdfReader) -> dict:
    """Per-field /V and /AP bytes, so an untouched field can be proven untouched.

    A filling operation is allowed to change exactly the fields it was asked to
    change. Everything else in the form must come across byte for byte — both
    the value a program reads (/V) and the appearance a person sees (/AP).
    """
    try:
        acro = resolve(reader.trailer["/Root"].get("/AcroForm"))
    except Exception:  # noqa: BLE001
        return {}
    if acro is None:
        return {}

    # Which page each widget sits on, so a field that vanished can be told
    # apart from a field that was pruned with its page.
    widget_page: dict[int, int] = {}
    for index, page in enumerate(reader.pages):
        for annot in resolve(page.get("/Annots")) or []:
            widget_page[id(resolve(annot))] = index

    out: dict[str, dict] = {}
    seen: set[int] = set()

    def ap_hash(node) -> str:
        ap = resolve(node.get("/AP"))
        if ap is None:
            return "(no /AP)"
        digest = hashlib.sha256()
        for key in sorted(str(k) for k in ap.keys()):
            entry = resolve(ap.get(key))
            raw = getattr(entry, "_data", None)
            if raw is None:
                try:
                    raw = entry.get_data()
                except Exception:  # noqa: BLE001
                    raw = b""
            digest.update(key.encode())
            digest.update(raw or b"")
        return digest.hexdigest()

    def walk(ref, prefix: str) -> None:
        node = resolve(ref)
        if not hasattr(node, "get") or id(node) in seen:
            return
        seen.add(id(node))
        partial = node.get("/T")
        name = f"{prefix}.{partial}" if prefix and partial else (partial or prefix)
        kids = resolve(node.get("/Kids")) or []
        child_fields = [k for k in kids
                        if hasattr(resolve(k), "get") and resolve(k).get("/T") is not None]
        if child_fields:
            for kid in child_fields:
                walk(kid, str(name) if name else "")
            return
        if not name:
            return
        value = node.get("/V")
        widget = resolve(kids[0]) if kids else node
        out[str(name)] = {
            "value": str(value) if value is not None else None,
            "value_sha256": sha256(str(value).encode()) if value is not None else "(unset)",
            "ap_sha256": ap_hash(widget if hasattr(widget, "get") else node),
            "da": str(node.get("/DA")) if node.get("/DA") else None,
            "page": widget_page.get(id(widget), widget_page.get(id(node), -1)),
        }

    for field in resolve(acro.get("/Fields")) or []:
        walk(field, "")
    return out


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
            "content_streams": content_stream_hashes(page),
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
        "field_fingerprints": field_fingerprints(reader),
        "metadata": metadata,
        "has_outlines": "/Outlines" in root,
        "has_acroform": "/AcroForm" in root,
        "has_struct_tree": "/StructTreeRoot" in root,
        "has_ocproperties": "/OCProperties" in root,
        "has_xmp": "/Metadata" in root,
        "has_names": "/Names" in root,
        # What /Names actually held. "/Names is gone" is too blunt a fact: the
        # tool deliberately never transports document JavaScript, so a document
        # whose /Names held nothing else legitimately loses the whole node,
        # while losing /Dests or /EmbeddedFiles would be a real defect.
        "names_entries": sorted(
            str(k).lstrip("/") for k in (resolve(root.get("/Names")) or {}).keys()
        ) if "/Names" in root else [],
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


def compare(before: dict, after: dict, mapping: list[int] | None,
            written: list[dict] | None = None,
            overlay: list[dict] | None = None) -> list[str]:
    """Return a list of differences. Empty list means structurally identical.

    `written` names the fields an operation declared it would change, with how
    it wrote them. Those are exempt from the untouched check and are reported;
    every other field must be byte-identical.
    """
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
            # An overlay is allowed to APPEND a stream; it is never allowed to
            # alter one. Every original stream must still be there, byte for
            # byte, with the additions alongside.
            overlaid = {entry["page"] for entry in (overlay or [])}
            src_streams = src.get("content_streams", [])
            dst_streams = dst.get("content_streams", [])
            if out_index in overlaid and all(h in dst_streams for h in src_streams):
                added = len(dst_streams) - len(src_streams)
                problems.append(
                    f"NOTE page {out_index}: {added} content stream(s) added for the "
                    f"overlay; the original stream(s) survive byte-identical")
            else:
                problems.append(
                    f"page content CHANGED: input page {in_index} -> output page "
                    f"{out_index} ({src['content_sha256'][:16]} != "
                    f"{dst['content_sha256'][:16]})")

        if (src["width_pt"], src["height_pt"]) != (dst["width_pt"], dst["height_pt"]):
            problems.append(
                f"page size changed: input {in_index} "
                f"{src['width_pt']}x{src['height_pt']} -> output {out_index} "
                f"{dst['width_pt']}x{dst['height_pt']}")

        if src["rotation"] != dst["rotation"]:
            # Rotation is the one page attribute an operation may legitimately
            # change, so this is a note, not a failure. It is reported because
            # the alternative is a rotate that silently did nothing and still
            # passed every check.
            problems.append(
                f"NOTE rotation on input page {in_index} -> output page "
                f"{out_index}: {src['rotation']} -> {dst['rotation']} degrees")

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
                "has_page_labels", "has_xmp"):
        if not (before[key] and not after[key]):
            continue
        if key == "has_acroform" and before.get("field_fingerprints"):
            # The form dictionary is removed when every field belonged to a page
            # that is not in the output; keeping it would list fields that
            # control nothing.
            surviving = [f for f in before["field_fingerprints"].values()
                         if f.get("page", -1) in (set(mapping or []))]
            if not surviving:
                problems.append("NOTE acroform removed because no field's page is in the output")
                continue
        problems.append(f"{key.replace('has_', '')} present in input, absent in output")

    lost_names = set(before["names_entries"]) - set(after["names_entries"])
    for entry in sorted(lost_names):
        if entry == "JavaScript":
            # Stated policy, not an accident: executable code written against the
            # original page structure is never carried into a rearranged
            # document. Reported so it stays visible, but it is not a defect.
            problems.append("NOTE /Names /JavaScript not carried across "
                            "(the tool never transports document JavaScript)")
        else:
            problems.append(f"/Names /{entry} present in input, absent in output")

    # Form fields: only the declared ones may differ.
    changed_names = {entry["field"] for entry in (written or [])}
    kept_pages = set(mapping or [])
    for name, old in before.get("field_fingerprints", {}).items():
        new = after.get("field_fingerprints", {}).get(name)
        if new is None:
            # A field whose page was not kept is SUPPOSED to be gone: block 1
            # prunes it deliberately rather than leaving a widget pointing at a
            # page that is not in the file. A field whose page IS in the output
            # and vanished anyway is a real defect.
            if old.get("page", -1) >= 0 and old["page"] not in kept_pages:
                problems.append(
                    f"NOTE form field {name} was dropped with its page "
                    f"(page {old['page'] + 1} is not in the output)")
            else:
                problems.append(f"form field lost from the output: {name}")
            continue
        if name in changed_names:
            continue
        if old["value_sha256"] != new["value_sha256"]:
            problems.append(
                f"UNTOUCHED field {name} had its value changed: "
                f"{old['value']!r} -> {new['value']!r}")
        if old["ap_sha256"] != new["ap_sha256"]:
            problems.append(
                f"UNTOUCHED field {name} had its appearance stream rewritten "
                f"({old['ap_sha256'][:12]} != {new['ap_sha256'][:12]})")

    for entry in written or []:
        name = entry["field"]
        new = after.get("field_fingerprints", {}).get(name)
        if new is None:
            problems.append(f"declared-written field is missing from the output: {name}")
            continue
        old_hash = before.get("field_fingerprints", {}).get(name, {}).get("value_sha256")
        if new["value_sha256"] == old_hash:
            problems.append(f"field {name} was declared written but its value did not change")

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

    verified = failed = refused = errored = 0
    operated_on: set[str] = set()
    print(f"{'operation':<46} {'result'}")
    print("-" * 74)

    for entry in entries:
        if entry.get("refused"):
            refused += 1
            print(f"{entry['input']:<46} refused at load: {entry['refused']}")
            continue
        if entry.get("error"):
            errored += 1
            print(f"{entry['input']} {entry['op']:<20} ERROR: {entry['error']}")
            continue
        if not entry.get("output"):
            continue

        verified += 1
        operated_on.add(entry["input"])
        before = load(entry["input"])
        after = load(entry["output"])
        problems = compare(before, after, entry.get("pages"),
                           entry.get("written"), entry.get("overlay"))
        real = [p for p in problems if not p.startswith("NOTE")]
        label = f"{entry['input']} -> {entry['op']}"

        if not real:
            notes = f"  ({len(problems)} note)" if problems else ""
            print(f"{label:<46} OK{notes}")
            for record in entry.get("written") or []:
                print(f"    field {record['field']!r:<24} doc={record['docType']}  "
                      f"font={record['fontSource']:<10} category={record['category']:<10} "
                      f"face={record['face']}")
                if record.get("reason") and record["reason"] != "original":
                    missing = "".join(record.get("missing") or [])
                    extra = f"  missing={missing!r}" if missing else ""
                    print(f"          reason={record['reason']}{extra}")
            for record in entry.get("overlay") or []:
                print(f"    overlay p{record['page']} @{record['x']},{record['y']}"
                      f"{'':<8} doc={record['docType']}  "
                      f"font={record['fontSource']:<10} category={record['category']:<10} "
                      f"face={record['face']:<14} size={record['size']}")
                bits = []
                if record.get("reason") and record["reason"] != "original":
                    bits.append(f"reason={record['reason']}")
                if record.get("missing"):
                    bits.append(f"missing={''.join(record['missing'])!r}")
                if record.get("ocrRuns"):
                    bits.append(f"runs={record['ocrRuns']}")
                if record.get("basis"):
                    bits.append(f"basis={record['basis']}")
                if record.get("correctedFrom"):
                    bits.append(f"was={record['correctedFrom']}")
                if bits:
                    print(f"          {'  '.join(bits)}")
        else:
            failed += 1
            print(f"{label:<46} {len(real)} DIFFERENCE(S)")
            for problem in real:
                print(f"    - {problem}")

    # Two different kinds of result, deliberately not added together.
    #
    # A verified operation and a correctly refused input are both good outcomes,
    # but they are not the same evidence: one says an operation preserved a
    # document, the other says a document never reached an operation. Merging
    # them into a single "n/n passed" would overstate how much was exercised.
    print("-" * 74)
    print("SUMMARY")
    print(f"  Operations verified   {verified - failed} of {verified} "
          f"clean, across {len(operated_on)} input document(s)")
    if failed:
        print(f"  Operations DIFFERING  {failed}  <-- these need explaining")
    if errored:
        print(f"  Operations that threw {errored}")
    print(f"  Inputs refused        {refused} "
          f"(refused correctly = the tool declined to process them; "
          f"no operation was exercised on these)")
    return 1 if (failed or errored) else 0


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
