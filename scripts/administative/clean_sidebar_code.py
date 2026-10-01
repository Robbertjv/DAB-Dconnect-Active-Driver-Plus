#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import ast
import html
import re
import shutil
import sys
from pathlib import Path


HTML_BREAK_RE = re.compile(
    r"<\s*br(?:\s+[^>]*)?/?>",
    flags=re.IGNORECASE,
)

HTML_BLOCK_RE = re.compile(
    r"<\s*/?\s*(?:pre|code|span|div)(?:\s+[^>]*)?>",
    flags=re.IGNORECASE,
)

MARKDOWN_FENCE_RE = re.compile(
    r"^[ \t]*```(?:python|py|powershell|ps1)?[ \t]*$",
    flags=re.IGNORECASE | re.MULTILINE,
)


def read_text_robust(path: Path) -> str:
    raw = path.read_bytes()

    for encoding in ("utf-8-sig", "utf-8", "cp1252"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue

    return raw.decode("utf-8", errors="replace")


def repeatedly_unescape_html(text: str, maximum: int = 8) -> str:
    for _ in range(maximum):
        decoded = html.unescape(text)
        if decoded == text:
            break
        text = decoded
    return text


def clean_sidebar_code(text: str) -> str:
    # Verwijder een eventuele BOM en onzichtbare webtekens.
    text = text.lstrip("\ufeff")
    text = text.replace("\u00a0", " ")
    text = text.replace("\u200b", "")
    text = text.replace("\u200c", "")
    text = text.replace("\u200d", "")

    # Decodeer ook dubbel of meervoudig gecodeerde HTML-entiteiten.
    text = repeatedly_unescape_html(text)

    # Zet HTML-regelafbrekingen om voordat de overige wrappers verdwijnen.
    text = HTML_BREAK_RE.sub("\n", text)
    text = HTML_BLOCK_RE.sub("", text)

    # Een verwijderde wrapper kan opnieuw gecodeerde inhoud blootleggen.
    text = repeatedly_unescape_html(text)
    text = HTML_BREAK_RE.sub("\n", text)
    text = HTML_BLOCK_RE.sub("", text)

    # Verwijder alleen Markdown-fences die op een zelfstandige regel staan.
    text = MARKDOWN_FENCE_RE.sub("", text)

    # Normaliseer regeleinden. Quotes en docstrings blijven volledig intact.
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text.strip("\n") + "\n"


def validate_python(text: str, filename: str):
    try:
        ast.parse(text, filename=filename)
        return True, ""
    except SyntaxError as exc:
        line = exc.lineno or 0
        column = exc.offset or 0
        details = f"regel {line}, kolom {column}: {exc.msg}"
        if exc.text:
            details += f"\n    {exc.text.rstrip()}"
        return False, details


def default_output_path(source: Path) -> Path:
    if source.suffix:
        return source.with_name(f"{source.stem}.clean{source.suffix}")
    return source.with_name(f"{source.name}.clean")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Strip HTML-entiteiten en presentatie-tags uit code die uit "
            "de sidebar is gekopieerd. Quotes en docstrings blijven intact."
        )
    )
    parser.add_argument("input", type=Path, help="vervuild bronbestand")
    parser.add_argument(
        "output",
        type=Path,
        nargs="?",
        help="uitvoerbestand; standaard: <naam>.clean.<extensie>",
    )
    parser.add_argument(
        "--in-place",
        action="store_true",
        help="overschrijf het bronbestand; standaard wordt eerst een .bak gemaakt",
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="maak bij --in-place geen back-up",
    )
    parser.add_argument(
        "--skip-validation",
        action="store_true",
        help="sla Python-syntaxcontrole over",
    )
    args = parser.parse_args()

    source = args.input
    if not source.exists():
        parser.error(f"invoerbestand bestaat niet: {source}")
    if not source.is_file():
        parser.error(f"invoerpad is geen bestand: {source}")
    if args.in_place and args.output is not None:
        parser.error("gebruik óf een outputbestand óf --in-place, niet beide")

    destination = source if args.in_place else (args.output or default_output_path(source))

    try:
        same_file = source.resolve() == destination.resolve()
    except FileNotFoundError:
        same_file = False

    if same_file and not args.in_place:
        parser.error("gebruik --in-place om het bronbestand te overschrijven")

    original = read_text_robust(source)
    cleaned = clean_sidebar_code(original)

    if args.in_place and not args.no_backup:
        backup = source.with_suffix(source.suffix + ".bak")
        shutil.copy2(source, backup)
        print(f"[OK] Back-up: {backup}")

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(cleaned, encoding="utf-8", newline="\n")
    print(f"[OK] UTF-8-uitvoer: {destination}")

    should_validate = destination.suffix.lower() == ".py" and not args.skip_validation
    if should_validate:
        valid, error = validate_python(cleaned, str(destination))
        if not valid:
            print("[FOUT] HTML is opgeschoond, maar Python-syntax is nog ongeldig:", file=sys.stderr)
            print(error, file=sys.stderr)
            print("[INFO] Het opgeschoonde bestand is wel bewaard.", file=sys.stderr)
            return 1
        print("[OK] Python-syntaxcontrole geslaagd.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
