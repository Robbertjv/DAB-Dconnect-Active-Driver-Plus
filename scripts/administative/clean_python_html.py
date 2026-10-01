#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
clean_python_html.py

Maakt gekopieerde Python-code schoon:
- decodeert HTML-entiteiten zoals &quot;, &lt;, &gt; en &amp;;
- verwijdert <pre>, </pre>, <code ...> en </code>;
- verwijdert Markdown-codeblokken zoals ```python en ```;
- verwijdert een eventuele UTF-8 BOM;
- vervangt non-breaking spaces door normale spaties;
- repareert vier opeenvolgende quotes naar geldige triple quotes;
- schrijft expliciet als UTF-8;
- controleert de uitvoer met ast.parse.

Gebruik:
    python clean_python_html.py vervuild.txt schoon.py

Het invoerbestand wordt niet gewijzigd.
"""

import argparse
import ast
import html
import re
import sys
from pathlib import Path


PRE_OPEN_RE = re.compile(r"<\s*pre(?:\s+[^>]*)?>", re.IGNORECASE)
PRE_CLOSE_RE = re.compile(r"<\s*/\s*pre\s*>", re.IGNORECASE)
CODE_OPEN_RE = re.compile(r"<\s*code(?:\s+[^>]*)?>", re.IGNORECASE)
CODE_CLOSE_RE = re.compile(r"<\s*/\s*code\s*>", re.IGNORECASE)

# Alleen Markdown-fences die een volledige regel vormen.
FENCE_RE = re.compile(
    r"^[ \t]*```(?:python|py)?[ \t]*$",
    re.IGNORECASE | re.MULTILINE,
)


def repeated_html_unescape(text: str, maximum: int = 5) -> str:
    """Decodeer ook dubbel-geëscapeerde tekst, zoals &amp;amp;quot;."""
    for _ in range(maximum):
        decoded = html.unescape(text)
        if decoded == text:
            break
        text = decoded
    return text


def remove_known_wrappers(text: str) -> str:
    """Verwijder alleen bekende wrappers; laat Python-vergelijkingen intact."""
    text = PRE_OPEN_RE.sub("", text)
    text = PRE_CLOSE_RE.sub("", text)
    text = CODE_OPEN_RE.sub("", text)
    text = CODE_CLOSE_RE.sub("", text)
    text = FENCE_RE.sub("", text)
    return text


def repair_quote_rubbish(text: str, remove: bool = False) -> str:
    """
    Behandel vier opeenvolgende enkele of dubbele quotes.

    Standaard worden vier quotes naar drie quotes gerepareerd, omdat een
    docstring zoals vier enkele quotes anders ongeldige Python is.

    Met --remove-four-quotes worden de reeksen letterlijk verwijderd.
    """
    replacement_single = "" if remove else "'''"
    replacement_double = "" if remove else '"""'

    text = text.replace("''''", replacement_single)
    text = text.replace('""""', replacement_double)
    return text


def normalize_text(text: str, remove_four_quotes: bool = False) -> str:
    # BOM en ongewenste Unicode-spaties opruimen.
    text = text.lstrip("\ufeff")
    text = text.replace("\u00a0", " ")
    text = text.replace("\u200b", "")

    # Eerst entities decoderen, daarna de werkelijk ontstane tags verwijderen.
    text = repeated_html_unescape(text)
    text = remove_known_wrappers(text)

    # Soms zijn wrappers na het verwijderen opnieuw als entities zichtbaar.
    text = repeated_html_unescape(text)
    text = remove_known_wrappers(text)

    text = repair_quote_rubbish(text, remove=remove_four_quotes)

    # Regeleinden normaliseren en overbodige lege regels aan begin/eind wissen.
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = text.strip("\n") + "\n"
    return text


def read_text_robust(path: Path) -> str:
    """Probeer eerst UTF-8; gebruik Windows-1252 alleen als noodoplossing."""
    raw = path.read_bytes()

    for encoding in ("utf-8-sig", "utf-8", "cp1252"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            pass

    # Laatste redmiddel: behoud zoveel mogelijk en vervang onleesbare bytes.
    return raw.decode("utf-8", errors="replace")


def validate_python(text: str, filename: str) -> tuple[bool, str]:
    try:
        ast.parse(text, filename=filename)
        return True, ""
    except SyntaxError as exc:
        line = exc.lineno or 0
        column = exc.offset or 0
        message = exc.msg or "onbekende syntaxfout"
        source_line = exc.text.rstrip() if exc.text else ""
        details = f"regel {line}, kolom {column}: {message}"
        if source_line:
            details += f"\n    {source_line}"
        return False, details


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Maak uit HTML gekopieerde Python-code schoon en schrijf UTF-8."
    )
    parser.add_argument(
        "input",
        type=Path,
        help="vervuild invoerbestand",
    )
    parser.add_argument(
        "output",
        type=Path,
        help="schoon Python-uitvoerbestand",
    )
    parser.add_argument(
        "--remove-four-quotes",
        action="store_true",
        help=(
            "verwijder vier quotes letterlijk in plaats van ze naar "
            "triple quotes te repareren"
        ),
    )
    parser.add_argument(
        "--write-even-if-invalid",
        action="store_true",
        help=(
            "schrijf ook wanneer na opschonen nog een Python-syntaxfout bestaat"
        ),
    )
    args = parser.parse_args()

    if not args.input.exists():
        print(
            f"[FOUT] Invoerbestand bestaat niet: {args.input}",
            file=sys.stderr,
        )
        return 2

    if args.input.resolve() == args.output.resolve():
        print(
            "[FOUT] Kies een ander uitvoerbestand; de invoer wordt niet overschreven.",
            file=sys.stderr,
        )
        return 2

    original = read_text_robust(args.input)

    cleaned = normalize_text(
        original,
        remove_four_quotes=args.remove_four_quotes,
    )

    valid, error = validate_python(cleaned, str(args.output))

    if not valid and not args.write_even_if_invalid:
        recovery = args.output.with_suffix(
            args.output.suffix + ".invalid.txt"
        )

        recovery.write_text(
            cleaned,
            encoding="utf-8",
            newline="\n",
        )

        print(
            "[FOUT] De opgeschoonde tekst is nog geen geldige Python:",
            file=sys.stderr,
        )
        print(error, file=sys.stderr)
        print(
            f"[INFO] Opgeschoonde tekst bewaard als: {recovery}",
            file=sys.stderr,
        )
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)

    args.output.write_text(
        cleaned,
        encoding="utf-8",
        newline="\n",
    )

    print(f"[OK] Geschreven als UTF-8: {args.output}")

    if valid:
        print("[OK] Python-syntaxcontrole geslaagd.")
    else:
        print(
            "[WAARSCHUWING] Bestand geschreven, "
            "maar syntaxcontrole faalde:"
        )
        print(error)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
