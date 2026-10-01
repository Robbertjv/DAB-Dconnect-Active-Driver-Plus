#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import ast
import html
import re
from pathlib import Path


def read_robust(path):
    raw = Path(path).read_bytes()
    for encoding in (&quot;utf-8-sig&quot;, &quot;utf-8&quot;, &quot;cp1252&quot;):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode(&quot;utf-8&quot;, errors=&quot;replace&quot;)


def clean(text, remove_four_quotes=False):
    # BOM, non-breaking spaces en zero-width spaces.
    text = text.lstrip(&quot;\ufeff&quot;)
    text = text.replace(&quot;\u00a0&quot;, &quot; &quot;)
    text = text.replace(&quot;\u200b&quot;, &quot;&quot;)

    # Decodeer ook dubbel ge-escapeerde HTML-entiteiten.
    for _ in range(5):
        decoded = html.unescape(text)
        if decoded == text:
            break
        text = decoded

    # Verwijder uitsluitend bekende HTML-wrappers.
    text = re.sub(r&quot;&lt;\s*pre(?:\s+[^&gt;]*)?&gt;&quot;, &quot;&quot;, text,
                  flags=re.IGNORECASE)
    text = re.sub(r&quot;&lt;\s*/\s*pre\s*&gt;&quot;, &quot;&quot;, text,
                  flags=re.IGNORECASE)
    text = re.sub(r&quot;&lt;\s*code(?:\s+[^&gt;]*)?&gt;&quot;, &quot;&quot;, text,
                  flags=re.IGNORECASE)
    text = re.sub(r&quot;&lt;\s*/\s*code\s*&gt;&quot;, &quot;&quot;, text,
                  flags=re.IGNORECASE)

    # Verwijder Markdown-fences die op een eigen regel staan.
    text = re.sub(
        r&quot;^[ \t]*```(?:python|py)?[ \t]*$&quot;,
        &quot;&quot;,
        text,
        flags=re.IGNORECASE | re.MULTILINE,
    )

    # Vier quotes zijn meestal beschadigde triple-quote delimiters.
    if remove_four_quotes:
        text = text.replace(&quot;''''&quot;, &quot;&quot;)
        text = text.replace('\&quot;\&quot;\&quot;\&quot;', &quot;&quot;)
    else:
        text = text.replace(&quot;''''&quot;, &quot;'''&quot;)
        text = text.replace('\&quot;\&quot;\&quot;\&quot;', '\&quot;\&quot;\&quot;')

    # Windows-regeleinden normaliseren.
    text = text.replace(&quot;\r\n&quot;, &quot;\n&quot;).replace(&quot;\r&quot;, &quot;\n&quot;)
    return text.strip(&quot;\n&quot;) + &quot;\n&quot;


def main():
    parser = argparse.ArgumentParser(
        description=&quot;Verwijder HTML-rommel uit Python-code en schrijf UTF-8.&quot;
    )
    parser.add_argument(&quot;input&quot;, help=&quot;vervuild invoerbestand&quot;)
    parser.add_argument(&quot;output&quot;, help=&quot;schoon .py-bestand&quot;)
    parser.add_argument(
        &quot;--remove-four-quotes&quot;,
        action=&quot;store_true&quot;,
        help=&quot;verwijder vier quotes in plaats van ze naar triple quotes te repareren&quot;,
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        parser.error(f&quot;invoerbestand bestaat niet: {input_path}&quot;)
    if input_path.resolve() == output_path.resolve():
        parser.error(&quot;gebruik verschillende invoer- en uitvoerbestanden&quot;)

    cleaned = clean(
        read_robust(input_path),
        remove_four_quotes=args.remove_four_quotes,
    )

    output_path.write_text(cleaned, encoding=&quot;utf-8&quot;, newline=&quot;\n&quot;)
    print(f&quot;[OK] UTF-8-bestand geschreven: {output_path}&quot;)

    try:
        ast.parse(cleaned, filename=str(output_path))
    except SyntaxError as exc:
        print(&quot;[FOUT] Er bestaat nog een Python-syntaxfout:&quot;)
        print(f&quot;       regel {exc.lineno}, kolom {exc.offset}: {exc.msg}&quot;)
        if exc.text:
            print(f&quot;       {exc.text.rstrip()}&quot;)
        return 1

    print(&quot;[OK] Python-syntaxcontrole geslaagd.&quot;)
    return 0


if __name__ == &quot;__main__&quot;:
    raise SystemExit(main())
