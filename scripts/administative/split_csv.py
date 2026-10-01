#!/usr/bin/env python3

import csv
import argparse
import re
from pathlib import Path


def parse_size(size_string):
    """
    Convert a size string such as:
        100
        100K
        100KB
        10M
        10MB
        1G
        1GB

    into bytes.
    """

    size_string = size_string.strip().upper()

    match = re.fullmatch(r"(\d+(?:\.\d+)?)\s*(B|KB|MB|GB)?", size_string)

    if not match:
        raise ValueError(
            f"Invalid size: '{size_string}'. "
            "Use values such as 100, 100KB, 10MB or 1GB."
        )

    number = float(match.group(1))
    unit = match.group(2) or "B"

    multipliers = {
        "B": 1,
        "KB": 1024,
        "MB": 1024 ** 2,
        "GB": 1024 ** 3,
    }

    return int(number * multipliers[unit])


def split_by_lines(input_file, output_dir, max_lines):
    """
    Split CSV based on the number of data rows.
    The header is written to every output file.
    """

    part_number = 1
    row_count = 0
    output_file = None
    writer = None
    output_path = None

    with open(
        input_file,
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as csvfile:

        reader = csv.reader(csvfile)

        try:
            header = next(reader)
        except StopIteration:
            print("Error: CSV file is empty.")
            return

        for row in reader:

            # Create a new output file
            if row_count == 0:

                output_filename = (
                    f"{input_file.stem}_part_{part_number}"
                    f"{input_file.suffix}"
                )

                output_path = output_dir / output_filename

                output_file = open(
                    output_path,
                    "w",
                    encoding="utf-8",
                    newline=""
                )

                writer = csv.writer(output_file)

                # Write header
                writer.writerow(header)

                print(f"Creating: {output_path}")

            writer.writerow(row)
            row_count += 1

            # Maximum number of rows reached
            if row_count >= max_lines:

                output_file.close()

                print(
                    f"  -> {row_count:,} rows written "
                    f"to {output_path.name}"
                )

                part_number += 1
                row_count = 0
                output_file = None
                writer = None

        # Close final file
        if output_file is not None:
            output_file.close()

            print(
                f"  -> {row_count:,} rows written "
                f"to {output_path.name}"
            )


def split_by_size(input_file, output_dir, max_size):
    """
    Split CSV based on the size of the output files in bytes.

    The header is written to every output file.
    """

    part_number = 1
    output_file = None
    writer = None
    output_path = None
    current_size = 0

    with open(
        input_file,
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as csvfile:

        reader = csv.reader(csvfile)

        try:
            header = next(reader)
        except StopIteration:
            print("Error: CSV file is empty.")
            return

        for row in reader:

            # Convert row to CSV text first so we know
            # how many bytes it will occupy.
            import io

            buffer = io.StringIO()
            temp_writer = csv.writer(buffer)
            temp_writer.writerow(row)

            row_data = buffer.getvalue()
            row_bytes = row_data.encode("utf-8")

            # Create a new file if necessary
            if output_file is None:

                output_filename = (
                    f"{input_file.stem}_part_{part_number}"
                    f"{input_file.suffix}"
                )

                output_path = output_dir / output_filename

                output_file = open(
                    output_path,
                    "w",
                    encoding="utf-8",
                    newline=""
                )

                writer = csv.writer(output_file)

                # Write header
                writer.writerow(header)

                output_file.flush()

                # Determine actual header size
                current_size = output_path.stat().st_size

                print(f"Creating: {output_path}")

            # If adding this row would exceed the limit,
            # start a new file first.
            if (
                current_size > 0
                and current_size + len(row_bytes) > max_size
            ):

                output_file.close()

                actual_size = output_path.stat().st_size

                print(
                    f"  -> {actual_size:,} bytes written "
                    f"to {output_path.name}"
                )

                part_number += 1

                output_file = None
                writer = None
                current_size = 0

                # Create new output file
                output_filename = (
                    f"{input_file.stem}_part_{part_number}"
                    f"{input_file.suffix}"
                )

                output_path = output_dir / output_filename

                output_file = open(
                    output_path,
                    "w",
                    encoding="utf-8",
                    newline=""
                )

                writer = csv.writer(output_file)

                writer.writerow(header)
                output_file.flush()

                current_size = output_path.stat().st_size

                print(f"Creating: {output_path}")

            writer.writerow(row)

            current_size += len(row_bytes)

        # Close final file
        if output_file is not None:

            output_file.close()

            actual_size = output_path.stat().st_size

            print(
                f"  -> {actual_size:,} bytes written "
                f"to {output_path.name}"
            )


def main():

    parser = argparse.ArgumentParser(
        description=(
            "Split a CSV file into multiple pieces while "
            "keeping the header in every piece."
        )
    )

    parser.add_argument(
        "input",
        help="Input CSV file"
    )

    parser.add_argument(
        "--size",
        required=True,
        help=(
            "Maximum size of each piece. "
            "For --mode lines use a number such as 10000. "
            "For --mode size use values such as 100MB, 500KB or 1GB."
        )
    )

    parser.add_argument(
        "--mode",
        required=True,
        choices=["lines", "size"],
        help=(
            "Split by number of lines or by file size."
        )
    )

    parser.add_argument(
        "-o",
        "--output",
        default="split_csv",
        help=(
            "Output directory. "
            "Default: split_csv"
        )
    )

    args = parser.parse_args()

    input_file = Path(args.input)
    output_dir = Path(args.output)

    if not input_file.exists():
        print(f"Error: input file does not exist: {input_file}")
        return

    if not input_file.is_file():
        print(f"Error: input is not a file: {input_file}")
        return

    output_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    try:

        if args.mode == "lines":

            try:
                max_lines = int(args.size)
            except ValueError:
                print(
                    "Error: line size must be an integer, "
                    "for example --size 10000"
                )
                return

            if max_lines <= 0:
                print("Error: size must be greater than 0.")
                return

            split_by_lines(
                input_file,
                output_dir,
                max_lines
            )

        elif args.mode == "size":

            try:
                max_size = parse_size(args.size)
            except ValueError as e:
                print(f"Error: {e}")
                return

            if max_size <= 0:
                print("Error: size must be greater than 0.")
                return

            split_by_size(
                input_file,
                output_dir,
                max_size
            )

    except KeyboardInterrupt:
        print("\nOperation cancelled.")

    print()
    print("Done.")


if __name__ == "__main__":
    main()
