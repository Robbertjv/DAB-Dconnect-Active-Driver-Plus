#!/usr/bin/env python3

"""
DAB Active Driver Plus - PCAN-View TRC analyser

Doel:
- Analyseer meerdere PCAN-View .TRC bestanden
- Geen externe Python packages nodig
- Gericht op reverse-engineering van onbekend CAN-protocol

Getest uitgangspunt:
PCAN-View TRC format v1.1

Gebruik:
    python dab_can_analyse.py

De standaard directorystructuur is:

    C:\\DAB_CAN\\
        dab_can_analyse.py
        trc\\
            file1.trc
            file2.trc
        results\\

Het script maakt automatisch een results-directory.
"""

from __future__ import annotations

import csv
import math
import re
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path


# ============================================================
# CONFIGURATIE
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
TRC_DIR = BASE_DIR / "trc"
RESULTS_DIR = BASE_DIR / "results"

# Hoeveel milliseconden na het begin van een capture als
# "startup" beschouwd worden.
STARTUP_MS = 5000.0

# Minimum aantal voorkomens om iets als periodiek te onderzoeken.
MIN_TIMING_SAMPLES = 5


# ============================================================
# DATASTRUCTUREN
# ============================================================

@dataclass
class Frame:
    number: int
    time_ms: float
    direction: str
    can_id: int
    dlc: int
    data: bytes

    @property
    def id_hex(self) -> str:
        return f"{self.can_id:08X}"

    @property
    def is_extended(self) -> bool:
        return self.can_id > 0x7FF


@dataclass
class FileInfo:
    path: Path
    frames: list[Frame]


# ============================================================
# TRC PARSER
# ============================================================

FRAME_RE = re.compile(
    r"^\s*(\d+)\)\s+"
    r"([0-9.+-]+)\s+"
    r"(\S+)\s+"
    r"([0-9A-Fa-f]+)\s+"
    r"(\d+)"
    r"(.*)$"
)


def parse_trc(path: Path) -> list[Frame]:
    """
    Parse PCAN-View TRC v1.x.

    Voorbeeld:
        1) 8972.0 Rx 00019563 7 01 00 00 0F 00 63 95
    """

    frames = []

    with path.open("r", encoding="latin-1", errors="replace") as f:

        for line in f:
            match = FRAME_RE.match(line)

            if not match:
                continue

            try:
                number = int(match.group(1))
                time_ms = float(match.group(2))
                direction = match.group(3)
                can_id = int(match.group(4), 16)
                dlc = int(match.group(5))

                data_text = match.group(6).strip()

                if data_text:
                    parts = data_text.split()
                    data = bytes(
                        int(x, 16)
                        for x in parts[:dlc]
                    )
                else:
                    data = b""

                frames.append(
                    Frame(
                        number=number,
                        time_ms=time_ms,
                        direction=direction,
                        can_id=can_id,
                        dlc=dlc,
                        data=data,
                    )
                )

            except (ValueError, IndexError):
                continue

    return frames


# ============================================================
# HULPFUNCTIES
# ============================================================

def fmt_hex(data: bytes) -> str:
    return " ".join(f"{x:02X}" for x in data)


def median_or_zero(values):
    if not values:
        return 0.0
    return statistics.median(values)


def mean_or_zero(values):
    if not values:
        return 0.0
    return statistics.mean(values)


def stdev_or_zero(values):
    if len(values) < 2:
        return 0.0
    return statistics.stdev(values)


def entropy(values):
    """
    Shannon entropy voor bytewaarden.
    """
    if not values:
        return 0.0

    counts = Counter(values)
    total = len(values)

    result = 0.0

    for count in counts.values():
        p = count / total
        result -= p * math.log2(p)

    return result


def hamming_distance(a: bytes, b: bytes) -> int:
    n = min(len(a), len(b))
    result = 0

    for i in range(n):
        result += (a[i] ^ b[i]).bit_count()

    return result + abs(len(a) - len(b)) * 8


# ============================================================
# ID STATISTIEK
# ============================================================

def analyze_ids(frames: list[Frame]):
    by_id = defaultdict(list)

    for frame in frames:
        by_id[frame.can_id].append(frame)

    result = []

    for can_id, items in by_id.items():

        times = [x.time_ms for x in items]

        intervals = [
            times[i] - times[i - 1]
            for i in range(1, len(times))
        ]

        dlcs = Counter(x.dlc for x in items)

        result.append({
            "id": can_id,
            "count": len(items),
            "first_ms": min(times),
            "last_ms": max(times),
            "duration_ms": max(times) - min(times),
            "mean_interval_ms": mean_or_zero(intervals),
            "median_interval_ms": median_or_zero(intervals),
            "stdev_interval_ms": stdev_or_zero(intervals),
            "dlcs": dlcs,
            "extended": can_id > 0x7FF,
        })

    result.sort(
        key=lambda x: x["count"],
        reverse=True
    )

    return result


# ============================================================
# TIMING ANALYSE
# ============================================================

def analyze_timing(frames: list[Frame]):

    by_id = defaultdict(list)

    for frame in frames:
        by_id[frame.can_id].append(frame.time_ms)

    result = []

    for can_id, times in by_id.items():

        if len(times) < MIN_TIMING_SAMPLES:
            continue

        intervals = [
            times[i] - times[i - 1]
            for i in range(1, len(times))
        ]

        result.append({
            "id": can_id,
            "count": len(times),
            "median": median_or_zero(intervals),
            "mean": mean_or_zero(intervals),
            "stdev": stdev_or_zero(intervals),
            "min": min(intervals),
            "max": max(intervals),
        })

    result.sort(
        key=lambda x: x["median"]
    )

    return result


# ============================================================
# FRAME PAIRS
# ============================================================

def analyze_pairs(frames: list[Frame], max_gap_ms=0.5):

    pairs = Counter()

    for a, b in zip(frames, frames[1:]):

        dt = b.time_ms - a.time_ms

        if dt < 0:
            continue

        if dt <= max_gap_ms:

            key = (a.can_id, b.can_id)

            pairs[key] += 1

    return pairs


# ============================================================
# ID / PAYLOAD RELATIES
# ============================================================

def analyze_id_payload_relationship(frames: list[Frame]):

    tests = Counter()
    matches = Counter()

    for frame in frames:

        if len(frame.data) < 2:
            continue

        low16 = frame.can_id & 0xFFFF

        b0 = frame.data[0]
        b1 = frame.data[1]

        last16_le = frame.data[-2] | (
            frame.data[-1] << 8
        )

        last16_be = (
            frame.data[-2] << 8
        ) | frame.data[-1]

        tests["last2_le"] += 1
        tests["last2_be"] += 1

        if last16_le == low16:
            matches["last2_le"] += 1

        if last16_be == low16:
            matches["last2_be"] += 1

    return tests, matches


# ============================================================
# BYTE ANALYSE
# ============================================================

def analyze_bytes(frames: list[Frame]):

    by_id = defaultdict(list)

    for frame in frames:
        by_id[frame.can_id].append(frame.data)

    result = {}

    for can_id, payloads in by_id.items():

        max_len = max(
            (len(x) for x in payloads),
            default=0
        )

        byte_info = []

        for index in range(max_len):

            values = [
                p[index]
                for p in payloads
                if len(p) > index
            ]

            if not values:
                continue

            unique = len(set(values))

            byte_info.append({
                "index": index,
                "unique": unique,
                "min": min(values),
                "max": max(values),
                "entropy": entropy(values),
                "constant": unique == 1,
            })

        result[can_id] = byte_info

    return result


# ============================================================
# MOGELIJKE COUNTERS
# ============================================================

def detect_counters(frames: list[Frame]):

    by_id = defaultdict(list)

    for frame in frames:
        by_id[frame.can_id].append(frame)

    candidates = []

    for can_id, items in by_id.items():

        if len(items) < 20:
            continue

        max_len = max(
            len(x.data) for x in items
        )

        for index in range(max_len):

            values = [
                x.data[index]
                for x in items
                if len(x.data) > index
            ]

            if len(values) < 20:
                continue

            sequential = 0

            for a, b in zip(values, values[1:]):
                if b == ((a + 1) & 0xFF):
                    sequential += 1

            ratio = sequential / (len(values) - 1)

            if ratio > 0.80:

                candidates.append({
                    "id": can_id,
                    "byte": index,
                    "ratio": ratio,
                })

    return candidates


# ============================================================
# STARTUP ANALYSE
# ============================================================

def startup_frames(frames: list[Frame]):

    if not frames:
        return []

    first_time = frames[0].time_ms

    return [
        frame
        for frame in frames
        if frame.time_ms - first_time <= STARTUP_MS
    ]


def analyze_startup(frames: list[Frame]):

    start = startup_frames(frames)

    by_id = Counter(
        frame.can_id
        for frame in start
    )

    return start, by_id


# ============================================================
# FILE SUMMARY
# ============================================================

def write_file_summary(info: FileInfo, out_dir: Path):

    frames = info.frames

    filename = info.path.stem

    output = out_dir / f"{filename}_summary.txt"

    with output.open("w", encoding="utf-8") as f:

        f.write("=" * 70 + "\n")
        f.write(f"FILE: {info.path.name}\n")
        f.write("=" * 70 + "\n\n")

        if not frames:
            f.write("No CAN frames found.\n")
            return

        duration = (
            frames[-1].time_ms
            - frames[0].time_ms
        )

        ids = analyze_ids(frames)

        f.write(f"Frames: {len(frames)}\n")
        f.write(f"Duration: {duration:.3f} ms\n")
        f.write(
            f"Unique CAN IDs: {len(ids)}\n"
        )

        extended = sum(
            1 for x in frames
            if x.is_extended
        )

        f.write(
            f"29-bit frames: {extended}\n"
        )

        f.write(
            f"11-bit frames: "
            f"{len(frames) - extended}\n\n"
        )

        f.write("MOST COMMON CAN IDs\n")
        f.write("-" * 70 + "\n")

        for item in ids[:100]:

            f.write(
                f"0x{item['id']:08X}  "
                f"{item['count']:8d}  "
                f"first={item['first_ms']:12.3f} ms  "
                f"median_dt={item['median_interval_ms']:10.4f} ms\n"
            )


# ============================================================
# CSV EXPORT
# ============================================================

def write_ids_csv(all_file_info, out_dir):

    path = out_dir / "id_statistics.csv"

    with path.open(
        "w",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.writer(f)

        writer.writerow([
            "file",
            "can_id",
            "extended",
            "count",
            "first_ms",
            "last_ms",
            "duration_ms",
            "mean_interval_ms",
            "median_interval_ms",
            "stdev_interval_ms",
        ])

        for info in all_file_info:

            for item in analyze_ids(info.frames):

                writer.writerow([
                    info.path.name,
                    f"0x{item['id']:08X}",
                    item["extended"],
                    item["count"],
                    f"{item['first_ms']:.6f}",
                    f"{item['last_ms']:.6f}",
                    f"{item['duration_ms']:.6f}",
                    f"{item['mean_interval_ms']:.6f}",
                    f"{item['median_interval_ms']:.6f}",
                    f"{item['stdev_interval_ms']:.6f}",
                ])


def write_frame_csv(all_file_info, out_dir):

    path = out_dir / "all_frames.csv"

    with path.open(
        "w",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.writer(f)

        writer.writerow([
            "file",
            "number",
            "time_ms",
            "direction",
            "can_id",
            "dlc",
            "data",
        ])

        for info in all_file_info:

            for frame in info.frames:

                writer.writerow([
                    info.path.name,
                    frame.number,
                    f"{frame.time_ms:.6f}",
                    frame.direction,
                    f"0x{frame.can_id:08X}",
                    frame.dlc,
                    fmt_hex(frame.data),
                ])


# ============================================================
# GLOBALE ANALYSE
# ============================================================

def write_global_report(all_file_info, out_dir):

    report_path = out_dir / "REPORT.txt"

    all_frames = []

    for info in all_file_info:
        all_frames.extend(info.frames)

    with report_path.open(
        "w",
        encoding="utf-8"
    ) as f:

        f.write("=" * 80 + "\n")
        f.write("DAB ACTIVE DRIVER PLUS - CAN ANALYSIS\n")
        f.write("=" * 80 + "\n\n")

        f.write(
            "This report is descriptive only.\n"
            "It does not attempt to assign meanings to CAN IDs.\n\n"
        )

        # ----------------------------------------------------
        # FILES
        # ----------------------------------------------------

        f.write("FILES\n")
        f.write("-" * 80 + "\n")

        for info in all_file_info:

            if info.frames:

                duration = (
                    info.frames[-1].time_ms
                    - info.frames[0].time_ms
                )

                f.write(
                    f"{info.path.name:35s} "
                    f"{len(info.frames):8d} frames  "
                    f"{duration:12.3f} ms\n"
                )

            else:

                f.write(
                    f"{info.path.name:35s} EMPTY\n"
                )

        f.write("\n")

        # ----------------------------------------------------
        # GLOBAL
        # ----------------------------------------------------

        unique_ids = Counter(
            frame.can_id
            for frame in all_frames
        )

        f.write("GLOBAL\n")
        f.write("-" * 80 + "\n")

        f.write(
            f"Total files:       {len(all_file_info)}\n"
        )

        f.write(
            f"Total frames:      {len(all_frames)}\n"
        )

        f.write(
            f"Unique CAN IDs:    {len(unique_ids)}\n"
        )

        extended = sum(
            1
            for frame in all_frames
            if frame.is_extended
        )

        f.write(
            f"29-bit frames:     {extended}\n"
        )

        f.write(
            f"11-bit frames:     "
            f"{len(all_frames) - extended}\n\n"
        )

        # ----------------------------------------------------
        # COMMON IDS
        # ----------------------------------------------------

        f.write("MOST COMMON CAN IDs\n")
        f.write("-" * 80 + "\n")

        for can_id, count in unique_ids.most_common(100):

            f.write(
                f"0x{can_id:08X}  {count:10d}\n"
            )

        f.write("\n")

        # ----------------------------------------------------
        # PAIRS
        # ----------------------------------------------------

        f.write("SHORT-GAP FRAME PAIRS\n")
        f.write("-" * 80 + "\n")

        pairs = analyze_pairs(
            all_frames,
            max_gap_ms=0.5
        )

        for (a, b), count in pairs.most_common(100):

            f.write(
                f"0x{a:08X} -> "
                f"0x{b:08X}   "
                f"{count:8d}\n"
            )

        f.write("\n")

        # ----------------------------------------------------
        # ID/PAYLOAD
        # ----------------------------------------------------

        f.write("CAN ID / PAYLOAD RELATIONSHIPS\n")
        f.write("-" * 80 + "\n")

        tests, matches = analyze_id_payload_relationship(
            all_frames
        )

        for key in tests:

            total = tests[key]
            match = matches[key]

            ratio = (
                match / total
                if total
                else 0
            )

            f.write(
                f"{key:12s} "
                f"{match:10d} / "
                f"{total:10d}  "
                f"{ratio * 100:8.3f}%\n"
            )

        f.write("\n")

        # ----------------------------------------------------
        # COUNTERS
        # ----------------------------------------------------

        f.write("POSSIBLE 8-BIT COUNTERS\n")
        f.write("-" * 80 + "\n")

        counter_candidates = detect_counters(
            all_frames
        )

        for candidate in counter_candidates[:100]:

            f.write(
                f"ID 0x{candidate['id']:08X}  "
                f"byte {candidate['byte']}  "
                f"sequential ratio="
                f"{candidate['ratio'] * 100:.2f}%\n"
            )

        f.write("\n")

        # ----------------------------------------------------
        # STARTUP
        # ----------------------------------------------------

        f.write("STARTUP ANALYSIS\n")
        f.write("-" * 80 + "\n")

        for info in all_file_info:

            start, counts = analyze_startup(
                info.frames
            )

            f.write(
                f"\n[{info.path.name}]\n"
            )

            f.write(
                f"Startup frames: {len(start)}\n"
            )

            for can_id, count in counts.most_common(50):

                f.write(
                    f"  0x{can_id:08X}  "
                    f"{count:8d}\n"
                )

        f.write("\n")

        # ----------------------------------------------------
        # FILE COMPARISON
        # ----------------------------------------------------

        f.write("FILE COMPARISON - CAN ID PRESENCE\n")
        f.write("-" * 80 + "\n")

        id_presence = defaultdict(set)

        for info in all_file_info:

            for frame in info.frames:

                id_presence[
                    frame.can_id
                ].add(info.path.name)

        for can_id in sorted(id_presence):

            files = id_presence[can_id]

            if len(files) != len(all_file_info):

                f.write(
                    f"0x{can_id:08X} "
                    f"present in {len(files)}/"
                    f"{len(all_file_info)} files\n"
                )

                for filename in sorted(files):

                    f.write(
                        f"    {filename}\n"
                    )

        f.write("\n")

        # ----------------------------------------------------
        # IMPORTANT RAW OBSERVATIONS
        # ----------------------------------------------------

        f.write("NOTES FOR FURTHER INVESTIGATION\n")
        f.write("-" * 80 + "\n")

        f.write(
            "1. This analysis does not assume CANopen.\n"
        )

        f.write(
            "2. 29-bit identifiers are treated as full identifiers.\n"
        )

        f.write(
            "3. Short-gap frame pairs are reported because the\n"
            "   supplied sample showed repeated ~0.1 ms pairs.\n"
        )

        f.write(
            "4. ID/payload relationships are reported because\n"
            "   the supplied sample showed possible correlation\n"
            "   between the CAN ID low 16 bits and the final\n"
            "   payload bytes.\n"
        )

        f.write(
            "5. No semantic interpretation of IDs is performed.\n"
        )

        f.write(
            "6. The next stage should compare captures made with\n"
            "   AD=0, AD=1, AD=2 and AD=3.\n"
        )

        f.write("\n")

    return report_path


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 70)
    print("DAB Active Driver Plus - CAN TRC Analyzer")
    print("=" * 70)
    print()

    if not TRC_DIR.exists():

        print(
            f"TRC directory not found:\n"
            f"  {TRC_DIR}\n"
        )

        print(
            "Create the directory and put your .TRC files in it."
        )

        return

    trc_files = sorted(
        TRC_DIR.glob("*.trc")
    )

    if not trc_files:

        print(
            f"No .TRC files found in:\n"
            f"  {TRC_DIR}\n"
        )

        return

    RESULTS_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    print(
        f"Found {len(trc_files)} TRC files."
    )

    all_file_info = []

    for path in trc_files:

        print(
            f"Reading: {path.name}"
        )

        frames = parse_trc(path)

        print(
            f"    {len(frames)} frames"
        )

        info = FileInfo(
            path=path,
            frames=frames
        )

        all_file_info.append(info)

        write_file_summary(
            info,
            RESULTS_DIR
        )

    print()
    print("Writing CSV data...")

    write_ids_csv(
        all_file_info,
        RESULTS_DIR
    )

    write_frame_csv(
        all_file_info,
        RESULTS_DIR
    )

    print("Writing global report...")

    report = write_global_report(
        all_file_info,
        RESULTS_DIR
    )

    print()
    print("=" * 70)
    print("DONE")
    print("=" * 70)
    print()
    print(
        f"Report:\n  {report}"
    )

    print()
    print(
        "Open REPORT.txt and paste its contents into the chat."
    )

    print()


if __name__ == "__main__":
    main()

