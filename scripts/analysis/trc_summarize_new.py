#!/usr/bin/env python3
"""
trc_summarize.py — complete PCAN-View .TRC parser and analyser
================================================================

Replaces the previous trc_summarize.py.

Features
--------
- Windows-safe wildcard expansion (cmd.exe does not expand * itself)
- Parses normal Rx/Tx CAN frames
- Preserves and reports ErrorFrame, bus status and all unknown records
- Detects missing/duplicate PCAN message numbers
- Checks DLC against the actual payload length
- Summarises CAN-ID families, timing, byte variability and ID echo
- Reports near-constant-byte anomalies
- Compares low-16 CAN-ID values across traces
- Exports both normal frames and error/status records in one run

Usage
-----
    python trc_summarize.py Trace_00*.trc --csv can
    python trc_summarize.py Trace_01*.trc --csv can --out-dir parsed
    python trc_summarize.py Trace_015.trc Trace_016.trc Trace_017.trc --csv can

CSV output
----------
    can_<trace>.csv          normal CAN frames
    can_events_<trace>.csv   errors, status and unknown records
"""

import argparse
import csv
import glob
import os
import re
import sys
from collections import Counter, defaultdict
from statistics import mean, pstdev


# ======================================================================
# 1. INPUT FILE HANDLING
# ======================================================================

def natural_key(text):
    """Sort Trace_2 before Trace_10."""
    return [int(part) if part.isdigit() else part.lower()
            for part in re.split(r"(\d+)", text)]


def expand_inputs(patterns):
    """Expand wildcards inside Python, so this also works in cmd.exe."""
    found = []
    missing = []

    for pattern in patterns:
        if any(ch in pattern for ch in "*?["):
            matches = glob.glob(pattern)
            if matches:
                found.extend(matches)
            else:
                missing.append(pattern)
        elif os.path.isfile(pattern):
            found.append(pattern)
        else:
            missing.append(pattern)

    result = []
    seen = set()
    for path in sorted(found, key=natural_key):
        absolute = os.path.abspath(path)
        if absolute not in seen:
            seen.add(absolute)
            result.append(path)

    return result, missing


# ======================================================================
# 2. PCAN-VIEW TRC PARSING
# ======================================================================

# Normal record, for example:
#      1)  8972.0  Rx  00019563  7  01 00 00 0F 00 63 95
FRAME_RE = re.compile(
    r"^\s*(?P<num>\d+)\)\s+"
    r"(?P<t>[+-]?[\d.]+)\s+"
    r"(?P<direction>Rx|Tx)\s+"
    r"(?P<can_id>[0-9A-Fa-f]+)\s+"
    r"(?P<dlc>\d+)\s*"
    r"(?P<data>.*)$",
    re.IGNORECASE,
)

# Any other numbered PCAN record with a numeric timestamp.
# This deliberately does not assume a specific ErrorFrame syntax.
RECORD_RE = re.compile(
    r"^\s*(?P<num>\d+)\)\s+"
    r"(?P<t>[+-]?[\d.]+)\s+"
    r"(?P<body>.*)$"
)

# Fallback for numbered records for which PCAN did not print a normal timestamp.
NUMBERED_RE = re.compile(
    r"^\s*(?P<num>\d+)\)\s*(?P<body>.*)$"
)


class Frame:
    __slots__ = (
        "num", "t", "direction", "can_id", "id_hex", "ext",
        "dlc", "data", "line_number", "raw", "dlc_ok"
    )

    def __init__(self, num, t, direction, id_hex, dlc, data,
                 line_number, raw, dlc_ok):
        self.num = num
        self.t = t
        self.direction = direction
        self.id_hex = id_hex.upper()
        self.can_id = int(id_hex, 16)
        self.ext = len(id_hex) > 3
        self.dlc = dlc
        self.data = data
        self.line_number = line_number
        self.raw = raw
        self.dlc_ok = dlc_ok


def classify_event(body):
    """Best-effort classification; original text is always retained."""
    text = body.lower()

    rules = [
        ("bus_off", (
            "bus-off", "bus off", "busoff"
        )),
        ("error_frame", (
            "errorframe", "error frame", "error-frame"
        )),
        ("bus_heavy", (
            "busheavy", "bus heavy"
        )),
        ("bus_warning", (
            "buswarning", "bus warning", "warning limit"
        )),
        ("error_passive", (
            "error passive", "bus passive"
        )),
        ("overrun", (
            "overrun", "overflow", "queue full", "receive queue"
        )),
        ("status", (
            "status", "buslight", "bus light"
        )),
        ("error", (
            "error", "err"
        )),
    ]

    for category, words in rules:
        if any(word in text for word in words):
            return category

    return "other_record"


def parse_data_bytes(text):
    tokens = text.split()
    if not all(re.fullmatch(r"[0-9A-Fa-f]{2}", token) for token in tokens):
        raise ValueError("payload contains a non-byte token")
    return tuple(int(token, 16) for token in tokens)


def parse_trc(path):
    frames = []
    events = []
    structural = []
    metadata = {}
    record_numbers = []

    with open(path, "r", encoding="utf-8-sig", errors="replace") as handle:
        for line_number, raw_line in enumerate(handle, 1):
            line = raw_line.rstrip("\r\n")

            if line.startswith(";"):
                if "$FILEVERSION=" in line:
                    metadata["file_version"] = line.split("$FILEVERSION=", 1)[1].strip()
                elif "$STARTTIME=" in line:
                    metadata["start_time_raw"] = line.split("$STARTTIME=", 1)[1].strip()
                elif "Start time:" in line:
                    metadata["start_time"] = line.split("Start time:", 1)[1].strip()
                elif "Generated by" in line:
                    metadata["generator"] = line.split("Generated by", 1)[1].strip()
                continue

            if not line.strip():
                continue

            frame_match = FRAME_RE.match(line)
            if frame_match:
                item = frame_match.groupdict()
                num = int(item["num"])
                t_ms = float(item["t"])
                dlc = int(item["dlc"])

                try:
                    data = parse_data_bytes(item["data"])
                    data_syntax_ok = True
                except ValueError:
                    data = tuple()
                    data_syntax_ok = False

                record_numbers.append(num)
                frames.append(Frame(
                    num=num,
                    t=t_ms,
                    direction=item["direction"].capitalize(),
                    id_hex=item["can_id"],
                    dlc=dlc,
                    data=data,
                    line_number=line_number,
                    raw=line,
                    dlc_ok=data_syntax_ok and len(data) == dlc,
                ))
                continue

            record_match = RECORD_RE.match(line)
            if record_match:
                item = record_match.groupdict()
                num = int(item["num"])
                record_numbers.append(num)
                events.append({
                    "line_number": line_number,
                    "num": num,
                    "t_ms": float(item["t"]),
                    "category": classify_event(item["body"]),
                    "body": item["body"],
                    "raw": line,
                })
                continue

            numbered_match = NUMBERED_RE.match(line)
            if numbered_match:
                item = numbered_match.groupdict()
                num = int(item["num"])
                record_numbers.append(num)
                events.append({
                    "line_number": line_number,
                    "num": num,
                    "t_ms": None,
                    "category": classify_event(item["body"]),
                    "body": item["body"],
                    "raw": line,
                })
                continue

            # Preserve every non-empty, non-comment line that remains.
            structural.append({
                "line_number": line_number,
                "category": "unparsed_structural",
                "raw": line,
            })

    counts = Counter(record_numbers)
    duplicate_numbers = sorted(num for num, count in counts.items() if count > 1)

    missing_numbers = []
    if record_numbers:
        present = set(record_numbers)
        first = min(record_numbers)
        last = max(record_numbers)
        missing_numbers = [num for num in range(first, last + 1)
                           if num not in present]

    return {
        "metadata": metadata,
        "frames": frames,
        "events": events,
        "structural": structural,
        "record_numbers": record_numbers,
        "missing_numbers": missing_numbers,
        "duplicate_numbers": duplicate_numbers,
    }


# ======================================================================
# 3. CAN ANALYSIS
# ======================================================================

def id_family(can_id):
    return can_id & 0xFFFF0000


def dominant_dlc(frames):
    return Counter(frame.dlc for frame in frames).most_common(1)[0][0]


def analyse_family(frames):
    out = {
        "count": len(frames),
        "dlc": Counter(frame.dlc for frame in frames),
        "t_first": frames[0].t,
        "t_last": frames[-1].t,
    }

    deltas = [current.t - previous.t
              for previous, current in zip(frames, frames[1:])]

    if deltas:
        out["dt_mean"] = mean(deltas)
        out["dt_std"] = pstdev(deltas) if len(deltas) > 1 else 0.0
        out["dt_min"] = min(deltas)
        out["dt_max"] = max(deltas)
        out["rate_hz"] = 1000.0 / out["dt_mean"] if out["dt_mean"] else 0.0

    dom_dlc = dominant_dlc(frames)
    same_dlc = [frame for frame in frames
                if frame.dlc == dom_dlc and frame.dlc_ok]

    byte_values = [Counter() for _ in range(dom_dlc)]
    for frame in same_dlc:
        for index, value in enumerate(frame.data[:dom_dlc]):
            byte_values[index][value] += 1

    byte_profile = []
    for index, counter in enumerate(byte_values):
        if not counter:
            byte_profile.append(f"B{index}: geen geldige data")
        elif len(counter) == 1:
            value = next(iter(counter))
            byte_profile.append(f"B{index}=0x{value:02X} (const)")
        elif len(counter) <= 4:
            values = ", ".join(
                f"0x{value:02X}x{count}"
                for value, count in counter.most_common()
            )
            byte_profile.append(f"B{index}: {values}")
        else:
            byte_profile.append(
                f"B{index}: {len(counter)} distinct (variable)"
            )

    echo_ok = 0
    for frame in same_dlc:
        if len(frame.data) >= 2:
            payload_tail_le = frame.data[-2] | (frame.data[-1] << 8)
            if payload_tail_le == (frame.can_id & 0xFFFF):
                echo_ok += 1

    low_values = [frame.can_id & 0xFFFF for frame in frames]

    out.update({
        "dominant_dlc": dom_dlc,
        "byte_profile": byte_profile,
        "id_echo_ok": echo_ok,
        "id_echo_total": len(same_dlc),
        "unique_low16": len(set(low_values)),
        "low16_repeats": len(low_values) - len(set(low_values)),
    })
    return out


def find_anomalies(frames, maximum=40):
    """Find deviations from bytes whose dominant value occurs >=95%."""
    groups = defaultdict(list)
    for frame in frames:
        if frame.dlc_ok:
            groups[(id_family(frame.can_id), frame.dlc)].append(frame)

    anomalies = []

    for group in groups.values():
        dlc = group[0].dlc
        for index in range(dlc):
            counter = Counter(frame.data[index] for frame in group)
            dominant_value, dominant_count = counter.most_common(1)[0]

            if len(counter) <= 1:
                continue
            if dominant_count / len(group) < 0.95:
                continue

            for frame in group:
                if frame.data[index] != dominant_value:
                    anomalies.append({
                        "t_ms": frame.t,
                        "num": frame.num,
                        "id_hex": frame.id_hex,
                        "byte_index": index,
                        "expected": dominant_value,
                        "actual": frame.data[index],
                        "data": frame.data,
                    })

    anomalies.sort(key=lambda item: (item["t_ms"], item["num"]))
    return anomalies[:maximum], len(anomalies)


def pairing_analysis(frames):
    """Check 0x0001xxxx -> 0x0011xxxx twins with identical low-16 value."""
    ordered = sorted(frames, key=lambda frame: (frame.t, frame.num))
    candidates = 0
    paired = 0
    gaps = []

    for current, following in zip(ordered, ordered[1:]):
        if id_family(current.can_id) != 0x00010000:
            continue

        candidates += 1
        if (id_family(following.can_id) == 0x00110000 and
                (following.can_id & 0xFFFF) == (current.can_id & 0xFFFF)):
            paired += 1
            gaps.append(following.t - current.t)

    return {
        "candidates": candidates,
        "paired": paired,
        "gap_mean": mean(gaps) if gaps else None,
        "gap_min": min(gaps) if gaps else None,
        "gap_max": max(gaps) if gaps else None,
    }


# ======================================================================
# 4. REPORTING
# ======================================================================

def format_number_list(values, maximum=40):
    if not values:
        return "geen"
    shown = ", ".join(str(value) for value in values[:maximum])
    if len(values) > maximum:
        shown += f", ... (+{len(values) - maximum})"
    return shown


def print_event_report(result, maximum_events):
    events = result["events"]
    structural = result["structural"]
    bad_dlc = [frame for frame in result["frames"] if not frame.dlc_ok]

    print("-" * 88)
    print("  PCAN ERROR / STATUS / PARSE AUDIT")
    print(f"    numbered error/status records : {len(events)}")
    print(f"    other unrecognised lines      : {len(structural)}")
    print(f"    DLC/payload mismatches        : {len(bad_dlc)}")
    print(f"    missing message numbers       : "
          f"{format_number_list(result['missing_numbers'])}")
    print(f"    duplicate message numbers     : "
          f"{format_number_list(result['duplicate_numbers'])}")

    if events:
        print("    event categories:")
        for category, count in Counter(
                event["category"] for event in events).most_common():
            print(f"      {category:<20} {count}")

        print("    event records (literal TRC text):")
        for event in events[:maximum_events]:
            time_text = (f"{event['t_ms']:.3f} ms"
                         if event["t_ms"] is not None else "no timestamp")
            print(
                f"      line={event['line_number']:<7} "
                f"msg={event['num']:<7} "
                f"t={time_text:<18} "
                f"{event['category']:<16} {event['body']}"
            )
        if len(events) > maximum_events:
            print(f"      ... {len(events) - maximum_events} more")

    if bad_dlc:
        print("    frames with DLC/payload mismatch:")
        for frame in bad_dlc[:maximum_events]:
            print(f"      line={frame.line_number:<7} {frame.raw}")
        if len(bad_dlc) > maximum_events:
            print(f"      ... {len(bad_dlc) - maximum_events} more")

    if structural:
        print("    other unrecognised non-comment lines:")
        for item in structural[:maximum_events]:
            print(f"      line={item['line_number']:<7} {item['raw']}")
        if len(structural) > maximum_events:
            print(f"      ... {len(structural) - maximum_events} more")


def report(path, result, maximum_anomalies, maximum_events):
    metadata = result["metadata"]
    frames = result["frames"]

    print("=" * 88)
    print(f"FILE: {path}")
    print(f"  file version : {metadata.get('file_version', '?')}")
    print(f"  start        : {metadata.get('start_time', '?')}")
    print(f"  tool         : {metadata.get('generator', '?')}")

    if not frames:
        print("  !! no normal Rx/Tx CAN frames parsed")
        print_event_report(result, maximum_events)
        print()
        return

    ordered = sorted(frames, key=lambda frame: (frame.t, frame.num))
    span_seconds = (ordered[-1].t - ordered[0].t) / 1000.0

    print(f"  normal frames: {len(frames)}")
    print(f"  span         : {span_seconds:.3f} s")
    print(f"  average rate : "
          f"{len(frames) / span_seconds if span_seconds else 0:.1f} frames/s")
    print(f"  directions   : "
          f"{dict(Counter(frame.direction for frame in frames))}")
    print(f"  ID types     : "
          f"{dict(Counter('29-bit' if frame.ext else '11-bit' for frame in frames))}")

    families = defaultdict(list)
    for frame in ordered:
        families[id_family(frame.can_id)].append(frame)

    print(f"  ID families  : {len(families)}")

    for family in sorted(families):
        analysis = analyse_family(families[family])
        print("-" * 88)
        print(f"  ID family 0x{family:08X} "
              f"(low 16 bits vary), n={analysis['count']}")
        print(f"    DLC          : {dict(analysis['dlc'])}")
        print(f"    period       : {analysis.get('dt_mean', 0):.4f} ms "
              f"(sd {analysis.get('dt_std', 0):.4f}, "
              f"min {analysis.get('dt_min', 0):.1f}, "
              f"max {analysis.get('dt_max', 0):.1f}) "
              f"=> {analysis.get('rate_hz', 0):.3f} Hz")
        print(f"    first/last   : {analysis['t_first']:.1f} .. "
              f"{analysis['t_last']:.1f} ms")
        print(f"    unique ID_lo : {analysis['unique_low16']} "
              f"({analysis['low16_repeats']} repeats)")
        print(f"    ID echo      : {analysis['id_echo_ok']}/"
              f"{analysis['id_echo_total']}")
        print(f"    byte profile (DLC {analysis['dominant_dlc']}):")
        for line in analysis["byte_profile"]:
            print(f"      {line}")

    pairing = pairing_analysis(frames)
    print("-" * 88)
    print("  PAIRING 0x0001xxxx -> 0x0011xxxx")
    print(f"    candidates : {pairing['candidates']}")
    print(f"    paired     : {pairing['paired']}")
    if pairing["gap_mean"] is not None:
        print(f"    gap        : mean {pairing['gap_mean']:.4f} ms, "
              f"min {pairing['gap_min']:.1f}, max {pairing['gap_max']:.1f}")

    anomalies, anomaly_total = find_anomalies(
        frames, maximum=maximum_anomalies
    )
    print("-" * 88)
    print(f"  CAN ANOMALIES (deviation from >=95% dominant byte): "
          f"{anomaly_total}")

    for anomaly in anomalies:
        payload = " ".join(f"{value:02X}" for value in anomaly["data"])
        print(
            f"    t={anomaly['t_ms']:10.1f} "
            f"#{anomaly['num']:<7} "
            f"ID={anomaly['id_hex']} "
            f"B{anomaly['byte_index']}: "
            f"0x{anomaly['expected']:02X} -> 0x{anomaly['actual']:02X} "
            f"[{payload}]"
        )

    if anomaly_total > len(anomalies):
        print(f"    ... {anomaly_total - len(anomalies)} more")

    print_event_report(result, maximum_events)
    print()


# ======================================================================
# 5. CSV EXPORT
# ======================================================================

def ensure_output_directory(output_directory):
    if output_directory:
        os.makedirs(output_directory, exist_ok=True)
        return output_directory
    return "."


def write_frame_csv(path, frames, prefix, output_directory):
    output_directory = ensure_output_directory(output_directory)
    basename = os.path.splitext(os.path.basename(path))[0]
    output_path = os.path.join(output_directory, f"{prefix}_{basename}.csv")

    with open(output_path, "w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle)
        writer.writerow([
            "source", "line_number", "num", "t_ms", "dir",
            "can_id_hex", "can_id_dec", "id_family_hex", "id_low16",
            "ext", "dlc", "dlc_ok",
            "b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7",
            "payload_hex"
        ])

        for frame in frames:
            bytes_padded = list(frame.data[:8]) + [""] * (8 - len(frame.data[:8]))
            writer.writerow([
                basename,
                frame.line_number,
                frame.num,
                f"{frame.t:.3f}",
                frame.direction,
                frame.id_hex,
                frame.can_id,
                f"0x{id_family(frame.can_id):08X}",
                frame.can_id & 0xFFFF,
                int(frame.ext),
                frame.dlc,
                int(frame.dlc_ok),
                *bytes_padded,
                " ".join(f"{value:02X}" for value in frame.data),
            ])

    print(f"  [frames csv] {output_path} ({len(frames)} rows)")
    return output_path


def write_event_csv(path, result, prefix, output_directory):
    output_directory = ensure_output_directory(output_directory)
    basename = os.path.splitext(os.path.basename(path))[0]
    output_path = os.path.join(
        output_directory, f"{prefix}_events_{basename}.csv"
    )

    with open(output_path, "w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle)
        writer.writerow([
            "source", "line_number", "message_number", "t_ms",
            "category", "body", "raw"
        ])

        for event in result["events"]:
            writer.writerow([
                basename,
                event["line_number"],
                event["num"],
                "" if event["t_ms"] is None else f"{event['t_ms']:.3f}",
                event["category"],
                event["body"],
                event["raw"],
            ])

        for item in result["structural"]:
            writer.writerow([
                basename,
                item["line_number"],
                "",
                "",
                item["category"],
                item["raw"],
                item["raw"],
            ])

    count = len(result["events"]) + len(result["structural"])
    print(f"  [events csv] {output_path} ({count} rows)")
    return output_path


# ======================================================================
# 6. CROSS-TRACE COMPARISON
# ======================================================================

def print_cross_trace_comparison(all_frames):
    usable = {
        path: {frame.can_id & 0xFFFF for frame in frames}
        for path, frames in all_frames.items()
        if frames
    }

    if len(usable) < 2:
        return

    print("=" * 88)
    print("CROSS-TRACE COMPARISON OF LOW-16 CAN-ID VALUES")
    names = list(usable)

    for index, left in enumerate(names):
        for right in names[index + 1:]:
            intersection = len(usable[left] & usable[right])
            union = len(usable[left] | usable[right])
            expected = len(usable[left]) * len(usable[right]) / 65536.0
            jaccard = 100.0 * intersection / union if union else 0.0

            print(
                f"  {os.path.basename(left):<36} vs "
                f"{os.path.basename(right):<36} "
                f"overlap={intersection:5d}, "
                f"expected_random={expected:7.1f}, "
                f"union={union:5d}, Jaccard={jaccard:5.1f}%"
            )

    print("  Interpretation: compare observed overlap with expected_random;")
    print("  a 5% Jaccard overlap alone is not evidence of a repeated sequence.")


# ======================================================================
# 7. MAIN
# ======================================================================

def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="trc_summarize.py",
        description=(
            "Parse and analyse PCAN-View TRC files, including error/status "
            "records. Wildcards are expanded internally for Windows cmd.exe."
        )
    )
    parser.add_argument(
        "inputs", nargs="+",
        help="TRC files or wildcards, for example Trace_01*.trc"
    )
    parser.add_argument(
        "--csv", metavar="PREFIX", default=None,
        help=(
            "export normal frames to PREFIX_<trace>.csv and errors/status "
            "to PREFIX_events_<trace>.csv"
        )
    )
    parser.add_argument(
        "--out-dir", metavar="DIRECTORY", default=None,
        help="output directory for both CSV types"
    )
    parser.add_argument(
        "--max-anomalies", type=int, default=40,
        help="maximum CAN anomalies printed per file (default: 40)"
    )
    parser.add_argument(
        "--max-events", type=int, default=100,
        help="maximum error/status records printed per file (default: 100)"
    )
    args = parser.parse_args(argv)

    files, missing = expand_inputs(args.inputs)

    for pattern in missing:
        print(f"WARNING: no file matched '{pattern}'", file=sys.stderr)

    if not files:
        print("ERROR: no input files found.", file=sys.stderr)
        return 2

    print(f"Processing {len(files)} file(s):")
    for path in files:
        print(f"  - {path}")
    print()

    all_frames = {}
    total_events = 0
    total_structural = 0

    for path in files:
        try:
            result = parse_trc(path)
        except OSError as error:
            print(f"ERROR reading '{path}': {error}", file=sys.stderr)
            continue

        all_frames[path] = result["frames"]
        total_events += len(result["events"])
        total_structural += len(result["structural"])

        report(
            path,
            result,
            maximum_anomalies=args.max_anomalies,
            maximum_events=args.max_events,
        )

        if args.csv:
            write_frame_csv(
                path, result["frames"], args.csv, args.out_dir
            )
            write_event_csv(
                path, result, args.csv, args.out_dir
            )

    print_cross_trace_comparison(all_frames)

    print("=" * 88)
    print("FINAL PARSE AUDIT")
    print(f"  numbered error/status records : {total_events}")
    print(f"  other unrecognised lines      : {total_structural}")
    print()
    print("Important: inspect the literal event text before interpreting ACK, bus-off")
    print("or error-passive behaviour. Normal-frame CSVs alone cannot prove that")
    print("the bus was error-free.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
