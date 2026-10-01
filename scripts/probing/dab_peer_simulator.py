#!/usr/bin/env python3
"""
DAB Active Driver Plus synthetic peer / transformed replay tester.

Tests supported
---------------
short   Continuous short-only peer traffic:
          0x001nTTTT  DLC5  01 00 00 LL HH

pair    Continuous long+short peer traffic:
          0x000nTTTT  DLC7  01 00 00 0F MM LL HH
          0x001nTTTT  DLC5  01 00 00 LL HH

replay  Read a normalized CSV capture, select native 0x0001/0x0011
        traffic, and transform it into one or more chosen peer families.
        Timing, long/short ordering, and marker values are preserved.

suite   Run short, pair, and (if --replay-csv is supplied) replay as
        separate stages with a passive observation gap between stages.

Safety
------
Transmission is disabled unless --send is explicitly supplied.
The default permitted short-family range is 0x0012..0x0018.
Use --allow-unsafe-family to override that range.

Dependency
----------
    pip install python-can

Example commands
----------------
# Dry-run: two synthetic controllers, short-only
python dab_peer_simulator.py --mode short --families 0x12,0x13 --duration 5

# Actually transmit two short-only synthetic controllers at 200 Hz each
python dab_peer_simulator.py --mode short --families 0x12,0x13 \
    --duration 5 --period-ms 5 --send

# Two complete long/short controller simulations
python dab_peer_simulator.py --mode pair --families 0x12,0x15 \
    --duration 5 --period-ms 5 --pair-gap-ms 0.15 --send

# Same, with a single marker 0x00 at startup, then marker 0x03
python dab_peer_simulator.py --mode pair --families 0x12,0x15 \
    --duration 5 --initial-marker 0x00 --marker 0x03 --send

# Transform native 0001/0011 traffic into three peer controllers
python dab_peer_simulator.py --mode replay --families 0x12,0x13,0x18 \
    --replay-csv can_Trace_015_20260928_2020_AD-0.csv \
    --replay-token-offset 0x2000 --duration 10 --send

# Run the staged test suite
python dab_peer_simulator.py --mode suite --families 0x12,0x13 \
    --stage-duration 5 --stage-gap 10 \
    --replay-csv R1_short_reference.csv --send
"""

from __future__ import annotations

import argparse
import csv
import random
import signal
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

try:
    import can
except ImportError:
    print("Missing dependency: python-can. Install with: pip install python-can")
    raise SystemExit(2)


NATIVE_LONG_FAMILY = 0x0001
NATIVE_SHORT_FAMILY = 0x0011
DEFAULT_ALLOWED_SHORT_FAMILIES = range(0x0012, 0x0019)


@dataclass(frozen=True)
class TxEvent:
    due_ns: int
    can_id: int
    data: bytes
    controller_index: int
    label: str


class CsvLogger:
    def __init__(self, path: Path, start_ns: int):
        self.path = path
        self.start_ns = start_ns
        self.lock = threading.Lock()
        self.handle = path.open("w", newline="", encoding="utf-8")
        self.writer = csv.writer(self.handle)
        self.writer.writerow([
            "utc", "host_rel_ms", "direction", "label", "controller_index",
            "can_id_hex", "extended", "dlc", "data_hex", "status"
        ])
        self.handle.flush()

    def write(self, direction: str, label: str, controller_index: int,
              can_id: int, data: bytes, status: str = "OK") -> None:
        now_ns = time.perf_counter_ns()
        utc = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
        utc += f".{int((time.time() % 1) * 1000):03d}Z"
        rel_ms = (now_ns - self.start_ns) / 1_000_000
        with self.lock:
            self.writer.writerow([
                utc, f"{rel_ms:.3f}", direction, label, controller_index,
                f"{can_id:08X}", 1, len(data), data.hex(" ").upper(), status
            ])
            self.handle.flush()

    def close(self) -> None:
        with self.lock:
            self.handle.close()


class Receiver(threading.Thread):
    def __init__(self, bus, logger: CsvLogger, stop_event: threading.Event):
        super().__init__(name="can-receiver", daemon=True)
        self.bus = bus
        self.logger = logger
        self.stop_event = stop_event

    def run(self) -> None:
        while not self.stop_event.is_set():
            try:
                msg = self.bus.recv(timeout=0.1)
            except Exception as exc:
                self.logger.write("RX_ERROR", "receiver", -1, 0, b"", repr(exc))
                return
            if msg is None:
                continue
            self.logger.write(
                "RX", "bus", -1, int(msg.arbitration_id), bytes(msg.data)
            )


def parse_int(text: str) -> int:
    return int(text.strip(), 0)


def parse_families(text: str) -> list[int]:
    values = []
    for part in text.replace(";", ",").split(","):
        part = part.strip()
        if part:
            values.append(parse_int(part))
    if not values:
        raise argparse.ArgumentTypeError("at least one family is required")
    if len(values) != len(set(values)):
        raise argparse.ArgumentTypeError("family list contains duplicates")
    return values


def validate_families(families: Iterable[int], allow_unsafe: bool) -> None:
    for family in families:
        if not (0 <= family <= 0x1FFF):
            raise ValueError(f"family 0x{family:X} exceeds the 13-bit family field")
        if family < 0x0010:
            raise ValueError(
                f"0x{family:04X} is a long family; --families expects short families"
            )
        if not allow_unsafe and family not in DEFAULT_ALLOWED_SHORT_FAMILIES:
            raise ValueError(
                f"short family 0x{family:04X} is outside tested range "
                "0x0012..0x0018; use --allow-unsafe-family to override"
            )


def can_id(family: int, token: int) -> int:
    return ((family & 0x1FFF) << 16) | (token & 0xFFFF)


def short_payload(token: int) -> bytes:
    return bytes((0x01, 0x00, 0x00, token & 0xFF, (token >> 8) & 0xFF))


def long_payload(token: int, marker: int) -> bytes:
    return bytes((
        0x01, 0x00, 0x00, 0x0F, marker & 0xFF,
        token & 0xFF, (token >> 8) & 0xFF
    ))


def wait_until_ns(deadline_ns: int, spin_ns: int = 300_000) -> None:
    """Hybrid sleep/spin wait. Python/Windows is not a hard real-time scheduler."""
    while True:
        remaining = deadline_ns - time.perf_counter_ns()
        if remaining <= 0:
            return
        if remaining > spin_ns:
            time.sleep((remaining - spin_ns) / 1_000_000_000)
        else:
            # Deliberately spin only for the final fraction of a millisecond.
            pass


def make_token_generators(count: int, seed: int, mode: str, start: int):
    generators = []
    for index in range(count):
        rng = random.Random(seed + index * 0x9E3779B1)
        counter = (start + index * 0x2000) & 0xFFFF

        def next_token(rng=rng, initial=counter):
            state = {"value": initial}

            def inner():
                if mode == "random":
                    return rng.randrange(0x10000)
                value = state["value"]
                state["value"] = (value + 1) & 0xFFFF
                return value
            return inner

        generators.append(next_token())
    return generators


def synthetic_events(args, start_ns: int, mode: str) -> list[TxEvent]:
    period_ns = round(args.period_ms * 1_000_000)
    pair_gap_ns = round(args.pair_gap_ms * 1_000_000)
    duration_ns = round(args.duration * 1_000_000_000)
    stagger_ns = round(args.controller_stagger_ms * 1_000_000)
    token_functions = make_token_generators(
        len(args.families), args.seed, args.token_mode, args.token_start
    )

    events: list[TxEvent] = []
    cycle = 0
    while cycle * period_ns < duration_ns:
        for index, short_family in enumerate(args.families):
            due = start_ns + cycle * period_ns + index * stagger_ns
            if due - start_ns >= duration_ns:
                continue
            token = token_functions[index]()

            if mode == "pair":
                long_family = short_family - 0x0010
                marker = (
                    args.initial_marker
                    if cycle == 0 and args.initial_marker is not None
                    else args.marker
                )
                events.append(TxEvent(
                    due, can_id(long_family, token), long_payload(token, marker),
                    index, f"pair_long_f{long_family:04X}"
                ))
                events.append(TxEvent(
                    due + pair_gap_ns, can_id(short_family, token),
                    short_payload(token), index, f"pair_short_f{short_family:04X}"
                ))
            else:
                events.append(TxEvent(
                    due, can_id(short_family, token), short_payload(token),
                    index, f"short_f{short_family:04X}"
                ))
        cycle += 1

    return sorted(events, key=lambda e: (e.due_ns, e.can_id))


def normalize_hex_id(value: str) -> int:
    value = value.strip().lower().replace("0x", "")
    return int(value, 16)


def parse_data_hex(value: str) -> bytes:
    return bytes.fromhex(value.strip())


def find_column(fieldnames: list[str], choices: tuple[str, ...]) -> str:
    lowered = {name.lower(): name for name in fieldnames}
    for choice in choices:
        if choice.lower() in lowered:
            return lowered[choice.lower()]
    raise ValueError(f"CSV requires one of columns: {', '.join(choices)}")


def load_native_replay(path: Path) -> list[tuple[float, int, bytes]]:
    """
    Load normalized CSV files used by this project.

    Supported timing columns: relative_ms, t_ms, timestamp_monotonic,
                              host_rel_us, hardware_rel_us
    Required ID column:      can_id_hex
    Required payload column: data_hex or payload_hex
    Optional direction:      direction or dir; TX rows are excluded because
                             a source trace should normally supply received
                             native-controller traffic.
    """
    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError("CSV has no header")
        fields = list(reader.fieldnames)
        id_col = find_column(fields, ("can_id_hex",))
        data_col = find_column(fields, ("data_hex", "payload_hex"))
        time_col = find_column(fields, (
            "relative_ms", "t_ms", "timestamp_monotonic",
            "host_rel_us", "hardware_rel_us"
        ))
        direction_col: Optional[str] = None
        for candidate in ("direction", "dir"):
            if candidate in fields:
                direction_col = candidate
                break

        rows = []
        first_time = None
        for row in reader:
            if direction_col:
                direction = (row.get(direction_col) or "").strip().upper()
                if direction in {"TX", "T"}:
                    continue
            try:
                raw_id = normalize_hex_id(row[id_col])
                family = raw_id >> 16
                if family not in (NATIVE_LONG_FAMILY, NATIVE_SHORT_FAMILY):
                    continue
                data = parse_data_hex(row[data_col])
                raw_time = float(row[time_col])
            except (ValueError, TypeError, KeyError):
                continue

            if time_col in ("host_rel_us", "hardware_rel_us"):
                time_ms = raw_time / 1000.0
            elif time_col == "timestamp_monotonic":
                time_ms = raw_time * 1000.0
            else:
                time_ms = raw_time

            if first_time is None:
                first_time = time_ms
            rows.append((time_ms - first_time, raw_id, data))

    if not rows:
        raise ValueError("no native 0x0001/0x0011 frames found in replay CSV")
    return rows


def rewrite_token_payload(data: bytes, family: int, token: int) -> bytes:
    mutable = bytearray(data)
    if family == NATIVE_LONG_FAMILY and len(mutable) >= 7:
        mutable[5] = token & 0xFF
        mutable[6] = (token >> 8) & 0xFF
    elif family == NATIVE_SHORT_FAMILY and len(mutable) >= 5:
        mutable[3] = token & 0xFF
        mutable[4] = (token >> 8) & 0xFF
    return bytes(mutable)


def replay_events(args, start_ns: int) -> list[TxEvent]:
    source = load_native_replay(args.replay_csv)
    speed = args.replay_speed
    if speed <= 0:
        raise ValueError("--replay-speed must be greater than zero")

    stagger_ns = round(args.controller_stagger_ms * 1_000_000)
    duration_ms = args.duration * 1000.0
    source_end_ms = source[-1][0]
    if source_end_ms <= 0:
        raise ValueError("replay source has no usable time span")

    events: list[TxEvent] = []
    loop_index = 0
    output_offset_ms = 0.0

    while output_offset_ms < duration_ms:
        for rel_ms, source_id, data in source:
            replay_ms = output_offset_ms + rel_ms / speed
            if replay_ms >= duration_ms:
                break
            source_family = source_id >> 16
            source_token = source_id & 0xFFFF

            for index, target_short_family in enumerate(args.families):
                token_delta = index * args.replay_token_offset
                target_token = (source_token + token_delta) & 0xFFFF
                if source_family == NATIVE_LONG_FAMILY:
                    target_family = target_short_family - 0x0010
                else:
                    target_family = target_short_family

                target_data = rewrite_token_payload(
                    data, source_family, target_token
                )
                due = (
                    start_ns
                    + round(replay_ms * 1_000_000)
                    + index * stagger_ns
                )
                events.append(TxEvent(
                    due, can_id(target_family, target_token), target_data,
                    index,
                    f"replay_{source_family:04X}_to_{target_family:04X}"
                ))

        if not args.loop_replay:
            break
        loop_index += 1
        output_offset_ms = loop_index * (source_end_ms / speed + args.loop_gap_ms)

    return sorted(events, key=lambda e: (e.due_ns, e.can_id))


def print_plan(events: list[TxEvent], start_ns: int, limit: int = 20) -> None:
    print(f"Planned frames: {len(events)}")
    for event in events[:limit]:
        rel_ms = (event.due_ns - start_ns) / 1_000_000
        print(
            f"  {rel_ms:10.3f} ms  {event.can_id:08X}  "
            f"DLC{len(event.data)}  {event.data.hex(' ').upper()}  {event.label}"
        )
    if len(events) > limit:
        print(f"  ... {len(events) - limit} additional frames")


def transmit_events(bus, events: list[TxEvent], logger: CsvLogger,
                    stop_event: threading.Event, late_warn_ms: float) -> None:
    for event in events:
        if stop_event.is_set():
            return
        wait_until_ns(event.due_ns)
        lateness_ms = (time.perf_counter_ns() - event.due_ns) / 1_000_000
        if lateness_ms > late_warn_ms:
            print(
                f"WARNING: TX scheduler late by {lateness_ms:.3f} ms "
                f"for {event.can_id:08X}", file=sys.stderr
            )
        msg = can.Message(
            arbitration_id=event.can_id,
            is_extended_id=True,
            is_fd=False,
            data=event.data,
        )
        try:
            bus.send(msg, timeout=0.1)
            logger.write(
                "TX", event.label, event.controller_index,
                event.can_id, event.data, "OK"
            )
        except Exception as exc:
            logger.write(
                "TX_ERROR", event.label, event.controller_index,
                event.can_id, event.data, repr(exc)
            )
            raise


def open_bus(args):
    kwargs = {
        "interface": args.interface,
        "channel": args.channel,
        "bitrate": args.bitrate,
    }
    return can.Bus(**kwargs)


def run_stage(args, mode: str, bus, logger: CsvLogger,
              stop_event: threading.Event) -> None:
    start_ns = time.perf_counter_ns() + round(args.start_delay * 1_000_000_000)
    if mode in ("short", "pair"):
        events = synthetic_events(args, start_ns, mode)
    elif mode == "replay":
        if not args.replay_csv:
            raise ValueError("replay mode requires --replay-csv")
        events = replay_events(args, start_ns)
    else:
        raise ValueError(f"unknown stage mode: {mode}")

    print(f"\n=== {mode.upper()} stage ===")
    print_plan(events, start_ns)
    if not args.send:
        print("DRY RUN: no frames transmitted; add --send to enable TX")
        return
    transmit_events(bus, events, logger, stop_event, args.late_warn_ms)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="DAB synthetic peer and transformed-replay tester"
    )
    parser.add_argument(
        "--mode", choices=("short", "pair", "replay", "suite"), required=True
    )
    parser.add_argument(
        "--families", type=parse_families, required=True,
        help="comma-separated target short families, e.g. 0x12,0x13,0x18"
    )
    parser.add_argument("--send", action="store_true", help="enable CAN transmission")
    parser.add_argument("--allow-unsafe-family", action="store_true")

    parser.add_argument("--interface", default="pcan")
    parser.add_argument("--channel", default="PCAN_USBBUS1")
    parser.add_argument("--bitrate", type=int, default=1_000_000)
    parser.add_argument("--duration", type=float, default=5.0)
    parser.add_argument("--period-ms", type=float, default=5.0)
    parser.add_argument("--pair-gap-ms", type=float, default=0.15)
    parser.add_argument(
        "--controller-stagger-ms", type=float, default=0.35,
        help="phase offset between simulated controllers"
    )
    parser.add_argument("--start-delay", type=float, default=1.0)
    parser.add_argument("--observe-after", type=float, default=10.0)
    parser.add_argument("--late-warn-ms", type=float, default=1.0)

    parser.add_argument("--token-mode", choices=("random", "counter"), default="random")
    parser.add_argument("--token-start", type=parse_int, default=0x1000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--marker", type=parse_int, default=0x03)
    parser.add_argument("--initial-marker", type=parse_int)

    parser.add_argument("--replay-csv", type=Path)
    parser.add_argument("--replay-speed", type=float, default=1.0)
    parser.add_argument(
        "--replay-token-offset", type=parse_int, default=0x2000,
        help=(
            "token offset per additional replayed controller; use 0 to retain "
            "identical source tokens for every transformed controller"
        )
    )
    parser.add_argument("--loop-replay", action="store_true")
    parser.add_argument("--loop-gap-ms", type=float, default=5.0)

    parser.add_argument("--stage-duration", type=float, default=5.0)
    parser.add_argument("--stage-gap", type=float, default=10.0)
    parser.add_argument(
        "--log", type=Path,
        default=Path(time.strftime("dab_peer_test_%Y%m%d-%H%M%S.csv"))
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    validate_families(args.families, args.allow_unsafe_family)

    if args.duration <= 0 or args.period_ms <= 0:
        raise ValueError("duration and period must be greater than zero")
    if args.pair_gap_ms < 0 or args.pair_gap_ms >= args.period_ms:
        raise ValueError("pair gap must be nonnegative and below the cycle period")
    if len(args.families) > 1 and args.controller_stagger_ms <= 0:
        print(
            "WARNING: multiple controllers have no phase staggering; CAN "
            "arbitration will serialize frames but host-side timing may bunch up",
            file=sys.stderr,
        )

    print("DAB peer simulator")
    print(f"Mode:              {args.mode}")
    print("Short families:    " + ", ".join(f"0x{x:04X}" for x in args.families))
    print("Derived long:      " + ", ".join(
        f"0x{x - 0x10:04X}" for x in args.families
    ))
    print(f"CAN:               {args.interface}/{args.channel} @ {args.bitrate} bit/s")
    print(f"Transmission:      {'ENABLED' if args.send else 'DISABLED (dry run)'}")
    print(f"Log:               {args.log}")

    # In dry-run mode no CAN hardware is opened.
    if not args.send:
        dummy_start = time.perf_counter_ns() + round(args.start_delay * 1e9)
        if args.mode == "suite":
            original_duration = args.duration
            args.duration = args.stage_duration
            for stage in ("short", "pair"):
                events = synthetic_events(args, dummy_start, stage)
                print(f"\n=== {stage.upper()} stage ===")
                print_plan(events, dummy_start)
            if args.replay_csv:
                events = replay_events(args, dummy_start)
                print("\n=== REPLAY stage ===")
                print_plan(events, dummy_start)
            args.duration = original_duration
        elif args.mode == "replay":
            print_plan(replay_events(args, dummy_start), dummy_start)
        else:
            print_plan(synthetic_events(args, dummy_start, args.mode), dummy_start)
        print("\nDRY RUN complete. No CAN bus was opened.")
        return 0

    stop_event = threading.Event()

    def stop_handler(_signum, _frame):
        stop_event.set()

    signal.signal(signal.SIGINT, stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)

    session_start_ns = time.perf_counter_ns()
    logger = CsvLogger(args.log, session_start_ns)
    bus = None
    receiver = None

    try:
        bus = open_bus(args)
        receiver = Receiver(bus, logger, stop_event)
        receiver.start()

        if args.mode == "suite":
            original_duration = args.duration
            args.duration = args.stage_duration
            stages = ["short", "pair"]
            if args.replay_csv:
                stages.append("replay")
            for stage_index, stage in enumerate(stages):
                if stop_event.is_set():
                    break
                run_stage(args, stage, bus, logger, stop_event)
                if stage_index != len(stages) - 1:
                    print(f"Passive stage gap: {args.stage_gap:.1f} s")
                    stop_event.wait(args.stage_gap)
            args.duration = original_duration
        else:
            run_stage(args, args.mode, bus, logger, stop_event)

        if not stop_event.is_set() and args.observe_after > 0:
            print(f"Passive post-observation: {args.observe_after:.1f} s")
            stop_event.wait(args.observe_after)

    finally:
        stop_event.set()
        if receiver:
            receiver.join(timeout=1.0)
        if bus:
            try:
                bus.shutdown()
            except Exception:
                pass
        logger.close()

    print(f"Finished. Log written to: {args.log}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
