#!/usr/bin/env python3
"""
dab_can_session_probe.py

Conservative stateful CAN-session experiment for the DAB Active Driver Plus.

Purpose
-------
1. Record a passive baseline.
2. Send one known short discovery/status probe.
3. Optionally emulate a persistent peer using short frames or long/short pairs.
4. Detect and decode 0x103C response bursts, including the inferred AD address.
5. Write raw CSV, event CSV, result CSV, metadata JSON, and summary JSON.

Safety defaults
---------------
- No transmission unless BOTH --send and --confirm ACTIVE are supplied.
- Default mode is passive/dry-run.
- Default sustained rate is 20 Hz, not the observed maximum of about 200 Hz.
- Transmission stops on an observed CAN error frame.
- A hard frame limit prevents accidental unlimited transmission.

Dependency
----------
    pip install python-can

Examples
--------
Passive validation only:
    python dab_can_session_probe.py

One active short-frame trial on family 0x0012:
    python dab_can_session_probe.py --send --confirm ACTIVE --mode short \
        --family 0012 --token C82D --sustain-seconds 10 --rate-hz 20

Persistent normal-order long/short pairs:
    python dab_can_session_probe.py --send --confirm ACTIVE --mode pair \
        --family 0012 --long-family 0002 --token-mode increment \
        --sustain-seconds 15 --rate-hz 20

Test the known +0x0800 alias:
    python dab_can_session_probe.py --send --confirm ACTIVE --mode short \
        --family 0812 --token C82D
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import random
import signal
import sys
import threading
import time
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

try:
    import can
except ImportError:
    print("Missing dependency: python-can. Install with: pip install python-can", file=sys.stderr)
    raise SystemExit(2)


# ---------------------------------------------------------------------------
# Constants and helpers
# ---------------------------------------------------------------------------

BITRATE = 1_000_000
KNOWN_RESPONSE_FAMILY = 0x103C
DEFAULT_TOKEN = 0xC82D
DEFAULT_SHORT_FAMILY = 0x0012
DEFAULT_LONG_FAMILY = 0x0002

STOP = threading.Event()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_hex(text: str, bits: int, label: str) -> int:
    try:
        value = int(text, 16)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{label} must be hexadecimal: {text!r}") from exc
    if not 0 <= value < (1 << bits):
        raise argparse.ArgumentTypeError(f"{label} must fit in {bits} bits")
    return value


def family_arg(text: str) -> int:
    return parse_hex(text, 13, "family")


def token_arg(text: str) -> int:
    return parse_hex(text, 16, "token")


def marker_arg(text: str) -> int:
    return parse_hex(text, 8, "marker")


def family_of(can_id: int) -> int:
    return (can_id >> 16) & 0x1FFF


def token_of(can_id: int) -> int:
    return can_id & 0xFFFF


def make_can_id(family: int, token: int) -> int:
    return ((family & 0x1FFF) << 16) | (token & 0xFFFF)


def token_bytes(token: int) -> tuple[int, int]:
    return token & 0xFF, (token >> 8) & 0xFF


def short_payload(token: int) -> bytes:
    lo, hi = token_bytes(token)
    return bytes((0x01, 0x00, 0x00, lo, hi))


def long_payload(token: int, marker: int) -> bytes:
    lo, hi = token_bytes(token)
    return bytes((0x01, 0x00, 0x00, 0x0F, marker, lo, hi))


def hex_data(data: bytes | bytearray) -> str:
    return " ".join(f"{b:02X}" for b in data)


def decode_103c_address(can_id: int) -> Optional[dict[str, Any]]:
    """Decode the demonstrated 103C status/data ID mapping for AD 1..8."""
    if family_of(can_id) != KNOWN_RESPONSE_FAMILY:
        return None

    low = token_of(can_id)
    for ad in range(1, 9):
        status_low = 0x0401 + ((ad - 1) << 4)
        data_low = status_low + 0x80
        if low == status_low:
            return {"address": ad, "response_kind": "status", "low16": f"{low:04X}"}
        if low == data_low:
            return {"address": ad, "response_kind": "data", "low16": f"{low:04X}"}

    return {"address": None, "response_kind": "other_103c", "low16": f"{low:04X}"}


def validate_mirrored_token(msg: can.Message) -> Optional[bool]:
    """Return True/False for known mirror layouts, or None when not applicable."""
    token = token_of(msg.arbitration_id)
    lo, hi = token_bytes(token)
    data = bytes(msg.data)

    if msg.dlc == 5 and len(data) >= 5 and data[:3] == b"\x01\x00\x00":
        return data[3] == lo and data[4] == hi
    if msg.dlc == 7 and len(data) >= 7 and data[:4] == b"\x01\x00\x00\x0F":
        return data[5] == lo and data[6] == hi
    return None


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

RAW_HEADERS = [
    "utc", "host_rel_ms", "adapter", "direction", "phase", "trial",
    "can_id_hex", "family_hex", "token_hex", "extended", "dlc",
    "data_hex", "is_error", "status", "mirror_valid",
    "decoded_ad", "response_kind",
]

EVENT_HEADERS = ["utc", "host_rel_ms", "phase", "event", "details"]

RESULT_HEADERS = [
    "utc", "trial", "mode", "short_family_hex", "long_family_hex",
    "marker_hex", "token_mode", "start_token_hex", "rate_hz",
    "sustain_seconds", "tx_attempted", "tx_ok", "rx_frames",
    "error_frames", "response_frames", "response_ids",
    "decoded_addresses", "first_response_latency_ms",
    "last_response_latency_ms", "response_burst_ms",
    "distinct_response_payloads", "aborted",
]


class CsvWriter:
    def __init__(self, path: Path, headers: list[str]):
        self.path = path
        self.file = path.open("w", newline="", encoding="utf-8")
        self.writer = csv.DictWriter(self.file, fieldnames=headers, extrasaction="ignore")
        self.writer.writeheader()
        self.lock = threading.Lock()

    def write(self, row: dict[str, Any]) -> None:
        with self.lock:
            self.writer.writerow(row)
            self.file.flush()

    def close(self) -> None:
        with self.lock:
            self.file.close()


@dataclass
class CapturedFrame:
    utc: str
    host_rel_ms: float
    direction: str
    phase: str
    trial: int
    can_id: int
    dlc: int
    data: bytes
    is_error: bool


class Recorder:
    def __init__(self, bus: can.BusABC, raw_writer: CsvWriter, start_mono: float):
        self.bus = bus
        self.raw_writer = raw_writer
        self.start_mono = start_mono
        self.phase = "initializing"
        self.trial = 0
        self.frames: list[CapturedFrame] = []
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self._run, name="dab-observer", daemon=True)
        self.error_seen = threading.Event()

    def set_context(self, phase: str, trial: int) -> None:
        with self.lock:
            self.phase = phase
            self.trial = trial

    def snapshot_index(self) -> int:
        with self.lock:
            return len(self.frames)

    def frames_since(self, index: int) -> list[CapturedFrame]:
        with self.lock:
            return list(self.frames[index:])

    def start(self) -> None:
        self.thread.start()

    def join(self, timeout: float = 2.0) -> None:
        self.thread.join(timeout)

    def _run(self) -> None:
        while not STOP.is_set():
            try:
                msg = self.bus.recv(timeout=0.1)
            except can.CanError as exc:
                self.error_seen.set()
                STOP.set()
                print(f"Observer CAN error: {exc}", file=sys.stderr)
                return

            if msg is None:
                continue

            now = time.monotonic()
            rel_ms = (now - self.start_mono) * 1000.0
            with self.lock:
                phase = self.phase
                trial = self.trial

            is_error = bool(getattr(msg, "is_error_frame", False))
            if is_error:
                self.error_seen.set()
                STOP.set()

            decoded = decode_103c_address(msg.arbitration_id) if msg.is_extended_id else None
            mirror = validate_mirrored_token(msg) if msg.is_extended_id else None
            frame = CapturedFrame(
                utc=utc_now(),
                host_rel_ms=rel_ms,
                direction="RX",
                phase=phase,
                trial=trial,
                can_id=msg.arbitration_id,
                dlc=msg.dlc,
                data=bytes(msg.data),
                is_error=is_error,
            )

            with self.lock:
                self.frames.append(frame)

            self.raw_writer.write({
                "utc": frame.utc,
                "host_rel_ms": f"{rel_ms:.3f}",
                "adapter": "observer",
                "direction": "RX",
                "phase": phase,
                "trial": trial,
                "can_id_hex": f"{msg.arbitration_id:08X}",
                "family_hex": f"{family_of(msg.arbitration_id):04X}" if msg.is_extended_id else "",
                "token_hex": f"{token_of(msg.arbitration_id):04X}" if msg.is_extended_id else "",
                "extended": int(msg.is_extended_id),
                "dlc": msg.dlc,
                "data_hex": hex_data(msg.data),
                "is_error": int(is_error),
                "status": "ERROR_FRAME" if is_error else "OK",
                "mirror_valid": "" if mirror is None else int(mirror),
                "decoded_ad": "" if not decoded or decoded["address"] is None else decoded["address"],
                "response_kind": "" if not decoded else decoded["response_kind"],
            })


# ---------------------------------------------------------------------------
# Experiment
# ---------------------------------------------------------------------------


class TokenGenerator:
    def __init__(self, mode: str, start: int, seed: int):
        self.mode = mode
        self.value = start & 0xFFFF
        self.random = random.Random(seed)

    def next(self) -> int:
        if self.mode == "fixed":
            return self.value
        if self.mode == "increment":
            result = self.value
            self.value = (self.value + 1) & 0xFFFF
            return result
        return self.random.randrange(0x10000)


class Experiment:
    def __init__(
        self,
        args: argparse.Namespace,
        injector: can.BusABC,
        recorder: Recorder,
        raw_writer: CsvWriter,
        event_writer: CsvWriter,
        result_writer: CsvWriter,
        start_mono: float,
    ):
        self.args = args
        self.injector = injector
        self.recorder = recorder
        self.raw_writer = raw_writer
        self.event_writer = event_writer
        self.result_writer = result_writer
        self.start_mono = start_mono
        self.tx_attempted = 0
        self.tx_ok = 0

    def rel_ms(self) -> float:
        return (time.monotonic() - self.start_mono) * 1000.0

    def event(self, phase: str, event: str, details: Any = None) -> None:
        if isinstance(details, (dict, list)):
            details = json.dumps(details, separators=(",", ":"), sort_keys=True)
        self.event_writer.write({
            "utc": utc_now(),
            "host_rel_ms": f"{self.rel_ms():.3f}",
            "phase": phase,
            "event": event,
            "details": "" if details is None else str(details),
        })

    def wait(self, seconds: float) -> None:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline and not STOP.is_set():
            if self.recorder.error_seen.is_set():
                STOP.set()
                break
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))

    def send_frame(self, can_id: int, data: bytes, phase: str, trial: int) -> bool:
        if self.tx_attempted >= self.args.max_tx_frames:
            self.event(phase, "safety_abort", "maximum TX frame count reached")
            STOP.set()
            return False

        self.tx_attempted += 1
        ok = False
        status = "DRY_RUN"

        if self.args.active:
            msg = can.Message(
                arbitration_id=can_id,
                is_extended_id=True,
                data=data,
                is_fd=False,
            )
            try:
                self.injector.send(msg, timeout=0.1)
                ok = True
                self.tx_ok += 1
                status = "OK"
            except can.CanError as exc:
                status = f"TX_ERROR:{exc}"
                STOP.set()

        self.raw_writer.write({
            "utc": utc_now(),
            "host_rel_ms": f"{self.rel_ms():.3f}",
            "adapter": "injector",
            "direction": "TX",
            "phase": phase,
            "trial": trial,
            "can_id_hex": f"{can_id:08X}",
            "family_hex": f"{family_of(can_id):04X}",
            "token_hex": f"{token_of(can_id):04X}",
            "extended": 1,
            "dlc": len(data),
            "data_hex": hex_data(data),
            "is_error": 0,
            "status": status,
            "mirror_valid": int(validate_mirrored_token(can.Message(
                arbitration_id=can_id,
                is_extended_id=True,
                data=data,
            )) or False),
            "decoded_ad": "",
            "response_kind": "",
        })
        return ok or not self.args.active

    def send_cycle(self, token: int, phase: str, trial: int) -> bool:
        short_id = make_can_id(self.args.family, token)
        long_id = make_can_id(self.args.long_family, token)
        short = (short_id, short_payload(token))
        long = (long_id, long_payload(token, self.args.marker))

        if self.args.mode == "short":
            sequence = (short,)
        elif self.args.mode == "long":
            sequence = (long,)
        elif self.args.mode == "pair":
            sequence = (long, short)
        else:
            sequence = (short, long)

        for index, (can_id, data) in enumerate(sequence):
            if STOP.is_set() or not self.send_frame(can_id, data, phase, trial):
                return False
            if index + 1 < len(sequence):
                self.wait(self.args.interframe_ms / 1000.0)
        return True

    def run_trial(self, trial: int) -> dict[str, Any]:
        phase = f"trial_{trial:02d}_{self.args.mode}_family_{self.args.family:04X}"
        self.recorder.set_context(phase, trial)
        self.event(phase, "phase_started", {
            "active": self.args.active,
            "mode": self.args.mode,
            "family": f"{self.args.family:04X}",
            "long_family": f"{self.args.long_family:04X}",
            "marker": f"{self.args.marker:02X}",
        })

        before_index = self.recorder.snapshot_index()
        tx_before = self.tx_attempted
        ok_before = self.tx_ok

        self.event(phase, "pre_window_started", self.args.pre_seconds)
        self.wait(self.args.pre_seconds)
        injection_mono = time.monotonic()

        generator = TokenGenerator(
            self.args.token_mode,
            self.args.token,
            self.args.seed + trial,
        )

        if not STOP.is_set():
            if self.args.sustain_seconds <= 0:
                token = generator.next()
                self.send_cycle(token, phase, trial)
            else:
                interval = 1.0 / self.args.rate_hz
                deadline = time.monotonic() + self.args.sustain_seconds
                next_send = time.monotonic()
                while time.monotonic() < deadline and not STOP.is_set():
                    token = generator.next()
                    if not self.send_cycle(token, phase, trial):
                        break
                    next_send += interval
                    remaining = next_send - time.monotonic()
                    if remaining > 0:
                        self.wait(remaining)
                    else:
                        next_send = time.monotonic()

        self.event(phase, "post_window_started", self.args.post_seconds)
        self.wait(self.args.post_seconds)

        frames = self.recorder.frames_since(before_index)
        responses = [f for f in frames if family_of(f.can_id) == KNOWN_RESPONSE_FAMILY]
        errors = [f for f in frames if f.is_error]

        ids = Counter(f"{f.can_id:08X}" for f in responses)
        payloads = sorted({hex_data(f.data) for f in responses})
        addresses = sorted({
            decoded["address"]
            for f in responses
            if (decoded := decode_103c_address(f.can_id)) and decoded["address"] is not None
        })

        latencies = [f.host_rel_ms - ((injection_mono - self.start_mono) * 1000.0) for f in responses]
        first_latency = min(latencies) if latencies else None
        last_latency = max(latencies) if latencies else None
        burst = (last_latency - first_latency) if latencies else None

        row = {
            "utc": utc_now(),
            "trial": trial,
            "mode": self.args.mode,
            "short_family_hex": f"{self.args.family:04X}",
            "long_family_hex": f"{self.args.long_family:04X}",
            "marker_hex": f"{self.args.marker:02X}",
            "token_mode": self.args.token_mode,
            "start_token_hex": f"{self.args.token:04X}",
            "rate_hz": self.args.rate_hz,
            "sustain_seconds": self.args.sustain_seconds,
            "tx_attempted": self.tx_attempted - tx_before,
            "tx_ok": self.tx_ok - ok_before,
            "rx_frames": len(frames),
            "error_frames": len(errors),
            "response_frames": len(responses),
            "response_ids": " | ".join(f"{key}:{value}" for key, value in sorted(ids.items())),
            "decoded_addresses": " | ".join(str(x) for x in addresses),
            "first_response_latency_ms": "" if first_latency is None else f"{first_latency:.3f}",
            "last_response_latency_ms": "" if last_latency is None else f"{last_latency:.3f}",
            "response_burst_ms": "" if burst is None else f"{burst:.3f}",
            "distinct_response_payloads": len(payloads),
            "aborted": int(STOP.is_set()),
        }
        self.result_writer.write(row)
        self.event(phase, "trial_completed", row)
        return row


# ---------------------------------------------------------------------------
# Command line and main
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Conservative DAB Active Driver Plus stateful CAN-session probe"
    )
    parser.add_argument("--injector", default="PCAN_USBBUS1")
    parser.add_argument("--observer", default="PCAN_USBBUS2")
    parser.add_argument("--interface", default="pcan")
    parser.add_argument("--bitrate", type=int, default=BITRATE)
    parser.add_argument("--output-dir", default="dab_session_results")

    parser.add_argument("--send", action="store_true", help="enable active transmission")
    parser.add_argument("--confirm", default="", help="must be exactly ACTIVE with --send")
    parser.add_argument("--assume-pump-stopped", action="store_true",
                        help="operator confirms the pump is stopped and hydraulically safe")

    parser.add_argument("--mode", choices=("short", "long", "pair", "reverse-pair"), default="short")
    parser.add_argument("--family", type=family_arg, default=DEFAULT_SHORT_FAMILY)
    parser.add_argument("--long-family", type=family_arg, default=DEFAULT_LONG_FAMILY)
    parser.add_argument("--marker", type=marker_arg, default=0x03)
    parser.add_argument("--token", type=token_arg, default=DEFAULT_TOKEN)
    parser.add_argument("--token-mode", choices=("fixed", "increment", "random"), default="increment")
    parser.add_argument("--seed", type=int, default=20260930)

    parser.add_argument("--baseline-seconds", type=float, default=10.0)
    parser.add_argument("--pre-seconds", type=float, default=2.0)
    parser.add_argument("--sustain-seconds", type=float, default=0.0,
                        help="0 sends one cycle; positive value sustains a peer")
    parser.add_argument("--post-seconds", type=float, default=5.0)
    parser.add_argument("--rate-hz", type=float, default=20.0)
    parser.add_argument("--interframe-ms", type=float, default=0.20)
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--gap-seconds", type=float, default=5.0)
    parser.add_argument("--max-tx-frames", type=int, default=10_000)
    return parser


def validate_args(args: argparse.Namespace) -> None:
    if args.send and args.confirm != "ACTIVE":
        raise SystemExit("Active TX refused: use both --send and --confirm ACTIVE")
    if args.send and not args.assume_pump_stopped:
        raise SystemExit(
            "Active TX refused: also supply --assume-pump-stopped after verifying a safe stopped state"
        )
    if args.bitrate != BITRATE:
        raise SystemExit("This experiment is constrained to the demonstrated 1,000,000 bit/s")
    if not 0 < args.rate_hz <= 200:
        raise SystemExit("--rate-hz must be greater than 0 and no more than 200")
    if args.sustain_seconds < 0 or args.sustain_seconds > 120:
        raise SystemExit("--sustain-seconds must be between 0 and 120")
    if args.repeats < 1 or args.repeats > 20:
        raise SystemExit("--repeats must be between 1 and 20")
    if args.interframe_ms < 0.05:
        raise SystemExit("--interframe-ms below 0.05 ms is refused")
    if args.max_tx_frames < 1:
        raise SystemExit("--max-tx-frames must be positive")

    frames_per_cycle = 2 if args.mode in ("pair", "reverse-pair") else 1
    estimated = args.repeats * (
        frames_per_cycle if args.sustain_seconds == 0
        else frames_per_cycle * int(args.sustain_seconds * args.rate_hz + 1)
    )
    if estimated > args.max_tx_frames:
        raise SystemExit(
            f"Planned TX count (~{estimated}) exceeds --max-tx-frames={args.max_tx_frames}"
        )

    # Families already associated with a deterministic response handler.
    known_safe_low = set(range(0x0012, 0x0019))
    known_safe_alias = set(range(0x0812, 0x0819))
    if args.send and args.family not in known_safe_low | known_safe_alias:
        raise SystemExit(
            f"Active TX refused for unvalidated short family {args.family:04X}. "
            "Edit the script deliberately if a new family is required."
        )


def install_signal_handlers() -> None:
    def handler(signum: int, _frame: Any) -> None:
        print(f"Signal {signum}; stopping safely...", file=sys.stderr)
        STOP.set()

    signal.signal(signal.SIGINT, handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, handler)


def open_bus(interface: str, channel: str, bitrate: int) -> can.BusABC:
    return can.Bus(
        interface=interface,
        channel=channel,
        bitrate=bitrate,
        receive_own_messages=False,
    )


def main() -> int:
    args = build_parser().parse_args()
    args.active = bool(args.send and args.confirm == "ACTIVE")
    validate_args(args)
    install_signal_handlers()

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    raw_path = out_dir / f"raw_{stamp}.csv"
    events_path = out_dir / f"events_{stamp}.csv"
    results_path = out_dir / f"results_{stamp}.csv"
    metadata_path = out_dir / f"metadata_{stamp}.json"
    summary_path = out_dir / f"summary_{stamp}.json"

    metadata = {
        "created_utc": utc_now(),
        "script": Path(__file__).name,
        "active": args.active,
        "python": sys.version,
        "python_can": getattr(can, "__version__", "unknown"),
        "arguments": {
            key: (f"{value:04X}" if key in {"family", "long_family", "token"} else
                  f"{value:02X}" if key == "marker" else value)
            for key, value in vars(args).items()
            if key != "active"
        },
    }
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    raw_writer = CsvWriter(raw_path, RAW_HEADERS)
    event_writer = CsvWriter(events_path, EVENT_HEADERS)
    result_writer = CsvWriter(results_path, RESULT_HEADERS)

    injector: Optional[can.BusABC] = None
    observer: Optional[can.BusABC] = None
    recorder: Optional[Recorder] = None
    results: list[dict[str, Any]] = []
    start_mono = time.monotonic()

    try:
        print(f"Opening observer {args.observer} at {args.bitrate} bit/s")
        observer = open_bus(args.interface, args.observer, args.bitrate)
        print(f"Opening injector {args.injector} at {args.bitrate} bit/s")
        injector = open_bus(args.interface, args.injector, args.bitrate)

        recorder = Recorder(observer, raw_writer, start_mono)
        recorder.start()

        experiment = Experiment(
            args, injector, recorder, raw_writer, event_writer, result_writer, start_mono
        )
        experiment.event("initializing", "session_started", metadata)

        print(
            "ACTIVE transmission enabled" if args.active
            else "PASSIVE/DRY-RUN mode: planned TX frames are logged but not put on the bus"
        )

        recorder.set_context("baseline", 0)
        experiment.event("baseline", "baseline_started", args.baseline_seconds)
        experiment.wait(args.baseline_seconds)
        baseline_frames = recorder.frames_since(0)
        spontaneous_103c = sum(
            family_of(frame.can_id) == KNOWN_RESPONSE_FAMILY for frame in baseline_frames
        )
        experiment.event("baseline", "baseline_completed", {
            "frames": len(baseline_frames),
            "spontaneous_103c_frames": spontaneous_103c,
            "error_frames": sum(frame.is_error for frame in baseline_frames),
        })

        if recorder.error_seen.is_set():
            raise RuntimeError("CAN error frame observed during baseline")

        for trial in range(1, args.repeats + 1):
            if STOP.is_set():
                break
            result = experiment.run_trial(trial)
            results.append(result)
            print(
                f"Trial {trial}: TX {result['tx_ok']}/{result['tx_attempted']}, "
                f"103C frames={result['response_frames']}, "
                f"addresses={result['decoded_addresses'] or '-'}"
            )
            if trial < args.repeats and not STOP.is_set():
                recorder.set_context("inter_trial_gap", trial)
                experiment.wait(args.gap_seconds)

        experiment.event("shutdown", "session_finished", {
            "stopped": STOP.is_set(),
            "trials_completed": len(results),
        })

        summary = {
            "created_utc": utc_now(),
            "active": args.active,
            "baseline_frames": len(baseline_frames),
            "baseline_spontaneous_103c_frames": spontaneous_103c,
            "trials_completed": len(results),
            "total_tx_attempted": sum(int(row["tx_attempted"]) for row in results),
            "total_tx_ok": sum(int(row["tx_ok"]) for row in results),
            "total_103c_frames": sum(int(row["response_frames"]) for row in results),
            "error_abort": bool(recorder.error_seen.is_set()),
            "results": results,
            "files": {
                "raw": str(raw_path),
                "events": str(events_path),
                "results": str(results_path),
                "metadata": str(metadata_path),
            },
        }
        summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(f"Results written to: {out_dir.resolve()}")
        return 1 if recorder.error_seen.is_set() else 0

    except KeyboardInterrupt:
        STOP.set()
        return 130
    except Exception as exc:
        STOP.set()
        event_writer.write({
            "utc": utc_now(),
            "host_rel_ms": f"{(time.monotonic() - start_mono) * 1000.0:.3f}",
            "phase": "fatal",
            "event": "fatal_exception",
            "details": repr(exc),
        })
        print(f"Fatal error: {exc}", file=sys.stderr)
        return 1
    finally:
        STOP.set()
        if recorder is not None:
            recorder.join()
        for bus in (injector, observer):
            if bus is not None:
                try:
                    bus.shutdown()
                except Exception:
                    pass
        raw_writer.close()
        event_writer.close()
        result_writer.close()


if __name__ == "__main__":
    raise SystemExit(main())
