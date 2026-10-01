#!/usr/bin/env python3
"""
dab_gateway_probe_test.py

Focused, low-rate experiment for the DAB Active Driver Plus CAN network.

Purpose
-------
Test these specific hypotheses without running another broad sweep:

H1  The standalone unit continuously occupies/claims short family 0x0011.
H2  A single 0x0012 short frame is interpreted as a second pump controller.
H3  0x0812 is behaviorally different from 0x0012 and may be a gateway class.
H4  0x0019 is outside the valid peer range and is a true negative control.
H5  0x103C process/status traffic appears only after a qualifying request.
H6  A qualifying request causes persistent peer/network-management behavior,
    not merely a short read-only response.

Safety design
-------------
* Listen-only mode is the default. Nothing is transmitted unless --send is used.
* Only ONE short DLC5 frame is sent per trial.
* Every transmission requires operator confirmation unless --assume-yes is used.
* CAN error frames abort the trial.
* The script never controls the pump and never sends long/pair traffic.
* Prefer running this first with the pump stopped and hydraulically safe.

Dependencies
------------
    py -m pip install python-can

Typical first run (capture only)
--------------------------------
    py dab_gateway_probe_test.py --condition stopped

Controlled comparison
---------------------
    py dab_gateway_probe_test.py --send --condition stopped \
        --families 0011,0012,0812,0019 --repeats 3

Use one physical adapter as injector and a second as observer, both connected to
exactly the same properly terminated CAN bus.
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
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

try:
    import can
except ImportError:
    print("Missing dependency: python-can", file=sys.stderr)
    print("Install with: py -m pip install python-can", file=sys.stderr)
    raise


# Confirmed/targeted response IDs for inverter addresses 1..8.
STATUS_IDS = {0x103C0401 + 0x10 * i: i + 1 for i in range(8)}
PROCESS_IDS = {0x103C0481 + 0x10 * i: i + 1 for i in range(8)}
RESPONSE_IDS = {**STATUS_IDS, **PROCESS_IDS}

RAW_HEADERS = [
    "utc",
    "host_rel_ms",
    "adapter",
    "direction",
    "phase",
    "trial",
    "condition",
    "probe_family_hex",
    "probe_token_hex",
    "can_id_hex",
    "family_hex",
    "token_hex",
    "extended",
    "dlc",
    "data_hex",
    "is_error",
    "status",
]

RESULT_HEADERS = [
    "utc",
    "trial",
    "condition",
    "probe_family_hex",
    "probe_token_hex",
    "tx_can_id_hex",
    "tx_data_hex",
    "tx_ok",
    "baseline_frames",
    "pre_frames",
    "post_frames",
    "post_error_frames",
    "response_frames",
    "response_ids",
    "response_addresses",
    "distinct_response_payloads",
    "first_response_latency_ms",
    "last_response_latency_ms",
    "response_burst_ms",
    "late_response_frames",
    "baseline_0011_frames",
    "baseline_0001_0011_pairs",
    "operator_display",
    "operator_comm_icon",
    "operator_pump_state",
    "operator_pressure_bar",
    "operator_notes",
]


@dataclass
class FrameRecord:
    utc: str
    host_rel_ms: float
    adapter: str
    direction: str
    phase: str
    trial: int
    condition: str
    probe_family_hex: str
    probe_token_hex: str
    can_id_hex: str
    family_hex: str
    token_hex: str
    extended: int
    dlc: int
    data_hex: str
    is_error: int
    status: str


@dataclass
class Observation:
    display: str = ""
    comm_icon: str = ""
    pump_state: str = ""
    pressure_bar: str = ""
    notes: str = ""


class CsvSink:
    def __init__(self, path: Path, headers: Sequence[str]):
        self.path = path
        self._file = path.open("w", newline="", encoding="utf-8")
        self._writer = csv.DictWriter(self._file, fieldnames=headers)
        self._writer.writeheader()
        self._lock = threading.Lock()

    def write(self, row: Dict[str, object]) -> None:
        with self._lock:
            self._writer.writerow(row)
            self._file.flush()

    def close(self) -> None:
        with self._lock:
            self._file.flush()
            self._file.close()


class Capture:
    def __init__(
        self,
        observer_bus: "can.BusABC",
        raw_sink: CsvSink,
        started_mono: float,
        condition: str,
        max_error_frames: int,
    ):
        self.bus = observer_bus
        self.raw_sink = raw_sink
        self.started_mono = started_mono
        self.condition = condition
        self.max_error_frames = max_error_frames
        self.phase = "initializing"
        self.trial = 0
        self.probe_family = ""
        self.probe_token = ""
        self.records: List[FrameRecord] = []
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.abort_event = threading.Event()
        self.error_count = 0
        self.thread = threading.Thread(target=self._reader, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=2.0)

    def set_phase(
        self,
        phase: str,
        trial: int = 0,
        probe_family: str = "",
        probe_token: str = "",
    ) -> None:
        with self.lock:
            self.phase = phase
            self.trial = trial
            self.probe_family = probe_family
            self.probe_token = probe_token

    def snapshot_index(self) -> int:
        with self.lock:
            return len(self.records)

    def records_since(self, index: int) -> List[FrameRecord]:
        with self.lock:
            return list(self.records[index:])

    def _reader(self) -> None:
        while not self.stop_event.is_set():
            try:
                msg = self.bus.recv(timeout=0.1)
            except Exception as exc:
                print(f"\nObserver receive error: {exc}", file=sys.stderr)
                self.abort_event.set()
                return

            if msg is None:
                continue

            now = time.monotonic()
            is_error = bool(getattr(msg, "is_error_frame", False))
            if is_error:
                self.error_count += 1
                if self.error_count >= self.max_error_frames:
                    print(
                        f"\nSafety abort: {self.error_count} CAN error frames observed.",
                        file=sys.stderr,
                    )
                    self.abort_event.set()

            arbitration_id = int(msg.arbitration_id)
            family = (arbitration_id >> 16) & 0x1FFF
            token = arbitration_id & 0xFFFF
            data = bytes(msg.data)

            with self.lock:
                phase = self.phase
                trial = self.trial
                probe_family = self.probe_family
                probe_token = self.probe_token

            record = FrameRecord(
                utc=utc_now(),
                host_rel_ms=round((now - self.started_mono) * 1000.0, 3),
                adapter="observer",
                direction="RX",
                phase=phase,
                trial=trial,
                condition=self.condition,
                probe_family_hex=probe_family,
                probe_token_hex=probe_token,
                can_id_hex=f"{arbitration_id:08X}",
                family_hex=f"{family:04X}",
                token_hex=f"{token:04X}",
                extended=int(bool(msg.is_extended_id)),
                dlc=int(msg.dlc),
                data_hex=hex_bytes(data),
                is_error=int(is_error),
                status="ERROR_FRAME" if is_error else "OK",
            )

            with self.lock:
                self.records.append(record)
            self.raw_sink.write(asdict(record))


class SafetyAbort(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def hex_bytes(data: bytes) -> str:
    return " ".join(f"{b:02X}" for b in data)


def parse_hex(value: str, bits: int) -> int:
    text = value.strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    result = int(text, 16)
    maximum = (1 << bits) - 1
    if not 0 <= result <= maximum:
        raise argparse.ArgumentTypeError(
            f"hex value {value!r} does not fit in {bits} bits"
        )
    return result


def parse_family_list(text: str) -> List[int]:
    families = [parse_hex(item, 13) for item in text.split(",") if item.strip()]
    if not families:
        raise argparse.ArgumentTypeError("at least one family is required")
    return families


def wait_with_abort(seconds: float, capture: Capture, label: str) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if capture.abort_event.is_set():
            raise SafetyAbort(f"aborted during {label}")
        time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))


def send_short_probe(
    injector_bus: "can.BusABC",
    family: int,
    token: int,
    capture: Capture,
    raw_sink: CsvSink,
    started_mono: float,
    trial: int,
    condition: str,
) -> Tuple[bool, float, int, bytes]:
    arbitration_id = (family << 16) | token
    payload = bytes([0x01, 0x00, 0x00, token & 0xFF, (token >> 8) & 0xFF])
    message = can.Message(
        arbitration_id=arbitration_id,
        is_extended_id=True,
        data=payload,
    )

    tx_mono = time.monotonic()
    ok = True
    status = "OK"
    try:
        injector_bus.send(message, timeout=0.5)
    except Exception as exc:
        ok = False
        status = f"TX_ERROR: {exc!r}"

    tx_record = FrameRecord(
        utc=utc_now(),
        host_rel_ms=round((tx_mono - started_mono) * 1000.0, 3),
        adapter="injector",
        direction="TX",
        phase="probe_tx",
        trial=trial,
        condition=condition,
        probe_family_hex=f"{family:04X}",
        probe_token_hex=f"{token:04X}",
        can_id_hex=f"{arbitration_id:08X}",
        family_hex=f"{family:04X}",
        token_hex=f"{token:04X}",
        extended=1,
        dlc=len(payload),
        data_hex=hex_bytes(payload),
        is_error=0,
        status=status,
    )
    raw_sink.write(asdict(tx_record))
    return ok, tx_mono, arbitration_id, payload


def response_records(records: Iterable[FrameRecord]) -> List[FrameRecord]:
    result = []
    for record in records:
        try:
            can_id = int(record.can_id_hex, 16)
        except ValueError:
            continue
        if can_id in RESPONSE_IDS and not record.is_error:
            result.append(record)
    return result


def count_baseline_pairs(records: Iterable[FrameRecord], max_gap_ms: float = 2.0) -> int:
    """Count matching 0001/0011 tokens occurring close together."""
    by_token: Dict[str, Dict[str, List[float]]] = defaultdict(
        lambda: {"0001": [], "0011": []}
    )
    for record in records:
        if record.is_error or record.family_hex not in ("0001", "0011"):
            continue
        by_token[record.token_hex][record.family_hex].append(record.host_rel_ms)

    pairs = 0
    for groups in by_token.values():
        left = sorted(groups["0001"])
        right = sorted(groups["0011"])
        i = j = 0
        while i < len(left) and j < len(right):
            delta = right[j] - left[i]
            if abs(delta) <= max_gap_ms:
                pairs += 1
                i += 1
                j += 1
            elif left[i] < right[j]:
                i += 1
            else:
                j += 1
    return pairs


def summarize_trial(
    trial: int,
    condition: str,
    family: int,
    token: int,
    tx_id: int,
    tx_data: bytes,
    tx_ok: bool,
    tx_mono: float,
    started_mono: float,
    baseline: List[FrameRecord],
    pre: List[FrameRecord],
    post: List[FrameRecord],
    late: List[FrameRecord],
    observation: Observation,
) -> Dict[str, object]:
    responses = response_records(post)
    late_responses = response_records(late)
    response_counts = Counter(r.can_id_hex for r in responses)
    addresses = sorted(
        {
            RESPONSE_IDS[int(r.can_id_hex, 16)]
            for r in responses
            if int(r.can_id_hex, 16) in RESPONSE_IDS
        }
    )
    payloads = sorted({r.data_hex for r in responses})

    if responses:
        response_times = [
            r.host_rel_ms - ((tx_mono - started_mono) * 1000.0)
            for r in responses
        ]
        first_latency = round(min(response_times), 3)
        last_latency = round(max(response_times), 3)
        burst = round(last_latency - first_latency, 3)
    else:
        first_latency = ""
        last_latency = ""
        burst = ""

    baseline_0011 = sum(
        1 for r in baseline if r.family_hex == "0011" and not r.is_error
    )

    return {
        "utc": utc_now(),
        "trial": trial,
        "condition": condition,
        "probe_family_hex": f"{family:04X}",
        "probe_token_hex": f"{token:04X}",
        "tx_can_id_hex": f"{tx_id:08X}",
        "tx_data_hex": hex_bytes(tx_data),
        "tx_ok": tx_ok,
        "baseline_frames": len(baseline),
        "pre_frames": len(pre),
        "post_frames": len(post),
        "post_error_frames": sum(r.is_error for r in post),
        "response_frames": len(responses),
        "response_ids": " | ".join(
            f"{can_id}:{count}" for can_id, count in sorted(response_counts.items())
        ),
        "response_addresses": ",".join(str(a) for a in addresses),
        "distinct_response_payloads": len(payloads),
        "first_response_latency_ms": first_latency,
        "last_response_latency_ms": last_latency,
        "response_burst_ms": burst,
        "late_response_frames": len(late_responses),
        "baseline_0011_frames": baseline_0011,
        "baseline_0001_0011_pairs": count_baseline_pairs(baseline),
        "operator_display": observation.display,
        "operator_comm_icon": observation.comm_icon,
        "operator_pump_state": observation.pump_state,
        "operator_pressure_bar": observation.pressure_bar,
        "operator_notes": observation.notes,
    }


def ask_observation(non_interactive: bool) -> Observation:
    if non_interactive:
        return Observation()

    print("\nRecord what the unit did after this ONE frame.")
    print("Leave a field blank if it was not observed.")
    return Observation(
        display=input("Display message/value: ").strip(),
        comm_icon=input("Communication icon (none/flash/on/other): ").strip(),
        pump_state=input("Pump state (stopped/running/stopped unexpectedly/etc.): ").strip(),
        pressure_bar=input("Observed pressure in bar: ").strip(),
        notes=input("Other notes: ").strip(),
    )


def require_confirmation(
    family: int,
    token: int,
    condition: str,
    assume_yes: bool,
) -> None:
    if assume_yes:
        return

    print("\nAbout to transmit exactly ONE frame:")
    print(f"  condition : {condition}")
    print(f"  CAN ID    : {(family << 16) | token:08X}")
    print(f"  family    : {family:04X}")
    print(f"  token     : {token:04X}")
    print(f"  data      : 01 00 00 {token & 0xFF:02X} {(token >> 8) & 0xFF:02X}")
    print("Type SEND to transmit, SKIP to skip, or ABORT to stop the script.")
    answer = input("Decision: ").strip().upper()
    if answer == "ABORT":
        raise KeyboardInterrupt
    if answer != "SEND":
        raise SafetyAbort("operator skipped transmission")


def build_order(families: Sequence[int], repeats: int, randomize: bool, seed: int) -> List[int]:
    order = [family for _ in range(repeats) for family in families]
    if randomize:
        random.Random(seed).shuffle(order)
    return order


def open_pcan_bus(channel: str, bitrate: int, receive_own_messages: bool = False):
    return can.interface.Bus(
        interface="pcan",
        channel=channel,
        bitrate=bitrate,
        receive_own_messages=receive_own_messages,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Single-shot DAB gateway-versus-peer family experiment"
    )
    parser.add_argument("--send", action="store_true", help="enable transmission")
    parser.add_argument("--injector", default="PCAN_USBBUS1")
    parser.add_argument("--observer", default="PCAN_USBBUS2")
    parser.add_argument("--bitrate", type=int, default=1_000_000)
    parser.add_argument(
        "--families",
        type=parse_family_list,
        default=parse_family_list("0011,0012,0812,0019"),
        help="comma-separated 13-bit family values in hex",
    )
    parser.add_argument(
        "--token", type=lambda x: parse_hex(x, 16), default=parse_hex("C82D", 16)
    )
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--baseline-seconds", type=float, default=15.0)
    parser.add_argument("--pre-seconds", type=float, default=2.0)
    parser.add_argument("--post-seconds", type=float, default=5.0)
    parser.add_argument(
        "--late-seconds",
        type=float,
        default=25.0,
        help="continued observation after the immediate response window",
    )
    parser.add_argument("--cooldown-seconds", type=float, default=15.0)
    parser.add_argument(
        "--condition",
        default="stopped",
        choices=["stopped", "running", "other"],
    )
    parser.add_argument("--output", default="dab_gateway_probe_results")
    parser.add_argument("--randomize", action="store_true")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--assume-yes", action="store_true")
    parser.add_argument("--non-interactive", action="store_true")
    parser.add_argument("--power-cycle-between", action="store_true")
    parser.add_argument("--max-error-frames", type=int, default=1)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.repeats < 1:
        raise SystemExit("--repeats must be at least 1")

    print("DAB focused gateway/peer test")
    print("================================")
    print(f"Mode: {'ACTIVE SEND' if args.send else 'LISTEN ONLY'}")
    print(f"Condition: {args.condition}")
    print("Families:", ", ".join(f"{f:04X}" for f in args.families))
    print(f"Token: {args.token:04X}")
    print("\nIMPORTANT: run the first comparison with the pump stopped.")

    if args.condition == "running" and args.send and not args.assume_yes:
        warning = input(
            "Pump-running active test selected. Type I_ACCEPT_THE_RISK to continue: "
        ).strip()
        if warning != "I_ACCEPT_THE_RISK":
            print("Cancelled.")
            return 2

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_dir = Path(args.output) / stamp
    output_dir.mkdir(parents=True, exist_ok=True)

    raw_sink = CsvSink(output_dir / "raw.csv", RAW_HEADERS)
    result_sink = CsvSink(output_dir / "results.csv", RESULT_HEADERS)
    event_sink = CsvSink(output_dir / "events.csv", ["utc", "event", "details"])

    metadata = {
        "created_utc": utc_now(),
        "script": Path(__file__).name,
        "send_enabled": args.send,
        "injector": args.injector,
        "observer": args.observer,
        "bitrate": args.bitrate,
        "families_hex": [f"{f:04X}" for f in args.families],
        "token_hex": f"{args.token:04X}",
        "condition": args.condition,
        "repeats": args.repeats,
        "baseline_seconds": args.baseline_seconds,
        "pre_seconds": args.pre_seconds,
        "post_seconds": args.post_seconds,
        "late_seconds": args.late_seconds,
        "cooldown_seconds": args.cooldown_seconds,
        "randomize": args.randomize,
        "seed": args.seed,
    }
    (output_dir / "metadata.json").write_text(
        json.dumps(metadata, indent=2), encoding="utf-8"
    )

    injector_bus = None
    observer_bus = None
    capture = None
    started_mono = time.monotonic()

    def log_event(event: str, details: object) -> None:
        event_sink.write(
            {
                "utc": utc_now(),
                "event": event,
                "details": details
                if isinstance(details, str)
                else json.dumps(details, ensure_ascii=False),
            }
        )

    def on_signal(signum, frame):
        del frame
        log_event("signal_abort", {"signal": signum})
        if capture is not None:
            capture.abort_event.set()

    signal.signal(signal.SIGINT, on_signal)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, on_signal)

    try:
        observer_bus = open_pcan_bus(args.observer, args.bitrate)
        if args.send:
            injector_bus = open_pcan_bus(args.injector, args.bitrate)

        capture = Capture(
            observer_bus=observer_bus,
            raw_sink=raw_sink,
            started_mono=started_mono,
            condition=args.condition,
            max_error_frames=args.max_error_frames,
        )
        capture.start()
        log_event("session_started", metadata)

        print(f"\nCapturing baseline for {args.baseline_seconds:.1f} s...")
        capture.set_phase("baseline")
        baseline_start = capture.snapshot_index()
        wait_with_abort(args.baseline_seconds, capture, "baseline")
        baseline = capture.records_since(baseline_start)

        spontaneous = response_records(baseline)
        baseline_0011 = sum(
            1 for r in baseline if r.family_hex == "0011" and not r.is_error
        )
        baseline_pairs = count_baseline_pairs(baseline)
        print(f"Baseline frames: {len(baseline)}")
        print(f"Baseline 0011 frames: {baseline_0011}")
        print(f"Matched 0001/0011 token pairs: {baseline_pairs}")
        print(f"Spontaneous targeted 103C frames: {len(spontaneous)}")
        log_event(
            "baseline_completed",
            {
                "frames": len(baseline),
                "family_0011_frames": baseline_0011,
                "matched_0001_0011_pairs": baseline_pairs,
                "spontaneous_103c_frames": len(spontaneous),
                "error_frames": sum(r.is_error for r in baseline),
            },
        )

        if capture.abort_event.is_set():
            raise SafetyAbort("CAN errors during baseline")

        if not args.send:
            print("\nListen-only run completed; no frames were transmitted.")
            return 0

        order = build_order(args.families, args.repeats, args.randomize, args.seed)
        completed_results: List[Dict[str, object]] = []

        for trial, family in enumerate(order, start=1):
            if capture.abort_event.is_set():
                raise SafetyAbort("capture requested abort")

            print("\n" + "-" * 72)
            print(f"Trial {trial}/{len(order)}: family {family:04X}")

            if args.power_cycle_between and not args.non_interactive:
                input(
                    "Power-cycle/reset the unit, restore the requested condition, "
                    "then press Enter: "
                )

            capture.set_phase(
                "pre", trial, f"{family:04X}", f"{args.token:04X}"
            )
            pre_start = capture.snapshot_index()
            wait_with_abort(args.pre_seconds, capture, "pre window")
            pre = capture.records_since(pre_start)

            try:
                require_confirmation(
                    family, args.token, args.condition, args.assume_yes
                )
            except SafetyAbort as exc:
                log_event(
                    "trial_skipped",
                    {"trial": trial, "family": f"{family:04X}", "reason": str(exc)},
                )
                print("Trial skipped.")
                continue

            capture.set_phase(
                "post", trial, f"{family:04X}", f"{args.token:04X}"
            )
            post_start = capture.snapshot_index()
            tx_ok, tx_mono, tx_id, tx_data = send_short_probe(
                injector_bus=injector_bus,
                family=family,
                token=args.token,
                capture=capture,
                raw_sink=raw_sink,
                started_mono=started_mono,
                trial=trial,
                condition=args.condition,
            )
            log_event(
                "probe_sent",
                {
                    "trial": trial,
                    "family_hex": f"{family:04X}",
                    "token_hex": f"{args.token:04X}",
                    "can_id_hex": f"{tx_id:08X}",
                    "tx_ok": tx_ok,
                },
            )
            if not tx_ok:
                raise SafetyAbort("probe transmission failed")

            wait_with_abort(args.post_seconds, capture, "immediate post window")
            post = capture.records_since(post_start)

            capture.set_phase(
                "late_observation", trial, f"{family:04X}", f"{args.token:04X}"
            )
            late_start = capture.snapshot_index()
            wait_with_abort(args.late_seconds, capture, "late observation window")
            late = capture.records_since(late_start)

            observation = ask_observation(args.non_interactive)
            result = summarize_trial(
                trial=trial,
                condition=args.condition,
                family=family,
                token=args.token,
                tx_id=tx_id,
                tx_data=tx_data,
                tx_ok=tx_ok,
                tx_mono=tx_mono,
                started_mono=started_mono,
                baseline=baseline,
                pre=pre,
                post=post,
                late=late,
                observation=observation,
            )
            result_sink.write(result)
            completed_results.append(result)
            log_event("trial_completed", result)

            print(
                f"Response frames: {result['response_frames']}; "
                f"IDs: {result['response_ids'] or 'none'}; "
                f"late responses: {result['late_response_frames']}"
            )

            notes_lower = " ".join(
                [observation.display, observation.pump_state, observation.notes]
            ).lower()
            if any(
                word in notes_lower
                for word in ("unexpected", "fault", "error", "stop", "wait")
            ):
                print("\nPotential operational disturbance recorded.")
                if not args.non_interactive:
                    decision = input(
                        "Type CONTINUE to proceed, anything else to abort: "
                    ).strip().upper()
                    if decision != "CONTINUE":
                        raise SafetyAbort("operator stopped after disturbance")

            if trial != len(order):
                capture.set_phase("cooldown")
                print(f"Cooling down/listening for {args.cooldown_seconds:.1f} s...")
                wait_with_abort(args.cooldown_seconds, capture, "cooldown")

        # Produce a compact machine-readable comparison.
        comparison: Dict[str, Dict[str, object]] = {}
        grouped: Dict[str, List[Dict[str, object]]] = defaultdict(list)
        for result in completed_results:
            grouped[str(result["probe_family_hex"])].append(result)

        for family, rows in sorted(grouped.items()):
            comparison[family] = {
                "trials": len(rows),
                "trials_with_103c_response": sum(
                    int(row["response_frames"]) > 0 for row in rows
                ),
                "total_response_frames": sum(
                    int(row["response_frames"]) for row in rows
                ),
                "late_response_frames": sum(
                    int(row["late_response_frames"]) for row in rows
                ),
                "communication_icon_observations": sorted(
                    {str(row["operator_comm_icon"]) for row in rows if row["operator_comm_icon"]}
                ),
                "display_observations": sorted(
                    {str(row["operator_display"]) for row in rows if row["operator_display"]}
                ),
                "pump_state_observations": sorted(
                    {str(row["operator_pump_state"]) for row in rows if row["operator_pump_state"]}
                ),
            }

        summary = {
            "created_utc": utc_now(),
            "baseline": {
                "frames": len(baseline),
                "family_0011_frames": baseline_0011,
                "matched_0001_0011_pairs": baseline_pairs,
                "spontaneous_target_103c_frames": len(spontaneous),
            },
            "comparison": comparison,
            "interpretation_guide": {
                "0011_no_response": "consistent with occupied/self slot, but not proof by itself",
                "0012_response_with_ui_change": "consistent with simulated peer slot",
                "0812_same_as_0012": "0x0800 is probably an alias/don't-care bit",
                "0812_response_without_ui_change": "supports, but does not prove, a gateway class",
                "0019_no_response": "supports upper boundary after slot 8",
                "late_103c_frames": "possible persistent peer/network-management state",
            },
        }
        (output_dir / "summary.json").write_text(
            json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
        )

        print(f"\nCompleted. Results written to: {output_dir.resolve()}")
        print("Review results.csv, events.csv, raw.csv, and summary.json.")
        return 0

    except KeyboardInterrupt:
        print("\nOperator abort.")
        log_event("session_aborted", "operator or signal")
        return 130
    except SafetyAbort as exc:
        print(f"\nSafety abort: {exc}", file=sys.stderr)
        log_event("safety_abort", str(exc))
        return 3
    except Exception as exc:
        print(f"\nFatal error: {exc!r}", file=sys.stderr)
        log_event("fatal_exception", repr(exc))
        return 1
    finally:
        if capture is not None:
            capture.stop()
        for bus in (injector_bus, observer_bus):
            if bus is not None:
                try:
                    bus.shutdown()
                except Exception:
                    pass
        log_event("session_finished", "shutdown")
        raw_sink.close()
        result_sink.close()
        event_sink.close()


if __name__ == "__main__":
    raise SystemExit(main())
