#!/usr/bin/env python3
"""DAB Active Driver Plus CAN validation tests.

Requires:
    pip install python-can

Examples:
    python dab_validation_tests.py boundary --send --repeats 5
    python dab_validation_tests.py alias --send --repeats 3
    python dab_validation_tests.py ad-matrix --send --repeats 3
    python dab_validation_tests.py token-sweep --send --family 0012
    python dab_validation_tests.py node-minimal --send --address 3
    python dab_validation_tests.py p4 --send
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import signal
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

import can

BITRATE = 1_000_000
DEFAULT_INJECTOR = "PCAN_USBBUS1"
DEFAULT_OBSERVER = "PCAN_USBBUS2"
POLL_TOKEN = 0xC82D
POLL_DATA = bytes.fromhex("01 00 00 2D C8")
RESPONSE_FAMILY = 0x103C
STOP = False


def stop_handler(_signum, _frame):
    global STOP
    STOP = True
    print("\nStop requested; finishing current receive window...")


signal.signal(signal.SIGINT, stop_handler)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_hex(value: str) -> int:
    return int(value.strip().lower().replace("0x", ""), 16)


def hex_data(data) -> str:
    return " ".join(f"{byte:02X}" for byte in data)


def make_bus(channel: str) -> can.BusABC:
    return can.Bus(interface="pcan", channel=channel, bitrate=BITRATE)


def error_frame(message: can.Message) -> bool:
    return bool(getattr(message, "is_error_frame", False))


def decode_response_address(arbitration_id: int) -> Optional[int]:
    if arbitration_id >> 16 != RESPONSE_FAMILY:
        return None
    low_byte = arbitration_id & 0xFF
    address = ((low_byte - 1) >> 4) + 1
    return address if 1 <= address <= 8 else None


@dataclass
class ProbeResult:
    utc: str
    test: str
    test_value: str
    repeat: int
    operator_ad: Optional[int]
    operator_state: str
    tx_can_id_hex: str
    tx_data_hex: str
    tx_ok: bool
    pre_frames: int
    post_frames: int
    response_frames: int
    response_ids: str
    response_payloads: str
    decoded_addresses: str
    first_response_latency_ms: Optional[float]
    last_response_latency_ms: Optional[float]
    error_frames: int
    notes: str


class TestLogger:
    RESULT_FIELDS = list(ProbeResult.__dataclass_fields__)
    RAW_FIELDS = [
        "utc", "host_rel_ms", "window", "can_id_hex", "extended",
        "dlc", "data_hex", "is_error"
    ]
    EVENT_FIELDS = ["utc", "event", "details"]

    def __init__(self, root: str, test_name: str, args: argparse.Namespace):
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.start_ns = time.monotonic_ns()
        self.folder = Path(root) / f"{stamp}_{test_name}"
        self.folder.mkdir(parents=True, exist_ok=False)
        self.results_file = self.folder / "results.csv"
        self.raw_file = self.folder / "raw.csv"
        self.events_file = self.folder / "events.csv"

        self._create_csv(self.results_file, self.RESULT_FIELDS)
        self._create_csv(self.raw_file, self.RAW_FIELDS)
        self._create_csv(self.events_file, self.EVENT_FIELDS)

        metadata = {
            "created_utc": utc_now(),
            "script": Path(__file__).name,
            "test": test_name,
            "bitrate": BITRATE,
            "arguments": vars(args),
        }
        (self.folder / "metadata.json").write_text(
            json.dumps(metadata, indent=2, default=str), encoding="utf-8"
        )

    @staticmethod
    def _create_csv(path: Path, fields: list[str]) -> None:
        with path.open("w", newline="", encoding="utf-8") as stream:
            csv.DictWriter(stream, fieldnames=fields).writeheader()

    @staticmethod
    def _append(path: Path, fields: list[str], row: dict) -> None:
        with path.open("a", newline="", encoding="utf-8") as stream:
            csv.DictWriter(stream, fieldnames=fields).writerow(row)

    def event(self, event: str, details: str = "") -> None:
        self._append(
            self.events_file, self.EVENT_FIELDS,
            {"utc": utc_now(), "event": event, "details": details},
        )

    def raw(self, arrival_ns: int, window: str, message: can.Message) -> None:
        self._append(
            self.raw_file,
            self.RAW_FIELDS,
            {
                "utc": utc_now(),
                "host_rel_ms": round((arrival_ns - self.start_ns) / 1e6, 3),
                "window": window,
                "can_id_hex": f"{message.arbitration_id:08X}",
                "extended": int(message.is_extended_id),
                "dlc": message.dlc,
                "data_hex": hex_data(message.data),
                "is_error": int(error_frame(message)),
            },
        )

    def result(self, result: ProbeResult) -> None:
        self._append(self.results_file, self.RESULT_FIELDS, asdict(result))


Captured = tuple[int, can.Message]


def collect(
    bus: can.BusABC,
    duration_s: float,
    logger: TestLogger,
    window: str,
) -> list[Captured]:
    captured: list[Captured] = []
    deadline_ns = time.monotonic_ns() + int(duration_s * 1e9)

    while not STOP and time.monotonic_ns() < deadline_ns:
        remaining = max(0.0, (deadline_ns - time.monotonic_ns()) / 1e9)
        message = bus.recv(timeout=min(0.02, remaining))
        if message is None:
            continue
        arrival_ns = time.monotonic_ns()
        captured.append((arrival_ns, message))
        logger.raw(arrival_ns, window, message)

    return captured


def transmit(
    bus: can.BusABC,
    arbitration_id: int,
    payload: bytes,
    enabled: bool,
) -> bool:
    if not enabled:
        return False

    bus.send(
        can.Message(
            arbitration_id=arbitration_id,
            is_extended_id=True,
            data=payload,
        ),
        timeout=0.2,
    )
    return True


def execute_probe(
    injector: can.BusABC,
    observer: can.BusABC,
    logger: TestLogger,
    args: argparse.Namespace,
    test: str,
    test_value: str,
    repeat: int,
    family: int,
    token: int = POLL_TOKEN,
    payload: bytes = POLL_DATA,
    operator_ad: Optional[int] = None,
    operator_state: str = "",
    notes: str = "",
) -> ProbeResult:
    pre = collect(observer, args.pre, logger, "pre")
    arbitration_id = (family << 16) | token

    tx_ns = time.monotonic_ns()
    tx_ok = transmit(injector, arbitration_id, payload, args.send)
    post = collect(observer, args.post, logger, "post")

    responses = [
        (arrival_ns, message)
        for arrival_ns, message in post
        if not error_frame(message)
        and message.is_extended_id
        and message.arbitration_id >> 16 == RESPONSE_FAMILY
    ]

    response_ids = sorted({f"{message.arbitration_id:08X}" for _, message in responses})
    response_payloads = sorted({hex_data(message.data) for _, message in responses})
    addresses = sorted({
        address
        for _, message in responses
        if (address := decode_response_address(message.arbitration_id)) is not None
    })
    latencies = [(arrival_ns - tx_ns) / 1e6 for arrival_ns, _ in responses]

    result = ProbeResult(
        utc=utc_now(),
        test=test,
        test_value=test_value,
        repeat=repeat,
        operator_ad=operator_ad,
        operator_state=operator_state,
        tx_can_id_hex=f"{arbitration_id:08X}",
        tx_data_hex=hex_data(payload),
        tx_ok=tx_ok,
        pre_frames=len(pre),
        post_frames=len(post),
        response_frames=len(responses),
        response_ids=" | ".join(response_ids),
        response_payloads=" || ".join(response_payloads),
        decoded_addresses=" | ".join(str(address) for address in addresses),
        first_response_latency_ms=round(min(latencies), 3) if latencies else None,
        last_response_latency_ms=round(max(latencies), 3) if latencies else None,
        error_frames=sum(error_frame(message) for _, message in pre + post),
        notes=notes,
    )
    logger.result(result)

    latency = "-" if result.first_response_latency_ms is None else f"{result.first_response_latency_ms:.3f}"
    print(
        f"{test_value:24s} r={repeat:2d} TX={result.tx_can_id_hex} "
        f"responses={result.response_frames:2d} first={latency} ms "
        f"IDs={result.response_ids or '-'}"
    )
    return result


def open_buses(args: argparse.Namespace):
    injector = make_bus(args.injector)
    try:
        observer = make_bus(args.observer)
    except Exception:
        injector.shutdown()
        raise
    return injector, observer


def run_family_test(
    args: argparse.Namespace,
    families: Iterable[int],
    test_name: str,
) -> None:
    logger = TestLogger(args.output, test_name, args)
    injector, observer = open_buses(args)
    logger.event("session_started", f"injector={args.injector}; observer={args.observer}")

    try:
        for family in families:
            for repeat in range(1, args.repeats + 1):
                if STOP:
                    break
                execute_probe(
                    injector, observer, logger, args, test_name,
                    f"family={family:04X}", repeat, family,
                )
                time.sleep(args.gap)
            if STOP:
                break
    finally:
        injector.shutdown()
        observer.shutdown()
        logger.event("session_finished", "interrupted" if STOP else "completed")

    print(f"Output written to: {logger.folder}")


def run_boundary(args: argparse.Namespace) -> None:
    families = [
        0x0010, 0x0011, 0x0012, 0x0018, 0x0019, 0x001A,
        0x0810, 0x0811, 0x0812, 0x0818, 0x0819, 0x081A,
    ]
    run_family_test(args, families, "boundary")


def run_alias(args: argparse.Namespace) -> None:
    bases = range(0x0011, 0x001A)
    alias_bits = [0x0000, 0x0100, 0x0200, 0x0400, 0x0800, 0x1000]
    families = sorted({base | bit for base in bases for bit in alias_bits})
    run_family_test(args, families, "alias")


def run_ad_matrix(args: argparse.Namespace) -> None:
    logger = TestLogger(args.output, "ad-matrix", args)
    injector, observer = open_buses(args)
    addresses = [args.address] if args.address else list(range(1, 9))

    try:
        for address in addresses:
            input(
                f"\nSet AD.6.5.7 to {address}, power-cycle if required, "
                "verify the display, then press Enter..."
            )
            logger.event("operator_ad_confirmed", str(address))

            for family in range(0x0012, 0x0019):
                for repeat in range(1, args.repeats + 1):
                    execute_probe(
                        injector, observer, logger, args, "ad-matrix",
                        f"AD={address};family={family:04X}", repeat, family,
                        operator_ad=address,
                    )
                    time.sleep(args.gap)
    except EOFError:
        logger.event("input_failure", "EOFError")
        print("Input stream closed; test aborted without generating placeholder probes.")
    finally:
        injector.shutdown()
        observer.shutdown()

    print(f"Output written to: {logger.folder}")


def run_token_sweep(args: argparse.Namespace) -> None:
    rng = random.Random(args.seed)
    tokens = [0x0000, 0x0001, 0x1234, 0x7FFF, 0x8000, 0xC82D, 0xFFFF]
    tokens += [rng.randrange(0x10000) for _ in range(args.random_tokens)]

    logger = TestLogger(args.output, "token-sweep", args)
    injector, observer = open_buses(args)

    try:
        for token in tokens:
            payload = bytes([0x01, 0x00, 0x00, token & 0xFF, token >> 8])
            for repeat in range(1, args.repeats + 1):
                execute_probe(
                    injector, observer, logger, args, "token-sweep",
                    f"token={token:04X}", repeat, args.family,
                    token=token, payload=payload,
                )
                time.sleep(args.gap)
    finally:
        injector.shutdown()
        observer.shutdown()

    print(f"Output written to: {logger.folder}")


def run_p4(args: argparse.Namespace) -> None:
    states = [
        ("pump_off_0.0bar", "Pump stopped; record residual pressure"),
        ("pump_on_2.0bar", "Pump genuinely running at 2.0 bar"),
        ("pump_on_2.2bar", "Pump genuinely running at 2.2 bar"),
        ("pump_on_2.5bar", "Pump genuinely running at 2.5 bar"),
        ("pump_off_final", "Pump stopped again"),
    ]

    logger = TestLogger(args.output, "p4", args)
    injector, observer = open_buses(args)

    try:
        for state, requirement in states:
            print(f"\nRequired physical state: {requirement}")
            input("Press Enter only after pressure, frequency and current are stable...")
            readings = input(
                "Enter display pressure, mechanical pressure, frequency, current and notes: "
            ).strip()
            logger.event("operator_state_confirmed", f"{state}; {readings}")

            for repeat in range(1, args.polls + 1):
                execute_probe(
                    injector, observer, logger, args, "p4", state, repeat,
                    0x0012, operator_state=state, notes=readings,
                )
                time.sleep(args.poll_gap)
    except EOFError:
        logger.event("input_failure", "EOFError")
        print("Input stream closed; test aborted without placeholder results.")
    finally:
        injector.shutdown()
        observer.shutdown()

    print(f"Output written to: {logger.folder}")


def make_node_frames(address: int, token: int, mode: str) -> list[can.Message]:
    low = token & 0xFF
    high = token >> 8

    long_frame = can.Message(
        arbitration_id=(address << 16) | token,
        is_extended_id=True,
        data=bytes([0x01, 0x00, 0x00, 0x0F, 0x03, low, high]),
    )
    short_frame = can.Message(
        arbitration_id=((0x10 + address) << 16) | token,
        is_extended_id=True,
        data=bytes([0x01, 0x00, 0x00, low, high]),
    )

    if mode == "short-only":
        return [short_frame]
    if mode == "long-only":
        return [long_frame]
    if mode == "reverse-pair":
        return [short_frame, long_frame]
    return [long_frame, short_frame]


def emulate_node(
    bus: can.BusABC,
    address: int,
    mode: str,
    duration: float,
    cycle_period: float,
    pair_gap: float,
    seed: int,
) -> int:
    rng = random.Random(seed)
    deadline = time.monotonic() + duration
    next_cycle = time.monotonic()
    sent = 0

    while not STOP and time.monotonic() < deadline:
        token = rng.randrange(1, 0x10000)
        frames = make_node_frames(address, token, mode)

        for index, frame in enumerate(frames):
            bus.send(frame, timeout=0.1)
            sent += 1
            if index + 1 < len(frames) and pair_gap > 0:
                time.sleep(pair_gap)

        next_cycle += cycle_period
        delay = next_cycle - time.monotonic()
        if delay > 0:
            time.sleep(delay)

    return sent


def run_node_minimal(args: argparse.Namespace) -> None:
    logger = TestLogger(args.output, "node-minimal", args)
    injector = make_bus(args.injector)
    modes = ["short-only", "long-only", "pair", "reverse-pair"]

    try:
        for mode in modes:
            input(
                f"\nReady for {mode}, synthetic address {args.address}. "
                "Press Enter to begin..."
            )
            logger.event("phase_started", mode)

            if args.send:
                sent = emulate_node(
                    injector, args.address, mode, args.duration,
                    args.cycle_period, args.pair_gap, args.seed,
                )
            else:
                sent = 0
                time.sleep(min(args.duration, 1.0))

            observation = input(
                "Record N, VP, communication icon, display message and pump behaviour: "
            ).strip()
            logger.event(
                "operator_observation",
                f"mode={mode}; frames_sent={sent}; {observation}",
            )
            input("Restore/recover the unit, then press Enter to continue...")
    except EOFError:
        logger.event("input_failure", "EOFError")
        print("Input stream closed; test aborted.")
    finally:
        injector.shutdown()

    print(f"Output written to: {logger.folder}")


def add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--send", action="store_true", help="Enable CAN transmission")
    parser.add_argument("--injector", default=DEFAULT_INJECTOR)
    parser.add_argument("--observer", default=DEFAULT_OBSERVER)
    parser.add_argument("--output", default="dab_validation_results")
    parser.add_argument("--pre", type=float, default=0.25)
    parser.add_argument("--post", type=float, default=0.35)
    parser.add_argument("--gap", type=float, default=0.40)
    parser.add_argument("--repeats", type=int, default=5)


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DAB CAN validation test harness")
    commands = parser.add_subparsers(dest="command", required=True)

    boundary = commands.add_parser("boundary")
    add_common(boundary)
    boundary.set_defaults(handler=run_boundary)

    alias = commands.add_parser("alias")
    add_common(alias)
    alias.set_defaults(handler=run_alias)

    matrix = commands.add_parser("ad-matrix")
    add_common(matrix)
    matrix.add_argument("--address", type=int, choices=range(1, 9))
    matrix.set_defaults(handler=run_ad_matrix)

    token = commands.add_parser("token-sweep")
    add_common(token)
    token.add_argument("--family", type=parse_hex, default=0x0012)
    token.add_argument("--random-tokens", type=int, default=25)
    token.add_argument("--seed", type=int, default=42)
    token.set_defaults(handler=run_token_sweep)

    p4 = commands.add_parser("p4")
    add_common(p4)
    p4.add_argument("--polls", type=int, default=5)
    p4.add_argument("--poll-gap", type=float, default=5.0)
    p4.set_defaults(handler=run_p4)

    node = commands.add_parser("node-minimal")
    add_common(node)
    node.add_argument("--address", type=int, choices=range(1, 9), default=3)
    node.add_argument("--duration", type=float, default=15.0)
    node.add_argument("--cycle-period", type=float, default=0.005)
    node.add_argument("--pair-gap", type=float, default=0.0001)
    node.add_argument("--seed", type=int, default=42)
    node.set_defaults(handler=run_node_minimal)

    return parser


def main() -> int:
    args = create_parser().parse_args()

    if args.send:
        confirmation = input(
            "ACTIVE CAN TRANSMISSION. Start with the pump stopped. Type SEND to continue: "
        ).strip()
        if confirmation != "SEND":
            print("Cancelled.")
            return 2
    else:
        print("DRY RUN: no CAN frames will be transmitted. Add --send to transmit.")

    try:
        args.handler(args)
        return 0
    except can.CanError as error:
        print(f"CAN error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
