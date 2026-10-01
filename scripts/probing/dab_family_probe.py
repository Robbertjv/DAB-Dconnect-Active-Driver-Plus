#!/usr/bin/env python3
"""
DAB Active Driver Plus – controlled CAN family probe

Purpose
-------
Keep token, DLC and payload fixed while varying only the upper CAN-ID family:

    can_id = (family << 16) | token

Timing correction
-----------------
TX/RX latency is calculated exclusively with time.monotonic_ns().
PCAN hardware timestamps and UTC timestamps are logged for reference, but are
never mixed with the monotonic host clock.

Safety
------
Transmission is disabled unless --send is explicitly supplied. By default the
known continuously active families 0x0001 and 0x0011 are blocked.

Example
-------
python dab_family_probe.py --send --families 0010,0012,0013,0014,0015 \
    --token C82D --repeats 3 --shuffle --seed 42

Alternatively, --family can be repeated:

python dab_family_probe.py --send --family 0010 --family 0012 \
    --family 0013 --token C82D
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import signal
import sys
import time
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

try:
    import PCANBasic as pcan
except ImportError:
    print(
        "ERROR: PCANBasic.py kon niet worden geïmporteerd. "
        "Installeer/kopieer de PEAK PCAN-Basic Python-wrapper naast dit script.",
        file=sys.stderr,
    )
    raise


RESPONSE_IDS = {0x103C0401, 0x103C0481}
ACTIVE_FAMILIES = {0x0001, 0x0011}
MAX_EXTENDED_ID = 0x1FFFFFFF
RAW_FIELDS = [
    "utc",
    "host_ns",
    "host_rel_ms",
    "hardware_us",
    "direction",
    "phase",
    "probe_index",
    "repeat_index",
    "probe_family_hex",
    "probe_token_hex",
    "can_id_hex",
    "family_hex",
    "token_hex",
    "dlc",
    "data_hex",
    "status_code",
    "status_text",
    "tx_ok",
    "latency_ms",
]
RESULT_FIELDS = [
    "utc",
    "probe_index",
    "repeat_index",
    "probe_family_hex",
    "probe_token_hex",
    "tx_can_id_hex",
    "tx_data_hex",
    "tx_ok",
    "rx_frames_in_window",
    "response_frames",
    "response_103C0401_count",
    "response_103C0481_count",
    "first_response_latency_ms",
    "last_response_latency_ms",
    "response_burst_ms",
    "response_ids",
    "distinct_response_payloads",
    "response_payloads",
]

STOP_REQUESTED = False


def request_stop(_signum=None, _frame=None) -> None:
    global STOP_REQUESTED
    STOP_REQUESTED = True


signal.signal(signal.SIGINT, request_stop)
if hasattr(signal, "SIGTERM"):
    signal.signal(signal.SIGTERM, request_stop)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def run_stamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def parse_hex(value: str, bits: int, label: str) -> int:
    text = value.strip().replace("_", "")
    if text.lower().startswith("0x"):
        text = text[2:]
    try:
        result = int(text, 16)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"{label} moet hexadecimaal zijn, bijvoorbeeld 0012 of 0x0012"
        ) from exc
    maximum = (1 << bits) - 1
    if not 0 <= result <= maximum:
        raise argparse.ArgumentTypeError(
            f"{label} buiten bereik: 0x{result:X}; toegestaan 0x0..0x{maximum:X}"
        )
    return result


def parse_family(value: str) -> int:
    # Het family-veld gebruikt maximaal 13 bits omdat family << 16 samen
    # met een 16-bit token in een 29-bit extended CAN-ID moet passen.
    return parse_hex(value, 13, "family")


def parse_token(value: str) -> int:
    return parse_hex(value, 16, "token")


def parse_family_list(value: str) -> list[int]:
    result: list[int] = []
    for item in value.split(","):
        if item.strip():
            result.append(parse_family(item))
    if not result:
        raise argparse.ArgumentTypeError("--families bevat geen waarden")
    return result


def unique_preserving_order(values: Iterable[int]) -> list[int]:
    seen: set[int] = set()
    output: list[int] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            output.append(value)
    return output


def data_to_hex(data: Iterable[int]) -> str:
    return " ".join(f"{int(byte):02X}" for byte in data)


def pcan_status_text(api, status: int) -> str:
    try:
        result, text = api.GetErrorText(status, 0)
        if result == pcan.PCAN_ERROR_OK:
            if isinstance(text, bytes):
                return text.decode(errors="replace")
            return str(text)
    except Exception:
        pass
    return f"PCAN status 0x{int(status):08X}"


def hardware_timestamp_us(timestamp) -> Optional[int]:
    """Convert TPCANTimestamp to µs when the classic API timestamp is present."""
    if timestamp is None:
        return None
    try:
        millis = int(timestamp.millis)
        overflow = int(timestamp.millis_overflow)
        micros = int(timestamp.micros)
        return ((overflow << 32) + millis) * 1000 + micros
    except (AttributeError, TypeError, ValueError):
        return None


def family_from_id(can_id: int) -> int:
    return (can_id >> 16) & 0x1FFF


def token_from_id(can_id: int) -> int:
    return can_id & 0xFFFF


def resolve_channel(name: str):
    try:
        return getattr(pcan, name)
    except AttributeError as exc:
        raise SystemExit(f"Onbekend PCAN-kanaal: {name}") from exc


def resolve_bitrate(value: str):
    key = value.strip().upper().replace(" ", "")
    mapping = {
        "1M": "PCAN_BAUD_1M",
        "1000000": "PCAN_BAUD_1M",
        "800K": "PCAN_BAUD_800K",
        "800000": "PCAN_BAUD_800K",
        "500K": "PCAN_BAUD_500K",
        "500000": "PCAN_BAUD_500K",
        "250K": "PCAN_BAUD_250K",
        "250000": "PCAN_BAUD_250K",
        "125K": "PCAN_BAUD_125K",
        "125000": "PCAN_BAUD_125K",
    }
    constant_name = mapping.get(key)
    if not constant_name or not hasattr(pcan, constant_name):
        raise SystemExit(f"Niet-ondersteunde bitrate: {value}")
    return getattr(pcan, constant_name)


@dataclass
class ReceivedFrame:
    utc: str
    host_ns: int
    hardware_us: Optional[int]
    can_id: int
    dlc: int
    data: bytes


class FamilyProbe:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.api = pcan.PCANBasic()
        self.channel = resolve_channel(args.channel)
        self.bitrate = resolve_bitrate(args.bitrate)
        self.session_start_ns = time.monotonic_ns()
        self.raw_file = None
        self.results_file = None
        self.raw_writer = None
        self.results_writer = None
        self.total_rx = 0
        self.total_tx_ok = 0
        self.total_tx_failed = 0

    def open_output(self) -> tuple[Path, Path, Path]:
        outdir = Path(self.args.output_dir)
        outdir.mkdir(parents=True, exist_ok=True)
        stamp = run_stamp()
        raw_path = outdir / f"dab_family_probe_raw_{stamp}.csv"
        results_path = outdir / f"dab_family_probe_results_{stamp}.csv"
        metadata_path = outdir / f"dab_family_probe_metadata_{stamp}.json"

        self.raw_file = raw_path.open("w", newline="", encoding="utf-8")
        self.results_file = results_path.open("w", newline="", encoding="utf-8")
        self.raw_writer = csv.DictWriter(self.raw_file, fieldnames=RAW_FIELDS)
        self.results_writer = csv.DictWriter(
            self.results_file, fieldnames=RESULT_FIELDS
        )
        self.raw_writer.writeheader()
        self.results_writer.writeheader()
        self.raw_file.flush()
        self.results_file.flush()
        return raw_path, results_path, metadata_path

    def initialize(self) -> None:
        status = self.api.Initialize(self.channel, self.bitrate)
        if status != pcan.PCAN_ERROR_OK:
            raise RuntimeError(
                f"PCAN Initialize mislukt: {pcan_status_text(self.api, status)}"
            )
        self.drain_receive_queue()

    def close(self) -> None:
        try:
            self.api.Uninitialize(self.channel)
        except Exception:
            pass
        if self.raw_file:
            self.raw_file.flush()
            self.raw_file.close()
        if self.results_file:
            self.results_file.flush()
            self.results_file.close()

    def drain_receive_queue(self) -> None:
        while True:
            status, _msg, _timestamp = self.api.Read(self.channel)
            if status == pcan.PCAN_ERROR_QRCVEMPTY:
                return
            if status != pcan.PCAN_ERROR_OK:
                return

    def log_raw(
        self,
        *,
        direction: str,
        phase: str,
        can_id: int,
        data: bytes,
        status_code: int,
        status_text: str,
        probe_index: Optional[int] = None,
        repeat_index: Optional[int] = None,
        probe_family: Optional[int] = None,
        probe_token: Optional[int] = None,
        host_ns: Optional[int] = None,
        hardware_us: Optional[int] = None,
        tx_ok: Optional[bool] = None,
        latency_ms: Optional[float] = None,
    ) -> None:
        if host_ns is None:
            host_ns = time.monotonic_ns()
        row = {
            "utc": utc_now(),
            "host_ns": host_ns,
            "host_rel_ms": round(
                (host_ns - self.session_start_ns) / 1_000_000.0, 6
            ),
            "hardware_us": "" if hardware_us is None else hardware_us,
            "direction": direction,
            "phase": phase,
            "probe_index": "" if probe_index is None else probe_index,
            "repeat_index": "" if repeat_index is None else repeat_index,
            "probe_family_hex": (
                "" if probe_family is None else f"{probe_family:04X}"
            ),
            "probe_token_hex": (
                "" if probe_token is None else f"{probe_token:04X}"
            ),
            "can_id_hex": f"{can_id:08X}",
            "family_hex": f"{family_from_id(can_id):04X}",
            "token_hex": f"{token_from_id(can_id):04X}",
            "dlc": len(data),
            "data_hex": data_to_hex(data),
            "status_code": int(status_code),
            "status_text": status_text,
            "tx_ok": "" if tx_ok is None else int(bool(tx_ok)),
            "latency_ms": "" if latency_ms is None else round(latency_ms, 6),
        }
        self.raw_writer.writerow(row)

    def read_one(self) -> Optional[ReceivedFrame]:
        status, msg, timestamp = self.api.Read(self.channel)
        if status == pcan.PCAN_ERROR_QRCVEMPTY:
            return None
        if status != pcan.PCAN_ERROR_OK:
            # Niet als CAN-frame behandelen. De fout blijft zichtbaar op stderr.
            print(
                f"PCAN Read: {pcan_status_text(self.api, status)}",
                file=sys.stderr,
            )
            return None

        # Neem de hosttimestamp onmiddellijk na Read(). Deze klok wordt ook voor
        # TX gebruikt en is daarom geschikt voor latencyberekening.
        host_ns = time.monotonic_ns()
        dlc = int(msg.LEN)
        data = bytes(int(msg.DATA[i]) for i in range(dlc))
        return ReceivedFrame(
            utc=utc_now(),
            host_ns=host_ns,
            hardware_us=hardware_timestamp_us(timestamp),
            can_id=int(msg.ID),
            dlc=dlc,
            data=data,
        )

    def capture_for(
        self,
        duration_s: float,
        phase: str,
        *,
        probe_index: Optional[int] = None,
        repeat_index: Optional[int] = None,
        probe_family: Optional[int] = None,
        probe_token: Optional[int] = None,
        tx_ns: Optional[int] = None,
    ) -> list[ReceivedFrame]:
        frames: list[ReceivedFrame] = []
        deadline_ns = time.monotonic_ns() + int(duration_s * 1_000_000_000)

        while not STOP_REQUESTED and time.monotonic_ns() < deadline_ns:
            frame = self.read_one()
            if frame is None:
                time.sleep(0.0005)
                continue

            self.total_rx += 1
            frames.append(frame)
            latency_ms = None
            if tx_ns is not None:
                latency_ms = (frame.host_ns - tx_ns) / 1_000_000.0

            self.log_raw(
                direction="RX",
                phase=phase,
                can_id=frame.can_id,
                data=frame.data,
                status_code=int(pcan.PCAN_ERROR_OK),
                status_text="OK",
                probe_index=probe_index,
                repeat_index=repeat_index,
                probe_family=probe_family,
                probe_token=probe_token,
                host_ns=frame.host_ns,
                hardware_us=frame.hardware_us,
                latency_ms=latency_ms,
            )

        self.raw_file.flush()
        return frames

    def send_probe(
        self,
        *,
        family: int,
        token: int,
        probe_index: int,
        repeat_index: int,
    ) -> tuple[bool, int, int, bytes, int, str]:
        can_id = (family << 16) | token
        if can_id > MAX_EXTENDED_ID:
            raise ValueError(f"CAN-ID buiten 29-bit bereik: 0x{can_id:X}")

        payload = bytes(
            [
                0x01,
                0x00,
                0x00,
                token & 0xFF,
                (token >> 8) & 0xFF,
            ]
        )

        if not self.args.send:
            host_ns = time.monotonic_ns()
            text = "DRY-RUN: niet verzonden"
            self.log_raw(
                direction="TX",
                phase="probe_tx_dry_run",
                can_id=can_id,
                data=payload,
                status_code=-1,
                status_text=text,
                probe_index=probe_index,
                repeat_index=repeat_index,
                probe_family=family,
                probe_token=token,
                host_ns=host_ns,
                tx_ok=False,
            )
            return False, host_ns, can_id, payload, -1, text

        msg = pcan.TPCANMsg()
        msg.ID = can_id
        msg.MSGTYPE = pcan.PCAN_MESSAGE_EXTENDED
        msg.LEN = len(payload)
        for index, byte in enumerate(payload):
            msg.DATA[index] = byte

        # Zelfde monotonic clock als RX. Neem de timestamp direct rond Write().
        before_ns = time.monotonic_ns()
        status = self.api.Write(self.channel, msg)
        after_ns = time.monotonic_ns()
        tx_ns = (before_ns + after_ns) // 2

        tx_ok = status == pcan.PCAN_ERROR_OK
        status_text = pcan_status_text(self.api, status)
        if tx_ok:
            self.total_tx_ok += 1
        else:
            self.total_tx_failed += 1

        self.log_raw(
            direction="TX",
            phase="probe_tx",
            can_id=can_id,
            data=payload,
            status_code=int(status),
            status_text=status_text,
            probe_index=probe_index,
            repeat_index=repeat_index,
            probe_family=family,
            probe_token=token,
            host_ns=tx_ns,
            tx_ok=tx_ok,
            latency_ms=0.0,
        )
        self.raw_file.flush()
        return tx_ok, tx_ns, can_id, payload, int(status), status_text

    def write_result(
        self,
        *,
        probe_index: int,
        repeat_index: int,
        family: int,
        token: int,
        can_id: int,
        payload: bytes,
        tx_ok: bool,
        tx_ns: int,
        rx_frames: list[ReceivedFrame],
    ) -> None:
        responses = [frame for frame in rx_frames if frame.can_id in RESPONSE_IDS]
        counts = Counter(frame.can_id for frame in responses)
        latencies = [
            (frame.host_ns - tx_ns) / 1_000_000.0 for frame in responses
        ]
        response_ids = sorted({frame.can_id for frame in responses})
        response_payloads = sorted({data_to_hex(frame.data) for frame in responses})

        first_latency = min(latencies) if latencies else None
        last_latency = max(latencies) if latencies else None
        burst_ms = (
            last_latency - first_latency
            if first_latency is not None and last_latency is not None
            else None
        )

        row = {
            "utc": utc_now(),
            "probe_index": probe_index,
            "repeat_index": repeat_index,
            "probe_family_hex": f"{family:04X}",
            "probe_token_hex": f"{token:04X}",
            "tx_can_id_hex": f"{can_id:08X}",
            "tx_data_hex": data_to_hex(payload),
            "tx_ok": int(tx_ok),
            "rx_frames_in_window": len(rx_frames),
            "response_frames": len(responses),
            "response_103C0401_count": counts[0x103C0401],
            "response_103C0481_count": counts[0x103C0481],
            "first_response_latency_ms": (
                "" if first_latency is None else round(first_latency, 6)
            ),
            "last_response_latency_ms": (
                "" if last_latency is None else round(last_latency, 6)
            ),
            "response_burst_ms": "" if burst_ms is None else round(burst_ms, 6),
            "response_ids": "|".join(f"{value:08X}" for value in response_ids),
            "distinct_response_payloads": len(response_payloads),
            "response_payloads": " || ".join(response_payloads),
        }
        self.results_writer.writerow(row)
        self.results_file.flush()

    def run(self, families: list[int], metadata_path: Path) -> None:
        sequence = [
            (repeat_index, family)
            for repeat_index in range(1, self.args.repeats + 1)
            for family in families
        ]
        if self.args.shuffle:
            rng = random.Random(self.args.seed)
            rng.shuffle(sequence)

        print(f"Baseline: {self.args.baseline_seconds:.3f} s")
        baseline_frames = self.capture_for(
            self.args.baseline_seconds,
            "baseline",
        )
        baseline_response_count = sum(
            frame.can_id in RESPONSE_IDS for frame in baseline_frames
        )
        print(
            f"Baseline ontvangen: {len(baseline_frames)} frames; "
            f"103C-responsframes: {baseline_response_count}"
        )

        for probe_index, (repeat_index, family) in enumerate(sequence, start=1):
            if STOP_REQUESTED:
                break

            print(
                f"[{probe_index}/{len(sequence)}] repeat={repeat_index}, "
                f"family=0x{family:04X}, token=0x{self.args.token:04X}"
            )

            self.capture_for(
                self.args.pre_seconds,
                "probe_pre",
                probe_index=probe_index,
                repeat_index=repeat_index,
                probe_family=family,
                probe_token=self.args.token,
            )

            tx_ok, tx_ns, can_id, payload, status, status_text = self.send_probe(
                family=family,
                token=self.args.token,
                probe_index=probe_index,
                repeat_index=repeat_index,
            )
            if self.args.send and not tx_ok:
                print(
                    f"  TX mislukt: 0x{status:08X} {status_text}",
                    file=sys.stderr,
                )

            rx_frames = self.capture_for(
                self.args.observe_seconds,
                "probe_rx",
                probe_index=probe_index,
                repeat_index=repeat_index,
                probe_family=family,
                probe_token=self.args.token,
                tx_ns=tx_ns,
            )
            self.write_result(
                probe_index=probe_index,
                repeat_index=repeat_index,
                family=family,
                token=self.args.token,
                can_id=can_id,
                payload=payload,
                tx_ok=tx_ok,
                tx_ns=tx_ns,
                rx_frames=rx_frames,
            )

            response_count = sum(
                frame.can_id in RESPONSE_IDS for frame in rx_frames
            )
            print(f"  bekende 103C-responsframes: {response_count}")

            if response_count:
                response_times = [
                    (frame.host_ns - tx_ns) / 1_000_000.0
                    for frame in rx_frames
                    if frame.can_id in RESPONSE_IDS
                ]
                print(
                    f"  eerste respons: {min(response_times):.3f} ms; "
                    f"burst: {max(response_times) - min(response_times):.3f} ms"
                )

            self.capture_for(
                self.args.gap_seconds,
                "inter_probe_gap",
                probe_index=probe_index,
                repeat_index=repeat_index,
                probe_family=family,
                probe_token=self.args.token,
            )

        metadata = {
            "script": Path(__file__).name,
            "finished_utc": utc_now(),
            "channel": self.args.channel,
            "bitrate": self.args.bitrate,
            "send_enabled": self.args.send,
            "families_hex": [f"{value:04X}" for value in families],
            "token_hex": f"{self.args.token:04X}",
            "payload_hex": data_to_hex(
                [
                    0x01,
                    0x00,
                    0x00,
                    self.args.token & 0xFF,
                    (self.args.token >> 8) & 0xFF,
                ]
            ),
            "repeats": self.args.repeats,
            "shuffle": self.args.shuffle,
            "seed": self.args.seed,
            "baseline_seconds": self.args.baseline_seconds,
            "pre_seconds": self.args.pre_seconds,
            "observe_seconds": self.args.observe_seconds,
            "gap_seconds": self.args.gap_seconds,
            "response_ids": [f"{value:08X}" for value in sorted(RESPONSE_IDS)],
            "latency_clock": "time.monotonic_ns",
            "baseline_frames": len(baseline_frames),
            "baseline_response_frames": baseline_response_count,
            "total_rx": self.total_rx,
            "total_tx_ok": self.total_tx_ok,
            "total_tx_failed": self.total_tx_failed,
            "stopped_by_user": STOP_REQUESTED,
        }
        metadata_path.write_text(
            json.dumps(metadata, indent=2), encoding="utf-8"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Varieer uitsluitend de CAN-ID-family terwijl token, DLC en payload "
            "gelijk blijven. Hexwaarden mogen met of zonder 0x worden opgegeven."
        )
    )
    parser.add_argument(
        "--family",
        action="append",
        type=parse_family,
        default=[],
        help=(
            "Eén family in hex, bijvoorbeeld --family 0012. "
            "Mag meerdere keren worden opgegeven."
        ),
    )
    parser.add_argument(
        "--families",
        action="append",
        type=parse_family_list,
        default=[],
        help=(
            "Kommalijst met families, bijvoorbeeld "
            "--families 0010,0012,0013,0014,0015"
        ),
    )
    parser.add_argument(
        "--token",
        type=parse_token,
        default=parse_token("C82D"),
        help="Vaste 16-bit token in hex; standaard C82D",
    )
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--baseline-seconds", type=float, default=10.0)
    parser.add_argument("--pre-seconds", type=float, default=0.5)
    parser.add_argument("--observe-seconds", type=float, default=0.3)
    parser.add_argument("--gap-seconds", type=float, default=2.0)
    parser.add_argument(
        "--shuffle",
        action="store_true",
        help="Randomiseer de family/repeat-volgorde",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Seed voor reproduceerbare randomisatie; standaard 42",
    )
    parser.add_argument("--channel", default="PCAN_USBBUS1")
    parser.add_argument("--bitrate", default="1M")
    parser.add_argument("--output-dir", default=".")
    parser.add_argument(
        "--send",
        action="store_true",
        help="TX werkelijk inschakelen; zonder deze vlag draait het script dry-run",
    )
    parser.add_argument(
        "--allow-active-families",
        action="store_true",
        help="Sta probes toe in normaal actieve families 0001/0011",
    )
    return parser


def validate_args(args: argparse.Namespace) -> list[int]:
    families: list[int] = list(args.family)
    for family_list in args.families:
        families.extend(family_list)
    if not families:
        families = [0x0012]
    families = unique_preserving_order(families)

    if args.repeats < 1:
        raise SystemExit("--repeats moet minimaal 1 zijn")
    for name in (
        "baseline_seconds",
        "pre_seconds",
        "observe_seconds",
        "gap_seconds",
    ):
        if getattr(args, name) < 0:
            raise SystemExit(f"--{name.replace('_', '-')} mag niet negatief zijn")

    blocked = sorted(set(families) & ACTIVE_FAMILIES)
    if blocked and not args.allow_active_families:
        formatted = ", ".join(f"0x{value:04X}" for value in blocked)
        raise SystemExit(
            f"Geblokkeerde actieve family/families: {formatted}. "
            "Gebruik alleen indien bewust gewenst: --allow-active-families"
        )

    return families


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    families = validate_args(args)

    print("DAB controlled family probe")
    print("Families:", ", ".join(f"0x{x:04X}" for x in families))
    print(f"Vaste token: 0x{args.token:04X}")
    print(
        "Vaste payload:",
        data_to_hex(
            [0x01, 0x00, 0x00, args.token & 0xFF, (args.token >> 8) & 0xFF]
        ),
    )
    print("TX:", "INGESCHAKELD" if args.send else "DRY-RUN")

    probe = FamilyProbe(args)
    raw_path = results_path = metadata_path = None
    try:
        raw_path, results_path, metadata_path = probe.open_output()
        probe.initialize()
        probe.run(families, metadata_path)
    except KeyboardInterrupt:
        request_stop()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        probe.close()

    print("Klaar.")
    if raw_path:
        print(f"Raw:      {raw_path}")
    if results_path:
        print(f"Results:  {results_path}")
    if metadata_path:
        print(f"Metadata: {metadata_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
