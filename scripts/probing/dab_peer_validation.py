#!/usr/bin/env python3
"""
DAB Active Driver Plus — peer-validatie en hiërarchietests.

Benodigd:
    pip install python-can

Aansluiting voor bewijs met twee adapters:
    PCAN_USBBUS1 = actieve injector/ACK-adapter
    PCAN_USBBUS2 = uitsluitend listen-only observer
    Beide adapters parallel op dezelfde CAN-H/CAN-L/GND.

Voorbeelden:
    python dab_peer_validation.py suppression
    python dab_peer_validation.py single-pair-timeout --repeats 20
    python dab_peer_validation.py locked-timeout --repeats 20
    python dab_peer_validation.py keepalive
    python dab_peer_validation.py short-families
    python dab_peer_validation.py pair-gap
    python dab_peer_validation.py addresses
    python dab_peer_validation.py reverse-order
    python dab_peer_validation.py interruptions
    python dab_peer_validation.py payload-001f --allow-001f-injection

Alle tests zenden CAN-frames. Gebruik alleen in een hydraulisch veilige toestand.
De payload-001f-test heeft een extra bevestiging nodig.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import signal
import threading
import time
from collections import Counter, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

import can


NORMAL_LONG_FAMILY = 0x0001
NORMAL_SHORT_FAMILY = 0x0011
ACTIVE_FAMILY = 0x001F
ACTIVE_PAYLOAD = bytes.fromhex("01 00 01 0F 01")
TRANSITION_PAYLOAD = bytes.fromhex("01 00 00 FF FF")

RAW_FIELDS = [
    "utc", "host_rel_ms", "adapter", "direction", "phase", "can_id_hex",
    "family_hex", "token_hex", "extended", "dlc", "data_hex", "status",
]
EVENT_FIELDS = ["utc", "host_rel_ms", "phase", "event", "details"]
SUMMARY_FIELDS = [
    "utc", "host_rel_ms", "test", "phase", "repeat", "metric", "value", "details"
]
OBS_FIELDS = [
    "utc", "host_rel_ms", "phase", "communication_icon", "unit_count",
    "error_message", "setpoint_bar", "display_pressure_bar", "status_bar_sp",
    "status_bar_rp", "pump_state", "mechanical_pressure_bar", "notes",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_numbers(text: str, cast=float) -> list:
    return [cast(x.strip()) for x in text.split(",") if x.strip()]


def data_hex(data: bytes) -> str:
    return data.hex(" ").upper()


def family_of(arbitration_id: int) -> int:
    return (arbitration_id >> 16) & 0x1FFF


def token_of(arbitration_id: int) -> int:
    return arbitration_id & 0xFFFF


def make_id(family: int, token: int) -> int:
    return ((family & 0x1FFF) << 16) | (token & 0xFFFF)


def make_long(address: int, token: int, marker: int = 0x03) -> can.Message:
    return can.Message(
        arbitration_id=make_id(address, token),
        is_extended_id=True,
        data=bytes([0x01, 0x00, 0x00, 0x0F, marker, token & 0xFF, token >> 8]),
    )


def make_short(address: int, token: int) -> can.Message:
    return can.Message(
        arbitration_id=make_id(0x0010 + address, token),
        is_extended_id=True,
        data=bytes([0x01, 0x00, 0x00, token & 0xFF, token >> 8]),
    )


class Sink:
    def __init__(self, path: Path, fields: list[str]):
        self.file = path.open("w", newline="", encoding="utf-8")
        self.writer = csv.DictWriter(self.file, fieldnames=fields, extrasaction="ignore")
        self.writer.writeheader()
        self.lock = threading.Lock()

    def write(self, row: dict) -> None:
        with self.lock:
            self.writer.writerow(row)
            self.file.flush()

    def close(self) -> None:
        with self.lock:
            self.file.flush()
            self.file.close()


@dataclass
class Config:
    test: str
    injector_channel: str
    observer_channel: Optional[str]
    bitrate: int
    output_dir: str
    repeats: int
    baseline_s: float
    activation_interval_ms: float
    activation_timeout_s: float
    active_hold_s: float
    observation_s: float
    keepalive_intervals_ms: list[float]
    family_interval_ms: float
    pair_gaps_ms: list[float]
    interruption_gaps_ms: list[float]
    addresses: list[int]
    allow_001f_injection: bool
    payload_rate_hz: float
    payload_duration_s: float


class Session:
    def __init__(self, cfg: Config, run_dir: Path):
        self.cfg = cfg
        self.test = cfg.test
        self.run_dir = run_dir
        self.start_ns = time.monotonic_ns()
        self.stop = threading.Event()
        self.phase_lock = threading.Lock()
        self.current_phase = "initializing"
        self.records_lock = threading.Lock()
        self.records = deque(maxlen=800_000)

        self.raw = Sink(run_dir / "raw.csv", RAW_FIELDS)
        self.events = Sink(run_dir / "events.csv", EVENT_FIELDS)
        self.summary_sink = Sink(run_dir / "summary.csv", SUMMARY_FIELDS)
        self.obs = Sink(run_dir / "display_observations.csv", OBS_FIELDS)

        self.injector = can.ThreadSafeBus(
            interface="pcan", channel=cfg.injector_channel, bitrate=cfg.bitrate,
            state=can.BusState.ACTIVE, receive_own_messages=False,
        )
        self.observer = None
        if cfg.observer_channel:
            self.observer = can.ThreadSafeBus(
                interface="pcan", channel=cfg.observer_channel, bitrate=cfg.bitrate,
                state=can.BusState.PASSIVE, receive_own_messages=False,
            )

        self.threads: list[threading.Thread] = []
        if self.observer is not None:
            self._start_reader(self.observer, "observer")
        else:
            self._start_reader(self.injector, "injector_rx")

        self.event(
            "session_started",
            f"injector={cfg.injector_channel}; observer={cfg.observer_channel}; bitrate={cfg.bitrate}",
        )

    def rel_ms(self, ns: Optional[int] = None) -> float:
        ns = time.monotonic_ns() if ns is None else ns
        return (ns - self.start_ns) / 1_000_000.0

    def phase(self) -> str:
        with self.phase_lock:
            return self.current_phase

    def set_phase(self, phase: str, details: str = "") -> int:
        with self.phase_lock:
            self.current_phase = phase
        start_ns = time.monotonic_ns()
        self.event("phase_started", details or phase)
        print(f"\n=== {phase} ===")
        return start_ns

    def event(self, name: str, details: str = "") -> None:
        self.events.write({
            "utc": utc_now(), "host_rel_ms": round(self.rel_ms(), 3),
            "phase": self.phase(), "event": name, "details": details,
        })

    def summary(self, repeat: int, metric: str, value, details: str = "") -> None:
        self.summary_sink.write({
            "utc": utc_now(), "host_rel_ms": round(self.rel_ms(), 3),
            "test": self.test, "phase": self.phase(), "repeat": repeat,
            "metric": metric, "value": value, "details": details,
        })

    def _start_reader(self, bus, adapter: str) -> None:
        thread = threading.Thread(target=self._reader, args=(bus, adapter), daemon=True)
        thread.start()
        self.threads.append(thread)

    def _reader(self, bus, adapter: str) -> None:
        while not self.stop.is_set():
            try:
                msg = bus.recv(timeout=0.1)
            except Exception as exc:
                self.event("rx_exception", f"{adapter}: {exc!r}")
                time.sleep(0.2)
                continue
            if msg is None:
                continue
            ns = time.monotonic_ns()
            record = {
                "mono_ns": ns,
                "host_rel_ms": self.rel_ms(ns),
                "adapter": adapter,
                "phase": self.phase(),
                "can_id": int(msg.arbitration_id),
                "family": family_of(int(msg.arbitration_id)),
                "token": token_of(int(msg.arbitration_id)),
                "dlc": int(msg.dlc),
                "data": bytes(msg.data),
            }
            with self.records_lock:
                self.records.append(record)
            self.raw.write({
                "utc": utc_now(), "host_rel_ms": round(record["host_rel_ms"], 3),
                "adapter": adapter, "direction": "RX", "phase": record["phase"],
                "can_id_hex": f"{record['can_id']:08X}",
                "family_hex": f"{record['family']:04X}",
                "token_hex": f"{record['token']:04X}", "extended": int(msg.is_extended_id),
                "dlc": record["dlc"], "data_hex": data_hex(record["data"]), "status": "OK",
            })

    def send(self, msg: can.Message, description: str) -> int:
        ns = time.monotonic_ns()
        status = "OK"
        try:
            self.injector.send(msg, timeout=0.5)
        except Exception as exc:
            status = repr(exc)
            self.event("tx_exception", status)
            raise
        self.raw.write({
            "utc": utc_now(), "host_rel_ms": round(self.rel_ms(ns), 3),
            "adapter": "injector", "direction": "TX", "phase": self.phase(),
            "can_id_hex": f"{msg.arbitration_id:08X}",
            "family_hex": f"{family_of(msg.arbitration_id):04X}",
            "token_hex": f"{token_of(msg.arbitration_id):04X}",
            "extended": int(msg.is_extended_id), "dlc": msg.dlc,
            "data_hex": data_hex(bytes(msg.data)), "status": status,
        })
        self.event("frame_sent", description)
        return ns

    def send_pair(self, address: int, token: Optional[int] = None, gap_ms: float = 0.2) -> tuple[int, int]:
        token = random.randrange(0x10000) if token is None else token
        long_ns = self.send(make_long(address, token), f"address={address}; long; token={token:04X}")
        target = time.perf_counter_ns() + int(gap_ms * 1_000_000)
        while time.perf_counter_ns() < target:
            if target - time.perf_counter_ns() > 1_000_000:
                time.sleep(0.0002)
        short_ns = self.send(make_short(address, token), f"address={address}; short; token={token:04X}")
        return long_ns, short_ns

    def send_short(self, address: int, token: Optional[int] = None) -> int:
        token = random.randrange(0x10000) if token is None else token
        return self.send(make_short(address, token), f"address={address}; short-only; token={token:04X}")

    def recent(self, since_ns: int, until_ns: Optional[int] = None) -> list[dict]:
        until_ns = time.monotonic_ns() if until_ns is None else until_ns
        with self.records_lock:
            return [r for r in self.records if since_ns <= r["mono_ns"] <= until_ns]

    def first_family_after(self, family: int, since_ns: int) -> Optional[dict]:
        with self.records_lock:
            for r in self.records:
                if r["mono_ns"] >= since_ns and r["family"] == family:
                    return dict(r)
        return None

    def wait_for_family(self, family: int, since_ns: int, timeout_s: float) -> Optional[dict]:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline and not self.stop.is_set():
            found = self.first_family_after(family, since_ns)
            if found:
                return found
            time.sleep(0.005)
        return None

    def wait(self, seconds: float, description: str) -> None:
        self.event("wait_started", f"{description}; {seconds:.3f}s")
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline and not self.stop.is_set():
            time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))
        self.event("wait_completed", description)

    def observe_display(self, prompt: str = "") -> None:
        if prompt:
            print(prompt)
        row = {
            "utc": utc_now(), "host_rel_ms": round(self.rel_ms(), 3), "phase": self.phase(),
            "communication_icon": input("Communicatie-icoon: ").strip(),
            "unit_count": input("Aantal units / N: ").strip(),
            "error_message": input("Foutmelding: ").strip(),
            "setpoint_bar": input("Setpoint [bar]: ").strip(),
            "display_pressure_bar": input("Displaydruk [bar]: ").strip(),
            "status_bar_sp": input("SP-statusbalk: ").strip(),
            "status_bar_rp": input("RP-statusbalk: ").strip(),
            "pump_state": input("Pompstatus: ").strip(),
            "mechanical_pressure_bar": input("Mechanische druk [bar]: ").strip(),
            "notes": input("Notities: ").strip(),
        }
        self.obs.write(row)
        self.event("display_observation", json.dumps(row, ensure_ascii=False))

    def family_counts(self, since_ns: int, until_ns: Optional[int] = None) -> Counter:
        return Counter(r["family"] for r in self.recent(since_ns, until_ns))

    def run_periodic_pairs(
        self, addresses: Iterable[int], duration_s: float, interval_ms: float,
        pair_gap_ms: float = 0.2, stop_on_001f: bool = False,
    ) -> tuple[int, Optional[dict]]:
        start_ns = time.monotonic_ns()
        deadline = time.monotonic() + duration_s
        next_send = time.perf_counter()
        first_001f = None
        while time.monotonic() < deadline and not self.stop.is_set():
            for address in addresses:
                self.send_pair(address, gap_ms=pair_gap_ms)
            if first_001f is None:
                first_001f = self.first_family_after(ACTIVE_FAMILY, start_ns)
                if first_001f and stop_on_001f:
                    break
            next_send += interval_ms / 1000.0
            delay = next_send - time.perf_counter()
            if delay > 0:
                time.sleep(delay)
            else:
                next_send = time.perf_counter()
        if first_001f is None:
            first_001f = self.first_family_after(ACTIVE_FAMILY, start_ns)
        return start_ns, first_001f

    def wait_for_normal(self, since_ns: int, timeout_s: float = 3.0) -> Optional[dict]:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            normal = self.first_family_after(NORMAL_LONG_FAMILY, since_ns)
            if normal:
                return normal
            time.sleep(0.005)
        return None

    def close(self, status: str) -> None:
        self.event("shutdown_started", status)
        self.stop.set()
        for thread in self.threads:
            thread.join(timeout=1.5)
        if self.observer is not None:
            self.observer.shutdown()
        self.injector.shutdown()
        self.raw.close()
        self.events.close()
        self.summary_sink.close()
        self.obs.close()


def activate(s: Session, cfg: Config, address: int = 3) -> tuple[bool, int, Optional[dict]]:
    start_ns, first = s.run_periodic_pairs(
        [address], cfg.activation_timeout_s, cfg.activation_interval_ms,
        stop_on_001f=True,
    )
    if first:
        s.summary(0, "activation_latency_ms", round((first["mono_ns"] - start_ns) / 1e6, 3), f"address={address}")
        return True, start_ns, first
    return False, start_ns, None


def ensure_recovered(s: Session, seconds: float = 2.0) -> None:
    start = time.monotonic_ns()
    normal = s.wait_for_normal(start, timeout_s=seconds)
    s.event("recovery_check", "normal traffic found" if normal else "normal traffic not found")


def test_suppression(s: Session, cfg: Config) -> None:
    if s.observer is None:
        raise RuntimeError("suppression vereist een tweede observer-adapter")
    s.set_phase("suppression_baseline", "independent listen-only baseline")
    baseline_ns = time.monotonic_ns()
    s.wait(cfg.baseline_s, "baseline")
    baseline_end = time.monotonic_ns()

    s.set_phase("suppression_address_3_active")
    active_ns = time.monotonic_ns()
    _, first = s.run_periodic_pairs([3], cfg.activation_timeout_s, cfg.activation_interval_ms)
    active_end = time.monotonic_ns()
    s.wait(cfg.active_hold_s, "active hold")

    s.set_phase("suppression_recovery")
    stop_ns = time.monotonic_ns()
    normal = s.wait_for_normal(stop_ns, 3.0)
    s.wait(cfg.observation_s, "recovery observation")
    recovery_end = time.monotonic_ns()

    for label, a, b in [
        ("baseline", baseline_ns, baseline_end),
        ("active", active_ns, active_end),
        ("recovery", stop_ns, recovery_end),
    ]:
        counts = s.family_counts(a, b)
        s.summary(1, f"{label}_family_counts", sum(counts.values()), json.dumps({f"{k:04X}": v for k, v in counts.items()}))
    s.summary(1, "001f_detected", int(first is not None))
    s.summary(1, "recovery_delay_ms", "" if normal is None else round((normal["mono_ns"] - stop_ns) / 1e6, 3))
    s.observe_display("Registreer de fysieke/displayreactie na de suppression-test.")


def test_single_pair_timeout(s: Session, cfg: Config) -> None:
    for n in range(1, cfg.repeats + 1):
        s.set_phase(f"single_pair_timeout_{n:02d}")
        ensure_recovered(s)
        start_ns = time.monotonic_ns()
        long_ns, short_ns = s.send_pair(2, gap_ms=0.2)
        first_001f = s.wait_for_family(ACTIVE_FAMILY, start_ns, cfg.observation_s)
        first_normal = s.first_family_after(NORMAL_LONG_FAMILY, short_ns)
        s.summary(n, "001f_after_single_pair", int(first_001f is not None))
        s.summary(n, "first_normal_after_pair_ms", "" if first_normal is None else round((first_normal["mono_ns"] - short_ns) / 1e6, 3))
        s.wait(1.2, "inter-repeat recovery")


def test_locked_timeout(s: Session, cfg: Config) -> None:
    for n in range(1, cfg.repeats + 1):
        s.set_phase(f"locked_timeout_{n:02d}")
        ensure_recovered(s)
        locked, _, _ = activate(s, cfg, address=2)
        s.summary(n, "lock_acquired", int(locked))
        if not locked:
            s.wait(2.0, "failed-lock recovery")
            continue
        s.run_periodic_pairs([2], cfg.active_hold_s, cfg.activation_interval_ms)
        stop_ns = time.monotonic_ns()
        normal = s.wait_for_normal(stop_ns, 3.0)
        timeout_ms = "" if normal is None else round((normal["mono_ns"] - stop_ns) / 1e6, 3)
        s.summary(n, "peer_timeout_ms", timeout_ms)
        s.wait(1.0, "inter-repeat recovery")


def test_keepalive(s: Session, cfg: Config) -> None:
    for n, interval_ms in enumerate(cfg.keepalive_intervals_ms, 1):
        s.set_phase(f"keepalive_{interval_ms:g}ms")
        ensure_recovered(s)
        start_ns, first = s.run_periodic_pairs([2], cfg.activation_timeout_s, interval_ms)
        s.summary(n, "interval_ms", interval_ms)
        s.summary(n, "001f_detected", int(first is not None))
        s.summary(n, "activation_latency_ms", "" if first is None else round((first["mono_ns"] - start_ns) / 1e6, 3))
        stop_ns = time.monotonic_ns()
        normal = s.wait_for_normal(stop_ns, 3.0)
        s.summary(n, "recovery_delay_ms", "" if normal is None else round((normal["mono_ns"] - stop_ns) / 1e6, 3))
        s.wait(1.0, "inter-interval recovery")


def test_short_families(s: Session, cfg: Config) -> None:
    for n, address in enumerate([2, 3, 4, 5], 1):
        s.set_phase(f"short_only_001{address}_500ms")
        ensure_recovered(s)
        start_ns = time.monotonic_ns()
        deadline = time.monotonic() + cfg.activation_timeout_s
        while time.monotonic() < deadline and not s.stop.is_set():
            s.send_short(address)
            time.sleep(cfg.family_interval_ms / 1000.0)
        first = s.first_family_after(ACTIVE_FAMILY, start_ns)
        s.summary(n, "family", f"001{address}")
        s.summary(n, "001f_detected", int(first is not None))
        s.summary(n, "activation_latency_ms", "" if first is None else round((first["mono_ns"] - start_ns) / 1e6, 3))
        s.wait(2.0, "recovery")


def test_pair_gap(s: Session, cfg: Config) -> None:
    for gap_index, gap_ms in enumerate(cfg.pair_gaps_ms, 1):
        s.set_phase(f"pair_gap_{gap_ms:g}ms")
        ensure_recovered(s)
        start_ns = time.monotonic_ns()
        actual_gaps = []
        deadline = time.monotonic() + cfg.activation_timeout_s
        while time.monotonic() < deadline and not s.stop.is_set():
            long_ns, short_ns = s.send_pair(2, gap_ms=gap_ms)
            actual_gaps.append((short_ns - long_ns) / 1e6)
            remaining_ms = max(0.0, cfg.family_interval_ms - gap_ms)
            time.sleep(remaining_ms / 1000.0)
        first = s.first_family_after(ACTIVE_FAMILY, start_ns)
        s.summary(gap_index, "requested_pair_gap_ms", gap_ms)
        s.summary(gap_index, "host_actual_gap_mean_ms", round(sum(actual_gaps) / len(actual_gaps), 3))
        s.summary(gap_index, "001f_detected", int(first is not None))
        s.summary(gap_index, "activation_latency_ms", "" if first is None else round((first["mono_ns"] - start_ns) / 1e6, 3))
        s.wait(2.0, "recovery")


def test_addresses(s: Session, cfg: Config) -> None:
    for n, address in enumerate(cfg.addresses, 1):
        s.set_phase(f"single_controller_address_{address}")
        ensure_recovered(s)
        start_ns, first = s.run_periodic_pairs([address], cfg.activation_timeout_s, cfg.activation_interval_ms)
        s.summary(n, "address", address)
        s.summary(n, "001f_detected", int(first is not None))
        s.summary(n, "activation_latency_ms", "" if first is None else round((first["mono_ns"] - start_ns) / 1e6, 3))
        s.observe_display(f"Registreer displayreactie met alleen adres {address} actief.")
        stop_ns = time.monotonic_ns()
        normal = s.wait_for_normal(stop_ns, 3.0)
        s.summary(n, "recovery_delay_ms", "" if normal is None else round((normal["mono_ns"] - stop_ns) / 1e6, 3))
        s.wait(1.0, "recovery")


def run_address_set(s: Session, addresses: list[int], duration_s: float, interval_ms: float) -> tuple[int, Optional[dict]]:
    return s.run_periodic_pairs(addresses, duration_s, interval_ms)


def test_reverse_order(s: Session, cfg: Config) -> None:
    sequences = [(2, 3), (3, 2), (2, 5), (5, 2)]
    for n, (first_address, second_address) in enumerate(sequences, 1):
        s.set_phase(f"reverse_{first_address}_then_{second_address}_first")
        ensure_recovered(s)
        first_start, first_001f = run_address_set(s, [first_address], cfg.activation_timeout_s, cfg.activation_interval_ms)
        s.summary(n, "first_address", first_address)
        s.summary(n, "first_lock", int(first_001f is not None))
        s.observe_display(f"Alleen adres {first_address} actief.")

        s.set_phase(f"reverse_{first_address}_then_{second_address}_both")
        both_start, both_001f = run_address_set(s, [first_address, second_address], cfg.active_hold_s, cfg.activation_interval_ms)
        s.summary(n, "second_address", second_address)
        s.summary(n, "001f_with_both", int(both_001f is not None))
        s.observe_display(f"Adres {first_address} en daarna {second_address} actief.")

        s.set_phase(f"reverse_{first_address}_then_{second_address}_first_only_again")
        run_address_set(s, [first_address], cfg.active_hold_s, cfg.activation_interval_ms)
        s.observe_display(f"Adres {second_address} gestopt; alleen {first_address} blijft actief.")
        stop_ns = time.monotonic_ns()
        normal = s.wait_for_normal(stop_ns, 3.0)
        s.summary(n, "final_recovery_ms", "" if normal is None else round((normal["mono_ns"] - stop_ns) / 1e6, 3))


def test_interruptions(s: Session, cfg: Config) -> None:
    for n, gap_ms in enumerate(cfg.interruption_gaps_ms, 1):
        s.set_phase(f"interruption_{gap_ms:g}ms_lock")
        ensure_recovered(s)
        locked, _, _ = activate(s, cfg, address=3)
        s.summary(n, "gap_ms", gap_ms)
        s.summary(n, "lock_acquired", int(locked))
        if not locked:
            continue
        s.run_periodic_pairs([3], cfg.active_hold_s, cfg.activation_interval_ms)

        s.set_phase(f"interruption_{gap_ms:g}ms_gap")
        gap_start = time.monotonic_ns()
        s.wait(gap_ms / 1000.0, "intentional peer interruption")
        gap_end = time.monotonic_ns()
        gap_records = s.recent(gap_start, gap_end)
        normal = next((r for r in gap_records if r["family"] == NORMAL_LONG_FAMILY), None)
        active = [r for r in gap_records if r["family"] == ACTIVE_FAMILY]
        s.summary(n, "normal_seen_during_gap", int(normal is not None))
        s.summary(n, "first_normal_delay_ms", "" if normal is None else round((normal["mono_ns"] - gap_start) / 1e6, 3))
        s.summary(n, "001f_frames_during_gap", len(active))

        s.set_phase(f"interruption_{gap_ms:g}ms_resume")
        resume_start, resumed = s.run_periodic_pairs([3], cfg.active_hold_s, cfg.activation_interval_ms)
        s.summary(n, "001f_after_resume", int(resumed is not None))
        stop_ns = time.monotonic_ns()
        s.wait_for_normal(stop_ns, 3.0)


def test_payload_001f(s: Session, cfg: Config) -> None:
    if not cfg.allow_001f_injection:
        raise RuntimeError("payload-001f vereist --allow-001f-injection")
    payloads = [
        ("exact_active", ACTIVE_PAYLOAD),
        ("exact_transition", TRANSITION_PAYLOAD),
        ("byte2_zero", bytes.fromhex("01 00 00 0F 01")),
        ("last_byte_zero", bytes.fromhex("01 00 01 0F 00")),
        ("command_zero", bytes.fromhex("01 00 01 00 01")),
    ]
    interval = 1.0 / cfg.payload_rate_hz
    for n, (label, payload) in enumerate(payloads, 1):
        s.set_phase(f"payload_001f_{label}", data_hex(payload))
        input("Bevestig hydraulisch veilige toestand; druk Enter om deze variant te testen: ")
        s.observe_display("Display vóór injectie.")
        start_ns = time.monotonic_ns()
        deadline = time.monotonic() + cfg.payload_duration_s
        while time.monotonic() < deadline and not s.stop.is_set():
            token = random.randrange(0x10000)
            msg = can.Message(
                arbitration_id=make_id(ACTIVE_FAMILY, token),
                is_extended_id=True, data=payload,
            )
            s.send(msg, f"001F payload variant={label}")
            time.sleep(interval)
        s.wait(cfg.observation_s, "post-payload observation")
        counts = s.family_counts(start_ns)
        s.summary(n, "payload", data_hex(payload), label)
        s.summary(n, "observed_family_counts", sum(counts.values()), json.dumps({f"{k:04X}": v for k, v in counts.items()}))
        s.observe_display("Display na injectie.")
        s.wait(2.0, "recovery")


TESTS = {
    "suppression": test_suppression,
    "single-pair-timeout": test_single_pair_timeout,
    "locked-timeout": test_locked_timeout,
    "keepalive": test_keepalive,
    "short-families": test_short_families,
    "pair-gap": test_pair_gap,
    "addresses": test_addresses,
    "reverse-order": test_reverse_order,
    "interruptions": test_interruptions,
    "payload-001f": test_payload_001f,
}


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="DAB peer-validatie")
    p.add_argument("test", choices=sorted(TESTS))
    p.add_argument("--injector-channel", default="PCAN_USBBUS1")
    p.add_argument("--observer-channel", default="PCAN_USBBUS2")
    p.add_argument("--no-observer", action="store_true")
    p.add_argument("--bitrate", type=int, default=1_000_000)
    p.add_argument("--output-dir", default="dab_peer_validation_results")
    p.add_argument("--repeats", type=int, default=20)
    p.add_argument("--baseline-s", type=float, default=10.0)
    p.add_argument("--activation-interval-ms", type=float, default=5.0)
    p.add_argument("--activation-timeout-s", type=float, default=10.0)
    p.add_argument("--active-hold-s", type=float, default=3.0)
    p.add_argument("--observation-s", type=float, default=3.0)
    p.add_argument("--keepalive-intervals-ms", default="50,100,200,500,1000,2000")
    p.add_argument("--family-interval-ms", type=float, default=500.0)
    p.add_argument("--pair-gaps-ms", default="0.2,0.5,1,2,5,10,20,50,100,200,500")
    p.add_argument("--interruption-gaps-ms", default="100,250,500,750,900,1000,1100,1250,1500,2000")
    p.add_argument("--addresses", default="2,3,5")
    p.add_argument("--allow-001f-injection", action="store_true")
    p.add_argument("--payload-rate-hz", type=float, default=2.0)
    p.add_argument("--payload-duration-s", type=float, default=3.0)
    return p


def config_from_args(a: argparse.Namespace) -> Config:
    return Config(
        test=a.test,
        injector_channel=a.injector_channel,
        observer_channel=None if a.no_observer else a.observer_channel,
        bitrate=a.bitrate,
        output_dir=a.output_dir,
        repeats=a.repeats,
        baseline_s=a.baseline_s,
        activation_interval_ms=a.activation_interval_ms,
        activation_timeout_s=a.activation_timeout_s,
        active_hold_s=a.active_hold_s,
        observation_s=a.observation_s,
        keepalive_intervals_ms=parse_numbers(a.keepalive_intervals_ms, float),
        family_interval_ms=a.family_interval_ms,
        pair_gaps_ms=parse_numbers(a.pair_gaps_ms, float),
        interruption_gaps_ms=parse_numbers(a.interruption_gaps_ms, float),
        addresses=parse_numbers(a.addresses, int),
        allow_001f_injection=a.allow_001f_injection,
        payload_rate_hz=a.payload_rate_hz,
        payload_duration_s=a.payload_duration_s,
    )


def confirm(cfg: Config) -> None:
    print("WAARSCHUWING: dit programma injecteert extended CAN-frames.")
    print("Zorg voor een hydraulisch veilige, bewaakte toestand.")
    phrase = input("Typ exact I_ACCEPT_DAB_CAN_INJECTION: ").strip()
    if phrase != "I_ACCEPT_DAB_CAN_INJECTION":
        raise SystemExit("Test geannuleerd")
    if cfg.test == "payload-001f":
        if not cfg.allow_001f_injection:
            raise SystemExit("Gebruik tevens --allow-001f-injection")
        phrase = input("Typ exact I_ACCEPT_001F_PAYLOAD_TEST: ").strip()
        if phrase != "I_ACCEPT_001F_PAYLOAD_TEST":
            raise SystemExit("001F-test geannuleerd")


def validate(cfg: Config) -> None:
    if cfg.repeats < 20 and cfg.test in {"single-pair-timeout", "locked-timeout"}:
        raise SystemExit("Timeouttests vereisen minimaal 20 herhalingen")
    if cfg.activation_interval_ms < 1.0:
        raise SystemExit("activation-interval-ms moet minimaal 1 ms zijn")
    if cfg.payload_rate_hz <= 0:
        raise SystemExit("payload-rate-hz moet positief zijn")
    if cfg.test == "suppression" and cfg.observer_channel is None:
        raise SystemExit("Suppression-bewijs vereist de tweede listen-only adapter")


def main() -> int:
    args = parser().parse_args()
    cfg = config_from_args(args)
    validate(cfg)
    confirm(cfg)

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = Path(cfg.output_dir) / f"{stamp}_{cfg.test}"
    run_dir.mkdir(parents=True, exist_ok=False)
    metadata_path = run_dir / "metadata.json"
    metadata_path.write_text(
        json.dumps({"started_utc": utc_now(), **asdict(cfg)}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    session: Optional[Session] = None
    status = "completed"

    def stop_handler(signum, _frame):
        nonlocal status
        status = f"aborted_by_signal_{signum}"
        if session:
            session.stop.set()

    signal.signal(signal.SIGINT, stop_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, stop_handler)

    try:
        session = Session(cfg, run_dir)
        TESTS[cfg.test](session, cfg)
        if session.stop.is_set():
            status = "aborted"
    except KeyboardInterrupt:
        status = "aborted_by_keyboard"
    except Exception as exc:
        status = f"failed: {exc!r}"
        if session:
            session.event("fatal_exception", repr(exc))
        raise
    finally:
        if session:
            session.close(status)
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata.update({"finished_utc": utc_now(), "status": status})
        metadata_path.write_text(json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Resultaten: {run_dir.resolve()}")
        print(f"Status: {status}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
