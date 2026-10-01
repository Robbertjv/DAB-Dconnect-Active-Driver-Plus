#!/usr/bin/env python3
"""
DAB Active Driver Plus — gerichte family-probes en optionele 13-bit brute-force scan.

Benodigd:
    pip install python-can

Aanbevolen hardware:
    PCAN_USBBUS1 = actieve injector/ACK-adapter
    PCAN_USBBUS2 = onafhankelijke listen-only observer

Voorbeelden:
    # Alleen passief naar alle families luisteren
    python dab_family_scanner.py passive --duration-s 300

    # Voorspelde AD-afhankelijke 103C-ID's voor AD 1 t/m 8 vastleggen
    python dab_family_scanner.py ad-map --enable-send

    # Alleen voor de hand liggende banken 0022-0028, 0032-0038 en 0042-0048
    python dab_family_scanner.py smart-banks --enable-send

    # Bekende lange families 0002-0008 met markers 00/03/04/05
    python dab_family_scanner.py marker-matrix --enable-send

    # Zelfgekozen bereik
    python dab_family_scanner.py scan --start-family 0x0020 --end-family 0x004F --enable-send

    # Alle 8192 mogelijke 13-bit families, met beschermde families overgeslagen
    python dab_family_scanner.py brute-force --enable-send --allow-bruteforce

    # Letterlijk alle 8192 families, inclusief bekende/protected families
    python dab_family_scanner.py brute-force --enable-send --allow-bruteforce \
        --include-protected

Brute-force is standaard begrensd, hervatbaar en interactief. Gebruik uitsluitend
in hydraulisch veilige toestand. Het programma kan fysieke pompbewegingen of
gevaarlijke hydraulische reacties niet automatisch herkennen.
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
from typing import Optional

import can


MAX_FAMILY = 0x1FFF
KNOWN_BACKGROUND = {0x0001, 0x0011}
PROTECTED_FAMILIES = {
    0x0000, 0x0001, 0x0011, 0x001F, 0x003C, 0x103C, 0x1FFF,
}
KNOWN_TRIGGER_ID = 0x0012C82D
KNOWN_TRIGGER_DATA = bytes.fromhex("01 00 00 2D C8")

RAW_FIELDS = [
    "utc", "host_rel_ms", "adapter", "direction", "phase", "probe_index",
    "probe_family_hex", "can_id_hex", "family_hex", "token_hex", "extended",
    "dlc", "data_hex", "status",
]
EVENT_FIELDS = ["utc", "host_rel_ms", "phase", "event", "details"]
RESULT_FIELDS = [
    "utc", "probe_index", "probe_family_hex", "grammar", "marker_hex",
    "tx_can_id_hex", "tx_data_hex", "tx_ok", "pre_window_frames",
    "post_window_frames", "candidate_frames", "candidate_families",
    "candidate_ids", "candidate_payloads", "first_candidate_latency_ms",
    "last_candidate_latency_ms", "active_001f_seen", "response_103c_seen",
    "operator_result", "notes",
]
AD_FIELDS = [
    "utc", "ad", "repeat", "predicted_status_id", "predicted_data_id",
    "observed_103c_ids", "observed_payloads", "prediction_matched",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_int(value: str) -> int:
    return int(value, 0)


def parse_family_list(text: str) -> set[int]:
    result = set()
    for part in text.split(","):
        part = part.strip()
        if part:
            value = int(part, 0)
            if not 0 <= value <= MAX_FAMILY:
                raise ValueError(f"family buiten 13-bit bereik: {part}")
            result.add(value)
    return result


def family_of(can_id: int) -> int:
    return (can_id >> 16) & MAX_FAMILY


def token_of(can_id: int) -> int:
    return can_id & 0xFFFF


def make_id(family: int, token: int) -> int:
    return ((family & MAX_FAMILY) << 16) | (token & 0xFFFF)


def hex_data(data: bytes) -> str:
    return data.hex(" ").upper()


def predicted_103c_ids(ad: int) -> tuple[int, int]:
    status_low16 = 0x0401 + ((ad - 1) * 0x10)
    return make_id(0x103C, status_low16), make_id(0x103C, status_low16 + 0x80)


class CsvSink:
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
    mode: str
    injector_channel: str
    observer_channel: Optional[str]
    bitrate: int
    output_dir: str
    enable_send: bool
    allow_bruteforce: bool
    include_protected: bool
    unattended: bool
    pause_on_response: bool
    start_family: int
    end_family: int
    grammar: str
    marker: int
    token: int
    randomize: bool
    repeats: int
    pre_window_s: float
    response_window_s: float
    inter_probe_s: float
    checkpoint_every: int
    duration_s: float
    exclude_families: set[int]
    resume_file: Optional[str]


class Scanner:
    def __init__(self, cfg: Config, run_dir: Path):
        self.cfg = cfg
        self.run_dir = run_dir
        self.start_ns = time.monotonic_ns()
        self.stop = threading.Event()
        self.emergency = threading.Event()
        self.phase_lock = threading.Lock()
        self.current_phase = "initializing"
        self.probe_lock = threading.Lock()
        self.probe_index = 0
        self.current_probe_family: Optional[int] = None
        self.records_lock = threading.Lock()
        self.records = deque(maxlen=1_000_000)

        self.raw = CsvSink(run_dir / "raw.csv", RAW_FIELDS)
        self.events = CsvSink(run_dir / "events.csv", EVENT_FIELDS)
        self.results = CsvSink(run_dir / "results.csv", RESULT_FIELDS)
        self.ad_results = CsvSink(run_dir / "ad_map.csv", AD_FIELDS)
        self.checkpoint_path = run_dir / "checkpoint.json"

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
        self.event("session_started", json.dumps(asdict(cfg), default=list))

    def rel_ms(self, ns: Optional[int] = None) -> float:
        ns = time.monotonic_ns() if ns is None else ns
        return (ns - self.start_ns) / 1_000_000.0

    def phase(self) -> str:
        with self.phase_lock:
            return self.current_phase

    def set_phase(self, phase: str, details: str = "") -> None:
        with self.phase_lock:
            self.current_phase = phase
        self.event("phase_started", details or phase)
        print(f"\n=== {phase} ===")

    def event(self, name: str, details: str = "") -> None:
        self.events.write({
            "utc": utc_now(), "host_rel_ms": round(self.rel_ms(), 3),
            "phase": self.phase(), "event": name, "details": details,
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
                self.emergency.set()
                continue
            if msg is None:
                continue
            ns = time.monotonic_ns()
            if msg.is_error_frame:
                self.event("can_error_frame", adapter)
                self.emergency.set()
            with self.probe_lock:
                probe_index = self.probe_index
                probe_family = self.current_probe_family
            record = {
                "mono_ns": ns,
                "adapter": adapter,
                "phase": self.phase(),
                "probe_index": probe_index,
                "probe_family": probe_family,
                "can_id": int(msg.arbitration_id),
                "family": family_of(int(msg.arbitration_id)),
                "token": token_of(int(msg.arbitration_id)),
                "dlc": int(msg.dlc),
                "data": bytes(msg.data),
            }
            with self.records_lock:
                self.records.append(record)
            self.raw.write({
                "utc": utc_now(), "host_rel_ms": round(self.rel_ms(ns), 3),
                "adapter": adapter, "direction": "RX", "phase": record["phase"],
                "probe_index": probe_index,
                "probe_family_hex": "" if probe_family is None else f"{probe_family:04X}",
                "can_id_hex": f"{record['can_id']:08X}",
                "family_hex": f"{record['family']:04X}",
                "token_hex": f"{record['token']:04X}", "extended": int(msg.is_extended_id),
                "dlc": record["dlc"], "data_hex": hex_data(record["data"]), "status": "OK",
            })

    def records_between(self, start_ns: int, end_ns: int) -> list[dict]:
        with self.records_lock:
            return [r for r in self.records if start_ns <= r["mono_ns"] <= end_ns]

    def wait(self, seconds: float) -> None:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline and not self.stop.is_set():
            if self.emergency.is_set():
                raise RuntimeError("CAN-fout of readerfout; scan gestopt")
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))

    def build_messages(self, family: int, grammar: str, marker: int, token: int) -> list[can.Message]:
        low = token & 0xFF
        high = (token >> 8) & 0xFF
        if grammar == "short":
            return [can.Message(
                arbitration_id=make_id(family, token), is_extended_id=True,
                data=bytes([0x01, 0x00, 0x00, low, high]),
            )]
        if grammar == "long":
            return [can.Message(
                arbitration_id=make_id(family, token), is_extended_id=True,
                data=bytes([0x01, 0x00, 0x00, 0x0F, marker, low, high]),
            )]
        if grammar == "pair":
            if family + 0x10 > MAX_FAMILY:
                raise ValueError("pair-family valt buiten 13-bit bereik")
            return [
                can.Message(
                    arbitration_id=make_id(family, token), is_extended_id=True,
                    data=bytes([0x01, 0x00, 0x00, 0x0F, marker, low, high]),
                ),
                can.Message(
                    arbitration_id=make_id(family + 0x10, token), is_extended_id=True,
                    data=bytes([0x01, 0x00, 0x00, low, high]),
                ),
            ]
        raise ValueError(grammar)

    def send(self, msg: can.Message, family: int) -> bool:
        status = "OK"
        ok = True
        ns = time.monotonic_ns()
        try:
            self.injector.send(msg, timeout=0.5)
        except Exception as exc:
            status = repr(exc)
            ok = False
            self.emergency.set()
        self.raw.write({
            "utc": utc_now(), "host_rel_ms": round(self.rel_ms(ns), 3),
            "adapter": "injector", "direction": "TX", "phase": self.phase(),
            "probe_index": self.probe_index, "probe_family_hex": f"{family:04X}",
            "can_id_hex": f"{msg.arbitration_id:08X}",
            "family_hex": f"{family_of(msg.arbitration_id):04X}",
            "token_hex": f"{token_of(msg.arbitration_id):04X}",
            "extended": 1, "dlc": msg.dlc, "data_hex": hex_data(bytes(msg.data)),
            "status": status,
        })
        return ok

    def probe_family(
        self, family: int, grammar: Optional[str] = None,
        marker: Optional[int] = None, token: Optional[int] = None,
        notes: str = "",
    ) -> dict:
        grammar = grammar or self.cfg.grammar
        marker = self.cfg.marker if marker is None else marker
        token = self.cfg.token if token is None else token
        with self.probe_lock:
            self.probe_index += 1
            self.current_probe_family = family
            probe_index = self.probe_index

        self.set_phase(f"probe_{probe_index:05d}_family_{family:04X}")
        pre_start = time.monotonic_ns()
        self.wait(self.cfg.pre_window_s)
        tx_start = time.monotonic_ns()
        messages = self.build_messages(family, grammar, marker, token)
        tx_ok = True
        tx_ids = set()
        for i, msg in enumerate(messages):
            tx_ids.add(msg.arbitration_id)
            tx_ok = self.send(msg, family) and tx_ok
            if i + 1 < len(messages):
                time.sleep(0.0002)
        tx_end = time.monotonic_ns()
        self.wait(self.cfg.response_window_s)
        post_end = time.monotonic_ns()

        pre = self.records_between(pre_start, tx_start)
        post = self.records_between(tx_end, post_end)
        candidates = []
        for r in post:
            is_echo = r["can_id"] in tx_ids
            is_background = r["family"] in KNOWN_BACKGROUND
            if not is_echo and not is_background:
                candidates.append(r)

        candidate_families = Counter(r["family"] for r in candidates)
        candidate_ids = Counter(r["can_id"] for r in candidates)
        payloads = sorted({hex_data(r["data"]) for r in candidates})
        latencies = [(r["mono_ns"] - tx_end) / 1e6 for r in candidates]
        result = {
            "utc": utc_now(), "probe_index": probe_index,
            "probe_family_hex": f"{family:04X}", "grammar": grammar,
            "marker_hex": f"{marker:02X}" if grammar in {"long", "pair"} else "",
            "tx_can_id_hex": " | ".join(f"{m.arbitration_id:08X}" for m in messages),
            "tx_data_hex": " || ".join(hex_data(bytes(m.data)) for m in messages),
            "tx_ok": int(tx_ok), "pre_window_frames": len(pre),
            "post_window_frames": len(post), "candidate_frames": len(candidates),
            "candidate_families": " | ".join(f"{k:04X}:{v}" for k, v in sorted(candidate_families.items())),
            "candidate_ids": " | ".join(f"{k:08X}:{v}" for k, v in sorted(candidate_ids.items())),
            "candidate_payloads": " || ".join(payloads),
            "first_candidate_latency_ms": round(min(latencies), 3) if latencies else "",
            "last_candidate_latency_ms": round(max(latencies), 3) if latencies else "",
            "active_001f_seen": int(0x001F in candidate_families),
            "response_103c_seen": int(0x103C in candidate_families),
            "operator_result": "", "notes": notes,
        }
        self.results.write(result)
        self.event("probe_completed", json.dumps(result, ensure_ascii=False))
        with self.probe_lock:
            self.current_probe_family = None

        if candidates:
            print(f"Kandidaatrespons na {family:04X}: {result['candidate_families']}")
            if self.cfg.pause_on_response and not self.cfg.unattended:
                answer = input("Fysieke reactie/fout? [Enter=geen, tekst=notitie, STOP=afbreken]: ").strip()
                result["operator_result"] = answer
                self.results.write({**result, "notes": "operator follow-up"})
                if answer.upper() == "STOP":
                    raise KeyboardInterrupt
        self.wait(self.cfg.inter_probe_s)
        return result

    def save_checkpoint(self, completed: list[int], remaining: list[int]) -> None:
        self.checkpoint_path.write_text(json.dumps({
            "updated_utc": utc_now(), "mode": self.cfg.mode,
            "completed_families": completed, "remaining_families": remaining,
            "next_probe_index": self.probe_index + 1,
        }, indent=2), encoding="utf-8")

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
        self.results.close()
        self.ad_results.close()


def mode_passive(s: Scanner, cfg: Config) -> None:
    s.set_phase("passive_family_discovery")
    print(f"Passief loggen gedurende {cfg.duration_s:.1f} s")
    start = time.monotonic_ns()
    s.wait(cfg.duration_s)
    counts = Counter(r["family"] for r in s.records_between(start, time.monotonic_ns()))
    s.event("passive_family_counts", json.dumps({f"{k:04X}": v for k, v in counts.items()}))
    print("Families:", {f"{k:04X}": v for k, v in counts.items()})


def mode_ad_map(s: Scanner, cfg: Config) -> None:
    for ad in range(1, 9):
        input(f"\nStel AD.6.5.7 veilig in op {ad}. Druk Enter wanneer stabiel: ")
        predicted_status, predicted_data = predicted_103c_ids(ad)
        for repeat in range(1, cfg.repeats + 1):
            s.set_phase(f"ad_{ad}_repeat_{repeat}")
            s.wait(cfg.pre_window_s)
            start = time.monotonic_ns()
            msg = can.Message(
                arbitration_id=KNOWN_TRIGGER_ID, is_extended_id=True,
                data=KNOWN_TRIGGER_DATA,
            )
            s.send(msg, family_of(KNOWN_TRIGGER_ID))
            s.wait(cfg.response_window_s)
            responses = [r for r in s.records_between(start, time.monotonic_ns()) if r["family"] == 0x103C]
            ids = sorted({r["can_id"] for r in responses})
            payloads = sorted({hex_data(r["data"]) for r in responses})
            matched = predicted_status in ids and predicted_data in ids
            s.ad_results.write({
                "utc": utc_now(), "ad": ad, "repeat": repeat,
                "predicted_status_id": f"{predicted_status:08X}",
                "predicted_data_id": f"{predicted_data:08X}",
                "observed_103c_ids": " | ".join(f"{x:08X}" for x in ids),
                "observed_payloads": " || ".join(payloads),
                "prediction_matched": int(matched),
            })
            print(f"AD={ad}, repeat={repeat}, IDs={[f'{x:08X}' for x in ids]}, match={matched}")
            s.wait(cfg.inter_probe_s)


def smart_families() -> list[int]:
    result = []
    for base in [0x0020, 0x0030, 0x0040]:
        result.extend(base + address for address in range(2, 9))
    result.append(0x003C)
    return result


def mode_marker_matrix(s: Scanner, cfg: Config) -> None:
    for family in range(0x0002, 0x0009):
        for marker in [0x00, 0x03, 0x04, 0x05]:
            for repeat in range(1, cfg.repeats + 1):
                s.probe_family(
                    family, grammar="long", marker=marker,
                    notes=f"marker matrix repeat={repeat}",
                )


def load_resume(path: str) -> list[int]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return [int(x) for x in data["remaining_families"]]


def scan_list(s: Scanner, cfg: Config, families: list[int]) -> None:
    excluded = set(cfg.exclude_families)
    if not cfg.include_protected:
        excluded |= PROTECTED_FAMILIES
    families = [f for f in families if f not in excluded]
    if cfg.randomize:
        random.shuffle(families)
    completed: list[int] = []
    total = len(families)
    print(f"Te testen families: {total}; geschatte minimale duur: "
          f"{total * (cfg.pre_window_s + cfg.response_window_s + cfg.inter_probe_s) / 60:.1f} min")

    for index, family in enumerate(list(families), 1):
        if s.stop.is_set():
            break
        print(f"[{index}/{total}] family 0x{family:04X}")
        s.probe_family(family)
        completed.append(family)
        remaining = families[index:]
        s.save_checkpoint(completed, remaining)
        if cfg.checkpoint_every and index % cfg.checkpoint_every == 0 and not cfg.unattended:
            answer = input(f"Checkpoint na {index} families. Enter=doorgaan, STOP=stoppen: ").strip()
            if answer.upper() == "STOP":
                break


def mode_scan(s: Scanner, cfg: Config) -> None:
    if cfg.resume_file:
        families = load_resume(cfg.resume_file)
    else:
        families = list(range(cfg.start_family, cfg.end_family + 1))
    scan_list(s, cfg, families)


def mode_smart_banks(s: Scanner, cfg: Config) -> None:
    scan_list(s, cfg, smart_families())


def mode_bruteforce(s: Scanner, cfg: Config) -> None:
    if cfg.resume_file:
        families = load_resume(cfg.resume_file)
    else:
        families = list(range(0x0000, 0x2000))
    scan_list(s, cfg, families)


MODES = {
    "passive": mode_passive,
    "ad-map": mode_ad_map,
    "smart-banks": mode_smart_banks,
    "marker-matrix": mode_marker_matrix,
    "scan": mode_scan,
    "brute-force": mode_bruteforce,
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="DAB family scanner")
    p.add_argument("mode", choices=sorted(MODES))
    p.add_argument("--injector-channel", default="PCAN_USBBUS1")
    p.add_argument("--observer-channel", default="PCAN_USBBUS2")
    p.add_argument("--no-observer", action="store_true")
    p.add_argument("--bitrate", type=int, default=1_000_000)
    p.add_argument("--output-dir", default="dab_family_scan_results")
    p.add_argument("--enable-send", action="store_true")
    p.add_argument("--allow-bruteforce", action="store_true")
    p.add_argument("--include-protected", action="store_true")
    p.add_argument("--unattended", action="store_true")
    p.add_argument("--no-pause-on-response", action="store_true")
    p.add_argument("--start-family", type=parse_int, default=0x0020)
    p.add_argument("--end-family", type=parse_int, default=0x004F)
    p.add_argument("--grammar", choices=["short", "long", "pair"], default="short")
    p.add_argument("--marker", type=parse_int, default=0x03)
    p.add_argument("--token", type=parse_int, default=0xC82D)
    p.add_argument("--randomize", action="store_true")
    p.add_argument("--repeats", type=int, default=3)
    p.add_argument("--pre-window-s", type=float, default=0.25)
    p.add_argument("--response-window-s", type=float, default=0.35)
    p.add_argument("--inter-probe-s", type=float, default=0.40)
    p.add_argument("--checkpoint-every", type=int, default=128)
    p.add_argument("--duration-s", type=float, default=300.0)
    p.add_argument("--exclude-families", default="")
    p.add_argument("--resume-file")
    return p


def make_config(a: argparse.Namespace) -> Config:
    return Config(
        mode=a.mode,
        injector_channel=a.injector_channel,
        observer_channel=None if a.no_observer else a.observer_channel,
        bitrate=a.bitrate,
        output_dir=a.output_dir,
        enable_send=a.enable_send,
        allow_bruteforce=a.allow_bruteforce,
        include_protected=a.include_protected,
        unattended=a.unattended,
        pause_on_response=not a.no_pause_on_response,
        start_family=a.start_family,
        end_family=a.end_family,
        grammar=a.grammar,
        marker=a.marker,
        token=a.token,
        randomize=a.randomize,
        repeats=a.repeats,
        pre_window_s=a.pre_window_s,
        response_window_s=a.response_window_s,
        inter_probe_s=a.inter_probe_s,
        checkpoint_every=a.checkpoint_every,
        duration_s=a.duration_s,
        exclude_families=parse_family_list(a.exclude_families),
        resume_file=a.resume_file,
    )


def validate(cfg: Config) -> None:
    if not 0 <= cfg.start_family <= cfg.end_family <= MAX_FAMILY:
        raise SystemExit("scanbereik moet binnen 0x0000-0x1FFF liggen")
    if not 0 <= cfg.marker <= 0xFF or not 0 <= cfg.token <= 0xFFFF:
        raise SystemExit("ongeldige marker of token")
    if cfg.repeats < 1:
        raise SystemExit("repeats moet minimaal 1 zijn")
    if cfg.mode != "passive" and not cfg.enable_send:
        raise SystemExit("Actieve modi vereisen --enable-send")
    if cfg.mode == "brute-force" and not cfg.allow_bruteforce:
        raise SystemExit("Brute-force vereist tevens --allow-bruteforce")
    if cfg.include_protected and cfg.mode != "brute-force":
        raise SystemExit("--include-protected is uitsluitend bedoeld voor brute-force")


def confirm(cfg: Config) -> None:
    if cfg.mode == "passive":
        return
    print("WAARSCHUWING: onbekende CAN-families kunnen commando's, resets of configuratie bevatten.")
    print("Het programma kan een fysieke of hydraulische reactie niet automatisch beoordelen.")
    phrase = input("Typ exact I_ACCEPT_UNKNOWN_DAB_FAMILY_PROBES: ").strip()
    if phrase != "I_ACCEPT_UNKNOWN_DAB_FAMILY_PROBES":
        raise SystemExit("Test geannuleerd")
    if cfg.mode == "brute-force":
        phrase = input("Typ exact I_ACCEPT_8192_FAMILY_SCAN: ").strip()
        if phrase != "I_ACCEPT_8192_FAMILY_SCAN":
            raise SystemExit("Brute-force geannuleerd")
    if cfg.include_protected:
        phrase = input("Typ exact I_ACCEPT_PROTECTED_FAMILIES: ").strip()
        if phrase != "I_ACCEPT_PROTECTED_FAMILIES":
            raise SystemExit("Protected-family scan geannuleerd")
    if cfg.unattended:
        phrase = input("Typ exact I_ACCEPT_UNATTENDED_OPERATION: ").strip()
        if phrase != "I_ACCEPT_UNATTENDED_OPERATION":
            raise SystemExit("Unattended scan geannuleerd")


def main() -> int:
    args = build_parser().parse_args()
    cfg = make_config(args)
    validate(cfg)
    confirm(cfg)

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = Path(cfg.output_dir) / f"{stamp}_{cfg.mode}"
    run_dir.mkdir(parents=True, exist_ok=False)
    metadata_path = run_dir / "metadata.json"
    metadata_path.write_text(
        json.dumps({"started_utc": utc_now(), **asdict(cfg)}, indent=2, ensure_ascii=False, default=list),
        encoding="utf-8",
    )

    scanner: Optional[Scanner] = None
    status = "completed"

    def signal_handler(signum, _frame):
        nonlocal status
        status = f"aborted_by_signal_{signum}"
        if scanner:
            scanner.stop.set()

    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, signal_handler)

    try:
        scanner = Scanner(cfg, run_dir)
        MODES[cfg.mode](scanner, cfg)
        if scanner.stop.is_set():
            status = "aborted"
    except KeyboardInterrupt:
        status = "aborted_by_operator"
    except Exception as exc:
        status = f"failed: {exc!r}"
        if scanner:
            scanner.event("fatal_exception", repr(exc))
        raise
    finally:
        if scanner:
            scanner.close(status)
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata.update({"finished_utc": utc_now(), "status": status})
        metadata_path.write_text(json.dumps(metadata, indent=2, ensure_ascii=False, default=list), encoding="utf-8")
        print(f"\nResultaten: {run_dir.resolve()}")
        print(f"Status: {status}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
