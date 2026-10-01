#!/usr/bin/env python3
"""
DAB Active Driver Plus — proceswaardetests P1 t/m P5.

Benodigd:
    pip install python-can

Voorbeelden:
    python dab_process_tests.py p1
    python dab_process_tests.py p2 --pressure-steps 1.5,1.8,2.0,2.2,2.5,2.0
    python dab_process_tests.py p3 --setpoint-steps 1.8,2.0,2.2,2.5,2.0
    python dab_process_tests.py p4 --enable-send
    python dab_process_tests.py p5 --enable-send --pressure-steps 1.5,1.8,2.0,2.2,2.5,2.2,2.0

P1-P3 zenden geen CAN-frames, maar staan standaard in ACTIVE mode zodat de
PCAN-adapter ACK kan geven. Gebruik --listen-only voor echte passieve mode.
P4-P5 vereisen --enable-send plus een expliciete bevestiging.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import signal
import sys
import threading
import time
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import can


PROBE_CAN_ID = 0x0012C82D
PROBE_DATA = bytes.fromhex("01 00 00 2D C8")
RESPONSE_FAMILY = 0x103C


RAW_FIELDS = [
    "utc", "host_rel_ms", "direction", "phase", "poll_id",
    "can_id_hex", "family_hex", "token_hex", "extended", "dlc",
    "data_hex", "status",
]

EVENT_FIELDS = ["utc", "host_rel_ms", "phase", "event", "details"]

OBS_FIELDS = [
    "utc", "host_rel_ms", "phase", "target_type", "target_value",
    "pump_command", "pump_state", "setpoint_bar", "display_pressure_bar",
    "mechanical_pressure_bar", "frequency_hz", "motor_current_a",
    "display_message", "notes",
]

POLL_FIELDS = [
    "utc", "host_rel_ms", "phase", "poll_id", "state_label",
    "target_pressure_bar", "tx_can_id_hex", "tx_data_hex", "tx_ok",
    "response_window_s", "response_frames", "response_ids",
    "distinct_response_payloads", "response_payloads",
    "first_response_latency_ms", "last_response_latency_ms",
]


@dataclass
class Config:
    test: str
    channel: str
    bitrate: int
    output_dir: str
    listen_only: bool
    enable_send: bool
    repeats: int
    baseline_s: float
    transition_s: float
    running_s: float
    post_s: float
    dwell_s: float
    pressure_steps: list[float]
    setpoint_steps: list[float]
    p4_states: list[str]
    polls_per_state: int
    poll_interval_s: float
    response_window_s: float


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_float_list(text: str) -> list[float]:
    return [float(x.strip()) for x in text.split(",") if x.strip()]


def safe_float(text: str) -> Optional[float]:
    text = text.strip().replace(",", ".")
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        return None


def slug(text: str) -> str:
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in text)


class CsvSink:
    def __init__(self, path: Path, fields: list[str]):
        self.path = path
        self.file = path.open("w", newline="", encoding="utf-8")
        self.writer = csv.DictWriter(self.file, fieldnames=fields, extrasaction="ignore")
        self.writer.writeheader()
        self.file.flush()
        self.lock = threading.Lock()

    def write(self, row: dict) -> None:
        with self.lock:
            self.writer.writerow(row)
            self.file.flush()

    def close(self) -> None:
        with self.lock:
            self.file.flush()
            self.file.close()


class DabTestSession:
    def __init__(self, cfg: Config, run_dir: Path):
        self.cfg = cfg
        self.run_dir = run_dir
        self.start_ns = time.monotonic_ns()
        self.stop_event = threading.Event()
        self.phase_lock = threading.Lock()
        self.current_phase = "initializing"
        self.poll_lock = threading.Lock()
        self.active_poll: Optional[dict] = None
        self.poll_counter = 0

        self.raw = CsvSink(run_dir / "raw.csv", RAW_FIELDS)
        self.events = CsvSink(run_dir / "events.csv", EVENT_FIELDS)
        self.observations = CsvSink(run_dir / "observations.csv", OBS_FIELDS)
        self.polls = CsvSink(run_dir / "polls.csv", POLL_FIELDS)

        state = can.BusState.PASSIVE if cfg.listen_only else can.BusState.ACTIVE
        self.bus = can.ThreadSafeBus(
            interface="pcan",
            channel=cfg.channel,
            bitrate=cfg.bitrate,
            state=state,
            receive_own_messages=False,
        )
        self.rx_thread = threading.Thread(target=self._rx_loop, name="dab-rx", daemon=True)
        self.rx_thread.start()
        self.event("session_started", f"{cfg.channel} at {cfg.bitrate} bit/s; state={state.name}")

    def rel_ms(self) -> float:
        return (time.monotonic_ns() - self.start_ns) / 1_000_000.0

    def phase(self) -> str:
        with self.phase_lock:
            return self.current_phase

    def set_phase(self, phase: str, details: str = "") -> None:
        with self.phase_lock:
            self.current_phase = phase
        self.event("phase_started", details or phase)
        print(f"\n=== {phase} ===")

    def event(self, event: str, details: str = "") -> None:
        self.events.write({
            "utc": utc_now(),
            "host_rel_ms": round(self.rel_ms(), 3),
            "phase": self.phase(),
            "event": event,
            "details": details,
        })

    def _frame_row(self, direction: str, msg: can.Message, status: str, poll_id: str = "") -> dict:
        arb = int(msg.arbitration_id)
        return {
            "utc": utc_now(),
            "host_rel_ms": round(self.rel_ms(), 3),
            "direction": direction,
            "phase": self.phase(),
            "poll_id": poll_id,
            "can_id_hex": f"{arb:08X}",
            "family_hex": f"{(arb >> 16) & 0x1FFF:04X}",
            "token_hex": f"{arb & 0xFFFF:04X}",
            "extended": int(bool(msg.is_extended_id)),
            "dlc": int(msg.dlc),
            "data_hex": bytes(msg.data).hex(" ").upper(),
            "status": status,
        }

    def _rx_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                msg = self.bus.recv(timeout=0.1)
            except Exception as exc:
                self.event("rx_exception", repr(exc))
                time.sleep(0.2)
                continue
            if msg is None:
                continue

            poll_id = ""
            family = (int(msg.arbitration_id) >> 16) & 0x1FFF
            now_ns = time.monotonic_ns()
            with self.poll_lock:
                poll = self.active_poll
                if poll is not None and now_ns <= poll["deadline_ns"]:
                    poll_id = poll["poll_id"]
                    if family == RESPONSE_FAMILY:
                        latency_ms = (now_ns - poll["sent_ns"]) / 1_000_000.0
                        poll["responses"].append({
                            "latency_ms": latency_ms,
                            "can_id_hex": f"{int(msg.arbitration_id):08X}",
                            "data_hex": bytes(msg.data).hex(" ").upper(),
                            "dlc": int(msg.dlc),
                        })
            self.raw.write(self._frame_row("RX", msg, "OK", poll_id))

    def wait(self, seconds: float, description: str) -> None:
        self.event("wait_started", f"{description}; {seconds:.3f} s")
        end = time.monotonic() + seconds
        last_print = -1
        while time.monotonic() < end and not self.stop_event.is_set():
            remaining = max(0, int(end - time.monotonic()))
            if remaining != last_print and (remaining % 10 == 0 or remaining < 5):
                print(f"  {description}: {remaining} s resterend")
                last_print = remaining
            time.sleep(min(0.2, max(0.0, end - time.monotonic())))
        self.event("wait_completed", description)

    def prompt(self, text: str, event_name: str = "operator_confirmed") -> str:
        answer = input(text).strip()
        self.event(event_name, answer)
        return answer

    def observation(self, target_type: str = "", target_value: str = "", quick: bool = False) -> None:
        print("Voer bekende waarden in. Leeg laten is toegestaan.")
        if quick:
            display_p = input("Displaydruk [bar]: ").strip()
            mechanical_p = input("Mechanische druk [bar]: ").strip()
            pump_state = input("Pompstatus: ").strip()
            notes = input("Notitie: ").strip()
            values = {
                "pump_command": "", "pump_state": pump_state, "setpoint_bar": "",
                "display_pressure_bar": safe_float(display_p),
                "mechanical_pressure_bar": safe_float(mechanical_p),
                "frequency_hz": "", "motor_current_a": "", "display_message": "",
                "notes": notes,
            }
        else:
            values = {
                "pump_command": input("Pompcommando: ").strip(),
                "pump_state": input("Werkelijke pompstatus: ").strip(),
                "setpoint_bar": safe_float(input("Setpoint [bar]: ")),
                "display_pressure_bar": safe_float(input("Displaydruk [bar]: ")),
                "mechanical_pressure_bar": safe_float(input("Mechanische druk [bar]: ")),
                "frequency_hz": safe_float(input("Frequentie [Hz]: ")),
                "motor_current_a": safe_float(input("Motorstroom [A]: ")),
                "display_message": input("Displaymelding: ").strip(),
                "notes": input("Notitie: ").strip(),
            }
        row = {
            "utc": utc_now(), "host_rel_ms": round(self.rel_ms(), 3),
            "phase": self.phase(), "target_type": target_type,
            "target_value": target_value, **values,
        }
        self.observations.write(row)
        self.event("operator_observation_recorded", json.dumps(row, ensure_ascii=False))

    def send_probe(self, state_label: str, target_pressure: Optional[float]) -> dict:
        if not self.cfg.enable_send:
            raise RuntimeError("CAN-transmissie is niet ingeschakeld")
        self.poll_counter += 1
        poll_id = f"poll_{self.poll_counter:05d}"
        msg = can.Message(
            arbitration_id=PROBE_CAN_ID,
            is_extended_id=True,
            data=PROBE_DATA,
        )
        sent_ns = time.monotonic_ns()
        poll = {
            "poll_id": poll_id,
            "sent_ns": sent_ns,
            "deadline_ns": sent_ns + int(self.cfg.response_window_s * 1_000_000_000),
            "responses": [],
        }
        with self.poll_lock:
            self.active_poll = poll

        tx_ok = True
        status = "OK"
        try:
            self.bus.send(msg, timeout=0.5)
        except Exception as exc:
            tx_ok = False
            status = repr(exc)
            self.event("tx_exception", status)
        self.raw.write(self._frame_row("TX", msg, status, poll_id))
        self.event("probe_sent", f"{poll_id}; state={state_label}; tx_ok={tx_ok}")

        self.wait(self.cfg.response_window_s, f"response window {poll_id}")
        with self.poll_lock:
            responses = list(poll["responses"])
            if self.active_poll is poll:
                self.active_poll = None

        ids = Counter(r["can_id_hex"] for r in responses)
        payloads = sorted(set(r["data_hex"] for r in responses))
        latencies = [r["latency_ms"] for r in responses]
        summary = {
            "utc": utc_now(),
            "host_rel_ms": round(self.rel_ms(), 3),
            "phase": self.phase(),
            "poll_id": poll_id,
            "state_label": state_label,
            "target_pressure_bar": "" if target_pressure is None else target_pressure,
            "tx_can_id_hex": f"{PROBE_CAN_ID:08X}",
            "tx_data_hex": PROBE_DATA.hex(" ").upper(),
            "tx_ok": int(tx_ok),
            "response_window_s": self.cfg.response_window_s,
            "response_frames": len(responses),
            "response_ids": " | ".join(f"{k}:{v}" for k, v in sorted(ids.items())),
            "distinct_response_payloads": len(payloads),
            "response_payloads": " || ".join(payloads),
            "first_response_latency_ms": round(min(latencies), 3) if latencies else "",
            "last_response_latency_ms": round(max(latencies), 3) if latencies else "",
        }
        self.polls.write(summary)
        self.event("probe_completed", json.dumps(summary, ensure_ascii=False))
        return summary

    def close(self, status: str = "completed") -> None:
        self.event("shutdown_started", status)
        self.stop_event.set()
        self.rx_thread.join(timeout=2.0)
        try:
            self.bus.shutdown()
        finally:
            self.raw.close()
            self.events.close()
            self.observations.close()
            self.polls.close()


def run_p1(s: DabTestSession, cfg: Config) -> None:
    """Passieve start/stopmeting. Dit is vooral een reproduceerbare referentietest."""
    for cycle in range(1, cfg.repeats + 1):
        s.set_phase(f"P1_cycle_{cycle:02d}_baseline_stopped")
        s.prompt("Zet de pomp veilig in stilstand. Druk Enter wanneer stabiel: ")
        s.wait(cfg.baseline_s, "stopped baseline")
        s.observation("cycle", str(cycle), quick=True)

        s.set_phase(f"P1_cycle_{cycle:02d}_start_transition")
        s.prompt("Geef NU het normale startcommando en druk direct Enter: ", "pump_start_marked")
        s.wait(cfg.transition_s, "start transition")

        s.set_phase(f"P1_cycle_{cycle:02d}_running_stable")
        s.wait(cfg.running_s, "stable running")
        s.observation("cycle", str(cycle))

        s.set_phase(f"P1_cycle_{cycle:02d}_stop_transition")
        s.prompt("Geef NU het normale stopcommando en druk direct Enter: ", "pump_stop_marked")
        s.wait(cfg.transition_s, "stop transition")

        s.set_phase(f"P1_cycle_{cycle:02d}_post_stop")
        s.wait(cfg.post_s, "post-stop observation")
        s.observation("cycle", str(cycle), quick=True)


def run_p2(s: DabTestSession, cfg: Config) -> None:
    """Passieve drukstappen met constant setpoint en zonder CAN-injectie."""
    s.prompt("Bevestig dat setpoint en overige instellingen constant blijven. Enter: ")
    for index, pressure in enumerate(cfg.pressure_steps, 1):
        phase = f"P2_step_{index:02d}_pressure_{slug(str(pressure))}_bar"
        s.set_phase(phase, f"target mechanical pressure={pressure} bar")
        s.prompt(f"Breng de installatie veilig naar {pressure:.3f} bar. Enter wanneer stabiel: ")
        s.event("target_reached", f"pressure={pressure}")
        s.observation("mechanical_pressure_target_bar", str(pressure))
        s.wait(cfg.dwell_s, f"pressure dwell {pressure} bar")
        s.observation("mechanical_pressure_target_bar", str(pressure), quick=True)


def run_p3(s: DabTestSession, cfg: Config) -> None:
    """Setpointsweep; liefst met stilstaande pomp of constant hydraulisch proces."""
    for index, setpoint in enumerate(cfg.setpoint_steps, 1):
        phase = f"P3_step_{index:02d}_setpoint_{slug(str(setpoint))}_bar"
        s.set_phase(phase, f"target setpoint={setpoint} bar")
        s.prompt(f"Stel SP veilig in op {setpoint:.3f} bar. Enter na bevestiging op display: ")
        s.event("setpoint_changed", f"setpoint={setpoint}")
        s.observation("setpoint_target_bar", str(setpoint))
        s.wait(cfg.dwell_s, f"setpoint dwell {setpoint} bar")
        s.observation("setpoint_target_bar", str(setpoint), quick=True)


def run_p4(s: DabTestSession, cfg: Config) -> None:
    """Losse 0012-polls bij stabiele, door de operator ingestelde toestanden."""
    for state_index, state_label in enumerate(cfg.p4_states, 1):
        s.set_phase(f"P4_state_{state_index:02d}_{slug(state_label)}", state_label)
        s.prompt(f"Maak toestand '{state_label}' veilig en stabiel. Druk Enter: ")
        s.observation("state_label", state_label)
        target = safe_float(state_label.split("bar")[0].split("_")[-1]) if "bar" in state_label else None
        for n in range(1, cfg.polls_per_state + 1):
            print(f"Poll {n}/{cfg.polls_per_state} in toestand {state_label}")
            summary = s.send_probe(state_label, target)
            print(f"  103C responses: {summary['response_frames']}")
            if n != cfg.polls_per_state:
                gap = max(0.0, cfg.poll_interval_s - cfg.response_window_s)
                s.wait(gap, "inter-poll gap")
        s.observation("state_label", state_label, quick=True)


def run_p5(s: DabTestSession, cfg: Config) -> None:
    """Periodieke 0012-polls tijdens gecontroleerde drukstappen/ramp."""
    for index, pressure in enumerate(cfg.pressure_steps, 1):
        state_label = f"pressure_{pressure:.3f}_bar"
        s.set_phase(f"P5_step_{index:02d}_{slug(state_label)}", state_label)
        s.prompt(f"Breng de installatie veilig naar {pressure:.3f} bar. Enter wanneer stabiel: ")
        s.observation("mechanical_pressure_target_bar", str(pressure))

        phase_end = time.monotonic() + cfg.dwell_s
        poll_number = 0
        while time.monotonic() < phase_end and not s.stop_event.is_set():
            poll_number += 1
            summary = s.send_probe(state_label, pressure)
            print(f"  P5 poll {poll_number}: {summary['response_frames']} 103C frames")
            remaining = phase_end - time.monotonic()
            gap = min(max(0.0, cfg.poll_interval_s - cfg.response_window_s), max(0.0, remaining))
            if gap > 0:
                s.wait(gap, "inter-poll gap")
        s.observation("mechanical_pressure_target_bar", str(pressure), quick=True)


def require_send_confirmation(cfg: Config) -> None:
    if cfg.test not in {"p4", "p5"}:
        return
    if not cfg.enable_send:
        raise SystemExit("P4/P5 vereist --enable-send")
    if cfg.listen_only:
        raise SystemExit("P4/P5 kan niet samen met --listen-only")
    print("\nWAARSCHUWING: deze test injecteert extended CAN-frames op de DAB-bus.")
    print(f"ID={PROBE_CAN_ID:08X}, DATA={PROBE_DATA.hex(' ').upper()}")
    confirmation = input("Typ exact I_UNDERSTAND_CAN_INJECTION om door te gaan: ").strip()
    if confirmation != "I_UNDERSTAND_CAN_INJECTION":
        raise SystemExit("Injectietest geannuleerd")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="DAB proceswaardetests P1-P5")
    p.add_argument("test", choices=["p1", "p2", "p3", "p4", "p5"])
    p.add_argument("--channel", default="PCAN_USBBUS1")
    p.add_argument("--bitrate", type=int, default=1_000_000)
    p.add_argument("--output-dir", default="dab_process_results")
    p.add_argument("--listen-only", action="store_true")
    p.add_argument("--enable-send", action="store_true")
    p.add_argument("--repeats", type=int, default=3)
    p.add_argument("--baseline-s", type=float, default=30.0)
    p.add_argument("--transition-s", type=float, default=15.0)
    p.add_argument("--running-s", type=float, default=60.0)
    p.add_argument("--post-s", type=float, default=30.0)
    p.add_argument("--dwell-s", type=float, default=30.0)
    p.add_argument("--pressure-steps", default="1.5,1.8,2.0,2.2,2.5,2.2,2.0")
    p.add_argument("--setpoint-steps", default="1.8,2.0,2.2,2.5,2.0")
    p.add_argument(
        "--p4-states",
        default="pump_off_0.0bar,pump_on_2.0bar,pump_on_2.2bar,pump_on_2.5bar,pump_off_final",
    )
    p.add_argument("--polls-per-state", type=int, default=5)
    p.add_argument("--poll-interval-s", type=float, default=5.0)
    p.add_argument("--response-window-s", type=float, default=1.0)
    return p


def make_config(args: argparse.Namespace) -> Config:
    return Config(
        test=args.test,
        channel=args.channel,
        bitrate=args.bitrate,
        output_dir=args.output_dir,
        listen_only=args.listen_only,
        enable_send=args.enable_send,
        repeats=args.repeats,
        baseline_s=args.baseline_s,
        transition_s=args.transition_s,
        running_s=args.running_s,
        post_s=args.post_s,
        dwell_s=args.dwell_s,
        pressure_steps=parse_float_list(args.pressure_steps),
        setpoint_steps=parse_float_list(args.setpoint_steps),
        p4_states=[x.strip() for x in args.p4_states.split(",") if x.strip()],
        polls_per_state=args.polls_per_state,
        poll_interval_s=args.poll_interval_s,
        response_window_s=args.response_window_s,
    )


def validate(cfg: Config) -> None:
    if cfg.bitrate <= 0:
        raise SystemExit("bitrate moet positief zijn")
    if cfg.repeats < 1 or cfg.polls_per_state < 1:
        raise SystemExit("repeats en polls-per-state moeten minimaal 1 zijn")
    if cfg.poll_interval_s < cfg.response_window_s:
        raise SystemExit("poll-interval-s moet minimaal response-window-s zijn")
    for value in [cfg.baseline_s, cfg.transition_s, cfg.running_s, cfg.post_s,
                  cfg.dwell_s, cfg.poll_interval_s, cfg.response_window_s]:
        if value < 0:
            raise SystemExit("tijdswaarden mogen niet negatief zijn")


def main() -> int:
    args = build_parser().parse_args()
    cfg = make_config(args)
    validate(cfg)
    require_send_confirmation(cfg)

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = Path(cfg.output_dir) / f"{stamp}_{cfg.test}"
    run_dir.mkdir(parents=True, exist_ok=False)
    (run_dir / "metadata.json").write_text(
        json.dumps({"started_utc": utc_now(), **asdict(cfg)}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    session: Optional[DabTestSession] = None
    final_status = "completed"

    def handle_signal(signum, _frame):
        nonlocal final_status
        final_status = f"aborted_by_signal_{signum}"
        if session is not None:
            session.stop_event.set()

    signal.signal(signal.SIGINT, handle_signal)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, handle_signal)

    try:
        session = DabTestSession(cfg, run_dir)
        runners = {"p1": run_p1, "p2": run_p2, "p3": run_p3, "p4": run_p4, "p5": run_p5}
        runners[cfg.test](session, cfg)
        if session.stop_event.is_set():
            final_status = "aborted"
    except KeyboardInterrupt:
        final_status = "aborted_by_keyboard"
    except Exception as exc:
        final_status = f"failed: {exc!r}"
        if session is not None:
            session.event("fatal_exception", repr(exc))
        raise
    finally:
        if session is not None:
            session.close(final_status)
        metadata_path = run_dir / "metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata.update({"finished_utc": utc_now(), "status": final_status})
        metadata_path.write_text(json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\nResultaten: {run_dir.resolve()}")
        print(f"Status: {final_status}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
