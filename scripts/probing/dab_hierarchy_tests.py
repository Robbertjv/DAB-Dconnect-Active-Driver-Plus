#!/usr/bin/env python3
"""
DAB Active Driver Plus hierarchy and long-duration simulation tests.

Planned tests
-------------
T14: one simulated controller at logical address 3
T15: simulated controllers at logical addresses 3 and 5, added sequentially
T16: simulated controllers directly after the real controller: addresses 2 and 3
T17: one simulated controller at address 3 for at least five minutes

Standard operator feedback is limited to N and VP. At every feedback prompt:
- Enter: leave that value unknown
- S: skip all operator feedback for the phase
- D: open optional detailed observations
- X: stop all simulation safely and abort the session

CAN simulation and logging continue while the program waits for operator input.
"""

from __future__ import annotations

import csv
import json
import queue
import random
import signal
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

import can


# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

CAN_INTERFACE = "pcan"
CAN_CHANNEL = "PCAN_USBBUS1"
CAN_BITRATE = 1_000_000

CYCLE_PERIOD_S = 0.005       # 200 Hz per simulated controller
PAIR_GAP_S = 0.00010         # target delay between long and short frames
LONG_MARKER = 0x03

BASELINE_S = 15
STABILIZE_S = 10
RECOVERY_S = 10
PROCESS_DURATION_S = 5 * 60
PROCESS_CHECKPOINT_S = 60

OUTPUT_DIRECTORY = Path("dab_hierarchy_results")

T14_ADDRESS = 3
T15_ADDRESSES = (3, 5)
T16_ADDRESSES = (2, 3)
T17_ADDRESS = 3

RAW_FIELDS = [
    "utc",
    "host_rel_ms",
    "direction",
    "phase",
    "controller_index",
    "can_id_hex",
    "extended",
    "dlc",
    "data_hex",
    "status",
]

EVENT_FIELDS = [
    "utc",
    "host_rel_ms",
    "phase",
    "event",
    "details",
]

OBSERVATION_FIELDS = [
    "utc",
    "host_rel_ms",
    "phase",
    "operator_N",
    "operator_VP_bar",
    "operator_feedback",
    "mechanical_pressure_bar",
    "communication_icon",
    "pump_state",
    "display_message",
    "notes",
]


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def bytes_to_hex(data: bytes) -> str:
    return " ".join(f"{value:02X}" for value in data)


def safe_text(value: object) -> str:
    return "" if value is None else str(value)


class AbortRequested(RuntimeError):
    pass


@dataclass
class RuntimeState:
    start_ns: int
    stop_event: threading.Event
    phase_lock: threading.Lock
    active_lock: threading.Lock
    phase: str = "initializing"

    def elapsed_ms(self) -> float:
        return (time.perf_counter_ns() - self.start_ns) / 1_000_000.0

    def set_phase(self, value: str) -> None:
        with self.phase_lock:
            self.phase = value

    def get_phase(self) -> str:
        with self.phase_lock:
            return self.phase


class CsvWriterThread(threading.Thread):
    def __init__(self, path: Path, fields: list[str], name: str):
        super().__init__(name=name, daemon=True)
        self.path = path
        self.fields = fields
        self.items: queue.Queue[Optional[dict]] = queue.Queue()
        self.ready = threading.Event()

    def put(self, row: dict) -> None:
        self.items.put(row)

    def close(self) -> None:
        self.items.put(None)

    def run(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=self.fields)
            writer.writeheader()
            handle.flush()
            self.ready.set()

            pending = 0
            while True:
                item = self.items.get()
                if item is None:
                    break
                writer.writerow({field: item.get(field, "") for field in self.fields})
                pending += 1
                if pending >= 100:
                    handle.flush()
                    pending = 0
            handle.flush()


class DabTestSession:
    def __init__(self):
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        OUTPUT_DIRECTORY.mkdir(parents=True, exist_ok=True)

        self.raw_path = OUTPUT_DIRECTORY / f"dab_hierarchy_raw_{timestamp}.csv"
        self.events_path = OUTPUT_DIRECTORY / f"dab_hierarchy_events_{timestamp}.csv"
        self.observations_path = OUTPUT_DIRECTORY / f"dab_hierarchy_observations_{timestamp}.csv"
        self.metadata_path = OUTPUT_DIRECTORY / f"dab_hierarchy_metadata_{timestamp}.json"

        self.state = RuntimeState(
            start_ns=time.perf_counter_ns(),
            stop_event=threading.Event(),
            phase_lock=threading.Lock(),
            active_lock=threading.Lock(),
        )

        self.raw_writer = CsvWriterThread(self.raw_path, RAW_FIELDS, "raw-csv-writer")
        self.event_writer = CsvWriterThread(self.events_path, EVENT_FIELDS, "event-csv-writer")
        self.observation_writer = CsvWriterThread(
            self.observations_path, OBSERVATION_FIELDS, "observation-csv-writer"
        )

        self.bus: Optional[can.BusABC] = None
        self.receiver_thread: Optional[threading.Thread] = None
        self.simulator_thread: Optional[threading.Thread] = None

        self.active_addresses: set[int] = set()
        self.random_generators = {
            address: random.Random((time.time_ns() ^ (address << 20)) & 0xFFFFFFFFFFFFFFFF)
            for address in range(1, 9)
        }

        # Sliding timestamps for a live indication of real-controller 0001/0011 traffic.
        self.real_rx_times: deque[float] = deque()
        self.rate_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    def log_raw(
        self,
        *,
        direction: str,
        can_id: int,
        data: bytes,
        status: str,
        controller_index: object = "",
        phase: Optional[str] = None,
    ) -> None:
        self.raw_writer.put(
            {
                "utc": utc_now(),
                "host_rel_ms": f"{self.state.elapsed_ms():.3f}",
                "direction": direction,
                "phase": phase or self.state.get_phase(),
                "controller_index": controller_index,
                "can_id_hex": f"{can_id:08X}",
                "extended": 1,
                "dlc": len(data),
                "data_hex": bytes_to_hex(data),
                "status": status,
            }
        )

    def log_event(self, event: str, details: object = "") -> None:
        row = {
            "utc": utc_now(),
            "host_rel_ms": f"{self.state.elapsed_ms():.3f}",
            "phase": self.state.get_phase(),
            "event": event,
            "details": safe_text(details),
        }
        self.event_writer.put(row)
        print(f"[{row['host_rel_ms']} ms] {event}: {details}")

    def log_observation(
        self,
        *,
        n: str = "",
        vp: str = "",
        feedback: str = "recorded",
        details: Optional[dict[str, str]] = None,
    ) -> None:
        details = details or {}
        self.observation_writer.put(
            {
                "utc": utc_now(),
                "host_rel_ms": f"{self.state.elapsed_ms():.3f}",
                "phase": self.state.get_phase(),
                "operator_N": n,
                "operator_VP_bar": vp,
                "operator_feedback": feedback,
                "mechanical_pressure_bar": details.get("mechanical_pressure_bar", ""),
                "communication_icon": details.get("communication_icon", ""),
                "pump_state": details.get("pump_state", ""),
                "display_message": details.get("display_message", ""),
                "notes": details.get("notes", ""),
            }
        )

    # ------------------------------------------------------------------
    # CAN threads
    # ------------------------------------------------------------------

    def open(self) -> None:
        self.raw_writer.start()
        self.event_writer.start()
        self.observation_writer.start()
        self.raw_writer.ready.wait()
        self.event_writer.ready.wait()
        self.observation_writer.ready.wait()

        self.bus = can.Bus(
            interface=CAN_INTERFACE,
            channel=CAN_CHANNEL,
            bitrate=CAN_BITRATE,
            receive_own_messages=False,
        )

        self.receiver_thread = threading.Thread(
            target=self._receiver_loop, name="can-receiver", daemon=True
        )
        self.simulator_thread = threading.Thread(
            target=self._simulator_loop, name="can-simulator", daemon=True
        )
        self.receiver_thread.start()
        self.simulator_thread.start()

        self._write_metadata(started=True)
        self.log_event("session_started", f"{CAN_CHANNEL} at {CAN_BITRATE} bit/s")

    def _receiver_loop(self) -> None:
        assert self.bus is not None
        while not self.state.stop_event.is_set():
            try:
                message = self.bus.recv(timeout=0.050)
            except Exception as exc:
                self.log_event("receive_error", repr(exc))
                time.sleep(0.050)
                continue

            if message is None:
                continue

            direction = "RX" if getattr(message, "is_rx", True) else "TX_ECHO"
            data = bytes(message.data)
            status = "ERROR_FRAME" if message.is_error_frame else "OK"
            self.log_raw(
                direction=direction,
                can_id=message.arbitration_id,
                data=data,
                status=status,
            )

            if direction == "RX":
                family = (message.arbitration_id >> 16) & 0x1FFF
                if family in (0x0001, 0x0011):
                    now = time.monotonic()
                    with self.rate_lock:
                        self.real_rx_times.append(now)
                        cutoff = now - 2.0
                        while self.real_rx_times and self.real_rx_times[0] < cutoff:
                            self.real_rx_times.popleft()

    def _send_frame(self, address: int, family: int, token: int, data: bytes) -> None:
        assert self.bus is not None
        can_id = (family << 16) | token
        message = can.Message(
            arbitration_id=can_id,
            is_extended_id=True,
            data=data,
        )
        try:
            self.bus.send(message, timeout=0.020)
            status = "OK"
        except Exception as exc:
            status = f"TX_ERROR:{exc!r}"
            self.log_event("transmit_error", f"address={address}, id={can_id:08X}, {exc!r}")

        self.log_raw(
            direction="TX",
            can_id=can_id,
            data=data,
            status=status,
            controller_index=address,
        )

    def _simulator_loop(self) -> None:
        next_cycle = time.perf_counter()

        while not self.state.stop_event.is_set():
            with self.state.active_lock:
                addresses = sorted(self.active_addresses)

            if not addresses:
                next_cycle = time.perf_counter() + CYCLE_PERIOD_S
                time.sleep(0.010)
                continue

            next_cycle += CYCLE_PERIOD_S

            for address in addresses:
                token = self.random_generators[address].randrange(0x0000, 0x10000)
                low = token & 0xFF
                high = (token >> 8) & 0xFF

                long_data = bytes((0x01, 0x00, 0x00, 0x0F, LONG_MARKER, low, high))
                short_data = bytes((0x01, 0x00, 0x00, low, high))

                self._send_frame(address, address, token, long_data)

                gap_end = time.perf_counter() + PAIR_GAP_S
                while time.perf_counter() < gap_end:
                    pass

                self._send_frame(address, 0x0010 + address, token, short_data)

            remaining = next_cycle - time.perf_counter()
            if remaining > 0.001:
                time.sleep(remaining - 0.0005)
            while time.perf_counter() < next_cycle:
                pass

            # Avoid an uncontrolled catch-up burst if the host was delayed.
            if time.perf_counter() - next_cycle > CYCLE_PERIOD_S:
                next_cycle = time.perf_counter()

    # ------------------------------------------------------------------
    # State and operator interaction
    # ------------------------------------------------------------------

    def real_pair_rate_hz(self) -> float:
        now = time.monotonic()
        with self.rate_lock:
            cutoff = now - 2.0
            while self.real_rx_times and self.real_rx_times[0] < cutoff:
                self.real_rx_times.popleft()
            return len(self.real_rx_times) / 2.0

    def set_active_addresses(self, addresses: Iterable[int], reason: str) -> None:
        validated = {int(address) for address in addresses}
        if any(address < 1 or address > 8 for address in validated):
            raise ValueError(f"Addresses must be in the range 1..8: {validated}")

        with self.state.active_lock:
            old = sorted(self.active_addresses)
            self.active_addresses = validated
            new = sorted(self.active_addresses)

        self.log_event("simulated_addresses_changed", f"{old} -> {new}; {reason}")

    def wait_period(self, seconds: float, description: str) -> None:
        self.log_event("wait_started", f"{description}; {seconds:.1f} s")
        deadline = time.monotonic() + seconds
        last_displayed = None

        while not self.state.stop_event.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break

            display_value = int(remaining + 0.999)
            if display_value != last_displayed and (display_value <= 5 or display_value % 5 == 0):
                rate = self.real_pair_rate_hz()
                print(
                    f"  {description}: {display_value:3d} s remaining "
                    f"| real 0001/0011 RX rate ≈ {rate:.1f} frames/s"
                )
                last_displayed = display_value
            time.sleep(min(0.2, max(0.01, remaining)))

        if self.state.stop_event.is_set():
            raise AbortRequested()
        print("\a", end="", flush=True)
        self.log_event("wait_completed", description)

    def operator_feedback(self) -> None:
        print("\n" + "-" * 68)
        print(f"PHASE: {self.state.get_phase()}")
        print("Simulation and CAN logging continue while this prompt is open.")
        print("Enter = unknown | S = skip phase feedback | D = details | X = abort")
        print("-" * 68)

        details: dict[str, str] = {}

        while True:
            raw_n = input("Displayed N: ").strip()
            command = raw_n.upper()

            if command == "X":
                raise AbortRequested()
            if command == "S":
                self.log_observation(feedback="skipped")
                self.log_event("operator_feedback_skipped")
                return
            if command == "D":
                details = self.optional_details()
                continue
            break

        raw_vp = input("Displayed VP [bar]: ").strip()
        if raw_vp.upper() == "X":
            raise AbortRequested()
        if raw_vp.upper() == "S":
            self.log_observation(n=raw_n, feedback="partially_skipped", details=details)
            self.log_event("operator_feedback_partially_skipped", f"N={raw_n}")
            return
        if raw_vp.upper() == "D":
            details = self.optional_details()
            raw_vp = input("Displayed VP [bar]: ").strip()
            if raw_vp.upper() == "X":
                raise AbortRequested()

        self.log_observation(n=raw_n, vp=raw_vp, feedback="recorded", details=details)
        self.log_event("operator_feedback_recorded", f"N={raw_n or 'unknown'}, VP={raw_vp or 'unknown'}")

    @staticmethod
    def optional_details() -> dict[str, str]:
        print("\nOptional detail view. Press Enter to skip any field.")
        return {
            "mechanical_pressure_bar": input("Mechanical pressure [bar]: ").strip(),
            "communication_icon": input("Communication icon/address: ").strip(),
            "pump_state": input("Pump state [SB/GO/FAULT/other]: ").strip(),
            "display_message": input("Display message: ").strip(),
            "notes": input("Other notes: ").strip(),
        }

    def begin_phase(self, phase: str, addresses: Iterable[int], reason: str) -> None:
        self.state.set_phase(phase)
        self.log_event("phase_started", phase)
        self.set_active_addresses(addresses, reason)

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    def baseline(self, phase: str) -> None:
        self.begin_phase(phase, (), "passive baseline")
        self.wait_period(BASELINE_S, "passive baseline")
        self.operator_feedback()

    def recovery(self, phase: str) -> None:
        self.begin_phase(phase, (), "all simulated controllers stopped")
        self.wait_period(RECOVERY_S, "post-simulation recovery")
        self.operator_feedback()

    def run_t14(self) -> None:
        print("\n=== T14: one simulated controller, logical address 3 ===")
        self.baseline("T14_baseline")

        self.begin_phase("T14_address_3_active", (T14_ADDRESS,), "start address 3")
        self.wait_period(STABILIZE_S, "address 3 stabilization")
        self.operator_feedback()

        self.recovery("T14_recovery")

    def run_t15(self) -> None:
        print("\n=== T15: logical addresses 3 and 5, sequentially added ===")
        a1, a2 = T15_ADDRESSES
        self.baseline("T15_baseline")

        self.begin_phase("T15_address_3_active", (a1,), f"start address {a1}")
        self.wait_period(STABILIZE_S, f"address {a1} stabilization")
        self.operator_feedback()

        self.begin_phase("T15_addresses_3_5_active", (a1, a2), f"add address {a2}")
        self.wait_period(STABILIZE_S, f"addresses {a1} and {a2} stabilization")
        self.operator_feedback()

        self.begin_phase("T15_address_3_only_after_5_stop", (a1,), f"stop address {a2}")
        self.wait_period(STABILIZE_S, f"address {a2} removal stabilization")
        self.operator_feedback()

        self.recovery("T15_recovery")

    def run_t16(self) -> None:
        print("\n=== T16: addresses directly after real controller: 2 and 3 ===")
        a1, a2 = T16_ADDRESSES
        self.baseline("T16_baseline")

        self.begin_phase("T16_address_2_active", (a1,), f"start address {a1}")
        self.wait_period(STABILIZE_S, f"address {a1} stabilization")
        self.operator_feedback()

        self.begin_phase("T16_addresses_2_3_active", (a1, a2), f"add address {a2}")
        self.wait_period(STABILIZE_S, f"addresses {a1} and {a2} stabilization")
        self.operator_feedback()

        self.begin_phase("T16_address_2_only_after_3_stop", (a1,), f"stop address {a2}")
        self.wait_period(STABILIZE_S, f"address {a2} removal stabilization")
        self.operator_feedback()

        self.recovery("T16_recovery")

    def run_t17(self) -> None:
        print("\n=== T17: address 3 active for at least five minutes ===")
        self.baseline("T17_baseline")

        self.begin_phase("T17_address_3_pre_process", (T17_ADDRESS,), "start long-duration address 3")
        self.wait_period(STABILIZE_S, "address 3 pre-process stabilization")
        self.operator_feedback()

        print("\nPrepare the real hydraulic process test.")
        print("Address 3 remains active and logging continues.")
        command = input("Press ENTER when ready to start the five-minute timer, or X to abort: ").strip()
        if command.upper() == "X":
            raise AbortRequested()

        self.state.set_phase("T17_five_minute_process")
        self.log_event("five_minute_process_started", f"minimum duration={PROCESS_DURATION_S} s")
        process_start = time.monotonic()

        checkpoints = list(
            range(PROCESS_CHECKPOINT_S, PROCESS_DURATION_S + 1, PROCESS_CHECKPOINT_S)
        )

        for checkpoint in checkpoints:
            remaining = checkpoint - (time.monotonic() - process_start)
            if remaining > 0:
                self.wait_period(remaining, f"process checkpoint at {checkpoint} seconds")
            print(f"\nProcess checkpoint: nominal elapsed time {checkpoint} seconds")
            self.operator_feedback()

        actual_duration = time.monotonic() - process_start
        self.log_event("five_minute_process_completed", f"actual duration={actual_duration:.3f} s")

        command = input(
            "Press ENTER to stop the simulated controller, or wait as long as needed. "
            "Type X to abort: "
        ).strip()
        if command.upper() == "X":
            raise AbortRequested()

        self.recovery("T17_recovery")

    def run_all(self) -> None:
        self.run_t14()
        self.run_t15()
        self.run_t16()
        self.run_t17()

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------

    def _write_metadata(self, started: bool) -> None:
        metadata = {
            "script": Path(__file__).name,
            "started": started,
            "utc": utc_now(),
            "can_interface": CAN_INTERFACE,
            "can_channel": CAN_CHANNEL,
            "can_bitrate": CAN_BITRATE,
            "cycle_period_s": CYCLE_PERIOD_S,
            "pair_gap_s": PAIR_GAP_S,
            "long_marker_hex": f"{LONG_MARKER:02X}",
            "baseline_s": BASELINE_S,
            "stabilize_s": STABILIZE_S,
            "recovery_s": RECOVERY_S,
            "process_duration_s": PROCESS_DURATION_S,
            "tests": {
                "T14": [T14_ADDRESS],
                "T15": list(T15_ADDRESSES),
                "T16": list(T16_ADDRESSES),
                "T17": [T17_ADDRESS],
            },
            "files": {
                "raw": str(self.raw_path),
                "events": str(self.events_path),
                "observations": str(self.observations_path),
            },
        }
        self.metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    def close(self) -> None:
        if self.state.stop_event.is_set():
            return

        self.log_event("shutdown_started")
        with self.state.active_lock:
            self.active_addresses.clear()
        self.state.stop_event.set()

        if self.simulator_thread is not None:
            self.simulator_thread.join(timeout=2.0)
        if self.receiver_thread is not None:
            self.receiver_thread.join(timeout=2.0)

        if self.bus is not None:
            try:
                self.bus.shutdown()
            except Exception as exc:
                print(f"CAN shutdown warning: {exc!r}", file=sys.stderr)

        self._write_metadata(started=False)

        self.raw_writer.close()
        self.event_writer.close()
        self.observation_writer.close()
        self.raw_writer.join(timeout=5.0)
        self.event_writer.join(timeout=5.0)
        self.observation_writer.join(timeout=5.0)

        print("\nSession closed safely.")
        print(f"Raw CAN log:       {self.raw_path}")
        print(f"Event log:         {self.events_path}")
        print(f"Operator feedback: {self.observations_path}")
        print(f"Metadata:          {self.metadata_path}")


def main() -> int:
    session = DabTestSession()

    def request_shutdown(signum, frame):
        print(f"\nSignal {signum} received; stopping simulation safely...")
        session.state.stop_event.set()

    signal.signal(signal.SIGINT, request_shutdown)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, request_shutdown)

    print("DAB hierarchy and process simulation test")
    print(f"Interface: {CAN_INTERFACE}, channel: {CAN_CHANNEL}, bitrate: {CAN_BITRATE}")
    print("\nPlanned logical addresses:")
    print(f"  T14: {T14_ADDRESS}")
    print(f"  T15: {T15_ADDRESSES}")
    print(f"  T16: {T16_ADDRESSES}")
    print(f"  T17: {T17_ADDRESS} for at least {PROCESS_DURATION_S // 60} minutes")
    print("\nWARNING: verify hydraulic pressure limits and retain a direct emergency stop.")

    confirmation = input("Type RUN to initialize CAN and begin: ").strip().upper()
    if confirmation != "RUN":
        print("Cancelled.")
        return 0

    try:
        session.open()
        session.run_all()
        session.log_event("all_tests_completed")
        return 0
    except AbortRequested:
        session.log_event("session_aborted_by_operator")
        print("Operator abort requested.")
        return 2
    except KeyboardInterrupt:
        session.log_event("session_interrupted")
        print("Interrupted.")
        return 130
    except Exception as exc:
        try:
            session.log_event("fatal_error", repr(exc))
        except Exception:
            pass
        print(f"Fatal error: {exc!r}", file=sys.stderr)
        return 1
    finally:
        session.close()


if __name__ == "__main__":
    raise SystemExit(main())
