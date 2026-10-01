#!/usr/bin/env python3
"""
pcan_peer_tests_chatbot.py
===========================
Complete PCAN peer simulator and logger for the DAB Active Driver Plus M/M 1.5.

Fixes compared with the original script:
- Compatible with PCANBasic wrappers that expose constants as int, ctypes or bytes.
- Continuous background reception, including during prompts and transmission.
- PCAN hardware timestamps for received records.
- Every TX attempt and Write() return code is logged.
- Requests error, status and TX echo frames when supported by the driver.
- No blind acquisition windows during Test 21 through Test 24.
- Explicit phase markers for baseline, injection, burst and post-observation.
- Unified timeline plus separate RX, TX and bus-event CSV files.
- Error-frame decoding and session summary.

Do not run PCAN-View on PCAN_USBBUS1 while this script is using that channel.

Examples:
    python pcan_peer_tests_chatbot.py --test baseline
    python pcan_peer_tests_chatbot.py --test 21 --send
    python pcan_peer_tests_chatbot.py --test all --send
    python pcan_peer_tests_chatbot.py --test 24 --test24-seconds 10 --send

Sending is disabled unless --send is explicitly supplied.
"""

import argparse
import csv
import json
import os
import random
import sys
import threading
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# PCAN-Basic import
# ---------------------------------------------------------------------------

try:
    from pcan.PCANBasic import *
except ImportError:
    try:
        from PCANBasic import *
    except ImportError:
        print("FOUT: PCANBasic.py kan niet worden geïmporteerd.")
        print("Plaats de officiële PEAK PCAN-Basic Python-wrapper naast dit script")
        print("of installeer hem op het actieve Python-pad.")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Compatibility helpers
# ---------------------------------------------------------------------------

def pcan_int(value):
    """
    Convert PCAN-Basic values robustly to int.

    Depending on PCANBasic.py and Python versions, constants may be ordinary
    integers, ctypes values, or one/more-byte byte strings.
    """
    if value is None:
        return 0

    if isinstance(value, (bytes, bytearray)):
        return int.from_bytes(value, byteorder="little", signed=False)

    if hasattr(value, "value"):
        return pcan_int(value.value)

    return int(value)


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def local_now_iso():
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def error_text(api, status):
    status_number = pcan_int(status)

    try:
        result = api.GetErrorText(status, 0)
    except TypeError:
        try:
            result = api.GetErrorText(status)
        except Exception:
            return "PCAN status 0x{:08X}".format(status_number)
    except Exception:
        return "PCAN status 0x{:08X}".format(status_number)

    if isinstance(result, tuple):
        if len(result) >= 2:
            text = result[1]
        else:
            text = result
    else:
        text = result

    if isinstance(text, bytes):
        return text.decode("utf-8", errors="replace")

    return str(text)


# ---------------------------------------------------------------------------
# PCAN and protocol configuration
# ---------------------------------------------------------------------------

CHANNEL = PCAN_USBBUS1
BITRATE = PCAN_BAUD_1M

PCAN_OK = pcan_int(PCAN_ERROR_OK)
PCAN_QUEUE_EMPTY = pcan_int(PCAN_ERROR_QRCVEMPTY)

MSGTYPE_STANDARD = pcan_int(globals().get("PCAN_MESSAGE_STANDARD", 0x00))
MSGTYPE_RTR = pcan_int(globals().get("PCAN_MESSAGE_RTR", 0x01))
MSGTYPE_EXTENDED = pcan_int(globals().get("PCAN_MESSAGE_EXTENDED", 0x02))
MSGTYPE_FD = pcan_int(globals().get("PCAN_MESSAGE_FD", 0x04))
MSGTYPE_BRS = pcan_int(globals().get("PCAN_MESSAGE_BRS", 0x08))
MSGTYPE_ESI = pcan_int(globals().get("PCAN_MESSAGE_ESI", 0x10))
MSGTYPE_ECHO = pcan_int(globals().get("PCAN_MESSAGE_ECHO", 0x20))
MSGTYPE_ERRFRAME = pcan_int(globals().get("PCAN_MESSAGE_ERRFRAME", 0x40))
MSGTYPE_STATUS = pcan_int(globals().get("PCAN_MESSAGE_STATUS", 0x80))

FAMILY_A = 0x00010000
FAMILY_B = 0x00110000

PAIR_GAP_S = 0.000114
CYCLE_PERIOD_S = 0.005

DEFAULT_PRE_SECONDS = 5.0
DEFAULT_POST_SECONDS = 10.0
DEFAULT_BASELINE_SECONDS = 10.0
DEFAULT_TEST22_BURST_SECONDS = 1.0
DEFAULT_TEST22_POST_SECONDS = 20.0
DEFAULT_TEST23_BURST_SECONDS = 1.0
DEFAULT_TEST23_POST_SECONDS = 10.0
DEFAULT_TEST24_SECONDS = 1.0
DEFAULT_TEST24_POST_SECONDS = 15.0


# ---------------------------------------------------------------------------
# General helpers
# ---------------------------------------------------------------------------

def status_ok(api, status, operation):
    number = pcan_int(status)
    if number == PCAN_OK:
        return True

    print("PCAN FOUT bij {}: 0x{:08X} - {}".format(
        operation,
        number,
        error_text(api, status),
    ))
    return False


def token_bytes(token):
    return token & 0xFF, (token >> 8) & 0xFF


def make_id(family, token):
    return family | (token & 0xFFFF)


def make_frame(can_id, data):
    msg = TPCANMsg()
    msg.ID = int(can_id)
    msg.MSGTYPE = MSGTYPE_EXTENDED
    msg.LEN = len(data)

    for index, value in enumerate(data):
        msg.DATA[index] = int(value) & 0xFF

    return msg


def frame_dlc7(token, marker=0x03):
    lo, hi = token_bytes(token)

    return make_frame(
        make_id(FAMILY_A, token),
        [0x01, 0x00, 0x00, 0x0F, marker & 0xFF, lo, hi],
    )


def frame_dlc5(token):
    lo, hi = token_bytes(token)

    return make_frame(
        make_id(FAMILY_B, token),
        [0x01, 0x00, 0x00, lo, hi],
    )


def sleep_until(target_ns):
    """Hybrid wait with a short final spin."""
    while True:
        remaining_ns = target_ns - time.perf_counter_ns()

        if remaining_ns <= 0:
            return

        if remaining_ns > 2_000_000:
            time.sleep((remaining_ns - 1_000_000) / 1_000_000_000)
        elif remaining_ns > 200_000:
            time.sleep(0)


def prompt_text(label, default=""):
    suffix = " [{}]".format(default) if default else ""
    value = input("{}{}: ".format(label, suffix)).strip()
    return value if value else default


def timestamp_to_us(timestamp):
    """Convert a PCAN hardware timestamp to microseconds."""
    if timestamp is None:
        return None

    try:
        millis = pcan_int(timestamp.millis)
        overflow = pcan_int(timestamp.millis_overflow)
        micros = pcan_int(timestamp.micros)

        return ((overflow << 32) + millis) * 1000 + micros
    except Exception:
        pass

    for attribute in ("value", "Value"):
        try:
            return pcan_int(getattr(timestamp, attribute))
        except Exception:
            pass

    try:
        return pcan_int(timestamp)
    except Exception:
        return None


def msgtype_labels(msg_type):
    value = pcan_int(msg_type)
    labels = []

    labels.append("EXT" if value & MSGTYPE_EXTENDED else "STD")

    if value & MSGTYPE_RTR:
        labels.append("RTR")
    if value & MSGTYPE_FD:
        labels.append("FD")
    if value & MSGTYPE_BRS:
        labels.append("BRS")
    if value & MSGTYPE_ESI:
        labels.append("ESI")
    if value & MSGTYPE_ECHO:
        labels.append("ECHO")
    if value & MSGTYPE_ERRFRAME:
        labels.append("ERRFRAME")
    if value & MSGTYPE_STATUS:
        labels.append("STATUS")

    return "|".join(labels)


# ---------------------------------------------------------------------------
# Error-frame decoding
# ---------------------------------------------------------------------------

ERROR_TYPE_BITS = {
    0x0001: "bit_error",
    0x0002: "form_error",
    0x0004: "stuff_error",
    0x0008: "other_error",
}

BIT_POSITION_NAMES = {
    2: "ID.28..ID.21",
    3: "start_of_frame",
    4: "SRTR",
    5: "IDE",
    6: "ID.20..ID.18",
    7: "ID.17..ID.13",
    8: "CRC_sequence",
    9: "reserved_bit_0",
    10: "data_field",
    11: "DLC",
    12: "RTR",
    13: "reserved_bit_1",
    14: "ID.12..ID.5",
    15: "ID.4..ID.0",
    17: "active_error_flag",
    18: "intermission",
    19: "tolerate_dominant_bits",
    23: "error_delimiter",
    24: "CRC_delimiter",
    25: "ACK_slot",
    26: "end_of_frame",
    27: "ACK_delimiter",
    28: "overload_flag",
}


def decode_error_frame(can_id, data):
    names = [
        name
        for bit, name in ERROR_TYPE_BITS.items()
        if can_id & bit
    ]

    direction = "unknown"
    position = None
    position_name = ""
    rx_counter = None
    tx_counter = None

    if len(data) >= 1:
        direction = {
            0: "tx",
            1: "rx",
        }.get(data[0], "value_{}".format(data[0]))

    if len(data) >= 2:
        position = data[1]
        position_name = BIT_POSITION_NAMES.get(
            position,
            "position_{}".format(position),
        )

    if len(data) >= 3:
        rx_counter = data[2]

    if len(data) >= 4:
        tx_counter = data[3]

    return {
        "error_type": "|".join(names) if names else "0x{:04X}".format(can_id),
        "error_direction": direction,
        "error_position": position,
        "error_position_name": position_name,
        "rx_error_counter": rx_counter,
        "tx_error_counter": tx_counter,
    }


# ---------------------------------------------------------------------------
# Unified timeline record
# ---------------------------------------------------------------------------

@dataclass
class TimelineRecord:
    sequence: int
    host_ns: int
    host_rel_us: float
    hardware_us: object
    hardware_rel_us: object
    phase: str
    direction: str
    kind: str
    status_code: int
    status_text: str
    can_id: object
    can_id_hex: str
    msg_type: object
    msg_type_hex: str
    msg_type_labels: str
    dlc: object
    data_hex: str
    token: object
    family_hex: str
    marker: object
    tx_description: str
    tx_success: object
    error_type: str
    error_direction: str
    error_position: object
    error_position_name: str
    rx_error_counter: object
    tx_error_counter: object


TIMELINE_COLUMNS = list(TimelineRecord.__dataclass_fields__.keys())


# ---------------------------------------------------------------------------
# Continuous RX acquisition
# ---------------------------------------------------------------------------

class ContinuousRecorder:
    def __init__(self, api, channel, poll_sleep_s=0.0002):
        self.api = api
        self.channel = channel
        self.poll_sleep_s = poll_sleep_s

        self.records = []
        self.phase_markers = []
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.thread = None

        self.phase = "initialising"
        self.sequence = 0
        self.host_zero_ns = time.perf_counter_ns()
        self.hardware_zero_us = None

        self.read_status_counts = Counter()
        self.max_queue_batch = 0
        self.total_rx = 0

    def _next_sequence(self):
        with self.lock:
            self.sequence += 1
            return self.sequence

    def _append(self, record):
        with self.lock:
            self.records.append(record)

    def current_phase(self):
        with self.lock:
            return self.phase

    def set_phase(self, phase, details=""):
        host_ns = time.perf_counter_ns()

        with self.lock:
            self.phase = phase
            self.phase_markers.append({
                "host_ns": host_ns,
                "host_rel_us": (host_ns - self.host_zero_ns) / 1000.0,
                "phase": phase,
                "details": details,
                "utc": utc_now_iso(),
            })

        print("[PHASE] {}{}".format(
            phase,
            " - " + details if details else "",
        ))

    def start(self):
        self.stop_event.clear()
        self.thread = threading.Thread(
            target=self._reader_loop,
            name="pcan-rx",
            daemon=True,
        )
        self.thread.start()

    def stop(self):
        self.stop_event.set()

        if self.thread is not None:
            self.thread.join(timeout=3.0)

        self.poll_once()

    def snapshot_index(self):
        with self.lock:
            return len(self.records)

    def _reader_loop(self):
        while not self.stop_event.is_set():
            count = self.poll_once()

            if count == 0:
                time.sleep(self.poll_sleep_s)

    def poll_once(self):
        batch_count = 0

        while True:
            host_ns = time.perf_counter_ns()

            try:
                result = self.api.Read(self.channel)
            except Exception as exc:
                self._append_read_status(
                    -1,
                    "Read exception: {}".format(exc),
                    host_ns,
                )
                break

            status = pcan_int(result[0])
            self.read_status_counts[status] += 1

            if status == PCAN_QUEUE_EMPTY:
                break

            if status != PCAN_OK:
                self._append_read_status(
                    status,
                    error_text(self.api, status),
                    host_ns,
                )
                break

            if len(result) < 2:
                self._append_read_status(
                    -2,
                    "Read returned no CAN message",
                    host_ns,
                )
                break

            msg = result[1]
            hardware_timestamp = result[2] if len(result) >= 3 else None
            hardware_us = timestamp_to_us(hardware_timestamp)

            if hardware_us is not None and self.hardware_zero_us is None:
                self.hardware_zero_us = hardware_us

            dlc = pcan_int(msg.LEN)
            data = bytes(
                pcan_int(msg.DATA[index])
                for index in range(dlc)
            )

            can_id = pcan_int(msg.ID)
            msg_type = pcan_int(msg.MSGTYPE)

            kind = "rx_frame"
            decoded = {
                "error_type": "",
                "error_direction": "",
                "error_position": None,
                "error_position_name": "",
                "rx_error_counter": None,
                "tx_error_counter": None,
            }

            if msg_type & MSGTYPE_ERRFRAME:
                kind = "rx_error_frame"
                decoded = decode_error_frame(can_id, data)
            elif msg_type & MSGTYPE_STATUS:
                kind = "rx_status_frame"
            elif msg_type & MSGTYPE_ECHO:
                kind = "rx_echo_frame"

            family = can_id & 0xFFFF0000
            token = can_id & 0xFFFF
            marker = data[4] if dlc == 7 and len(data) >= 5 else None

            self._append(TimelineRecord(
                sequence=self._next_sequence(),
                host_ns=host_ns,
                host_rel_us=(host_ns - self.host_zero_ns) / 1000.0,
                hardware_us=hardware_us,
                hardware_rel_us=(
                    hardware_us - self.hardware_zero_us
                    if hardware_us is not None and self.hardware_zero_us is not None
                    else None
                ),
                phase=self.current_phase(),
                direction="RX",
                kind=kind,
                status_code=status,
                status_text="OK",
                can_id=can_id,
                can_id_hex="{:08X}".format(can_id),
                msg_type=msg_type,
                msg_type_hex="0x{:02X}".format(msg_type),
                msg_type_labels=msgtype_labels(msg_type),
                dlc=dlc,
                data_hex=" ".join("{:02X}".format(value) for value in data),
                token=token,
                family_hex="0x{:08X}".format(family),
                marker=marker,
                tx_description="",
                tx_success=None,
                **decoded
            ))

            batch_count += 1
            self.total_rx += 1

        self.max_queue_batch = max(self.max_queue_batch, batch_count)
        return batch_count

    def _append_read_status(self, status, text, host_ns):
        self._append(TimelineRecord(
            sequence=self._next_sequence(),
            host_ns=host_ns,
            host_rel_us=(host_ns - self.host_zero_ns) / 1000.0,
            hardware_us=None,
            hardware_rel_us=None,
            phase=self.current_phase(),
            direction="RX",
            kind="read_status",
            status_code=pcan_int(status),
            status_text=str(text),
            can_id=None,
            can_id_hex="",
            msg_type=None,
            msg_type_hex="",
            msg_type_labels="",
            dlc=None,
            data_hex="",
            token=None,
            family_hex="",
            marker=None,
            tx_description="",
            tx_success=False,
            error_type="",
            error_direction="",
            error_position=None,
            error_position_name="",
            rx_error_counter=None,
            tx_error_counter=None,
        ))

    def log_tx(self, msg, description, status, success):
        host_ns = time.perf_counter_ns()
        dlc = pcan_int(msg.LEN)

        data = bytes(
            pcan_int(msg.DATA[index])
            for index in range(dlc)
        )

        can_id = pcan_int(msg.ID)
        msg_type = pcan_int(msg.MSGTYPE)
        family = can_id & 0xFFFF0000
        token = can_id & 0xFFFF
        marker = data[4] if dlc == 7 and len(data) >= 5 else None

        self._append(TimelineRecord(
            sequence=self._next_sequence(),
            host_ns=host_ns,
            host_rel_us=(host_ns - self.host_zero_ns) / 1000.0,
            hardware_us=None,
            hardware_rel_us=None,
            phase=self.current_phase(),
            direction="TX",
            kind="tx_attempt",
            status_code=pcan_int(status),
            status_text="OK" if success else error_text(self.api, status),
            can_id=can_id,
            can_id_hex="{:08X}".format(can_id),
            msg_type=msg_type,
            msg_type_hex="0x{:02X}".format(msg_type),
            msg_type_labels=msgtype_labels(msg_type),
            dlc=dlc,
            data_hex=" ".join("{:02X}".format(value) for value in data),
            token=token,
            family_hex="0x{:08X}".format(family),
            marker=marker,
            tx_description=description,
            tx_success=bool(success),
            error_type="",
            error_direction="",
            error_position=None,
            error_position_name="",
            rx_error_counter=None,
            tx_error_counter=None,
        ))


# ---------------------------------------------------------------------------
# CAN transmitter
# ---------------------------------------------------------------------------

class CanTransmitter:
    def __init__(self, api, channel, recorder, enabled):
        self.api = api
        self.channel = channel
        self.recorder = recorder
        self.enabled = enabled
        self.sent_ok = 0
        self.sent_failed = 0

    def send(self, msg, description=""):
        if not self.enabled:
            status = PCAN_OK
            success = True
            description = "DRY_RUN " + description
        else:
            status = pcan_int(self.api.Write(self.channel, msg))
            success = status == PCAN_OK

        self.recorder.log_tx(
            msg,
            description,
            status,
            success,
        )

        if success:
            self.sent_ok += 1
        else:
            self.sent_failed += 1
            print("TX FOUT {}: 0x{:08X} {}".format(
                description,
                status,
                error_text(self.api, status),
            ))

        return success

    def send_pair(self, token, marker=0x03, pair_gap_s=PAIR_GAP_S):
        first = frame_dlc7(token, marker=marker)
        second = frame_dlc5(token)

        if not self.send(
            first,
            "pair_dlc7 marker=0x{:02X}".format(marker),
        ):
            return False

        target_ns = time.perf_counter_ns() + int(pair_gap_s * 1_000_000_000)
        sleep_until(target_ns)

        return self.send(second, "pair_dlc5")

    def send_periodic(
        self,
        seconds,
        mode="pair",
        fixed_token=None,
        marker=0x03,
        rate_hz=200.0,
    ):
        period_ns = int(1_000_000_000 / rate_hz)
        start_ns = time.perf_counter_ns()
        deadline_ns = start_ns

        cycles = 0
        late_cycles = 0
        max_late_us = 0.0

        while True:
            now_ns = time.perf_counter_ns()

            if now_ns - start_ns >= int(seconds * 1_000_000_000):
                break

            token = (
                fixed_token
                if fixed_token is not None
                else random.randint(0x0000, 0xFFFF)
            )

            if mode == "dlc7":
                self.send(
                    frame_dlc7(token, marker=marker),
                    "periodic_dlc7",
                )
            elif mode == "dlc5":
                self.send(
                    frame_dlc5(token),
                    "periodic_dlc5",
                )
            elif mode == "pair":
                self.send_pair(token, marker=marker)
            else:
                raise ValueError("Unknown TX mode: {}".format(mode))

            cycles += 1
            deadline_ns += period_ns

            now_ns = time.perf_counter_ns()
            lateness_ns = now_ns - deadline_ns

            if lateness_ns > 0:
                late_cycles += 1
                max_late_us = max(
                    max_late_us,
                    lateness_ns / 1000.0,
                )

                if lateness_ns > period_ns:
                    deadline_ns = now_ns
            else:
                sleep_until(deadline_ns)

        return {
            "cycles": cycles,
            "late_cycles": late_cycles,
            "max_late_us": round(max_late_us, 3),
        }


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def timed_observation(recorder, phase, seconds, details=""):
    recorder.set_phase(phase, details)
    deadline_ns = time.perf_counter_ns() + int(seconds * 1_000_000_000)

    while time.perf_counter_ns() < deadline_ns:
        time.sleep(0.05)


def run_baseline(recorder, seconds):
    start = recorder.snapshot_index()

    timed_observation(
        recorder,
        "baseline",
        seconds,
        "no transmission",
    )

    return start, recorder.snapshot_index()


def run_test21_variant(
    recorder,
    transmitter,
    name,
    marker,
    token,
    pre_seconds,
    post_seconds,
):
    start = recorder.snapshot_index()

    timed_observation(
        recorder,
        name + ":pre",
        pre_seconds,
        "passive baseline",
    )

    recorder.set_phase(
        name + ":inject",
        "single pair token={:04X}, marker={:02X}".format(token, marker),
    )

    transmitter.send_pair(
        token=token,
        marker=marker,
    )

    timed_observation(
        recorder,
        name + ":post",
        post_seconds,
        "passive observation",
    )

    return start, recorder.snapshot_index()


def run_test21(recorder, transmitter, args):
    results = {}

    print("\nTEST 21A — één 0F 00-paar")
    input("ENTER om Test 21A te starten...")

    results["test21_startmarker"] = run_test21_variant(
        recorder,
        transmitter,
        "test21_startmarker",
        marker=0x00,
        token=0x1234,
        pre_seconds=args.pre_seconds,
        post_seconds=args.post_seconds,
    )

    print("\nControleer N, communicatiepictogram, displaymelding en FF.")
    input("ENTER om Test 21B te starten...")

    print("\nTEST 21B — één 0F 03-paar")

    results["test21_normal"] = run_test21_variant(
        recorder,
        transmitter,
        "test21_normal",
        marker=0x03,
        token=0x1234,
        pre_seconds=args.pre_seconds,
        post_seconds=args.post_seconds,
    )

    return results


def run_test22(recorder, transmitter, args):
    print("\nTEST 22 — startmarker plus vaste-tokenburst")
    input("ENTER om Test 22 te starten...")

    start = recorder.snapshot_index()

    timed_observation(
        recorder,
        "test22:pre",
        args.pre_seconds,
        "passive baseline",
    )

    recorder.set_phase(
        "test22:startmarker",
        "single 0F 00 pair, token 1234",
    )

    transmitter.send_pair(
        token=0x1234,
        marker=0x00,
    )

    recorder.set_phase(
        "test22:burst",
        "fixed token 1234, 200 Hz pairs",
    )

    stats = transmitter.send_periodic(
        seconds=args.test22_burst_seconds,
        mode="pair",
        fixed_token=0x1234,
        marker=0x03,
        rate_hz=200.0,
    )

    print("TX timing:", stats)

    timed_observation(
        recorder,
        "test22:post",
        args.test22_post_seconds,
        "passive observation",
    )

    return {
        "test22": (
            start,
            recorder.snapshot_index(),
        )
    }


def run_test23(recorder, transmitter, args):
    results = {}

    for mode in ("dlc7", "dlc5", "pair"):
        name = "test23_" + mode

        print("\nTEST 23 —", mode)
        input("ENTER om {} te starten...".format(name))

        start = recorder.snapshot_index()

        timed_observation(
            recorder,
            name + ":pre",
            args.pre_seconds,
            "passive baseline",
        )

        recorder.set_phase(
            name + ":burst",
            "fixed token 1234, mode={}".format(mode),
        )

        stats = transmitter.send_periodic(
            seconds=args.test23_burst_seconds,
            mode=mode,
            fixed_token=0x1234,
            marker=0x03,
            rate_hz=200.0,
        )

        print("TX timing:", stats)

        timed_observation(
            recorder,
            name + ":post",
            args.test23_post_seconds,
            "passive observation",
        )

        results[name] = (
            start,
            recorder.snapshot_index(),
        )

    return results


def run_test24(recorder, transmitter, args):
    print("\nTEST 24 — realistisch veranderende token")
    input("ENTER om Test 24 te starten...")

    start = recorder.snapshot_index()

    timed_observation(
        recorder,
        "test24:pre",
        args.pre_seconds,
        "passive baseline",
    )

    start_token = random.randint(0x0000, 0xFFFF)

    recorder.set_phase(
        "test24:startmarker",
        "random start token {:04X}".format(start_token),
    )

    transmitter.send_pair(
        token=start_token,
        marker=0x00,
    )

    recorder.set_phase(
        "test24:burst",
        "random token, 200 Hz pairs",
    )

    stats = transmitter.send_periodic(
        seconds=args.test24_seconds,
        mode="pair",
        fixed_token=None,
        marker=0x03,
        rate_hz=200.0,
    )

    print("TX timing:", stats)

    timed_observation(
        recorder,
        "test24:post",
        args.test24_post_seconds,
        "passive observation",
    )

    return {
        "test24": (
            start,
            recorder.snapshot_index(),
        )
    }


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def record_to_row(record):
    row = asdict(record)

    for key, value in row.items():
        if value is None:
            row[key] = ""

    return row


def write_records_csv(path, records):
    with open(
        path,
        "w",
        newline="",
        encoding="utf-8-sig",
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=TIMELINE_COLUMNS,
        )

        writer.writeheader()

        for record in sorted(records, key=lambda item: item.sequence):
            writer.writerow(record_to_row(record))


def write_phase_markers(path, markers):
    columns = [
        "host_ns",
        "host_rel_us",
        "phase",
        "details",
        "utc",
    ]

    with open(
        path,
        "w",
        newline="",
        encoding="utf-8-sig",
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=columns,
        )

        writer.writeheader()
        writer.writerows(markers)


def write_split_csvs(output_dir, records):
    rx_frames = [
        record
        for record in records
        if record.kind in ("rx_frame", "rx_echo_frame")
    ]

    tx_records = [
        record
        for record in records
        if record.direction == "TX"
    ]

    bus_events = [
        record
        for record in records
        if record.kind in (
            "rx_error_frame",
            "rx_status_frame",
            "read_status",
        )
    ]

    write_records_csv(
        os.path.join(output_dir, "rx_frames.csv"),
        rx_frames,
    )

    write_records_csv(
        os.path.join(output_dir, "tx_attempts.csv"),
        tx_records,
    )

    write_records_csv(
        os.path.join(output_dir, "bus_events.csv"),
        bus_events,
    )


def write_per_test_csvs(output_dir, records, test_ranges):
    for name, indexes in test_ranges.items():
        start_index, end_index = indexes
        subset = records[start_index:end_index]

        write_records_csv(
            os.path.join(
                output_dir,
                name + "_timeline.csv",
            ),
            subset,
        )


def collect_manual_notes(test_name):
    print("\nHandmatige observaties voor", test_name)

    return {
        "test": test_name,
        "N": prompt_text("N", "1"),
        "AD": prompt_text("AD", "0"),
        "communication_icon": prompt_text(
            "communicatiepictogram",
            "no comm",
        ),
        "display_message": prompt_text(
            "displaymelding",
            "geen",
        ),
        "FF_new_error": prompt_text(
            "nieuwe FF-fout",
            "geen",
        ),
        "SP_bar": prompt_text("SP [bar]", ""),
        "RP_bar": prompt_text("RP [bar]", ""),
        "pump_state": prompt_text(
            "pompstatus",
            "gedeactiveerd",
        ),
        "free_notes": prompt_text("overige notities", ""),
        "local_time": local_now_iso(),
    }


# ---------------------------------------------------------------------------
# Analysis summary
# ---------------------------------------------------------------------------

def analyse_records(records):
    rx_frames = [
        record
        for record in records
        if record.kind in ("rx_frame", "rx_echo_frame")
    ]

    error_frames = [
        record
        for record in records
        if record.kind == "rx_error_frame"
    ]

    status_frames = [
        record
        for record in records
        if record.kind == "rx_status_frame"
    ]

    read_status_records = [
        record
        for record in records
        if record.kind == "read_status"
    ]

    tx_records = [
        record
        for record in records
        if record.direction == "TX"
    ]

    print("\n" + "=" * 88)
    print("SESSION SUMMARY")
    print("=" * 88)
    print("RX normal/echo frames :", len(rx_frames))
    print("RX error frames       :", len(error_frames))
    print("RX status frames      :", len(status_frames))
    print("Read() status records :", len(read_status_records))
    print("TX attempts           :", len(tx_records))
    print("TX success/failure    : {}/{}".format(
        sum(1 for record in tx_records if record.tx_success),
        sum(1 for record in tx_records if not record.tx_success),
    ))

    print("\nPer phase:")
    phase_counts = defaultdict(Counter)

    for record in records:
        phase_counts[record.phase][record.kind] += 1

    for phase, counts in phase_counts.items():
        print("  {:<30} {}".format(
            phase,
            dict(counts),
        ))

    if error_frames:
        print("\nDecoded error frames:")

        for record in error_frames[:100]:
            print(
                "  hw_rel_us={} phase={} type={} dir={} pos={} "
                "REC={} TEC={} data={}".format(
                    record.hardware_rel_us,
                    record.phase,
                    record.error_type,
                    record.error_direction,
                    record.error_position_name,
                    record.rx_error_counter,
                    record.tx_error_counter,
                    record.data_hex,
                )
            )

        if len(error_frames) > 100:
            print("  ... {} meer".format(len(error_frames) - 100))

    timestamped_rx = [
        record
        for record in rx_frames
        if record.hardware_us not in (None, "")
    ]

    timestamped_rx.sort(key=lambda record: record.hardware_us)

    gaps_us = [
        current.hardware_us - previous.hardware_us
        for previous, current in zip(
            timestamped_rx,
            timestamped_rx[1:],
        )
    ]

    if gaps_us:
        ordered_gaps = sorted(gaps_us)

        print("\nHardware timestamp gaps, all RX frames:")
        print("  min/median/max [us]: {:.1f} / {:.1f} / {:.1f}".format(
            min(ordered_gaps),
            ordered_gaps[len(ordered_gaps) // 2],
            max(ordered_gaps),
        ))
        print("  gaps >20 ms :", sum(1 for gap in gaps_us if gap > 20_000))
        print("  gaps >500 ms:", sum(1 for gap in gaps_us if gap > 500_000))

    marker_counts = Counter(
        record.marker
        for record in rx_frames
        if record.marker is not None
    )

    print("\nDLC7 marker values:", {
        "0x{:02X}".format(key): value
        for key, value in sorted(marker_counts.items())
    })


# ---------------------------------------------------------------------------
# PCAN feature configuration
# ---------------------------------------------------------------------------

def try_set_value(
    api,
    channel,
    parameter_name,
    value_name,
    result_log,
):
    parameter = globals().get(parameter_name)
    value = globals().get(value_name)

    if parameter is None or value is None:
        result_log[parameter_name] = {
            "supported_by_wrapper": False,
            "status": None,
            "text": "constant unavailable",
        }
        return False

    try:
        status_raw = api.SetValue(
            channel,
            parameter,
            value,
        )
        status = pcan_int(status_raw)
    except Exception as exc:
        result_log[parameter_name] = {
            "supported_by_wrapper": True,
            "status": None,
            "text": "SetValue exception: {}".format(exc),
        }
        return False

    result_log[parameter_name] = {
        "supported_by_wrapper": True,
        "status": status,
        "text": (
            "OK"
            if status == PCAN_OK
            else error_text(api, status_raw)
        ),
    }

    return status == PCAN_OK


def initialise_pcan(api):
    print("\nPCAN-USB initialiseren: USB1, Classical CAN, 1 Mbit/s...")

    status_raw = api.Initialize(
        CHANNEL,
        BITRATE,
    )

    if not status_ok(
        api,
        status_raw,
        "Initialize",
    ):
        return False, {}

    settings = {}

    try_set_value(
        api,
        CHANNEL,
        "PCAN_ALLOW_ERROR_FRAMES",
        "PCAN_PARAMETER_ON",
        settings,
    )

    try_set_value(
        api,
        CHANNEL,
        "PCAN_ALLOW_STATUS_FRAMES",
        "PCAN_PARAMETER_ON",
        settings,
    )

    try_set_value(
        api,
        CHANNEL,
        "PCAN_ALLOW_ECHO_FRAMES",
        "PCAN_PARAMETER_ON",
        settings,
    )

    if (
        "PCAN_BUSOFF_AUTORESET" in globals()
        and "PCAN_PARAMETER_OFF" in globals()
    ):
        try_set_value(
            api,
            CHANNEL,
            "PCAN_BUSOFF_AUTORESET",
            "PCAN_PARAMETER_OFF",
            settings,
        )

    print("PCAN feature configuration:")

    for key, value in settings.items():
        print("  {:<28} {}".format(
            key,
            value["text"],
        ))

    return True, settings


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Complete DAB PCAN peer simulator and acquisition logger"
    )

    parser.add_argument(
        "--send",
        action="store_true",
        help="CAN daadwerkelijk verzenden; standaard is dry-run",
    )

    parser.add_argument(
        "--test",
        choices=[
            "baseline",
            "21",
            "22",
            "23",
            "24",
            "all",
        ],
        default="21",
    )

    parser.add_argument(
        "--output",
        default="pcan_peer_results",
    )

    parser.add_argument(
        "--pre-seconds",
        type=float,
        default=DEFAULT_PRE_SECONDS,
    )

    parser.add_argument(
        "--post-seconds",
        type=float,
        default=DEFAULT_POST_SECONDS,
    )

    parser.add_argument(
        "--baseline-seconds",
        type=float,
        default=DEFAULT_BASELINE_SECONDS,
    )

    parser.add_argument(
        "--test22-burst-seconds",
        type=float,
        default=DEFAULT_TEST22_BURST_SECONDS,
    )

    parser.add_argument(
        "--test22-post-seconds",
        type=float,
        default=DEFAULT_TEST22_POST_SECONDS,
    )

    parser.add_argument(
        "--test23-burst-seconds",
        type=float,
        default=DEFAULT_TEST23_BURST_SECONDS,
    )

    parser.add_argument(
        "--test23-post-seconds",
        type=float,
        default=DEFAULT_TEST23_POST_SECONDS,
    )

    parser.add_argument(
        "--test24-seconds",
        type=float,
        default=DEFAULT_TEST24_SECONDS,
    )

    parser.add_argument(
        "--test24-post-seconds",
        type=float,
        default=DEFAULT_TEST24_POST_SECONDS,
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="optionele reproduceerbare PRNG-seed",
    )

    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    session_name = "{}_{}".format(
        datetime.now().strftime("%Y%m%d_%H%M%S"),
        args.test,
    )

    output_dir = os.path.join(
        args.output,
        session_name,
    )

    os.makedirs(
        output_dir,
        exist_ok=True,
    )

    print("=" * 88)
    print("PCAN PEER SIMULATION — COMPLETE LOGGER")
    print("=" * 88)
    print("Output:", os.path.abspath(output_dir))
    print("TX mode:", "ENABLED" if args.send else "DRY-RUN")
    print("Test:", args.test)

    if args.send:
        print("\n*** REAL CAN TRANSMISSION IS ENABLED ***")
        confirmation = input("Typ ZENDEN om door te gaan: ").strip()

        if confirmation != "ZENDEN":
            print("Afgebroken.")
            return 1

    api = PCANBasic()

    initialised, pcan_settings = initialise_pcan(api)

    if not initialised:
        return 2

    recorder = ContinuousRecorder(
        api,
        CHANNEL,
    )

    transmitter = CanTransmitter(
        api,
        CHANNEL,
        recorder,
        enabled=args.send,
    )

    test_ranges = {}
    manual_notes = []

    metadata = {
        "script": os.path.basename(__file__),
        "script_version": "2026-09-25-complete-logger-v2",
        "started_utc": utc_now_iso(),
        "started_local": local_now_iso(),
        "channel": "PCAN_USBBUS1",
        "bitrate": 1_000_000,
        "can_mode": "Classical CAN, extended 29-bit TX",
        "send_enabled": args.send,
        "test": args.test,
        "arguments": vars(args),
        "pcan_settings": pcan_settings,
        "pair_gap_between_write_calls_us": PAIR_GAP_S * 1_000_000,
        "cycle_period_us": CYCLE_PERIOD_S * 1_000_000,
        "device": {
            "product": "DAB Active Driver Plus M/M 1.5",
            "software_version": "2.13",
        },
    }

    try:
        recorder.start()
        recorder.set_phase(
            "session_idle",
            "continuous RX active",
        )

        time.sleep(1.0)

        if args.test in ("baseline", "all"):
            test_ranges["baseline"] = run_baseline(
                recorder,
                args.baseline_seconds,
            )

            manual_notes.append(
                collect_manual_notes("baseline")
            )

        if args.test in ("21", "all"):
            test_ranges.update(
                run_test21(
                    recorder,
                    transmitter,
                    args,
                )
            )

            manual_notes.append(
                collect_manual_notes("test21")
            )

        if args.test in ("22", "all"):
            test_ranges.update(
                run_test22(
                    recorder,
                    transmitter,
                    args,
                )
            )

            manual_notes.append(
                collect_manual_notes("test22")
            )

        if args.test in ("23", "all"):
            test_ranges.update(
                run_test23(
                    recorder,
                    transmitter,
                    args,
                )
            )

            manual_notes.append(
                collect_manual_notes("test23")
            )

        if args.test in ("24", "all"):
            test_ranges.update(
                run_test24(
                    recorder,
                    transmitter,
                    args,
                )
            )

            manual_notes.append(
                collect_manual_notes("test24")
            )

    except KeyboardInterrupt:
        print("\nCtrl+C — test gestopt; RX wordt nog gedraind.")
        recorder.set_phase("aborted", "Ctrl+C")

    finally:
        recorder.set_phase(
            "shutdown",
            "final RX drain",
        )

        time.sleep(0.25)
        recorder.stop()

        records = list(recorder.records)
        phase_markers = list(recorder.phase_markers)

        write_records_csv(
            os.path.join(output_dir, "timeline_all.csv"),
            records,
        )

        write_split_csvs(
            output_dir,
            records,
        )

        write_phase_markers(
            os.path.join(output_dir, "phase_markers.csv"),
            phase_markers,
        )

        write_per_test_csvs(
            output_dir,
            records,
            test_ranges,
        )

        with open(
            os.path.join(output_dir, "manual_notes.json"),
            "w",
            encoding="utf-8",
        ) as handle:
            json.dump(
                manual_notes,
                handle,
                indent=2,
                ensure_ascii=False,
            )

        metadata.update({
            "finished_utc": utc_now_iso(),
            "finished_local": local_now_iso(),
            "total_records": len(records),
            "total_rx": recorder.total_rx,
            "max_queue_batch": recorder.max_queue_batch,
            "read_status_counts": {
                "0x{:08X}".format(pcan_int(key)): value
                for key, value in recorder.read_status_counts.items()
            },
            "tx_sent_ok": transmitter.sent_ok,
            "tx_sent_failed": transmitter.sent_failed,
        })

        with open(
            os.path.join(output_dir, "metadata.json"),
            "w",
            encoding="utf-8",
        ) as handle:
            json.dump(
                metadata,
                handle,
                indent=2,
                ensure_ascii=False,
            )

        analyse_records(records)

        print("\nPCAN-kanaal afsluiten...")

        status_raw = api.Uninitialize(CHANNEL)
        status = pcan_int(status_raw)

        if status != PCAN_OK:
            print("Uninitialize waarschuwing: 0x{:08X} {}".format(
                status,
                error_text(api, status_raw),
            ))

    print("\nBestanden geschreven:")

    for filename in sorted(os.listdir(output_dir)):
        print("  " + filename)

    print("\nUpload voor analyse bij voorkeur:")
    print("  timeline_all.csv")
    print("  phase_markers.csv")
    print("  metadata.json")
    print("  manual_notes.json")
    print("  bus_events.csv")

    return 0


if __name__ == "__main__":
    sys.exit(main())
