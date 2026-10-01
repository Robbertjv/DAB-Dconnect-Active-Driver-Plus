#!/usr/bin/env python3

"""
PCAN peer-simulatie / protocolonderzoek
=======================================

Windows 10
PEAK PCAN-USB
Classical CAN
Bitrate: 1 Mbit/s
Extended CAN IDs

Tests:
    baseline
    21 - Eén synthetisch framepaar
    22 - Korte startsequentie met vaste token
    23 - Afzonderlijke frametypes
    24 - Realistisch veranderende token

Belangrijke eigenschappen:
    - api.Reset(CHANNEL) vóór iedere capture
    - Capture wordt gestart vóór de eerste Write()
    - RX wordt tijdens bursts continu gelezen
    - RX gebruikt PCAN hardware timestamps
    - PCAN_ALLOW_ERROR_FRAMES wordt ingeschakeld
    - Error/statusframes worden opgeslagen
    - Iedere Write() wordt gelogd met tijdstip + returncode
    - RX en TX worden afzonderlijk naar CSV geschreven

Gebruik:

    Alleen baseline:
        python pcan_peer_tests_chatgpt.py --test baseline

    Test 21:
        python pcan_peer_tests_chatgpt.py --test 21 --send

    Test 22:
        python pcan_peer_tests_chatgpt.py --test 22 --send

    Test 23:
        python pcan_peer_tests_chatgpt.py --test 23 --send

    Test 24:
        python pcan_peer_tests_chatgpt.py --test 24 --send

    Alle tests:
        python pcan_peer_tests_chatgpt.py --test all --send

    Test 24 gedurende 30 seconden:
        python pcan_peer_tests_chatgpt.py --test 24 --test24-seconds 30 --send
"""

import argparse
import csv
import os
import platform
import random
import sys
import time
from collections import Counter
from dataclasses import dataclass


# ============================================================================
# PCAN-BASIC IMPORT
# ============================================================================

PCAN_MODULE_NAME = None

try:

    import pcan.PCANBasic as PCANBasicModule
    from pcan.PCANBasic import *

    PCAN_MODULE_NAME = "pcan.PCANBasic"

except ImportError:

    try:

        import PCANBasic as PCANBasicModule
        from PCANBasic import *

        PCAN_MODULE_NAME = "PCANBasic"

    except ImportError:

        print()
        print("=" * 78)
        print("FOUT: PCAN-Basic Python wrapper niet gevonden.")
        print("=" * 78)
        print()
        print("Controleer of PCANBasic.py beschikbaar is.")
        print()
        sys.exit(1)


# ============================================================================
# CONFIGURATIE
# ============================================================================

CHANNEL = PCAN_USBBUS1

# 1 Mbit/s
BITRATE = PCAN_BAUD_1M

# CAN-ID families
FAMILY_A = 0x00010000
FAMILY_B = 0x00110000

# Extended / 29-bit
MSG_TYPE = PCAN_MESSAGE_EXTENDED

# Baseline
BASELINE_SECONDS = 10.0

# Test 21
TEST21_OBSERVE_SECONDS = 10.0

# Test 22
TEST22_BURST_SECONDS = 1.0
TEST22_OBSERVE_SECONDS = 20.0

# Test 23
TEST23_BURST_SECONDS = 1.0

# Test 24
TEST24_DEFAULT_SECONDS = 1.0
TEST24_RATE_HZ = 200.0
TEST24_PERIOD_S = 1.0 / TEST24_RATE_HZ

# Gewenste tijd tussen DLC7 en DLC5
PAIR_GAP_S = 0.000114


# ============================================================================
# PCAN CONSTANT HELPERS
# ============================================================================

def pcan_error_ok():

    return globals().get(
        "PCAN_ERROR_OK",
        0,
    )


def pcan_error_qrcvempty():

    return globals().get(
        "PCAN_ERROR_QRCVEMPTY",
        0x00020,
    )


def pcan_message_errframe():

    return globals().get(
        "PCAN_MESSAGE_ERRFRAME",
        0x40,
    )


def pcan_parameter_on():

    return globals().get(
        "PCAN_PARAMETER_ON",
        1,
    )


def status_is_ok(status):

    return status == pcan_error_ok()


# ============================================================================
# OMGEVINGSINFORMATIE
# ============================================================================

def print_environment():

    print()
    print("=" * 78)
    print("PCAN / PYTHON OMGEVING")
    print("=" * 78)

    print(
        "Python:       {}".format(
            sys.version.replace("\n", " ")
        )
    )

    print(
        "Platform:     {}".format(
            platform.platform()
        )
    )

    print(
        "Executable:   {}".format(
            sys.executable
        )
    )

    print(
        "PCAN module:  {}".format(
            PCAN_MODULE_NAME
        )
    )

    print(
        "Module file:  {}".format(
            getattr(
                PCANBasicModule,
                "__file__",
                "onbekend",
            )
        )
    )

    module_version = getattr(
        PCANBasicModule,
        "__version__",
        None,
    )

    if module_version is None:

        module_version = getattr(
            PCANBasicModule,
            "VERSION",
            None,
        )

    print(
        "Module versie: {}".format(
            module_version
            if module_version is not None
            else "niet beschikbaar"
        )
    )

    print()

    print(
        "PCAN_MESSAGE_ERRFRAME: {}".format(
            globals().get(
                "PCAN_MESSAGE_ERRFRAME",
                "NIET BESCHIKBAAR",
            )
        )
    )

    print(
        "PCAN_ALLOW_ERROR_FRAMES: {}".format(
            globals().get(
                "PCAN_ALLOW_ERROR_FRAMES",
                "NIET BESCHIKBAAR",
            )
        )
    )

    print(
        "PCAN_PARAMETER_ON: {}".format(
            globals().get(
                "PCAN_PARAMETER_ON",
                "NIET BESCHIKBAAR",
            )
        )
    )

    print()


# ============================================================================
# PCAN ERROR TEXT
# ============================================================================

def error_text(api, status):

    try:

        result = api.GetErrorText(
            status,
            0,
        )

        if isinstance(result, tuple):

            if len(result) >= 2:
                return str(result[1])

            return str(result)

        return str(result)

    except Exception as exc:

        return (
            "geen errortekst beschikbaar ({})".format(
                exc
            )
        )


# ============================================================================
# VEILIGE CONVERSIE VAN PCAN DATA
# ============================================================================

def value_to_byte(value):

    """
    Converteert één DATA[] element naar 0..255.

    Belangrijk voor oudere PCANBasic.py wrappers.

    Sommige wrappers geven:
        64

    andere:
        c_ubyte(64)

    en jouw wrapper kan ook geven:
        b'@'

    Daarom wordt alles hier expliciet afgehandeld.
    """

    if isinstance(value, int):

        return value & 0xFF

    if isinstance(value, bytes):

        if len(value) == 0:
            return 0

        if len(value) == 1:
            return value[0]

        return int.from_bytes(
            value,
            byteorder="little",
        ) & 0xFF

    if isinstance(
        value,
        (
            bytearray,
            memoryview,
        ),
    ):

        raw = bytes(value)

        if len(raw) == 0:
            return 0

        if len(raw) == 1:
            return raw[0]

        return int.from_bytes(
            raw,
            byteorder="little",
        ) & 0xFF

    # ctypes c_ubyte e.d.
    try:

        return int(value) & 0xFF

    except Exception:

        pass

    # Laatste poging: bytes()
    try:

        raw = bytes(value)

        if len(raw) == 1:
            return raw[0]

        return int.from_bytes(
            raw,
            byteorder="little",
        ) & 0xFF

    except Exception:

        raise ValueError(
            "Kan PCAN DATA waarde niet converteren: {!r}".format(
                value
            )
        )


def message_data_bytes(msg):

    dlc = int(msg.LEN)

    result = []

    for i in range(dlc):

        result.append(
            value_to_byte(
                msg.DATA[i]
            )
        )

    return bytes(result)


# ============================================================================
# TIMESTAMPS
# ============================================================================

def pcan_timestamp_us(timestamp):

    """
    PCAN hardware timestamp.

    PCAN timestamp:
        micros
        millis
        millis_overflow
    """

    return (
        int(timestamp.micros)
        + (
            1000
            * int(timestamp.millis)
        )
        + (
            0x100000000
            * 1000
            * int(timestamp.millis_overflow)
        )
    )


def local_timestamp_us():

    """
    Alleen voor TX logging.

    RX gebruikt PCAN hardware timestamp.
    """

    return (
        time.perf_counter_ns()
        // 1000
    )


# ============================================================================
# DATASTRUCTUREN
# ============================================================================

@dataclass
class RxRecord:

    hardware_timestamp_us: int
    can_id: int
    dlc: int
    data: bytes
    msg_type: int
    status: int
    is_error: bool


@dataclass
class TxRecord:

    local_write_timestamp_us: int
    can_id: int
    dlc: int
    data: bytes
    msg_type: int
    return_code: int


# ============================================================================
# CAN FRAME CONSTRUCTIE
# ============================================================================

def token_bytes(token):

    return [
        token & 0xFF,
        (token >> 8) & 0xFF,
    ]


def make_can_id(
    family,
    token,
):

    return (
        family
        | (token & 0xFFFF)
    )


def make_frame(
    can_id,
    data,
):

    msg = TPCANMsg()

    msg.ID = int(can_id)

    msg.MSGTYPE = MSG_TYPE

    msg.LEN = len(data)

    for index, value in enumerate(data):

        msg.DATA[index] = int(value)

    return msg


def frame_dlc7(
    token,
    start_marker=False,
):

    lo, hi = token_bytes(
        token
    )

    marker = (
        0x00
        if start_marker
        else 0x03
    )

    return make_frame(
        make_can_id(
            FAMILY_A,
            token,
        ),
        [
            0x01,
            0x00,
            0x00,
            0x0F,
            marker,
            lo,
            hi,
        ],
    )


def frame_dlc5(token):

    lo, hi = token_bytes(
        token
    )

    return make_frame(
        make_can_id(
            FAMILY_B,
            token,
        ),
        [
            0x01,
            0x00,
            0x00,
            lo,
            hi,
        ],
    )


# ============================================================================
# RX CAPTURE
# ============================================================================

class Capture:

    def __init__(
        self,
        api,
        channel,
        name,
    ):

        self.api = api
        self.channel = channel
        self.name = name

        self.records = []

        self.rx_calls = 0

        self.error_records = 0

    def read_available(self):

        """
        Lees alle beschikbare frames uit de PCAN queue.

        Deze functie wordt tijdens bursts voortdurend
        aangeroepen.
        """

        self.rx_calls += 1

        while True:

            try:

                result = self.api.Read(
                    self.channel
                )

            except Exception as exc:

                print(
                    "[RX EXCEPTION] {}".format(
                        exc
                    )
                )

                break

            if not isinstance(
                result,
                tuple,
            ):

                print(
                    "[RX] Onverwachte Read()-return: {}".format(
                        result
                    )
                )

                break

            status = result[0]

            # Queue leeg.
            if status == pcan_error_qrcvempty():

                break

            # PCAN status/error.
            if not status_is_ok(
                status
            ):

                self.records.append(
                    RxRecord(
                        hardware_timestamp_us=-1,
                        can_id=0,
                        dlc=0,
                        data=b"",
                        msg_type=0,
                        status=int(status),
                        is_error=True,
                    )
                )

                self.error_records += 1

                print(
                    "[RX STATUS] "
                    "0x{:08X} {}".format(
                        int(status),
                        error_text(
                            self.api,
                            status,
                        ),
                    )
                )

                continue

            if len(result) < 3:

                print(
                    "[RX] Read() gaf minder dan 3 waarden."
                )

                break

            msg = result[1]

            timestamp = result[2]

            # --------------------------------------------------------------
            # Hardware timestamp
            # --------------------------------------------------------------

            try:

                timestamp_us = (
                    pcan_timestamp_us(
                        timestamp
                    )
                )

            except Exception as exc:

                print(
                    "[RX] Timestamp fout: {}".format(
                        exc
                    )
                )

                timestamp_us = -1

            # --------------------------------------------------------------
            # CAN ID
            # --------------------------------------------------------------

            try:

                can_id = int(
                    msg.ID
                )

            except Exception:

                try:

                    can_id = int.from_bytes(
                        bytes(msg.ID),
                        byteorder="little",
                    )

                except Exception:

                    can_id = 0

            # --------------------------------------------------------------
            # DLC
            # --------------------------------------------------------------

            try:

                dlc = int(
                    msg.LEN
                )

            except Exception:

                dlc = 0

            # --------------------------------------------------------------
            # MSGTYPE
            # --------------------------------------------------------------

            try:

                msg_type = int(
                    msg.MSGTYPE
                )

            except Exception:

                try:

                    msg_type = int.from_bytes(
                        bytes(msg.MSGTYPE),
                        byteorder="little",
                    )

                except Exception:

                    msg_type = 0

            # --------------------------------------------------------------
            # DATA
            # --------------------------------------------------------------

            try:

                data = message_data_bytes(
                    msg
                )

            except Exception as exc:

                print(
                    "[RX DATA ERROR] {}".format(
                        exc
                    )
                )

                # We slaan het frame niet stilletjes
                # over. Het wordt als errorrecord
                # vastgelegd.
                self.records.append(
                    RxRecord(
                        hardware_timestamp_us=timestamp_us,
                        can_id=can_id,
                        dlc=dlc,
                        data=b"",
                        msg_type=msg_type,
                        status=int(status),
                        is_error=True,
                    )
                )

                self.error_records += 1

                continue

            # --------------------------------------------------------------
            # Error frame
            # --------------------------------------------------------------

            is_error = bool(
                msg_type
                & int(
                    pcan_message_errframe()
                )
            )

            if is_error:

                self.error_records += 1

            # --------------------------------------------------------------
            # Opslaan
            # --------------------------------------------------------------

            self.records.append(
                RxRecord(
                    hardware_timestamp_us=timestamp_us,
                    can_id=can_id,
                    dlc=dlc,
                    data=data,
                    msg_type=msg_type,
                    status=int(status),
                    is_error=is_error,
                )
            )

    def run(
        self,
        seconds,
        poll_interval_s=0.00005,
    ):

        start = time.perf_counter()

        while True:

            # Tijdens de gehele capture lezen.
            self.read_available()

            now = time.perf_counter()

            if (
                now - start
                >= seconds
            ):

                break

            time.sleep(
                poll_interval_s
            )

        # Laatste queue drain.
        self.read_available()


# ============================================================================
# TX
# ============================================================================

class CanTransmitter:

    def __init__(
        self,
        api,
        channel,
        enabled,
    ):

        self.api = api
        self.channel = channel
        self.enabled = enabled

        self.tx_records = []

    def clear_log(self):

        self.tx_records.clear()

    def send(
        self,
        msg,
        description="",
    ):

        write_timestamp = (
            local_timestamp_us()
        )

        data = message_data_bytes(
            msg
        )

        # --------------------------------------------------------------
        # DRY RUN
        # --------------------------------------------------------------

        if not self.enabled:

            return_code = (
                pcan_error_ok()
            )

            self.tx_records.append(
                TxRecord(
                    local_write_timestamp_us=(
                        write_timestamp
                    ),
                    can_id=int(
                        msg.ID
                    ),
                    dlc=int(
                        msg.LEN
                    ),
                    data=data,
                    msg_type=int(
                        msg.MSGTYPE
                    ),
                    return_code=int(
                        return_code
                    ),
                )
            )

            print(
                "[DRY-RUN TX] "
                "t={} "
                "ID={:08X} "
                "DLC={} "
                "DATA={} "
                "RC=0x{:08X} "
                "{}".format(
                    write_timestamp,
                    int(msg.ID),
                    int(msg.LEN),
                    " ".join(
                        "{:02X}".format(x)
                        for x in data
                    ),
                    int(return_code),
                    description,
                )
            )

            return True

        # --------------------------------------------------------------
        # ECHTE WRITE
        # --------------------------------------------------------------

        try:

            return_code = self.api.Write(
                self.channel,
                msg,
            )

        except Exception as exc:

            print(
                "[TX EXCEPTION] {}".format(
                    exc
                )
            )

            return_code = 0xFFFFFFFF

        self.tx_records.append(
            TxRecord(
                local_write_timestamp_us=(
                    write_timestamp
                ),
                can_id=int(
                    msg.ID
                ),
                dlc=int(
                    msg.LEN
                ),
                data=data,
                msg_type=int(
                    msg.MSGTYPE
                ),
                return_code=int(
                    return_code
                ),
            )
        )

        print(
            "[TX] "
            "t={} "
            "ID={:08X} "
            "DLC={} "
            "DATA={} "
            "RC=0x{:08X} "
            "{}".format(
                write_timestamp,
                int(msg.ID),
                int(msg.LEN),
                " ".join(
                    "{:02X}".format(x)
                    for x in data
                ),
                int(return_code),
                description,
            )
        )

        if not status_is_ok(
            return_code
        ):

            print(
                "[TX ERROR] {}".format(
                    error_text(
                        self.api,
                        return_code,
                    )
                )
            )

            return False

        return True

    def send_pair(
        self,
        token,
        start_marker=False,
    ):

        msg_a = frame_dlc7(
            token,
            start_marker=start_marker,
        )

        msg_b = frame_dlc5(
            token
        )

        # Eerst DLC7.
        ok = self.send(
            msg_a,
            (
                "DLC7/START"
                if start_marker
                else "DLC7"
            ),
        )

        if not ok:

            return False

        # Zo goed mogelijk richting 114 us.
        target = (
            time.perf_counter()
            + PAIR_GAP_S
        )

        spin_wait_until(
            target
        )

        # Daarna DLC5.
        ok = self.send(
            msg_b,
            "DLC5",
        )

        return ok


# ============================================================================
# HIGH RESOLUTION WAIT
# ============================================================================

def spin_wait_until(target):

    while True:

        remaining = (
            target
            - time.perf_counter()
        )

        if remaining <= 0:

            return

        if remaining > 0.001:

            time.sleep(
                remaining / 2
            )


# ============================================================================
# ERROR FRAMES INSCHAKELEN
# ============================================================================

def enable_error_frames(
    api,
    channel,
):

    parameter = globals().get(
        "PCAN_ALLOW_ERROR_FRAMES",
        None,
    )

    if parameter is None:

        print(
            "WAARSCHUWING: "
            "PCAN_ALLOW_ERROR_FRAMES bestaat niet "
            "in deze Python-wrapper."
        )

        return False

    status = api.SetValue(
        channel,
        parameter,
        pcan_parameter_on(),
    )

    if not status_is_ok(
        status
    ):

        print(
            "WAARSCHUWING: "
            "PCAN_ALLOW_ERROR_FRAMES kon niet "
            "worden ingesteld."
        )

        print(
            "Status: 0x{:08X} {}".format(
                int(status),
                error_text(
                    api,
                    status,
                ),
            )
        )

        return False

    print(
        "PCAN_ALLOW_ERROR_FRAMES = ON"
    )

    return True


# ============================================================================
# PCAN INITIALISATIE
# ============================================================================

def initialize_pcan(api):

    print()
    print("=" * 78)
    print("PCAN INITIALISEREN")
    print("=" * 78)

    print(
        "Kanaal:  PCAN_USBBUS1"
    )

    print(
        "Bitrate: 1 Mbit/s"
    )

    print(
        "CAN:     Extended / 29-bit"
    )

    status = api.Initialize(
        CHANNEL,
        BITRATE,
    )

    if not status_is_ok(
        status
    ):

        print(
            "Initialize mislukt: "
            "0x{:08X} {}".format(
                int(status),
                error_text(
                    api,
                    status,
                ),
            )
        )

        return False

    enable_error_frames(
        api,
        CHANNEL,
    )

    return True


# ============================================================================
# RESET
# ============================================================================

def reset_channel(
    api,
    channel,
    name,
):

    print()

    print(
        "PCAN Reset() vóór capture: {}".format(
            name
        )
    )

    status = api.Reset(
        channel
    )

    if not status_is_ok(
        status
    ):

        print(
            "Reset mislukt: "
            "0x{:08X} {}".format(
                int(status),
                error_text(
                    api,
                    status,
                ),
            )
        )

        return False

    return True


# ============================================================================
# CAPTURE ARM
# ============================================================================

def arm_capture(
    api,
    channel,
    name,
):

    if not reset_channel(
        api,
        channel,
        name,
    ):

        return None

    capture = Capture(
        api,
        channel,
        name,
    )

    # Queue direct na Reset legen/lezen.
    capture.read_available()

    print(
        "CAPTURE GEARMED: {}".format(
            name
        )
    )

    return capture


# ============================================================================
# CSV OUTPUT
# ============================================================================

def write_rx_csv(
    capture,
    filename,
):

    with open(
        filename,
        "w",
        newline="",
        encoding="utf-8",
    ) as f:

        writer = csv.writer(f)

        writer.writerow([
            "hardware_timestamp_us",
            "can_id_hex",
            "can_id_decimal",
            "dlc",
            "data_hex",
            "msg_type_hex",
            "status_hex",
            "is_error",
        ])

        for r in capture.records:

            writer.writerow([
                r.hardware_timestamp_us,
                "{:08X}".format(
                    r.can_id
                ),
                r.can_id,
                r.dlc,
                " ".join(
                    "{:02X}".format(x)
                    for x in r.data
                ),
                "0x{:02X}".format(
                    r.msg_type
                ),
                "0x{:08X}".format(
                    r.status
                ),
                int(r.is_error),
            ])


def write_tx_csv(
    transmitter,
    filename,
):

    with open(
        filename,
        "w",
        newline="",
        encoding="utf-8",
    ) as f:

        writer = csv.writer(f)

        writer.writerow([
            "local_write_timestamp_us",
            "can_id_hex",
            "can_id_decimal",
            "dlc",
            "data_hex",
            "msg_type_hex",
            "return_code_hex",
        ])

        for r in transmitter.tx_records:

            writer.writerow([
                r.local_write_timestamp_us,
                "{:08X}".format(
                    r.can_id
                ),
                r.can_id,
                r.dlc,
                " ".join(
                    "{:02X}".format(x)
                    for x in r.data
                ),
                "0x{:02X}".format(
                    r.msg_type
                ),
                "0x{:08X}".format(
                    r.return_code
                ),
            ])


# ============================================================================
# CAPTURE SAMENVATTING
# ============================================================================

def summarize_capture(
    capture,
    name,
):

    print()
    print("=" * 78)

    print(
        "RX SAMENVATTING: {}".format(
            name
        )
    )

    print("=" * 78)

    print(
        "Records:       {}".format(
            len(capture.records)
        )
    )

    print(
        "Error/status:  {}".format(
            capture.error_records
        )
    )

    normal = [
        r
        for r in capture.records
        if not r.is_error
        and status_is_ok(
            r.status
        )
    ]

    if not normal:

        print(
            "Geen normale CAN-frames ontvangen."
        )

        return

    valid_timestamps = [
        r.hardware_timestamp_us
        for r in normal
        if r.hardware_timestamp_us >= 0
    ]

    if valid_timestamps:

        duration_s = max(
            (
                max(valid_timestamps)
                - min(valid_timestamps)
            ) / 1_000_000.0,
            0.000001,
        )

    else:

        duration_s = 0.000001

    print(
        "Normale CAN frames: {}".format(
            len(normal)
        )
    )

    print(
        "Hardware timestamp span: {:.6f} s".format(
            duration_s
        )
    )

    counts = Counter(
        r.can_id
        for r in normal
    )

    print()

    print(
        "{:<12} {:>10} {:>12} {:>8} {}".format(
            "CAN-ID",
            "count",
            "Hz",
            "DLC",
            "eerste DATA",
        )
    )

    print("-" * 78)

    for can_id, count in sorted(
        counts.items()
    ):

        records = [
            r
            for r in normal
            if r.can_id == can_id
        ]

        frequency = (
            count
            / duration_s
        )

        dlcs = sorted(
            set(
                r.dlc
                for r in records
            )
        )

        example = " ".join(
            "{:02X}".format(x)
            for x in records[0].data
        )

        print(
            "{:<12} {:>10} {:>12.3f} {:>8} {}".format(
                "{:08X}".format(
                    can_id
                ),
                count,
                frequency,
                ",".join(
                    str(x)
                    for x in dlcs
                ),
                example,
            )
        )


# ============================================================================
# BASELINE
# ============================================================================

def run_baseline(
    api,
    channel,
    tx,
    output_dir,
):

    print()
    print("=" * 78)
    print("BASELINE")
    print("=" * 78)

    print()
    print("Noteer vooraf:")

    print()

    print(
        "  SP = __________________"
    )

    print(
        "  RP = __________________"
    )

    print(
        "  AD = __________________"
    )

    print(
        "  NA = __________________"
    )

    print(
        "  NC = __________________"
    )

    print(
        "  IC = __________________"
    )

    print(
        "  N  = __________________"
    )

    print()

    input(
        "ENTER = baseline capture starten..."
    )

    tx.clear_log()

    capture = arm_capture(
        api,
        channel,
        "baseline",
    )

    if capture is None:

        return

    capture.run(
        BASELINE_SECONDS
    )

    rx_file = os.path.join(
        output_dir,
        "baseline_rx.csv",
    )

    tx_file = os.path.join(
        output_dir,
        "baseline_tx.csv",
    )

    write_rx_csv(
        capture,
        rx_file,
    )

    write_tx_csv(
        tx,
        tx_file,
    )

    summarize_capture(
        capture,
        "baseline",
    )

    print()

    print(
        "Baseline opgeslagen:"
    )

    print(
        rx_file
    )


# ============================================================================
# TEST 21
# ============================================================================

def test21(
    api,
    channel,
    tx,
    output_dir,
):

    print()
    print("=" * 78)
    print("TEST 21 - ÉÉN SYNTHETISCH FRAMEPAAR")
    print("=" * 78)

    # ------------------------------------------------------------------------
    # DEEL 1: STARTMARKER
    # ------------------------------------------------------------------------

    print()

    print(
        "Deel 1:"
    )

    print(
        "00011234  7  01 00 00 0F 00 34 12"
    )

    print(
        "00111234  5  01 00 00 34 12"
    )

    input(
        "ENTER = Reset + capture + injectie..."
    )

    tx.clear_log()

    capture = arm_capture(
        api,
        channel,
        "test21_startmarker",
    )

    if capture is None:

        return

    # Capture staat nu al aan.
    tx.send_pair(
        0x1234,
        start_marker=True,
    )

    # Daarna 10 seconden niets sturen.
    capture.run(
        TEST21_OBSERVE_SECONDS
    )

    write_rx_csv(
        capture,
        os.path.join(
            output_dir,
            "test21_startmarker_rx.csv",
        ),
    )

    write_tx_csv(
        tx,
        os.path.join(
            output_dir,
            "test21_startmarker_tx.csv",
        ),
    )

    summarize_capture(
        capture,
        "test21_startmarker",
    )

    # ------------------------------------------------------------------------
    # DEEL 2: NORMAAL PAAR
    # ------------------------------------------------------------------------

    print()

    print(
        "Deel 2:"
    )

    print(
        "00011234  7  01 00 00 0F 03 34 12"
    )

    print(
        "00111234  5  01 00 00 34 12"
    )

    input(
        "ENTER = nieuwe Reset + capture + injectie..."
    )

    tx.clear_log()

    capture = arm_capture(
        api,
        channel,
        "test21_normal",
    )

    if capture is None:

        return

    tx.send_pair(
        0x1234,
        start_marker=False,
    )

    capture.run(
        TEST21_OBSERVE_SECONDS
    )

    write_rx_csv(
        capture,
        os.path.join(
            output_dir,
            "test21_normal_rx.csv",
        ),
    )

    write_tx_csv(
        tx,
        os.path.join(
            output_dir,
            "test21_normal_tx.csv",
        ),
    )

    summarize_capture(
        capture,
        "test21_normal",
    )


# ============================================================================
# TEST 22
# ============================================================================

def test22(
    api,
    channel,
    tx,
    output_dir,
):

    print()
    print("=" * 78)
    print("TEST 22 - KORTE STARTSEQUENTIE")
    print("=" * 78)

    input(
        "ENTER = Reset + capture + directe start..."
    )

    tx.clear_log()

    capture = arm_capture(
        api,
        channel,
        "test22",
    )

    if capture is None:

        return

    # Eén startmarker.
    tx.send_pair(
        0x1234,
        start_marker=True,
    )

    start = time.perf_counter()

    next_cycle = start

    sent = 0

    while (
        time.perf_counter()
        - start
        < TEST22_BURST_SECONDS
    ):

        # RX blijven lezen.
        capture.read_available()

        now = time.perf_counter()

        if now < next_cycle:

            time.sleep(
                min(
                    next_cycle - now,
                    0.001,
                )
            )

            continue

        tx.send_pair(
            0x1234,
            start_marker=False,
        )

        sent += 1

        next_cycle += (
            TEST24_PERIOD_S
        )

    capture.read_available()

    print()

    print(
        "Test 22 burst: {} normale paren.".format(
            sent
        )
    )

    print(
        "Nu 20 seconden alleen RX..."
    )

    capture.run(
        TEST22_OBSERVE_SECONDS
    )

    write_rx_csv(
        capture,
        os.path.join(
            output_dir,
            "test22_rx.csv",
        ),
    )

    write_tx_csv(
        tx,
        os.path.join(
            output_dir,
            "test22_tx.csv",
        ),
    )

    summarize_capture(
        capture,
        "test22",
    )


# ============================================================================
# TEST 23
# ============================================================================

def test23_mode(
    api,
    channel,
    tx,
    output_dir,
    mode,
):

    print()

    print(
        "-" * 78
    )

    print(
        "TEST 23: {}".format(
            mode
        )
    )

    print(
        "-" * 78
    )

    input(
        "ENTER = Reset + capture + burst..."
    )

    tx.clear_log()

    name = (
        "test23_{}".format(
            mode
        )
    )

    capture = arm_capture(
        api,
        channel,
        name,
    )

    if capture is None:

        return

    start = time.perf_counter()

    next_cycle = start

    while (
        time.perf_counter()
        - start
        < TEST23_BURST_SECONDS
    ):

        # RX tijdens burst.
        capture.read_available()

        now = time.perf_counter()

        if now < next_cycle:

            time.sleep(
                min(
                    next_cycle - now,
                    0.001,
                )
            )

            continue

        token = 0x1234

        if mode == "dlc7":

            tx.send(
                frame_dlc7(
                    token,
                    start_marker=False,
                ),
                "DLC7",
            )

        elif mode == "dlc5":

            tx.send(
                frame_dlc5(
                    token
                ),
                "DLC5",
            )

        elif mode == "pair":

            tx.send_pair(
                token,
                start_marker=False,
            )

        next_cycle += (
            TEST24_PERIOD_S
        )

        if (
            time.perf_counter()
            > next_cycle
        ):

            next_cycle = (
                time.perf_counter()
            )

    capture.read_available()

    write_rx_csv(
        capture,
        os.path.join(
            output_dir,
            "{}_rx.csv".format(
                name
            ),
        ),
    )

    write_tx_csv(
        tx,
        os.path.join(
            output_dir,
            "{}_tx.csv".format(
                name
            ),
        ),
    )

    summarize_capture(
        capture,
        name,
    )


def test23(
    api,
    channel,
    tx,
    output_dir,
):

    print()
    print("=" * 78)
    print("TEST 23 - AFZONDERLIJKE FRAMETYPES")
    print("=" * 78)

    for mode in (
        "dlc7",
        "dlc5",
        "pair",
    ):

        test23_mode(
            api,
            channel,
            tx,
            output_dir,
            mode,
        )

        print()

        print(
            "Controleer N, "
            "communicatiepictogram, "
            "adres/E, "
            "meldingen en FF."
        )


# ============================================================================
# TEST 24
# ============================================================================

def test24(
    api,
    channel,
    tx,
    output_dir,
    seconds,
):

    print()
    print("=" * 78)
    print("TEST 24 - REALISTISCH VERANDERENDE TOKEN")
    print("=" * 78)

    print(
        "Duur: {:.3f} s".format(
            seconds
        )
    )

    print(
        "Rate: 200 Hz"
    )

    print(
        "Periode: 5 ms"
    )

    print(
        "DLC7 -> ~114 us -> DLC5"
    )

    input(
        "ENTER = Reset + capture + directe start..."
    )

    tx.clear_log()

    capture = arm_capture(
        api,
        channel,
        "test24",
    )

    if capture is None:

        return

    # ------------------------------------------------------------------------
    # STARTMARKER
    # ------------------------------------------------------------------------

    start_token = random.randint(
        0x0000,
        0xFFFF,
    )

    print()

    print(
        "Starttoken: {:04X}".format(
            start_token
        )
    )

    tx.send_pair(
        start_token,
        start_marker=True,
    )

    # ------------------------------------------------------------------------
    # 200 Hz
    # ------------------------------------------------------------------------

    start = time.perf_counter()

    next_cycle = start

    sent = 0

    while (
        time.perf_counter()
        - start
        < seconds
    ):

        # RX voortdurend blijven lezen.
        capture.read_available()

        now = time.perf_counter()

        if now < next_cycle:

            time.sleep(
                min(
                    next_cycle - now,
                    0.001,
                )
            )

            continue

        token = random.randint(
            0x0000,
            0xFFFF,
        )

        tx.send_pair(
            token,
            start_marker=False,
        )

        sent += 1

        next_cycle += (
            TEST24_PERIOD_S
        )

        # Voorkom dat Windows scheduling
        # meerdere paren tegelijk veroorzaakt.
        if (
            time.perf_counter()
            > next_cycle
        ):

            next_cycle = (
                time.perf_counter()
            )

    capture.read_available()

    write_rx_csv(
        capture,
        os.path.join(
            output_dir,
            "test24_rx.csv",
        ),
    )

    write_tx_csv(
        tx,
        os.path.join(
            output_dir,
            "test24_tx.csv",
        ),
    )

    summarize_capture(
        capture,
        "test24",
    )

    print()

    print(
        "Verzonden normale paren: {}".format(
            sent
        )
    )


# ============================================================================
# MAIN
# ============================================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "PCAN peer tests 21-24"
        )
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
        default="all",
    )

    parser.add_argument(
        "--send",
        action="store_true",
        help=(
            "Werkelijk CAN frames verzenden."
        ),
    )

    parser.add_argument(
        "--test24-seconds",
        type=float,
        default=TEST24_DEFAULT_SECONDS,
    )

    parser.add_argument(
        "--output",
        default="pcan_test_results",
    )

    args = parser.parse_args()

    os.makedirs(
        args.output,
        exist_ok=True,
    )

    # ------------------------------------------------------------------------
    # Omgeving
    # ------------------------------------------------------------------------

    print_environment()

    print(
        "Output:       {}".format(
            os.path.abspath(
                args.output
            )
        )
    )

    print(
        "Kanaal:       PCAN_USBBUS1"
    )

    print(
        "Bitrate:      1 Mbit/s"
    )

    print(
        "CAN ID type:  Extended / 29-bit"
    )

    if args.send:

        print()

        print(
            "*** ECHTE CAN TRANSMISSIE INGESCHAKELD ***"
        )

    else:

        print()

        print(
            "*** DRY-RUN: GEEN FRAMES WORDEN VERZONDEN ***"
        )

        print(
            "Gebruik --send om daadwerkelijk te zenden."
        )

    # ------------------------------------------------------------------------
    # PCAN
    # ------------------------------------------------------------------------

    api = PCANBasic()

    if not initialize_pcan(
        api
    ):

        sys.exit(2)

    tx = CanTransmitter(
        api,
        CHANNEL,
        args.send,
    )

    try:

        if args.test in (
            "baseline",
            "all",
        ):

            run_baseline(
                api,
                CHANNEL,
                tx,
                args.output,
            )

        if args.test in (
            "21",
            "all",
        ):

            test21(
                api,
                CHANNEL,
                tx,
                args.output,
            )

        if args.test in (
            "22",
            "all",
        ):

            test22(
                api,
                CHANNEL,
                tx,
                args.output,
            )

        if args.test in (
            "23",
            "all",
        ):

            test23(
                api,
                CHANNEL,
                tx,
                args.output,
            )

        if args.test in (
            "24",
            "all",
        ):

            test24(
                api,
                CHANNEL,
                tx,
                args.output,
                args.test24_seconds,
            )

    except KeyboardInterrupt:

        print()
        print()
        print(
            "CTRL+C: test afgebroken."
        )

    except Exception as exc:

        print()
        print("=" * 78)
        print("ONVERWACHTE FOUT")
        print("=" * 78)
        print(
            repr(exc)
        )

    finally:

        print()
        print(
            "PCAN kanaal afsluiten..."
        )

        try:

            status = api.Uninitialize(
                CHANNEL
            )

            if status != PCAN_ERROR_OK:

                print(
                    "Uninitialize: "
                    "0x{:08X} {}".format(
                        int(status),
                        error_text(
                            api,
                            status,
                        ),
                    )
                )

            else:

                print(
                    "PCAN kanaal afgesloten."
                )

        except Exception as exc:

            print(
                "Fout tijdens Uninitialize: {}".format(
                    exc
                )
            )

    print()
    print("=" * 78)
    print("KLAAR")
    print("=" * 78)

    print()

    print(
        "Resultaten:"
    )

    print(
        os.path.abspath(
            args.output
        )
    )


if __name__ == "__main__":

    main()
