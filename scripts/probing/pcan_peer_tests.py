#!/usr/bin/env python3
"""
PCAN peer-simulatie - Test 21 t/m 24

Hardware:
    PEAK PCAN-USB
    Windows 10
    Classical CAN, extended 29-bit identifiers

De tests:
    21 - Een synthetisch framepaar
    22 - Korte startsequentie met vaste token
    23 - Afzonderlijke frametypes
    24 - Realistisch veranderende token, 200 Hz

BELANGRIJK:
    Zenden staat standaard UIT.
    Gebruik expliciet --send om CAN-frames te verzenden.

De ontvangen CAN-frames worden tijdens iedere test opgeslagen als CSV.
Daarnaast wordt een samenvatting gemaakt van:
    - ontvangen CAN-ID's
    - aantallen
    - gemiddelde frequentie
    - eerste/laatste ontvangst
    - DLC
    - data

De scriptresultaten kunnen N/SP/RP/AD/NA/NC/IC op het apparaat
niet rechtstreeks uitlezen. Noteer die waarden daarom vooraf zelf.
"""

import argparse
import csv
import os
import random
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime


# ---------------------------------------------------------------------------
# PCAN-Basic import
# ---------------------------------------------------------------------------

try:
    from pcan.PCANBasic import *
except ImportError:
    try:
        from PCANBasic import *
    except ImportError:
        print()
        print("FOUT: PCANBasic.py kan niet worden geïmporteerd.")
        print()
        print("Zorg dat de PEAK PCAN-Basic Python wrapper beschikbaar is,")
        print("bijvoorbeeld naast dit script.")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Configuratie
# ---------------------------------------------------------------------------

CHANNEL = PCAN_USBBUS1

# Pas dit aan wanneer de CAN-bus een andere bitrate gebruikt.
# Veel klassieke CAN-systemen gebruiken 500 kbit/s, maar dit moet
# overeenkomen met het bestaande systeem.
# BITRATE = PCAN_BAUD_500K
BITRATE = PCAN_BAUD_1M

# De twee CAN-ID-families uit de opgegeven voorbeelden.
FAMILY_A = 0x00010000
FAMILY_B = 0x00110000

# 29-bit extended CAN
MSG_TYPE = PCAN_MESSAGE_EXTENDED

# Testtijden
BASELINE_SECONDS = 10.0
OBSERVE_AFTER_SINGLE_PAIR = 10.0
TEST22_BURST_SECONDS = 1.0
TEST22_OBSERVE_SECONDS = 20.0
TEST23_BURST_SECONDS = 1.0
TEST24_INITIAL_SECONDS = 1.0

# Test 24
TEST24_RATE_HZ = 200.0
TEST24_PERIOD_S = 1.0 / TEST24_RATE_HZ       # 5 ms
PAIR_GAP_S = 0.000114                       # 0,114 ms


# ---------------------------------------------------------------------------
# Hulpfuncties
# ---------------------------------------------------------------------------

def now_string():
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def error_text(api, status):
    """Maak PCAN-foutstatus leesbaar, ongeacht wrappervariant."""
    try:
        result = api.GetErrorText(status, 0)
    except TypeError:
        try:
            result = api.GetErrorText(status)
        except Exception:
            return "PCAN error 0x%08X" % int(status)

    if isinstance(result, tuple):
        if len(result) >= 2:
            return str(result[1])
        return str(result)

    return str(result)


def check_status(api, status, operation):
    if status != PCAN_ERROR_OK:
        print(
            "PCAN FOUT bij {}: 0x{:08X} - {}".format(
                operation,
                int(status),
                error_text(api, status),
            )
        )
        return False

    return True


def wait_with_abort(seconds):
    """
    Wacht, maar reageer op Ctrl+C.
    """
    end = time.perf_counter() + seconds

    while True:
        remaining = end - time.perf_counter()

        if remaining <= 0:
            return True

        time.sleep(min(0.05, remaining))


def spin_wait_until(target):
    """
    Hoge-resolutie wachtfunctie voor de ~114 us software-gap.

    Let op:
        Windows/Python/USB/PCAN-driver kunnen de werkelijke CAN-bus
        timing beïnvloeden. Dit garandeert dus geen exacte 114 us
        tussen fysieke CAN-frame-starts.
    """
    while True:
        remaining = target - time.perf_counter()

        if remaining <= 0:
            return

        if remaining > 0.001:
            time.sleep(remaining / 2.0)


def token_from_id(can_id):
    return can_id & 0xFFFF


def make_id(family, token):
    return family | (token & 0xFFFF)


def token_bytes(token):
    return [
        token & 0xFF,
        (token >> 8) & 0xFF,
    ]


def make_frame(can_id, data):
    """
    Maak TPCANMsg voor klassieke CAN.
    """
    msg = TPCANMsg()

    msg.ID = can_id
    msg.MSGTYPE = MSG_TYPE
    msg.LEN = len(data)

    for i, value in enumerate(data):
        msg.DATA[i] = value

    return msg


def frame_dlc7(token, start_marker=False):
    lo, hi = token_bytes(token)

    marker = 0x00 if start_marker else 0x03

    return make_frame(
        make_id(FAMILY_A, token),
        [0x01, 0x00, 0x00, 0x0F, marker, lo, hi],
    )


def frame_dlc5(token):
    lo, hi = token_bytes(token)

    return make_frame(
        make_id(FAMILY_B, token),
        [0x01, 0x00, 0x00, lo, hi],
    )


# ---------------------------------------------------------------------------
# RX capture
# ---------------------------------------------------------------------------

@dataclass
class RxRecord:
    timestamp: float
    can_id: int
    dlc: int
    data: bytes
    msg_type: int


class Capture:
    def __init__(self, api, channel, name):
        self.api = api
        self.channel = channel
        self.name = name
        self.records = []

    def poll(self):
        """
        Lees alle momenteel beschikbare CAN-frames.
        """
        while True:
            result = self.api.Read(self.channel)

            status = result[0]

            if status == PCAN_ERROR_QRCVEMPTY:
                break

            if status != PCAN_ERROR_OK:
                print(
                    "RX fout tijdens {}: 0x{:08X} {}".format(
                        self.name,
                        int(status),
                        error_text(self.api, status),
                    )
                )
                break

            msg = result[1]

            timestamp = time.perf_counter()

            data = bytes(
                int(msg.DATA[i])
                for i in range(int(msg.LEN))
            )

            record = RxRecord(
                timestamp=timestamp,
                can_id=int(msg.ID),
                dlc=int(msg.LEN),
                data=data,
                msg_type=int(msg.MSGTYPE),
            )

            self.records.append(record)

    def run(self, seconds):
        print()
        print(
            "[RX] {} - {:.3f} seconden".format(
                self.name,
                seconds,
            )
        )

        start = time.perf_counter()
        next_poll = start

        while True:
            now = time.perf_counter()

            if now - start >= seconds:
                break

            self.poll()

            # Regelmatig pollen zonder de CPU volledig te belasten.
            next_poll += 0.0005

            remaining = next_poll - time.perf_counter()

            if remaining > 0:
                time.sleep(min(remaining, 0.0005))
            else:
                next_poll = time.perf_counter()

        self.poll()

        print(
            "[RX] {} frames ontvangen.".format(
                len(self.records)
            )
        )


# ---------------------------------------------------------------------------
# CSV / analyse
# ---------------------------------------------------------------------------

def write_csv(capture, filename):
    with open(
        filename,
        "w",
        newline="",
        encoding="utf-8",
    ) as f:

        writer = csv.writer(f)

        writer.writerow([
            "timestamp_monotonic",
            "can_id_hex",
            "can_id_decimal",
            "dlc",
            "data_hex",
            "msg_type",
        ])

        for r in capture.records:
            writer.writerow([
                "{:.9f}".format(r.timestamp),
                "{:08X}".format(r.can_id),
                r.can_id,
                r.dlc,
                " ".join("{:02X}".format(x) for x in r.data),
                "0x{:02X}".format(r.msg_type),
            ])


def summarize(capture):
    print()
    print("=" * 72)
    print("SAMENVATTING:", capture.name)
    print("=" * 72)

    if not capture.records:
        print("Geen CAN-frames ontvangen.")
        return

    counts = Counter(r.can_id for r in capture.records)

    first_time = capture.records[0].timestamp
    last_time = capture.records[-1].timestamp

    duration = max(last_time - first_time, 0.000001)

    print(
        "Totaal ontvangen: {}".format(
            len(capture.records)
        )
    )

    print(
        "Aantal verschillende CAN-ID's: {}".format(
            len(counts)
        )
    )

    print()
    print(
        "{:<12} {:>10} {:>12} {:>8} {}".format(
            "CAN-ID",
            "count",
            "Hz",
            "DLC",
            "voorbeeld DATA",
        )
    )

    print("-" * 72)

    for can_id, count in sorted(counts.items()):
        records = [
            r for r in capture.records
            if r.can_id == can_id
        ]

        dlcs = sorted(set(r.dlc for r in records))

        hz = count / duration

        example = " ".join(
            "{:02X}".format(x)
            for x in records[0].data
        )

        print(
            "{:<12} {:>10} {:>12.2f} {:>8} {}".format(
                "{:08X}".format(can_id),
                count,
                hz,
                ",".join(map(str, dlcs)),
                example,
            )
        )

    # Specifiek kijken naar de twee families.
    family_a = [
        r for r in capture.records
        if (r.can_id & 0xFFFF0000) == FAMILY_A
    ]

    family_b = [
        r for r in capture.records
        if (r.can_id & 0xFFFF0000) == FAMILY_B
    ]

    print()
    print(
        "Familie A 0x{:08X}: {} frames".format(
            FAMILY_A,
            len(family_a),
        )
    )

    print(
        "Familie B 0x{:08X}: {} frames".format(
            FAMILY_B,
            len(family_b),
        )
    )


# ---------------------------------------------------------------------------
# CAN TX
# ---------------------------------------------------------------------------

class CanTransmitter:
    def __init__(self, api, channel, enabled):
        self.api = api
        self.channel = channel
        self.enabled = enabled

    def send(self, msg, description=""):
        if not self.enabled:
            print(
                "[DRY-RUN] TX {} ID={:08X} DLC={}".format(
                    description,
                    int(msg.ID),
                    int(msg.LEN),
                )
            )
            return True

        result = self.api.Write(
            self.channel,
            msg,
        )

        if result != PCAN_ERROR_OK:
            print(
                "TX FOUT {}: 0x{:08X} {}".format(
                    description,
                    int(result),
                    error_text(self.api, result),
                )
            )
            return False

        return True

    def send_pair(
        self,
        token,
        start_marker=False,
        pair_gap=PAIR_GAP_S,
    ):
        """
        DLC7 gevolgd door DLC5.
        """

        msg_a = frame_dlc7(
            token,
            start_marker=start_marker,
        )

        msg_b = frame_dlc5(token)

        if not self.send(
            msg_a,
            "DLC7/start" if start_marker else "DLC7",
        ):
            return False

        # Zo dicht mogelijk bij de opgegeven 114 us.
        target = time.perf_counter() + pair_gap
        spin_wait_until(target)

        if not self.send(
            msg_b,
            "DLC5",
        ):
            return False

        return True


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------

def run_baseline(api, channel, output_dir):
    print()
    print("=" * 72)
    print("BASELINE")
    print("=" * 72)

    print()
    print("Controleer nu handmatig:")
    print()
    print("  - pomp RUN/STOP gedeactiveerd")
    print("  - SP = __________________")
    print("  - RP = __________________")
    print("  - AD = __________________")
    print("  - NA = __________________")
    print("  - NC = __________________")
    print("  - IC = __________________")
    print()
    print("Noteer ook:")
    print("  - N")
    print("  - communicatiepictogram")
    print("  - eventueel huidig adres")
    print("  - eventuele foutmelding")
    print()
    input("Druk ENTER om de 10 s baseline te starten...")

    cap = Capture(api, channel, "baseline")
    cap.run(BASELINE_SECONDS)

    filename = os.path.join(
        output_dir,
        "baseline.csv",
    )

    write_csv(cap, filename)
    summarize(cap)

    print()
    print("Baseline opgeslagen als:")
    print(filename)

    return cap


# ---------------------------------------------------------------------------
# Test 21
# ---------------------------------------------------------------------------

def test21(api, channel, tx, output_dir):
    print()
    print("=" * 72)
    print("TEST 21 - EEN SYNTHETISCH FRAMEPAAR")
    print("=" * 72)

    print()
    print("Paar 1:")
    print("00011234  7  01 00 00 0F 00 34 12")
    print("00111234  5  01 00 00 34 12")

    input(
        "Druk ENTER om het eerste paar te verzenden..."
    )

    cap1 = Capture(
        api,
        channel,
        "test21_startmarker",
    )

    # Eerst één startmarker.
    tx.send_pair(
        token=0x1234,
        start_marker=True,
    )

    cap1.run(OBSERVE_AFTER_SINGLE_PAIR)

    file1 = os.path.join(
        output_dir,
        "test21_startmarker.csv",
    )

    write_csv(cap1, file1)
    summarize(cap1)

    print()
    print("Controleer handmatig:")
    print("  N: 1 -> 2 ?")
    print("  communicatiepictogram veranderd?")
    print("  adres of knipperende E?")
    print("  parameter/firmware/productmelding?")
    print("  nieuwe CAN-ID-families?")
    print("  bestaande 200 Hz-stroom veranderd?")
    print("  FF/fouthistorie gewijzigd?")

    print()
    print("Tweede capture: normaal paar:")
    print("00011234  7  01 00 00 0F 03 34 12")
    print("00111234  5  01 00 00 34 12")

    input(
        "Druk ENTER om het normale paar te verzenden..."
    )

    cap2 = Capture(
        api,
        channel,
        "test21_normal",
    )

    tx.send_pair(
        token=0x1234,
        start_marker=False,
    )

    cap2.run(OBSERVE_AFTER_SINGLE_PAIR)

    file2 = os.path.join(
        output_dir,
        "test21_normal.csv",
    )

    write_csv(cap2, file2)
    summarize(cap2)

    return cap1, cap2


# ---------------------------------------------------------------------------
# Test 22
# ---------------------------------------------------------------------------

def test22(api, channel, tx, output_dir):
    print()
    print("=" * 72)
    print("TEST 22 - KORTE STARTSEQUENTIE MET VASTE TOKEN")
    print("=" * 72)

    input(
        "Druk ENTER om Test 22 te starten..."
    )

    cap = Capture(
        api,
        channel,
        "test22",
    )

    # Eén 0F 00 startmarker.
    tx.send_pair(
        token=0x1234,
        start_marker=True,
    )

    # Daarna 1 seconde iedere 5 ms een normaal paar.
    start = time.perf_counter()
    next_cycle = start
    sent = 0

    while True:
        now = time.perf_counter()

        if now - start >= TEST22_BURST_SECONDS:
            break

        tx.send_pair(
            token=0x1234,
            start_marker=False,
        )

        sent += 1

        next_cycle += TEST24_PERIOD_S

        remaining = next_cycle - time.perf_counter()

        if remaining > 0:
            time.sleep(remaining)
        else:
            next_cycle = time.perf_counter()

    print()
    print(
        "Test 22 burst beëindigd; {} normale paren verzonden.".format(
            sent
        )
    )

    print(
        "Nu 20 seconden niets verzenden en alleen ontvangen."
    )

    cap.run(TEST22_OBSERVE_SECONDS)

    filename = os.path.join(
        output_dir,
        "test22.csv",
    )

    write_csv(cap, filename)
    summarize(cap)

    print()
    print("Controleer handmatig:")
    print("  N / communicatiepictogram / adres / E")
    print("  parameter-, firmware- of productmelding")
    print("  nieuwe CAN-ID-families")
    print("  bestaande 200 Hz-stroom")
    print("  FF/fouthistorie")

    return cap


# ---------------------------------------------------------------------------
# Test 23
# ---------------------------------------------------------------------------

def test23_one(
    api,
    channel,
    tx,
    output_dir,
    mode,
):
    """
    mode:
        dlc7
        dlc5
        pair
    """

    print()
    print("-" * 72)
    print("TEST 23:", mode)
    print("-" * 72)

    input(
        "Druk ENTER om deze 1 s burst te starten..."
    )

    cap = Capture(
        api,
        channel,
        "test23_" + mode,
    )

    start = time.perf_counter()
    next_cycle = start

    while time.perf_counter() - start < TEST23_BURST_SECONDS:

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
                frame_dlc5(token),
                "DLC5",
            )

        elif mode == "pair":
            tx.send_pair(
                token,
                start_marker=False,
            )

        next_cycle += TEST24_PERIOD_S

        remaining = next_cycle - time.perf_counter()

        if remaining > 0:
            time.sleep(remaining)
        else:
            next_cycle = time.perf_counter()

    # Korte RX-drain.
    cap.poll()

    filename = os.path.join(
        output_dir,
        "test23_{}.csv".format(mode),
    )

    write_csv(cap, filename)
    summarize(cap)

    return cap


def test23(api, channel, tx, output_dir):
    print()
    print("=" * 72)
    print("TEST 23 - AFZONDERLIJKE FRAMETYPES")
    print("=" * 72)

    print()
    print("Er worden drie aparte captures gemaakt:")
    print("  1. alleen DLC7")
    print("  2. alleen DLC5")
    print("  3. DLC7 + DLC5 als paar")
    print()

    results = []

    for mode in (
        "dlc7",
        "dlc5",
        "pair",
    ):
        results.append(
            test23_one(
                api,
                channel,
                tx,
                output_dir,
                mode,
            )
        )

        print()
        print(
            "Controleer na {}: N/display/communicatie/FF.".format(
                mode
            )
        )

        input(
            "ENTER voor de volgende capture..."
        )

    return results


# ---------------------------------------------------------------------------
# Test 24
# ---------------------------------------------------------------------------

def test24(api, channel, tx, output_dir, seconds):
    print()
    print("=" * 72)
    print("TEST 24 - REALISTISCH VERANDERENDE TOKEN")
    print("=" * 72)

    print()
    print("Configuratie:")
    print("  startmarker       : één 0F 00-paar")
    print("  normale frequentie: 200 Hz")
    print("  periode           : 5 ms")
    print("  pair gap          : 114 us software-timing")
    print("  token             : willekeurig 16-bit")
    print("  token in beide ID's")
    print("  token little-endian in payload")
    print("  volgorde          : DLC7 -> DLC5")
    print()

    print(
        "Let op: 114 us is een softwarematige afstand tussen de "
        "Write()-aanroepen."
    )

    print(
        "De werkelijke on-bus timing wordt ook bepaald door "
        "CAN-bitrate, frame-lengte, USB en driver."
    )

    input(
        "Druk ENTER om Test 24 te starten..."
    )

    cap = Capture(
        api,
        channel,
        "test24",
    )

    # Willekeurige starttoken.
    start_token = random.randint(
        0x0000,
        0xFFFF,
    )

    print(
        "Starttoken = {:04X}".format(
            start_token
        )
    )

    # Eén 0F 00-paar.
    tx.send_pair(
        token=start_token,
        start_marker=True,
    )

    # Daarna 200 Hz nieuwe token.
    start = time.perf_counter()
    next_cycle = start
    sent = 0

    while True:
        now = time.perf_counter()

        if now - start >= seconds:
            break

        token = random.randint(
            0x0000,
            0xFFFF,
        )

        tx.send_pair(
            token=token,
            start_marker=False,
        )

        sent += 1

        next_cycle += TEST24_PERIOD_S

        remaining = next_cycle - time.perf_counter()

        if remaining > 0:
            time.sleep(remaining)
        else:
            # Als Windows/Python achterloopt, niet onbeperkt
            # oude cycli inhalen.
            next_cycle = time.perf_counter()

    cap.poll()

    filename = os.path.join(
        output_dir,
        "test24.csv",
    )

    write_csv(cap, filename)
    summarize(cap)

    print()
    print(
        "Normale paren verzonden: {}".format(
            sent
        )
    )

    print()
    print("Controleer handmatig:")
    print("  N")
    print("  communicatiepictogram")
    print("  adres / knipperende E")
    print("  parameter/firmware/productverschillen")
    print("  nieuwe CAN-ID-families")
    print("  verandering bestaande 200 Hz-stroom")
    print("  FF/fouthistorie")

    return cap


# ---------------------------------------------------------------------------
# PCAN initialisatie
# ---------------------------------------------------------------------------

def initialize_pcan(api):
    print()
    print("PCAN-USB initialiseren...")

    result = api.Initialize(
        CHANNEL,
        BITRATE,
    )

    if not check_status(
        api,
        result,
        "PCAN.Initialize",
    ):
        return False

    print("PCAN-USB kanaal geïnitialiseerd.")
#    print("Bitrate: 500 kbit/s")
    print("Bitrate: 1 Mbit/s")
    print("CAN-ID type: extended 29-bit")

    return True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="PCAN Test 21-24"
    )

    parser.add_argument(
        "--send",
        action="store_true",
        help=(
            "Sta daadwerkelijk CAN-zenden toe. "
            "Zonder deze optie is het script dry-run."
        ),
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
        help="Welke test uitvoeren.",
    )

    parser.add_argument(
        "--test24-seconds",
        type=float,
        default=1.0,
        help=(
            "Duur van de normale Test-24-stroom. "
            "Standaard 1 seconde."
        ),
    )

    parser.add_argument(
        "--output",
        default="pcan_test_results",
        help="Directory voor CSV-bestanden.",
    )

    args = parser.parse_args()

    os.makedirs(
        args.output,
        exist_ok=True,
    )

    print()
    print("=" * 72)
    print("PCAN PEER-SIMULATIE")
    print("TEST 21 / 22 / 23 / 24")
    print("=" * 72)

    if args.send:
        print()
        print("*** CAN ZENDEN IS INGESCHAKELD ***")
        print()
        print(
            "Controleer dat de pomp in de bedoelde veilige/"
            "gedeactiveerde testtoestand staat."
        )
    else:
        print()
        print("*** DRY-RUN: GEEN CAN-FRAMES WORDEN VERZONDEN ***")
        print()
        print(
            "Gebruik --send wanneer de bekabeling, bitrate en "
            "testtoestand gecontroleerd zijn."
        )

    print()

    api = PCANBasic()

    if not initialize_pcan(api):
        sys.exit(2)

    tx = CanTransmitter(
        api,
        CHANNEL,
        enabled=args.send,
    )

    try:
        # Baseline
        if args.test in ("baseline", "all"):
            run_baseline(
                api,
                CHANNEL,
                args.output,
            )

        # Test 21
        if args.test in ("21", "all"):
            test21(
                api,
                CHANNEL,
                tx,
                args.output,
            )

        # Test 22
        if args.test in ("22", "all"):
            test22(
                api,
                CHANNEL,
                tx,
                args.output,
            )

        # Test 23
        if args.test in ("23", "all"):
            test23(
                api,
                CHANNEL,
                tx,
                args.output,
            )

        # Test 24
        if args.test in ("24", "all"):
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
        print("!!! Ctrl+C ontvangen - test onmiddellijk gestopt !!!")

    finally:
        print()
        print("PCAN kanaal afsluiten...")

        result = api.Uninitialize(
            CHANNEL
        )

        if result != PCAN_ERROR_OK:
            print(
                "Waarschuwing bij Uninitialize: 0x{:08X} {}".format(
                    int(result),
                    error_text(api, result),
                )
            )
        else:
            print("PCAN kanaal afgesloten.")

    print()
    print("=" * 72)
    print("KLAAR")
    print("=" * 72)
    print()
    print(
        "Resultaten staan in: {}".format(
            os.path.abspath(args.output)
        )
    )


if __name__ == "__main__":
    main()
