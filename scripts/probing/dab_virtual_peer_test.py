import argparse
import csv
import random
import time
from datetime import datetime, timezone

import can


RESPONSE_IDS = {
    0x103C0401,
    0x103C0481,
}


def parse_hex(value):
    return int(value, 16)


def token_bytes(token):
    return token & 0xFF, (token >> 8) & 0xFF


def make_short_frame(family, token):
    low, high = token_bytes(token)

    return can.Message(
        arbitration_id=((family & 0x1FFF) << 16) | token,
        is_extended_id=True,
        data=[0x01, 0x00, 0x00, low, high],
    )


def make_long_frame(family, token, marker):
    low, high = token_bytes(token)

    return can.Message(
        arbitration_id=((family & 0x1FFF) << 16) | token,
        is_extended_id=True,
        data=[0x01, 0x00, 0x00, 0x0F, marker, low, high],
    )


def precise_wait_us(delay_us):
    target = time.perf_counter_ns() + int(delay_us * 1000)

    while time.perf_counter_ns() < target:
        pass


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def log_row(writer, direction, phase, message, relative_ms):
    writer.writerow(
        {
            "utc": utc_now(),
            "relative_ms": f"{relative_ms:.3f}",
            "direction": direction,
            "phase": phase,
            "can_id_hex": f"{message.arbitration_id:08X}",
            "extended": int(message.is_extended_id),
            "dlc": message.dlc,
            "data_hex": " ".join(f"{byte:02X}" for byte in message.data),
        }
    )


def send_message(bus, writer, message, phase, start_ns):
    bus.send(message, timeout=0.1)

    relative_ms = (time.perf_counter_ns() - start_ns) / 1_000_000
    log_row(writer, "TX", phase, message, relative_ms)

    print(
        f"{relative_ms:10.3f} ms  TX  "
        f"{message.arbitration_id:08X}  "
        f"DLC{message.dlc}  "
        f"{message.data.hex(' ').upper()}"
    )


def receive_until(bus, writer, deadline_ns, phase, start_ns, counters):
    while time.perf_counter_ns() < deadline_ns:
        remaining_s = max(
            0.0,
            (deadline_ns - time.perf_counter_ns()) / 1_000_000_000,
        )

        message = bus.recv(timeout=min(0.05, remaining_s))

        if message is None:
            continue

        relative_ms = (time.perf_counter_ns() - start_ns) / 1_000_000
        log_row(writer, "RX", phase, message, relative_ms)

        if message.arbitration_id in RESPONSE_IDS:
            counters[message.arbitration_id] += 1

            print(
                f"{relative_ms:10.3f} ms  RX  "
                f"{message.arbitration_id:08X}  "
                f"DLC{message.dlc}  "
                f"{message.data.hex(' ').upper()}"
            )


def next_token(current, mode, rng):
    if mode == "fixed":
        return current

    if mode == "increment":
        return (current + 1) & 0xFFFF

    return rng.randrange(0x0000, 0x10000)


def main():
    parser = argparse.ArgumentParser(
        description="Controlled DAB Active Driver Plus virtual-peer test"
    )

    parser.add_argument(
        "--mode",
        choices=["short", "long", "pair", "reverse", "peer"],
        required=True,
    )
    parser.add_argument(
        "--channel",
        default="PCAN_USBBUS1",
    )
    parser.add_argument(
        "--bitrate",
        type=int,
        default=1_000_000,
    )
    parser.add_argument(
        "--long-family",
        type=parse_hex,
        default=0x0002,
        help="Upper family for the DLC7 frame, default 0002",
    )
    parser.add_argument(
        "--short-family",
        type=parse_hex,
        default=0x0012,
        help="Upper family for the DLC5 frame, default 0012",
    )
    parser.add_argument(
        "--token",
        type=parse_hex,
        default=0xC82D,
    )
    parser.add_argument(
        "--token-mode",
        choices=["fixed", "increment", "random"],
        default="fixed",
    )
    parser.add_argument(
        "--marker",
        type=parse_hex,
        default=0x03,
    )
    parser.add_argument(
        "--pair-gap-us",
        type=float,
        default=114.0,
    )
    parser.add_argument(
        "--period-ms",
        type=float,
        default=1000.0,
        help="Peer cycle period; used only in peer mode",
    )
    parser.add_argument(
        "--duration-s",
        type=float,
        default=10.0,
        help="Transmission duration; used only in peer mode",
    )
    parser.add_argument(
        "--pre-s",
        type=float,
        default=5.0,
    )
    parser.add_argument(
        "--post-s",
        type=float,
        default=2.0,
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
    )
    parser.add_argument(
        "--output",
        default="dab_virtual_peer_log.csv",
    )

    args = parser.parse_args()

    if not 0 <= args.token <= 0xFFFF:
        raise ValueError("Token must be between 0000 and FFFF")

    if not 0 <= args.marker <= 0xFF:
        raise ValueError("Marker must be between 00 and FF")

    rng = random.Random(args.seed)

    bus = can.Bus(
        interface="pcan",
        channel=args.channel,
        bitrate=args.bitrate,
    )

    counters = {
        0x103C0401: 0,
        0x103C0481: 0,
    }

    fieldnames = [
        "utc",
        "relative_ms",
        "direction",
        "phase",
        "can_id_hex",
        "extended",
        "dlc",
        "data_hex",
    ]

    start_ns = time.perf_counter_ns()

    try:
        with open(args.output, "w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()

            print(f"Listening for {args.pre_s:.3f} seconds before transmission...")

            receive_until(
                bus,
                writer,
                time.perf_counter_ns() + int(args.pre_s * 1_000_000_000),
                "baseline",
                start_ns,
                counters,
            )

            token = args.token

            if args.mode == "short":
                short_frame = make_short_frame(args.short_family, token)
                send_message(bus, writer, short_frame, "short_only", start_ns)

            elif args.mode == "long":
                long_frame = make_long_frame(
                    args.long_family,
                    token,
                    args.marker,
                )
                send_message(bus, writer, long_frame, "long_only", start_ns)

            elif args.mode == "pair":
                long_frame = make_long_frame(
                    args.long_family,
                    token,
                    args.marker,
                )
                short_frame = make_short_frame(args.short_family, token)

                send_message(bus, writer, long_frame, "pair_long", start_ns)
                precise_wait_us(args.pair_gap_us)
                send_message(bus, writer, short_frame, "pair_short", start_ns)

            elif args.mode == "reverse":
                long_frame = make_long_frame(
                    args.long_family,
                    token,
                    args.marker,
                )
                short_frame = make_short_frame(args.short_family, token)

                send_message(bus, writer, short_frame, "reverse_short", start_ns)
                precise_wait_us(args.pair_gap_us)
                send_message(bus, writer, long_frame, "reverse_long", start_ns)

            elif args.mode == "peer":
                end_ns = time.perf_counter_ns() + int(
                    args.duration_s * 1_000_000_000
                )
                cycle = 0

                while time.perf_counter_ns() < end_ns:
                    cycle_start_ns = time.perf_counter_ns()

                    long_frame = make_long_frame(
                        args.long_family,
                        token,
                        args.marker,
                    )
                    short_frame = make_short_frame(
                        args.short_family,
                        token,
                    )

                    send_message(
                        bus,
                        writer,
                        long_frame,
                        f"peer_{cycle:05d}_long",
                        start_ns,
                    )

                    precise_wait_us(args.pair_gap_us)

                    send_message(
                        bus,
                        writer,
                        short_frame,
                        f"peer_{cycle:05d}_short",
                        start_ns,
                    )

                    token = next_token(token, args.token_mode, rng)
                    cycle += 1

                    cycle_deadline_ns = (
                        cycle_start_ns + int(args.period_ms * 1_000_000)
                    )

                    receive_until(
                        bus,
                        writer,
                        cycle_deadline_ns,
                        "peer_observation",
                        start_ns,
                        counters,
                    )

            print(f"Observing for {args.post_s:.3f} seconds after transmission...")

            receive_until(
                bus,
                writer,
                time.perf_counter_ns() + int(args.post_s * 1_000_000_000),
                "post",
                start_ns,
                counters,
            )

    finally:
        bus.shutdown()

    print()
    print("Response summary")
    print("----------------")
    print(f"103C0401: {counters[0x103C0401]} frames")
    print(f"103C0481: {counters[0x103C0481]} frames")
    print(f"CSV log:   {args.output}")


if __name__ == "__main__":
    main()
