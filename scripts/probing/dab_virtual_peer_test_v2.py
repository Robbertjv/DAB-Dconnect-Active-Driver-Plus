"""
DAB Active Driver Plus M/M 1.5 - controlled virtual-peer CAN test utility.

Modes
-----
short    : send one DLC5 short frame
long     : send one DLC7 long frame
pair     : send long frame, wait, then short frame
reverse  : send short frame, wait, then long frame
peer     : repeat a cycle for a given duration
           use --peer-frames to select short, long or pair

All received frames are written to CSV. Frames on 103C0401 and 103C0481
are highlighted on screen and summarized as bursts at the end.
"""

import argparse
import csv
import random
import time
from datetime import datetime, timezone

import can


RESPONSE_IDS = (
    0x103C0401,
    0x103C0481,
)


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
    if delay_us <= 0:
        return

    target_ns = time.perf_counter_ns() + int(delay_us * 1000)

    while time.perf_counter_ns() < target_ns:
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


def send_message(bus, writer, message, phase, start_ns, stats):
    bus.send(message, timeout=0.1)

    relative_ms = (time.perf_counter_ns() - start_ns) / 1_000_000

    log_row(writer, "TX", phase, message, relative_ms)

    stats["tx_frames"] += 1

    if stats["first_tx_ms"] is None:
        stats["first_tx_ms"] = relative_ms

    print(
        f"{relative_ms:11.3f} ms  TX  "
        f"{message.arbitration_id:08X}  "
        f"DLC{message.dlc}  "
        + " ".join(f"{byte:02X}" for byte in message.data)
    )


def receive_until(bus, writer, deadline_ns, phase, start_ns, stats):
    while time.perf_counter_ns() < deadline_ns:
        remaining_s = (deadline_ns - time.perf_counter_ns()) / 1_000_000_000

        if remaining_s <= 0:
            break

        message = bus.recv(timeout=min(0.05, remaining_s))

        if message is None:
            continue

        relative_ms = (time.perf_counter_ns() - start_ns) / 1_000_000

        log_row(writer, "RX", phase, message, relative_ms)

        stats["rx_frames"] += 1

        if message.arbitration_id in RESPONSE_IDS:
            stats["counts"][message.arbitration_id] += 1
            stats["response_times_ms"].append(relative_ms)

            print(
                f"{relative_ms:11.3f} ms  RX  "
                f"{message.arbitration_id:08X}  "
                f"DLC{message.dlc}  "
                + " ".join(f"{byte:02X}" for byte in message.data)
            )


def next_token(current, mode, rng):
    if mode == "fixed":
        return current

    if mode == "increment":
        return (current + 1) & 0xFFFF

    return rng.randrange(0x0000, 0x10000)


def summarize_bursts(times_ms, gap_ms):
    bursts = []

    for moment in sorted(times_ms):
        if not bursts or moment - bursts[-1][-1] > gap_ms:
            bursts.append([moment])
        else:
            bursts[-1].append(moment)

    return bursts


def build_parser():
    parser = argparse.ArgumentParser(
        description=(
            "Controlled virtual-peer test for the DAB Active Driver Plus "
            "proprietary CAN application layer"
        )
    )

    parser.add_argument(
        "--mode",
        choices=["short", "long", "pair", "reverse", "peer"],
        required=True,
        help="Transmission pattern to use",
    )
    parser.add_argument(
        "--peer-frames",
        choices=["pair", "short", "long"],
        default="pair",
        help="Frames sent per cycle in peer mode, default pair",
    )
    parser.add_argument(
        "--channel",
        default="PCAN_USBBUS1",
        help="PCAN channel, default PCAN_USBBUS1",
    )
    parser.add_argument(
        "--bitrate",
        type=int,
        default=1_000_000,
        help="CAN bitrate in bit/s, default 1000000",
    )
    parser.add_argument(
        "--long-family",
        type=parse_hex,
        default=0x0002,
        help="Upper family field for the DLC7 frame, default 0002",
    )
    parser.add_argument(
        "--short-family",
        type=parse_hex,
        default=0x0012,
        help="Upper family field for the DLC5 frame, default 0012",
    )
    parser.add_argument(
        "--token",
        type=parse_hex,
        default=0xC82D,
        help="16-bit token, default C82D",
    )
    parser.add_argument(
        "--token-mode",
        choices=["fixed", "increment", "random"],
        default="fixed",
        help="Token behaviour between peer cycles, default fixed",
    )
    parser.add_argument(
        "--marker",
        type=parse_hex,
        default=0x03,
        help="Marker byte in the DLC7 frame, default 03",
    )
    parser.add_argument(
        "--pair-gap-us",
        type=float,
        default=114.0,
        help="Gap between long and short frame in microseconds, default 114",
    )
    parser.add_argument(
        "--period-ms",
        type=float,
        default=1000.0,
        help="Peer cycle period in milliseconds, peer mode only",
    )
    parser.add_argument(
        "--duration-s",
        type=float,
        default=10.0,
        help="Peer transmission duration in seconds, peer mode only",
    )
    parser.add_argument(
        "--pre-s",
        type=float,
        default=5.0,
        help="Passive baseline duration before transmitting, default 5",
    )
    parser.add_argument(
        "--post-s",
        type=float,
        default=2.0,
        help="Passive observation after the last frame, default 2",
    )
    parser.add_argument(
        "--burst-gap-ms",
        type=float,
        default=500.0,
        help="Response gap that separates two bursts, default 500",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Seed for the random token generator, default 42",
    )
    parser.add_argument(
        "--output",
        default="dab_virtual_peer_log.csv",
        help="CSV output file",
    )

    return parser


def run_single_shot(bus, writer, args, start_ns, stats):
    token = args.token

    long_frame = make_long_frame(args.long_family, token, args.marker)
    short_frame = make_short_frame(args.short_family, token)

    if args.mode == "short":
        send_message(bus, writer, short_frame, "short_only", start_ns, stats)

    elif args.mode == "long":
        send_message(bus, writer, long_frame, "long_only", start_ns, stats)

    elif args.mode == "pair":
        send_message(bus, writer, long_frame, "pair_long", start_ns, stats)
        precise_wait_us(args.pair_gap_us)
        send_message(bus, writer, short_frame, "pair_short", start_ns, stats)

    elif args.mode == "reverse":
        send_message(bus, writer, short_frame, "reverse_short", start_ns, stats)
        precise_wait_us(args.pair_gap_us)
        send_message(bus, writer, long_frame, "reverse_long", start_ns, stats)

    stats["cycles"] += 1


def run_peer(bus, writer, args, start_ns, stats, rng):
    token = args.token
    cycle = 0

    end_ns = time.perf_counter_ns() + int(args.duration_s * 1_000_000_000)

    while time.perf_counter_ns() < end_ns:
        cycle_start_ns = time.perf_counter_ns()

        if args.peer_frames in ("pair", "long"):
            long_frame = make_long_frame(
                args.long_family,
                token,
                args.marker,
            )

            send_message(
                bus,
                writer,
                long_frame,
                f"peer_{cycle:05d}_long",
                start_ns,
                stats,
            )

        if args.peer_frames == "pair":
            precise_wait_us(args.pair_gap_us)

        if args.peer_frames in ("pair", "short"):
            short_frame = make_short_frame(args.short_family, token)

            send_message(
                bus,
                writer,
                short_frame,
                f"peer_{cycle:05d}_short",
                start_ns,
                stats,
            )

        stats["cycles"] += 1

        token = next_token(token, args.token_mode, rng)
        cycle += 1

        cycle_deadline_ns = cycle_start_ns + int(args.period_ms * 1_000_000)

        receive_until(
            bus,
            writer,
            min(cycle_deadline_ns, end_ns),
            "peer_observation",
            start_ns,
            stats,
        )


def print_summary(args, stats):
    print()
    print("Summary")
    print("-------")
    print(f"Mode                : {args.mode}")

    if args.mode == "peer":
        print(f"Peer frames         : {args.peer_frames}")
        print(f"Period              : {args.period_ms:.1f} ms")
        print(f"Token mode          : {args.token_mode}")

    print(f"Long family         : {args.long_family:04X}")
    print(f"Short family        : {args.short_family:04X}")
    print(f"Start token         : {args.token:04X}")
    print(f"Probe cycles sent   : {stats['cycles']}")
    print(f"TX frames sent      : {stats['tx_frames']}")
    print(f"RX frames logged    : {stats['rx_frames']}")
    print(f"103C0401 frames     : {stats['counts'][0x103C0401]}")
    print(f"103C0481 frames     : {stats['counts'][0x103C0481]}")

    bursts = summarize_bursts(stats["response_times_ms"], args.burst_gap_ms)

    print(f"Response bursts     : {len(bursts)}")

    if stats["cycles"] and bursts:
        ratio = len(bursts) / stats["cycles"]
        print(f"Bursts per cycle    : {ratio:.2f}")

    for index, burst in enumerate(bursts, start=1):
        first = burst[0]
        last = burst[-1]

        line = (
            f"  burst {index:2d}: "
            f"{len(burst):3d} frames, "
            f"start {first:.1f} ms, "
            f"end {last:.1f} ms, "
            f"duration {last - first:.1f} ms"
        )

        if stats["first_tx_ms"] is not None and index == 1:
            line += f", first latency {first - stats['first_tx_ms']:.1f} ms"

        print(line)

    print(f"CSV log             : {args.output}")


def main():
    args = build_parser().parse_args()

    if not 0 <= args.token <= 0xFFFF:
        raise SystemExit("Token must be between 0000 and FFFF")

    if not 0 <= args.marker <= 0xFF:
        raise SystemExit("Marker must be between 00 and FF")

    rng = random.Random(args.seed)

    stats = {
        "counts": {identifier: 0 for identifier in RESPONSE_IDS},
        "response_times_ms": [],
        "cycles": 0,
        "tx_frames": 0,
        "rx_frames": 0,
        "first_tx_ms": None,
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

    bus = can.Bus(
        interface="pcan",
        channel=args.channel,
        bitrate=args.bitrate,
    )

    start_ns = time.perf_counter_ns()

    try:
        with open(args.output, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()

            print(f"Passive baseline for {args.pre_s:.1f} s ...")

            receive_until(
                bus,
                writer,
                time.perf_counter_ns() + int(args.pre_s * 1_000_000_000),
                "baseline",
                start_ns,
                stats,
            )

            if args.mode == "peer":
                run_peer(bus, writer, args, start_ns, stats, rng)
            else:
                run_single_shot(bus, writer, args, start_ns, stats)

            print(f"Passive observation for {args.post_s:.1f} s ...")

            receive_until(
                bus,
                writer,
                time.perf_counter_ns() + int(args.post_s * 1_000_000_000),
                "post",
                start_ns,
                stats,
            )

    except KeyboardInterrupt:
        print()
        print("Interrupted by user, writing summary ...")

    finally:
        bus.shutdown()

    print_summary(args, stats)


if __name__ == "__main__":
    main()
