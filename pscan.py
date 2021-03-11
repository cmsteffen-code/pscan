#!/usr/bin/env python3

"""Pscan: A fast Python port scanner."""

import argparse
import os
import sys
import textwrap


PORT_RANGE_FORMAT = textwrap.dedent(
    """\
    Ports can be specified as solo ports or hyphenated ranges, which
    may be combined with commas. For example:

    Port String      Corresponding Port List
    -----------      -----------------------
    23               [23]
    23,24            [23, 24]
    23-25            [23, 24, 25]
    21-23,80,443-445 [21, 22, 23, 80, 443, 444, 445]

    This script requires root privileges for low-level packet control.
    """
)


def parse_ports(port_string):
    """Convert a port specification string into a list of ports."""
    ports = set()
    for range_string in port_string.split(","):
        port_range = [int(port) for port in range_string.split("-")]
        ports = ports.union(set(range(min(port_range), max(port_range) + 1)))
    return sorted(ports)


def scan(hostname, port_range):
    """Scan the specified ports on the target host."""
    _ = (hostname, port_range)
    return {
        80: "open",
        81: "closed",
    }


def main():
    """Run the port scanner."""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="pscan: a fast Python port scanner",
        epilog=PORT_RANGE_FORMAT,
    )
    parser.add_argument(
        "hostname", type=str, help="The hostname or IP to scan."
    )
    parser.add_argument(
        "port_string", type=str, help="The port range to scan."
    )
    args = parser.parse_args()
    if os.getuid() != 0:
        print("[!] This script requires root privileges.")
        sys.exit(1)
    ports = parse_ports(args.port_string)
    print(f"[*] Scanning {len(ports)} ports on {args.hostname}")
    results = scan(args.hostname, ports)
    print("[*] Results:")
    for port, result in results.items():
        print(f"{' ' * 4}{port}{' ' * (6-len(str(port)))}{result}")


if __name__ == "__main__":
    main()
