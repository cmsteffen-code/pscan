#!/usr/bin/env python3

"""Pscan: A fast Python port scanner."""

import argparse
import datetime
import os
from queue import SimpleQueue
import socket
import sys
import textwrap
import threading
from multiprocessing.dummy import Pool as ThreadPool

from scapy.all import conf, sr1, ICMP, IP, TCP, sniff, send


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


def ping(hostname):
    """Ping the target host. Return either the ping delay or None."""
    conf.verb = 0
    start = datetime.datetime.now()
    online = sr1(IP(dst=hostname) / ICMP(), timeout=3) is not None
    end = datetime.datetime.now()
    return int((end - start).total_seconds() * 1000) if online else None

def syn_spray(host, ports):
    """Send a spray of SYN packets to the specified ports."""

    def send_syn(port):
        """Send the SYN packet to the host."""
        send(IP(dst=host) / TCP(dport=port, flags="S"))

    conf.verb = 0
    pool = ThreadPool(20)
    pool.map(send_syn, ports)
    pool.close()
    pool.join()

def sniffer(ports, host, out_queue):
    """Receive incoming packets and check for open ports."""
    packets = sniff(
        filter=(
            f"tcp and src portrange {min(ports)}-{max(ports)} "
            f"and inbound and host {host}"
        ),
        timeout=10, # TODO: Fix this.
    )
    live_ports = set()
    for packet in packets:
        if packet['TCP'].flags == "SA":
            live_ports.add(packet.sport)
    for port in sorted(live_ports):
        out_queue.put(port)

def scan(hostname, port_range):
    """Scan the specified ports on the target host."""
    _ = (hostname, port_range)
    good_ports = SimpleQueue()
    threads = [
        threading.Thread(
            target=sniffer, args=(port_range, hostname, good_ports)
        ),
        threading.Thread(target=syn_spray, args=(hostname, port_range)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    open_ports = list()
    while not good_ports.empty():
        open_ports.append(good_ports.get())
    return open_ports


def main():
    """Run the port scanner."""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="pscan: a fast Python port scanner",
        epilog=PORT_RANGE_FORMAT,
    )
    parser.add_argument(
        "-N", "--no-ping", default=True, action="store_const", const=False, help="Skip initial ping.", dest="ping",
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

    try:
        socket.gethostbyname(args.hostname)
    except socket.gaierror:
        print(f"[!] Could not resolve hostname: {args.hostname}")
        sys.exit(1)

    if args.ping:
        latency = ping(args.hostname)
        if not latency:
            print("[!] No ping response from target host.")
            sys.exit(1)
        print(f"[*] Ping: {latency}ms")
    else:
        print("[*] Skipping initial ping.")

    ports = parse_ports(args.port_string)
    print(f"[*] Scanning {len(ports)} ports on {args.hostname}")
    start = datetime.datetime.now()
    open_ports = scan(args.hostname, ports)
    end = datetime.datetime.now()
    delta = end-start
    hours = delta.seconds // 3600
    minutes = (delta.seconds // 60) - (hours * 60)
    seconds = delta.seconds - (minutes * 60) - (hours * 3600)
    scan_time = f"[*] Scan completed in " + (
        f"{hours} hours, " if hours else ""
    ) + (
        f"{minutes} minutes, " if minutes else ""
    ) + (
        f"{seconds}.{str(delta.microseconds)[:3]} seconds"
    )
    print(scan_time)
    print("[*] Results:")
    for port in open_ports:
        print(f"{' ' * 4}{port}{' ' * (6-len(str(port)))}open")


if __name__ == "__main__":
    main()
