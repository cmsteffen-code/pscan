# pscan

A fast Python port scanner. Performs a SYN "stealth" scan.

_Note: "Stealth" is a misnomer. This script is like screaming in a library._

## Usage

```
usage: pscan.py [-h] [-N] [-P PORT_STRING] hostname

pscan: a fast Python port scanner

positional arguments:
  hostname              The hostname or IP to scan.

optional arguments:
  -h, --help            show this help message and exit
  -N, --no-ping         Skip initial ping.
  -P PORT_STRING, --ports PORT_STRING
                        The port range to scan.

Ports can be specified as solo ports or hyphenated ranges, which may be
combined with commas. For example:

Port String      Corresponding Port List
-----------      -----------------------
23               [23]
23,24            [23, 24]
23-25            [23, 24, 25]
21-23,80,443-445 [21, 22, 23, 80, 443, 444, 445]

If no port range is specified, the script defaults to the top 1,000 ports.

This script requires root privileges for low-level packet control.
```

## How it Works

Linear port scans check each port, one at a time, sequentially.

1. Send the SYN packet.
2. Listen for a response.
3. Check if it's a SYN/ACK.
4. If so, port is open.
5. Start again at 1, for the next port.

This is very slow. One way to speed it up would be to run the above process with threads, giving each thread one port to scan. That way, each thread can be checking a different port. However, this too has its drawbacks. You're still sending a packet, then waiting for its response before freeing up the thread for the next packet.

A much faster way would be:

1. Start a packet sniffer, listening for incoming SYN/ACK packets from the ports being scanned.
2. While the sniffer runs, send all the SYN packets as fast as possible, without waiting for a response.
3. Once the "SYN spray" is complete, wait a short while, then close the sniffer.
4. Look through the packets collected by the sniffer to see which ports responded with SYN/ACK.

This is how `pscan` works. It sends a SYN spray, then sniffs for replies. This enables `pscan` to work quite quickly, scanning 1,000 ports in just over 2 seconds:

```
./pscan.py -N reddit.com
[*] Skipping initial ping.
[*] Scanning 1000 ports on reddit.com
[*] Port spray complete...
[*] Scan completed in 2.323 seconds
[*] Results:
    21    open
    80    open
    443   open
    554   open
    7070  open
```

Scanning all 65,535 ports takes just over 4 minutes:

```
./pscan.py -N reddit.com -P 1-65535
[*] Skipping initial ping.
[*] Scanning 65535 ports on reddit.com
[*] Port spray complete...
[*] Scan completed in 4 minutes, 17.118 seconds
[*] Results:
    21    open
    80    open
    443   open
    554   open
    7070  open
```

For comparison, the same scan in `nmap` takes over 20 minutes:

```
nmap -sS -Pn -p 1-65535 reddit.com
Starting Nmap 7.80 ( https://nmap.org ) at 2021-03-12 21:50 CST
Nmap scan report for reddit.com (151.101.1.140)
Host is up (0.18s latency).
Other addresses for reddit.com (not scanned): 151.101.129.140 151.101.65.140 151.101.193.140
Not shown: 65530 filtered ports
PORT     STATE SERVICE
21/tcp   open  ftp
80/tcp   open  http
443/tcp  open  https
554/tcp  open  rtsp
7070/tcp open  realserver

Nmap done: 1 IP address (1 host up) scanned in 1213.68 seconds
```
