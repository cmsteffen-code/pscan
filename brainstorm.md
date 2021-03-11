I want to design an asynchronous scan.

1. Create a sniffer to handle incoming TCP packets from the specific host.
2. Send out a spray of SYN packets to the target ports.
3. Capture and log any RST or SYN/ACK packets.
4. Send RST/ACK responses.
5. After the time-out is reached, end the scan.
6. Reveal the results.
