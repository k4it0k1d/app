#!/usr/bin/env python3
"""Sniff ALL loopback (127.0.0.1) TCP traffic and print HTTP / JSON-RPC payloads.

Run as root INSIDE the Linux sandbox VM:
    sudo python3 lo-intercept.py                 # all loopback TCP
    sudo python3 lo-intercept.py --port 28471    # only the MCP server port
    sudo python3 lo-intercept.py --port 28471 --only-json   # only payloads with { or JSON-RPC

Notes:
- 127.0.0.1:28471 is plaintext HTTP, so you see the full MCP requests/responses
  (tools/call, and the RPCs: evaluate hook / evaluate skill, etc.).
- This captures TCP only. The Unix socket /tmp/cc-socks/<pid>.sock is NOT TCP;
  for that use: strace -f -e trace=read,write,sendto,recvfrom -p <pid>  (or socat).
- Passive sniff (observe). To MODIFY traffic you need a MITM proxy instead.
- Quick alternative if tcpdump exists:  tcpdump -i lo -A -s0 'tcp'
"""
import argparse
import socket
import struct
import sys

ETH_P_ALL = 0x0003


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="lo")
    ap.add_argument("--port", type=int, default=0,
                    help="filter to this TCP port (src OR dst); 0 = all loopback")
    ap.add_argument("--max", type=int, default=4096,
                    help="max payload bytes printed per segment")
    ap.add_argument("--only-json", action="store_true",
                    help="only print segments whose payload looks like JSON / JSON-RPC")
    ap.add_argument("--out", help="append captured output to this file (default: stdout). "
                                  "line-buffered, so `tail -f` works")
    args = ap.parse_args()

    out = open(args.out, "a", buffering=1) if args.out else sys.stdout

    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        s.bind((args.iface, 0))
    except PermissionError:
        sys.exit("needs root (AF_PACKET raw socket). Run with sudo.")

    print(f"[*] sniffing {args.iface}  (port filter: {args.port or 'all'})  — Ctrl-C to stop",
          file=sys.stderr, flush=True)

    while True:
        frame = s.recv(65535)
        if len(frame) < 14:
            continue
        eth_type = struct.unpack("!H", frame[12:14])[0]
        if eth_type != 0x0800:            # IPv4 only (loopback 127.0.0.1)
            continue
        ip = frame[14:]
        if len(ip) < 20:
            continue
        ihl = (ip[0] & 0x0F) * 4
        if ip[9] != 6:                    # TCP only
            continue
        src = socket.inet_ntoa(ip[12:16])
        dst = socket.inet_ntoa(ip[16:20])
        tcp = ip[ihl:]
        if len(tcp) < 20:
            continue
        sport, dport = struct.unpack("!HH", tcp[0:4])
        data_off = (tcp[12] >> 4) * 4
        payload = tcp[data_off:]
        if not payload:
            continue
        if args.port and args.port not in (sport, dport):
            continue

        text = payload[:args.max].decode("utf-8", "replace")
        if args.only_json:
            stripped = text.lstrip()
            if not (stripped.startswith("{") or '"jsonrpc"' in text or '"method"' in text):
                continue

        out.write(f"\n=== {src}:{sport} -> {dst}:{dport}  ({len(payload)} bytes) ===\n")
        out.write(text + "\n")
        out.flush()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
