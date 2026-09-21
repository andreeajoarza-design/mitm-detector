#!/usr/bin/env python3
"""Generates the two sample captures used by the replay test and for manual runs.

    python tools/make_sample_pcaps.py

Output (overwritten on every run, no external libraries needed):
    src/test/resources/pcap/normal_arp.pcap
    src/test/resources/pcap/arp_spoofing.pcap

Network in the captures: 192.168.1.0/24, gateway .1, victim .10, attacker .66.
Timestamps are fixed (2026-01-01 10:00:00 UTC) so every run gives identical files.
"""
import os
import struct
from datetime import datetime, timezone

T0 = int(datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc).timestamp())

GATEWAY = ("192.168.1.1", "aa:aa:aa:aa:aa:01")
VICTIM = ("192.168.1.10", "bb:bb:bb:bb:bb:10")
ATTACKER = ("192.168.1.66", "cc:cc:cc:cc:cc:66")

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
ZERO_MAC = "00:00:00:00:00:00"


def mac(text):
    return bytes(int(part, 16) for part in text.split(":"))


def ip(text):
    return bytes(int(part) for part in text.split("."))


def arp_frame(op, eth_src, eth_dst, sender, target_mac, target_ip):
    """Ethernet + ARP frame, padded to the 60-byte minimum like a real capture."""
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, op)
    arp += mac(sender[1]) + ip(sender[0]) + mac(target_mac) + ip(target_ip)
    frame = mac(eth_dst) + mac(eth_src) + struct.pack("!H", 0x0806) + arp
    return frame + b"\x00" * (60 - len(frame))


def request(sender, target_ip):
    return arp_frame(1, sender[1], BROADCAST_MAC, sender, ZERO_MAC, target_ip)


def reply(sender, target):
    return arp_frame(2, sender[1], target[1], sender, target[1], target[0])


def write_pcap(path, packets):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        # magic, version 2.4, timezone, sigfigs, snaplen, link type 1 = Ethernet
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for seconds, frame in sorted(packets, key=lambda p: p[0]):
            whole = int(seconds)
            micro = int(round((seconds - whole) * 1_000_000))
            f.write(struct.pack("<IIII", T0 + whole, micro, len(frame), len(frame)))
            f.write(frame)
    print(f"{path}: {len(packets)} packets")


def normal_traffic():
    packets = []
    # Victim and attacker host both resolve the gateway, and the gateway resolves the victim.
    for t in (0, 20, 40, 60):
        packets.append((t, request(VICTIM, GATEWAY[0])))
        packets.append((t + 0.01, reply(GATEWAY, VICTIM)))
        packets.append((t + 1, request(GATEWAY, VICTIM[0])))
        packets.append((t + 1.01, reply(VICTIM, GATEWAY)))
    return packets


def spoofing_traffic():
    # Normal traffic at t=0 and t=20, so the gateway and victim bindings are learned first.
    packets = [p for p in normal_traffic() if p[0] < 30]
    packets = packets[:8]
    # The attacker host also resolves the gateway once, so its MAC is a known host.
    packets.append((5, request(ATTACKER, GATEWAY[0])))
    packets.append((5.01, reply(GATEWAY, ATTACKER)))
    # Poisoning starts at t=30: the attacker tells the victim "192.168.1.1 is at cc:cc:cc:cc:cc:66"
    # every 2 seconds, without any request from the victim.
    for t in (30, 32, 34, 36, 38):
        packets.append((t, reply((GATEWAY[0], ATTACKER[1]), VICTIM)))
    return packets


if __name__ == "__main__":
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "test", "resources", "pcap")
    write_pcap(os.path.normpath(os.path.join(root, "normal_arp.pcap")), normal_traffic())
    write_pcap(os.path.normpath(os.path.join(root, "arp_spoofing.pcap")), spoofing_traffic())
