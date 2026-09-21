#!/usr/bin/env python3
"""Generates the two sample captures used by the replay test and for manual runs.

    python tools/make_sample_pcaps.py

Output (overwritten on every run, no external libraries needed):
    src/test/resources/pcap/normal_arp.pcap
    src/test/resources/pcap/arp_spoofing.pcap
    src/test/resources/pcap/normal_dns.pcap
    src/test/resources/pcap/dns_spoofing.pcap
    src/test/resources/pcap/normal_dhcp.pcap
    src/test/resources/pcap/dhcp_rogue.pcap

Network in the captures: 192.168.1.0/24, gateway (and DNS resolver) .1, victim .10, attacker .66.
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


# ---------------------------------------------------------------------------
# DNS captures. Client 192.168.1.10 asks the resolver 192.168.1.1 (the gateway).
# ---------------------------------------------------------------------------

def dns_name(name):
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\x00"


def dns_query(txid, name):
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack("!HH", 1, 1)


def dns_response(txid, name, addresses):
    message = struct.pack("!HHHHHH", txid, 0x8180, 1, len(addresses), 0, 0)
    message += dns_name(name) + struct.pack("!HH", 1, 1)
    for address in addresses:
        # name = pointer to the question (offset 12), type A, class IN, TTL 300, length 4
        message += struct.pack("!HHHIH", 0xC00C, 1, 1, 300, 4) + ip(address)
    return message


def ipv4_checksum(header):
    total = sum((header[i] << 8) + header[i + 1] for i in range(0, len(header), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def udp_frame(eth_src, eth_dst, src_ip, dst_ip, src_port, dst_port, payload):
    udp = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0) + payload   # UDP checksum 0 = unused
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0, ip(src_ip), ip(dst_ip))
    header = header[:10] + struct.pack("!H", ipv4_checksum(header)) + header[12:]
    frame = mac(eth_dst) + mac(eth_src) + struct.pack("!H", 0x0800) + header + udp
    return frame + b"\x00" * max(0, 60 - len(frame))


def client_port(txid):
    return 40000 + (txid & 0x0FFF)


def dns_query_packet(t, txid, name):
    frame = udp_frame(VICTIM[1], GATEWAY[1], VICTIM[0], GATEWAY[0], client_port(txid), 53, dns_query(txid, name))
    return (t, frame)


def dns_answer_packet(t, txid, name, addresses, sender_mac=GATEWAY[1]):
    """A response that claims to come from the resolver (192.168.1.1), sent by the machine with sender_mac."""
    frame = udp_frame(sender_mac, VICTIM[1], GATEWAY[0], VICTIM[0], 53, client_port(txid),
                      dns_response(txid, name, addresses))
    return (t, frame)


def lookup(t, txid, name, addresses):
    return [dns_query_packet(t, txid, name), dns_answer_packet(t + 0.02, txid, name, addresses)]


def normal_dns_traffic():
    packets = []
    packets += lookup(0, 0x1001, "www.example.com", ["198.51.100.7"])
    packets += lookup(2, 0x1002, "intranet.local", ["192.168.1.50"])      # internal name, private address is normal
    packets += lookup(10, 0x1003, "www.example.com", ["198.51.100.7"])
    packets += lookup(20, 0x1004, "www.example.com", ["198.51.100.8"])    # address rotation between public addresses
    packets += lookup(30, 0x1005, "www.example.com", ["198.51.100.7"])
    packets.append(dns_answer_packet(30.04, 0x1005, "www.example.com", ["198.51.100.7"]))   # identical duplicate
    packets += lookup(40, 0x1006, "intranet.local", ["192.168.1.50"])
    return packets


def dns_spoofing_traffic():
    packets = []
    # Two normal lookups, so the detector learns that the name resolves to a public address.
    packets += lookup(0, 0x2001, "www.example.com", ["198.51.100.7"])
    packets += lookup(10, 0x2002, "www.example.com", ["198.51.100.7"])
    # t=30: the attacker answers the victim's query 3 ms after it is sent, before the real resolver
    # (30 ms). The forged answer points the name to the attacker's own machine.
    packets.append(dns_query_packet(30, 0x2003, "www.example.com"))
    packets.append(dns_answer_packet(30.003, 0x2003, "www.example.com", [ATTACKER[0]], sender_mac=ATTACKER[1]))
    packets.append(dns_answer_packet(30.030, 0x2003, "www.example.com", ["198.51.100.7"]))
    # t=50: a forged answer for a name the victim never asked about.
    packets.append(dns_answer_packet(50, 0x2BAD, "login.example.com", [ATTACKER[0]], sender_mac=ATTACKER[1]))
    return packets


# ---------------------------------------------------------------------------
# DHCP captures. The real server is the gateway 192.168.1.1, the rogue one is the attacker .66.
# ---------------------------------------------------------------------------

DHCP_DISCOVER, DHCP_OFFER, DHCP_REQUEST, DHCP_ACK = 1, 2, 3, 5


def dhcp_option(code, data):
    return bytes([code, len(data)]) + data


def dhcp_payload(op, xid, client_mac, msg_type, server_ip=None, yiaddr="0.0.0.0", routers=(), dns=()):
    fixed = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", op, 1, 6, 0, xid, 0, 0x8000,
                        ip("0.0.0.0"), ip(yiaddr), ip("0.0.0.0"), ip("0.0.0.0"),
                        mac(client_mac) + b"\x00" * 10, b"\x00" * 64, b"\x00" * 128)
    options = dhcp_option(53, bytes([msg_type]))
    if server_ip:
        options += dhcp_option(54, ip(server_ip))
    if routers:
        options += dhcp_option(3, b"".join(ip(r) for r in routers))
    if dns:
        options += dhcp_option(6, b"".join(ip(d) for d in dns))
    return fixed + bytes([0x63, 0x82, 0x53, 0x63]) + options + b"\xff"


def dhcp_from_client(t, xid, client_mac, msg_type, server_ip=None):
    payload = dhcp_payload(1, xid, client_mac, msg_type, server_ip)
    return (t, udp_frame(client_mac, BROADCAST_MAC, "0.0.0.0", "255.255.255.255", 68, 67, payload))


def dhcp_from_server(t, xid, client_mac, msg_type, server, yiaddr, routers, dns, eth_src=None):
    """A broadcast reply that claims to come from server (ip, mac); eth_src overrides the MAC it is sent from."""
    payload = dhcp_payload(2, xid, client_mac, msg_type, server[0], yiaddr, routers, dns)
    return (t, udp_frame(eth_src or server[1], BROADCAST_MAC, server[0], "255.255.255.255", 67, 68, payload))


def dhcp_exchange(t, xid, client_mac, yiaddr):
    """DISCOVER, OFFER, REQUEST, ACK with the real server."""
    settings = ([GATEWAY[0]], [GATEWAY[0]])
    return [
        dhcp_from_client(t, xid, client_mac, DHCP_DISCOVER),
        dhcp_from_server(t + 0.02, xid, client_mac, DHCP_OFFER, GATEWAY, yiaddr, *settings),
        dhcp_from_client(t + 0.5, xid, client_mac, DHCP_REQUEST, GATEWAY[0]),
        dhcp_from_server(t + 0.52, xid, client_mac, DHCP_ACK, GATEWAY, yiaddr, *settings),
    ]


def normal_dhcp_traffic():
    packets = []
    packets += dhcp_exchange(0, 0x3001, VICTIM[1], "192.168.1.100")
    packets += dhcp_exchange(20, 0x3002, "dd:dd:dd:dd:dd:20", "192.168.1.101")
    return packets


def dhcp_rogue_traffic():
    packets = []
    packets += dhcp_exchange(0, 0x4001, VICTIM[1], "192.168.1.100")      # the detector learns the real server
    # t=30: the victim asks again. The rogue server answers 15 ms before the real one, naming itself
    # as gateway and DNS server, and the client picks the first offer it receives.
    xid = 0x4002
    packets.append(dhcp_from_client(30, xid, VICTIM[1], DHCP_DISCOVER))
    packets.append(dhcp_from_server(30.005, xid, VICTIM[1], DHCP_OFFER, ATTACKER, "192.168.1.150",
                                    [ATTACKER[0]], [ATTACKER[0]]))
    packets.append(dhcp_from_server(30.020, xid, VICTIM[1], DHCP_OFFER, GATEWAY, "192.168.1.100",
                                    [GATEWAY[0]], [GATEWAY[0]]))
    packets.append(dhcp_from_client(30.5, xid, VICTIM[1], DHCP_REQUEST, ATTACKER[0]))
    packets.append(dhcp_from_server(30.52, xid, VICTIM[1], DHCP_ACK, ATTACKER, "192.168.1.150",
                                    [ATTACKER[0]], [ATTACKER[0]]))
    # t=50: a reply that copies the real server's IP address but is sent from the attacker's MAC.
    packets.append(dhcp_from_server(50, 0x4003, VICTIM[1], DHCP_OFFER, GATEWAY, "192.168.1.151",
                                    [ATTACKER[0]], [ATTACKER[0]], eth_src=ATTACKER[1]))
    return packets


if __name__ == "__main__":
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "test", "resources", "pcap")
    write_pcap(os.path.normpath(os.path.join(root, "normal_arp.pcap")), normal_traffic())
    write_pcap(os.path.normpath(os.path.join(root, "arp_spoofing.pcap")), spoofing_traffic())
    write_pcap(os.path.normpath(os.path.join(root, "normal_dns.pcap")), normal_dns_traffic())
    write_pcap(os.path.normpath(os.path.join(root, "dns_spoofing.pcap")), dns_spoofing_traffic())
    write_pcap(os.path.normpath(os.path.join(root, "normal_dhcp.pcap")), normal_dhcp_traffic())
    write_pcap(os.path.normpath(os.path.join(root, "dhcp_rogue.pcap")), dhcp_rogue_traffic())
