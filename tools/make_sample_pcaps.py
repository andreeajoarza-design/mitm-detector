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
    src/test/resources/pcap/normal_http.pcap
    src/test/resources/pcap/http_sslstrip.pcap
    src/test/resources/pcap/ml_baseline.pcap
    src/test/resources/pcap/ml_arp_flood.pcap
    src/test/resources/pcap/normal_icmp.pcap
    src/test/resources/pcap/icmp_redirect.pcap

Network in the captures: 192.168.1.0/24, gateway (and DNS resolver) .1, victim .10, attacker .66.
The HTTP captures also use three web servers outside the LAN (documentation address ranges).
Timestamps are fixed (each capture has its own reference hour) so every run gives identical files.
"""
import math
import os
import random
import struct
from datetime import datetime, timezone

def base_time(hour, minute=0):
    return int(datetime(2026, 1, 1, hour, minute, 0, tzinfo=timezone.utc).timestamp())

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


def write_pcap(path, packets, t0):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        # magic, version 2.4, timezone, sigfigs, snaplen, link type 1 = Ethernet
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for seconds, frame in sorted(packets, key=lambda p: p[0]):
            # Whole microseconds first, then split: rounding the fraction alone can give 1_000_000,
            # which is not a valid microsecond field.
            whole, micro = divmod(int(round(seconds * 1_000_000)), 1_000_000)
            f.write(struct.pack("<IIII", t0 + whole, micro, len(frame), len(frame)))
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


# ---------------------------------------------------------------------------
# ICMP Redirect captures. The real gateway is 192.168.1.1, the attacker is 192.168.1.66.
# ---------------------------------------------------------------------------

def icmp_redirect(sender, victim, new_gateway_ip, code=1):
    """ICMP type 5 (Redirect), code 1 = "redirect for host": sender tells victim to use
    new_gateway_ip as gateway from now on."""
    icmp = struct.pack("!BBH", 5, code, 0) + ip(new_gateway_ip)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(icmp), 0, 0, 64, 1, 0, ip(sender[0]), ip(victim[0]))
    header = header[:10] + struct.pack("!H", ipv4_checksum(header)) + header[12:]
    frame = mac(victim[1]) + mac(sender[1]) + struct.pack("!H", 0x0800) + header + icmp
    return frame + b"\x00" * max(0, 60 - len(frame))


def normal_icmp_traffic():
    packets = []
    # Two genuine redirects from the real gateway, same MAC both times: nothing suspicious.
    packets.append((0, icmp_redirect(GATEWAY, VICTIM, "192.168.1.50")))
    packets.append((20, icmp_redirect(GATEWAY, VICTIM, "192.168.1.51")))
    return packets


def icmp_redirect_traffic():
    packets = []
    packets.append((0, icmp_redirect(GATEWAY, VICTIM, "192.168.1.50")))          # learns the real gateway
    # t=30: claims to be the gateway's IP, but arrives from the attacker's MAC.
    packets.append((30, icmp_redirect((GATEWAY[0], ATTACKER[1]), VICTIM, ATTACKER[0])))
    # t=50: the attacker uses its own address and names itself as the new gateway.
    packets.append((50, icmp_redirect(ATTACKER, VICTIM, ATTACKER[0])))
    return packets


# ---- HTTP (plain port 80, for the SSL stripping detector) ----------------------------------------

SHOP = ("203.0.113.10", "shop.example.net")      # redirects plain HTTP to HTTPS
BANK = ("203.0.113.20", "bank.example.net")      # redirects plain HTTP to HTTPS
NEWS = ("198.51.100.20", "news.example.org")     # only speaks plain HTTP


def tcp_checksum(src_ip, dst_ip, segment):
    pseudo = ip(src_ip) + ip(dst_ip) + struct.pack("!BBH", 0, 6, len(segment))
    data = pseudo + segment + (b"\x00" if len(segment) % 2 else b"")
    return ipv4_checksum(data)


def tcp_frame(eth_src, eth_dst, src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload):
    segment = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, 0x50, flags, 65535, 0, 0) + payload
    segment = segment[:16] + struct.pack("!H", tcp_checksum(src_ip, dst_ip, segment)) + segment[18:]
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(segment), 0, 0x4000, 64, 6, 0, ip(src_ip), ip(dst_ip))
    header = header[:10] + struct.pack("!H", ipv4_checksum(header)) + header[12:]
    frame = mac(eth_dst) + mac(eth_src) + struct.pack("!H", 0x0800) + header + segment
    return frame + b"\x00" * max(0, 60 - len(frame))


PSH_ACK = 0x18
ACK = 0x10


def http_get(t, port, server, host, path):
    text = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n"
    return (t, tcp_frame(VICTIM[1], GATEWAY[1], VICTIM[0], server[0], port, 80, 1000, 5000, PSH_ACK,
                         text.encode("ascii")))


def http_reply(t, port, server, status_line, headers, body=b"", sender_mac=GATEWAY[1]):
    """A response that claims to come from the web server, sent by the machine with sender_mac."""
    lines = [status_line] + headers + [f"Content-Length: {len(body)}", "Connection: close"]
    payload = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body
    return (t, tcp_frame(sender_mac, VICTIM[1], server[0], VICTIM[0], 80, port, 5000, 1000 + 100, PSH_ACK, payload))


def http_ack(t, port, server):
    return (t, tcp_frame(VICTIM[1], GATEWAY[1], VICTIM[0], server[0], port, 80, 1100, 5300, ACK, b""))


def https_redirect(t, port, server, status_line="HTTP/1.1 301 Moved Permanently", sender_mac=GATEWAY[1]):
    return http_reply(t, port, server, status_line, [f"Location: https://{server[1]}/"], sender_mac=sender_mac)


PAGE = b"<html><body><form action='/login'>...</form></body></html>"


def normal_http_traffic():
    packets = []
    packets += [http_get(0, 51000, SHOP, SHOP[1], "/"), https_redirect(0.03, 51000, SHOP), http_ack(0.031, 51000, SHOP)]
    packets += [http_get(5, 51001, BANK, BANK[1], "/"),
                https_redirect(5.03, 51001, BANK, "HTTP/1.1 302 Found")]
    # A site that has no HTTPS at all: a plain page is normal for it.
    packets += [http_get(10, 51002, NEWS, NEWS[1], "/"),
                http_reply(10.04, 51002, NEWS, "HTTP/1.1 200 OK", ["Content-Type: text/html; charset=utf-8"], PAGE)]
    # A picture fetched over plain HTTP from a site that otherwise redirects: not a page, so not a sign.
    packets += [http_get(20, 51003, SHOP, SHOP[1], "/logo.png"),
                http_reply(20.03, 51003, SHOP, "HTTP/1.1 200 OK", ["Content-Type: image/png"], b"\x89PNG....")]
    packets += [http_get(30, 51004, SHOP, SHOP[1], "/"), https_redirect(30.03, 51004, SHOP)]
    return packets


def http_sslstrip_traffic():
    packets = []
    # Before the attack: the detector sees both sites redirecting to HTTPS.
    packets += [http_get(0, 51000, SHOP, SHOP[1], "/"), https_redirect(0.03, 51000, SHOP)]
    packets += [http_get(5, 51001, BANK, BANK[1], "/"), https_redirect(5.03, 51001, BANK, "HTTP/1.1 302 Found")]
    # t=30: the attacker sits in the path (for example after ARP poisoning) and answers the same request
    # with the page itself, fetched over HTTPS on its own and handed over as plain HTTP.
    packets += [http_get(30, 51002, SHOP, SHOP[1], "/"),
                http_reply(30.05, 51002, SHOP, "HTTP/1.1 200 OK", ["Content-Type: text/html; charset=utf-8"], PAGE,
                           sender_mac=ATTACKER[1])]
    # t=45: for the bank, the attacker turns the redirect to HTTPS into a redirect to HTTP.
    packets += [http_get(45, 51003, BANK, BANK[1], "/login"),
                http_reply(45.05, 51003, BANK, "HTTP/1.1 302 Found", [f"Location: http://www.{BANK[1]}/login"],
                           sender_mac=ATTACKER[1])]
    return packets


# ---- Anomaly detector (Isolation Forest) ------------------------------------------------------------

DNS_NAMES = ["www.example.com", "mail.example.com", "cdn.example.net", "api.example.org", "news.example.org"]


def exponential(rng, mean, cap):
    return min(cap, int(-math.log(1 - rng.random()) * mean))


def quiet_network_traffic(seconds, seed):
    """Traffic of a quiet home network in 10 s windows: a few DNS lookups and web responses in every
    window (with the odd browsing burst), and an ARP exchange in about one window in seven."""
    rng = random.Random(seed)
    packets = []
    txid = 0x5000
    for window in range(seconds // 10):
        t = window * 10 + 0.5
        if rng.random() < 0.15:
            packets.append((t, request(VICTIM, GATEWAY[0])))
            packets.append((t + 0.01, reply(GATEWAY, VICTIM)))
            t += 0.5
        for _ in range(exponential(rng, 4, 30)):
            txid += 1
            name = DNS_NAMES[txid % len(DNS_NAMES)]
            packets += lookup(t, txid, name, ["198.51.100.7"])
            t += 0.05
        for _ in range(exponential(rng, 3, 20)):
            packets.append(http_reply(t, 51000 + rng.randrange(1000), NEWS, "HTTP/1.1 200 OK",
                                      ["Content-Type: image/png"], b"\x89PNG" + bytes(40)))
            t += 0.05
    return packets


def ml_baseline_traffic():
    return quiet_network_traffic(600, seed=11)


def ml_arp_flood_traffic():
    packets = quiet_network_traffic(300, seed=12)
    # t=200: the attacker sends 40 ARP replies in 5 seconds, announcing six addresses as its own MAC.
    for i in range(40):
        announced = ("192.168.1.%d" % (1 + i % 6), ATTACKER[1])
        packets.append((200 + i * 0.125, reply(announced, VICTIM)))
    return packets


if __name__ == "__main__":
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "test", "resources", "pcap")
    write_pcap(os.path.normpath(os.path.join(root, "normal_arp.pcap")), normal_traffic(), base_time(9, 15))
    write_pcap(os.path.normpath(os.path.join(root, "arp_spoofing.pcap")), spoofing_traffic(), base_time(9, 15))
    write_pcap(os.path.normpath(os.path.join(root, "normal_dns.pcap")), normal_dns_traffic(), base_time(11, 40))
    write_pcap(os.path.normpath(os.path.join(root, "dns_spoofing.pcap")), dns_spoofing_traffic(), base_time(11, 40))
    write_pcap(os.path.normpath(os.path.join(root, "normal_dhcp.pcap")), normal_dhcp_traffic(), base_time(14, 5))
    write_pcap(os.path.normpath(os.path.join(root, "dhcp_rogue.pcap")), dhcp_rogue_traffic(), base_time(14, 5))
    write_pcap(os.path.normpath(os.path.join(root, "normal_http.pcap")), normal_http_traffic(), base_time(16, 50))
    write_pcap(os.path.normpath(os.path.join(root, "http_sslstrip.pcap")), http_sslstrip_traffic(), base_time(16, 50))
    write_pcap(os.path.normpath(os.path.join(root, "ml_baseline.pcap")), ml_baseline_traffic(), base_time(20, 30))
    write_pcap(os.path.normpath(os.path.join(root, "ml_arp_flood.pcap")), ml_arp_flood_traffic(), base_time(20, 30))
    write_pcap(os.path.normpath(os.path.join(root, "normal_icmp.pcap")), normal_icmp_traffic(), base_time(18, 20))
    write_pcap(os.path.normpath(os.path.join(root, "icmp_redirect.pcap")), icmp_redirect_traffic(), base_time(18, 20))
