import argparse
import os
import socket
import struct
import sys
import time

MAX_HOPS = 30
PROBES_PER_HOP = 3
TIMEOUT = 2.0

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ICMP_TIME_EXCEEDED = 11


def calc_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b'\x00'

    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        total += word

    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16

    return ~total & 0xFFFF


def build_icmp_packet(identifier: int, sequence: int) -> bytes:
    payload = struct.pack('!d', time.time())

    header = struct.pack(
        '!BBHHH',
        ICMP_ECHO_REQUEST,
        0,
        0,
        identifier,
        sequence
    )

    checksum = calc_checksum(header + payload)

    header = struct.pack(
        '!BBHHH',
        ICMP_ECHO_REQUEST,
        0,
        checksum,
        identifier,
        sequence
    )

    return header + payload


def resolve_host(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"mytraceroute: не удалось разрешить имя '{target}'")
        sys.exit(1)


def reverse_dns(ip: str) -> str:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return ""


def parse_icmp_response(recv_packet: bytes, identifier: int):
    ip_header_len = (recv_packet[0] & 0x0F) * 4
    sender_ip = socket.inet_ntoa(recv_packet[12:16])

    icmp_offset = ip_header_len
    if len(recv_packet) < icmp_offset + 8:
        return None

    icmp_type, icmp_code = struct.unpack('!BB', recv_packet[icmp_offset:icmp_offset + 2])

    if icmp_type == ICMP_ECHO_REPLY:
        reply_id = struct.unpack('!H', recv_packet[icmp_offset + 4:icmp_offset + 6])[0]
        if reply_id == identifier:
            return sender_ip, ICMP_ECHO_REPLY

    elif icmp_type == ICMP_TIME_EXCEEDED:
        inner_ip_offset = icmp_offset + 8
        if len(recv_packet) < inner_ip_offset + 1:
            return None

        inner_ip_header_len = (recv_packet[inner_ip_offset] & 0x0F) * 4
        inner_icmp_offset = inner_ip_offset + inner_ip_header_len
        if len(recv_packet) < inner_icmp_offset + 8:
            return None

        inner_id = struct.unpack('!H', recv_packet[inner_icmp_offset + 4:inner_icmp_offset + 6])[0]
        if inner_id == identifier:
            return sender_ip, ICMP_TIME_EXCEEDED

    return None


def traceroute(target: str, dns_lookup: bool = False):
    dest_ip = resolve_host(target)

    identifier = os.getpid() & 0xFFFF
    sequence = 0

    print(f"Трассировка маршрута до {target} ({dest_ip}), максимум {MAX_HOPS} хопов:\n")

    for ttl in range(1, MAX_HOPS + 1):
        rtts = []
        hop_ip = None
        reached = False

        for probe in range(PROBES_PER_HOP):
            sequence += 1

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            except PermissionError:
                print("Ошибка: требуются права администратора (sudo).")
                sys.exit(1)

            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            sock.settimeout(TIMEOUT)

            packet = build_icmp_packet(identifier, sequence)

            send_time = time.time()
            try:
                sock.sendto(packet, (dest_ip, 0))
            except OSError as e:
                print(f"Ошибка отправки: {e}")
                sock.close()
                rtts.append(None)
                continue

            while True:
                try:
                    recv_packet, addr = sock.recvfrom(1024)
                    recv_time = time.time()
                except socket.timeout:
                    rtts.append(None)
                    break

                result = parse_icmp_response(recv_packet, identifier)
                if result is None:
                    continue

                sender_ip, icmp_type = result
                rtt_ms = (recv_time - send_time) * 1000.0
                rtts.append(rtt_ms)
                hop_ip = sender_ip

                if icmp_type == ICMP_ECHO_REPLY:
                    reached = True
                break

            sock.close()

        rtt_strs = []
        for rtt in rtts:
            if rtt is None:
                rtt_strs.append("  *  ")
            else:
                rtt_strs.append(f"{rtt:6.2f} ms")

        rtt_line = "  ".join(rtt_strs)

        if hop_ip:
            if dns_lookup:
                hostname = reverse_dns(hop_ip)
                if hostname:
                    addr_str = f"{hostname} ({hop_ip})"
                else:
                    addr_str = f"{hop_ip}"
            else:
                addr_str = f"{hop_ip}"
            print(f" {ttl:2d}  {rtt_line}  {addr_str}")
        else:
            print(f" {ttl:2d}  {rtt_line}  *")

        if reached:
            print("\nТрассировка завершена.")
            return

    print("\nДостигнут максимум хопов, цель не достигнута.")


def main():
    parser = argparse.ArgumentParser(
        prog='mytraceroute',
        description='Простейший аналог traceroute на Python (ICMP, raw sockets).'
    )
    parser.add_argument(
        'target',
        help='Целевой узел: IP-адрес или доменное имя (например, google.com или 8.8.8.8)'
    )
    parser.add_argument(
        '-d', '--dns',
        action='store_true',
        help='Включить обратное DNS-разрешение для промежуточных узлов'
    )

    args = parser.parse_args()
    traceroute(args.target, dns_lookup=args.dns)


if __name__ == '__main__':
    main()
