
import argparse
import gzip
import zlib
from scapy.all import sniff, wrpcap, rdpcap, TCP, Raw
from scapy.sessions import TCPSession
from urllib.parse import urlsplit, parse_qs
from collections import defaultdict


def decode_body(body, headers):
    """Декодирование сжатого HTTP-тела."""
    encoding = headers.get("content-encoding", "").lower()

    try:
        if encoding == "gzip":
            return gzip.decompress(body)

        if encoding == "deflate":
            try:
                return zlib.decompress(body)
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS)

    except (OSError, zlib.error):
        print("[!] Не удалось распаковать тело ответа")

    return body


def parse_http(data):
    """Разделение HTTP-сообщения на заголовки и тело."""
    separator = b"\r\n\r\n"

    if separator not in data:
        return None

    header_data, body = data.split(separator, 1)

    try:
        lines = header_data.decode("latin-1").split("\r\n")
    except UnicodeDecodeError:
        return None

    if not lines:
        return None

    headers = {}

    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()

    return lines[0], headers, body


def show_http(data, direction):
    parsed = parse_http(data)

    if not parsed:
        return

    first_line, headers, body = parsed

    print("\n" + "=" * 70)
    print(f"[{direction}]")
    print(first_line)

    if direction == "REQUEST":
        parts = first_line.split()

        if len(parts) >= 2:
            method, target = parts[0], parts[1]

            print("Method:", method)
            print("URL:", target)

            parsed_url = urlsplit(target)
            params = parse_qs(parsed_url.query)

            if params:
                print("GET parameters:", params)

    else:
        print("Status:", first_line)

    print("\nHeaders:")

    for key, value in headers.items():
        print(f"{key}: {value}")

    decoded = decode_body(body, headers)

    print("\nBody:")

    content_type = headers.get("content-type", "")

    if "text" in content_type or "json" in content_type or not content_type:
        print(decoded.decode("utf-8", errors="replace")[:5000])
    else:
        print(f"[Binary data: {len(decoded)} bytes]")

    print("=" * 70)


def capture(filename, interface, duration):
    print("[*] Starting packet capture...")
    print("[*] Interface:", interface)
    print("[*] Duration:", duration, "seconds")
    print("[*] Press Ctrl+C to stop early.")

    packets = []

    try:
        packets = sniff(
            iface=interface,
            filter="tcp port 8008",
            timeout=duration
        )
    except KeyboardInterrupt:
        print("\n[*] Capture interrupted.")

    if packets:
        wrpcap(filename, packets)
        print(f"[*] Saved {len(packets)} packets to {filename}")
    else:
        print("[!] No packets captured.")


def analyze(filename):
    print("[*] Reading:", filename)

    packets = rdpcap(filename)

    # TCP-сессии позволяют объединять фрагменты HTTP.
    sessions = sniff(
        offline=filename,
        session=TCPSession
    )

    print("[*] Total packets:", len(packets))
    print("[*] Reassembled packets:", len(sessions))

    for packet in sessions:
        if TCP not in packet or Raw not in packet:
            continue

        payload = bytes(packet[Raw].load)

        if payload.startswith((b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ")):
            show_http(payload, "REQUEST")

        elif payload.startswith(b"HTTP/"):
            show_http(payload, "RESPONSE")


def main():
    parser = argparse.ArgumentParser(
        description="HTTP traffic analyzer based on Scapy"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    cap = subparsers.add_parser("capture")
    cap.add_argument("-o", "--output", default="traffic.pcap")
    cap.add_argument("-i", "--interface", default="lo")
    cap.add_argument("-t", "--time", type=int, default=120)

    ana = subparsers.add_parser("analyze")
    ana.add_argument("-f", "--file", default="traffic.pcap")

    args = parser.parse_args()

    if args.command == "capture":
        capture(args.output, args.interface, args.time)

    elif args.command == "analyze":
        analyze(args.file)


if __name__ == "__main__":
    main()
