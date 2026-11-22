import argparse
from scapy.all import sniff, wrpcap, rdpcap, TCP, Raw

def capture(args):
    print("[*] Interface:", args.iface)
    print("[*] Filter: tcp port", args.port)
    print("[*] Capturing for", args.seconds, "seconds")

    packets = sniff(
        iface=args.iface,
        filter="tcp port " + str(args.port),
        timeout=args.seconds
    )

    wrpcap(args.output, packets)
    print("[+] Packets captured:", len(packets))
    print("[+] Saved:", args.output)

def analyze(args):
    packets = rdpcap(args.input)

    with open(args.output, "w", encoding="utf-8") as report:
        report.write("PCAP ANALYSIS\n")
        report.write("Packets: " + str(len(packets)) + "\n\n")

        for number, packet in enumerate(packets, 1):
            if TCP not in packet or Raw not in packet:
                continue

            payload = bytes(packet[Raw].load)

            if packet.haslayer("IP"):
                src = packet["IP"].src
                dst = packet["IP"].dst
            else:
                src = packet.src
                dst = packet.dst

            sport = packet[TCP].sport
            dport = packet[TCP].dport

            text = payload.decode("utf-8", errors="replace")

            report.write("=" * 70 + "\n")
            report.write("Packet: " + str(number) + "\n")
            report.write("Direction: %s:%s -> %s:%s\n" %
                         (src, sport, dst, dport))
            report.write(text + "\n\n")

    print("[+] Analysis saved:", args.output)
    print("[+] Packets in file:", len(packets))

parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(dest="command", required=True)

cap = subparsers.add_parser("capture")
cap.add_argument("-i", "--iface", default="lo")
cap.add_argument("-p", "--port", type=int, default=8008)
cap.add_argument("-t", "--seconds", type=int, default=120)
cap.add_argument("-o", "--output", required=True)
cap.set_defaults(func=capture)

ana = subparsers.add_parser("analyze")
ana.add_argument("-f", "--input", required=True)
ana.add_argument("-o", "--output", required=True)
ana.set_defaults(func=analyze)

args = parser.parse_args()
args.func(args)
