from scapy.all import sniff, IP, TCP, UDP
import sys

OUTPUT_FILE = "packet_log.txt"

def packet_callback(packet, output_file):
    try:
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            protocol = packet[IP].proto

            output_file.write(f"Source IP: {ip_src}\n")
            output_file.write(f"Destination IP: {ip_dst}\n")
            
            if protocol == 6:
                output_file.write("Protocol: TCP\n")
            elif protocol == 17:
                output_file.write("Protocol: UDP\n")
            else:
                output_file.write(f"Protocol: {protocol}\n")

            if TCP in packet:
                payload = packet[TCP].payload
            elif UDP in packet:
                payload = packet[UDP].payload
            else:
                payload = None
            
            if payload:
                output_file.write(f"Payload: {bytes(payload)}\n")
            output_file.write("-" * 50 + "\n")
    except KeyboardInterrupt:
        print("Keyboard interrupt detected. Stopping packet sniffer...")
        output_file.close()
        sys.exit(0)

def main():
    print("Starting packet sniffer...")
    with open(OUTPUT_FILE, 'w') as output_file:
        try:
            sniff(prn=lambda packet: packet_callback(packet, output_file), store=0)
        except KeyboardInterrupt:
            print("\nKeyboard interrupt detected. Stopping packet sniffer...")
            output_file.close()

    print(f"Packet sniffing complete. Results saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
