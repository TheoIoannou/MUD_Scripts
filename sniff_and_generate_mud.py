import scapy.all as scapy
import time
import json
import os

DEVICE_MAC = "c0:5d:89:dd:ef:44"
MUD_PROFILE_PATH = "/home/theodoros/mud_profiles/esp32-DDEF44.json"
CAPTURE_DURATION = 120  # seconds

def capture_ips():
    allowed_ips = set()

    def packet_callback(packet):
        if packet.haslayer(scapy.IP):
            src_mac = packet.src.lower()
            dst_ip = packet[scapy.IP].dst
            if src_mac == DEVICE_MAC:
                if dst_ip not in allowed_ips:
                    print(f"Captured allowed IP: {dst_ip}")
                    allowed_ips.add(dst_ip)

    print(f"Sniffing traffic for {CAPTURE_DURATION} seconds to detect allowed IPs...")
    scapy.sniff(iface="wlan0", prn=packet_callback, timeout=CAPTURE_DURATION)

    return list(allowed_ips)

def generate_mud_profile(allowed_ips):
    mud = {
        "mud-version": 1,
        "mud-url": "http://example.com/mud/esp32-DDEF44.json",
        "last-update": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "cache-validity": 3600,
        "is-supported": True,
        "systeminfo": "ESP32 test device",
        "from-device-policy": [{"access": "permit", "protocol": "icmp", "to-ipv4": ip} for ip in allowed_ips],
        "to-device-policy": []
    }

    os.makedirs(os.path.dirname(MUD_PROFILE_PATH), exist_ok=True)
    with open(MUD_PROFILE_PATH, "w") as f:
        json.dump(mud, f, indent=4)
    print(f"MUD profile saved at {MUD_PROFILE_PATH}")

def main():
    if os.path.exists(MUD_PROFILE_PATH):
        print("MUD profile already exists. No need to sniff again.")
        return

    allowed_ips = capture_ips()

    if allowed_ips:
        generate_mud_profile(allowed_ips)
    else:
        print("No allowed IPs captured. MUD not generated.")

if __name__ == "__main__":
    main()
