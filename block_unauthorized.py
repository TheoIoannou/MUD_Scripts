import scapy.all as scapy
import json
import subprocess

DEVICE_MAC = "c0:5d:89:dd:ef:44"
MUD_PROFILE_PATH = "/home/theodoros/mud_profiles/esp32-DDEF44.json"

def load_allowed_ips():
    with open(MUD_PROFILE_PATH, "r") as f:
        mud = json.load(f)
        return [rule.get("to-ipv4") for rule in mud.get("from-device-policy", [])]

def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        src_mac = packet.src.lower()
        dst_ip = packet[scapy.IP].dst

        if src_mac == DEVICE_MAC:
            print(f"DEBUG: Packet from {src_mac} -> {dst_ip}")
            print(f"DEBUG: Allowed IPs: {allowed_ips}")

            if dst_ip not in allowed_ips and not dst_ip.startswith("255.255.255"):
                print("\n🚨 ALERT: Unauthorized communication detected!")
                print(f"Source MAC: {src_mac} tried to reach {dst_ip}, which is NOT allowed!")
                print("⛔ Blocking device before it can continue...\n")

                subprocess.run(["sudo", "iptables", "-I", "INPUT", "-m", "mac", "--mac-source", src_mac, "-j", "DROP"])
                subprocess.run(["sudo", "iptables", "-I", "FORWARD", "-m", "mac", "--mac-source", src_mac, "-j", "DROP"])

                # Disconnect immediately
                subprocess.run(["sudo", "iw", "dev", "wlan0", "station", "del", src_mac])

                exit()

if __name__ == "__main__":
    allowed_ips = load_allowed_ips()
    if not allowed_ips:
        print("No allowed IPs found. Exiting.")
        exit(1)

    print("🚀 Monitoring traffic for unauthorized communication...")
    scapy.sniff(iface="wlan0", prn=packet_callback, store=0)
