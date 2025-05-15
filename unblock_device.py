import subprocess

DEVICE_MAC = "c0:5d:89:dd:ef:44"

print("🔓 Unblocking ESP32...")

commands = [
    ["sudo", "iptables", "-D", "INPUT", "-m", "mac", "--mac-source", DEVICE_MAC, "-j", "DROP"],
    ["sudo", "iptables", "-D", "FORWARD", "-m", "mac", "--mac-source", DEVICE_MAC, "-j", "DROP"]
]

for cmd in commands:
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print(f"⚠️  Command failed or rule not found: {' '.join(cmd)}")

print("✅ ESP32 is now unblocked.")
