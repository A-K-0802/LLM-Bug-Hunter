import os
import dotenv

from ssh_exec import SSHExecutor, SSHExecutorError

dotenv.load_dotenv()
PASSWORD = os.getenv("KALI_SSH_PASSWORD")

if not PASSWORD:
    raise RuntimeError("Set KALI_SSH_PASSWORD before running this script.")

ssh = SSHExecutor(
    host="127.0.0.1",
    port=2222,
    username="aalok",
    password=PASSWORD
)

try:
    print("[+] Connecting to Kali...")
    ssh.connect()
    print("[+] Connected!\n")

    # Test 1: whoami
    result = ssh.run_command("whoami")
    print("=== whoami ===")
    print(result)

    # Test 2: current directory
    result = ssh.run_command("pwd")
    print("\n=== pwd ===")
    print(result)

    # Test 3: list files
    result = ssh.run_command("ls -la")
    print("\n=== ls -la ===")
    print(result)

    # Test 4: basic network command
    result = ssh.run_command("ip a | head -n 5")
    print("\n=== ip a (partial) ===")
    print(result)

except SSHExecutorError as exc:
    print(f"[-] SSH error: {exc}")

except Exception as exc:
    print(f"[-] Unexpected error: {exc}")

finally:
    ssh.close()
    print("\n[+] Connection closed")