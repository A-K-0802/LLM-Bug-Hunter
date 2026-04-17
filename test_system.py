import os
from dotenv import load_dotenv

from ssh_exec import SSHExecutor, SSHExecutorError

load_dotenv()

PASSWORD = os.getenv("KALI_SSH_PASSWORD")


def print_section(title):
    print("\n" + "=" * 20 + f" {title} " + "=" * 20)


def test_connection(ssh):
    print_section("CONNECTION TEST")
    try:
        ssh.connect()
        print("Connection successful")
    except Exception as e:
        print("Connection failed:", e)


def test_basic_commands(ssh):
    print_section("BASIC COMMANDS")

    commands = [
        "whoami",
        "pwd",
        "ls"
    ]

    for cmd in commands:
        try:
            result = ssh.run_command(cmd)
            print(f"\nCommand: {cmd}")
            print("Output:", result["output"][:200])
            print("Error:", result["error"])
            print("Exit Code:", result["exit_code"])
        except Exception as e:
            print(f"Error running {cmd}:", e)


def test_blocked_commands(ssh):
    print_section("BLOCKED COMMAND TEST")

    commands = [
        "rm -rf /",
        "shutdown now",
        ":(){ :|:& };:"
    ]

    for cmd in commands:
        result = ssh.run_command(cmd)
        print(f"\nCommand: {cmd}")
        print("Expected: blocked")
        print("Actual:", result["error"])


def test_not_allowed_commands(ssh):
    print_section("NOT ALLOWED COMMAND TEST")

    commands = [
        "python3 --version",
        "gcc --version"
    ]

    for cmd in commands:
        result = ssh.run_command(cmd)
        print(f"\nCommand: {cmd}")
        print("Expected: not allowed")
        print("Actual:", result["error"])


def test_timeout_behavior(ssh):
    print_section("TIMEOUT TEST")

    try:
        # Simulates long-running command
        result = ssh.run_command("sleep 2")
        print("Short sleep success")

        # This should still work due to adaptive timeout
        result = ssh.run_command("sleep 5")
        print("Long sleep handled correctly")

    except SSHExecutorError as e:
        print("Timeout handling failed:", e)


def test_output_trimming(ssh):
    print_section("OUTPUT TRIMMING TEST")

    # generate large output
    result = ssh.run_command("ls -R /usr")

    output = result["output"]
    print("Output length:", len(output))

    if "[truncated]" in output:
        print("Trimming works correctly")
    else:
        print("Trimming may not be working")


def test_exit_codes(ssh):
    print_section("EXIT CODE TEST")

    result = ssh.run_command("ls")
    print("Valid command exit code:", result["exit_code"])

    result = ssh.run_command("ls non_existent_file")
    print("Invalid command exit code:", result["exit_code"])


def main():
    ssh = SSHExecutor(
        host="127.0.0.1",
        port=2222,
        username="aalok",
        password=PASSWORD
    )

    try:
        test_connection(ssh)
        test_basic_commands(ssh)
        test_blocked_commands(ssh)
        test_not_allowed_commands(ssh)
        test_timeout_behavior(ssh)
        test_output_trimming(ssh)
        test_exit_codes(ssh)

    finally:
        ssh.close()
        print_section("TEST COMPLETE")


if __name__ == "__main__":
    main()