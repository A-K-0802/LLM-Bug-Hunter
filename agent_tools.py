from langchain.tools import Tool
from ssh_exec import SSHExecutor
import dotenv
import os


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
ssh.connect()

def run_kali_command(command: str) -> str:
    result = ssh.run_command(command)

    if result["error"]:
        return f"ERROR:\n{result['error']}"

    # truncate output (important)
    return result["output"][:1000]


ssh_tool = Tool(
    name="KaliTerminal",
    func=run_kali_command,
    description="""
Use this tool to execute Linux commands on a Kali machine.

Useful for:
- running nmap scans
- directory brute forcing (ffuf)
- checking files (ls, cat)
- making HTTP requests (curl)

Input: a single shell command string
"""
)