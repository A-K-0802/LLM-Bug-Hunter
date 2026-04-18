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


def read_file_head(filepath: str) -> str:
    result = ssh.read_file_head(filepath, lines=100)
    return result["output"]


def read_file_chunk(input_str: str) -> str:
    """
    Input format: filepath,start,size
    Example: result.json,0,50
    """
    try:
        filepath, start, size = input_str.split(",")
        result = ssh.read_file_chunk(filepath, int(start), int(size))
        return result["output"]
    except Exception:
        return "Invalid input format. Use: filepath,start,size"


def read_json_chunk(filepath: str) -> str:
    result = ssh.read_json_chunk(filepath, limit=20)
    return result["output"]

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


