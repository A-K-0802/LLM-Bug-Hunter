import paramiko
from paramiko import SSHClient


class SSHExecutorError(Exception):
    """Raised when connecting to SSH or executing command fails."""


class SSHExecutor:
    # Allowed tools for the agent
    ALLOWED_COMMANDS = [
        "nmap",
        "ffuf",
        "curl",
        "ls",
        "pwd",
        "cat",
        "gau",
        "jq",
        "head",
        "sed",
    ]

    BLOCKED_PATTERNS = [
        "rm ",
        "shutdown",
        "reboot",
        "mkfs",
        ":(){",  # fork bomb
    ]

    def __init__(
        self,
        host,
        port,
        username,
        password,
        connect_timeout=10,
        banner_timeout=15,
        auth_timeout=15,
    ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.connect_timeout = connect_timeout
        self.banner_timeout = banner_timeout
        self.auth_timeout = auth_timeout
        self.client: SSHClient | None = None

    # ---------------------------
    # Connection
    # ---------------------------
    def connect(self):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            self.client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=self.connect_timeout,
                banner_timeout=self.banner_timeout,
                auth_timeout=self.auth_timeout,
                look_for_keys=False,
                allow_agent=False,
            )
        except Exception as exc:
            self.client = None
            raise SSHExecutorError(
                f"Failed to connect to {self.host}:{self.port} as '{self.username}': {exc}"
            ) from exc

    # ---------------------------
    # Validation
    # ---------------------------
    def _is_allowed(self, command: str) -> bool:
        return any(command.startswith(cmd) for cmd in self.ALLOWED_COMMANDS)

    def _is_blocked(self, command: str) -> bool:
        return any(pattern in command for pattern in self.BLOCKED_PATTERNS)


    def _process_output(self, output: str) -> str:
        MAX_LEN = 2000

        if len(output) > MAX_LEN:
            return output[:MAX_LEN] + "\n...[truncated]"

        return output


    def read_file_head(self, filepath: str, lines: int = 100):
        command = f"head -n {lines} {filepath}"
        return self.run_command(command)
    
    def read_file_chunk(self, filepath: str, start: int, size: int = 100):
        end = start + size
        command = f"sed -n '{start},{end}p' {filepath}"
        return self.run_command(command)
    
    def read_json_chunk(self, filepath: str, limit: int = 20):
        command = f"jq '.results[:{limit}]' {filepath}"
        return self.run_command(command)
    # ---------------------------
    # Execution
    # ---------------------------
    def run_command(self, command: str, timeout: int | None = None):
        if self.client is None:
            raise SSHExecutorError("SSH client not connected. Call connect() first.")

        if not command or not command.strip():
            raise SSHExecutorError("Command cannot be empty.")

        if timeout is None:
            if command.startswith("ffuf"):
                timeout = 900   # 15 minutes
            elif command.startswith("nmap"):
                timeout = 300   # 5 minutes
            else:
                timeout = 60    # default


        if self._is_blocked(command):
            return {
                "command": command,
                "output": "",
                "error": "Blocked unsafe command",
                "exit_code": -1,
            }

        if not self._is_allowed(command):
            return {
                "command": command,
                "output": "",
                "error": "Command not allowed",
                "exit_code": -1,
            }

        try:
            _stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)

            raw_output = stdout.read().decode(errors="replace")
            
            error = stderr.read().decode(errors="replace")
            output = self._process_output(raw_output)
            exit_code = stdout.channel.recv_exit_status()

            # Trim output (VERY important for LLMs)
            MAX_LEN = 2000
            if len(output) > MAX_LEN:
                output = output[:MAX_LEN] + "\n...[truncated]"

            return {
                "command": command,
                "output": output.strip(),
                "error": error.strip(),
                "exit_code": exit_code,
            }

        except Exception as exc:
            raise SSHExecutorError(f"Command failed: {command!r}: {exc}") from exc

    # ---------------------------
    # Cleanup
    # ---------------------------
    def close(self):
        if self.client:
            self.client.close()
            self.client = None