from paramiko import SSHClient
import paramiko


class SSHExecutorError(Exception):
    """Raised when connecting to SSH or executing command fails."""


class SSHExecutor:
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

    def run_command(self, command, timeout=30):
        if self.client is None:
            raise SSHExecutorError("SSH client not connected. Call connect() first.")

        if not command or not command.strip():
            raise SSHExecutorError("Command cannot be empty.")

        try:
            _stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)

            output = stdout.read().decode(errors="replace")
            error = stderr.read().decode(errors="replace")
            exit_code = stdout.channel.recv_exit_status()

            return {
                "command": command,
                "output": output.strip(),
                "error": error.strip(),
                "exit_code": exit_code,
            }
        except Exception as exc:
            raise SSHExecutorError(f"Command failed: {command!r}: {exc}") from exc

    def close(self):
        if self.client:
            self.client.close()
            self.client = None
