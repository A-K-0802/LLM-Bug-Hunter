import os
import re
from typing import List, Dict

from dotenv import load_dotenv

from ssh_exec import SSHExecutor
from llm import get_planner, get_analyser
from prompt import PLANNER_PROMPT, ANALYZER_PROMPT

load_dotenv()


class BugBountyAgent:
    def __init__(self, target: str, max_steps: int = 5):
        self.target = target
        self.max_steps = max_steps

        self.password = os.getenv("KALI_SSH_PASSWORD")

        # LLMs
        self.planner = get_planner()
        self.analyzer = get_analyser()

        # SSH Executor
        self.ssh = SSHExecutor(
            host="127.0.0.1",
            port=2222,
            username="aalok",
            password=self.password
        )

        # Memory
        self.executed_commands: List[str] = []
        self.history: List[Dict] = []

        # Context buffer
        self.context = f"Target: {self.target}\n"

    def connect(self):
        self.ssh.connect()

    def close(self):
        self.ssh.close()

    # ---------------------------
    # Parsing Utilities
    # ---------------------------
    def extract_command(self, text: str) -> str | None:
        """
        Extract command from a planner response.
        Accepts minor formatting variations like extra spaces or casing.
        """
        match = re.search(r"(?im)^\s*command\s*:\s*(.+?)\s*$", text)
        if match:
            return match.group(1).strip()

        # Fallback: if the model outputs a bare command line, accept it.
        allowed_prefix = r"(?:subfinder|gau|mkdir|ls|cat|head|sed|jq)"
        for raw_line in text.splitlines():
            line = raw_line.strip().strip("`")
            if re.match(rf"(?i)^\s*{allowed_prefix}\b", line):
                return line

        # Fallback: extract a quoted command from narrative text.
        quoted_match = re.search(
            rf'"\s*({allowed_prefix}[^"\n]*)\s*"',
            text,
            flags=re.IGNORECASE,
        )
        if quoted_match:
            return quoted_match.group(1).strip()
        return None

    def _is_valid_planner_command(self, command: str) -> bool:
        if not command:
            return False
        if command in self.executed_commands:
            return False
        if self.ssh._is_blocked(command):
            return False
        if not self.ssh._is_allowed(command):
            return False
        return True

    def _repair_planner_output(self, raw_output: str) -> str | None:
        repair_prompt = f"""
You previously returned an invalid planner output.

Allowed tools:
subfinder, gau, ls, cat, head, sed, jq

Return exactly one line in this format:
COMMAND: <single linux command>

Do not output anything else.
Do not ask questions.
Do not request more context.

Context:
{self.context}

Previous invalid output:
{raw_output}
"""

        repaired = self.planner.invoke(repair_prompt)
        if hasattr(repaired, "content"):
            repaired = repaired.content

        print("\n[PLANNER REPAIR RAW OUTPUT]")
        print(repaired)

        repaired_cmd = self.extract_command(repaired)
        if repaired_cmd and self._is_valid_planner_command(repaired_cmd):
            return repaired_cmd
        return None

    def _build_fallback_command(self) -> str | None:
        """
        Deterministic safe fallback if planner output is invalid.
        """
        candidates = [
            f"mkdir -p recon/{self.target}",
            f"subfinder -d {self.target} -silent | head -n 50",
            f"subfinder -d {self.target} -silent -o recon/{self.target}/subfinder.txt",
            f"gau {self.target} | head -n 100",
            f"gau {self.target} | sed -n '1,120p'",
            "ls",
        ]

        for cmd in candidates:
            if self._is_valid_planner_command(cmd):
                return cmd
        return None

    # ---------------------------
    # Planner Step
    # ---------------------------
    def plan_next_step(self) -> str | None:
        prompt = PLANNER_PROMPT.format(context=self.context)

        response = self.planner(prompt)
        response = getattr(response, "content", response)
        response = response if isinstance(response, str) else str(response)
        command = self.extract_command(response)

        print("\n[PLANNER RAW OUTPUT]")
        print(response)

        if command and self._is_valid_planner_command(command):
            return command

        fallback = self._build_fallback_command()
        if fallback:
            print("[INFO] Using deterministic fallback command.")
            return fallback

        repaired = self._repair_planner_output(response)
        if repaired:
            return repaired

        print("Planner failed to produce a valid command.")
        return None

    # ---------------------------
    # Execution Step
    # ---------------------------
    def execute_command(self, command: str) -> str | None:
        result = self.ssh.run_command(command)

        if result["error"] and result.get("exit_code", 1) != 0:
            print("\n[EXECUTION ERROR]")
            print(result["error"])
            return None
        elif result["error"]:
            print("\n[EXECUTION WARNING]")
            print(result["error"])

        output = result["output"]

        
        if len(output) > 1500 or "[truncated]" in output.lower():
            print("\n[INFO] Large output detected")

            self.context += """
    NOTE:
    The previous command produced large output.

    Do NOT read full output.
    Instead:
    - Use head for preview
    - Use jq for JSON
    - Use sed for partial reading
    """

        
        if command.startswith("subfinder") or command.startswith("gau"):
            print("[INFO] Recon enumeration command detected")

            self.context += """
    NOTE:
    Enumeration output may be large.

    Next step:
    Use 'head' or 'sed' to inspect a subset of lines.
    """

        return output
    # ---------------------------
    # Analysis Step
    # ---------------------------
    def analyze_output(self, output: str) -> str:
        analyzer_input = f"{ANALYZER_PROMPT}\n\n{output}"
        analyzed = self.analyzer(analyzer_input)
        analyzed = getattr(analyzed, "content", analyzed)
        analyzed = analyzed if isinstance(analyzed, str) else str(analyzed)

        print("\n[ANALYZED OUTPUT]")
        print(analyzed)

        return analyzed

    # ---------------------------
    # Context Management
    # ---------------------------
    def update_context(self, command: str, analysis: str):
        entry = {
            "command": command,
            "analysis": analysis
        }

        self.history.append(entry)
        self.executed_commands.append(command)

        self.context += f"""
Command: {command}
Analysis Summary: {analysis}
"""

        # prevent context explosion
        MAX_CONTEXT = 3000
        if len(self.context) > MAX_CONTEXT:
            self.context = self.context[-MAX_CONTEXT:]

    # ---------------------------
    # Main Loop
    # ---------------------------
    def run(self):
        self.connect()

        try:
            for step in range(self.max_steps):
                print(f"\n========== STEP {step + 1} ==========")

                # 1. Plan
                command = self.plan_next_step()
                if not command:
                    break

                print(f"\n[EXECUTING] {command}")

                # 2. Execute
                output = self.execute_command(command)
                if output is None:
                    break

                # trim raw output before analysis
                trimmed_output = output[:2000]

                # 3. Analyze
                analysis = self.analyze_output(trimmed_output)

                # 4. Update memory/context
                self.update_context(command, analysis)

        finally:
            self.close()
            print("\nExecution completed.")


# ---------------------------
# Entry Point
# ---------------------------
if __name__ == "__main__":

    try:
        input_tar = input("Enter target domain (default: example.com): ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\nUsing default target...")
        input_tar = ""
    target = input_tar if input_tar else "example.com"
    agent = BugBountyAgent(
        target=target,
        max_steps=5
    )

    agent.run()