import os
import re
from typing import List, Dict

from dotenv import load_dotenv

from ssh_exec import SSHExecutor
from llm import get_planner, get_analyser
from prompt import PLANNER_PROMPT, ANALYZER_PROMPT
from phases import PHASE_SEQUENCE, PHASE_NAMES, PHASE_OBJECTIVES, PHASE_TOOLS

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
        self.executed_command_signatures: set[str] = set()
        self.current_phase_index = 0
        self.pending_phase_complete = False
        self.subfinder_output_saved = False

        # Context buffer
        self.context = f"Target: {self.target}\n"

    def _subfinder_output_path(self) -> str:
        return f"recon/{self.target}/subfinder.txt"

    def connect(self):
        self.ssh.connect()

    def close(self):
        self.ssh.close()

    def get_current_phase(self) -> str:
        return PHASE_SEQUENCE[self.current_phase_index]

    def get_current_phase_name(self) -> str:
        phase = self.get_current_phase()
        return PHASE_NAMES.get(phase, phase)

    def get_current_phase_objective(self) -> str:
        phase = self.get_current_phase()
        return PHASE_OBJECTIVES.get(phase, "")

    def get_current_phase_tools(self) -> List[str]:
        phase = self.get_current_phase()
        return PHASE_TOOLS.get(phase, [])

    def _advance_phase(self):
        if self.current_phase_index >= len(PHASE_SEQUENCE) - 1:
            return
        self.current_phase_index += 1
        print(f"[PHASE] Advancing to: {self.get_current_phase_name()}")

    def _extract_phase_complete(self, text: str) -> bool:
        match = re.search(r"(?im)^\s*phase_complete\s*:\s*(true|false)\s*$", text)
        return bool(match and match.group(1).lower() == "true")

    def _command_primary_tool(self, command: str) -> str:
        command = command.strip()
        if not command:
            return ""
        return command.split()[0].lower()

    def _normalize_command(self, command: str) -> str:
        normalized = command.strip().lower()
        normalized = re.sub(r"\s*\|\s*", " | ", normalized)
        normalized = re.sub(r"\s+", " ", normalized)
        return normalized

    def _is_subfinder_save_command(self, command: str) -> bool:
        expected = f"subfinder -d {self.target} -silent -o {self._subfinder_output_path()}"
        return self._normalize_command(command) == self._normalize_command(expected)

    def _references_only_target_scope(self, command: str) -> bool:
        # Reject explicit external domains. Keep localhost/private/internal literals out of scope checks.
        domains = re.findall(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", command.lower())
        if not domains:
            return True

        target = self.target.lower().strip()
        file_like_suffixes = (
            ".txt",
            ".json",
            ".md",
            ".log",
            ".yaml",
            ".yml",
            ".csv",
            ".xml",
        )
        for domain in domains:
            if domain.endswith(file_like_suffixes):
                continue
            if domain == target or domain.endswith(f".{target}"):
                continue
            return False
        return True

    def _is_phase_allowed(self, command: str) -> bool:
        primary = self._command_primary_tool(command)
        return primary in self.get_current_phase_tools()

    def _allowed_prefix_pattern(self) -> str:
        escaped = [re.escape(cmd) for cmd in self.ssh.ALLOWED_COMMANDS]
        return "(?:" + "|".join(escaped) + ")"

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
        allowed_prefix = self._allowed_prefix_pattern()
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
        signature = self._normalize_command(command)
        if signature in self.executed_command_signatures:
            return False
        if not self._references_only_target_scope(command):
            return False
        if not self._is_phase_allowed(command):
            return False
        if self.ssh._is_blocked(command):
            return False
        if not self.ssh._is_allowed(command):
            return False

        # Subdomain phase must persist subfinder output before allowing preview loops.
        if self.get_current_phase() == "subdomain_enum":
            if command.startswith("subfinder"):
                if self.subfinder_output_saved:
                    return False
                if not self._is_subfinder_save_command(command):
                    return False

        return True

    def _repair_planner_output(self, raw_output: str) -> str | None:
        repair_prompt = f"""
                You previously returned an invalid planner output.

                Current phase: {self.get_current_phase_name()}
                Allowed tools for this phase:
                {', '.join(self.get_current_phase_tools())}

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

        repaired = self.planner(repair_prompt)
        repaired = getattr(repaired, "content", repaired)
        repaired = repaired if isinstance(repaired, str) else str(repaired)

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
        phase = self.get_current_phase()
        candidates_by_phase = {
            "subdomain_enum": [
                f"mkdir -p recon/{self.target}",
                f"subfinder -d {self.target} -silent -o recon/{self.target}/subfinder.txt",
                f"cat recon/{self.target}/subfinder.txt | head -n 50",
            ],
            "url_enum": [
                f"gau {self.target} | head -n 100",
                f"gau {self.target} | sed -n '1,120p'",
                f"waybackurls {self.target} | head -n 100",
            ],
            "live_host_validation": [
                f"cat recon/{self.target}/subfinder.txt | httpx -silent | head -n 100",
                f"cat recon/{self.target}/subfinder.txt | sort -u | head -n 100",
            ],
            "attack_surface_map": [
                f"cat recon/{self.target}/subfinder.txt | head -n 20",
                f"curl -s https://{self.target} | head -n 40",
                "ls",
            ],
        }
        candidates = candidates_by_phase.get(phase, ["ls"])

        for cmd in candidates:
            if self._is_valid_planner_command(cmd):
                return cmd
        return None

    def _auto_advance_phase(self, command: str) -> bool:
        phase = self.get_current_phase()
        if phase == "subdomain_enum" and self._is_subfinder_save_command(command):
            self.subfinder_output_saved = True
            print("[PHASE] Subdomain output saved, advancing phase.")
            self._advance_phase()
            self.pending_phase_complete = False
            return True

        if phase == "url_enum" and (command.startswith("gau") or command.startswith("waybackurls")):
            print("[PHASE] URL enumeration signal detected, advancing phase.")
            self._advance_phase()
            self.pending_phase_complete = False
            return True

        if phase == "live_host_validation" and command.startswith("httpx"):
            print("[PHASE] Live host validation signal detected, advancing phase.")
            self._advance_phase()
            self.pending_phase_complete = False
            return True

        return False

    # ---------------------------
    # Planner Step
    # ---------------------------
    def plan_next_step(self) -> str | None:
        prompt = PLANNER_PROMPT.format(
            phase=self.get_current_phase_name(),
            phase_objective=self.get_current_phase_objective(),
            allowed_tools=", ".join(self.get_current_phase_tools()),
            context=self.context,
        )

        response = self.planner(prompt)
        response = getattr(response, "content", response)
        response = response if isinstance(response, str) else str(response)
        self.pending_phase_complete = self._extract_phase_complete(response)
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

        # Detect persisted subdomain output command even if it has no stdout.
        if self._is_subfinder_save_command(command) and result.get("exit_code", 1) == 0:
            self.subfinder_output_saved = True

        
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
        analyzer_prompt = ANALYZER_PROMPT.format(phase=self.get_current_phase_name())
        analyzer_input = f"{analyzer_prompt}\n\n{output}"
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
        self.executed_command_signatures.add(self._normalize_command(command))

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
            print(f"[PHASE] Starting: {self.get_current_phase_name()}")
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
                auto_advanced = self._auto_advance_phase(command)

                if self.pending_phase_complete and not auto_advanced:
                    self.pending_phase_complete = False
                    self._advance_phase()

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