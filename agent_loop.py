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
        Extract command using regex for robustness.
        Expected format:
        COMMAND: <command>
        """
        match = re.search(r"COMMAND:\s*(.+)", text)
        if match:
            return match.group(1).strip()
        return None

    # ---------------------------
    # Planner Step
    # ---------------------------
    def plan_next_step(self) -> str | None:
        prompt = PLANNER_PROMPT.format(context=self.context)

        response = self.planner(prompt)

        command = self.extract_command(response)

        print("\n[PLANNER RAW OUTPUT]")
        print(response)

        if not command:
            print("Planner failed to produce a valid command.")
            return None

        if command in self.executed_commands:
            print("Duplicate command detected. Stopping execution.")
            return None

        return command

    # ---------------------------
    # Execution Step
    # ---------------------------
    def execute_command(self, command: str) -> str | None:
        result = self.ssh.run_command(command)

        if result["error"]:
            print("\n[EXECUTION ERROR]")
            print(result["error"])
            return None

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

        
        if command.startswith("ffuf"):
            print("[INFO] ffuf detected")

            self.context += """
    NOTE:
    ffuf outputs should be saved as JSON.

    Next step:
    Use 'jq' to extract results from result.json
    """

        return output
    # ---------------------------
    # Analysis Step
    # ---------------------------
    def analyze_output(self, output: str) -> str:
        analyzer_input = f"{ANALYZER_PROMPT}\n\n{output}"
        analyzed = self.analyzer(analyzer_input)

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
    agent = BugBountyAgent(
        target="example.com",
        max_steps=5
    )

    agent.run()