import json
import os
import re
from typing import Dict, List

from dotenv import load_dotenv

from findings import FindingsStore
from llm import get_analyser, get_planner
from phases import PHASE_NAMES, PHASE_OBJECTIVES, PHASE_SEQUENCE, PHASE_TOOLS
from prompt import ANALYZER_PROMPT, ATTACK_SURFACE_PROMPT, PLANNER_PROMPT
from ssh_exec import SSHExecutor

load_dotenv()


class BugBountyAgent:
    def __init__(self, target: str, max_steps: int = 5):
        self.target = target.strip().lower()
        self.max_steps_per_phase = max_steps

        self.password = os.getenv("KALI_SSH_PASSWORD")

        self.planner = get_planner()
        self.analyzer = get_analyser()

        self.ssh = SSHExecutor(
            host="127.0.0.1",
            port=2222,
            username="aalok",
            password=self.password,
        )

        self.findings = FindingsStore(self.target)

        self.phases = PHASE_SEQUENCE
        self.current_phase = 0
        self.phase_steps = {phase: 0 for phase in self.phases}

        self.executed_commands: List[str] = []
        self.executed_command_signatures: set[str] = set()
        self.history: List[Dict] = []

        self.context = self._build_context_header()

    def _build_context_header(self) -> str:
        return (
            f"Target: {self.target}\n"
            f"Current Findings Summary: {self.findings.summary()}\n"
        )

    def _recon_dir(self) -> str:
        return f"recon/{self.target}"

    def _all_subdomains_file(self) -> str:
        return f"{self._recon_dir()}/all_subdomains.txt"

    def _httpx_file(self) -> str:
        return f"{self._recon_dir()}/httpx_out.txt"

    def _gau_file(self) -> str:
        return f"{self._recon_dir()}/gau_urls.txt"

    def _phase_name(self) -> str:
        phase = self.phases[self.current_phase]
        return PHASE_NAMES.get(phase, phase)

    def _phase_key(self) -> str:
        return self.phases[self.current_phase]

    def _phase_objective(self) -> str:
        return PHASE_OBJECTIVES.get(self._phase_key(), "")

    def _phase_tools(self) -> List[str]:
        return PHASE_TOOLS.get(self._phase_key(), [])

    def connect(self):
        self.ssh.connect()

    def close(self):
        self.ssh.close()

    def _allowed_prefix_pattern(self) -> str:
        escaped = [re.escape(cmd) for cmd in self.ssh.ALLOWED_COMMANDS]
        return "(?:" + "|".join(escaped) + ")"

    def _normalize_command(self, command: str) -> str:
        normalized = command.strip().lower()
        normalized = re.sub(r"\s*\|\s*", " | ", normalized)
        normalized = re.sub(r"\s+", " ", normalized)
        return normalized

    def _command_uses_tool(self, command: str, tool: str) -> bool:
        return bool(re.search(rf"(?<![a-z0-9_-]){re.escape(tool)}(?![a-z0-9_-])", command.lower()))

    def _references_only_target_scope(self, text: str) -> bool:
        domains = re.findall(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", text.lower())
        if not domains:
            return True

        target = self.target
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

    def extract_command(self, text: str) -> str | None:
        match = re.search(r"(?im)^\s*command\s*:\s*(.+?)\s*$", text)
        if match:
            return match.group(1).strip()

        allowed_prefix = self._allowed_prefix_pattern()
        for raw_line in text.splitlines():
            line = raw_line.strip().strip("`")
            if re.match(rf"(?i)^\s*{allowed_prefix}\b", line):
                return line

        quoted_match = re.search(
            rf'"\s*({allowed_prefix}[^"\n]*)\s*"',
            text,
            flags=re.IGNORECASE,
        )
        if quoted_match:
            return quoted_match.group(1).strip()

        return None

    def _extract_phase_complete(self, text: str) -> bool:
        match = re.search(r"(?im)^\s*phase_complete\s*:\s*(true|false)\s*$", text)
        return bool(match and match.group(1).lower() == "true")

    def _is_phase_allowed(self, command: str) -> bool:
        tools = self._phase_tools()
        if not tools:
            return False

        command_lc = command.lower()
        return any(self._command_uses_tool(command_lc, tool) for tool in tools)

    def _is_valid_planner_command(self, command: str) -> bool:
        if not command or not command.strip():
            return False

        signature = self._normalize_command(command)
        if signature in self.executed_command_signatures:
            return False

        if not self._references_only_target_scope(command):
            return False

        if not self.ssh._is_allowed(command):
            return False

        if self.ssh._is_blocked(command):
            return False

        if not self._is_phase_allowed(command):
            return False

        phase = self._phase_key()

        if phase == "subdomain_enum":
            # Ensure at least one enumerator command in this phase.
            if not any(self._command_uses_tool(command, t) for t in ("subfinder", "assetfinder", "sort", "cat")):
                return False

        if phase == "alive_check":
            if self.phase_steps[phase] == 0 and not self._command_uses_tool(command, "httpx"):
                return False

        if phase == "fingerprint":
            if self.phase_steps[phase] == 0 and not (
                self._command_uses_tool(command, "gau") or self._command_uses_tool(command, "waybackurls")
            ):
                return False

        if phase == "vuln_scan":
            blocked_templates = ("fuzzing/", "brute-force/", "dos/")
            cmd_lc = command.lower()
            if any(bt in cmd_lc for bt in blocked_templates):
                return False

        return True

    def _build_fallback_command(self) -> str | None:
        recon_dir = self._recon_dir()
        all_subs = self._all_subdomains_file()
        httpx_out = self._httpx_file()
        gau_out = self._gau_file()

        candidates_by_phase = {
            "subdomain_enum": [
                f"mkdir -p {recon_dir}",
                f"subfinder -d {self.target} -silent -o {recon_dir}/subfinder_out.txt",
                f"assetfinder --subs-only {self.target} | sort -u > {recon_dir}/assetfinder_out.txt",
                f"cat {recon_dir}/subfinder_out.txt {recon_dir}/assetfinder_out.txt | sort -u > {all_subs}",
                f"head -n 100 {all_subs}",
            ],
            "alive_check": [
                f"httpx -l {all_subs} -silent -status-code -title -tech-detect -o {httpx_out}",
                f"cat {httpx_out} | grep -E \"200|301|302|403|401\" | head -n 100",
                f"nmap -sT -p 80,443,8080,8443,3000,5000,9000 {self.target}",
                f"curl -I https://{self.target}",
            ],
            "fingerprint": [
                f"gau {self.target} | sort -u > {gau_out}",
                f"waybackurls {self.target} | sort -u >> {gau_out}",
                f"cat {gau_out} | grep \"?\" | sort -u > {recon_dir}/parameterized_urls.txt",
                f"cat {gau_out} | grep -E \"\\.(php|asp|aspx|jsp|json|xml|env|git|bak|sql|config)$\" | sort -u > {recon_dir}/sensitive_urls.txt",
                f"ffuf -u https://{self.target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403 -o {recon_dir}/ffuf_out.txt",
            ],
            "vuln_scan": [
                f"nuclei -l {recon_dir}/alive_hosts.txt -t exposures/ -t misconfiguration/ -t takeovers/ -severity low,medium,high -o {recon_dir}/nuclei_out.txt",
                f"nuclei -u https://{self.target} -t vulnerabilities/generic/ -o {recon_dir}/nuclei_api.txt",
                f"curl -s https://{self.target}/.env | head -n 20",
                f"cat {recon_dir}/nuclei_out.txt | head -n 100",
            ],
        }

        phase = self._phase_key()
        for cmd in candidates_by_phase.get(phase, []):
            if self._is_valid_planner_command(cmd):
                return cmd
        return None

    def plan_next_step(self) -> str | None:
        prompt = PLANNER_PROMPT.format(
            phase=self._phase_name(),
            phase_objective=self._phase_objective(),
            allowed_tools=", ".join(self._phase_tools()) if self._phase_tools() else "None",
            context=self.context,
        )

        response = self.planner(prompt)
        response = getattr(response, "content", response)
        response = response if isinstance(response, str) else str(response)

        print("\n[PLANNER RAW OUTPUT]")
        print(response)

        command = self.extract_command(response)
        if command and self._is_valid_planner_command(command):
            return command

        fallback = self._build_fallback_command()
        if fallback:
            print("[INFO] Using deterministic fallback command.")
            return fallback

        return None

    def execute_command(self, command: str) -> str | None:
        result = self.ssh.run_command(command)

        if result["error"] and result.get("exit_code", 1) != 0:
            print("\n[EXECUTION ERROR]")
            print(result["error"])
            return None

        if result["error"]:
            print("\n[EXECUTION WARNING]")
            print(result["error"])

        return result["output"]

    def _extract_target_subdomains(self, text: str) -> List[str]:
        target = re.escape(self.target)
        pattern = rf"\b(?:[a-z0-9-]+\.)+{target}\b"
        return sorted(set(re.findall(pattern, text.lower())))

    def _extract_urls(self, text: str) -> List[str]:
        urls = re.findall(r"https?://[^\s\]\)\"']+", text)
        return sorted(set(urls))

    def _extract_httpx_alive_hosts(self, text: str) -> List[Dict]:
        rows: List[Dict] = []
        for line in text.splitlines():
            m = re.match(r"^(https?://[^\s]+)\s+\[(\d{3})\](.*)$", line.strip())
            if not m:
                continue
            url = m.group(1).strip()
            status = int(m.group(2))
            rest = m.group(3)
            host_match = re.match(r"^https?://([^/]+)", url)
            host = host_match.group(1).lower() if host_match else ""
            tech = [t.strip() for t in re.findall(r"\[([^\]]+)\]", rest) if t.strip()]
            rows.append({"host": host, "status": status, "tech": tech, "ports": []})
        return rows

    def _extract_attack_surfaces_from_analysis(self, analysis: str) -> List[Dict[str, str]]:
        section_match = re.search(r"(?is)ATTACK_SURFACES:\s*(.*)$", analysis)
        if not section_match:
            return []

        lines = [ln.strip() for ln in section_match.group(1).splitlines() if ln.strip()]
        surfaces: List[Dict[str, str]] = []
        for line in lines:
            if not line.startswith("-"):
                continue
            payload = line[1:].strip()
            if payload.lower() in {"none", "none."}:
                continue

            surface_type = ""
            endpoint = ""
            suggested_test = ""

            if ":" in payload:
                surface_type, rest = payload.split(":", 1)
                surface_type = surface_type.strip()
            else:
                rest = payload

            if " - " in rest:
                endpoint, suggested_test = rest.split(" - ", 1)
            else:
                endpoint = rest

            endpoint = endpoint.strip()
            suggested_test = suggested_test.strip()
            if endpoint and not self._references_only_target_scope(endpoint):
                continue

            surfaces.append(
                {
                    "surface_type": surface_type,
                    "endpoint": endpoint,
                    "suggested_test": suggested_test,
                }
            )
        return surfaces

    def _extract_attack_surfaces_from_mapping(self, text: str) -> List[Dict[str, str]]:
        blocks = re.split(r"(?im)^ATTACK_SURFACE:\s*", text)
        surfaces: List[Dict[str, str]] = []

        for block in blocks:
            block = block.strip()
            if not block:
                continue

            lines = [ln.rstrip() for ln in block.splitlines() if ln.strip()]
            category = lines[0].strip() if lines else ""
            target_line = ""
            severity = ""
            plan_lines: List[str] = []
            in_plan = False

            for ln in lines[1:]:
                if ln.startswith("TARGET:"):
                    target_line = ln.split(":", 1)[1].strip()
                    in_plan = False
                elif ln.startswith("SEVERITY:"):
                    severity = ln.split(":", 1)[1].strip()
                    in_plan = False
                elif ln.startswith("ATTACK_PLAN:"):
                    in_plan = True
                elif in_plan:
                    plan_lines.append(ln.strip())

            if target_line and not self._references_only_target_scope(target_line):
                continue

            surfaces.append(
                {
                    "surface_type": category,
                    "endpoint": target_line,
                    "severity": severity,
                    "suggested_test": " ".join(plan_lines[:2]).strip(),
                    "attack_plan": "\n".join(plan_lines).strip(),
                }
            )

        return surfaces

    def analyze_output(self, output: str) -> str:
        analyzer_prompt = ANALYZER_PROMPT.format(phase=self._phase_name())
        analyzer_input = f"{analyzer_prompt}\n\n{output[:2000]}"
        analyzed = self.analyzer(analyzer_input)
        analyzed = getattr(analyzed, "content", analyzed)
        analyzed = analyzed if isinstance(analyzed, str) else str(analyzed)

        print("\n[ANALYZED OUTPUT]")
        print(analyzed)

        return analyzed

    def _update_findings_from_command_output(self, command: str, output: str):
        phase = self._phase_key()

        subs = self._extract_target_subdomains(output)
        if subs:
            self.findings.add_subdomains(subs)

        if phase == "alive_check":
            alive_rows = self._extract_httpx_alive_hosts(output)
            if alive_rows:
                self.findings.add_alive_hosts(alive_rows)

        if phase == "fingerprint":
            urls = self._extract_urls(output)
            if urls:
                self.findings.add_endpoints("all_urls", urls)

                parameterized = [u for u in urls if "?" in u]
                if parameterized:
                    self.findings.add_endpoints("parameterized", parameterized)

                sensitive = [
                    u
                    for u in urls
                    if re.search(r"\.(env|git|sql|bak|config|php|asp|aspx|jsp|json|xml)$", u.lower())
                ]
                if sensitive:
                    self.findings.add_endpoints("sensitive_files", sensitive)

                api_eps = [u for u in urls if re.search(r"/api|/graphql|/rest", u.lower())]
                if api_eps:
                    self.findings.add_endpoints("api_endpoints", api_eps)

                admins = [u for u in urls if re.search(r"/admin|/dashboard|/manager|/console", u.lower())]
                if admins:
                    self.findings.add_endpoints("admin_panels", admins)

        if phase == "vuln_scan":
            rows = []
            for ln in output.splitlines():
                line = ln.strip()
                if not line:
                    continue
                rows.append({"tool": "scanner", "target": self.target, "finding": line})
            if rows:
                self.findings.add_vuln_scan_results(rows)

    def update_context(self, command: str, analysis: str):
        self.history.append({"command": command, "analysis": analysis, "phase": self._phase_key()})
        self.executed_commands.append(command)
        self.executed_command_signatures.add(self._normalize_command(command))

        attack_surfaces = self._extract_attack_surfaces_from_analysis(analysis)
        if attack_surfaces:
            self.findings.add_attack_surfaces(attack_surfaces)

        self.context += (
            f"\nPhase: {self._phase_name()}\n"
            f"Command: {command}\n"
            f"Analysis Summary: {analysis}\n"
            f"Updated Findings Summary: {self.findings.summary()}\n"
        )

        max_context = 4500
        if len(self.context) > max_context:
            self.context = self.context[-max_context:]

    def check_phase_advance(self, analysis: str) -> bool:
        if self._extract_phase_complete(analysis):
            if self.current_phase < len(self.phases) - 1:
                self.current_phase += 1
                print(f"\n[PHASE] Advancing to: {self._phase_name()}")
                return True
        return False

    def run_attack_surface_phase(self):
        findings_json = json.dumps(self.findings.data, indent=2)
        prompt = ATTACK_SURFACE_PROMPT.format(findings_json=findings_json)

        result = self.analyzer(prompt)
        result = getattr(result, "content", result)
        result = result if isinstance(result, str) else str(result)

        print("\n[ATTACK SURFACE MAP]")
        print(result)

        surfaces = self._extract_attack_surfaces_from_mapping(result)
        if surfaces:
            self.findings.add_attack_surfaces(surfaces)

        self.context += (
            f"\nPhase: {self._phase_name()}\n"
            f"Attack Surface Mapping:\n{result}\n"
            f"Updated Findings Summary: {self.findings.summary()}\n"
        )

    def generate_final_report(self):
        report_path = f"final_report_{self.target.replace('.', '_')}.md"
        lines = [
            f"# Final Recon Report: {self.target}",
            "",
            "## Summary",
            self.findings.summary(),
            "",
            "## Subdomains",
        ]

        for sub in self.findings.data.get("subdomains", []):
            lines.append(f"- {sub}")

        lines.extend(["", "## Alive Hosts"])
        for host in self.findings.data.get("alive_hosts", []):
            if isinstance(host, dict):
                lines.append(
                    f"- {host.get('host')} | status={host.get('status')} | tech={', '.join(host.get('tech', []))}"
                )
            else:
                lines.append(f"- {host}")

        lines.extend(["", "## Endpoints"])
        endpoints = self.findings.data.get("endpoints", {})
        for category, values in endpoints.items():
            lines.append(f"### {category}")
            for value in values:
                lines.append(f"- {value}")
            lines.append("")

        lines.extend(["## Attack Surfaces"])
        for surface in self.findings.data.get("attack_surfaces", []):
            lines.append(
                f"- {surface.get('surface_type', 'Unknown')}: {surface.get('endpoint', '')} "
                f"| severity={surface.get('severity', 'N/A')}"
            )
            if surface.get("attack_plan"):
                lines.append(f"  plan: {surface.get('attack_plan')}")

        lines.extend(["", "## Vulnerability Scan Results"])
        for row in self.findings.data.get("vuln_scan_results", []):
            lines.append(f"- {row.get('finding', '')}")

        with open(report_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

        print(f"\n[REPORT] Wrote {report_path}")

    def run(self):
        self.connect()

        total_steps = self.max_steps_per_phase * len(self.phases)

        try:
            print(f"[PHASE] Starting: {self._phase_name()}")

            for step in range(total_steps):
                if self.current_phase >= len(self.phases):
                    break

                phase_name = self._phase_name()
                phase_key = self._phase_key()
                print(f"\n=== STEP {step + 1} | PHASE: {phase_name} ===")

                if phase_key == "attack_surface_map":
                    self.run_attack_surface_phase()
                    if self.current_phase < len(self.phases) - 1:
                        self.current_phase += 1
                        print(f"\n[PHASE] Advancing to: {self._phase_name()}")
                    continue

                command = self.plan_next_step()
                if not command:
                    print("[INFO] No valid command from planner/fallback; advancing phase.")
                    if self.current_phase < len(self.phases) - 1:
                        self.current_phase += 1
                        print(f"\n[PHASE] Advancing to: {self._phase_name()}")
                    continue

                print(f"\n[EXECUTING] {command}")
                output = self.execute_command(command)
                if output is None:
                    self.phase_steps[phase_key] += 1
                    if self.phase_steps[phase_key] >= self.max_steps_per_phase and self.current_phase < len(self.phases) - 1:
                        print("[INFO] Phase step limit reached after execution errors; advancing phase.")
                        self.current_phase += 1
                        print(f"\n[PHASE] Advancing to: {self._phase_name()}")
                    continue

                self._update_findings_from_command_output(command, output)
                analysis = self.analyze_output(output)
                self.update_context(command, analysis)

                self.phase_steps[phase_key] += 1
                advanced = self.check_phase_advance(analysis)

                if not advanced and self.phase_steps[phase_key] >= self.max_steps_per_phase:
                    if self.current_phase < len(self.phases) - 1:
                        print("[INFO] Phase step limit reached; forcing advance.")
                        self.current_phase += 1
                        print(f"\n[PHASE] Advancing to: {self._phase_name()}")

        finally:
            self.close()
            self.generate_final_report()
            print("\nExecution completed.")


if __name__ == "__main__":
    try:
        input_tar = input("Enter target domain (default: example.com): ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\nUsing default target...")
        input_tar = ""

    target = input_tar if input_tar else "example.com"

    agent = BugBountyAgent(target=target, max_steps=5)
    agent.run()
