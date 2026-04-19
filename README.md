# LLM-Bug-Hunter

An autonomous bug bounty reconnaissance agent that connects to a Kali Linux VM over SSH and performs systematic vulnerability discovery across five distinct phases. The LLM directs the entire workflow, executing reconnaissance commands and analyzing results in real-time.

## What This Project Contains

- `agent_loop.py`
	Main BugBountyAgent class orchestrating the five-phase reconnaissance workflow.
	Manages phase transitions, command execution, output analysis, and findings persistence.

- `phases.py`
	Phase definitions and configuration (objectives, allowed tools, phase sequence).
	Ensures the agent stays within scope for each reconnaissance stage.

- `findings.py`
	FindingsStore class managing all discovered assets and findings.
	Persists results to findings.json and provides structured data access.

- `prompt.py`
	LLM prompts for planner (command generation), analyzer (output interpretation), and attack surface mapping.

- `ssh_exec.py`
	SSH executor wrapper using Paramiko.
	Handles SSH connection and remote command execution.

- `llm.py`
	LLM provider setup using Hugging Face via LangChain.
	Reads API key from `.env`.

- `test_ssh.py`
	Manual connectivity test script.
	Verifies SSH login and sample command execution.

## The Five-Phase Reconnaissance Workflow

The agent systematically moves through five phases, each with clear objectives and tool restrictions:

### Phase 1: Subdomain Enumeration
Discover all subdomains associated with the target using passive reconnaissance tools.
- **Tools:** subfinder, assetfinder, amass (passive only)
- **Output:** all_subdomains.txt
- **Completion:** Deduplicated list saved, no new subdomains discovered

### Phase 2: Alive Check & Tech Fingerprinting
Probe subdomains to identify live hosts, HTTP status codes, and technology stacks.
- **Tools:** httpx, nmap (TCP connect, no sudo), curl
- **Output:** alive_hosts in findings.json with status codes and tech stack
- **Completion:** Live hosts identified with tech fingerprinting complete

### Phase 3: Endpoint & Parameter Discovery
Find all accessible endpoints, parameters, and sensitive files on alive hosts.
- **Tools:** gau, waybackurls, ffuf, grep, sed
- **Output:** endpoints, parameterized URLs, sensitive files, API patterns
- **Completion:** Parameter enumeration and fuzzing complete on high-value hosts

### Phase 4: Attack Surface Mapping
Pure reasoning phase—LLM analyzes all findings and produces a structured attack plan.
- **Tools:** None (no SSH commands)
- **Output:** Attack surfaces categorized (IDOR, SQLi, SSRF, XSS, auth bypass, etc.)
- **Completion:** Attack plan generated for Phase 5

### Phase 5: Vulnerability Scanning
Execute targeted, non-destructive scans based on Phase 4's attack map.
- **Tools:** nuclei (safe templates only), curl, grep
- **Output:** nuclei scan results, curl verification of high-priority targets
- **Completion:** Vulnerability assessment complete, final report generated

## Environment Setup

Install dependencies:

```powershell
D:/Python/python.exe -m pip install paramiko python-dotenv langchain langchain-community langchain-huggingface huggingface_hub
```

Create a `.env` file in project root:

```env
KALI_SSH_PASSWORD=your_kali_password
HUGGINGFACE_API_KEY=your_hf_token
```

## Prerequisites for Kali VM

- SSH service running: `sudo service ssh start`
- Port forwarding: Host `127.0.0.1:2222` -> Guest SSH port `22`
- Non-sudo user account for SSH login
- Required tools installed:
  ```bash
  sudo apt update && sudo apt install -y subfinder assetfinder amass httpx nmap gau waybackurls ffuf nuclei curl
  ```

## First Run

1. Test SSH executor first:

```powershell
D:/Python/python.exe .\test_ssh.py
```

Expected: Successful connection with command outputs (`whoami`, `pwd`, `ls -la`, etc.)

2. Run the bug bounty agent:

```powershell
D:/Python/python.exe .\agent_loop.py <target_domain>
```

Example: `D:/Python/python.exe .\agent_loop.py example.com`

Expected flow:
- Prints current phase and step number
- LLM generates appropriate reconnaissance command for the phase
- Command executes on Kali VM
- Output analyzed and added to findings.json
- Phase advances when objective is complete
- Final report generated after all phases complete

## Findings Output

All discovered assets and vulnerabilities are persisted to `findings_<target>.json`, organized by phase:

```json
{
  "target": "example.com",
  "subdomains": [...],
  "alive_hosts": [...],
  "endpoints": {...},
  "attack_surface": [...],
  "vulnerabilities": [...]
}
```

A detailed markdown report is also generated as `final_report_<target>.md`.

## Notes & Best Practices

- **Never commit `.env`** — keep API keys and passwords out of version control
- **Use a non-sudo Kali user** for all SSH operations to maintain security boundaries
- **Phase progression is automatic** — the LLM signals `PHASE_COMPLETE: true` when objectives are met
- **Tool restrictions are enforced per phase** — the LLM cannot use tools outside its current phase's allowed list
- **Command deduplication** — the agent tracks executed commands to avoid repeating reconnaissance
- **Non-destructive scanning only** — nuclei uses safe passive/detect templates; no fuzzing or brute-force tools
