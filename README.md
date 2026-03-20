# LLM-Bug-Hunter

This project connects an LLM to a Kali Linux VM over SSH (non-sudo user) and runs step-by-step reconnaissance commands for bug bounty style workflows.

## What This Project Contains

- `ssh_exec.py`
	SSH executor wrapper using Paramiko.
	Handles SSH connection and remote command execution.

- `test_ssh.py`
	Manual connectivity test script.
	Verifies SSH login and sample command execution (`whoami`, `pwd`, `ls -la`, `ip a`).

- `llm.py`
	LLM provider setup using Hugging Face via LangChain.
	Reads API key from `.env`.

- `agent_loop.py`
	Main agent loop.
	Sends context to LLM, parses JSON output, executes one command on Kali, and feeds output back for next step.

## Prerequisites

- Windows host with Python 3.10+
- Kali VM with SSH service enabled
- VirtualBox port forwarding from host to Kali SSH port
- Hugging Face API key

## Port Forwarding Setup (VirtualBox)

1. Open VM network settings and add SSH port forwarding.
2. Example mapping: Host `127.0.0.1:2222` -> Guest `22`.
3. In Kali, start SSH:
	 `sudo service ssh start`
4. Validate from Windows:
	 `ssh <kali_username>@127.0.0.1 -p 2222`

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

## First Run

1. Test SSH executor first:

```powershell
D:/Python/python.exe .\test_ssh.py
```

Expected: successful connection plus command outputs.

2. Run agent loop:

```powershell
D:/Python/python.exe .\agent_loop.py
```

Expected flow:
- prints step number
- prints raw LLM JSON
- executes returned command on Kali
- prints truncated command output

## Notes

- Do not commit `.env`.
- Use a non-sudo Kali user.
- Keep command allowlist strict in `SYSTEM_PROMPT` inside `agent_loop.py`.
