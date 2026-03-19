# LLM-Bug-Hunter
Giving an LLM acess to kali linux to see the efficiency of the LLM on hunting bugs in bug bounty programs. No sudo access to be given.

Using Port forwarding to send commands to a remote terminal of KALI.

### Steps for port forwarding setup:

1. Setup SSH connection with KALI using port forwarding (using virtualbox) - add port forwarding options in network setting of virtual machine.
2. On KALI, start ssh services using "sudo service ssh start". Check this using "sudo service ssh status".
3. On windows powershell, check service via, "ssh <username_kali>@<ip_mentioned_in_portForwarding> -p <port_mentioned>"
