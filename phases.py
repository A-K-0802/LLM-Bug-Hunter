PHASE_SEQUENCE = [
    "subdomain_enum",
    "alive_check",
    "fingerprint",
    "attack_surface_map",
    "vuln_scan",
]


PHASE_NAMES = {
    "subdomain_enum": "Subdomain Enumeration",
    "alive_check": "Alive Check and Tech Fingerprinting",
    "fingerprint": "Endpoint and Parameter Discovery",
    "attack_surface_map": "Attack Surface Mapping",
    "vuln_scan": "Vulnerability Scanning",
}


PHASE_OBJECTIVES = {
    "subdomain_enum": "Discover all subdomains and save a deduplicated list to recon/<target>/all_subdomains.txt.",
    "alive_check": "Probe all subdomains with httpx and identify alive hosts with status and tech stack.",
    "fingerprint": "Enumerate endpoints, parameters, and sensitive paths from alive hosts.",
    "attack_surface_map": "Analyze findings only and output a structured attack map. No SSH command execution.",
    "vuln_scan": "Run targeted, non-destructive nuclei/curl checks based on mapped attack surfaces.",
}


PHASE_TOOLS = {
    "subdomain_enum": [
        "subfinder",
        "assetfinder",
        "mkdir",
        "cat",
        "head",
        "sed",
        "sort",
        "grep",
        "ls",
    ],
    "alive_check": ["httpx", "nmap", "curl", "grep", "cat", "head", "sed", "sort", "ls"],
    "fingerprint": ["gau", "waybackurls", "ffuf", "grep", "sed", "head", "cat", "sort", "ls"],
    "attack_surface_map": [
        # Pure reasoning phase (no SSH tools).
    ],
    "vuln_scan": ["nuclei", "curl", "grep", "cat", "head", "sed", "ls"],
}
