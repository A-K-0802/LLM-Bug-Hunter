PHASE_SEQUENCE = [
    "subdomain_enum",
    "url_enum",
    "live_host_validation",
    "attack_surface_map",
]


PHASE_NAMES = {
    "subdomain_enum": "Subdomain Enumeration",
    "url_enum": "URL and Endpoint Enumeration",
    "live_host_validation": "Live Host Validation",
    "attack_surface_map": "Attack Surface Mapping",
}


PHASE_OBJECTIVES = {
    "subdomain_enum": "Discover and save subdomains for the target.",
    "url_enum": "Enumerate historical and discovered URLs/endpoints from known domains.",
    "live_host_validation": "Identify which discovered hosts are alive and reachable.",
    "attack_surface_map": "Map candidate attack surfaces and run focused scans.",
}


PHASE_TOOLS = {
    "subdomain_enum": ["subfinder", "mkdir", "ls", "cat", "head", "sed", "sort", "grep", "jq"],
    "url_enum": ["gau", "waybackurls", "cat", "head", "sed", "sort", "grep", "jq", "ls"],
    "live_host_validation": ["httpx", "cat", "head", "sed", "sort", "grep", "jq", "ls"],
    "attack_surface_map": [
        "nmap",
        "nuclei",
        "ffuf",
        "curl",
        "cat",
        "head",
        "sed",
        "sort",
        "grep",
        "jq",
        "ls",
    ],
}
