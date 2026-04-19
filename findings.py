import json
import os


class FindingsStore:
    def __init__(self, target: str):
        safe_target = target.replace(".", "_")
        self.path = f"findings_{safe_target}.json"
        self.data = self._load()

    def _load(self):
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as f:
                return json.load(f)

        return {
            "subdomains": [],
            "alive_hosts": [],
            "endpoints": {
                "all_urls": [],
                "parameterized": [],
                "sensitive_files": [],
                "api_endpoints": [],
                "admin_panels": [],
            },
            "attack_surfaces": [],
            "vuln_scan_results": [],
        }

    def save(self):
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2)

    def add_subdomains(self, subdomains: list[str]):
        current = set(self.data.get("subdomains", []))
        current.update(s for s in subdomains if s)
        self.data["subdomains"] = sorted(current)
        self.save()

    def add_alive_hosts(self, hosts: list[str]):
        current = self.data.get("alive_hosts", [])
        seen_hosts = {h.get("host", "").strip().lower() for h in current if isinstance(h, dict)}

        for host in hosts:
            if isinstance(host, str):
                host_name = host.strip().lower()
                if not host_name or host_name in seen_hosts:
                    continue
                current.append({"host": host_name, "status": None, "tech": [], "ports": []})
                seen_hosts.add(host_name)
                continue

            if not isinstance(host, dict):
                continue

            host_name = str(host.get("host", "")).strip().lower()
            if not host_name:
                continue

            if host_name in seen_hosts:
                for item in current:
                    if item.get("host", "").strip().lower() != host_name:
                        continue
                    if host.get("status") is not None:
                        item["status"] = host.get("status")
                    if isinstance(host.get("tech"), list):
                        merged_tech = sorted(set(item.get("tech", []) + host.get("tech", [])))
                        item["tech"] = merged_tech
                    if isinstance(host.get("ports"), list):
                        merged_ports = sorted(set(item.get("ports", []) + host.get("ports", [])))
                        item["ports"] = merged_ports
                    break
            else:
                current.append(
                    {
                        "host": host_name,
                        "status": host.get("status"),
                        "tech": sorted(set(host.get("tech", []))) if isinstance(host.get("tech"), list) else [],
                        "ports": sorted(set(host.get("ports", []))) if isinstance(host.get("ports"), list) else [],
                    }
                )
                seen_hosts.add(host_name)

        self.data["alive_hosts"] = current
        self.save()

    def add_endpoints(self, category: str, urls: list[str]):
        endpoints = self.data.get("endpoints", {})
        if category not in endpoints:
            endpoints[category] = []

        current = set(endpoints.get(category, []))
        current.update(u for u in urls if u)
        endpoints[category] = sorted(current)
        self.data["endpoints"] = endpoints
        self.save()

    def add_attack_surfaces(self, surfaces: list[dict]):
        existing = self.data.get("attack_surfaces", [])
        seen = {
            (
                s.get("surface_type", "").strip().lower(),
                s.get("endpoint", "").strip().lower(),
                s.get("suggested_test", "").strip().lower(),
            )
            for s in existing
        }

        for surface in surfaces:
            key = (
                surface.get("surface_type", "").strip().lower(),
                surface.get("endpoint", "").strip().lower(),
                surface.get("suggested_test", "").strip().lower(),
            )
            if key in seen:
                continue
            if not key[0] and not key[1]:
                continue
            existing.append(surface)
            seen.add(key)

        self.data["attack_surfaces"] = existing
        self.save()

    def add_vuln_scan_results(self, rows: list[dict]):
        existing = self.data.get("vuln_scan_results", [])
        seen = {
            (
                r.get("tool", "").strip().lower(),
                r.get("target", "").strip().lower(),
                r.get("finding", "").strip().lower(),
            )
            for r in existing
        }

        for row in rows:
            key = (
                row.get("tool", "").strip().lower(),
                row.get("target", "").strip().lower(),
                row.get("finding", "").strip().lower(),
            )
            if key in seen:
                continue
            existing.append(row)
            seen.add(key)

        self.data["vuln_scan_results"] = existing
        self.save()

    def summary(self) -> str:
        return (
            f"Subdomains: {len(self.data.get('subdomains', []))} | "
            f"Alive hosts: {len(self.data.get('alive_hosts', []))} | "
            f"URLs: {len(self.data.get('endpoints', {}).get('all_urls', []))} | "
            f"Attack surfaces: {len(self.data.get('attack_surfaces', []))} | "
            f"Vuln results: {len(self.data.get('vuln_scan_results', []))}"
        )
