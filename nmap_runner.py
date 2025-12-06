# nmap_runner.py
import subprocess
import shlex

class NmapRunner:
    def run_stream(self, target, options):
        cmd = f"nmap {options} {target}".strip()
        try:
            process = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in iter(process.stdout.readline, ''):
                yield line
        except Exception as e:
            yield f"[ERROR] {str(e)}\n"

    def build_options(self, selections):
        opts = []

        scan = selections.get("scan", "")
        host_discovery = selections.get("host_discovery", "")
        ports_raw = selections.get("ports", "").strip()
        version = selections.get("version_detection", "")
        script = selections.get("script", "")
        evasion = selections.get("evasion", "")
        timing = selections.get("timing", "")

        # Scan type
        if scan == "--randomize-hosts -iR":
            count = selections.get("random_count", "10")
            opts.append(f"--randomize-hosts -iR {count}")
        elif scan == "-iL" and selections.get("iL_file"):
            opts.append(f"-iL {selections['iL_file']}")
        elif scan == "--exclude" and selections.get("exclude_hosts"):
            opts.append(f"--exclude {selections['exclude_hosts']}")
        elif scan:
            opts.append(scan)

        # Ports and host discovery
        use_special_ports = ports_raw in ["-p-", "-F"] or ports_raw.startswith("--top-ports") or ports_raw.startswith("--exclude-ports")
        if host_discovery in ["-PS", "-PA", "-PU"]:
            if not ports_raw:
                raise ValueError(f"Ports required for {host_discovery}.")
            if use_special_ports:
                raise ValueError(f"Cannot use special ports with {host_discovery}.")
            opts.append(f"{host_discovery}{ports_raw}")
        else:
            if use_special_ports:
                opts.append(ports_raw)
            elif ports_raw:
                opts.append(f"-p {ports_raw}")
            if host_discovery:
                opts.append(host_discovery)

        # Version
        if version:
            opts.append(version)

        # Timing
        if timing:
            opts.append(timing)

        # NSE script
        if script:
            opts.append(script)

        # Evasion
        if evasion:
            opts.append(evasion)

        return " ".join(o for o in opts if o.strip())
