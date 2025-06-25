import subprocess

def run_assetfinder(domain):
    """
    Run assetfinder on the given domain and return the results as a list.
    Requires assetfinder to be installed and in the system PATH.
    """
    cmd = [
        "assetfinder",
        "--subs-only",
        domain
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    subdomains = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return subdomains 