import subprocess

def run_gau(domain):
    """
    Run gau on the given domain and return the results as a list of URLs.
    Requires gau to be installed and in the system PATH.
    """
    cmd = [
        "gau",
        domain
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    urls = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return urls 