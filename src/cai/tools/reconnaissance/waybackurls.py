import subprocess

def run_waybackurls(domain):
    """
    Run waybackurls on the given domain and return the results as a list of URLs.
    Requires waybackurls to be installed and in the system PATH.
    """
    cmd = [
        "waybackurls",
        domain
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    urls = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return urls 