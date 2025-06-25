import subprocess
import json
import tempfile
import os

def run_subfinder(domain, output_format="json"):
    """
    Run subfinder on the given domain and return the results as a list.
    Requires subfinder to be installed and in the system PATH.
    """
    with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as tmpfile:
        output_path = tmpfile.name
    try:
        cmd = [
            "subfinder",
            "-d", domain,
            "-o", output_path,
            "-oJ"  # Output as JSON
        ]
        subprocess.run(cmd, check=True)
        with open(output_path, "r", encoding="utf-8") as f:
            results = json.load(f)
        return results
    finally:
        if os.path.exists(output_path):
            os.remove(output_path) 