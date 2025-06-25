import subprocess
import os
import tempfile

def run_paramspider(domain):
    """
    Run paramspider on the given domain and return the discovered parameters as a list.
    Requires paramspider to be installed and in the system PATH.
    """
    with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as tmpfile:
        output_path = tmpfile.name
    try:
        cmd = [
            "paramspider",
            "--domain", domain,
            "--output", output_path
        ]
        subprocess.run(cmd, check=True)
        with open(output_path, "r", encoding="utf-8") as f:
            params = [line.strip() for line in f if line.strip()]
        return params
    finally:
        if os.path.exists(output_path):
            os.remove(output_path) 