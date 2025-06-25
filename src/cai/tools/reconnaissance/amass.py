import subprocess
import json
import tempfile
import os

def run_amass(domain, output_format="json"):
    """
    Run amass on the given domain and return the results as a list.
    Requires amass to be installed and in the system PATH.
    """
    with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as tmpfile:
        output_path = tmpfile.name
    try:
        cmd = [
            "amass",
            "enum",
            "-d", domain,
            "-json", output_path
        ]
        subprocess.run(cmd, check=True)
        results = []
        with open(output_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    results.append(json.loads(line))
        return results
    finally:
        if os.path.exists(output_path):
            os.remove(output_path) 