import subprocess
import json
import tempfile
import os

def run_arjun(url):
    """
    Run arjun on the given URL and return the discovered parameters as a list.
    Requires arjun to be installed and in the system PATH.
    """
    with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as tmpfile:
        output_path = tmpfile.name
    try:
        cmd = [
            "arjun",
            "-u", url,
            "--output", output_path,
            "--json"
        ]
        subprocess.run(cmd, check=True)
        with open(output_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        params = data.get("parameters", [])
        return params
    finally:
        if os.path.exists(output_path):
            os.remove(output_path) 