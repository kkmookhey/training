# status_checker.py (The "trusted" dependency)
def get_asset_status(hostname: str) -> str:
    # In a real app, this would ping the host or query an API.
    # For our demo, it just returns a simulated status.
    return f"Status for {hostname} is: Online and Healthy."