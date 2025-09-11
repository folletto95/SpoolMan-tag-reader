# Utility functions per il progetto

def hex_to_ascii(hex_str):
    try:
        return bytes.fromhex(hex_str).decode("utf-8", errors="ignore")
    except Exception:
        return None
