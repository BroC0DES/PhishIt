import os
import ipinfo
from dotenv import load_dotenv

load_dotenv()  # loads .env from the project root (see .env.example)

# Set IPINFO_TOKEN in your .env file (copy .env.example) or your shell.
# Never hardcode the token in this file if it's going into a shared/git repo.
ACCESS_TOKEN = os.getenv("IPINFO_TOKEN")
if not ACCESS_TOKEN:
    raise RuntimeError("Set IPINFO_TOKEN as an environment variable before running.")

handler = ipinfo.getHandler(ACCESS_TOKEN)

# In-memory cache so repeated lookups of the same IP (common when testing,
# or when multiple modules import this file) don't burn API quota.
_cache = {}


def get_ip_info(ip):

    if ip in _cache:
        return _cache[ip]

    try:
        details = handler.getDetails(ip)

        result = {
            "country": details.country_name or "Unknown",
            "city": details.city or "Unknown",
            "region": details.region or "Unknown",
            "isp": details.all.get("org", "Unknown")
        }

    except Exception as e:
        print("IP lookup failed:", e)

        result = {
            "country": "Unknown",
            "city": "Unknown",
            "region": "Unknown",
            "isp": "Unknown"
        }

    _cache[ip] = result
    return result