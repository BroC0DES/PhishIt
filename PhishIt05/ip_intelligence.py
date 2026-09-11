import os
import ipinfo

# Set this in your shell before running, e.g.:
#   export IPINFO_TOKEN=your_token_here
# Never hardcode the token in this file if it's going into a shared/git repo.
ACCESS_TOKEN = os.getenv("1137b23642ef45")
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