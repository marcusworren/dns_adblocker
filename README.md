# Simple DNS Blocker

This is a simple DNS server that can block specific domains based on a blocklist. It listens on port 53 and forwards DNS queries to a real DNS server (e.g., Google's 8.8.8.8) if the domain is not blocked.

## Features
- Loads a blocklist of domains from a `hosts.txt` file.
- Blocks queries for domains listed in the blocklist.
- Forwards queries for other domains to a real DNS server.
