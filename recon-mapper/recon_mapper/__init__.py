"""recon-mapper — reconnaissance & attack-surface mapper.

Given a domain, it enumerates subdomains (passively via certificate
transparency and actively via DNS brute-forcing), resolves which hosts are
live, fingerprints their web stack from HTTP responses, and can optionally
scan common TCP ports — producing a single consolidated report.
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
