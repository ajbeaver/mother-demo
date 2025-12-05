import random


# Excluded ranges for realism
_EXCLUDED_PREFIXES = [
    0,      # "This" network
    10,     # Private
    127,    # Loopback
    169,    # Link-local
    172,    # Private (172.16.0.0/12 but we exclude whole 172 to stay simple)
    192,    # Often private (192.168.x.x), we exclude whole to be safe
    224,    # Multicast
    225, 226, 227, 228, 229, 230, 231,
    232, 233, 234, 235, 236, 237, 238, 239,  # Multicast block
    255,    # Broadcast
]


def random_ip() -> str:
    """
    Generate a random public-Internet-style IPv4 address
    excluding private/reserved/broken ranges.
    """
    while True:
        a = random.randint(1, 254)
        if a in _EXCLUDED_PREFIXES:
            continue

        b = random.randint(0, 255)
        c = random.randint(0, 255)
        d = random.randint(1, 254)

        return f"{a}.{b}.{c}.{d}"


# Weighted port list for realistic benign activity
_COMMON_PORTS = [
    443, 443, 443,         # heavily weighted
    80, 80,                # common web
    8080,                  # alt web
    22,                    # ssh
    53,                    # dns
    3306,                  # mysql
]


def random_common_port() -> int:
    """
    Return a port chosen from a small weighted pool of common benign ports.
    """
    return random.choice(_COMMON_PORTS)
