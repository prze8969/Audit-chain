import re

PRIVILEGED_NAMES = {
    'owner',
    'admin',
    'governance',
    'guardian',
    'operator',
    'implementation',
    'pendingowner',
}

GUARD_RE = re.compile(r'^(only|auth|restricted|requires?)', re.IGNORECASE)
REENTRANCY_RE = re.compile(r'nonreentrant|reentrancyguard|^lock$|mutex', re.IGNORECASE)

IMPACT = {
    'High': 10,
    'Medium': 5,
    'Low': 2,
    'Informational': 0.5,
    'Optimization': 0.1,
}

CONF = {
    'High': 1.0,
    'Medium': 0.8,
    'Low': 0.5,
}

CLASS_MAP = {
    'reentrancy-eth': 'R',
    'reentrancy-no-eth': 'R',
    'unchecked-lowlevel': 'U',
    'unchecked-send': 'U',
}

MAX_HOPS = 6
