import json
from pathlib import Path

TEMPLATE_PATH = Path('samples/template.sol')
VARIANTS_DIR = Path('samples/variants')

MUTATIONS = {
    'clean': {
        'NR_withdraw': 'nonReentrant',
        'PRE': "balances[msg.sender] -= amount;",
        'POST': '',
        'MOD_setOwner': 'onlyOwner',
        'MOD_handOver': 'onlyOwner',
        'CALL_refund': "(bool ok, ) = msg.sender.call{value: amount}(''); require(ok, 'refund failed');",
    },
    'm1': {
        'NR_withdraw': 'nonReentrant',
        'PRE': "balances[msg.sender] -= amount;",
        'POST': '',
        'MOD_setOwner': '',
        'MOD_handOver': 'onlyOwner',
        'CALL_refund': "(bool ok, ) = msg.sender.call{value: amount}(''); require(ok, 'refund failed');",
    },
    'm2': {
        'NR_withdraw': 'nonReentrant',
        'PRE': "balances[msg.sender] -= amount;",
        'POST': '',
        'MOD_setOwner': 'onlyOwner',
        'MOD_handOver': '',
        'CALL_refund': "(bool ok, ) = msg.sender.call{value: amount}(''); require(ok, 'refund failed');",
    },
    'm3': {
        'NR_withdraw': '',
        'PRE': '',
        'POST': "balances[msg.sender] -= amount;",
        'MOD_setOwner': 'onlyOwner',
        'MOD_handOver': 'onlyOwner',
        'CALL_refund': "(bool ok, ) = msg.sender.call{value: amount}(''); require(ok, 'refund failed');",
    },
    'm4': {
        'NR_withdraw': 'nonReentrant',
        'PRE': "balances[msg.sender] -= amount;",
        'POST': '',
        'MOD_setOwner': 'onlyOwner',
        'MOD_handOver': 'onlyOwner',
        'CALL_refund': "msg.sender.call{value: amount}('');",
    },
    'm5': {
        'NR_withdraw': '',
        'PRE': '',
        'POST': "balances[msg.sender] -= amount;",
        'MOD_setOwner': '',
        'MOD_handOver': 'onlyOwner',
        'CALL_refund': "(bool ok, ) = msg.sender.call{value: amount}(''); require(ok, 'refund failed');",
    },
    'm6': {
        'NR_withdraw': 'nonReentrant',
        'PRE': "balances[msg.sender] -= amount;",
        'POST': '',
        'MOD_setOwner': 'onlyOwner',
        'MOD_handOver': '',
        'CALL_refund': "msg.sender.call{value: amount}('');",
    },
    'm7': {
        'NR_withdraw': '',
        'PRE': '',
        'POST': "balances[msg.sender] -= amount;",
        'MOD_setOwner': '',
        'MOD_handOver': '',
        'CALL_refund': "msg.sender.call{value: amount}('');",
    },
}

LABELS = [
    {'variant': 'clean', 'expected': []},
    {'variant': 'm1', 'expected': [
        {'klass': 'P', 'function_id': 'Treasury.setOwner(address)', 'var': 'Treasury.owner', 'path': ['Treasury.setOwner(address)']}
    ]},
    {'variant': 'm2', 'expected': [
        {'klass': 'P', 'function_id': 'Treasury._grant(address)', 'var': 'Treasury.owner', 'path': ['Treasury.handOver(address)', 'Treasury._grant(address)']}
    ]},
    {'variant': 'm3', 'expected': [
        {'klass': 'R', 'function_id': 'Treasury.withdraw(uint256)', 'path': ['Treasury.withdraw(uint256)']}
    ]},
    {'variant': 'm4', 'expected': [
        {'klass': 'U', 'function_id': 'Treasury.refund(uint256)', 'path': ['Treasury.refund(uint256)']}
    ]},
    {'variant': 'm5', 'expected': [
        {'klass': 'P', 'function_id': 'Treasury.setOwner(address)', 'var': 'Treasury.owner', 'path': ['Treasury.setOwner(address)']},
        {'klass': 'R', 'function_id': 'Treasury.withdraw(uint256)', 'path': ['Treasury.withdraw(uint256)']}
    ]},
    {'variant': 'm6', 'expected': [
        {'klass': 'P', 'function_id': 'Treasury._grant(address)', 'var': 'Treasury.owner', 'path': ['Treasury.handOver(address)', 'Treasury._grant(address)']},
        {'klass': 'U', 'function_id': 'Treasury.refund(uint256)', 'path': ['Treasury.refund(uint256)']}
    ]},
    {'variant': 'm7', 'expected': [
        {'klass': 'P', 'function_id': 'Treasury.setOwner(address)', 'var': 'Treasury.owner', 'path': ['Treasury.setOwner(address)']},
        {'klass': 'P', 'function_id': 'Treasury._grant(address)', 'var': 'Treasury.owner', 'path': ['Treasury.handOver(address)', 'Treasury._grant(address)']},
        {'klass': 'R', 'function_id': 'Treasury.withdraw(uint256)', 'path': ['Treasury.withdraw(uint256)']},
        {'klass': 'U', 'function_id': 'Treasury.refund(uint256)', 'path': ['Treasury.refund(uint256)']}
    ]},
]


def generate_variants() -> None:
    VARIANTS_DIR.mkdir(parents=True, exist_ok=True)
    template = TEMPLATE_PATH.read_text(encoding='utf-8')
    for name, replacements in MUTATIONS.items():
        code = template
        for marker, val in replacements.items():
            code = code.replace(f'/*@@{marker}@@*/', val)
        (VARIANTS_DIR / f'{name}.sol').write_text(code, encoding='utf-8')

    (VARIANTS_DIR / 'labels.json').write_text(json.dumps(LABELS, indent=2), encoding='utf-8')


if __name__ == '__main__':
    generate_variants()
