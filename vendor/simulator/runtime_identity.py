"""Parse the Renode banner without confusing the fourth build component with ABI."""
import re


def parse_banner(text):
    pattern = (r'(?im)^\s*Renode\s+v?(?P<reported>(?P<base>[0-9]+\.[0-9]+\.[0-9]+)'
               r'(?:\.[0-9]+)?)(?:[+-][0-9A-Za-z][0-9A-Za-z.-]*)?\s*$')
    matches = list(re.finditer(pattern, text))
    if len(matches) != 1 or matches[0]['base'] not in ('1.16.0', '1.17.0'):
        raise ValueError('UnsupportedRenodeRuntime')
    return {'reportedVersion': matches[0]['reported'], 'compatibilityVersion': matches[0]['base']}
