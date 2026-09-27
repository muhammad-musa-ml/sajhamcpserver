"""Reproduce the Origin decision matrix from upstream and this branch.

Run from the repository root: python docs/mcp_origin_benchmark.py
Uses the unmodified upstream function at BASE_COMMIT via git show, rather
than a handwritten approximation. This measures policy rejection counts,
not attack success or request latency.
"""

import ast
import csv
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sajha.core.mcp_2025_11_25 import validate_origin

BASE_COMMIT = '5d819c78a8a4791f5fac666d9736dc3af1a9a354'
SOURCE = 'sajha/core/mcp_2025_11_25.py'
CASES = [
    ('no Origin header', None, False),
    ('trusted localhost', 'http://localhost:3002', False),
    ('trusted loopback', 'http://127.0.0.1:3002', False),
    ('external website', 'https://attacker.example', True),
    ('host suffix trick', 'http://localhost.evil.example:3002', True),
    ('opaque null Origin', 'null', True),
    ('wildcard Origin', '*', True),
    ('wildcard bind address', 'http://0.0.0.0:3002', True),
    ('origin with path', 'https://attacker.example/path', True),
]


def upstream_validator():
    source = subprocess.check_output(
        ['git', 'show', f'{BASE_COMMIT}:{SOURCE}'], cwd=ROOT, text=True,
        encoding='utf-8',
    )
    node = next(
        node for node in ast.parse(source).body
        if isinstance(node, ast.FunctionDef) and node.name == 'validate_origin'
    )
    namespace = {'Optional': Optional, 'List': List}
    exec(compile(ast.Module(body=[node], type_ignores=[]), SOURCE, 'exec'), namespace)
    return namespace['validate_origin']


def main():
    before = upstream_validator()
    rows = []
    for label, origin, untrusted in CASES:
        rows.append({
            'case': label,
            'origin': origin or '(absent)',
            'untrusted': untrusted,
            'upstream_allowed': before(origin),
            'fixed_allowed': validate_origin(origin),
        })

    csv_path = ROOT / 'docs' / 'mcp_origin_results.csv'
    with csv_path.open('w', newline='', encoding='utf-8') as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    untrusted = [row for row in rows if row['untrusted']]
    counts = [
        sum(not row['upstream_allowed'] for row in untrusted),
        sum(not row['fixed_allowed'] for row in untrusted),
    ]
    assert counts == [0, 6], counts
    assert all(row['fixed_allowed'] for row in rows if not row['untrusted'])

    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="680" height="230" viewBox="0 0 680 230">
<rect width="680" height="230" fill="#f8fafc"/>
<text x="30" y="32" font-family="Arial" font-size="19" font-weight="bold" fill="#0f172a">Untrusted MCP Origins rejected</text>
<text x="30" y="55" font-family="Arial" font-size="12" fill="#475569">Six untrusted inputs; higher rejection count is better</text>
<text x="30" y="99" font-family="Arial" font-size="14" fill="#334155">Upstream</text>
<rect x="150" y="77" width="420" height="30" rx="5" fill="#e2e8f0"/>
<text x="585" y="99" font-family="Arial" font-size="16" font-weight="bold" fill="#b91c1c">{counts[0]}/6</text>
<text x="30" y="153" font-family="Arial" font-size="14" fill="#334155">Fixed</text>
<rect x="150" y="131" width="420" height="30" rx="5" fill="#e2e8f0"/>
<rect x="150" y="131" width="{420 * counts[1] // 6}" height="30" rx="5" fill="#047857"/>
<text x="585" y="153" font-family="Arial" font-size="16" font-weight="bold" fill="#047857">{counts[1]}/6</text>
<text x="30" y="205" font-family="Arial" font-size="11" fill="#64748b">Validator decisions from pinned upstream commit and current code; HTTP route tests run separately.</text>
</svg>'''
    (ROOT / 'docs' / 'mcp_origin_results.svg').write_text(svg, encoding='utf-8')
    print(f'Untrusted Origins rejected: upstream {counts[0]}/6; fixed {counts[1]}/6')
    print(f'Wrote {csv_path} and docs/mcp_origin_results.svg')


if __name__ == '__main__':
    main()
