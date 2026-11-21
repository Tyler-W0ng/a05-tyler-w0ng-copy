"""Run via: docker compose --profile mcp exec -T mcp python - < mcp-static/smoke_codeql.py"""

import asyncio
import json
from pathlib import Path
import tempfile

from mcp import Client


async def call(client, name, arguments):
    response = await client.call_tool(name, arguments)
    assert not response.is_error, response
    result = response.structured_content
    if not isinstance(result, dict):
        result = json.loads(''.join(getattr(block, 'text', '') for block in response.content))
    assert not result.get('error'), result
    assert result['exit_code'] == 0, result
    return result


async def main():
    async with Client('http://localhost:8000/mcp', read_timeout_seconds=960) as client:
        names = {tool.name for tool in (await client.list_tools()).tools}
        assert {'codeql_create_database', 'codeql_analyze'} <= names, names
        with tempfile.TemporaryDirectory(prefix='codeql-smoke-') as folder:
            Path(folder, 'example.c').write_text(
                '#include <stdlib.h>\n'
                'int main(void) {\n'
                ' char *p = malloc(4);\n'
                ' if (!p) return 1;\n'
                ' free(p);\n'
                ' p[0] = 1;\n'
                ' return p[0];\n'
                '}\n'
            )
            database = await call(client, 'codeql_create_database', {
                'target_path': folder,
                'build_command': 'gcc -O0 -g example.c -o example',
            })
            print('Database created:', database['database_path'], flush=True)
            result = await call(client, 'codeql_analyze', {
                'database_path': database['database_path'],
                'suite': 'security-extended',
                'query': 'Critical/UseAfterFree.ql',
            })
            assert any(f['rule_id'] == 'cpp/use-after-free' for f in result['findings']), result
            print('PASS: MCP database creation and use-after-free detection')
            print('SARIF:', result['sarif_path'])


asyncio.run(main())
