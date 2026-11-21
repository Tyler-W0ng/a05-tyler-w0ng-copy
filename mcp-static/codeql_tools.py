"""Bounded CodeQL operations; databases and SARIF artifacts live in /tmp."""

import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
from uuid import uuid4


ROOT = Path('/tmp/codeql-work')
SUITES = {'code-scanning', 'security-extended', 'security-and-quality'}


def _run(argv: list[str], timeout: int, cwd: Path) -> dict:
    """Kill the whole build/query process group if its deadline expires."""
    with tempfile.TemporaryFile(mode='w+') as stdout, tempfile.TemporaryFile(mode='w+') as stderr:
        try:
            process = subprocess.Popen(
                argv, cwd=cwd, stdout=stdout, stderr=stderr,
                start_new_session=True,
            )
        except OSError as exc:
            return {'error': str(exc), 'exit_code': None}
        timed_out = False
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        # Full CodeQL logs remain in the database; bound the tool response.
        logs = {}
        for name, stream in [('stdout', stdout), ('stderr', stderr)]:
            stream.seek(0, 2)
            stream.seek(max(0, stream.tell() - 24000))
            logs[name] = stream.read()
        result = {'exit_code': process.returncode, **logs}
        if timed_out:
            result['error'] = f'CodeQL exceeded {timeout} seconds'
        elif process.returncode:
            result['error'] = 'CodeQL command failed; inspect stdout and stderr'
        return result


def create_database(target_path: str, build_command: str, timeout_seconds: int) -> dict:
    source = Path(target_path).resolve()
    if not source.is_dir() or not source.is_relative_to(Path('/tmp')):
        return {'error': 'target_path must be an existing writable source directory under /tmp'}
    if not build_command.strip():
        return {'error': 'Provide a build command that recompiles the target, such as make -B'}
    if not 1 <= timeout_seconds <= 900:
        return {'error': 'timeout_seconds must be between 1 and 900'}
    ROOT.mkdir(parents=True, exist_ok=True)
    database = ROOT / uuid4().hex
    result = _run([
        'codeql', 'database', 'create', str(database),
        '--language=cpp', f'--source-root={source}',
        f'--command={build_command}', '--threads=2', '--ram=2048',
    ], timeout_seconds, source)
    result.update(database_path=str(database), target_path=str(source))
    return result


def analyze_database(database_path: str, suite: str, timeout_seconds: int,
                     query: str | None = None) -> dict:
    database = Path(database_path).resolve()
    if not database.is_relative_to(ROOT) or not (database / 'codeql-database.yml').is_file():
        return {'error': 'Use a database_path returned by codeql_create_database'}
    if suite not in SUITES:
        return {'error': f'suite must be one of {sorted(SUITES)}'}
    if not 1 <= timeout_seconds <= 900:
        return {'error': 'timeout_seconds must be between 1 and 900'}
    if query is not None and (
        not query.endswith('.ql') or Path(query).is_absolute()
        or '..' in Path(query).parts or ':' in query
    ):
        return {'error': 'query must be a relative .ql path inside the bundled cpp-queries pack'}
    selection = query or f'codeql-suites/cpp-{suite}.qls'
    report = database / f'{suite}-{uuid4().hex}.sarif'
    result = _run([
        'codeql', 'database', 'analyze', str(database),
        f'codeql/cpp-queries:{selection}',
        '--format=sarifv2.1.0', f'--output={report}',
        '--threads=2', '--ram=2048',
    ], timeout_seconds, ROOT)
    result.update(database_path=str(database), sarif_path=str(report))
    if result.get('error'):
        return result
    try:
        sarif = json.loads(report.read_text())
        findings = []
        for run in sarif.get('runs', []):
            for finding in run.get('results', []):
                findings.append({
                    'rule_id': finding.get('ruleId'),
                    'level': finding.get('level'),
                    'message': finding.get('message', {}),
                    'locations': finding.get('locations', []),
                    'code_flows': finding.get('codeFlows', []),
                })
        result.update(findings=findings[:100], finding_count=len(findings),
                      truncated=len(findings) > 100)
    except (OSError, ValueError) as exc:
        result['error'] = f'Could not read SARIF: {exc}'
    return result
