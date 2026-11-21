"""Pinned, disposable source checkouts for static analysis."""
import os
import re
import signal
import subprocess
from pathlib import Path
from uuid import uuid4

ROOT = Path('/tmp/static-work').resolve()


def _run(argv: list[str], cwd: Path, timeout: int = 180) -> dict:
    try:
        process = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True,
                                   start_new_session=True)
    except OSError as exc:
        return {'exit_code': None, 'error': str(exc)}
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        timed_out = False
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate()
        timed_out = True
    result = {'exit_code': process.returncode, 'timed_out': timed_out,
              'stdout': stdout[-12000:], 'stderr': stderr[-12000:]}
    if timed_out:
        result['error'] = f'command exceeded {timeout} seconds'
    return result


def checkout(repository: str, commit: str) -> dict:
    if not re.fullmatch(r'https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?', repository):
        return {'error': 'repository must be an https://github.com/<owner>/<repo> URL'}
    if not re.fullmatch(r'[0-9a-fA-F]{40}', commit):
        return {'error': 'commit must be a full 40-character Git hash'}
    ROOT.mkdir(parents=True, exist_ok=True)
    target = ROOT / uuid4().hex
    cloned = _run(['git', 'clone', '--no-checkout', '--depth=1', repository, str(target)], ROOT)
    if cloned.get('exit_code'):
        import shutil
        shutil.rmtree(target, ignore_errors=True)
        initialized = _run(['git', 'init', str(target)], ROOT, 30)
        if initialized.get('exit_code'):
            return initialized
        _run(['git', 'remote', 'add', 'origin', repository], target, 30)
    fetched = _run(['git', 'fetch', '--depth=1', 'origin', commit], target)
    if fetched.get('exit_code'):
        return {'error': 'could not fetch requested commit', **fetched}
    result = _run(['git', 'checkout', '--detach', commit], target, 30)
    result.update(target_path=str(target), repository=repository, commit=commit)
    return result
