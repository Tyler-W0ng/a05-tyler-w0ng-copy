"""Bounded checkout, sanitizer execution, and fuzzing helpers.

All target code runs in the MCP container, in a disposable checkout below
/tmp. Commands are deliberately bounded and their output is capped.
"""
import os
from pathlib import Path
import re
import signal
import subprocess
from uuid import uuid4

ROOT = Path('/tmp/dynamic-work').resolve()
MAX_OUTPUT = 24000


def _run(argv, cwd: Path, timeout: int, env=None, input_data=None):
    try:
        p = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    except OSError as exc:
        return {'error': str(exc), 'exit_code': None}
    try:
        out, err = p.communicate(input=input_data, timeout=timeout)
        timed_out = False
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        out, err = p.communicate()
        timed_out = True
    result = {'exit_code': p.returncode, 'timed_out': timed_out,
              'stdout': out[-MAX_OUTPUT:], 'stderr': err[-MAX_OUTPUT:]}
    if timed_out:
        result['error'] = f'command exceeded {timeout} seconds'
    return result


def checkout(repository: str, commit: str) -> dict:
    if not re.fullmatch(r'https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?', repository):
        return {'error': 'repository must be an https://github.com/<owner>/<repo> URL'}
    if not re.fullmatch(r'[0-9a-fA-F]{40}', commit):
        return {'error': 'commit must be a full 40-character Git hash'}
    ROOT.mkdir(parents=True, exist_ok=True)
    dest = ROOT / uuid4().hex
    clone = _run(['git', 'clone', '--no-checkout', '--depth=1', repository, str(dest)], ROOT, 180)
    if clone.get('exit_code'):
        # A pinned commit may not be the advertised branch tip.
        if dest.exists():
            import shutil; shutil.rmtree(dest, ignore_errors=True)
        clone = _run(['git', 'init', str(dest)], ROOT, 30)
        if clone.get('exit_code'):
            return clone
        _run(['git', 'remote', 'add', 'origin', repository], dest, 30)
        clone = _run(['git', 'fetch', '--depth=1', 'origin', commit], dest, 180)
    else:
        clone = _run(['git', 'fetch', '--depth=1', 'origin', commit], dest, 180)
    if clone.get('exit_code'):
        return {'error': 'could not fetch requested commit', **clone}
    result = _run(['git', 'checkout', '--detach', commit], dest, 30)
    result.update(target_path=str(dest), repository=repository, commit=commit)
    return result


def build(target_path: str, build_command: str = 'make', timeout_seconds: int = 300) -> dict:
    path = Path(target_path).resolve()
    if not path.is_relative_to(ROOT) or not path.is_dir():
        return {'error': 'target_path must be a checkout returned by dynamic_checkout'}
    if not 1 <= timeout_seconds <= 600:
        return {'error': 'timeout_seconds must be 1..600'}
    # Inject ASan/UBSan for ordinary Make based projects; preserve caller flags.
    env = os.environ.copy()
    env['CC'] = env.get('CC', 'clang')
    env['CXX'] = env.get('CXX', 'clang++')
    env['CFLAGS'] = (env.get('CFLAGS', '') + ' -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined').strip()
    env['CXXFLAGS'] = (env.get('CXXFLAGS', '') + ' -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined').strip()
    result = _run(['/bin/sh', '-lc', build_command], path, timeout_seconds, env)
    result.update(target_path=str(path), sanitizer='address,undefined', build_command=build_command)
    return result


def run_input(target_path: str, command: str, input_data: str = '', timeout_seconds: int = 10) -> dict:
    path = Path(target_path).resolve()
    if not path.is_relative_to(ROOT) or not path.is_dir():
        return {'error': 'target_path must be a checkout returned by dynamic_checkout'}
    if not 1 <= timeout_seconds <= 60:
        return {'error': 'timeout_seconds must be 1..60'}
    result = _run(['/bin/sh', '-lc', command], path, timeout_seconds, os.environ.copy(), input_data)
    result.update(target_path=str(path), command=command, input=input_data,
                  sanitizer_report=bool(re.search(r'AddressSanitizer|UndefinedBehaviorSanitizer|runtime error:', result.get('stderr', ''))))
    return result


def fuzz(target_path: str, fuzz_command: str, timeout_seconds: int = 60) -> dict:
    path = Path(target_path).resolve()
    if not path.is_relative_to(ROOT) or not path.is_dir():
        return {'error': 'target_path must be a checkout returned by dynamic_checkout'}
    if not 1 <= timeout_seconds <= 300:
        return {'error': 'timeout_seconds must be 1..300'}
    result = _run(['/bin/sh', '-lc', fuzz_command], path, timeout_seconds, os.environ.copy())
    crashes = sorted(str(p.relative_to(path)) for p in path.rglob('crash-*') if p.is_file())[:100]
    log_text = result.get('stderr', '') + result.get('stdout', '')
    coverage = re.findall(r'(?:cov|coverage):\s*([0-9,]+)', log_text, flags=re.IGNORECASE)
    return {'target_path': str(path), 'campaign_seconds': timeout_seconds,
            'crashing_inputs': crashes, 'coverage_observations': coverage[-10:],
            'sanitizer_report': bool(re.search(
                r'AddressSanitizer|UndefinedBehaviorSanitizer|runtime error:', log_text)),
            **result}
