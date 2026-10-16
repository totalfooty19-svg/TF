"""Minimal runner for machines without pytest: python tests/run_tests.py"""
import sys, traceback, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import test_core as T
fails = 0
for name in [n for n in dir(T) if n.startswith('test_')]:
    try: getattr(T, name)(); print('ok  ', name)
    except Exception: fails += 1; print('FAIL', name); traceback.print_exc()
sys.exit(1 if fails else 0)
