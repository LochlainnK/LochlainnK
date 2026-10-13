#!/usr/bin/env python3
"""Solve a day's Script-Analysis challenge across all three modes.

Usage:
  HUNTRESS_GM_TOKEN=... python3 solve_day.py N [--mode single|time_trial|mastery|all] [--lane LANE]

Resolves the challenge id for day N (default lane script-analysis), then solves
single_solve, time_trial and mastery (untimed). Prints a flag summary.
"""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, 'lib'))
import gm
from solve_any import solve_route

args = sys.argv[1:]
day = next(a for a in args if not a.startswith('--'))
mode = 'all'; lane = 'script-analysis'; ranked = '--ranked' in args; parallel = '--parallel' in args
if '--mode' in args:
    mode = args[args.index('--mode') + 1]
if '--lane' in args:
    lane = args[args.index('--lane') + 1]

base_id = gm.resolve_id(day, lane)
modes = ['single_solve', 'time_trial', 'mastery'] if mode == 'all' else [mode]
routes = {'single_solve': base_id, 'time_trial': base_id + '/time_trial',
          'mastery': base_id + '/mastery'}

print('Day %s -> %s%s' % (day, base_id, '  [parallel]' if parallel else ''))
results = {}

def run_mode(m):
    want_ranked = ranked and m != 'single_solve'
    res, flag = solve_route(routes[m], ranked=want_ranked, verbose=not parallel)
    if want_ranked and res != 'CORRECT':
        # ranked timed attempt missed the window (or unavailable) -> guarantee the
        # solve untimed. HoF may already be registered from the ranked attempt.
        res, flag = solve_route(routes[m], ranked=False, verbose=not parallel)
    return m, res, flag

if parallel:
    # Modes are independent routes/attempts -> solve them concurrently (good for
    # untimed throughput). NB: with --ranked this makes the three timed attempts
    # contend for server write-throughput, which can cost a borderline HoF window;
    # for HoF prefer running ranked modes one at a time.
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=len(modes)) as pool:
        for m, res, flag in pool.map(run_mode, modes):
            results[m] = (res, flag); print('  %-12s %-10s %s' % (m, res, flag))
else:
    for m in modes:
        print('\n=== %s%s ===' % (m, ' [ranked]' if (ranked and m != 'single_solve') else ''))
        _, res, flag = run_mode(m)
        results[m] = (res, flag)

print('\n==== SUMMARY: Day %s (%s) ====' % (day, base_id))
for m in modes:
    res, flag = results[m]
    print('  %-12s %-12s %s' % (m, res, flag))
