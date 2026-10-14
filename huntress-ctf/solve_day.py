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
day = next((a for a in args if not a.startswith('--')), None)
if day is None:
    sys.exit('usage: HUNTRESS_GM_TOKEN=... python3 solve_day.py N '
             '[--mode single_solve|time_trial|mastery] [--lane LANE] [--ranked] [--parallel]')
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
# Order matters: solve single_solve FIRST (untimed, no pressure — this is where
# the decoder is validated and any new family surfaces), then carry what it
# learned (the control/expansion values, which the brute discovers) forward as
# PRIORS into time_trial, then into mastery. Mastery's multiple sets decode in
# parallel inside solve_route. Labels are per-variant, so priors are a first-try
# shortcut for the brute, never a guarantee.
ORDER = ['single_solve', 'time_trial', 'mastery']
modes = [m for m in ORDER if (mode == 'all' or m == mode)]

def run_mode(m, priors, verbose):
    want_ranked = ranked and m != 'single_solve'
    res, flag, learned = solve_route(routes[m], ranked=want_ranked, verbose=verbose, priors=priors)
    if want_ranked and res != 'CORRECT':
        # ranked timed attempt missed the window (or unavailable) -> guarantee the
        # solve untimed. HoF may already be registered from the ranked attempt.
        res, flag, learned = solve_route(routes[m], ranked=False, verbose=verbose, priors=priors)
    return res, flag, learned

if parallel:
    # Concurrency override: run modes at once (good for untimed throughput). This
    # forgoes priors threading, and with --ranked the timed attempts contend for
    # server throughput; for the learning-first flow use the default (sequential).
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=len(modes)) as pool:
        for m, (res, flag, _) in zip(modes, pool.map(lambda mm: run_mode(mm, {}, False), modes)):
            results[m] = (res, flag); print('  %-12s %-10s %s' % (m, res, flag))
else:
    priors = {}
    for m in modes:
        print('\n=== %s%s%s ===' % (m, ' [ranked]' if (ranked and m != 'single_solve') else '',
                                     ' [priors:%d]' % len(priors) if priors else ''))
        res, flag, learned = run_mode(m, priors, True)
        results[m] = (res, flag)
        priors.update(learned)  # carry control/expansion knowledge forward

print('\n==== SUMMARY: Day %s (%s) ====' % (day, base_id))
for m in modes:
    res, flag = results[m]
    print('  %-12s %-12s %s' % (m, res, flag))
