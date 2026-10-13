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
mode = 'all'; lane = 'script-analysis'
if '--mode' in args:
    mode = args[args.index('--mode') + 1]
if '--lane' in args:
    lane = args[args.index('--lane') + 1]

base_id = gm.resolve_id(day, lane)
modes = ['single_solve', 'time_trial', 'mastery'] if mode == 'all' else [mode]
routes = {'single_solve': base_id, 'time_trial': base_id + '/time_trial',
          'mastery': base_id + '/mastery'}

print('Day %s -> %s' % (day, base_id))
results = {}
for m in modes:
    print('\n=== %s ===' % m)
    res, flag = solve_route(routes[m])
    results[m] = (res, flag)

print('\n==== SUMMARY: Day %s (%s) ====' % (day, base_id))
for m in modes:
    res, flag = results[m]
    print('  %-12s %-12s %s' % (m, res, flag))
