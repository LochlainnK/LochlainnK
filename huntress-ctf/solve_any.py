#!/usr/bin/env python3
"""Solve one Script-Analysis route (single_solve / time_trial / mastery), untimed.

Strategy (banking is ATOMIC per submission — see PLAYBOOK.md §1):
  1. decode every file -> answers
  2. submit all reliable (non control/expansion) answers as one group (banks them)
  3. brute control/expansion per-id in parallel (each correct single submit banks)
  4. final submit -> CORRECT

Usage: HUNTRESS_GM_TOKEN=... python3 solve_any.py <challenge-route>
"""
import os, sys, time, tempfile, collections
from concurrent.futures import ThreadPoolExecutor
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'lib'))
import pyzipper
import gm, solve as S

BAT_CTRL = ['direct', 'goto_dispatch', 'call_subroutine', 'for_once', 'if_guard', 'errorlevel_guard']
VBS_CTRL = ['direct', 'for_once', 'do_once', 'while_once', 'select_case', 'error_guard']
EXP = ['for_indirect', 'delayed', 'call_double', 'percent']
POOLS = {
    'scenario': ['resource_hijacking', 'synthetic_collection', 'synthetic_impact'],
    'fnstyle': ['declaration', 'named_expression', 'anonymous_expression'],
    'invstyle': ['direct', 'call', 'apply'], 'propstyle': ['dot', 'bracket_literal', 'mixed'],
    'role': ['benign_utility', 'stager', 'dropper', 'downloader', 'uploader', 'launcher',
             'impact', 'staged_chain', 'relay', 'persistence_descriptor', 'advanced_syntax'],
    'attack': ['none', 'T1059', 'T1059.001', 'T1059.003', 'T1059.004', 'T1059.005', 'T1059.006',
               'T1059.007', 'T1105', 'T1140', 'T1041', 'T1486', 'T1053', 'T1053.003', 'T1053.005',
               'T1053.006', 'T1555.003', 'T1005', 'T1496', 'T1218', 'T1620'],
}
HARD = {'control', 'expansion'}


def cpool(aid, kind):
    if kind == 'expansion':
        return EXP
    if kind == 'control':
        return VBS_CTRL if aid.split('.', 1)[-1].startswith('vbscript-') else BAT_CTRL
    return POOLS.get(kind, [])


def unz(src, dd):
    os.makedirs(dd, exist_ok=True)
    with pyzipper.AESZipFile(src) as z:
        z.setpassword(b'infected')
        z.extractall(dd)


def solve_route(CH, verbose=True, ranked=False, priors=None):
    # priors: {role-key -> control/expansion value learned on an earlier mode of the
    # same challenge}, tried FIRST in the brute to shortcut it. Labels are per-variant
    # so this is a shortcut when it matches, never a guarantee.
    priors = priors or {}
    t0 = time.time()
    def log(m):
        if verbose:
            print('[%.1fs] %s' % (time.time() - t0, m))
    if ranked:
        bodies = ({'op': 'retry', 'challenge': CH, 'run_for_time': True},
                  {'challenge': CH, 'run_for_time': True},
                  {'op': 'retry', 'challenge': CH}, {'challenge': CH})
    else:
        bodies = ({'op': 'retry', 'challenge': CH}, {'challenge': CH})
    # Ranked bodies try run_for_time first (fresh timed attempt = HoF); they fall
    # back to untimed. A route with no timed mode returns timed_intent_not_available.
    TRANSIENT = {'temporarily_unavailable', 'error', 'rate_limited', 'try_again'}
    start = None; solved = False
    for sweep in range(6):            # retry the whole body set through transient errors
        last_transient = False
        for body in bodies:
            r = gm.post(body)
            if not ranked and r.get('result') in ('CORRECT', 'already_solved'):
                st = gm.status(CH); log('already solved: flag=%s' % st.get('flag'))
                return 'CORRECT', st.get('flag'), {}
            if r.get('result') in ('CORRECT', 'already_solved'):
                solved = True; continue
            if 'questions' in r and (r.get('artifacts') or r.get('download')):
                start = r; break
            if r.get('error') in TRANSIENT or r.get('result') == 'error':
                last_transient = True
        if start is not None or solved or not last_transient:
            break
        time.sleep(3)
        log('transient start error, retrying (%d)...' % (sweep + 1))
    if start is None:
        st = gm.status(CH)
        if solved or st.get('result') == 'CORRECT':
            log('already solved (no fresh/timed variant to start): flag=%s' % st.get('flag'))
            return 'CORRECT', st.get('flag'), {}
        log('cannot start: %r' % {k: r.get(k) for k in ('result', 'error')})
        return None, None, {}
    if ranked and not (start.get('deadline') or start.get('run_for_time')):
        log('note: ranked timed attempt not granted (route may not support HoF); solving untimed')
    qs = start['questions']; ids = start['answer_ids']
    base = tempfile.mkdtemp(prefix='slv_')
    ans = {}
    multi = any('.' in i for i in ids)

    def subq(tag):
        return [{'id': q['id'].split('.', 1)[1], 'artifact': q['artifact'],
                 'answer_format': q['answer_format']} for q in qs if q['id'].startswith(tag + '.')]

    # Each mastery set is independent -> decode them in parallel (download + extract
    # + node-backed solve). Threads are fine: requests session is pooled/thread-safe,
    # each set writes a separate dir, and each returns its own dict to merge.
    def decode_set(job):
        dd, sub, tag, src = job
        os.makedirs(dd, exist_ok=True)
        if src[0] == 'dl':
            z = os.path.join(dd, 'z.zip'); gm.download(src[1], z); unz(z, dd)
        else:  # already-extracted inner zip at src[1]
            unz(src[1], dd)
        return tag, S.solve(dd, sub)

    if multi:
        arts = start.get('artifacts') or []
        tags = sorted({i.split('.', 1)[0] for i in ids})
        jobs = []
        if arts and len(arts) >= len(tags):
            for idx, tag in enumerate(tags):
                jobs.append((os.path.join(base, tag), subq(tag), tag, ('dl', arts[idx]['download'])))
        else:
            oz = os.path.join(base, 'o.zip'); gm.download(start['download'], oz); unz(oz, base)
            inners = sorted(f for f in os.listdir(base) if f.endswith('.zip') and f != 'o.zip')
            for tag, inner in zip(tags, inners):
                jobs.append((os.path.join(base, tag), subq(tag), tag, ('inner', os.path.join(base, inner))))
        with ThreadPoolExecutor(max_workers=min(len(jobs), 8)) as pool:
            for tag, d in pool.map(decode_set, jobs):
                for k, v in d.items():
                    ans[tag + '.' + k] = v
    else:
        z = os.path.join(base, 'z.zip')
        gm.download(start.get('download') or start['artifacts'][0]['download'], z)
        unz(z, base)
        for k, v in S.solve(base, qs).items():
            ans[k] = v

    kof = {i: S.kind_of(i.split('.', 1)[-1]) for i in ids}
    undec = [i for i in ids if ans.get(i) in (None, '')]
    log('decoded %d/%d  undecoded-kinds=%s' % (len(ids) - len(undec), len(ids),
                                               set(kof[i] for i in undec)))

    reliable = [i for i in ids if kof[i] not in HARD and ans.get(i) not in (None, '')]
    rr = gm.submit(CH, {i: ans[i] for i in reliable}).get('result')
    log('reliable group: %s' % rr)

    targets = [i for i in ids if kof[i] in HARD]
    if rr not in ('accepted', 'CORRECT'):  # a reliable kind is wrong (new day) -> localize
        g = collections.defaultdict(list)
        for i in reliable:
            g[kof[i]].append(i)
        for kind, gl in g.items():
            if gm.submit(CH, {i: ans[i] for i in gl}).get('result') not in ('accepted', 'CORRECT'):
                if cpool(gl[0], kind):
                    targets += gl
                else:
                    qf = {q['id']: q['artifact'].split('-> ')[-1] for q in qs}
                    log('!! exact-kind wrong (decode bug?): %s e.g. %s in %s'
                        % (kind, gl[0], qf.get(gl[0])))
    # Per-id parallel brute on one persistent pool: each worker tries an id's
    # candidates in order (detector guess first) and stops at the first that banks.
    # Monotonic banking makes earlier wrong tries harmless. This beat a round-based
    # scheme in practice (no per-round pool churn); keep-alive session keeps it fast.
    def brute(i):
        rk = i.split('.', 1)[-1]
        seen = set()
        for c in ([priors.get(rk), ans.get(i)] + cpool(i, kof[i])):
            if not c or c in seen:
                continue
            seen.add(c)
            # A transient result (rate_limited/error) does NOT mean the candidate is
            # wrong — the submit never reached a verdict. Retry it a few times with
            # small backoff so a throttled submit doesn't burn the candidate and leave
            # the id falsely "stuck" (the failure mode seen on big mastery bundles).
            for attempt in range(5):
                res = gm.submit(CH, {i: c}).get('result')
                if res in ('accepted', 'CORRECT', 'already_solved'):
                    return i, c
                if res in ('incorrect', 'expired'):
                    break  # a real verdict: this candidate is wrong, move on
                time.sleep(0.4 * (attempt + 1))  # transient -> back off and re-test same candidate
        return i, None
    stuck = []
    prior_hits = 0
    if targets:
        # Cap concurrency: the server serializes writes, so too many in-flight submits
        # just trigger rate-limiting. 12 overlaps latency without overwhelming it.
        with ThreadPoolExecutor(max_workers=min(len(targets), 12)) as pool:
            for i, c in pool.map(brute, targets):
                if c:
                    ans[i] = c
                    if priors.get(i.split('.', 1)[-1]) == c:
                        prior_hits += 1
                else:
                    stuck.append(i)
    log('bruted %d ids, stuck %d%s' % (len(targets), len(stuck),
        (' (prior hits %d/%d)' % (prior_hits, len(targets))) if priors and targets else ''))
    learned = {i.split('.', 1)[-1]: ans[i] for i in targets if i not in stuck}

    gm.submit(CH, {i: ans[i] for i in ids if ans.get(i) not in (None, '')})
    st = gm.status(CH)
    log('FINAL result=%s flag=%s' % (st.get('result'), st.get('flag')))
    if stuck and st.get('result') != 'CORRECT':
        qf = {q['id']: q['artifact'].split('-> ')[-1] for q in qs}
        bk = collections.Counter(kof[i] for i in stuck)
        log('UNSOLVED stuck kinds=%s (first few below)' % dict(bk))
        for i in stuck[:12]:
            print('  STUCK', i, kof[i], qf.get(i), repr(ans.get(i))[:40])
    return st.get('result'), st.get('flag'), learned


if __name__ == '__main__':
    solve_route(sys.argv[1])
