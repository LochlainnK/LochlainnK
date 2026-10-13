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


def solve_route(CH, verbose=True):
    t0 = time.time()
    def log(m):
        if verbose:
            print('[%.1fs] %s' % (time.time() - t0, m))
    start = None
    for body in ({'op': 'retry', 'challenge': CH}, {'challenge': CH}):
        r = gm.post(body)
        if 'questions' in r and (r.get('artifacts') or r.get('download')):
            start = r
            break
    if start is None:
        log('cannot start: %r' % r)
        return None, None
    qs = start['questions']; ids = start['answer_ids']
    base = tempfile.mkdtemp(prefix='slv_')
    ans = {}
    multi = any('.' in i for i in ids)

    def solve_set(dd, sub, tag=None):
        for k, v in S.solve(dd, sub).items():
            ans[(tag + '.' + k) if tag else k] = v

    def subq(tag):
        return [{'id': q['id'].split('.', 1)[1], 'artifact': q['artifact'],
                 'answer_format': q['answer_format']} for q in qs if q['id'].startswith(tag + '.')]

    if multi:
        arts = start.get('artifacts') or []
        tags = sorted({i.split('.', 1)[0] for i in ids})
        if arts and len(arts) >= len(tags):
            for idx, tag in enumerate(tags):
                dd = os.path.join(base, tag); z = os.path.join(dd, 'z.zip')
                os.makedirs(dd, exist_ok=True); gm.download(arts[idx]['download'], z); unz(z, dd)
                solve_set(dd, subq(tag), tag)
        else:
            oz = os.path.join(base, 'o.zip'); gm.download(start['download'], oz); unz(oz, base)
            inners = sorted(f for f in os.listdir(base) if f.endswith('.zip') and f != 'o.zip')
            for tag, inner in zip(tags, inners):
                dd = os.path.join(base, tag); unz(os.path.join(base, inner), dd)
                solve_set(dd, subq(tag), tag)
    else:
        z = os.path.join(base, 'z.zip')
        gm.download(start.get('download') or start['artifacts'][0]['download'], z)
        unz(z, base); solve_set(base, qs)

    kof = {i: S.kind_of(i.split('.', 1)[-1]) for i in ids}
    undec = [i for i in ids if ans.get(i) in (None, '')]
    log('decoded %d/%d  undecoded-kinds=%s' % (len(ids) - len(undec), len(ids),
                                               set(kof[i] for i in undec)))

    reliable = [i for i in ids if kof[i] not in HARD and ans.get(i) not in (None, '')]
    rr = gm.submit(CH, {i: ans[i] for i in reliable}).get('result')
    log('reliable group: %s' % rr)

    def brute(i):
        for c in [ans.get(i)] + [x for x in cpool(i, kof[i]) if x != ans.get(i)]:
            if c and gm.submit(CH, {i: c}).get('result') in ('accepted', 'CORRECT', 'already_solved'):
                return i, c
        return i, None

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
    stuck = []
    with ThreadPoolExecutor(max_workers=12) as pool:
        for i, c in pool.map(brute, targets):
            if c:
                ans[i] = c
            else:
                stuck.append(i)
    log('bruted %d ids, stuck %d' % (len(targets), len(stuck)))

    gm.submit(CH, {i: ans[i] for i in ids if ans.get(i) not in (None, '')})
    st = gm.status(CH)
    log('FINAL result=%s flag=%s' % (st.get('result'), st.get('flag')))
    if stuck:
        qf = {q['id']: q['artifact'].split('-> ')[-1] for q in qs}
        for i in stuck[:40]:
            print('  STUCK', i, kof[i], qf.get(i), repr(ans.get(i))[:40])
    return st.get('result'), st.get('flag')


if __name__ == '__main__':
    solve_route(sys.argv[1])
