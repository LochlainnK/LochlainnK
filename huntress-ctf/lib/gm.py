"""Game Master HTTP client. Token from $HUNTRESS_GM_TOKEN, kept out of argv/logs
(passed to curl via a 0600 --config file in a temp dir)."""
import json, os, subprocess, tempfile, time, atexit

URL = os.environ.get('HUNTRESS_GM_URL', 'https://2026.huntress.ctf.games/')
_TOKEN = os.environ.get('HUNTRESS_GM_TOKEN', '').strip()
if not _TOKEN:
    raise SystemExit('Set $HUNTRESS_GM_TOKEN to your Game Master bearer token.')
_d = tempfile.mkdtemp(prefix='gmcfg_')
_CFG = os.path.join(_d, 'auth.cfg')
with open(_CFG, 'w') as f:
    os.chmod(_CFG, 0o600)
    f.write('header = "Authorization: Bearer %s"\n' % _TOKEN)
atexit.register(lambda: (os.remove(_CFG), os.rmdir(_d)) if os.path.exists(_CFG) else None)


def post(obj, retries=4):
    for _ in range(retries):
        r = subprocess.run(['curl', '-sS', '-m', '120', '--config', _CFG,
                             '-H', 'Content-Type: application/json',
                             '--data-binary', '@-', URL],
                            input=json.dumps(obj), capture_output=True, text=True)
        try:
            return json.loads(r.stdout)
        except Exception:
            time.sleep(0.6)
    return {'result': 'error'}


def get(query):
    r = subprocess.run(['curl', '-sS', '-m', '120', '--config', _CFG, URL + '?' + query],
                       capture_output=True, text=True)
    try:
        return json.loads(r.stdout)
    except Exception:
        return {'result': 'error', 'raw': r.stdout[:200]}


def download(path, dst):
    subprocess.run(['curl', '-sS', '-m', '120', '--config', _CFG, '-o', dst,
                    URL.rstrip('/') + path], check=True)


def submit(challenge, answers):
    return post({'challenge': challenge, 'answers': answers})


def status(challenge):
    return get('op=status&challenge=' + challenge)


def resolve_id(day, lane='script-analysis'):
    """Return the single_solve challenge id for a day+lane, from the full catalog."""
    d = get('op=list&all=true')
    for c in d.get('challenges', []):
        if c.get('mode') == 'single_solve' and c.get('day') == int(day) and c.get('lane') == lane:
            return c['id']
    raise SystemExit('No %s challenge found for day %s' % (lane, day))
