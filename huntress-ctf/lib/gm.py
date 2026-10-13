"""Game Master HTTP client. Token from $HUNTRESS_GM_TOKEN, kept out of argv/logs.

Uses a pooled keep-alive requests.Session (fast enough for ranked/HoF timed
runs); falls back to curl --config if requests is unavailable."""
import json, os, subprocess, tempfile, time, atexit

URL = os.environ.get('HUNTRESS_GM_URL', 'https://2026.huntress.ctf.games/')
_TOKEN = os.environ.get('HUNTRESS_GM_TOKEN', '').strip()
if not _TOKEN:
    raise SystemExit('Set $HUNTRESS_GM_TOKEN to your Game Master bearer token.')
_CA = next((p for p in ('/root/.ccr/ca-bundle.crt',) if os.path.exists(p)), True)

_SESS = None
try:
    import requests
    from requests.adapters import HTTPAdapter
    _SESS = requests.Session()
    _SESS.headers['Authorization'] = 'Bearer ' + _TOKEN
    _SESS.verify = _CA
    _SESS.mount('https://', HTTPAdapter(pool_connections=8, pool_maxsize=64, max_retries=0))
except Exception:
    _SESS = None

# curl fallback config (also used for downloads)
_d = tempfile.mkdtemp(prefix='gmcfg_')
_CFG = os.path.join(_d, 'auth.cfg')
with open(_CFG, 'w') as f:
    os.chmod(_CFG, 0o600)
    f.write('header = "Authorization: Bearer %s"\n' % _TOKEN)
atexit.register(lambda: (os.path.exists(_CFG) and os.remove(_CFG)) or (os.path.isdir(_d) and os.rmdir(_d)))


def post(obj, retries=4):
    for _ in range(retries):
        if _SESS is not None:
            try:
                return _SESS.post(URL, data=json.dumps(obj),
                                  headers={'Content-Type': 'application/json'}, timeout=120).json()
            except Exception:
                time.sleep(0.4); continue
        r = subprocess.run(['curl', '-sS', '-m', '120', '--config', _CFG,
                            '-H', 'Content-Type: application/json', '--data-binary', '@-', URL],
                           input=json.dumps(obj), capture_output=True, text=True)
        try:
            return json.loads(r.stdout)
        except Exception:
            time.sleep(0.4)
    return {'result': 'error'}


def get(query):
    if _SESS is not None:
        try:
            return _SESS.get(URL + '?' + query, timeout=120).json()
        except Exception:
            pass
    r = subprocess.run(['curl', '-sS', '-m', '120', '--config', _CFG, URL + '?' + query],
                       capture_output=True, text=True)
    try:
        return json.loads(r.stdout)
    except Exception:
        return {'result': 'error', 'raw': r.stdout[:200]}


def download(path, dst):
    if _SESS is not None:
        try:
            open(dst, 'wb').write(_SESS.get(URL.rstrip('/') + path, timeout=120).content)
            return
        except Exception:
            pass
    subprocess.run(['curl', '-sS', '-m', '120', '--config', _CFG, '-o', dst,
                    URL.rstrip('/') + path], check=True)


def submit(challenge, answers):
    return post({'challenge': challenge, 'answers': answers})


def status(challenge):
    return get('op=status&challenge=' + challenge)


def resolve_id(day, lane='script-analysis'):
    d = get('op=list&all=true')
    for c in d.get('challenges', []):
        if c.get('mode') == 'single_solve' and c.get('day') == int(day) and c.get('lane') == lane:
            return c['id']
    raise SystemExit('No %s challenge found for day %s' % (lane, day))
