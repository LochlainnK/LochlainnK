# Static analyzer for the "Shell We Begin" fixtures. Decodes each inert sample's
# embedded descriptor and derives the quiz answers. No fixture code is executed
# except JScript recover_* funcs via an isolated node vm (handled externally).
import ast, base64, json, os, re, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
LANG_CSI = {'js':'T1059.007','bat':'T1059.003','vbs':'T1059.005','py':'T1059.006','sh':'T1059.004','mjs':'T1059.007'}

def role_of(steps):
    last = steps[-1]
    if last == 'return_configuration': return 'benign_utility'
    if last == 'handoff_script': return 'staged_chain'
    if last == 'dispatch_next_stage': return 'relay'
    if last in ('upload_remote','transmit_remote'): return 'uploader'
    if last == 'write_recovery_note': return 'impact'
    if last == 'register_descriptor': return 'persistence_descriptor'
    if last == 'dispatch_process':
        return 'staged_chain' if ('acquire_remote' in steps or 'profile_host' in steps) else 'launcher'
    if last.startswith('dispatch_'): return 'stager'
    if last == 'write_file':
        return 'downloader' if 'acquire_remote' in steps else 'dropper'
    return 'unknown'

def attack_of(role, lang):
    base = {'benign_utility':'none','stager':'T1105','downloader':'T1105','dropper':'T1140',
            'uploader':'T1041','impact':'T1486',
            'persistence_descriptor':('T1053.003' if lang in ('sh','mjs') else 'T1053.005')}
    return base.get(role, LANG_CSI[lang])

# ---- generic codec inversion ----
def _bytes_from(rep, m):
    if isinstance(m,(list,tuple)): b=[int(x) for x in m]
    elif isinstance(m,(bytes,bytearray)): b=list(m)
    elif '\\u' in m:
        b=[int(x,16) for x in re.findall(r'\\u([0-9a-fA-F]{4})',m)]
    elif '\\x' in m:
        b=[int(x,16) for x in re.findall(r'\\x([0-9a-fA-F]{2})',m)]
    else:
        s=m; rev=rep.startswith('reversed')
        if 'base64' in rep or '_text' in rep:
            s2=re.sub(r'\s','',s)
            if rev: s2=s2[::-1]                       # reverse the base64 TEXT, not the bytes
            s2+='='*(-len(s2)%4)
            dec = base64.urlsafe_b64decode if ('urlsafe' in rep or '-' in s2 or '_' in s2) else base64.b64decode
            return list(dec(s2))                      # text already de-reversed
        elif 'hex' in rep:
            toks=re.findall(r'[0-9a-fA-F]+',re.sub(r'0x','',s))
            b=list(bytes.fromhex(toks[0])) if len(toks)==1 else [int(t,16) for t in toks]
        else:
            b=[int(x) for x in re.findall(r'\d+',s)]
        if rev: b=b[::-1]
        return b
    if rep.startswith('reversed'): b=b[::-1]
    return b

def _inv(tr, key, b):
    k=[int(x,16) for x in key.split(',') if x] if key else []
    if tr in ('identity',''): return b
    if tr=='reverse_bytes': return b[::-1]
    if tr=='single_byte_xor': return [x^k[0] for x in b]
    if tr=='repeating_key_xor': return [x^k[i%len(k)] for i,x in enumerate(b)]
    if tr=='add_modulo_256': return [(x-k[0])%256 for x in b]
    if tr=='subtract_modulo_256': return [(x+k[0])%256 for x in b]
    if tr=='rolling_xor':
        o=[];p=k[0]
        for x in b: o.append(x^p); p=x
        return o
    if tr=='reverse_then_xor': return [x^k[0] for x in b[::-1]]
    raise ValueError(tr)

_XPFX={'xor':'single_byte_xor','add':'add_modulo_256','sub':'subtract_modulo_256','rolling':'rolling_xor'}
def decode_label(label, m):
    rep,tr,key=(label.split('|')+['',''])[:3]
    # combined 2-field form like "xor_hex|3e" => transform=single_byte_xor, rep=hex, key=3e
    pfx=rep.split('_',1)[0]
    if pfx in _XPFX and not key and tr and not rep.startswith('reversed'):
        key=tr; tr=_XPFX[pfx]; rep=rep.split('_',1)[1]
    b=_bytes_from(rep,m)
    for bb in (b, b[::-1]):
        try: o=bytes(_inv(tr,key,bb))
        except Exception: continue
        for oo in (o,o[::-1]):
            if oo[:2]==b'v=': return oo.decode('latin1'), rep, tr
    raise ValueError('decode failed: '+label)

def fields(desc):
    return dict(x.split('=',1) for x in desc.strip().split('|') if '=' in x)
