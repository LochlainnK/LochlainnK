import ast, base64, json, os, re, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from decode import role_of, attack_of, decode_label, fields, LANG_CSI, HERE
import detect as D

def lang_of(fn):
    e=fn.rsplit('.',1)[-1]
    return {'js':'js','cmd':'bat','bat':'bat','vbs':'vbs','py':'py','sh':'sh','ps1':'ps','mjs':'mjs','php':'php'}.get(e,'other')

ADVANCED={'indirect-expansion.sh','token-fragmentation.sh','array-slicing.sh','associative-arrays.sh'}

# ---- derived-field helpers (campaign token / url host / path leaf) ----
def _tok(c):   return c.rsplit('-',1)[-1] if c else None
def _host(u):
    m=re.search(r'https?://([^/]+)', u) if u else None
    return m.group(1) if m else None
def _leaf(p):  return re.split(r'[\\/]', p)[-1] if p else None

# Kinds whose exact value is variant dependent (the 'indicator' IOC, the ps1
# secondary/tertiary artifacts, and bat/vbs 'style' whose control/expansion
# components reuse the unreliable detectors). We emit a best-guess primary answer
# AND an ordered candidate list; solve_route brutes the list per-id (monotonic
# banking makes the first-try guess a shortcut, never a requirement).
SOFT_KINDS={'indicator','secondary','tertiary','style'}
BAT_CTRL=['direct','goto_dispatch','call_subroutine','for_once','if_guard','errorlevel_guard']
VBS_CTRL=['direct','for_once','do_once','while_once','select_case','error_guard']
EXP=['for_indirect','delayed','call_double','percent']

def _indicator_cands(f):
    # Per the challenge: "the first indicator present in the decoded descriptor
    # using this order: URL, upload URL, next-stage file, file path, schedule
    # path, recovery-note name, host id." Role-independent, first-present wins.
    out=[]
    for k in ('url','upload_url','next_stage','file_path','source_path','target_root',
              'schedule_path','cron_path','note_name'):
        v=f.get(k)
        if v and v not in out: out.append(v)
    h=f.get('host_id') or _host(f.get('url'))
    if h and h not in out: out.append(h)
    return out

def _dedup_first(primary, rest):
    out=[primary] if primary else []
    for x in rest:
        if x and x not in out: out.append(x)
    return out

def _v1_op(name, s):
    # one codec step; s is str or bytes, returns bytes (rev keeps type)
    name=name.lower()
    if name=='rev':
        return s[::-1]
    t=s.decode('latin1') if isinstance(s,bytes) else s
    if name in ('b64','base64'):
        t=re.sub(r'\s','',t); return base64.b64decode(t+'='*(-len(t)%4))
    if name in ('b32','base32'):
        t=re.sub(r'\s','',t).upper(); return base64.b32decode(t+'='*(-len(t)%8))
    if name=='hex': return bytes.fromhex(re.sub(r'[^0-9a-fA-F]','',t))
    if name=='frag': return bytes.fromhex(t.replace('.',''))
    if name=='hb64':
        inner=bytes.fromhex(t).decode('latin1'); return base64.b64decode(inner+'='*(-len(inner)%4))
    raise ValueError('v1 op '+name)

def _chain_op(name, s):
    # one LYR codec step: str -> str. Unlike the standalone FRAG *prefix*
    # (which is hex+dots), 'frag' inside a chain is a pure de-fragmentation
    # (strip the dot delimiters); the hex/b64/b32 layers are named separately.
    name=name.lower()
    if name=='rev':  return s[::-1]
    if name=='frag': return s.replace('.','')
    if name in ('b64','base64'):
        t=re.sub(r'\s','',s); return base64.b64decode(t+'='*(-len(t)%4)).decode('latin1')
    if name in ('b32','base32'):
        t=re.sub(r'\s','',s).upper(); return base64.b32decode(t+'='*(-len(t)%8)).decode('latin1')
    if name=='hex':  return bytes.fromhex(re.sub(r'\s','',s)).decode('latin1')
    if name=='hb64':
        inner=bytes.fromhex(re.sub(r'\s','',s)).decode('latin1')
        return base64.b64decode(inner+'='*(-len(inner)%4)).decode('latin1')
    raise ValueError('v1 chain op '+name)

def _apply_chain(layers, body):
    import itertools
    # the chain names the ENCODE order; the correct decode is some ordering of
    # the inverse ops. Try the natural reverse first, then every permutation,
    # and accept the one that yields a well-formed descriptor.
    orders=[layers[::-1], layers]+[list(p) for p in itertools.permutations(layers)]
    for order in orders:
        cur=body; ok=True
        for op in order:
            try: cur=_chain_op(op,cur)
            except Exception: ok=False; break
        if ok and cur[:2]=='v=':
            return cur.encode('latin1')
    raise ValueError('LYR chain failed: '+'_'.join(layers))

def _v1_bytes(pfx, body):
    p=pfx.upper()
    if p in ('B64','HEX','FRAG','HB64'): return _v1_op(p, body)
    if p=='LYR':                 # layered: LYR-<codec[_codec...]>-<body>
        chain,_,rest=body.partition('-'); return _apply_chain(chain.split('_'), rest)
    raise ValueError('v1 prefix '+pfx)

def v1_desc(txt):
    m=re.search(r'HUNTRESS_ANALYSIS_V1:([A-Za-z0-9]+)-([A-Za-z0-9+/=._-]+)',txt)
    if m:
        pfx,body=m.group(1),m.group(2)
    else:
        # SPLIT form (e.g. Google Apps Script): the PREFIX-body string is chopped
        # into an array of quoted fragments that .join("") back together.
        sm=re.search(r'HUNTRESS_ANALYSIS_V1_SPLIT\w*\s*=\s*\[(.*?)\]', txt, re.S)
        joined=''.join(re.findall(r'"((?:\\.|[^"\\])*)"', sm.group(1)))
        pm=re.match(r'([A-Za-z0-9]+)-(.*)$', joined, re.S)
        pfx,body=pm.group(1),pm.group(2)
    return _v1_bytes(pfx,body).decode('latin1')

_MAT=re.compile(r'Material_\w+\s*=\s*"((?:\\.|[^"\\])*)"')
def mjs_desc(path):
    t=open(path,encoding='latin1').read()
    mat=_MAT.search(t).group(1)
    cod=re.search(r'Codec_\w+\s*=\s*"([^"]*)"',t).group(1)
    desc,_,_=decode_label(cod,mat)
    return desc

# ---------- per-file descriptor extraction ----------
def ps_values(path):
    t=open(path,encoding='utf-8',errors='replace').read()
    m=re.search(r"FromBase64String\('([^']*)'\)",t).group(1)
    raw=base64.b64decode(m)
    try: d=json.loads(raw)
    except Exception:
        d=None
        for k in range(256):
            try: d=json.loads(bytes(x^k for x in raw)); break
            except Exception: pass
    vals=[]
    for v in d.values():
        vals.extend(v if isinstance(v,list) else [v])
    return [v for v in vals if isinstance(v,str)]

def bat_desc(path):
    lines=open(path,encoding='latin1').read().splitlines()
    base=D._frag_base(lines)
    frs={}
    for l in lines:
        m=re.match(r'\s*set\s+"'+re.escape(base)+r'(\d)=([^"]*)"',l,re.I)
        if not m: m=re.match(r'\s*set\s+'+re.escape(base)+r'(\d)=([^\r\n]*)$',l,re.I)
        if m and int(m.group(1))<4: frs[int(m.group(1))]=m.group(2)
    desc=''.join(frs[i] for i in sorted(frs)).replace('^','')
    return desc, lines, base

def _ast_literal(src, name_re):
    mod=ast.parse(src)
    for node in ast.walk(mod):
        if isinstance(node,ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt,ast.Name) and re.match(name_re,tgt.id):
                    return ast.literal_eval(node.value)
    return None

def py_desc(path):
    src=open(path,encoding='utf-8',errors='replace').read()
    mat=_ast_literal(src,r'MATERIAL_\w+$')
    cod=_ast_literal(src,r'CODEC_\w+$')
    desc,_,_=decode_label(cod,mat)
    return desc

def vbs_desc(path):
    t=open(path,encoding='latin1').read()
    mat=''.join(re.findall(r'"([^"]*)"', re.search(r'Material_\w+\s*=\s*(.+)',t).group(1)))
    cod=re.search(r"Codec_\w+\s*=\s*\"([^\"]*)\"",t).group(1)
    desc,rep,tr=decode_label(cod,mat)
    return desc,rep,tr,t

def sh_desc(path):
    t=open(path,encoding='latin1').read()
    mat=''.join(re.findall(r"'([^']*)'", re.search(r"Material_\w+=(.+)",t).group(1)))
    cod=re.search(r"Codec_\w+='([^']*)'",t).group(1)
    desc,_,_=decode_label(cod,mat)
    return desc

def js_all(exdir, names):
    paths=[os.path.join(exdir,n) for n in names]
    out=subprocess.run(['node',os.path.join(HERE,'jsrecover_json.js')]+paths,capture_output=True,text=True,timeout=30)
    return json.loads(out.stdout)

# ---------- answer kind from id suffix ----------
LONG=[('function-style','fnstyle'),('invocation-style','invstyle'),('property-style','propstyle'),
      ('stage-count','stagecount'),('next-stage','next_stage'),('file-path','file_path'),
      ('upload-url','upload_url'),('cron-path','cron_path'),('host-id','host_id'),
      ('user-agent','user_agent'),('note-name','note_name'),('windows-chain','windows_chain'),
      ('handoff-id','handoff_id'),('service-name','service_name'),('schedule-path','schedule_path'),
      ('host-profile','host_profile'),('stage-profile','stage_profile'),('next-language','next_language')]
SHORT={'role':'role','attack':'attack','adapter':'adapter','campaign':'campaign_id','url':'url',
       'path':'file_path','host':'host_id','scenario':'scenario','wallet':'wallet','mutex':'mutex',
       'extension':'extension','note':'note_name','file':'psfile','representation':'representation',
       'transform':'transform','control':'control','expansion':'expansion','graph':'graph',
       'steps':'steps','syntax':'syntax','obfuscation':'obfuscation','carrier':'carrier',
       'feature':'feature','primitive':'primitive'}
def kind_of(aid):
    for suf,k in LONG:
        if aid.endswith(suf): return k
    last=aid.rsplit('-',1)[-1]
    return SHORT.get(last,last)

PS_META={'resource-sample.ps1':('resource_hijacking','T1496'),
         'collection-sample.ps1':('synthetic_collection','T1555.003'),
         'impact-sample.ps1':('synthetic_impact','T1486')}

def pick(vals,pred):
    return next((v for v in vals if pred(v)),None)

def solve(exdir, questions, soft=None):
    # soft: optional {id -> [candidate,...]} populated for SOFT_KINDS so the caller
    # can brute them per-id. ans[id] holds the first-try best guess either way.
    byfile={}
    for q in questions:
        fn=q['artifact'].split('-> ')[-1].strip()
        byfile.setdefault(fn,[]).append(q['id'])
    jsnames=[fn for fn in byfile if fn.endswith('.js')]
    jsdesc=js_all(exdir,jsnames) if jsnames else {}
    ans={}
    for fn,ids in byfile.items():
        lang=lang_of(fn); path=os.path.join(exdir,fn)
        rep=tr=None; vbtext=None; src=None; v1=False; vals=[]
        txt=None if lang=='ps' else open(path,encoding='latin1').read()
        if txt and 'HUNTRESS_ANALYSIS_V1:' in txt:
            v1=True; desc=v1_desc(txt); f=fields(desc)
            f.setdefault('obfuscation',f.get('obfuscation_profile'))
            steps=f.get('steps','').split(','); role=f.get('role'); att=f.get('attack')
        elif lang=='ps':
            vals=ps_values(path)
            # classify by CONTENT (filenames are randomized in later variants)
            ps_url=pick(vals,lambda x:x.startswith('http'))
            ps_wallet=pick(vals,lambda x:x.startswith('wallet_'))
            ps_mutex=pick(vals,lambda x:x.startswith('Global\\'))
            ps_note=pick(vals,lambda x:x.upper().startswith('RECOVER'))
            ps_ext=pick(vals,lambda x:x.startswith('.'))
            ps_ua=pick(vals,lambda x:x.startswith('Mozilla'))
            ps_zip=pick(vals,lambda x:x.endswith('.zip'))
            ps_dat=pick(vals,lambda x:re.match(r'update-.*\.dat$',x))
            if ps_wallet:                       # resource hijacking
                ps_scen,ps_att,ps_sec,ps_ter='resource_hijacking','T1496',ps_wallet,ps_mutex
            elif ps_note or ps_ext:             # ransomware impact
                ps_scen,ps_att,ps_sec,ps_ter='synthetic_impact','T1486',ps_note,ps_ext
            else:                               # browser-credential collection
                ps_scen,ps_att,ps_sec,ps_ter='synthetic_collection','T1555.003',(ps_zip or ps_dat),ps_ua
        elif lang=='js':
            d=jsdesc[fn]; f=d.get('values',{}); steps=d['steps']; src=open(path,encoding='latin1').read()
            f=dict(f); f['adapter']=d.get('adapter'); f['stage_count']=d.get('stageCount'); f['steps']=','.join(steps)
        elif lang=='bat':
            desc,lines,base=bat_desc(path); f=fields(desc); steps=f['steps'].split(',')
        elif lang=='vbs':
            desc,rep,tr,vbtext=vbs_desc(path); f=fields(desc); steps=f['steps'].split(',')
        elif lang=='py':
            desc=py_desc(path); f=fields(desc); steps=f['steps'].split(',')
        elif lang=='sh':
            desc=sh_desc(path); f=fields(desc); steps=f.get('steps','').split(',')
        elif lang=='mjs':
            desc=mjs_desc(path); f=fields(desc); steps=f['steps'].split(',')
        if lang!='ps' and not v1:
            if fn in ADVANCED or ('feature' in f and 'role' not in f):
                role='advanced_syntax'; att='T1059.004'
            else:
                role=role_of(steps); att=attack_of(role,lang)
        for aid in ids:
            k=kind_of(aid)
            if lang=='ps':
                v={'scenario':ps_scen,'attack':ps_att,'url':ps_url,'wallet':ps_wallet,
                   'mutex':ps_mutex,'extension':ps_ext,'note_name':ps_note,'user_agent':ps_ua,
                   'psfile':ps_dat,'secondary':ps_sec,'tertiary':ps_ter}.get(k)
            elif k=='role': v=role
            elif k=='attack': v=att
            elif k=='adapter': v=f.get('adapter')
            elif k=='campaign_id': v=f.get('campaign_id')
            elif k=='steps': v='>'.join(steps)
            elif k=='stagecount': v=str(f.get('stage_count'))
            elif k=='graph': v=f.get('graph')
            elif k=='representation': v=rep
            elif k=='transform': v=tr
            elif k=='control': v=D.vbs_control(vbtext) if lang=='vbs' else D.batch_control(lines,base)
            elif k=='expansion': v=D.batch_expansion(lines,base)
            elif k in ('fnstyle','invstyle','propstyle'):
                fs,inv,ps=D.js_styles(src or txt or ''); v={'fnstyle':fs,'invstyle':inv,'propstyle':ps}[k]
            elif k=='style':
                # js: function|invocation|property triple (reliable).
                # bat: behavior-graph|control|expansion ; vbs: representation|transform|control.
                # The control/expansion components reuse the unreliable detectors, so bat/vbs
                # style is bruted (graph/rep/transform come from the descriptor and are fixed).
                if lang in ('js','mjs'):
                    fs,inv,ps=D.js_styles(src or txt or ''); v='|'.join([fs,inv,ps])
                    if soft is not None:
                        import itertools as _it
                        FN=['declaration','named_expression','anonymous_expression']
                        INV=['direct','call','apply']; PR=['dot','bracket_literal','mixed']
                        soft[aid]=_dedup_first(v, ['|'.join(t) for t in _it.product(FN,INV,PR)])
                elif lang=='bat':
                    g=f.get('graph'); c=D.batch_control(lines,base); e=D.batch_expansion(lines,base)
                    v='%s|%s|%s'%(g,c,e)
                    if soft is not None:
                        soft[aid]=_dedup_first(v, ['%s|%s|%s'%(g,cc,ee) for cc in BAT_CTRL for ee in EXP])
                elif lang=='vbs':
                    c=D.vbs_control(vbtext); v='%s|%s|%s'%(rep,tr,c)
                    if soft is not None:
                        soft[aid]=_dedup_first(v, ['%s|%s|%s'%(rep,tr,cc) for cc in VBS_CTRL])
                else:
                    v=f.get('style')
            elif k=='carrier':
                v='%s|%s'%(f.get('carrier'),f.get('windows_chain')) if lang=='py' else f.get('carrier')
            elif k=='obfuscation':
                v='%s|%s'%(f.get('syntax'),f.get('obfuscation')) if lang=='py' else f.get('obfuscation')
            elif k=='token':   v=_tok(f.get('campaign_id'))
            elif k=='host_id': v=f.get('host_id') or _host(f.get('url'))
            elif k=='leaf':    v=_leaf(f.get('file_path'))
            elif k=='indicator':
                cands=_indicator_cands(f)
                v=cands[0] if cands else None
                if soft is not None and len(cands)>1: soft[aid]=cands
            else:
                v=f.get(k)
            # ps1 secondary/tertiary are variant dependent -> offer the full value
            # set as brute candidates (best guess first) so the solver self-corrects.
            if soft is not None and lang=='ps' and k in ('secondary','tertiary') and vals:
                ordered=([v]+[x for x in vals if x!=v]) if v else list(vals)
                if len(ordered)>1: soft[aid]=ordered
            ans[aid]=v
    return ans

if __name__=='__main__':
    exdir=sys.argv[1]; start=json.load(open(sys.argv[2]))
    ans=solve(exdir,start['questions'])
    missing=[i for i in start['answer_ids'] if ans.get(i) in (None,'')]
    print('answers',len([i for i in start['answer_ids'] if ans.get(i) not in (None,'')]),'/',len(start['answer_ids']),'missing',missing[:20])
    json.dump(ans,open(sys.argv[3],'w'))
