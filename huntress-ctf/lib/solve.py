import ast, base64, json, os, re, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from decode import role_of, attack_of, decode_label, fields, LANG_CSI, HERE
import detect as D

def lang_of(fn):
    e=fn.rsplit('.',1)[-1]
    return {'js':'js','cmd':'bat','bat':'bat','vbs':'vbs','py':'py','sh':'sh','ps1':'ps','mjs':'mjs','php':'php'}.get(e,'other')

ADVANCED={'indirect-expansion.sh','token-fragmentation.sh','array-slicing.sh','associative-arrays.sh'}

def v1_desc(txt):
    m=re.search(r'HUNTRESS_ANALYSIS_V1:([A-Z0-9]+)-([A-Za-z0-9+/=._-]+)',txt)
    pfx,body=m.group(1),m.group(2)
    if pfx=='B64': b=base64.b64decode(body+'='*(-len(body)%4))
    elif pfx=='HEX': b=bytes.fromhex(body)
    elif pfx=='FRAG': b=bytes.fromhex(body.replace('.',''))
    elif pfx=='HB64':
        inner=bytes.fromhex(body).decode('latin1'); b=base64.b64decode(inner+'='*(-len(inner)%4))
    else: raise ValueError('v1 prefix '+pfx)
    return b.decode('latin1')

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

def solve(exdir, questions):
    byfile={}
    for q in questions:
        fn=q['artifact'].split('-> ')[-1].strip()
        byfile.setdefault(fn,[]).append(q['id'])
    jsnames=[fn for fn in byfile if fn.endswith('.js')]
    jsdesc=js_all(exdir,jsnames) if jsnames else {}
    ans={}
    for fn,ids in byfile.items():
        lang=lang_of(fn); path=os.path.join(exdir,fn)
        rep=tr=None; vbtext=None; src=None; v1=False
        txt=None if lang=='ps' else open(path,encoding='latin1').read()
        if txt and 'HUNTRESS_ANALYSIS_V1:' in txt:
            v1=True; desc=v1_desc(txt); f=fields(desc)
            f.setdefault('obfuscation',f.get('obfuscation_profile'))
            steps=f.get('steps','').split(','); role=f.get('role'); att=f.get('attack')
        elif lang=='ps':
            vals=ps_values(path)
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
                sc,at=PS_META[fn]
                v={'scenario':sc,'attack':at,
                   'url':pick(vals,lambda x:x.startswith('http')),
                   'wallet':pick(vals,lambda x:x.startswith('wallet_')),
                   'mutex':pick(vals,lambda x:x.startswith('Global\\')),
                   'extension':pick(vals,lambda x:x.startswith('.')),
                   'note_name':pick(vals,lambda x:x.upper().startswith('RECOVER')),
                   'user_agent':pick(vals,lambda x:x.startswith('Mozilla')),
                   'psfile':pick(vals,lambda x:re.match(r'update-.*\.dat$',x))}.get(k)
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
                fs,inv,ps=D.js_styles(src); v={'fnstyle':fs,'invstyle':inv,'propstyle':ps}[k]
            else:
                v=f.get(k)
            ans[aid]=v
    return ans

if __name__=='__main__':
    exdir=sys.argv[1]; start=json.load(open(sys.argv[2]))
    ans=solve(exdir,start['questions'])
    missing=[i for i in start['answer_ids'] if ans.get(i) in (None,'')]
    print('answers',len([i for i in start['answer_ids'] if ans.get(i) not in (None,'')]),'/',len(start['answer_ids']),'missing',missing[:20])
    json.dump(ans,open(sys.argv[3],'w'))
