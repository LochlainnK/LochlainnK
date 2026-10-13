import re
# ---- JScript style detectors ----
def js_styles(t):
    if re.search(r'^\s*function\s+inspect_\w+\s*\(', t, re.M): fs='declaration'
    elif re.search(r'inspect_\w+\s*=\s*function\s+\w+\s*\(', t): fs='named_expression'
    else: fs='anonymous_expression'
    m=re.search(r'=\s*eval\(\s*"\("\s*\+\s*recover_\w+([^;]*?)\+\s*"\)"\s*\)', t)
    tail=m.group(1) if m else ''
    inv='call' if '.call(' in tail else ('apply' if '.apply(' in tail else 'direct')
    body=t[t.find('inspect_'):]
    var=None
    mv=re.search(r'(\w+)\s*=\s*eval\(', body)
    if mv: var=mv.group(1)
    kinds=set()
    if var:
        for p in ('steps','adapter','values','stageCount'):
            if re.search(r'\b'+re.escape(var)+r'\.'+p+r'\b', body): kinds.add('dot')
            if re.search(r'\b'+re.escape(var)+r'\[\s*["\']'+p+r'["\']\s*\]', body): kinds.add('bracket')
    ps='mixed' if len(kinds)>1 else ('dot' if kinds=={'dot'} else 'bracket_literal')
    return fs,inv,ps

# ---- VBScript control-flow wrapper around the Decode_ call ----
def vbs_control(t):
    lines=[l.strip() for l in t.splitlines()]
    di=next((i for i,l in enumerate(lines) if re.search(r'=\s*Decode_\w+\(',l)),None)
    if di is None: return 'direct'
    up=lines[max(0,di-6):di]
    joined='\n'.join(up)
    if any(re.match(r'Do\b',l) for l in up): return 'do_once'
    if any(re.match(r'While\b',l) for l in up): return 'while_once'
    if any(re.match(r'Select Case\b',l) for l in up): return 'select_case'
    if 'On Error Resume Next' in joined: return 'error_guard'
    if any(re.match(r'For\b',l) for l in up): return 'for_once'
    return 'direct'

# ---- Batch fragment base + reconstruction line ----
def _frag_base(lines):
    c={}
    for l in lines:
        m=re.match(r'\s*set\s+"?([A-Za-z_]+?)0\b',l,re.I)
        if m: c[m.group(1)]=c.get(m.group(1),0)+1
    # pick base that has 0..3 defined
    for base in c:
        if all(any(re.match(r'\s*set\s+"?'+re.escape(base)+str(n)+r'\b',l,re.I) for l in lines) for n in range(4)):
            return base
    return max(c,key=c.get) if c else None

def _recon_line(lines, base):
    # line that assigns the recovered var from the fragments (concat or loop)
    cand=[]
    for i,l in enumerate(lines):
        ll=l.strip()
        if 'set' not in ll.lower(): continue
        if re.match(r'set\s+"?'+re.escape(base)+r'[0-3]\b',ll,re.I): continue  # fragment definition
        if re.search(r'(%%|%|!)'+re.escape(base),ll): cand.append(i)
    return cand[-1] if cand else None

def batch_expansion(lines, base):
    i=_recon_line(lines,base)
    if i is None: return 'percent'
    l=lines[i].strip()
    if 'call set' in l and '%%' in l: return 'call_double'
    if '!'+base in l: return 'delayed'
    if re.search(r"for\s+/f",l,re.I): return 'for_indirect'
    return 'percent'

def batch_control(lines, base):
    i=_recon_line(lines,base)
    if i is None: return 'direct'
    # which label section does line i belong to?
    lab=None; lab_idx=None
    for j in range(i,-1,-1):
        m=re.match(r':(\w+)\s*$',lines[j].strip())
        if m: lab=m.group(1); lab_idx=j; break
    SEP=('HUNTRESS_SEPARATOR_DONE','HUNTRESS_INSPECT')
    if lab and lab not in SEP:
        # reached by call or goto?
        call_lines=[k for k,l in enumerate(lines) if re.search(r'call\s+:'+lab+r'\b',l,re.I)]
        if call_lines:
            cl=lines[call_lines[0]]
            rl=lines[i].strip().lower()
            recon_is_for=rl.startswith('for ')
            recon_is_callset=('call set' in rl) and not recon_is_for
            if re.search(r'for\s+/l',cl,re.I) and not recon_is_callset: return 'for_once'
            return 'call_subroutine'
    # guards on the reconstruction line itself or a preceding line
    up=[lines[k].strip() for k in range(max(0,i-4),i+1)]
    for l in reversed(up):
        if re.search(r'if\s+errorlevel',l,re.I): return 'errorlevel_guard'
        if re.search(r'if\s+defined',l,re.I) or re.search(r'if\s+(/i\s+)?"',l,re.I): return 'if_guard'
    if lab and lab not in SEP:
        if any(re.search(r'goto\s+:'+lab+r'\b',l,re.I) for l in lines): return 'goto_dispatch'
    # one-item for over fragments reached via for/l call handled above; here if the
    # recon line itself is a for-loop invoked from a for/l subroutine we'd have returned.
    return 'direct'

# ---- Bash ordered steps / stage count come from descriptor ----
