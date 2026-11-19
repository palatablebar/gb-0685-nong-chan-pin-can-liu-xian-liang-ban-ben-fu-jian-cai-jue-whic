import hashlib,re

# 外发遮蔽规则:检测说明(note)仅以令牌级遮蔽进入外发复核包。
# 遮蔽复核人联系方式(手机、座机、邮箱)与设备编号;其余说明文字、
# 初检/复检关系与判定依据原样保留。内部归档与数据库始终留存原文。
PLACEHOLDER='〔已遮蔽·{}〕'
SPECS=[
    ('contact.email','联系方式',re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'),0),
    ('contact.phone','联系方式',re.compile(r'(?<![\d-])(?:1[3-9]\d{9}|0\d{2,3}-?\d{7,8})(?![\d-])'),0),
    ('equipment','设备编号',re.compile(r'(?<![A-Za-z0-9])(?:EQ|DEV|INS)-[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*'),0),
    ('equipment','设备编号',re.compile(r'((?:设备|仪器)编号\s*[:：#]?\s*)([A-Za-z0-9][A-Za-z0-9-]{1,})'),2),
]

def mask_text(text):
    """返回(外发文本,命中列表)。命中只记录类别与指纹,绝不记录原文。"""
    hits=[];masked=str(text)
    for kind,label,pattern,group in SPECS:
        def repl(match,kind=kind,label=label,group=group):
            token=match.group(group) if group else match.group(0)
            hits.append({'kind':kind,'label':label,'placeholder':PLACEHOLDER.format(label),
                'fingerprint':hashlib.sha256(token.encode('utf-8')).hexdigest()[:12]})
            return (match.group(1) if group==2 else '')+PLACEHOLDER.format(label)
        masked=pattern.sub(repl,masked)
    return masked,hits

def redact(state):
    """从状态派生外发遮蔽视图。纯函数:同源输入必得同一份遮蔽记录,不改写状态。"""
    calculations=state.get('calculations',[])
    chosen={c.get('line') for c in calculations}
    replaced={c['replaces'] for c in calculations if c.get('replaces')}
    notes=[];records=[]
    for m in state.get('measurements',[]):
        text=str(m.get('note') or '').strip()
        if not text:continue
        masked,hits=mask_text(text)
        line=m.get('_line')
        if line in chosen:role='复检' if m.get('relation') else '初检'
        elif m.get('id') in replaced:role='初检(被替代)'
        else:role='历史版本'
        notes.append({'line':line,'id':m.get('id',''),'role':role,'text':masked,'masked':len(hits)})
        for seq,h in enumerate(hits):records.append({'line':line,'id':m.get('id',''),'field':'note','seq':seq,**h})
    # 隔离记录逐条保留,仅说明字段在外发时遮蔽;内部原文留存于状态与数据库。
    for q in state.get('quarantine',[]):
        raw=q.get('raw')
        text=str(raw.get('note') or '').strip() if isinstance(raw,dict) else ''
        if not text:continue
        for seq,h in enumerate(mask_text(text)[1]):
            records.append({'line':q.get('line'),'id':q.get('id',''),'field':'note','seq':seq,**h})
    notes.sort(key=lambda n:(n['line'] or 0))
    records.sort(key=lambda r:(r['line'] or 0,r['seq']))
    findings={}
    for r in records:findings[r['label']]=findings.get(r['label'],0)+1
    return {'notes':notes,'records':records,'kept':len(notes),'masked':len(records),'findings':findings}
