import io,csv,json,hashlib
from app.modules.m7_archive.redact import mask_text,redact

def _dump(row):
    return json.dumps(row,ensure_ascii=False,sort_keys=True)

def bundle(state):
    # 内部归档:原文留存,不做遮蔽。
    out=io.StringIO(newline='');writer=csv.writer(out)
    writer.writerow(['记录类型','批次','来源行','业务ID','原因码','内容'])
    rid=state.get('run_id','preview')
    writer.writerow(['运行清单',rid,'','','',_dump(state.get('manifest',{}))])
    writer.writerow(['对账',rid,'','','',_dump(state.get('reconcile',{}))])
    for row in state.get('calculations',[]):writer.writerow(['计算',rid,row.get('line',''),row.get('id',''),row.get('code',''),_dump(row)])
    for row in state['quarantine']:writer.writerow(['隔离',rid,row['line'],row.get('id',''),row['code'],_dump(row.get('raw',{}))])
    return '\ufeff'+out.getvalue()

def client_bundle(state):
    # 外发复核包:检测说明经令牌级遮蔽后进入;隔离记录逐条保留以便核对。
    redaction=state.get('redaction') or redact(state)
    notes={n['line']:n for n in redaction['notes']}
    out=io.StringIO(newline='');writer=csv.writer(out)
    writer.writerow(['记录类型','批次','来源行','业务ID','原因码','内容'])
    rid=state.get('run_id','preview')
    writer.writerow(['运行清单',rid,'','','',_dump(state.get('manifest',{}))])
    writer.writerow(['对账',rid,'','','',_dump(state.get('reconcile',{}))])
    for row in state.get('calculations',[]):
        content=dict(row);note=notes.get(row.get('line'))
        if note:content['note']=note['text']
        writer.writerow(['计算',rid,row.get('line',''),row.get('id',''),row.get('code',''),_dump(content)])
    for n in redaction['notes']:
        writer.writerow(['说明',rid,n['line'],n['id'],'',_dump({'role':n['role'],'note':n['text'],'masked':n['masked']})])
    for row in state['quarantine']:
        raw=row.get('raw')
        if isinstance(raw,dict):
            raw=dict(raw)
            if str(raw.get('note') or '').strip():raw['note']=mask_text(raw['note'])[0]
        writer.writerow(['隔离',rid,row['line'],row.get('id',''),row['code'],_dump(raw)])
    for r in redaction['records']:
        writer.writerow(['遮蔽',rid,r['line'],r['id'],r['label'],_dump({'field':r['field'],'kind':r['kind'],'placeholder':r['placeholder']})])
    return '\ufeff'+out.getvalue()

def checksum(state):
    return hashlib.sha256(bundle(state).encode('utf-8')).hexdigest()

def client_checksum(state):
    return hashlib.sha256(client_bundle(state).encode('utf-8')).hexdigest()
