from app.modules.m7_archive.export_out import checksum
from app.modules.m7_archive.redact import redact

def execute(state):
    redaction=redact(state);state['redaction']=redaction
    state['archive']={'sha256':checksum(state),'client_sha256':'',
        'evidence_count':len(state.get('calculations',[]))+len(state['quarantine']),
        'note_count':redaction['kept'],'masked_count':redaction['masked'],
        'ready':state.get('reconcile',{}).get('balanced',False)}
    return state
