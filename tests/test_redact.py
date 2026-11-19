import csv,io,json
from copy import deepcopy
from app import store
from app.workflow import load,run
from app.modules.m7_archive.redact import mask_text,redact
from app.modules.m7_archive.export_out import bundle,client_bundle,client_checksum
import pytest

def rows_of(text):
    return list(csv.reader(io.StringIO(text.lstrip('\ufeff'))))

def test_mask_contact_and_equipment():
    masked,hits=mask_text('同样本复检，复核人电话13800001111，设备编号EQ-7788')
    assert '13800001111' not in masked and 'EQ-7788' not in masked
    assert '同样本复检' in masked and {h['label'] for h in hits}=={'联系方式','设备编号'}

def test_mask_email_and_labeled_equipment():
    masked,hits=mask_text('复核邮箱fuyuan@lab026.example，仪器编号：LCMS-09')
    assert 'fuyuan@lab026.example' not in masked and 'LCMS-09' not in masked
    assert '仪器编号：' in masked and len(hits)==2

def test_mask_keeps_verdict_text():
    masked,hits=mask_text('初检报告\n原始谱图A')
    assert masked=='初检报告\n原始谱图A' and hits==[]

def test_mask_never_touches_verdict_fields():
    # 判定依据数值不得被误判为联系方式
    for text in ['0.004','2026-08-01','限量0.005，区间[0,0.01)','LC-MS/MS','P01']:
        assert mask_text(text)==(text,[])

def test_redaction_records_carry_no_original(state):
    blob=json.dumps(state['redaction'],ensure_ascii=False)
    for token in ['13800001111','13900002222','13800003333','EQ-7788','LCMS-09','fuyuan@lab026.example']:
        assert token not in blob
    assert state['redaction']['masked']==6 and state['redaction']['findings']=={'联系方式':4,'设备编号':2}

def test_client_bundle_masks_note_but_keeps_reason(state):
    text=client_bundle(state)
    for token in ['13800001111','13900002222','13800003333','EQ-7788','LCMS-09','fuyuan@lab026.example']:
        assert token not in text
    assert '同样本复检' in text and '初检报告' in text and '〔已遮蔽·联系方式〕' in text

def test_client_bundle_explains_relation_and_basis(state):
    rows=rows_of(client_bundle(state))
    calc=[r for r in rows if r[0]=='计算' and r[3]=='00002'][0]
    content=json.loads(calc[5])
    assert content['replaces']=='00001' and content['limit']=='0.005' and content['code']=='PASS'
    assert '同样本复检' in content['note']
    notes=[r for r in rows if r[0]=='说明']
    roles={json.loads(r[5])['role'] for r in notes}
    assert {'初检','复检','初检(被替代)'}<=roles

def test_client_bundle_quarantine_verifiable(state):
    rows=rows_of(client_bundle(state));q=[r for r in rows if r[0]=='隔离']
    assert len(q)==len(state['quarantine'])
    missing=[r for r in q if r[4]=='MISSING'][0]
    raw=json.loads(missing[5])
    assert '缺检出限' in raw['note'] and '13800003333' not in json.dumps(raw,ensure_ascii=False)

def test_internal_original_preserved(state):
    # 内部状态与内部归档留存原文,遮蔽只发生在外发包
    assert '13800001111' in json.dumps(state['measurements'],ensure_ascii=False)
    assert '缺检出限，联系13800003333' in bundle(state)

def test_redaction_deterministic_rerun(state,raw):
    again=run(raw,{})
    assert again['redaction']['records']==state['redaction']['records']
    assert again['redaction']['notes']==state['redaction']['notes']

def test_masking_non_destructive(state):
    before=deepcopy(state);client_bundle(state);assert state==before

def test_rerun_keeps_confirmed_content(state,tmp_path,monkeypatch):
    monkeypatch.setenv('DB_PATH',str(tmp_path/'r.db'))
    store.save(state['run_id'],state);store.review(state['run_id'],1,'通过')
    again=run(load('dirty.csv'),{});store.save(again['run_id'],again)
    kept=store.get(state['run_id'])
    assert kept['decision']=='通过' and kept['review_version']==2
    assert len(store.history())==1 and kept['redaction']['records']==state['redaction']['records']

def test_failed_run_preserves_internal(client):
    good=client.post('/api/runs',json={'sample':'dirty.csv'}).get_json()
    assert client.post('/api/runs',json={'csv':'wrong\n1\n'}).status_code==422
    kept=client.get('/api/runs/'+good['run_id']).get_json()
    blob=json.dumps(kept,ensure_ascii=False)
    assert kept['quarantine'] and '13800001111' in blob

def test_export_endpoint_masks(client):
    s=client.post('/api/runs',json={'sample':'dirty.csv'}).get_json()
    body=client.get('/api/archive/'+s['run_id']+'/export.csv').data.decode('utf-8-sig')
    assert '13800001111' not in body and '同样本复检' in body and '遮蔽' in body and '运行清单' in body

def test_client_checksum_recorded(state):
    assert state['archive']['client_sha256']==client_checksum(state)

def test_workbench_shows_kept_and_masked(client):
    client.post('/api/runs',json={'sample':'dirty.csv'})
    page=client.get('/m7_archive').data.decode()
    assert '外发说明' in page and '遮蔽记录' in page and '〔已遮蔽·联系方式〕' in page
    assert '13800001111' not in page
