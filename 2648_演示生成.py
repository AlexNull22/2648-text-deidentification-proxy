"""生成自造JSON/CSV并真实验证NER、映射恢复和本机HTTP流程。"""
import argparse
from collections import Counter
import csv
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import html
import importlib.util
import json
from pathlib import Path
import platform
import threading
import urllib.request
from cryptography.fernet import Fernet

ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('scrub2648',ROOT/'2648_脱敏核心.py')
core=importlib.util.module_from_spec(spec); spec.loader.exec_module(core)

def run_demo(output):
    output=Path(output).resolve()
    if output.exists(): raise ValueError('演示目录已存在，请选择全新的2648前缀目录。')
    output.mkdir(parents=True)
    private=output/'2648_私有数据'; private.mkdir()
    profiles=[('John Smith','Microsoft','Seattle','john.smith@example.com','+1 212-555-0100','10001','4111 1111 1111 1111'),('Mary Johnson','Google','London','mary.johnson@example.net','+44 20 7946 0958','90210','5555 5555 5555 4444')]
    records=[]
    for i in range(30):
        name,company,city,email,phone,postal,card=profiles[i%2]
        text=f'{name} works at {company} in {city}. Email {email} or call {phone}. ZIP {postal}; card {card}.'
        records.append({'record_id':f'{i+1:03d}','text':text})
    (private/'2648_输入.json').write_text(json.dumps(records[:20],indent=2),encoding='utf-8')
    with (private/'2648_输入.csv').open('w',newline='',encoding='utf-8') as stream:
        writer=csv.DictWriter(stream,fieldnames=['record_id','text']); writer.writeheader(); writer.writerows(records[20:])
    original=core.load_input(private/'2648_输入.json')+core.load_input(private/'2648_输入.csv')
    assert original==records
    key=Fernet.generate_key(); (private/'2648_本地密钥.key').write_bytes(key)
    vault=core.Vault(private/'2648_加密映射.sqlite',key)
    detector=core.Detector(); pipeline=core.Pipeline(vault,detector)
    cleaned=pipeline.scrub('demo2648',records)
    assert sum(cleaned['counts'].values())==210,cleaned['counts']
    assert all(cleaned['counts'].get(kind)==30 for kind in ['PERSON','CORP','LOCATION','EMAIL','PHONE','POSTAL','CARD'])
    restored=pipeline.restore('demo2648',cleaned['payload'])
    assert restored==records
    assert pipeline.scrub('demo2648',records)==cleaned
    serialized=json.dumps(cleaned,ensure_ascii=False)
    raw_values=set(value for profile in profiles for value in profile)
    assert all(value not in serialized for value in raw_values)
    assert all(value.encode() not in (private/'2648_加密映射.sqlite').read_bytes() for value in raw_values)
    (output/'2648_处理后.json').write_text(serialized,encoding='utf-8')
    (private/'2648_恢复结果.json').write_text(json.dumps(restored,indent=2),encoding='utf-8')
    received=[]
    class Sink(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_POST(self):
            data=self.rfile.read(int(self.headers['Content-Length']))
            received.append(json.loads(data))
            self.send_response(503 if self.path=='/fail' else 200); self.send_header('Content-Length','2'); self.end_headers(); self.wfile.write(b'{}')
    sink=ThreadingHTTPServer(('127.0.0.1',0),Sink)
    sink_thread=threading.Thread(target=sink.serve_forever,daemon=True); sink_thread.start()
    server=core.serve(pipeline,port=0)
    api_thread=threading.Thread(target=server.serve_forever,daemon=True); api_thread.start()
    try:
        delivered=pipeline.forward('demo2648',records,f'http://127.0.0.1:{sink.server_port}/ok',output/'2648_异常队列')
        queued=pipeline.forward('demo2648',records,f'http://127.0.0.1:{sink.server_port}/fail',output/'2648_异常队列')
        request=urllib.request.Request(f'http://127.0.0.1:{server.server_port}/scrub',data=json.dumps({'session':'demo2648','payload':records}).encode(),headers={'Content-Type':'application/json'})
        with urllib.request.urlopen(request) as response: webhook=json.load(response)
        assert webhook==cleaned
    finally:
        server.shutdown();server.server_close();api_thread.join()
        sink.shutdown();sink.server_close();sink_thread.join()
    assert delivered['status']=='delivered' and queued['status']=='queued'
    assert len(received)==2 and all(item['payload']==cleaned['payload'] for item in received)
    queued_file=output/'2648_异常队列'/queued['queue_file']
    queued_bytes=queued_file.read_text(encoding='utf-8')
    assert all(value not in queued_bytes for value in raw_values)
    assert json.loads(queued_bytes)['payload']==cleaned['payload']
    stats=vault.stats('demo2648')
    metrics={'synthetic_records':30,'json_records':20,'csv_records':10,'replacement_occurrences':210,'unique_mappings':sum(stats.values()),'entity_counts':cleaned['counts'],'exact_restored_records':30,'same_session_repeat_identical':True,'webhook_verified':True,'downstream_sanitized_posts':2,'delivered_posts':1,'queued_failures':1,'sample_raw_values_absent_from_outbox_queue_and_vault':True,'spacy_model':'en_core_web_sm','model_version':detector.model_version,'python':platform.python_version(),'independent_demo':True}
    (output/'2648_演示核验.json').write_text(json.dumps(metrics,ensure_ascii=False,indent=2),encoding='utf-8')
    render(output,metrics,records,cleaned['payload'])
    print(json.dumps(metrics,ensure_ascii=False,indent=2))
    return metrics

def render(output,metrics,original,cleaned):
    e=lambda text:html.escape(str(text),quote=True)
    rows=''.join(f'<tr><td>{e(a["record_id"])}</td><td>{e(b["text"])}</td><td><span>精确恢复通过</span></td></tr>' for a,b in zip(original,cleaned))
    counts=''.join(f'<tr><td>{e(k)}</td><td>{n}</td><td>按会话复用</td></tr>' for k,n in metrics['entity_counts'].items())
    page='''<!doctype html><html lang="zh-CN" translate="no"><meta charset="utf-8"><meta name="google" content="notranslate"><meta name="viewport" content="width=device-width,initial-scale=1"><title>2648 文本脱敏代理</title><style>*{box-sizing:border-box}body{margin:0;background:#f3f6f8;color:#1c3344;font:15px/1.6 'Segoe UI','Microsoft YaHei',sans-serif}main{max-width:1400px;margin:auto;padding:30px 35px}header{display:flex;justify-content:space-between;align-items:start}.eyebrow{color:#337a79;letter-spacing:.16em;font-size:11px;font-weight:700}h1{font-size:34px;line-height:1.25;margin:9px 0}h2{font-size:20px;margin:0 0 12px}p{color:#5d7180;margin:7px 0}.label{background:#e2f0ed;color:#23675a;border-radius:6px;padding:8px 12px;font-size:12px}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:15px;margin:24px 0}.metric,section{background:#fff;border:1px solid #dce5eb;border-radius:11px;padding:21px}.metric strong{display:block;font-size:32px;color:#165e62;margin-top:5px}.metric small{color:#687d8a}.compare{display:grid;grid-template-columns:1fr 1fr;gap:15px}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:14px/1.8 Consolas,monospace;margin:15px 0 0;padding:17px;border-radius:7px;background:#f4f6f8}.clean{background:#edf7f4;color:#215d55}.note{padding:13px 18px;background:#eaf0f6;border-radius:7px;margin:16px 0;font-size:13px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:15px;margin:18px 0}table{border-collapse:collapse;width:100%;font-size:12px}td,th{padding:10px;border-bottom:1px solid #e6edf2;text-align:left;vertical-align:top}th{color:#6a7d8b;font-weight:500}td span{color:#277d60}input{padding:9px 12px;border:1px solid #cbd8e1;border-radius:6px;float:right}.small{font-size:12px}a{color:#247581}footer{font-size:12px;color:#667d8c;margin:20px 0}@media(max-width:800px){main{padding:18px}.metrics{grid-template-columns:repeat(2,1fr)}.compare,.grid{grid-template-columns:1fr}header{display:block}input{float:none}}</style><main><header><div><div class="eyebrow">PYTHON / LOCAL TEXT TOKENIZATION</div><h1>先替换身份，再处理文本</h1><p>2648 文本脱敏代理 · spaCy 英文实体识别 + 结构化规则 · 独立演示</p></div><div class="label">自造英文样例 · 人工复核必需</div></header><div class="metrics"><div class="metric"><small>JSON / CSV 自造记录</small><strong>30</strong><small>20 条 JSON + 10 条 CSV</small></div><div class="metric"><small>已识别信息替换</small><strong>210</strong><small>7 类实体 / 14 个加密映射</small></div><div class="metric"><small>精确恢复记录</small><strong>30 / 30</strong><small>原始结构与文本逐字一致</small></div><div class="metric"><small>下游故障进入队列</small><strong>1</strong><small>队列仅保存处理后载荷</small></div></div><div class="compare"><section><h2>自造输入</h2><p class="small">姓名、机构、地点、邮箱、电话、邮编、演示卡号</p><pre>ORIGINAL</pre></section><section><h2>处理后载荷</h2><p class="small">同一会话、同一精确身份复用固定格式占位符</p><pre class="clean">CLEANED</pre></section></div><div class="note">SQLite 中的原值字段经过 Fernet 加密，使用 HMAC 查重，密钥单独保管。占位符在本地恢复；模型或格式失败时拒绝处理。</div><div class="grid"><section><h2>实体替换统计</h2><table><thead><tr><th>类别</th><th>出现次数</th><th>映射策略</th></tr></thead><tbody>COUNTS</tbody></table></section><section><h2>真实本机接口验收</h2><p>Webhook 输入 → 识别与替换 → 本机下游</p><p class="small">1 次成功交付 + 1 次 503 故障排队；收到的载荷及队列均检查了样例原值不存在。</p><p class="small">密文映射可重用；重复输入的处理结果一致；30 条数据精确恢复。</p><p class="small"><a href="2648_演示核验.json">查看机器核验记录 ↗</a></p><p class="small">没有连接真实 LLM 或客户平台。英文 NER 为概率模型，未保证任意个人信息零漏检。</p></section></div><section><input aria-label="筛选处理记录" id="filter" placeholder="筛选记录编号或占位符"><h2>逐条处理与恢复记录</h2><table><thead><tr><th>记录</th><th>处理后文本</th><th>恢复核验</th></tr></thead><tbody id="records">ROWS</tbody></table></section><footer>独立作品；全部文本与服务均为自建演示。不能将本样例中的通过结果解释为隐私合规、生产就绪或对未知文本的零漏识别保证。身份依精确字符串匹配，原始大小写和标点随映射保留。</footer></main><script>document.querySelector('#filter').addEventListener('input',e=>document.querySelectorAll('#records tr').forEach(r=>r.hidden=!r.textContent.toLowerCase().includes(e.target.value.toLowerCase())))</script></html>'''
    page=page.replace('ORIGINAL',e(original[0]['text'])).replace('CLEANED',e(cleaned[0]['text'])).replace('COUNTS',counts).replace('ROWS',rows)
    (output/'2648_演示总览.html').write_text(page,encoding='utf-8')

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,default=ROOT/'2648_演示数据');args=parser.parse_args();run_demo(args.output)
