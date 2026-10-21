"""英文文本脱敏演示：真实spaCy实体识别、规则匹配、加密映射与本机下游。"""
from __future__ import annotations
import argparse
from collections import Counter
import csv
import importlib.util
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import re
import sys
import threading
import urllib.request
from urllib.parse import urlsplit
import uuid

ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('vault2648',ROOT/'2648_加密映射库.py')
vault_module=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=vault_module
spec.loader.exec_module(vault_module)
Vault=vault_module.Vault
TOKENISH=re.compile(r'\[[A-Z][A-Z_]*_\d+\]')
LIMIT=100_000

class ProcessingError(Exception):
    """错误信息不得包含传入原文。"""

class Detector:
    def __init__(self,model_name='en_core_web_sm'):
        import spacy
        try:
            self.nlp=spacy.load(model_name,disable=['tagger','parser','lemmatizer','attribute_ruler'])
            if 'ner' not in self.nlp.pipe_names: raise ValueError()
        except Exception:
            raise ProcessingError('实体模型未就绪；处理已停止，请安装en_core_web_sm。') from None
        self.model_name=model_name
        self.model_version=self.nlp.meta.get('version','unknown')
        self.lock=threading.Lock()
    def detect(self,text):
        if not isinstance(text,str) or len(text)>LIMIT:
            raise ProcessingError('文本类型或长度不受支持。')
        candidates=[]
        patterns=[
            ('CARD',r'(?<!\w)(?:\d[ -]?){12,18}\d(?!\w)',100),
            ('EMAIL',r'(?<![\w.+-])[A-Za-z0-9.!#$%&\x27*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,}(?![\w.-])',90),
            ('PHONE',r'(?<!\w)(?:\+\d{1,3}[ .-]?)?(?:\(\d{2,4}\)|\d{2,4})[ .-]\d{3,4}[ .-]\d{3,4}(?:\s*(?:ext\.?|x)\s*\d{1,5})?(?!\w)',80),
            ('PHONE',r'(?<!\w)\+?\d{10,12}(?!\w)',80),
            ('POSTAL',r'(?<![\w-])\d{5}(?:-\d{4})?(?![\w-])',70),
        ]
        for kind,pattern,priority in patterns:
            for match in re.finditer(pattern,text,flags=re.IGNORECASE):
                candidates.append(dict(start=match.start(),end=match.end(),kind=kind,value=match.group(),priority=priority))
        try:
            with self.lock:
                doc=self.nlp(text)
            types={'PERSON':'PERSON','ORG':'CORP','GPE':'LOCATION','LOC':'LOCATION'}
            for ent in doc.ents:
                if ent.label_ in types:
                    candidates.append(dict(start=ent.start_char,end=ent.end_char,kind=types[ent.label_],value=ent.text,priority=50))
        except Exception:
            raise ProcessingError('实体识别失败；处理已停止，没有发送原文。') from None
        selected=[]
        for item in sorted(candidates,key=lambda x:(-x['priority'],-(x['end']-x['start']),x['start'])):
            if not any(item['start']<old['end'] and old['start']<item['end'] for old in selected):
                selected.append(item)
        return [{k:v for k,v in x.items() if k!='priority'} for x in sorted(selected,key=lambda x:x['start'])]

def validate_payload(payload,*,reject_tokens=True):
    try:
        if len(json.dumps(payload,ensure_ascii=False,allow_nan=False))>LIMIT:
            raise ProcessingError('载荷超过100000字符限制。')
    except (TypeError,ValueError,RecursionError):
        raise ProcessingError('载荷必须是有限的JSON数据。') from None
    strings=[]
    nodes=[0]
    def walk(value,depth=0):
        nodes[0]+=1
        if depth>12 or nodes[0]>2000: raise ProcessingError('载荷层级或项数超过限制。')
        if isinstance(value,str):
            if reject_tokens and TOKENISH.search(value):
                raise ProcessingError('输入含保留占位符；为避免恢复歧义，已拒绝。')
            strings.append(value)
        elif value is None or type(value) is bool: pass
        elif type(value) in (int,float):
            if abs(value)>=10_000:
                raise ProcessingError('五位及以上数值须使用文本形式提交，以便识别潜在个人信息。')
        elif isinstance(value,list):
            for child in value: walk(child,depth+1)
        elif isinstance(value,dict):
            for key,child in value.items():
                if not isinstance(key,str): raise ProcessingError('JSON对象的键必须是文本。')
                walk(key,depth+1); walk(child,depth+1)
        else: raise ProcessingError('载荷包含不受支持的数据类型。')
    walk(payload)
    return strings

def transform(payload,convert):
    if isinstance(payload,str): return convert(payload)
    if isinstance(payload,list): return [transform(v,convert) for v in payload]
    if isinstance(payload,dict):
        output={}
        for key,value in payload.items():
            new=convert(key)
            if new in output: raise ProcessingError('转换后字段名发生冲突，处理已停止。')
            output[new]=transform(value,convert)
        return output
    return payload

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,request,fp,code,message,headers,newurl):
        fp.close()
        raise ProcessingError('下游重定向被拒绝。')

def local_endpoint(url):
    try:
        p=urlsplit(url)
        if p.scheme!='http' or p.hostname not in ('127.0.0.1','::1') or p.username or p.password or p.query or p.fragment or not p.port or not re.fullmatch(r'/[A-Za-z0-9_/-]*',p.path or '/'):
            raise ValueError()
        return url
    except (ValueError,TypeError):
        raise ProcessingError('演示下游仅支持明确端口的本机HTTP地址，不允许凭据、查询或重定向。') from None

class Pipeline:
    def __init__(self,vault,detector):
        self.vault=vault; self.detector=detector
    def scrub(self,session,payload):
        self.vault.stats(session) # preflight session before model or payload processing
        strings=validate_payload(payload)
        # Detect every string before producing tokens; failed NER cannot fall back to raw data.
        detected={s:self.detector.detect(s) for s in dict.fromkeys(strings)}
        counts=Counter()
        def convert(text):
            parts=[]; cursor=0
            for item in detected[text]:
                parts.append(text[cursor:item['start']])
                parts.append(self.vault.token_for(session,item['kind'],item['value']))
                counts[item['kind']]+=1
                cursor=item['end']
            parts.append(text[cursor:])
            return ''.join(parts)
        cleaned=transform(payload,convert)
        return {'payload':cleaned,'counts':dict(sorted(counts.items()))}
    def restore(self,session,payload):
        self.vault.stats(session)
        validate_payload(payload,reject_tokens=False)
        return transform(payload,lambda text:self.vault.restore_text(session,text))
    def forward(self,session,payload,url,queue_dir):
        local_endpoint(url)
        cleaned=self.scrub(session,payload)
        body=json.dumps({'session':session,**cleaned},ensure_ascii=False).encode('utf-8')
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
        try:
            with opener.open(urllib.request.Request(url,data=body,headers={'Content-Type':'application/json'},method='POST'),timeout=5) as response:
                status=response.status
                if not 200<=status<300: raise ValueError()
            return {'status':'delivered','http_status':status,**cleaned}
        except Exception as exc:
            if hasattr(exc,'close'): exc.close()
            queue_dir=Path(queue_dir)
            if any(p.is_symlink() or (hasattr(p,'is_junction') and p.is_junction()) for p in (queue_dir,*queue_dir.parents)):
                raise ProcessingError('异常队列路径不能使用符号链接。') from None
            queue_dir.mkdir(parents=True,exist_ok=True)
            target=queue_dir/f'2648_待重试_{uuid.uuid4().hex}.json'
            temporary=target.with_suffix('.tmp')
            queued={'schema_version':1,'session':session,'reason':'downstream_unavailable',**cleaned}
            try:
                with temporary.open('x',encoding='utf-8') as stream:
                    json.dump(queued,stream,ensure_ascii=False,indent=2)
                    stream.flush(); os.fsync(stream.fileno())
                os.replace(temporary,target)
            finally:
                if temporary.exists(): temporary.unlink()
            return {'status':'queued','queue_file':target.name,**cleaned}

def load_input(path):
    path=Path(path)
    if path.stat().st_size>LIMIT: raise ProcessingError('输入文件超过100000字节限制。')
    with path.open(encoding='utf-8-sig',newline='') as stream:
        if path.suffix.lower()=='.csv':
            reader=csv.DictReader(stream)
            if not reader.fieldnames or len(reader.fieldnames)!=len(set(reader.fieldnames)):
                raise ProcessingError('CSV表头为空或重复。')
            rows=list(reader)
            if any(None in r or None in r.values() for r in rows): raise ProcessingError('CSV列数不一致。')
            return rows
        try: return strict_json(stream.read())
        except (ValueError,RecursionError): raise ProcessingError('JSON格式无效。') from None

def strict_json(text):
    def pairs(items):
        result={}
        for key,value in items:
            if key in result: raise ProcessingError('JSON键重复。')
            result[key]=value
        return result
    def constant(_): raise ProcessingError('JSON含非有限数字。')
    return json.loads(text,object_pairs_hook=pairs,parse_constant=constant)

def serve(pipeline,port=8763,forward_url=None,queue_dir='2648_异常队列'):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args): pass # never log payload or request path
        def do_POST(self):
            code=200
            try:
                expected=f'127.0.0.1:{self.server.server_port}'
                if self.headers.get('Host')!=expected or self.headers.get('Origin') not in (None,'http://'+expected) or self.headers.get_content_type()!='application/json':
                    raise ProcessingError('请求来源或内容类型被拒绝。')
                length=int(self.headers.get('Content-Length','0'))
                if not 0<length<=LIMIT: raise ProcessingError('请求长度不受支持。')
                request=strict_json(self.rfile.read(length))
                if not isinstance(request,dict) or set(request)!={'session','payload'}:
                    raise ProcessingError('请求必须包含session和payload。')
                if self.path=='/scrub': response=pipeline.scrub(request['session'],request['payload'])
                elif self.path=='/restore': response={'payload':pipeline.restore(request['session'],request['payload'])}
                elif self.path=='/forward' and forward_url:
                    response=pipeline.forward(request['session'],request['payload'],forward_url,queue_dir)
                else: raise ProcessingError('请求路径不可用。')
            except Exception:
                code=400; response={'error':'request_rejected','message':'请求未完成；检查数据格式、会话、模型和密钥。'}
            body=json.dumps(response,ensure_ascii=False).encode('utf-8')
            self.send_response(code); self.send_header('Content-Type','application/json; charset=utf-8'); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
    return ThreadingHTTPServer(('127.0.0.1',port),Handler)

def main():
    parser=argparse.ArgumentParser(description='2648 本地脱敏代理：英文NER与结构化规则演示')
    parser.add_argument('--input',type=Path); parser.add_argument('--output',type=Path)
    parser.add_argument('--vault',type=Path,default=Path('2648_本地映射.sqlite'))
    parser.add_argument('--key-file',type=Path,required=True)
    parser.add_argument('--create-key',action='store_true')
    parser.add_argument('--session',default='demo2648'); parser.add_argument('--restore',action='store_true')
    parser.add_argument('--forward-url'); parser.add_argument('--queue-dir',type=Path,default=Path('2648_异常队列'))
    parser.add_argument('--serve',action='store_true'); parser.add_argument('--port',type=int,default=8763)
    args=parser.parse_args()
    output_stream=None; completed=False
    try:
        if args.create_key:
            from cryptography.fernet import Fernet
            with args.key_file.open('xb') as stream: stream.write(Fernet.generate_key())
            print('2648_密钥已生成，请单独保管。'); return 0
        if not args.serve:
            if not args.input or not args.output: raise ProcessingError('需要--input与--output。')
            paths=[args.input,args.output,args.vault,args.key_file]
            if len({p.resolve() for p in paths})!=len(paths):
                raise ProcessingError('输入、输出、映射库和密钥路径必须互不相同。')
            # Reserve an exclusive writable result before any model, vault or forwarding side effect.
            output_stream=args.output.open('x',encoding='utf-8')
        pipeline=Pipeline(Vault(args.vault,args.key_file.read_bytes().strip()),Detector())
        if args.serve:
            server=serve(pipeline,args.port,args.forward_url,args.queue_dir)
            print(f'2648_本机接口：http://127.0.0.1:{server.server_port}（仅本机演示）',flush=True)
            try: server.serve_forever()
            except KeyboardInterrupt: pass
            finally: server.server_close()
            return 0
        original=load_input(args.input)
        if args.restore: result=pipeline.restore(args.session,original)
        elif args.forward_url: result=pipeline.forward(args.session,original,args.forward_url,args.queue_dir)
        else: result=pipeline.scrub(args.session,original)['payload']
        json.dump(result,output_stream,ensure_ascii=False,indent=2)
        output_stream.flush(); os.fsync(output_stream.fileno()); completed=True
        print('2648_处理完成，结果已保存。'); return 0
    except Exception:
        print('2648_处理未完成：检查模型、密钥、数据格式与输出路径；原文未写入日志。',file=sys.stderr)
        return 2
    finally:
        if output_stream is not None:
            output_stream.close()
            if not completed: args.output.unlink(missing_ok=True)

if __name__=='__main__': raise SystemExit(main())
