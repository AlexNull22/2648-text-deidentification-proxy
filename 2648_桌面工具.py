"""只在本地执行的文本脱敏/恢复桌面界面。"""
import argparse
import importlib.util
import json
from pathlib import Path
import queue
import tempfile
import threading
import time
import tkinter as tk
from tkinter import ttk
from cryptography.fernet import Fernet

ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('scrub2648',ROOT/'2648_脱敏核心.py')
core=importlib.util.module_from_spec(spec); spec.loader.exec_module(core)
SAMPLE='John Smith works at Microsoft in Seattle. Email john.smith@example.com or call +1 212-555-0100. ZIP 10001; card 4111 1111 1111 1111.'

def make_pipeline(directory):
    directory=Path(directory)
    directory.mkdir(parents=True,exist_ok=True)
    key=directory/'2648_本地密钥.key'
    database=directory/'2648_加密映射.sqlite'
    if not key.exists():
        if database.exists(): raise core.ProcessingError('已有映射库缺少原密钥，请找回密钥；不会生成替换密钥。')
        with key.open('xb') as stream: stream.write(Fernet.generate_key())
    return core.Pipeline(core.Vault(database,key.read_bytes().strip()),core.Detector())

class Application:
    def __init__(self,window,pipeline):
        self.window=window; self.pipeline=pipeline; self.events=queue.Queue(); self.last_session=None; self.last_result=None
        window.title('2648 文本脱敏代理'); window.geometry('1120x700')
        frame=ttk.Frame(window,padding=24); frame.pack(fill='both',expand=True)
        ttk.Label(frame,text='先替换身份，再处理文本',font=('Microsoft YaHei',22,'bold')).pack(anchor='w')
        ttk.Label(frame,text='英文 spaCy 实体识别 + 结构化规则 · 本地加密映射 · 可恢复占位符').pack(anchor='w',pady=(5,15))
        controls=ttk.Frame(frame); controls.pack(fill='x',pady=(0,15))
        ttk.Label(controls,text='会话标识').pack(side='left')
        self.session=tk.StringVar(value='demo2648')
        ttk.Entry(controls,textvariable=self.session,width=26).pack(side='left',padx=12)
        self.scrub_button=ttk.Button(controls,text='识别并脱敏',command=self.scrub); self.scrub_button.pack(side='left',padx=6)
        self.restore_button=ttk.Button(controls,text='本地恢复',command=self.restore,state='disabled'); self.restore_button.pack(side='left',padx=6)
        pane=ttk.Panedwindow(frame,orient='horizontal'); pane.pack(fill='both',expand=True)
        left=ttk.Frame(pane,padding=8); right=ttk.Frame(pane,padding=8); pane.add(left,weight=1); pane.add(right,weight=1)
        ttk.Label(left,text='输入文本（初始为自造样例）').pack(anchor='w',pady=(0,8))
        self.source=tk.Text(left,wrap='word',font=('Consolas',12),undo=True); self.source.pack(fill='both',expand=True); self.source.insert('1.0',SAMPLE)
        ttk.Label(right,text='处理后文本 / 本地恢复结果').pack(anchor='w',pady=(0,8))
        self.output=tk.Text(right,wrap='word',font=('Consolas',12),undo=True); self.output.pack(fill='both',expand=True)
        self.status=tk.StringVar(value='仅在本机处理。英文NER可能漏识别，结果需要人工复核。')
        ttk.Label(frame,textvariable=self.status,wraplength=1050).pack(anchor='w',pady=(14,4))
        ttk.Label(frame,text='会话使用不含个人信息的ASCII标识。密钥和映射库留在2648_本地数据中，不上传。').pack(anchor='w')
        window.after(80,self.poll)
    def launch(self,operation):
        self.scrub_button.configure(state='disabled'); self.restore_button.configure(state='disabled')
        self.status.set('正在本地处理…')
        def worker():
            try: self.events.put(('ok',operation()))
            except Exception: self.events.put(('error',None))
        threading.Thread(target=worker,daemon=True).start()
    def scrub(self):
        text=self.source.get('1.0','end-1c'); session=self.session.get()
        def operation():
            result=self.pipeline.scrub(session,text)
            return {'text':result['payload'],'session':session,'counts':result['counts'],'restored':False}
        self.launch(operation)
    def restore(self):
        text=self.output.get('1.0','end-1c'); session=self.last_session
        self.launch(lambda:{'text':self.pipeline.restore(session,text),'session':session,'counts':{},'restored':True})
    def poll(self):
        try:
            state,result=self.events.get_nowait()
            self.scrub_button.configure(state='normal')
            if state=='error': self.status.set('处理未完成。检查输入、会话或密钥；原文未写入日志。')
            else:
                self.last_result=result
                self.output.delete('1.0','end'); self.output.insert('1.0',result['text'])
                self.last_session=result['session']
                if result['restored']:
                    self.status.set('已使用本次脱敏时的会话在本地恢复。再次恢复前请重新脱敏。')
                else:
                    self.restore_button.configure(state='normal')
                    self.status.set(f'本次替换 {sum(result["counts"].values())} 处：'+json.dumps(result['counts'],ensure_ascii=False)+'。请人工复核。')
        except queue.Empty: pass
        self.window.after(80,self.poll)

def self_check():
    with tempfile.TemporaryDirectory(prefix='2648_桌面验收_') as folder:
        window=tk.Tk(); window.withdraw(); app=Application(window,make_pipeline(folder))
        app.scrub_button.invoke(); deadline=time.monotonic()+15
        while app.last_result is None and time.monotonic()<deadline: window.update(); time.sleep(.02)
        assert app.last_result and sum(app.last_result['counts'].values())==7
        assert 'John Smith' not in app.output.get('1.0','end-1c')
        app.session.set('different_session') # restore stays bound to the successful scrub session
        app.last_result=None; app.restore_button.invoke(); deadline=time.monotonic()+15
        while app.last_result is None and time.monotonic()<deadline: window.update(); time.sleep(.02)
        assert app.output.get('1.0','end-1c')==SAMPLE
        window.destroy()
        print(json.dumps({'desktop_integration_passed':True,'replacements':7,'exact_restore':True,'restore_session_bound':True}))

if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--self-check',action='store_true'); args=parser.parse_args()
    if args.self_check:self_check()
    else:
        window=tk.Tk(); Application(window,make_pipeline(ROOT/'2648_本地数据')); window.mainloop()
