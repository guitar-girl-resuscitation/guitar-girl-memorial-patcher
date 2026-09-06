"""Real Rust ingress + synthetic subprocess workers; no game files or secrets."""
import concurrent.futures
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("managed", ROOT / "deploy/run_managed.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
WORKER = r'''
import os,json,time,sys
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
c=json.loads(Path(os.environ['GGFM_PATCHER_CONFIG']).read_text())
time.sleep(c.get('startupDelay',0))
if c.get('badHealth'): sys.exit(17)
revision=c['testRevision']
class H(BaseHTTPRequestHandler):
 def log_message(self,*args): pass
 def do_GET(self):
  if self.path=='/slow':
   self.send_response(200); self.send_header('Content-Length','60000'); self.end_headers()
   for i in range(60): self.wfile.write(b'x'*1000);self.wfile.flush();time.sleep(.06)
   return
  body=json.dumps({'ok':True,'androidVersion':{'revision':revision},'revision':revision,
   'ip':self.headers.get('x-ggfm-client-ip'),'key':bool(self.headers.get('x-ggfm-gateway-key'))}).encode()
  self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
 def do_POST(self):
  if self.headers.get('Content-Length'): self.rfile.read(int(self.headers['Content-Length']))
  self.do_GET()
host,port=c['listen'].split(':')
ThreadingHTTPServer((host,int(port)),H).serve_forever()
'''

def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]

class BlueGreenTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ggfm-bluegreen-')
        self.root = Path(self.tmp.name)
        self.binary = Path(os.environ.get('GGFM_TEST_GATEWAY', ROOT / 'target/debug' / ('ggfm-patcher-web.exe' if os.name == 'nt' else 'ggfm-patcher-web')))
        if not self.binary.is_file(): self.skipTest('build ggfm-patcher-web before these integration tests')
        self.base = json.loads((ROOT / 'config/patcher.example.json').read_text())
        self.base['listen'] = f'127.0.0.1:{free_port()}'
        self.base['security'] = {'requestsPerMinute':1000,'apiPerMinute':1000,'downloadsPerTenMinutes':1000}
        self.saved_env = dict(os.environ)
        self.blue = m.BlueGreen(self.root,self.base,self.binary,settle=.3,retain=0)
        self.script = self.root/'worker.py'; self.script.write_text(WORKER)
        self.children = []
        def start(g):
            p = subprocess.Popen([sys.executable,str(self.script)],env=m.child_env(g))
            self.children.append(p); return p
        self.mocks = [patch.object(m,'start',start),patch.object(m,'supports_blue_green',return_value=True)]
        for mock in self.mocks: mock.start()
        m.STOP=False
        self.old = self.blue.backend(self.generation(8))
        self.child = m.start(self.old)
        self.assertTrue(m.ready(self.old,self.child))
        self.state = {'active':self.old,'pair':'old','counter':9,'identity':{'signer':'unchanged'}}
        self.statefile = self.root/'state.json';m.atomic_json(self.statefile,self.state)
        self.blue.start_gateway(self.old)
        self.url = 'http://'+self.base['listen']
        for _ in range(100):
            try:
                self.get('/healthz'); break
            except (OSError,ValueError): time.sleep(.05)
        else: self.fail('gateway failed to bind')

    def generation(self,revision,**flags):
        c=dict(self.base,testRevision=revision,**flags)
        path=self.root/f'g{revision}.json';path.write_text(json.dumps(c))
        return {'binary':str(self.binary),'config':str(path),'revision':revision}
    def get(self,path,data=None,headers=None):
        req=urllib.request.Request(self.url+path,data=data,headers=headers or {})
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req,timeout=8) as res:
            return json.loads(res.read())
    def tearDown(self):
        if hasattr(self,'blue'): self.blue.close()
        for child in getattr(self,'children',[]): m.stop(child)
        for mock in reversed(getattr(self,'mocks',[])): mock.stop()
        if hasattr(self,'saved_env'):
            os.environ.clear();os.environ.update(self.saved_env)
        self.tmp.cleanup()

    def test_stream_old_tokens_and_no_gap_during_real_cutover(self):
        seen=[]; failures=[]; done=threading.Event()
        def poll():
            while not done.is_set():
                try: seen.append(self.get('/healthz')['revision'])
                except Exception as error: failures.append(str(error))
                time.sleep(.04)
        thread=threading.Thread(target=poll);thread.start()
        with concurrent.futures.ThreadPoolExecutor(1) as pool:
            stream=pool.submit(lambda: urllib.request.urlopen(self.url+'/slow',timeout=8).read())
            time.sleep(.15)
            active,child=self.blue.activate(self.generation(9,startupDelay=.5),self.old,self.child,self.state,self.statefile,'new')
            self.assertFalse(stream.done(), 'slow download must span the cutover')
            self.assertEqual(len(stream.result()),60000)
        done.set();thread.join()
        self.assertEqual(active['revision'],9)
        self.assertFalse(failures,failures)
        self.assertIn(8,seen)
        self.assertEqual(self.get('/healthz')['revision'],9)
        self.assertEqual(self.get('/api/v1/download/g8.test')['revision'],8)
        self.assertEqual(self.get('/api/v1/download/g9.test')['revision'],9)
        body=json.dumps({'proof':{'nonce':'g8.test','chunksBase64':[]}}).encode()
        self.assertEqual(self.get('/api/v1/prebuilt/prove',body,{'Content-Type':'application/json'})['revision'],8)
        self.assertEqual(self.state['identity']['signer'],'unchanged')
        # Authenticated local forwarding, not a spoofable public header.
        result=self.get('/',headers={'x-ggfm-client-ip':'198.51.100.1','x-ggfm-gateway-key':'forged'})
        self.assertEqual(result['ip'],'127.0.0.1');self.assertTrue(result['key'])
        # A crashed newly-active process rolls back without restarting old.
        m.stop(child)
        rolled,_=self.blue.maintain(active,child,self.state,self.statefile)
        self.assertEqual(rolled['revision'],8)
        self.assertEqual(self.get('/healthz')['revision'],8)

    def test_failed_candidate_and_state_commit_leave_old_online(self):
        for flags in ({'badHealth':True},{'startupDelay':.1}):
            ctx=patch.object(m,'atomic_json',side_effect=OSError('disk full')) if 'startupDelay' in flags else patch.object(m,'log')
            candidate=self.generation(9,**flags)
            # Only inject failure at publication, not while preparing runtime config.
            if 'startupDelay' in flags:
                original=m.atomic_json
                def persist(path,value):
                    if path==self.statefile: raise OSError('disk full')
                    original(path,value)
                ctx=patch.object(m,'atomic_json',side_effect=persist)
            with ctx:
                active,child=self.blue.activate(candidate,self.old,self.child,self.state,self.statefile,'new')
            self.assertEqual(active,self.old);self.assertIs(child,self.child)
            self.assertEqual(self.get('/healthz')['revision'],8)
            self.assertEqual(json.loads(self.statefile.read_text())['pair'],'old')

    def test_unknown_generation_is_not_forwarded_to_new_worker(self):
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.get('/api/v1/download/g999.test')
        self.assertEqual(error.exception.code,410)

    def test_retirement_waits_for_streams_and_token_quiet_period(self):
        active,child=self.blue.activate(self.generation(9),self.old,self.child,self.state,self.statefile,'new')
        self.blue.gateway.terminate()
        self.blue.gateway.wait()
        # Freeze stats writing and replace only the liveness observation.
        with patch.object(self.blue.gateway,'poll',return_value=None):
            stats=self.blue.routes.with_suffix('.stats.json')
            old,old_child,_,_,pair=self.blue.retired
            self.blue.retired=(old,old_child,time.monotonic()-2000,time.monotonic()-2000,pair)
            m.atomic_json(stats,{'8':1})
            self.blue.maintain(active,child,self.state,self.statefile)
            self.assertIsNone(old_child.poll())
            m.atomic_json(stats,{'8':0})
            self.blue.maintain(active,child,self.state,self.statefile)
            self.assertIsNone(old_child.poll(), 'recent stream may have issued a token')
            self.blue.retired=(old,old_child,time.monotonic()-2000,time.monotonic()-601,pair)
            self.blue.maintain(active,child,self.state,self.statefile)
            self.assertIsNotNone(old_child.poll())
            self.assertEqual(json.loads(self.blue.routes.read_text())['targets'],{'9':active['port']})

if __name__=='__main__': unittest.main()
