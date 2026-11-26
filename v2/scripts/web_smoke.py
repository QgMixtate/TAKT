#!/usr/bin/env python3
"""Production static Web UI against real isolated backend/PG; private browser inputs."""
import http.client,http.server,json,os,ssl,subprocess,threading,urllib.parse
from pathlib import Path
from machine_smoke import main as machine_harness,freeport
from dev import ROOT
POLICY="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
def browser_scenario(**s):
 context=ssl.create_default_context(cafile=s['ca_file']);port=urllib.parse.urlsplit(s['origin']).port
 class Handler(http.server.SimpleHTTPRequestHandler):
  def __init__(self,*args,**kwargs):super().__init__(*args,directory=str(ROOT/'web/dist'),**kwargs)
  def log_message(self,*args):pass
  def end_headers(self):self.send_header('Content-Security-Policy',POLICY);self.send_header('Cache-Control','no-store');super().end_headers()
  def dispatch(self):
   if self.path.startswith('/api/') or self.path.startswith('/health/'):
    length=int(self.headers.get('Content-Length','0'))
    if length>1048576:self.send_error(413);return
    body=self.rfile.read(length);headers={k:v for k,v in self.headers.items() if k.lower() not in ('host','connection','content-length')};connection=http.client.HTTPSConnection('127.0.0.1',s['center_port'],context=context,timeout=20)
    try:
     connection.request(self.command,self.path,body=body,headers=headers);response=connection.getresponse();raw=response.read();self.send_response(response.status)
     for key,value in response.getheaders():
      if key.lower() not in ('connection','content-length','transfer-encoding'):self.send_header(key,value)
     self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
    finally:connection.close()
   elif self.path in ('/contracts/openapi.json','/contracts/c09.openapi.json'):
    raw=(ROOT/'.dist/contracts'/self.path.rsplit('/',1)[1]).read_bytes();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
   elif self.command=='GET':super().do_GET()
   else:self.send_error(405)
  do_GET=dispatch
  do_POST=dispatch
  do_DELETE=dispatch
  do_PATCH=dispatch
  do_PUT=dispatch
 server=http.server.ThreadingHTTPServer(('127.0.0.1',port),Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();path=s['directory']/'browser-input.json';fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 # C23 из Web: настоящий portable init/collect этого хоста — вывод init вставляется в Web, пакет загружается из браузера
 site,scope=s['sql']("SELECT site_id::text||' '||scope_id::text FROM scope.network_scopes LIMIT 1").split();pdir=s['directory']/'portable-web';pdir.mkdir(mode=0o700)
 init=subprocess.run([str(ROOT/'.dist/surveyscan-portable'),'init','--state',str(pdir/'state'),'--tenant',s['tenant'],'--site',site,'--scope',scope],capture_output=True,text=True,check=True,timeout=30).stdout
 subprocess.run([str(ROOT/'.dist/surveyscan-portable'),'collect','--state',str(pdir/'state'),'--out',str(pdir/'audit.zip')],capture_output=True,check=True,timeout=120)
 with os.fdopen(fd,'w') as f:json.dump({**{k:s[k] for k in ('origin','username','password','asset')},'portable_init':init,'portable_package':str(pdir/'audit.zip'),'installer':INSTALLER},f)
 try:
  env=dict(os.environ);env.setdefault('PLAYWRIGHT_BROWSERS_PATH','/workspace/.cache/surveyscan-browsers');subprocess.run(['node','scripts/smoke.mjs',str(path)],cwd=ROOT/'web',env=env,check=True,timeout=80)
 finally:server.shutdown();server.server_close();thread.join(timeout=5)
def fake_release():
 """C52.04: каталог выпуска для центра в смоке — файлы установки и manifest (без подписи: ключ центру не задаётся)."""
 import hashlib,tempfile
 root=Path(tempfile.mkdtemp(prefix='c52-release-'));(root/'installers').mkdir()
 files={'surveyscan-collector_0.0.0-c13_windows_x64.msi':os.urandom(40000),'surveyscan-collector_0.0.0~c13-1_amd64.deb':os.urandom(20000)}
 index={'format':'surveyscan-installers-v1','files':[{'name':'surveyscan-collector_0.0.0-c13_windows_x64.msi','component':'collector','os':'windows','arch':'x64','format':'msi'},
  {'name':'surveyscan-collector_0.0.0~c13-1_amd64.deb','component':'collector','os':'linux','arch':'amd64','format':'deb'}]}
 files['index.json']=json.dumps(index).encode();entries={}
 for n,b in files.items():(root/'installers'/n).write_bytes(b);entries['installers/'+n]={'sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b),'mode':420}
 (root/'release-manifest.json').write_text(json.dumps({'format':'surveyscan-release-v1','version':'0.0.0-c13','files':entries}))
 name='surveyscan-collector_0.0.0-c13_windows_x64.msi';return root,{'name':name,'sha256':entries['installers/'+name]['sha256'],'version':'0.0.0-c13'}
if __name__=='__main__':
 RELEASE,INSTALLER=fake_release();os.environ['SURVEYSCAN_V2_RELEASE_DIR']=str(RELEASE)
 machine_harness(web_scenario=browser_scenario,browser_origin=f'http://127.0.0.1:{freeport()}',inventory12=True) # 1.2: импорт portable-пакета из Web (C23)
