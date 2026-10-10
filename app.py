import os, sqlite3, hashlib, hmac, secrets, threading, time
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from werkzeug.utils import secure_filename

BASE = Path(__file__).resolve().parent
PROTECTED = BASE / 'protected_files'
DB = BASE / 'integrity.db'
KEYFILE = BASE / '.integrity_key'
PROTECTED.mkdir(exist_ok=True)
app = Flask(__name__)
app.secret_key = secrets.token_hex(24)


def key():
    if not KEYFILE.exists(): KEYFILE.write_bytes(secrets.token_bytes(32))
    return KEYFILE.read_bytes()

def digest(path):
    sha = hashlib.sha256(); mac = hmac.new(key(), digestmod=hashlib.sha256)
    with open(path,'rb') as f:
        for chunk in iter(lambda:f.read(1024*1024), b''):
            sha.update(chunk); mac.update(chunk)
    return sha.hexdigest(), mac.hexdigest()

def dbconn():
    c=sqlite3.connect(DB, timeout=10); c.row_factory=sqlite3.Row; return c

def init_db():
    with dbconn() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS files(id INTEGER PRIMARY KEY, name TEXT UNIQUE, path TEXT, sha256 TEXT, hmac256 TEXT, size INTEGER, status TEXT, registered_at TEXT, last_checked TEXT);
        CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, file_name TEXT, event_type TEXT, severity TEXT, details TEXT, old_hash TEXT, new_hash TEXT, created_at TEXT);
        ''')

def now(): return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
def log_event(name, typ, sev, details, old='', new=''):
    with dbconn() as c: c.execute('INSERT INTO events(file_name,event_type,severity,details,old_hash,new_hash,created_at) VALUES(?,?,?,?,?,?,?)',(name,typ,sev,details,old,new,now()))

def register(path, replace=False):
    sha, mac=digest(path); st=os.stat(path); n=Path(path).name
    with dbconn() as c:
        old=c.execute('SELECT * FROM files WHERE name=?',(n,)).fetchone()
        if old and not replace: return False
        if old:
            c.execute('UPDATE files SET path=?,sha256=?,hmac256=?,size=?,status=?,registered_at=?,last_checked=? WHERE name=?',(str(path),sha,mac,st.st_size,'SECURE',now(),now(),n))
            log_event(n,'BASELINE_UPDATED','MEDIUM','Authorized baseline updated.',old['sha256'],sha)
        else:
            c.execute('INSERT INTO files(name,path,sha256,hmac256,size,status,registered_at,last_checked) VALUES(?,?,?,?,?,?,?,?)',(n,str(path),sha,mac,st.st_size,'SECURE',now(),now()))
            log_event(n,'REGISTERED','INFO','File added to protected integrity baseline.','',sha)
    return True

def scan():
    with dbconn() as c: rows=c.execute('SELECT * FROM files').fetchall()
    known={r['name'] for r in rows}
    for r in rows:
        p=Path(r['path']); status='SECURE'
        if not p.exists(): status='DELETED'
        else:
            try:
                sha,mac=digest(p)
                if not hmac.compare_digest(mac,r['hmac256']): status='TAMPERED'
            except Exception: status='ERROR'
        if status != r['status']:
            if status=='TAMPERED': log_event(r['name'],'TAMPER_DETECTED','CRITICAL','Cryptographic fingerprint mismatch. File content changed without baseline authorization.',r['sha256'],sha)
            elif status=='DELETED': log_event(r['name'],'FILE_DELETED','CRITICAL','Protected file is missing from monitored storage.',r['sha256'],'')
            elif status=='SECURE': log_event(r['name'],'FILE_RESTORED','INFO','File content matches the trusted cryptographic baseline.',r['sha256'],sha)
        with dbconn() as c: c.execute('UPDATE files SET status=?,last_checked=? WHERE id=?',(status,now(),r['id']))
    for p in PROTECTED.iterdir():
        if p.is_file() and p.name not in known and not p.name.startswith('.'):
            with dbconn() as c:
                exists=c.execute("SELECT 1 FROM events WHERE file_name=? AND event_type='UNREGISTERED_FILE'",(p.name,)).fetchone()
            if not exists: log_event(p.name,'UNREGISTERED_FILE','MEDIUM','New file detected in protected directory but it has no trusted baseline.')

def monitor():
    while True:
        try: scan()
        except Exception as e: print('monitor:',e)
        time.sleep(3)

@app.route('/')
def index():
    scan()
    with dbconn() as c:
        files=c.execute('SELECT * FROM files ORDER BY id DESC').fetchall()
        events=c.execute('SELECT * FROM events ORDER BY id DESC LIMIT 15').fetchall()
    counts={'total':len(files),'secure':sum(x['status']=='SECURE' for x in files),'tampered':sum(x['status']=='TAMPERED' for x in files),'deleted':sum(x['status']=='DELETED' for x in files)}
    return render_template('index.html', files=files, events=events, counts=counts)

@app.post('/upload')
def upload():
    f=request.files.get('file')
    if not f or not f.filename: flash('Choose a file first.','error'); return redirect(url_for('index'))
    name=secure_filename(f.filename); p=PROTECTED/name; f.save(p)
    if register(p): flash(f'{name} registered and protected.','ok')
    else: flash('A protected file with that name already exists. Use Update Baseline only for an authorized change.','error')
    return redirect(url_for('index'))

@app.post('/baseline/<int:file_id>')
def baseline(file_id):
    with dbconn() as c: r=c.execute('SELECT * FROM files WHERE id=?',(file_id,)).fetchone()
    if r and Path(r['path']).exists(): register(Path(r['path']), True); flash('Trusted baseline updated.','ok')
    return redirect(url_for('index'))

@app.post('/scan')
def manual_scan(): scan(); flash('Integrity scan completed.','ok'); return redirect(url_for('index'))

@app.route('/api/status')
def api_status():
    with dbconn() as c:
        files=[dict(x) for x in c.execute('SELECT * FROM files ORDER BY id DESC')]
        events=[dict(x) for x in c.execute('SELECT * FROM events ORDER BY id DESC LIMIT 15')]
    return jsonify(files=files,events=events)

@app.route('/download/<int:file_id>')
def download(file_id):
    with dbconn() as c: r=c.execute('SELECT * FROM files WHERE id=?',(file_id,)).fetchone()
    return send_file(r['path'],as_attachment=True) if r and Path(r['path']).exists() else ('Not found',404)

if __name__=='__main__':
    init_db(); threading.Thread(target=monitor,daemon=True).start(); app.run(host='127.0.0.1',port=5000,debug=False)
