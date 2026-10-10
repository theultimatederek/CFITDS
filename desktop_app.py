import os, sqlite3, hashlib, hmac, secrets, threading, time
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

BASE = Path(__file__).resolve().parent
DATA = BASE / 'data'; DATA.mkdir(exist_ok=True)
DB = DATA / 'integrity.db'; KEYFILE = DATA / '.integrity_key'
SCAN_SECONDS = 3


def now(): return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
def key():
    if not KEYFILE.exists(): KEYFILE.write_bytes(secrets.token_bytes(32))
    return KEYFILE.read_bytes()
def digest(path):
    sha=hashlib.sha256(); mac=hmac.new(key(), digestmod=hashlib.sha256)
    with open(path,'rb') as f:
        for chunk in iter(lambda:f.read(1024*1024), b''):
            sha.update(chunk); mac.update(chunk)
    return sha.hexdigest(), mac.hexdigest()
def dbconn():
    c=sqlite3.connect(DB, timeout=30)
    c.row_factory=sqlite3.Row
    c.execute('PRAGMA busy_timeout=30000')
    return c
def init_db():
    with dbconn() as c:
        c.execute('PRAGMA journal_mode=WAL')
        c.execute('PRAGMA synchronous=NORMAL')
        c.executescript('''
        CREATE TABLE IF NOT EXISTS files(id INTEGER PRIMARY KEY, name TEXT, path TEXT UNIQUE, sha256 TEXT, hmac256 TEXT, size INTEGER, status TEXT, registered_at TEXT, last_checked TEXT);
        CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, file_name TEXT, event_type TEXT, severity TEXT, details TEXT, old_hash TEXT, new_hash TEXT, created_at TEXT);
        ''')
def log_event(name, typ, sev, details, old='', new=''):
    with dbconn() as c: c.execute('INSERT INTO events(file_name,event_type,severity,details,old_hash,new_hash,created_at) VALUES(?,?,?,?,?,?,?)',(name,typ,sev,details,old,new,now()))
def register(path, replace=False):
    p=Path(path).resolve(); sha,mac=digest(p); st=p.stat()
    with dbconn() as c:
        old=c.execute('SELECT * FROM files WHERE path=?',(str(p),)).fetchone()
        if old and not replace: return False
        if old:
            old_sha=old['sha256']
            c.execute('UPDATE files SET sha256=?,hmac256=?,size=?,status=?,registered_at=?,last_checked=? WHERE id=?',(sha,mac,st.st_size,'SECURE',now(),now(),old['id']))
            event=('BASELINE_UPDATED','MEDIUM','Authorized cryptographic baseline updated.',old_sha,sha)
        else:
            c.execute('INSERT INTO files(name,path,sha256,hmac256,size,status,registered_at,last_checked) VALUES(?,?,?,?,?,?,?,?)',(p.name,str(p),sha,mac,st.st_size,'SECURE',now(),now()))
            event=('REGISTERED','INFO','File registered in trusted integrity baseline.','',sha)
    # Log only after the baseline transaction is committed/closed.
    log_event(p.name,*event)
    return True
def remove_file(fid):
    removed_name=None
    with dbconn() as c:
        r=c.execute('SELECT * FROM files WHERE id=?',(fid,)).fetchone()
        if r:
            removed_name=r['name']
            c.execute('DELETE FROM files WHERE id=?',(fid,))
    if removed_name:
        log_event(removed_name,'UNREGISTERED','INFO','File removed from active monitoring. It was not deleted from disk.')
def scan():
    with dbconn() as c: rows=c.execute('SELECT * FROM files').fetchall()
    for r in rows:
        p=Path(r['path']); status='SECURE'; current=''
        if not p.exists(): status='DELETED'
        else:
            try:
                current,mac=digest(p)
                if not hmac.compare_digest(mac,r['hmac256']): status='TAMPERED'
            except Exception: status='ERROR'
        if status != r['status']:
            if status=='TAMPERED': log_event(r['name'],'TAMPER_DETECTED','CRITICAL','HMAC-SHA-256 verification failed: file content differs from trusted baseline.',r['sha256'],current)
            elif status=='DELETED': log_event(r['name'],'FILE_DELETED','CRITICAL','Protected file is missing from its original location.',r['sha256'],'')
            elif status=='SECURE': log_event(r['name'],'FILE_RESTORED','INFO','File again matches the trusted cryptographic baseline.',r['sha256'],current)
            elif status=='ERROR': log_event(r['name'],'SCAN_ERROR','HIGH','File could not be read during integrity verification.',r['sha256'],current)
        with dbconn() as c: c.execute('UPDATE files SET status=?,last_checked=? WHERE id=?',(status,now(),r['id']))

def short_hash(s): return (s[:12]+'…'+s[-8:]) if s and len(s)>24 else (s or '—')

class App(tk.Tk):
    def __init__(self):
        super().__init__(); self.title('CFITDS — Cryptographic File Integrity & Tamper Detection System')
        self.geometry('1260x760'); self.minsize(1050,650); self.protocol('WM_DELETE_WINDOW',self.close)
        self.running=True; self.last_critical=0
        self.configure(bg='#0b1220'); self._style(); self._ui(); self.refresh(); threading.Thread(target=self.monitor,daemon=True).start()
    def _style(self):
        s=ttk.Style(self); s.theme_use('clam')
        s.configure('Treeview', background='#111827', fieldbackground='#111827', foreground='#e5e7eb', rowheight=30, borderwidth=0)
        s.configure('Treeview.Heading', background='#1f2937', foreground='#f9fafb', relief='flat', font=('Segoe UI',10,'bold'))
        s.map('Treeview', background=[('selected','#2563eb')])
    def _ui(self):
        top=tk.Frame(self,bg='#0f172a',height=72); top.pack(fill='x'); top.pack_propagate(False)
        tk.Label(top,text='🛡  CFITDS',font=('Segoe UI',20,'bold'),fg='#f8fafc',bg='#0f172a').pack(side='left',padx=24)
        tk.Label(top,text='Cryptographic File Integrity & Tamper Detection System',font=('Segoe UI',11),fg='#94a3b8',bg='#0f172a').pack(side='left')
        tk.Button(top,text='＋ Protect File',command=self.add_file,bg='#2563eb',fg='white',activebackground='#1d4ed8',relief='flat',font=('Segoe UI',10,'bold'),padx=16,pady=8).pack(side='right',padx=24,pady=16)
        main=tk.Frame(self,bg='#0b1220'); main.pack(fill='both',expand=True,padx=22,pady=18)
        cards=tk.Frame(main,bg='#0b1220'); cards.pack(fill='x')
        self.cardvars={k:tk.StringVar(value='0') for k in ('Protected','Secure','Tampered','Missing')}
        for i,(k,sub) in enumerate([('Protected','files monitored'),('Secure','verified'),('Tampered','integrity failed'),('Missing','deleted/moved')]):
            f=tk.Frame(cards,bg='#111827',highlightthickness=1,highlightbackground='#263244'); f.grid(row=0,column=i,sticky='ew',padx=(0 if i==0 else 6,6 if i<3 else 0),ipady=10); cards.grid_columnconfigure(i,weight=1)
            tk.Label(f,text=k.upper(),fg='#94a3b8',bg='#111827',font=('Segoe UI',9,'bold')).pack(anchor='w',padx=16,pady=(6,0))
            tk.Label(f,textvariable=self.cardvars[k],fg='#f8fafc',bg='#111827',font=('Segoe UI',25,'bold')).pack(anchor='w',padx=16)
            tk.Label(f,text=sub,fg='#64748b',bg='#111827',font=('Segoe UI',9)).pack(anchor='w',padx=16,pady=(0,4))
        action=tk.Frame(main,bg='#0b1220'); action.pack(fill='x',pady=(15,8))
        tk.Label(action,text='Protected Files',font=('Segoe UI',14,'bold'),fg='#f8fafc',bg='#0b1220').pack(side='left')
        for text,cmd in [('Scan Now',self.manual_scan),('Update Baseline',self.update_baseline),('Remove Monitoring',self.remove_selected)]:
            tk.Button(action,text=text,command=cmd,bg='#1f2937',fg='#e5e7eb',activebackground='#374151',relief='flat',padx=12,pady=6).pack(side='right',padx=(8,0))
        cols=('status','name','path','hash','checked'); self.tree=ttk.Treeview(main,columns=cols,show='headings',height=9)
        widths=(100,190,430,190,160)
        for c,t,w in zip(cols,['STATUS','FILE','ORIGINAL LOCATION','TRUSTED SHA-256','LAST CHECKED'],widths): self.tree.heading(c,text=t); self.tree.column(c,width=w,anchor='w')
        self.tree.pack(fill='x'); self.tree.tag_configure('TAMPERED',foreground='#fca5a5'); self.tree.tag_configure('DELETED',foreground='#fcd34d'); self.tree.tag_configure('SECURE',foreground='#86efac')
        low=tk.Frame(main,bg='#0b1220'); low.pack(fill='both',expand=True,pady=(15,0))
        left=tk.Frame(low,bg='#111827',highlightthickness=1,highlightbackground='#263244'); left.pack(side='left',fill='both',expand=True,padx=(0,8))
        right=tk.Frame(low,bg='#111827',highlightthickness=1,highlightbackground='#263244',width=365); right.pack(side='right',fill='both',padx=(8,0)); right.pack_propagate(False)
        tk.Label(left,text='Security Audit Trail',font=('Segoe UI',12,'bold'),fg='#f8fafc',bg='#111827').pack(anchor='w',padx=14,pady=10)
        self.events=ttk.Treeview(left,columns=('time','severity','event','file'),show='headings',height=8)
        for c,t,w in [('time','TIME',145),('severity','SEVERITY',90),('event','EVENT',170),('file','FILE',220)]: self.events.heading(c,text=t); self.events.column(c,width=w,anchor='w')
        self.events.pack(fill='both',expand=True,padx=10,pady=(0,10))
        tk.Label(right,text='Integrity Evidence',font=('Segoe UI',12,'bold'),fg='#f8fafc',bg='#111827').pack(anchor='w',padx=14,pady=10)
        self.detail=tk.Text(right,bg='#0f172a',fg='#cbd5e1',insertbackground='white',relief='flat',wrap='word',font=('Consolas',9),padx=12,pady=12); self.detail.pack(fill='both',expand=True,padx=10,pady=(0,10)); self.detail.insert('1.0','Select a protected file to inspect its cryptographic evidence.'); self.detail.configure(state='disabled')
        self.tree.bind('<<TreeviewSelect>>',lambda e:self.show_detail())
        self.status=tk.StringVar(value='Monitoring active • scan interval: 3 seconds'); tk.Label(self,textvariable=self.status,anchor='w',bg='#07101d',fg='#64748b',font=('Segoe UI',9),padx=22,pady=7).pack(fill='x')
    def selected_id(self):
        s=self.tree.selection(); return int(s[0]) if s else None
    def add_file(self):
        p=filedialog.askopenfilename(title='Select a file to protect');
        if not p:return
        try:
            if register(p): messagebox.showinfo('Protection Enabled','Trusted SHA-256 and HMAC-SHA-256 baseline created.\n\nThe original file is now being monitored.')
            else: messagebox.showwarning('Already Protected','This exact file is already registered.')
            self.refresh()
        except Exception as e: messagebox.showerror('Registration Failed',str(e))
    def update_baseline(self):
        fid=self.selected_id()
        if not fid:return messagebox.showinfo('Select File','Select a protected file first.')
        with dbconn() as c:r=c.execute('SELECT * FROM files WHERE id=?',(fid,)).fetchone()
        if not r or not Path(r['path']).exists():return messagebox.showerror('Unavailable','The selected file does not currently exist.')
        if messagebox.askyesno('Authorize New Baseline','Only do this if the file change is legitimate.\n\nAccept the current file as the new trusted version?'):
            register(r['path'],True); self.refresh()
    def remove_selected(self):
        fid=self.selected_id()
        if not fid:return
        if messagebox.askyesno('Stop Monitoring','Remove this file from monitoring? The original file will NOT be deleted.'):
            remove_file(fid); self.refresh()
    def manual_scan(self):
        scan(); self.status.set('Manual integrity scan completed at '+datetime.now().strftime('%H:%M:%S')); self.refresh()
    def refresh(self):
        with dbconn() as c:
            files=c.execute('SELECT * FROM files ORDER BY id DESC').fetchall(); events=c.execute('SELECT * FROM events ORDER BY id DESC LIMIT 40').fetchall()
        counts={'Protected':len(files),'Secure':sum(r['status']=='SECURE' for r in files),'Tampered':sum(r['status']=='TAMPERED' for r in files),'Missing':sum(r['status']=='DELETED' for r in files)}
        for k,v in counts.items():self.cardvars[k].set(str(v))
        selected=self.tree.selection(); self.tree.delete(*self.tree.get_children())
        icons={'SECURE':'✓ SECURE','TAMPERED':'⚠ TAMPERED','DELETED':'✕ MISSING','ERROR':'! ERROR'}
        for r in files:self.tree.insert('', 'end', iid=str(r['id']), values=(icons.get(r['status'],r['status']),r['name'],r['path'],short_hash(r['sha256']),r['last_checked']),tags=(r['status'],))
        if selected and self.tree.exists(selected[0]):self.tree.selection_set(selected[0])
        self.events.delete(*self.events.get_children())
        for e in events:self.events.insert('','end',values=(e['created_at'],e['severity'],e['event_type'],e['file_name']))
        if files:self.show_detail()
    def show_detail(self):
        fid=self.selected_id();
        if not fid:return
        with dbconn() as c:r=c.execute('SELECT * FROM files WHERE id=?',(fid,)).fetchone(); ev=c.execute('SELECT * FROM events WHERE file_name=? ORDER BY id DESC LIMIT 1',(r['name'],)).fetchone() if r else None
        if not r:return
        current='Unavailable'
        if Path(r['path']).exists():
            try:current=digest(r['path'])[0]
            except:current='Read error'
        text=f"STATUS: {r['status']}\n\nFile: {r['name']}\nPath: {r['path']}\nSize: {r['size']} bytes\n\nTRUSTED SHA-256\n{r['sha256']}\n\nCURRENT SHA-256\n{current}\n\nHMAC-SHA-256\nStored securely for keyed verification.\n\nRegistered: {r['registered_at']}\nLast checked: {r['last_checked']}"
        if ev:text+=f"\n\nLATEST EVENT\n{ev['event_type']} [{ev['severity']}]\n{ev['details']}"
        self.detail.configure(state='normal');self.detail.delete('1.0','end');self.detail.insert('1.0',text);self.detail.configure(state='disabled')
    def monitor(self):
        while self.running:
            try:
                scan()
                with dbconn() as c:e=c.execute("SELECT * FROM events WHERE severity='CRITICAL' ORDER BY id DESC LIMIT 1").fetchone()
                self.after(0,self.refresh)
                if e and e['id']>self.last_critical:
                    self.last_critical=e['id']; self.after(0,lambda ev=dict(e):messagebox.showwarning('Security Alert',f"{ev['event_type']}\n\nFile: {ev['file_name']}\n{ev['details']}"))
            except Exception as e:self.after(0,lambda:self.status.set('Monitoring error — use Scan Now'))
            time.sleep(SCAN_SECONDS)
    def close(self): self.running=False; self.destroy()

if __name__=='__main__':
    init_db(); App().mainloop()
