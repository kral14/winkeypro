"""WinKey internet companion. Only three bounded actions; no remote shell."""
import os
import sys
from pathlib import Path
import json
import time
import secrets
import hashlib
import threading
import sqlite3
from contextlib import closing
import queue
import socket
import urllib.parse
import ctypes
import subprocess
import requests
import win32crypt
import qrcode
from PIL import ImageTk

DEFAULT_URL = "https://winkey-remote-nesib.beigesong32770.chatgpt.site"
APP_VERSION = "remote-20261028-3"

def user_data_directory():
    if os.environ.get("WINKEY_REMOTE_DATA"):
        return Path(os.environ["WINKEY_REMOTE_DATA"])
    # Resolve the Windows user's real folder; do not inherit a launcher's redirected LOCALAPPDATA.
    folder = ctypes.create_unicode_buffer(32768)
    shell = ctypes.windll.shell32
    shell.SHGetFolderPathW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint, ctypes.c_wchar_p]
    if shell.SHGetFolderPathW(None, 0x001C, None, 0, folder) == 0 and folder.value:
        return Path(folder.value) / "WinKeyRemote"
    return Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "WinKeyRemote"

DATA = user_data_directory()
# Tests/builds can redirect runtime files into their own disposable directory.
DATA = Path(os.environ.get("WINKEY_REMOTE_DATA", DATA))
CONFIG = DATA / "agent.dpapi"


def configure_runtime():
    DATA.mkdir(parents=True, exist_ok=True)
    os.environ['WINKEY_DATA_DIR'] = str(DATA)


def config_path():
    if getattr(sys, 'frozen', False):
        portable = Path(sys.executable).resolve().parent / 'connection.dpapi'
        if portable.is_file():
            return portable
    return CONFIG


def load_config():
    source = config_path()
    if not source.exists(): return {}
    return json.loads(win32crypt.CryptUnprotectData(source.read_bytes(), None, None, None, 0)[1].decode('utf-8'))


def save_config(config):
    configure_runtime()
    encrypted = win32crypt.CryptProtectData(json.dumps(config).encode('utf-8'), 'WinKey Remote', None, None, None, 0)
    target = config_path()
    temporary = target.with_suffix('.tmp')
    temporary.write_bytes(encrypted)
    os.replace(temporary, target)


def valid_url(value):
    url = urllib.parse.urlparse(value)
    if url.scheme != 'https' or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise ValueError('HTTPS sayt ünvanı tələb olunur')
    return value.rstrip('/')


def mobile_link(config):
    if not config.get('device_id'):
        return ''
    query = {'device': config['device_id']}
    if not config.get('paired') and config.get('pair_code') and time.time()-config.get('pair_created',0)<600:
        query['code'] = config['pair_code']
    return valid_url(config.get('url', DEFAULT_URL)) + '/mobile?' + urllib.parse.urlencode(query)


class Client:
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.url = valid_url(config.get('url', DEFAULT_URL))
        self.session.headers.update({'OAI-Sites-Authorization': 'Bearer ' + config['service_key']})
        if config.get('secret'): self.session.headers['Authorization'] = 'Bearer ' + config['secret']

    def post(self, endpoint, payload):
        response = self.session.post(self.url + '/api/agent/' + endpoint, json=payload, timeout=(6, 12), allow_redirects=False)
        if 300 <= response.status_code < 400:
            raise RuntimeError('Sayt xidmət açarını qəbul etmədi; bağlantı giriş səhifəsinə yönləndirildi')
        if response.status_code >= 400:
            raise RuntimeError(f'Server cavabı: HTTP {response.status_code}')
        return response.json()

    def register(self):
        secret = secrets.token_hex(32)
        code = ''.join(secrets.choice('ABCDEFGHJKLMNPQRSTUVWXYZ23456789') for _ in range(12))
        digest = lambda text: hashlib.sha256(text.encode()).hexdigest()
        result = self.post('register', {'name':socket.gethostname(), 'secret_hash':digest(secret), 'pair_hash':digest(code)})
        self.config.update(secret=secret, device_id=result['device_id'], pair_code=code, pair_created=time.time())
        self.session.headers['Authorization'] = 'Bearer ' + secret
        save_config(self.config)
        return code


def consume_command(command):
    # Persist before executing. If the agent dies or HTTP is retried, never type twice.
    with closing(sqlite3.connect(DATA / 'consumed.sqlite')) as db, db:
        db.execute('CREATE TABLE IF NOT EXISTS consumed (id TEXT PRIMARY KEY, created REAL NOT NULL)')
        try:
            db.execute('INSERT INTO consumed VALUES (?, ?)', (command['id'], time.time()))
        except sqlite3.IntegrityError:
            return False
    return True


def execute(command, pin):
    from pc_agent import unlock_engine as engine
    if command.get('action') not in ('unlock','lock','wake'):
        return {'success':False,'status':'INVALID_ACTION'}
    if command.get('expires',0) < time.time()*1000:
        return {'success':False,'status':'EXPIRED'}
    if not consume_command(command): return {'success':False,'status':'DUPLICATE_REJECTED'}
    if command['action']=='unlock':
        if not pin: return {'success':False,'status':'PIN_NOT_CONFIGURED'}
        return engine.unlock_workstation(pin)
    if command['action']=='lock':
        ok = engine.lock_workstation()
        if ok:
            for _ in range(15):
                time.sleep(.1)
                if engine.is_workstation_locked(): return {'success':True,'status':'LOCKED'}
        return {'success':False,'status':'LOCK_NOT_CONFIRMED'}
    ok = engine.wake_screen()
    return {'success':ok,'status':'WAKE_REQUESTED' if ok else 'WAKE_FAILED'}


def run_agent(config, messages, stop):
    client = Client(config)
    try:
        if not config.get('device_id'): client.register()
        code = config.get('pair_code','')
        messages.put(('code', '-'.join(code[i:i+4] for i in range(0,len(code),4))))
        messages.put(('mobile_url',mobile_link(config)))
    except Exception as exc:
        messages.put(('status', str(exc))); return
    from pc_agent import unlock_engine as engine
    pending_result = None
    failures = 0
    while not stop.is_set():
        try:
            if pending_result:
                client.post('result', pending_result)
                pending_result = None
            evidence = engine.get_lock_state()
            data = client.post('poll', {'device_id':config['device_id'], 'locked':evidence['locked'] if evidence['wts'].get('confirmed') else None, 'pin_ready':bool(config.get('pin'))})
            messages.put(('status', 'Onlayn — əmrlər gözlənilir' if data.get('paired') else 'Saytda qoşulma kodunu daxil edin'))
            if data.get('paired'): messages.put(('paired', True))
            elif time.time()-config.get('pair_created',0)>600:
                fresh=client.register()
                messages.put(('code','-'.join(fresh[i:i+4] for i in range(0,len(fresh),4))))
                messages.put(('mobile_url',mobile_link(config)))
            command = data.get('command')
            if command:
                messages.put(('status','Əməliyyat: '+command['action']))
                try: result = execute(command, config.get('pin',''))
                except Exception as exc: result={'success':False,'status':type(exc).__name__}
                pending_result = {'device_id':config['device_id'],'command_id':command['id'],'success':bool(result.get('success')),'status':result.get('status'),'attempt_id':result.get('attempt_id','')}
                client.post('result', pending_result)
                pending_result = None
                messages.put(('status', 'Tamamlandı' if result.get('success') else 'Əməliyyat alınmadı; loqu yoxlayın'))
            failures=0
            stop.wait(1.2)
        except Exception as exc:
            failures += 1
            messages.put(('status', str(exc)))
            stop.wait(min(20, 2 ** min(failures,4)))


def gui():
    import tkinter as tk
    from tkinter import ttk, messagebox
    configure_runtime()
    startup_error = ''
    try: config=load_config()
    except Exception as exc:
        config={}
        startup_error=f'Ayarlar oxunmadı ({type(exc).__name__}). Eyni Windows hesabından başladın.'
    def config_log(message):
        with (DATA / 'connection.log').open('a', encoding='utf-8') as stream:
            stream.write(time.strftime('%Y-%m-%d %H:%M:%S') + ' ' + message + '\n')
    config_log(f'APP_START version={APP_VERSION}; config_path={config_path()}; config_exists={config_path().exists()}; service_present={bool(config.get("service_key"))}; pin_present={bool(config.get("pin"))}; load_error={bool(startup_error)}')
    root=tk.Tk();root.title('WinKey — '+APP_VERSION);root.geometry('570x610');root.configure(bg='#141a15')
    root.option_add('*Font', 'Segoe 10')
    def label(text, size=11, color='#c4d0bd'):
        tk.Label(root,text=text,font=('Segoe UI',size),bg='#141a15',fg=color,wraplength=480,justify='left').pack(anchor='w',padx=28,pady=(12,4))
    label('WinKey',27,'#c8f279');label('Telefondan bir toxunuşla Windows kilidini aç.',11)
    label('Veb tətbiq ünvanı')
    url=tk.StringVar(value=config.get('url',DEFAULT_URL));ttk.Entry(root,textvariable=url,width=63).pack(padx=28,fill='x')
    label('Windows PIN/parolu — yalnız bu kompüterdə saxlanır')
    pin=tk.StringVar(value=config.get('pin',''));ttk.Entry(root,textvariable=pin,show='•',width=63).pack(padx=28,fill='x')
    label('İnternet bağlantısı')
    service=tk.StringVar(value=config.get('service_key',''))
    service_status=tk.StringVar(value='Xidmət ayarı hazırdır ✓' if service.get() else 'Xidmət ayarı yüklənməyib — Ayarları yenilə basın')
    tk.Label(root,textvariable=service_status,bg='#141a15',fg='#c8f279',wraplength=510).pack(anchor='w',padx=28,pady=4)
    status=tk.StringVar(value=startup_error or 'Hazırdır');code=tk.StringVar(value='—')
    mobile_url=tk.StringVar(value=mobile_link(config))
    qr_window=None
    qr_label=None
    tk.Label(root,textvariable=code,font=('Consolas',24,'bold'),fg='#c8f279',bg='#141a15').pack(pady=(23,3))
    tk.Label(root,textvariable=status,wraplength=480,fg='#a4b39b',bg='#141a15').pack(pady=10)
    messages=queue.Queue();stop=threading.Event();thread=None
    def connect():
        nonlocal config,thread
        if thread and thread.is_alive():
            messagebox.showinfo('WinKey','Ayarları dəyişmək üçün əvvəl köməkçini bağlayıb yenidən açın.');return
        try:
            # Refresh from disk even when this window was opened before provisioning.
            latest=load_config()
            if not service.get() and latest.get('service_key'):
                service.set(latest['service_key'])
            for key in ('device_id','secret','pair_code','pair_created','paired'):
                if key not in config and key in latest: config[key]=latest[key]
            service_status.set('Xidmət ayarı hazırdır ✓' if service.get() else 'Xidmət ayarı tapılmadı')
            config_log(f'CONNECT_REQUEST service_present={bool(service.get())}; pin_present={bool(pin.get())}; config_path={config_path()}')
            valid_url(url.get())
            if not service.get(): raise ValueError('Xidmət giriş açarı konfiqurasiya edilməyib')
            if not pin.get(): raise ValueError('Windows PIN/parolunu yazın')
            config.update(url=url.get().rstrip('/'),pin=pin.get(),service_key=service.get())
            if not config.get('paired') and time.time()-config.get('pair_created',0)>600:
                for key in ('device_id','secret','pair_code'): config.pop(key,None)
            save_config(config)
            status.set('Serverə qoşulur; kod hazırlanır…')
            stop.clear();thread=threading.Thread(target=run_agent,args=(config,messages,stop),daemon=True);thread.start()
        except Exception as exc: messagebox.showerror('WinKey',str(exc))
    def reload_settings():
        nonlocal config
        try:
            latest=load_config()
            if latest.get('service_key'): service.set(latest['service_key'])
            if not pin.get() and latest.get('pin'): pin.set(latest['pin'])
            config.update(latest)
            service_status.set('Xidmət ayarı hazırdır ✓' if service.get() else 'Xidmət ayarı tapılmadı')
            status.set('Ayarlar yeniləndi. Saxla və qoşul basın.')
            config_log(f'CONFIG_REFRESH service_present={bool(service.get())}; pin_present={bool(pin.get())}')
        except Exception as exc:
            status.set(f'Ayarlar oxunmadı: {type(exc).__name__}')
            config_log('CONFIG_REFRESH_FAILED type='+type(exc).__name__)
    def paint_qr():
        if qr_label is not None and qr_label.winfo_exists() and mobile_url.get():
            qr=qrcode.QRCode(box_size=5,border=4,error_correction=qrcode.constants.ERROR_CORRECT_M)
            qr.add_data(mobile_url.get());qr.make(fit=True)
            image=qr.make_image(fill_color='black',back_color='white').convert('RGB')
            photo=ImageTk.PhotoImage(image)
            qr_label.configure(image=photo)
            qr_label.image=photo
    def show_qr():
        nonlocal qr_window,qr_label
        if not mobile_url.get():
            messagebox.showinfo('WinKey','Əvvəl Saxla və qoşul basın. Bağlantı yarandıqda QR hazır olacaq.');return
        if qr_window is not None and qr_window.winfo_exists():qr_window.lift();paint_qr();return
        qr_window=tk.Toplevel(root);qr_window.title('WinKey — Telefon üçün QR');qr_window.configure(bg='#141a15');qr_window.resizable(False,False)
        tk.Label(qr_window,text='Telefonun kamerası ilə oxut',font=('Segoe UI',15),fg='#c8f279',bg='#141a15').pack(padx=24,pady=(22,15))
        qr_label=tk.Label(qr_window,bg='white');qr_label.pack(padx=24,pady=5)
        tk.Label(qr_window,text='Mobil səhifədə yalnız Kilidlə və Kilidi aç var.\nİlk dəfə hesabına giriş istənə bilər.',font=('Segoe UI',10),fg='#acbda1',bg='#141a15').pack(padx=24,pady=(15,22))
        paint_qr()
    buttons=tk.Frame(root,bg='#141a15');buttons.pack(pady=10)
    ttk.Button(buttons,text='Saxla və qoşul',command=connect).pack(side='left',padx=7)
    ttk.Button(buttons,text='Veb paneli aç',command=lambda:os.startfile(valid_url(url.get()))).pack(side='left',padx=7)
    ttk.Button(buttons,text='Loqları aç',command=lambda:os.startfile(str(DATA))).pack(side='left',padx=7)
    extra=tk.Frame(root,bg='#141a15');extra.pack(pady=5)
    ttk.Button(extra,text='Telefon üçün QR',command=show_qr).pack(side='left',padx=7)
    ttk.Button(extra,text='Ayarları yenilə',command=reload_settings).pack(side='left',padx=7)
    label('Kompüter açıq, internetə bağlı və köməkçi işlək olmalıdır. PIN serverə göndərilmir.',9,'#7b8d73')
    def check():
        try:
            while True:
                key,value=messages.get_nowait()
                if key=='code':code.set(value)
                elif key=='status':status.set(value)
                elif key=='mobile_url':mobile_url.set(value);paint_qr()
                elif key=='paired' and not config.get('paired'):
                    config['paired']=True;save_config(config);code.set('QOŞULDU')
                    mobile_url.set(mobile_link(config));paint_qr()
        except queue.Empty:pass
        root.after(200,check)
    def close():stop.set();root.destroy()
    root.protocol('WM_DELETE_WINDOW',close);check()
    if config.get('service_key') and config.get('pin'):root.after(500,connect)
    root.mainloop()


def main():
    configure_runtime()
    if '--self-test' in sys.argv:
        from pc_agent import unlock_engine, secure_input_worker
        try:
            saved=load_config(); config_error=''
        except Exception as exc:
            saved={}; config_error=type(exc).__name__
        status = {'version':APP_VERSION, 'config_path':str(config_path()), 'config_exists':config_path().exists(), 'service_present':bool(saved.get('service_key')), 'config_error':config_error, 'engine':unlock_engine.VERSION, 'focus_script_present':Path(unlock_engine.__file__).with_name('focus_credential.ps1').exists(), 'worker_available':callable(secure_input_worker.run_worker)}
        (DATA / 'self-test.json').write_text(json.dumps(status))
        return
    if '--secure-worker' in sys.argv:
        from pc_agent.secure_input_worker import run_worker
        run_worker();return
    if '--configure-service-stdin' in sys.argv:
        config=load_config();config.update(json.load(sys.stdin));save_config(config);print('Configured encrypted service access');return
    if not ctypes.windll.shell32.IsUserAnAdmin():
        args=sys.argv[1:] if getattr(sys,'frozen',False) else [str(Path(__file__).resolve()),*sys.argv[1:]]
        result=ctypes.windll.shell32.ShellExecuteW(None,'runas',sys.executable,subprocess.list2cmdline(args),None,0)
        if result<=32:raise RuntimeError('Administrator icazəsi verilmədi')
        return
    gui()

if __name__=='__main__':
    # Source launch and PyInstaller both resolve the existing engine package.
    if not getattr(sys,'frozen',False):sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
    main()
