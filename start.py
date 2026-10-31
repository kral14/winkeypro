"""
WinKey // Mobil Kilid Açma Sistemi
Tək Python Skripti: Avtomatik Admin Hüququ, Firewall İcazəsi və Server Başlatma
"""
import os
import sys
import time
import socket
import ctypes
import subprocess
from pathlib import Path

# Fix Windows console encoding
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def elevate_if_needed():
    """Əgər skript admin hüququ ilə işləmirsə, UAC ilə avtomatik admin kimi başladır."""
    if not is_admin():
        print("[*] Administrator hüquqları tələb olunur, UAC pəncərəsi açılır...")
        script = os.path.abspath(sys.argv[0])
        params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}" {params}', None, 1)
        if int(ret) > 32:
            # Uğurla admin kimi başladıldı, cari pəncərəni bağlayırıq
            sys.exit(0)
        else:
            print("[!] Administrator icazəsi verilmədi.")
            input("Davam etmək üçün Enter basın...")
            sys.exit(1)

def kill_port_occupants(port=8888):
    """Port 8888-də ilişib qalmış köhnə prosesləri təmizləyir."""
    try:
        import psutil
        my_pid = os.getpid()
        killed = 0
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr and conn.laddr.port == port and conn.pid:
                if conn.pid != my_pid:
                    try:
                        p = psutil.Process(conn.pid)
                        p.kill()
                        killed += 1
                    except Exception:
                        pass
        if killed > 0:
            print(f"[*] Port {port}-dəki {killed} ədəd köhnə proses dayandırıldı.")
            time.sleep(0.5)
    except Exception:
        pass

def ensure_firewall(port=8888):
    """Windows Firewall-da port 8888-i yerli Wi-Fi üçün açır."""
    try:
        cmd = f'netsh advfirewall firewall add rule name="WinKey Port {port}" dir=in action=allow protocol=TCP localport={port}'
        subprocess.run(cmd, shell=True, capture_output=True)
    except Exception:
        pass

def cleanup_old_scheduled_tasks():
    """Köhnə xidməti tapşırıqlardan təmizləyir."""
    try:
        subprocess.run('schtasks /delete /tn "WinKeyService" /f', shell=True, capture_output=True)
    except Exception:
        pass

if __name__ == "__main__":
    # 1. Admin hüququnu yoxla və təmin et
    elevate_if_needed()

    # 2. Köhnə servisləri və portu təmizlə
    cleanup_old_scheduled_tasks()
    kill_port_occupants(8888)

    # 3. Firewall icazəsini aç
    ensure_firewall(8888)

    # 4. pc_agent qovluğunu aktiv işçi qovluq təyin et
    base_dir = Path(__file__).resolve().parent
    agent_dir = base_dir / "pc_agent"
    sys.path.insert(0, str(base_dir))
    sys.path.insert(0, str(agent_dir))
    os.chdir(str(agent_dir))

    # 5. Serveri başlat
    from pc_agent import server
    import uvicorn

    ips = server.get_ip_addresses()
    primary_ip = ips[0]
    port = server.config.get("port", 8888)
    primary_url = f"http://{primary_ip}:{port}"

    server.generate_qr_assets(primary_url)
    server.print_banner(primary_url, ips, port)

    print(f"[*] Server Uvicorn mühərriki ilə 0.0.0.0:{port} üzərində işə salınır...")
    uvicorn.run(server.app, host="0.0.0.0", port=port, log_level="info")
