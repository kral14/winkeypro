"""Read service access from stdin; never pass it in arguments or print it."""
import sys, json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from remote_agent.app import load_config, save_config, DEFAULT_URL
if sys.stdin.isatty():
    import msvcrt
    print('Ready for encrypted configuration (input hidden).', flush=True)
    characters=[]
    while True:
        char=msvcrt.getwch()
        if char in ('\r','\n'):break
        if char=='\x03':raise KeyboardInterrupt
        characters.append(char)
    payload=json.loads(''.join(characters))
else:
    payload=json.loads(sys.stdin.readline())
config=load_config()
config.update(url=DEFAULT_URL, service_key=payload['service_key'])
# Migrate the user's existing local PIN directly into Windows DPAPI storage.
legacy=Path(__file__).resolve().parent.parent/'pc_agent'/'config.json'
if not config.get('pin') and legacy.exists():
    config['pin']=json.loads(legacy.read_text(encoding='utf-8')).get('pin','')
save_config(config)
print('Encrypted configuration saved; PIN configured:', bool(config.get('pin')))
