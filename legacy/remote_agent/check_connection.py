import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from remote_agent.app import Client,load_config,configure_runtime
configure_runtime()
config=load_config()
client=Client(config)
if not config.get('device_id'):client.register()
reply=client.post('poll',{'device_id':config['device_id'],'locked':None,'pin_ready':bool(config.get('pin'))})
print('Live service connection OK; registration saved; paired:',reply.get('paired'))
