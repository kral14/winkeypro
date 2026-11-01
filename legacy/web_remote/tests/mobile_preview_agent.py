"""Local-only fake PC: never imports Windows engine or sends keyboard input."""
import requests, secrets, hashlib, time
base='http://127.0.0.1:5173'
secret=secrets.token_hex(32);code='ABCDWXYZ2345'
client=requests.Session()
def post(route,body):
 r=client.post(base+'/api/agent/'+route,json=body,timeout=20);r.raise_for_status();return r.json()
hash=lambda s:hashlib.sha256(s.encode()).hexdigest()
device=post('register',{'name':'Mobil sınaq kompüteri','secret_hash':hash(secret),'pair_hash':hash(code)})['device_id']
client.headers['Authorization']='Bearer '+secret
print('QA_URL='+base+'/mobile?device='+device+'&code='+code,flush=True)
locked=True
for _ in range(180):
 response=post('poll',{'device_id':device,'locked':locked,'pin_ready':True})
 command=response.get('command')
 if command:
  locked=command['action']=='lock'
  post('result',{'device_id':device,'command_id':command['id'],'success':True,'status':'SIMULATED_ONLY'})
  print('SIMULATED',command['action'],flush=True)
 time.sleep(1)
