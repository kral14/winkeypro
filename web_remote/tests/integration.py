import requests, secrets, hashlib
BASE='http://127.0.0.1:5173'
secret=secrets.token_hex(32)
code=''.join(secrets.choice('ABCDEFGHJKLMNPQRSTUVWXYZ23456789') for _ in range(12))
hash=lambda x:hashlib.sha256(x.encode()).hexdigest()
agent=requests.Session()
browser=requests.Session()
browser.get(BASE+'/signin-with-chatgpt?return_to=/',timeout=20)
browser.headers.update({'Origin':BASE})
def post(session,path,data,status=200):
 response=session.post(BASE+'/api/'+path,json=data,timeout=20)
 assert response.status_code==status,(path,response.status_code,response.text[:200])
 return response.json()
device=post(agent,'agent/register',{'name':'QA Windows PC','secret_hash':hash(secret),'pair_hash':hash(code)})['device_id']
agent.headers['Authorization']='Bearer '+secret
post(browser,'pair',{'code':code})
status={'device_id':device,'locked':True,'pin_ready':True}
assert post(agent,'agent/poll',status)['paired']
command=post(browser,'commands',{'device_id':device,'action':'unlock'})['command_id']
claimed=post(agent,'agent/poll',status)['command']
assert claimed['id']==command and claimed['action']=='unlock'
assert post(agent,'agent/poll',status)['command'] is None
post(agent,'agent/result',{'device_id':device,'command_id':command,'success':True,'status':'SIMULATED_SUCCESS'})
assert browser.get(BASE+'/api/commands/'+command,timeout=20).json()['state']=='success'
post(requests.Session(),'agent/poll',status,403)
other=requests.Session();other.headers.update({'oai-authenticated-user-id':'other-owner','oai-authenticated-user-email':'other@example.test','Origin':BASE})
assert other.get(BASE+'/api/commands/'+command,timeout=20).status_code==401
post(other,'commands',{'device_id':device,'action':'unlock'},401)
post(browser,'commands',{'device_id':device,'action':'shell'},400)
print('PASS: pairing, command delivery, one-time claim, acknowledgement, bad-token rejection, anonymous command rejection, action allowlist')
