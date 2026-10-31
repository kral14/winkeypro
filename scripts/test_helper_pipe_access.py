"""Real Windows pipe access regression; never calls lock or input APIs."""
import ctypes,sys,os,threading,uuid
from ctypes import wintypes
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'pc_agent'))
import helper_main as helper
k=ctypes.WinDLL('kernel32',use_last_error=True)
a=ctypes.WinDLL('advapi32',use_last_error=True)
H=ctypes.c_void_p
class SA(ctypes.Structure):
    _fields_=[('length',wintypes.DWORD),('descriptor',H),('inherit',wintypes.BOOL)]
k.GetCurrentProcess.restype=H
sid=helper.get_token_user_sid(k.GetCurrentProcess())
assert sid
sd=H()
a.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,ctypes.POINTER(H),H]
a.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype=wintypes.BOOL
assert a.ConvertStringSecurityDescriptorToSecurityDescriptorW(f'D:P(A;;0x0012008b;;;SY)(A;;0x0012008b;;;{sid})',1,ctypes.byref(sd),None)
sa=SA(ctypes.sizeof(SA),sd,False)
k.CreateNamedPipeW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,wintypes.DWORD,wintypes.DWORD,wintypes.DWORD,wintypes.DWORD,ctypes.POINTER(SA)]
k.CreateNamedPipeW.restype=H
k.ConnectNamedPipe.argtypes=[H,H];k.ConnectNamedPipe.restype=wintypes.BOOL
k.CloseHandle.argtypes=[H]
k.WriteFile.argtypes=[H,H,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD),H]
k.ReadFile.argtypes=[H,H,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD),H]
k.LocalFree.argtypes=[H]
name='WinKey_Codex_Access_'+uuid.uuid4().hex
pipe=k.CreateNamedPipeW('\\\\.\\pipe\\'+name,3|0x80000,8,1,512,512,3000,ctypes.byref(sa))
k.LocalFree(sd)
assert pipe and pipe!=H(-1).value
# Reproduce original client's denied broad mask.
bad=helper.kernel32.CreateFileW('\\\\.\\pipe\\'+name,0xC0000000,0,None,3,0x40000000,None)
assert bad in (None,H(-1).value), 'Broad access unexpectedly allowed'
print('PASS: old GENERIC_READ|GENERIC_WRITE request rejected')
errors=[]
def server():
    try:
        ok=k.ConnectNamedPipe(pipe,None)
        assert ok or ctypes.get_last_error()==535
        data=b'DUMMY_TEST_ONLY\n';n=wintypes.DWORD()
        assert k.WriteFile(pipe,data,len(data),ctypes.byref(n),None)
        buf=ctypes.create_string_buffer(128)
        assert k.ReadFile(pipe,buf,len(buf),ctypes.byref(n),None)
        assert b'ACK_CREDENTIAL_RECEIVED' in buf.raw[:n.value]
    except BaseException as e:errors.append(e)
t=threading.Thread(target=server,daemon=True);t.start()
try:
    received=helper.read_ephemeral_credential_from_pipe(name,os.getpid())
    assert received=='DUMMY_TEST_ONLY'
    t.join(5);assert not t.is_alive(), 'Server did not finish'
    assert not errors,repr(errors)
    print('PASS: production helper minimum-mask read and ACK completed; no input invoked')
finally:k.CloseHandle(pipe)
