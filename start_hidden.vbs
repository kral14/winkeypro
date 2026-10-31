Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
currentDir = fso.GetParentFolderName(WScript.ScriptFullName)
cmd = "python """ & currentDir & "\pc_agent\server.py"""
WshShell.Run cmd, 0, False
