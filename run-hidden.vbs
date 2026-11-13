Set sh = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
dir = fso.GetParentFolderName(WScript.ScriptFullName)
sh.CurrentDirectory = dir
exe = dir & "\backend\target\release\jobpilot.exe"
If fso.FileExists(exe) Then sh.Run """" & exe & """", 0, False
