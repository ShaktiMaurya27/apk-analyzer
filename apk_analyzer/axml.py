import struct
import xml.etree.ElementTree as ET
from typing import Optional, List, Tuple

class AXMLParser:
    """
    Pure Python parser for Android Binary XML (AXML) files, commonly found in APK AndroidManifest.xml.
    Decodes strings, elements, and attributes into a standard ElementTree.
    """
    CHUNK_AXML_FILE = 0x00080003
    CHUNK_RESOURCEIDS = 0x00080180
    CHUNK_STRINGPOOL = 0x0001001c
    CHUNK_START_NAMESPACE = 0x00100100
    CHUNK_END_NAMESPACE = 0x00100101
    CHUNK_START_TAG = 0x00100102
    CHUNK_END_TAG = 0x00100103
    CHUNK_TEXT = 0x00100104

    def __init__(self, raw_bytes: bytes):
        self.raw = raw_bytes
        self.string_pool: List[str] = []

    def parse(self) -> Optional[ET.Element]:
        if not self.raw:
            return None
        
        # Check if it's already plain UTF-8 text XML
        if self.raw.strip().startswith(b"<?xml") or self.raw.strip().startswith(b"<manifest"):
            try:
                return ET.fromstring(self.raw.decode("utf-8", errors="ignore"))
            except Exception:
                pass

        if len(self.raw) < 8:
            return None

        header_type, _ = struct.unpack("<HH", self.raw[:4])
        magic = struct.unpack("<I", self.raw[:4])[0]

        if magic != self.CHUNK_AXML_FILE and header_type != 0x0003:
            # Try plain text fallback if magic doesn't match
            try:
                return ET.fromstring(self.raw.decode("utf-8", errors="ignore"))
            except Exception:
                return None

        offset = 8
        element_stack: List[ET.Element] = []
        root_element: Optional[ET.Element] = None

        while offset < len(self.raw):
            if offset + 8 > len(self.raw):
                break
            chunk_type, header_size, chunk_size = struct.unpack("<HH2xI", self.raw[offset:offset+8])
            
            # Combine type and header size for 32-bit chunk type check
            full_type = (header_size << 16) | chunk_type if header_size < 0x0100 else chunk_type

            if chunk_type == 0x0001 or full_type == self.CHUNK_STRINGPOOL:
                self.string_pool = self._parse_string_pool(offset)
            elif chunk_type == 0x0102 or full_type == self.CHUNK_START_TAG:
                elem, consumed = self._parse_start_tag(offset)
                if elem is not None:
                    if element_stack:
                        element_stack[-1].append(elem)
                    else:
                        root_element = elem
                    element_stack.append(elem)
            elif chunk_type == 0x0103 or full_type == self.CHUNK_END_TAG:
                if element_stack:
                    element_stack.pop()
            
            if chunk_size == 0 or chunk_size > len(self.raw) - offset:
                break
            offset += chunk_size

        return root_element

    def _parse_string_pool(self, offset: int) -> List[str]:
        strings = []
        try:
            string_count, style_count, flags, strings_start, styles_start = struct.unpack(
                "<IIIII", self.raw[offset+8:offset+28]
            )
            is_utf8 = bool(flags & (1 << 8))
            offsets_start = offset + 28
            
            string_offsets = []
            for i in range(string_count):
                st_off = struct.unpack("<I", self.raw[offsets_start + i*4 : offsets_start + (i+1)*4])[0]
                string_offsets.append(st_off)

            base_strings = offset + strings_start
            for st_off in string_offsets:
                pos = base_strings + st_off
                if pos >= len(self.raw):
                    strings.append("")
                    continue
                if is_utf8:
                    # UTF-8 format in AXML string pool: length byte(s) then string
                    # Skip 1 or 2 bytes for char length, then 1 or 2 bytes for byte length
                    u16len = self.raw[pos]
                    pos += 1
                    if u16len & 0x80:
                        pos += 1
                    u8len = self.raw[pos]
                    pos += 1
                    if u8len & 0x80:
                        u8len = ((u8len & 0x7F) << 8) | self.raw[pos]
                        pos += 1
                    s_bytes = self.raw[pos:pos+u8len]
                    strings.append(s_bytes.decode("utf-8", errors="ignore"))
                else:
                    # UTF-16 format: 2-byte char count, then UTF-16LE characters
                    u16len = struct.unpack("<H", self.raw[pos:pos+2])[0]
                    pos += 2
                    if u16len & 0x8000:
                        u16len = ((u16len & 0x7FFF) << 16) | struct.unpack("<H", self.raw[pos:pos+2])[0]
                        pos += 2
                    byte_len = u16len * 2
                    s_bytes = self.raw[pos:pos+byte_len]
                    strings.append(s_bytes.decode("utf-16le", errors="ignore"))
        except Exception:
            pass
        return strings

    def _parse_start_tag(self, offset: int) -> Tuple[Optional[ET.Element], int]:
        try:
            # Header size, chunk size, line number, comment, ns, name_idx, attr_start, attr_size, attr_count
            name_idx = struct.unpack("<I", self.raw[offset+20:offset+24])[0]
            tag_name = self.string_pool[name_idx] if name_idx < len(self.string_pool) else "unknown"
            
            # Clean tag name
            if ":" in tag_name:
                tag_name = tag_name.split(":")[-1]

            elem = ET.Element(tag_name)

            attr_start_off, attr_size, attr_count = struct.unpack("<HHH", self.raw[offset+24:offset+30])
            attr_offset = offset + 36

            for _ in range(attr_count):
                if attr_offset + 20 > len(self.raw):
                    break
                ns_idx, name_idx, val_str_idx, type_val, data_val = struct.unpack(
                    "<IIIII", self.raw[attr_offset:attr_offset+20]
                )
                attr_name = self.string_pool[name_idx] if name_idx < len(self.string_pool) else f"attr_{name_idx}"
                
                # Format value based on type or string pool index
                attr_val = ""
                if val_str_idx != 0xFFFFFFFF and val_str_idx < len(self.string_pool):
                    attr_val = self.string_pool[val_str_idx]
                elif type_val == 0x10 or type_val == 0x11:  # TYPE_INT_DEC / TYPE_INT_HEX
                    attr_val = str(data_val)
                elif type_val == 0x12:  # TYPE_INT_BOOLEAN
                    attr_val = "true" if data_val != 0 else "false"
                else:
                    attr_val = str(data_val)

                elem.set(attr_name, attr_val)
                attr_offset += 20

            return elem, 0
        except Exception:
            return None, 0
