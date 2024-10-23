import yara
import pefile
import argparse
import struct
import idc
import string
import idaapi

RULE_SOURCE = """rule StealC
{
	meta:
		author = "Yung Binary"
		hash = "619751f5ed0a9716318092998f2e4561f27f7f429fe6103406ecf16e33837470"
	strings:
		$decode_1 = {
			6A ??
			68 ?? ?? ?? ??
			68 ?? ?? ?? ??
			E8 ?? ?? ?? ??
			83 C4 0C
			A3 ?? ?? ?? ??
		}
	
	condition:
		$decode_1
}"""

def yara_scan(raw_data):
    yara_rules = yara.compile(source=RULE_SOURCE)
    matches = yara_rules.match(data=raw_data)

    for match in matches:
        for block in match.strings:
            for instance in block.instances:
                yield instance.offset

def xor_data(data, key):
    decoded = bytearray()
    for i in range(len(data)):
        decoded.append(data[i] ^ key[i])
    return decoded

MAX_STRING_SIZE = 100

def string_from_offset(data, offset):
    return data[offset : offset + MAX_STRING_SIZE].split(b"\0", 1)[0]

loaded_bin_path = idc.get_input_file_path()

with open(loaded_bin_path, "rb") as f:
    filebuf = f.read()

pe = pefile.PE(data=filebuf, fast_load=False)
image_base = idaapi.get_imagebase()

for str_decode_offset in yara_scan(filebuf):
    str_size = int(filebuf[str_decode_offset + 1])
    # Ensure it's not a dummy string
    if not str_size:
        continue

    key_rva = filebuf[str_decode_offset + 3 : str_decode_offset + 7]
    encoded_str_rva = filebuf[str_decode_offset + 8 : str_decode_offset + 12]
    dword_rva = filebuf[str_decode_offset + 21 : str_decode_offset + 25]

    key_offset = pe.get_offset_from_rva(struct.unpack("i", key_rva)[0] - image_base)
    encoded_str_offset = pe.get_offset_from_rva(struct.unpack("i", encoded_str_rva)[0] - image_base)
    dword_offset = struct.unpack("i", dword_rva)[0]
    dword_name = f"dword_{hex(dword_offset)[2:]}"

    key = string_from_offset(filebuf, key_offset)
    encoded_str = string_from_offset(filebuf, encoded_str_offset)

    decoded_str = xor_data(encoded_str, key).decode()

    print(f'Decoding string at {hex(key_offset + image_base)}, result: {dword_name} = {decoded_str}')
    idc.set_cmt(dword_offset, decoded_str, 0)
    ea = idaapi.get_fileregion_ea(str_decode_offset)
    idc.set_cmt(ea, decoded_str, 0)
