import subprocess
import os
from elftools.elf.elffile import ELFFile
from elftools.elf import segments

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")


def check_elf_by_segment(file_name):
    def _get_section_header_stringtable(ELFFile_Obj):
        return None

    try:
        file_obj = open(file_name, "rb")
    except Exception as e:
        return True

    file_size = os.path.getsize(file_name)
    if file_size <= 0:
        return True

    orgi_get_section_header_stringtable = getattr(ELFFile, "_get_section_header_stringtable", None)
    setattr(ELFFile, "_get_section_header_stringtable", _get_section_header_stringtable)

    try:
        elf_file = ELFFile(file_obj)
    except Exception as e:
        file_obj.close()
        return True

    ph_offset_in_file = elf_file.header["e_phoff"]
    if ph_offset_in_file > file_size:
        return True
    is_broken = False
    for n in range(0, ELFFile.num_segments(elf_file)):
        segment_header = ELFFile._get_segment_header(elf_file, n)
        if segment_header['p_type'] == "PT_LOAD":
            loadable_segment = segments.Segment(segment_header, elf_file.stream)
            segment_start = loadable_segment['p_offset']
            segment_size = loadable_segment['p_filesz']
            if segment_start + segment_size > file_size:
                is_broken = True
                break

    file_obj.close()
    setattr(ELFFile, "_get_section_header_stringtable", orgi_get_section_header_stringtable)
    return is_broken


def check_elf_by_ida_script(file):
    def run_ida_script(ida_exe, ida_script, file):
        cmd = f"\"{ida_exe}\" -c -A \"-S{ida_script}\" \"{file}\""
        proc = subprocess.Popen(cmd, shell=True)
        try:
            proc.wait(timeout=60)
        except Exception as e:
            proc.kill()

    IDA_EXE_INSTALLED_PATH = "/Applications/IDAPro7.0/ida.app/Contents/MacOS/ida"
    IDA_PYTHON_SCRIPT = os.path.join(os.path.dirname(__file__), "ida_python_script.py")
    run_ida_script(IDA_EXE_INSTALLED_PATH, IDA_PYTHON_SCRIPT, file)
    
    
def check_elf_by_capstone(file_name):
    def _get_section_header_stringtable(ELFFile_Obj):
        return None
    try:
        file_obj = open(file_name, "rb")
    except Exception as e:
        print(f"open file error {file_name}")
        return False
    orgi_get_section_header_stringtable = getattr(ELFFile, "_get_section_header_stringtable", None)
    setattr(ELFFile, "_get_section_header_stringtable", _get_section_header_stringtable)
    try:
        elf_file = ELFFile(file_obj)
    except Exception as e:
        print(f"create ELFFile object error. {file_name} {e}")
        file_obj.close()
        return False
    arch = elf_file.get_machine_arch().lower()
    if arch == "mips" and elf_file.elfclass == 64:
        arch = "mips64"
    cs_arch_mode_sm_dict = {
        "x86": (CS_ARCH_X86, CS_MODE_32),
        "x64": (CS_ARCH_X86, CS_MODE_64),
        "mips": (CS_ARCH_MIPS, CS_MODE_MIPS32),
        "mips64": (CS_ARCH_MIPS, CS_MODE_MIPS64),
        "arm": (CS_ARCH_ARM, CS_MODE_ARM),
        "aarch64": (CS_ARCH_ARM64, CS_MODE_ARM),
    }
    
    segment, data = None, None
    for idx in range(0, ELFFile.num_segments(elf_file)):
        segment = elf_file.get_segment(idx)
        if segment.header.p_type != "PT_LOAD":
            continue
        if segment.header.p_vaddr < elf_file.header.e_entry < (segment.header.p_vaddr + segment.header.p_memsz):
            data = segment.data()
            break
    if data is None:
        file_obj.close()
        return False
    offset = elf_file.header.e_entry - segment.header.p_vaddr
    if offset <= 0:
        file_obj.close()
        return False
    # TODO Ugly Magic number.
    MAGNUM = 10
    length = MAGNUM * 4
    item = cs_arch_mode_sm_dict.get(arch, None)
    if item is None:
        file_obj.close()
        return False
    cs_arch, cs_mode = item
    cs_mode_endian = CS_MODE_LITTLE_ENDIAN if elf_file.little_endian is True else CS_MODE_BIG_ENDIAN
    md = Cs(cs_arch, cs_mode + cs_mode_endian)
    lst = [_ for _ in md.disasm(data[offset:offset + length], elf_file.header.e_entry)]
    setattr(ELFFile, "_get_section_header_stringtable", orgi_get_section_header_stringtable)
    file_obj.close()
    # TODO Ugly code.
    if arch == "mips":
        if len(lst) < MAGNUM:
            return True
    return False


# Test
for file in os.listdir(DATA_DIR):
    file_abs_path = os.path.join(DATA_DIR, file)
    is_broken = check_elf_by_segment(file_abs_path)
    print(f"{file_abs_path} is broken {is_broken}")

# Test
for file in os.listdir(DATA_DIR):
    file_abs_path = os.path.join(DATA_DIR, file)
    check_elf_by_ida_script(file_abs_path)
    
# Test
for file in os.listdir(DATA_DIR):
    file_abs_path = os.path.join(DATA_DIR, file)
    check_elf_by_capstone(file_abs_path)
