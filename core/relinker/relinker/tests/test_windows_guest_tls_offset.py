import ctypes
import os
from pathlib import Path
import platform
import struct
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

from test_guest_intel_trampolines import PLAIN_SITE, guest_fixture, main_fixture
from test_tls_function_coverage import pe_bytes_at

RUNNER = Path(__file__).with_name("windows_image_runner.py")
RUNS_ON_HOST = sys.platform == "linux" and platform.machine() == "x86_64"
MEMORY_SIZE = 0x21
TLS_LOAD = bytes.fromhex("66 66 66 64 48 8b 04 25 00 00 00 00")


def module_fixture(alignment, value, addend):
    image = guest_fixture(PLAIN_SITE)
    struct.pack_into("<H", image, 56, 4)
    struct.pack_into("<IIQQQQQQ", image, 232, 7, 4, 0x980, 0x2380, 0x2380,
                     0x10, MEMORY_SIZE, alignment)
    struct.pack_into("<IxxxxQ", image, 0x980, 42, 99)
    names = b"\0value\0read_tls\0"
    image[0x800:0x800 + len(names)] = names
    struct.pack_into("<Q", image, 0x618, len(names))
    image[0x820:0x868] = bytes(72)
    struct.pack_into("<IBBHQQ", image, 0x838, 1, 6, 0, 1, value, 4)
    struct.pack_into("<Q", image, 0x648, 0x2280)
    struct.pack_into("<IIIIII", image, 0x880, 1, 3, 1, 0, 2, 0)
    struct.pack_into("<Q", image, 0x668, 24)
    struct.pack_into("<QQq", image, 0x900, 0x2370, (1 << 32) | 18, addend)
    code = TLS_LOAD + bytes.fromhex("48 8b 0d") + struct.pack("<i", 0x2370 - 0x1013)
    code += bytes.fromhex("8b 04 08 c3")
    image[0x400:0x500] = b"\xcc" * 0x100
    image[0x400:0x400 + len(code)] = code
    struct.pack_into("<IBBHQQ", image, 0x850, 7, 0x12, 0, 1, 0x1000, len(code))
    return image


def execute(module, expected):
    if os.name == "nt":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.LoadLibraryW.argtypes = [ctypes.c_wchar_p]
        kernel32.LoadLibraryW.restype = ctypes.c_void_p
        kernel32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        kernel32.GetProcAddress.restype = ctypes.c_void_p
        kernel32.FreeLibrary.argtypes = [ctypes.c_void_p]
        base = kernel32.LoadLibraryW(str(module))
        assert base, (module, ctypes.get_last_error())
        try:
            address = kernel32.GetProcAddress(base, b"read_tls")
            assert address, (module, ctypes.get_last_error())
            read_tls = ctypes.CFUNCTYPE(ctypes.c_int)(address)
            assert read_tls() == expected, module
            with ThreadPoolExecutor(max_workers=1) as executor:
                assert executor.submit(read_tls).result(timeout=5) == expected, module
        finally:
            kernel32.FreeLibrary(base)
    elif RUNS_ON_HOST:
        result = subprocess.run([sys.executable, str(RUNNER), str(module), "0x10000"],
                                capture_output=True, timeout=10)
        assert result.returncode == expected, (module, result.returncode, result.stderr)


def main():
    relinker = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="anyps5-guest-tls-offset-") as directory:
        work = Path(directory)
        source = work / "input.elf"
        source.write_bytes(main_fixture())
        module_dir = work / "sce_module"
        module_dir.mkdir()
        cases = []
        for alignment in (0, 1, 2, 4, 8, 16, 32, 64):
            for value, addend, expected in ((0, 0, 42), (0, 8, 99), (8, -8, 42)):
                name = f"tls-{alignment}-{value}-{addend}.prx"
                (module_dir / name).write_bytes(module_fixture(alignment, value, addend))
                cases.append((name, alignment, value, addend, expected))
        result = subprocess.run([str(relinker), "--windows", str(source), str(work / "output.exe")],
                                capture_output=True, text=True, timeout=15)
        assert result.returncode == 0, (result.stdout, result.stderr)
        for name, alignment, value, addend, expected in cases:
            module = work / "app0" / "sce_module" / (name + ".guest.prx")
            actual, = struct.unpack("<q", pe_bytes_at(module.read_bytes(), 0x11370, 8))
            size = (MEMORY_SIZE + max(alignment, 1) - 1) // max(alignment, 1) * max(alignment, 1)
            assert actual == value + addend - size, (name, actual, value + addend - size)
            execute(module, expected)
    print("Windows guest TLS offset tests passed")


if __name__ == "__main__":
    main()
