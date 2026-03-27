"""
run_pefile.py
pefile wrapper — parses PE header information for Windows executables.
Gracefully skips non-PE files (ELF, APK, etc.)
"""

import logging
import math
from pathlib import Path

logger = logging.getLogger(__name__)


def calculate_entropy(data: bytes) -> float:
    """Shannon entropy — high entropy sections suggest packing or encryption."""
    if not data:
        return 0.0
    frequency = [0] * 256
    for byte in data:
        frequency[byte] += 1
    entropy = 0.0
    for count in frequency:
        if count:
            p = count / len(data)
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def is_pe(sample_path: Path) -> bool:
    with open(sample_path, "rb") as f:
        magic = f.read(2)
    return magic == b"MZ"


def run_pefile(sample_path: Path) -> dict:
    """
    Parse PE headers and return structured metadata.
    Returns graceful skip result for non-PE files.
    """
    result = {
        "tool": "pefile",
        "sample": str(sample_path),
        "success": False,
        "error": None,
        "is_pe": False,
        "headers": {},
        "sections": [],
        "imports": [],
        "exports": [],
        "summary": {
            "architecture": None,
            "compile_timestamp": None,
            "imphash": None,
            "total_sections": 0,
            "total_imports": 0,
            "total_exports": 0,
            "high_entropy_sections": [],
            "suspicious_imports": [],
        }
    }

    if not sample_path.exists():
        result["error"] = f"Sample not found: {sample_path}"
        logger.error(result["error"])
        return result

    if not is_pe(sample_path):
        result["error"] = "Not a PE file — skipping pefile analysis"
        logger.info(f"pefile: {sample_path.name} is not a PE, skipping")
        return result

    result["is_pe"] = True

    try:
        import pefile
        import datetime

        pe = pefile.PE(str(sample_path))

        # File header
        machine = pe.FILE_HEADER.Machine
        arch_map = {0x14c: "x86", 0x8664: "x64", 0x1c0: "ARM", 0xaa64: "ARM64"}
        architecture = arch_map.get(machine, f"unknown (0x{machine:04x})")

        timestamp = pe.FILE_HEADER.TimeDateStamp
        try:
            compile_time = datetime.datetime.fromtimestamp(timestamp).isoformat()
        except Exception:
            compile_time = str(timestamp)

        result["headers"] = {
            "machine": architecture,
            "compile_timestamp": compile_time,
            "num_sections": pe.FILE_HEADER.NumberOfSections,
            "characteristics": hex(pe.FILE_HEADER.Characteristics),
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
            "subsystem": pe.OPTIONAL_HEADER.Subsystem,
        }

        result["summary"]["architecture"] = architecture
        result["summary"]["compile_timestamp"] = compile_time

        # Imphash
        try:
            result["summary"]["imphash"] = pe.get_imphash()
        except Exception:
            pass

        # Sections
        high_entropy = []
        for section in pe.sections:
            name = section.Name.decode(errors="replace").rstrip("\x00")
            data = section.get_data()
            entropy = calculate_entropy(data)
            sec = {
                "name": name,
                "virtual_address": hex(section.VirtualAddress),
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": entropy,
                "characteristics": hex(section.Characteristics),
            }
            result["sections"].append(sec)
            if entropy > 7.0:
                high_entropy.append(f"{name} (entropy: {entropy})")

        result["summary"]["total_sections"] = len(result["sections"])
        result["summary"]["high_entropy_sections"] = high_entropy

        # Imports
        suspicious_apis = {
            "virtualalloc", "virtualprotect", "writeprocessmemory",
            "createremotethread", "shellexecute", "winexec",
            "loadlibrary", "getprocaddress", "isdebuggerpresent",
            "checkremotedebuggerpresent", "ntqueryinformationprocess",
            "cryptencrypt", "cryptdecrypt", "internetopen", "internetconnect",
            "httpsendrequest", "urldownloadtofile", "createservice",
            "regsetvalue", "regcreatekey",
        }

        suspicious_found = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode(errors="replace")
                functions = []
                for imp in entry.imports:
                    fname = imp.name.decode(errors="replace") if imp.name else f"ord_{imp.ordinal}"
                    functions.append(fname)
                    if fname.lower().rstrip("aw") in suspicious_apis:
                        suspicious_found.append(f"{dll}::{fname}")
                result["imports"].append({"dll": dll, "functions": functions})

        result["summary"]["total_imports"] = len(result["imports"])
        result["summary"]["suspicious_imports"] = suspicious_found

        # Exports
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                name = exp.name.decode(errors="replace") if exp.name else f"ord_{exp.ordinal}"
                result["exports"].append(name)

        result["summary"]["total_exports"] = len(result["exports"])
        result["success"] = True

        logger.info(
            f"pefile complete: {len(result['sections'])} sections, "
            f"{len(result['imports'])} import DLLs, "
            f"{len(suspicious_found)} suspicious imports"
        )

        pe.close()

    except Exception as e:
        result["error"] = f"pefile analysis failed: {e}"
        logger.error(result["error"])

    return result


if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    if len(sys.argv) < 2:
        print("Usage: python run_pefile.py <sample_path>")
        sys.exit(1)

    sample = Path(sys.argv[1])
    results = run_pefile(sample)

    print(f"\n{'='*55}")
    print(f"  pefile Results: {sample.name}")
    print(f"{'='*55}")
    print(f"  Success      : {results['success']}")
    print(f"  Is PE        : {results['is_pe']}")

    if results["error"]:
        print(f"  Note         : {results['error']}")

    if results["is_pe"] and results["success"]:
        s = results["summary"]
        print(f"  Architecture : {s['architecture']}")
        print(f"  Compiled     : {s['compile_timestamp']}")
        print(f"  Imphash      : {s['imphash'] or 'n/a'}")
        print(f"  Sections     : {s['total_sections']}")
        print(f"  Import DLLs  : {s['total_imports']}")
        print(f"  Exports      : {s['total_exports']}")

        if s["high_entropy_sections"]:
            print(f"\n  --- High Entropy Sections ---")
            for sec in s["high_entropy_sections"]:
                print(f"    {sec}")

        if s["suspicious_imports"]:
            print(f"\n  --- Suspicious Imports ---")
            for imp in s["suspicious_imports"]:
                print(f"    {imp}")
