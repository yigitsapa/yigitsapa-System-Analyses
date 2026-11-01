# yigitsapa System Analyses Engine — Windows hardware inventory and system analysis.
from __future__ import annotations
import argparse
import csv
import concurrent.futures as cf
import ctypes
import datetime as dt
import json
import math
import mmap
import multiprocessing as mp
import os
import platform
import re
import shutil
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable
import contextlib
import hashlib
import html as html_lib
import importlib.util
import io
import plistlib
_PROVIDER_LOCK = threading.RLock()
_INVENTORY_PROVIDERS: dict[str, tuple[Any, frozenset[str] | None]] = {}
_PLATFORM_PROVIDERS: dict[str, Any] = {}
def _provider_key(value: str) -> str:
    key = str(value).strip().lower()
    if not key or not re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", key):
        raise ValueError('provider name must not be empty and may contain only letters, digits, ., _, -')
    return key
def register_inventory_provider(name: str, collector, *, systems: Iterable[str] | None = None,
                                replace: bool = False) -> None:
    key = _provider_key(name)
    if not callable(collector):
        raise TypeError('collector must be callable')
    system_keys = frozenset(str(x).strip().lower() for x in systems) if systems is not None else None
    if system_keys is not None and any(not x for x in system_keys):
        raise ValueError('systems must contain non-empty operating-system names')
    with _PROVIDER_LOCK:
        if key in _INVENTORY_PROVIDERS and not replace:
            raise ValueError(f"inventory provider is already registered: {key}")
        _INVENTORY_PROVIDERS[key] = (collector, system_keys)
def unregister_inventory_provider(name: str) -> bool:
    key = _provider_key(name)
    with _PROVIDER_LOCK:
        return _INVENTORY_PROVIDERS.pop(key, None) is not None
def register_platform_provider(system: str, collector, *, replace: bool = False) -> None:
    key = _provider_key(system)
    if not callable(collector):
        raise TypeError('collector must be callable')
    builtins = {"windows", "linux", "darwin"}
    with _PROVIDER_LOCK:
        if key in builtins and not replace:
            raise ValueError(f"replace=True is required to replace the built-in platform provider: {key}")
        if key in _PLATFORM_PROVIDERS and not replace:
            raise ValueError(f"platform provider is already registered: {key}")
        _PLATFORM_PROVIDERS[key] = collector
def unregister_platform_provider(system: str) -> bool:
    key = _provider_key(system)
    with _PROVIDER_LOCK:
        return _PLATFORM_PROVIDERS.pop(key, None) is not None
def registered_providers() -> dict[str, Any]:
    with _PROVIDER_LOCK:
        return {
            "inventory": [
                {"name": name, "systems": sorted(systems) if systems is not None else None}
                for name, (_, systems) in sorted(_INVENTORY_PROVIDERS.items())
            ],
            "platform": sorted(_PLATFORM_PROVIDERS),
        }
MEMORY_TYPES = {
    0x01: 'Other', 0x02: "Unknown", 0x03: "DRAM", 0x04: "EDRAM",
    0x05: "VRAM", 0x06: "SRAM", 0x07: "RAM", 0x08: "ROM",
    0x09: "Flash", 0x0A: "EEPROM", 0x0B: "FEPROM", 0x0C: "EPROM",
    0x0D: "CDRAM", 0x0E: "3DRAM", 0x0F: "SDRAM", 0x10: "SGRAM",
    0x11: "RDRAM", 0x12: "DDR", 0x13: "DDR2", 0x14: "DDR2 FB-DIMM",
    0x18: "DDR3", 0x19: "FBD2", 0x1A: "DDR4", 0x1B: "LPDDR",
    0x1C: "LPDDR2", 0x1D: "LPDDR3", 0x1E: "LPDDR4",
    0x1F: 'Logical persistent memory', 0x20: "HBM", 0x21: "HBM2",
    0x22: "DDR5", 0x23: "LPDDR5", 0x24: "HBM3", 0x25: "MRDIMM",
}
MEMORY_FORM_FACTORS = {
    0x01: 'Other', 0x02: "Unknown", 0x03: "SIMM", 0x04: "SIP",
    0x05: "Chip", 0x06: "DIP", 0x07: "ZIP", 0x08: 'Proprietary card',
    0x09: "DIMM", 0x0A: "TSOP", 0x0B: 'Chip rank', 0x0C: "RIMM",
    0x0D: "SO-DIMM", 0x0E: "SRIMM", 0x0F: "FB-DIMM", 0x10: "Die",
    0x11: "CAMM", 0x12: "CUDIMM", 0x13: "CSODIMM",
}
WMI_MEMORY_TYPES = {
    0: "Unknown", 1: 'Other', 2: "DRAM", 3: "Synchronous DRAM", 4: "Cache DRAM",
    5: "EDO", 6: "EDRAM", 7: "VRAM", 8: "SRAM", 9: "RAM", 10: "ROM", 11: "Flash",
    12: "EEPROM", 13: "FEPROM", 14: "EPROM", 15: "CDRAM", 16: "3DRAM", 17: "SDRAM",
    18: "SGRAM", 19: "RDRAM", 20: "DDR", 21: "DDR2", 22: "DDR2 FB-DIMM",
    24: "DDR3", 25: "FBD2", 26: "DDR4", 27: "LPDDR", 28: "LPDDR2", 29: "LPDDR3",
    30: "LPDDR4", 31: 'Logical persistent memory', 32: "HBM", 33: "HBM2", 34: "DDR5",
    35: "LPDDR5", 36: "HBM3",
}
WMI_MEMORY_FORM_FACTORS = {
    0: "Unknown", 1: 'Other', 2: "SIP", 3: "DIP", 4: "ZIP", 5: "SOJ",
    6: 'Custom', 7: "SIMM", 8: "DIMM", 9: "TSOP", 10: "PGA", 11: "RIMM",
    12: "SO-DIMM", 13: "SRIMM", 14: "SMD", 15: "SSMP", 16: "QFP",
    17: "TQFP", 18: "SOIC", 19: "LCC", 20: "PLCC", 21: "BGA",
    22: "FPBGA", 23: "LGA",
}
GPU_VENDOR_IDS = {
    0x10DE: "NVIDIA", 0x1002: "AMD/ATI", 0x1022: "AMD",
    0x8086: "Intel", 0x13B5: "ARM", 0x5143: "Qualcomm",
    0x106B: "Apple", 0x1010: "Imagination Technologies",
    0x1AF4: "VirtIO", 0x15AD: "VMware", 0x1414: "Microsoft",
    0x1B36: "QEMU", 0x80EE: "VirtualBox", 0x1234: "QEMU/Bochs",
    0x17CB: "Qualcomm", 0x19E5: "Huawei", 0x1D94: "Multimedia/SoC vendor",
    0x102B: "Matrox", 0x1039: "SiS", 0x1106: "VIA",
    0x5333: "S3 Graphics", 0x1013: "Cirrus Logic", 0x3D3D: "3Dlabs",
    0x1A03: "ASPEED", 0x18CA: "XGI", 0x14E4: "Broadcom",
    0x1F3A: "Allwinner", 0x2207: "Rockchip", 0x1D17: "Zhaoxin",
}
def parse_pci_ids(text: str) -> tuple[dict[int, str], dict[tuple[int, int], str]]:
    vendors: dict[int, str] = {}
    devices: dict[tuple[int, int], str] = {}
    current_vendor: int | None = None
    for raw_line in text.splitlines():
        if not raw_line or raw_line.startswith(("#", "C ")):
            if raw_line.startswith("C "):
                current_vendor = None
            continue
        if raw_line.startswith("\t\t"):
            continue
        if raw_line.startswith("\t"):
            match = re.match(r"^\t([0-9A-Fa-f]{4})\s+(\S.*)$", raw_line)
            if match and current_vendor is not None:
                devices[(current_vendor, int(match.group(1), 16))] = match.group(2).strip()
            continue
        match = re.match(r"^([0-9A-Fa-f]{4})\s+(\S.*)$", raw_line)
        current_vendor = None
        if match:
            current_vendor = int(match.group(1), 16)
            vendors[current_vendor] = match.group(2).strip()
    return vendors, devices
@lru_cache(maxsize=1)
def _system_pci_ids() -> tuple[dict[int, str], dict[tuple[int, int], str]]:
    candidates = (
        "/usr/share/hwdata/pci.ids", "/usr/share/misc/pci.ids",
        "/usr/share/pci.ids", "/usr/share/pciutils/pci.ids",
        "/var/lib/pciutils/pci.ids",
    )
    for candidate in candidates:
        try:
            text = Path(candidate).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        vendors, devices = parse_pci_ids(text)
        if vendors:
            return vendors, devices
    return {}, {}
def pci_display_names(vendor_id: int, device_id: int) -> tuple[str | None, str | None]:
    vendors, devices = _system_pci_ids()
    vendor = vendors.get(int(vendor_id)) or GPU_VENDOR_IDS.get(int(vendor_id))
    device = devices.get((int(vendor_id), int(device_id)))
    return vendor, device
ARCHITECTURES = {
    "amd64": "x86_64", "x64": "x86_64", "x86_64": "x86_64", "x86-64": "x86_64",
    "i386": "x86", "i486": "x86", "i586": "x86", "i686": "x86", "i86pc": "x86", "x86": "x86",
    "arm64": "aarch64", "arm64e": "aarch64", "arm64ec": "aarch64", "arm64x": "aarch64",
    "aarch64": "aarch64", "aarch64_be": "aarch64_be", "armv8": "arm", "armv8-a": "arm",
    "armv8l": "arm", "armv8.1-a": "arm", "armv8.2-a": "arm", "armv9": "arm", "armv9-a": "arm",
    "armv9l": "arm", "armv7l": "arm", "armv7": "arm", "armv6l": "arm", "arm": "arm",
    "ppc64le": "ppc64le", "powerpc64le": "ppc64le", "ppc64": "ppc64", "powerpc64": "ppc64",
    "ppc": "ppc", "powerpc": "ppc", "sparc": "sparc", "sparc64": "sparc64",
    "s390": "s390", "s390x": "s390x", "riscv32": "riscv32", "riscv32gc": "riscv32",
    "riscv32imac": "riscv32", "riscv64": "riscv64", "riscv64gc": "riscv64", "riscv64imafdc": "riscv64",
    "loongarch32": "loongarch32", "loongarch64": "loongarch64", "loong64": "loongarch64",
    "ia64": "ia64", "itanium": "ia64", "mips": "mips", "mipsel": "mips", "mips64": "mips64", "mips64el": "mips64",
    "alpha": "alpha", "sh4": "sh4", "parisc": "parisc", "parisc64": "parisc64",
    "xtensa": "xtensa", "avr32": "avr32", "epiphany": "epiphany", "wasm32": "wasm32",
}
WMI_ARCHITECTURES = {
    0: "x86", 1: "MIPS", 2: "Alpha", 3: "PowerPC", 5: "ARM",
    6: "Itanium/IA-64", 9: "x86_64", 12: "ARM64",
}
ARM_CPU_IMPLEMENTERS = {
    0x41: "ARM", 0x42: "Broadcom", 0x43: "Cavium", 0x44: "DEC",
    0x46: "Fujitsu", 0x48: "HiSilicon", 0x4E: "NVIDIA", 0x50: "Applied Micro",
    0x51: "Qualcomm", 0x56: "Marvell", 0x61: "Apple", 0x69: "Intel",
    0x6D: "Microsoft", 0x70: "Phytium", 0xC0: "Ampere",
}
def _records(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if isinstance(value, list):
        return [x for x in value if isinstance(x, dict)]
    return [value] if isinstance(value, dict) else []
def _first(obj: dict[str, Any] | None, *keys: str, default: Any = None) -> Any:
    if not isinstance(obj, dict):
        return default
    for key in keys:
        if key in obj and obj[key] not in (None, ""):
            return obj[key]
        for actual, value in obj.items():
            if actual.lower() == key.lower() and value not in (None, ""):
                return value
    return default
def _optional_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        token = value.strip().lower()
        if token in {"1", "true", "yes", "y", "on", "enabled", "present", "connected"}:
            return True
        if token in {"0", "false", "no", "n", "off", "disabled", "absent", "disconnected", ""}:
            return False
    return None
def _number(value: Any) -> int | float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        text = value.strip().replace(",", "")
        if not text:
            return None
        try:
            return int(text, 0)
        except ValueError:
            try:
                return float(text)
            except ValueError:
                return None
    return None
def _clean_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text if text and text.lower() not in {"none", "unknown", "not specified", "to be filled by o.e.m."} else None
def _memory_size_bytes(value: Any) -> int | None:
    number = _number(value)
    if number is not None:
        return int(number) if number >= 0 else None
    if not isinstance(value, str):
        return None
    match = re.search(r"([0-9]+(?:\.[0-9]+)?)\s*(bytes?|[kmgtpe]?i?b)\b", value.strip(), re.I)
    if not match:
        return None
    amount = float(match.group(1))
    unit = match.group(2).lower()
    multipliers = {
        "b": 1, "byte": 1, "bytes": 1,
        "kb": 1000, "kib": 1024, "mb": 1000**2, "mib": 1024**2,
        "gb": 1000**3, "gib": 1024**3, "tb": 1000**4, "tib": 1024**4,
        "pb": 1000**5, "pib": 1024**5, "eb": 1000**6, "eib": 1024**6,
    }
    multiplier = multipliers.get(unit)
    return int(amount * multiplier) if multiplier is not None else None
def canonical_architecture(machine: str | None = None, wmi_arch: Any = None) -> dict[str, str | None]:
    raw = str(machine or platform.machine() or "unknown").strip()
    canonical = ARCHITECTURES.get(raw.lower(), raw.lower() or "unknown")
    if wmi_arch is not None:
        numeric = _number(wmi_arch)
        wmi_label = WMI_ARCHITECTURES.get(int(numeric)) if numeric is not None else None
    else:
        wmi_label = None
    if wmi_label:
        wmi_key = wmi_label.lower()
        canonical = ARCHITECTURES.get(wmi_key, wmi_key)
    family = (
        "x86" if canonical in {"x86", "x86_64"} else
        "ARM" if canonical in {"arm", "aarch64"} or canonical.startswith("aarch64_") else
        "PowerPC" if canonical.startswith(("ppc", "powerpc")) else
        "MIPS" if canonical.startswith("mips") else
        "RISC-V" if canonical.startswith("riscv") else
        "IBM Z" if canonical in {"s390", "s390x"} else
        "LoongArch" if canonical.startswith("loongarch") else
        "IA-64" if canonical == "ia64" else "Other/unknown"
    )
    return {"reported": raw, "canonical": canonical, "family": family, "wmi_architecture": wmi_label}
def identify_gpu_vendor(vendor_id: Any = None, vendor_name: Any = None, device_name: Any = None) -> str:
    numeric = _number(vendor_id)
    if numeric is not None:
        name = GPU_VENDOR_IDS.get(int(numeric))
        if name:
            return name
    text = f"{vendor_name or ''} {device_name or ''}".lower()
    for tokens, vendor in (
        (("nvidia", "geforce", "quadro", "tesla", "rtx", "gtx"), "NVIDIA"),
        (("advanced micro devices", "amd", "radeon", "ati technologies"), "AMD/ATI"),
        (("intel", "iris xe", "uhd graphics", "arc graphics"), "Intel"),
        (("apple", "m-series gpu"), "Apple"),
        (("qualcomm", "adreno"), "Qualcomm"),
        (("arm", "mali"), "ARM"),
        (("apple", "apple gpu", "agx"), "Apple"),
        (("imagination", "powervr"), "Imagination Technologies"),
        (("vivante",), "Vivante"), (("mediatek",), "MediaTek/SoC"),
        (("vmware",), "VMware"), (("virtualbox",), "VirtualBox"),
        (("virtio", "qemu", "bochs"), "Virtual/Emulated"),
        (("microsoft basic display", "hyper-v"), "Microsoft/Virtual"),
    ):
        if any(token in text for token in tokens):
            return vendor
    return _clean_text(vendor_name) or "Unknown"
def classify_storage_kind(*, name: Any = None, model: Any = None, bus: Any = None,
                          transport: Any = None, rotational: Any = None, device_type: Any = None,
                          is_virtual: bool | None = None) -> str:
    n = f"{name or ''} {model or ''}".lower()
    b = f"{bus or ''} {transport or ''}".strip().lower()
    t = str(device_type or "").lower()
    virtual_types = {"lvm", "raid", "raid0", "raid1", "raid4", "raid5", "raid6", "raid10",
                     "md", "md0", "mdraid", "mpath", "multipath", "loop", "zram", "crypt", "dm",
                     "device-mapper", "thin-pool", "cache", "ceph", "rbd", "zfs", "bcache", "vdo"}
    virtual_names = ("virtual disk", "vmware virtual", "qemu", "virtio", "loop", "zram", "device-mapper",
                     "multipath", "mdraid", "software raid", "storage spaces", "ceph rbd", "zfs volume",
                     "iscsi virtual", "vdo device", "bcache")
    if is_virtual or any(x in n + " " + b for x in virtual_names) or t in virtual_types:
        return 'Virtual/mapped storage'
    if t in {"rom", "cd", "cdrom", "optical"} or "cd-rom" in n or "dvd" in n or "blu-ray" in n:
        return 'Optical drive'
    if "nvme" in n or "nvme" in b:
        return "NVMe SSD"
    if any(x in b for x in ("emmc", "mmc")) or "mmcblk" in n:
        return "eMMC/MMC/SD storage"
    media = str(device_type or "").strip().lower()
    if "cdrom" in t or "optical" in t or media in {"optical", "cdrom"}:
        return 'Optical drive'
    if media in {"hdd", "hard disk", "hard drive"}:
        return "HDD"
    if media in {"ssd", "solid state", "solid state drive"}:
        return "SSD"
    rotation_number = _number(rotational)
    if rotation_number is not None and rotation_number > 0:
        return "HDD"
    if any(x in b for x in ("iscsi", "i scsi", "nvmeof", "nvmf")):
        return "iSCSI/NVMe-oF storage"
    if any(x in b for x in ("sas", "scsi", "fibre", "fc", "fcp", "fcoe")):
        return "SAS/SCSI/Fibre Channel"
    if any(x in b for x in ("ufs", "universal flash")) or any(x in n for x in ("ufs storage", "ufs device")):
        return "UFS flash storage"
    if any(x in b for x in ("usb", "firewire", "thunderbolt")):
        base = "USB/external storage" if "usb" in b else "External storage"
        if rotational is True:
            return base + " (HDD)"
        if rotational is False:
            return base + " (SSD/flash)"
        return base
    if rotational is True or str(rotational).lower() in {"1", "true", "yes"}:
        return "HDD"
    if rotational is False or str(rotational).lower() in {"0", "false", "no"}:
        return "SSD (non-rotational)"
    if any(x in n for x in ("ssd", "solid state", "flash storage", "ufs storage")):
        return "SSD/flash storage"
    if any(x in n for x in ("hard disk", "hdd", "hard drive")):
        return "HDD"
    if any(x in b for x in ("raid",)) or "raid" in n:
        return "RAID storage"
    if any(x in b for x in ("sata", "ata", "ahci", "ide", "pata", "atapi")):
        return "SATA/ATA/IDE/PATA storage (media unknown)"
    if "raid" in n or "raid" in b:
        return "RAID storage"
    return _clean_text(bus) or _clean_text(transport) or 'Unknown storage type'
def _run(args: list[str], timeout: float = 12.0) -> tuple[int, str, str]:
    try:
        result = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace",
                                timeout=timeout, check=False, shell=False)
        return result.returncode, result.stdout or "", result.stderr or ""
    except (OSError, subprocess.SubprocessError) as exc:
        return -1, "", str(exc)
def _cmd_json(args: list[str], timeout: float = 12.0) -> tuple[Any, str | None]:
    rc, out, err = _run(args, timeout)
    if rc != 0:
        return None, err.strip() or f"command exit code {rc}"
    try:
        return json.loads(out), None
    except (json.JSONDecodeError, TypeError) as exc:
        return None, f"Could not parse JSON: {exc}"
def _source(sources: list[dict[str, Any]], name: str, status: str, detail: str | None = None,
            count: int | None = None) -> None:
    row: dict[str, Any] = {"name": name, "status": status}
    if detail:
        row["detail"] = detail[:600]
    if count is not None:
        row["count"] = int(count)
    sources.append(row)
def _bytes_from_wmi_size(max_capacity_bytes: Any, max_capacity_ex_kib: Any = None) -> int | None:
    extended_kib = _number(max_capacity_ex_kib)
    legacy_bytes = _number(max_capacity_bytes)
    if extended_kib is not None and extended_kib > 0:
        return int(extended_kib * 1024)
    if legacy_bytes is not None and legacy_bytes > 0:
        return int(legacy_bytes)
    return None
def extract_smbios_inventory(structs: Iterable[dict[str, Any]] | None) -> dict[str, Any]:
    output: dict[str, Any] = {
        "bios": {}, "system": {}, "baseboards": [], "processors": [],
        "memory_arrays": [], "memory_devices": [], "system_slots": [], "onboard_devices": [],
        "source": "SMBIOS",
    }
    if not structs:
        return output
    for record in structs:
        try:
            typ = int(record.get("type", -1))
            data = record.get("data", b"")
            strings = record.get("strings", [])
            if not isinstance(data, (bytes, bytearray)):
                continue

            def u8(offset: int) -> int | None:
                return data[offset] if 0 <= offset < len(data) else None

            def u16(offset: int) -> int | None:
                return int.from_bytes(data[offset:offset + 2], "little") if offset >= 0 and offset + 2 <= len(data) else None

            def u32(offset: int) -> int | None:
                return int.from_bytes(data[offset:offset + 4], "little") if offset >= 0 and offset + 4 <= len(data) else None

            def u64(offset: int) -> int | None:
                return int.from_bytes(data[offset:offset + 8], "little") if offset >= 0 and offset + 8 <= len(data) else None

            def st(offset: int) -> str | None:
                index = u8(offset)
                if index is None or index <= 0 or index > len(strings):
                    return None
                return _clean_text(strings[index - 1])

            if typ == 0 and not output["bios"]:
                output["bios"] = {"vendor": st(4), "version": st(5), "release_date": st(8), "source": "SMBIOS Type 0"}
            elif typ == 1 and not output["system"]:
                output["system"] = {"manufacturer": st(4), "product": st(5), "version": st(6), "family": st(26), "source": "SMBIOS Type 1"}
            elif typ == 2:
                output["baseboards"].append({"manufacturer": st(4), "product": st(5), "version": st(6),
                                             "asset_tag": st(8), "location": st(10), "source": "SMBIOS Type 2"})
            elif typ == 4:
                cores = u8(35)
                if cores == 0xFF:
                    cores = u16(42)
                threads = u8(37)
                if threads == 0xFF:
                    threads = u16(46)
                output["processors"].append({"socket": st(4), "manufacturer": st(7), "name": st(16),
                                              "cores": cores, "threads": threads,
                                              "max_clock_mhz": u16(20), "current_clock_mhz": u16(22),
                                              "processor_type_code": u8(5), "source": "SMBIOS Type 4"})
            elif typ == 9:
                slot_type = u8(5)
                usage = u8(7)
                output["system_slots"].append({"name": st(4), "slot_type_code": slot_type,
                    "slot_type": _slot_type_name(slot_type), "usage_code": usage,
                    "usage": {1: "Other", 2: "Unknown", 3: "Available", 4: "In use"}.get(usage, "Unknown/other"),
                    "length_code": u8(8), "slot_id": u16(9), "segment": u16(13),
                    "bus": u8(15), "device_function": u8(16), "source": "SMBIOS Type 9"})
            elif typ == 10:
                pos = 4
                while pos + 1 < len(data) and data[pos] != 0:
                    kind_status = data[pos]
                    description_index = data[pos + 1]
                    desc = None
                    if description_index and description_index <= len(strings):
                        desc = _clean_text(strings[description_index - 1])
                    output["onboard_devices"].append({"name": desc, "device_type_code": kind_status & 0x7F,
                        "device_type": _onboard_type_name(kind_status & 0x7F), "enabled": bool(kind_status & 0x80),
                        "source": "SMBIOS Type 10"})
                    pos += 2
            elif typ == 16:
                cap32 = u32(7)
                cap64 = u64(15)
                max_bytes = int(cap64) if cap32 == 0x80000000 and cap64 else (int(cap32) * 1024 if cap32 not in (None, 0) else None)
                use_code = u8(5)
                output["memory_arrays"].append({"handle": record.get("handle"), "location_code": u8(4),
                    "use_code": use_code, "use": {1: "Other", 2: "Unknown", 3: "System memory", 4: "Video memory",
                        5: "Flash", 6: "Non-volatile RAM", 7: "Cache memory"}.get(use_code, "Unknown/other"),
                    "error_correction_code": u8(6), "max_capacity_bytes": max_bytes,
                    "memory_devices_reported": u16(13), "source": "SMBIOS Type 16"})
            elif typ == 17:
                size_code = u16(12)
                size_bytes: int | None
                state = "installed"
                if size_code == 0:
                    size_bytes, state = 0, "empty"
                elif size_code == 0xFFFF:
                    size_bytes, state = None, "unknown"
                elif size_code == 0x7FFF:
                    extended_size = u32(28)
                    size_bytes = int(extended_size * 1024 * 1024) if extended_size else None
                    state = "installed" if size_bytes else "unknown"
                elif size_code & 0x8000:
                    size_bytes = int(size_code & 0x7FFF) * 1024
                else:
                    size_bytes = int(size_code) * 1024 * 1024
                mem_type_code = u8(18)
                form_code = u8(14)
                speed = u16(21)
                config_speed = u16(32)
                if speed == 0xFFFF:
                    speed = u32(84)
                if config_speed == 0xFFFF:
                    config_speed = u32(88)
                output["memory_devices"].append({
                    "array_handle": u16(4), "device_handle": record.get("handle"), "locator": st(16), "bank_locator": st(17),
                    "state": state, "size_bytes": size_bytes, "memory_type_code": mem_type_code,
                    "memory_type": MEMORY_TYPES.get(mem_type_code, f"Unknown SMBIOS RAM type (0x{mem_type_code:02X})" if mem_type_code is not None else "Unknown"),
                    "form_factor_code": form_code, "form_factor": MEMORY_FORM_FACTORS.get(form_code, f"Unknown form factor (0x{form_code:02X})" if form_code is not None else "Unknown"),
                    "speed_mts": speed if speed not in (0, 0xFFFF) else None,
                    "configured_speed_mts": config_speed if config_speed not in (0, 0xFFFF) else None,
                    "manufacturer": st(23), "part_number": st(26), "serial_number": st(24),
                    "total_width_bits": u16(8), "data_width_bits": u16(10), "rank": (u8(27) or 0) & 0x0F,
                    "ecc": bool(u16(8) and u16(10) and u16(8) > u16(10)),
                    "source": "SMBIOS Type 17"})
            elif typ == 41:
                raw_type = u8(5)
                output["onboard_devices"].append({"name": st(4), "device_type_code": (raw_type & 0x7F) if raw_type is not None else None,
                    "device_type": _onboard_type_name(raw_type & 0x7F) if raw_type is not None else "Unknown",
                    "enabled": bool(raw_type & 0x80) if raw_type is not None else None,
                    "segment": u16(7), "bus": u8(9), "device_function": u8(10), "source": "SMBIOS Type 41"})
        except (IndexError, TypeError, ValueError, OverflowError):
            continue
    return output
def _slot_type_name(code: int | None) -> str:
    return {
        0x01: "Other", 0x02: "Unknown", 0x03: "ISA", 0x04: "MCA", 0x05: "EISA",
        0x06: "PCI", 0x07: "PC Card", 0x08: "VL-VESA", 0x09: "Proprietary",
        0x0A: "Processor card", 0x0B: "Proprietary memory card", 0x0C: "I/O riser",
        0x0D: "NuBus", 0x0E: "PCI-66MHz", 0x0F: "AGP", 0x10: "AGP 2x",
        0x11: "AGP 4x", 0x12: "PCI-X", 0x13: "AGP 8x", 0x14: "M.2 socket 1-DP",
        0x15: "M.2 socket 1-SD", 0x16: "M.2 socket 2", 0x17: "M.2 socket 3",
        0x18: "MXM Type I", 0x19: "MXM Type II", 0x1A: "MXM Type III", 0x1B: "MXM Type IV",
        0x1C: "MXM 3.0 Type A", 0x1D: "MXM 3.0 Type B", 0x1E: "PCI Express Gen 2 SFF- motherboards",
        0x1F: "PCI Express Gen 3 SFF", 0x20: "PCI Express Mini 52-pin", 0x21: "PCI Express Mini 76-pin",
        0x22: "PCI Express Gen 4 SFF", 0x23: "PCI Express Gen 5 SFF",
    }.get(code, f"Unknown slot type (0x{code:02X})" if code is not None else "Unknown")
def _onboard_type_name(code: int) -> str:
    return {0x01: "Other", 0x02: "Unknown", 0x03: "Video", 0x04: "SCSI controller", 0x05: "Ethernet",
            0x06: "Token Ring", 0x07: "Sound", 0x08: "PATA controller", 0x09: "SATA controller",
            0x0A: "SAS controller", 0x0B: "Wireless LAN", 0x0C: "Bluetooth", 0x0D: "WWAN",
            0x0E: "eMMC", 0x0F: "NVMe controller", 0x10: "UFS controller"}.get(code, f"Other/unknown (0x{code:02X})")
def _normalize_cpu(raw: dict[str, Any], machine: str, source: str) -> dict[str, Any]:
    name = _clean_text(_first(raw, "Name", "name", "ProcessorName", "model name", "model_name", "brand_raw", "Processor"))
    manufacturer = _clean_text(_first(raw, "Manufacturer", "manufacturer", "Vendor", "vendor", "Vendor ID", "vendor_id",
                                      "CPU implementer", "CPU Implementer", "cpu_implementer"))
    lower = f"{manufacturer or ''} {name or ''}".lower()
    implementer_match = re.fullmatch(r"\s*(?:0x)?([0-9a-f]{2})\s*", manufacturer or "", re.I)
    implementer_vendor = ARM_CPU_IMPLEMENTERS.get(int(implementer_match.group(1), 16)) if implementer_match else None
    vendor_aliases = (
        (("authenticamd", "advanced micro devices", "amd", "hygon"), "AMD"),
        (("genuineintel", "intel"), "Intel"),
        (("apple",), "Apple"),
        (("qualcomm", "nuvia"), "Qualcomm"),
        (("ampere",), "Ampere"),
        (("broadcom",), "Broadcom"),
        (("nvidia",), "NVIDIA"),
        (("cavium",), "Cavium"),
        (("hisilicon", "hi silicon", "huawei"), "HiSilicon/Huawei"),
        (("marvell",), "Marvell"),
        (("phyt(i)?um", "phytium"), "Phytium"),
        (("fujitsu",), "Fujitsu"),
        (("loongson",), "Loongson"),
        (("zhaoxin", "centaurhauls", "centaur"), "Zhaoxin/Centaur"),
        (("transmeta",), "Transmeta"),
        (("sifive", "risc-v", "riscv"), "RISC-V vendor/implementation"),
        (("ibm",), "IBM"),
        (("mediatek", "mtk"), "MediaTek"),
        (("samsung",), "Samsung"),
        (("via technologies", "via eden", "via c3", "via c7"), "VIA"),
        (("loongarch",), "Loongson/LoongArch"),
        (("arm",), "ARM ecosystem / implementer unknown"),
    )
    vendor = next((label for tokens, label in vendor_aliases if any(re.search(token, lower) for token in tokens)), None)
    if vendor is None and implementer_vendor:
        vendor = implementer_vendor
    if vendor is None and manufacturer:
        vendor = manufacturer
    if vendor is None:
        vendor = "Unknown"
    if vendor == "ARM ecosystem / implementer unknown" and implementer_vendor:
        vendor = implementer_vendor
    arch_raw = _first(raw, "Architecture", "architecture", "machine", default=machine)
    wmi_arch = arch_raw if (isinstance(arch_raw, (int, float)) and not isinstance(arch_raw, bool)) or (isinstance(arch_raw, str) and arch_raw.strip().isdigit()) else _first(raw, "ArchitectureCode")
    arch_source = machine if wmi_arch is not None else (str(arch_raw) if arch_raw is not None else machine)
    arch = canonical_architecture(arch_source, wmi_arch)
    cores = _number(_first(raw, "NumberOfCores", "cores", "Core(s) per socket", "Core Count"))
    threads = _number(_first(raw, "NumberOfLogicalProcessors", "threads", "CPU(s)", "Thread(s) per core"))
    return {"name": name or platform.processor() or machine, "vendor": vendor, "manufacturer_raw": manufacturer,
            "architecture": arch, "cores": int(cores) if cores else None,
            "logical_processors": int(threads) if threads else None,
            "socket": _clean_text(_first(raw, "SocketDesignation", "socket", "Socket")),
            "family": _first(raw, "Family", "family"), "model": _first(raw, "Model", "model"),
            "stepping": _first(raw, "Stepping", "stepping"),
            "max_clock_mhz": _number(_first(raw, "MaxClockSpeed", "max_clock_mhz", "MaxMHz")),
            "current_clock_mhz": _number(_first(raw, "CurrentClockSpeed", "current_clock_mhz", "MHz")),
            "cache_l2_bytes": int(_number(_first(raw, "L2CacheSize")) * 1024) if _number(_first(raw, "L2CacheSize")) else None,
            "cache_l3_bytes": int(_number(_first(raw, "L3CacheSize")) * 1024) if _number(_first(raw, "L3CacheSize")) else None,
            "virtualization_firmware_enabled": _first(raw, "VirtualizationFirmwareEnabled"), "source": source}
def infer_integrated_gpu(vendor: str | None, device_name: str | None) -> bool | None:
    label = str(vendor or "").lower()
    name = str(device_name or "").lower()
    compact = re.sub(r"[^a-z0-9]+", " ", name).strip()
    if label == "apple" or label in {"qualcomm", "arm", "mediatek/soc", "vivante", "imagination technologies"}:
        return True
    if label == "intel":
        if re.search(r"\barc\s+(?:[ab]\d{3,4}|pro\s+[a-z]?\d{2,4})\b", compact) or any(
            token in compact for token in ("dg1", "dg2", "battlemage", "alchemist discrete")
        ):
            return False
        if any(token in compact for token in ("uhd graphics", "iris xe", "iris plus", "iris pro", "hd graphics", "xe-lpg", "xe-lpd", "intel graphics")):
            return True
        if "arc graphics" in compact:
            return True
    if label == "amd/ati":
        if any(token in compact for token in ("radeon rx", "radeon pro", "radeon instinct", "firepro", "radeon vii")):
            return False
        if re.search(r"\bradeon\s+(?:graphics|vega\s*\d+|\d{3,4}[ms])\b", compact):
            return True
    if label == "nvidia":
        if any(token in compact for token in ("jetson", "tegra", "orin", "xavier")):
            return True
        if re.search(r"\bnvidia\s+a\d{2,4}\b", compact) or any(
            token in compact for token in ("geforce", "quadro", "tesla", "rtx", "gtx", "l40", "h100", "h200")
        ):
            return False
    return None
def _normalize_gpu(raw: dict[str, Any], source: str) -> dict[str, Any]:
    name = _clean_text(_first(raw, "name", "Name", "FriendlyName", "Chipset Model", "sppci_model", "model", "Description", "VideoProcessor")) or 'Unknown graphics adapter'
    pnp = _clean_text(_first(raw, "PNPDeviceID", "pnp_device_id", "device_id_string", "InstanceId"))
    vendor_id = _first(raw, "vendor_id", "VendorId", "VendorID", "VEN")
    device_id = _first(raw, "device_id", "DeviceId", "DEV")
    if pnp:
        ven_match = re.search(r"VEN_([0-9a-fA-F]{4})", pnp, re.I)
        dev_match = re.search(r"DEV_([0-9a-fA-F]{4})", pnp, re.I)
        if vendor_id is None and ven_match:
            vendor_id = int(ven_match.group(1), 16)
        if device_id is None and dev_match:
            device_id = int(dev_match.group(1), 16)
    if isinstance(vendor_id, str):
        match = re.search(r"(?:VEN_|0x)?([0-9a-fA-F]{4})", vendor_id)
        if match:
            vendor_id = int(match.group(1), 16)
    if isinstance(device_id, str):
        match = re.search(r"(?:DEV_|0x)?([0-9a-fA-F]{4})", device_id)
        if match:
            device_id = int(match.group(1), 16)
    vendor = identify_gpu_vendor(vendor_id, _first(raw, "vendor_name", "AdapterCompatibility", "Vendor", "Manufacturer"), name)
    integrated = _optional_bool(_first(raw, "integrated", "Integrated"))
    explicit_virtual = _optional_bool(_first(raw, "software", "is_virtual", "Virtual"))
    virtual = explicit_virtual is True or any(x in name.lower() for x in ("virtual display", "microsoft basic render", "vmware svga", "virtualbox graphics", "virtio gpu"))
    if integrated is None:
        integrated = infer_integrated_gpu(vendor, name)
    vram_raw = _first(raw, "dedicated_vram", "DedicatedVideoMemory", "AdapterRAM", "dedicated_memory_bytes", "memory_bytes", "spdisplays_vram", "VRAM", "vram")
    vram = _number(vram_raw)
    if vram is None:
        vram = _memory_size_bytes(vram_raw)
    vram_source = "reported by adapter" if vram is not None else None
    if source == "Win32_VideoController" and vram is not None and vram >= 0xF0000000:
        vram_source = "WMI uint32 value; may be truncated/wrapped"
    dedicated_memory_source = _clean_text(_first(raw, "dedicated_memory_source", "memory_source")) or source
    return {"name": name, "vendor": vendor, "vendor_id": int(_number(vendor_id)) if _number(vendor_id) is not None else None,
            "device_id": int(_number(device_id)) if _number(device_id) is not None else None,
            "pnp_device_id": pnp, "integrated": integrated, "virtual": virtual,
            "dedicated_memory_bytes": int(vram) if vram is not None else None, "memory_source_quality": vram_source,
            "dedicated_memory_source": dedicated_memory_source if vram is not None else None,
            "driver_version": _clean_text(_first(raw, "driver_version", "DriverVersion", "Driver Version")),
            "driver_date": _clean_text(_first(raw, "driver_date", "DriverDate", "Driver Date")),
            "bus": _clean_text(_first(raw, "bus", "Bus", "Location")),
            "status": _clean_text(_first(raw, "Status", "status")),
            "problem_code": _first(raw, "Problem", "problem_code"),
            "compatible_raw": _clean_text(_first(raw, "compatible_raw", "compatible", "Compatible")),
            "luid": _clean_text(_first(raw, "luid", "Luid")),
            "source": source}
def _gpu_key(gpu: dict[str, Any]) -> tuple[Any, ...]:
    if gpu.get("pnp_device_id"):
        return ("pnp", str(gpu["pnp_device_id"]).lower())
    if gpu.get("vendor_id") is not None and gpu.get("device_id") is not None:
        return ("pci", gpu["vendor_id"], gpu["device_id"], str(gpu.get("name", "")).lower())
    return ("name", str(gpu.get("name", "")).lower(), str(gpu.get("vendor", "")).lower())
def _merge_gpus(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def pci_id_key(gpu: dict[str, Any]) -> tuple[Any, ...] | None:
        if gpu.get("vendor_id") is None or gpu.get("device_id") is None:
            return None
        return (gpu.get("vendor_id"), gpu.get("device_id"))
    pnp_groups: dict[str, list[dict[str, Any]]] = {}
    unlinked: list[dict[str, Any]] = []
    for record in records:
        pnp = str(record.get("pnp_device_id") or "").strip().lower()
        if pnp:
            pnp_groups.setdefault(pnp, []).append(record)
        else:
            unlinked.append(record)
    groups: list[tuple[tuple[Any, ...], list[dict[str, Any]]]] = [
        (("pnp", pnp), items) for pnp, items in pnp_groups.items()
    ]
    pnp_pci_groups: dict[tuple[Any, ...], list[int]] = {}
    for idx, (_, items) in enumerate(groups):
        keys = {pci_id_key(item) for item in items}
        keys.discard(None)
        for key in keys:
            pnp_pci_groups.setdefault(key, []).append(idx)
    unlinked_by_pci: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for item in unlinked:
        pci_key = pci_id_key(item)
        if pci_key:
            unlinked_by_pci.setdefault(pci_key, []).append(item)
    consumed: set[int] = set()
    output_groups: list[tuple[tuple[Any, ...], list[dict[str, Any]]]] = list(groups)
    for pci_key, items in unlinked_by_pci.items():
        candidates = pnp_pci_groups.get(pci_key, [])
        if len(items) == 1 and len(candidates) == 1:
            output_groups[candidates[0]][1].append(items[0])
            consumed.add(id(items[0]))
    for item in unlinked:
        if id(item) not in consumed:
            output_groups.append((_gpu_key(item), [item]))
    merged: list[dict[str, Any]] = []
    for _, items in output_groups:
        current: dict[str, Any] = {}
        source_names: list[str] = []
        for raw in sorted(items, key=lambda row: (bool(row.get("pnp_device_id")), bool(row.get("luid"))), reverse=True):
            for field, value in raw.items():
                if value not in (None, "", [], {}):
                    if field == "dedicated_memory_bytes":
                        current_quality = str(current.get("memory_source_quality") or "").lower()
                        incoming_quality = str(raw.get("memory_source_quality") or "").lower()
                        current_source = str(current.get("dedicated_memory_source") or current.get("source") or "").lower()
                        incoming_source = str(raw.get("source") or "").lower()
                        current_weak = ("truncated" in current_quality or "wrapped" in current_quality
                                        or "win32_videocontroller" in current_source)
                        incoming_strong = ("truncated" not in incoming_quality and "wrapped" not in incoming_quality
                                           and bool(incoming_quality))
                        incoming_better_source = any(token in incoming_source for token in ("dxgi", "nvml")) and not any(
                            token in current_source for token in ("dxgi", "nvml"))
                        if (current.get(field) in (None, "", [], {}) or (current_weak and incoming_strong)
                                or incoming_better_source):
                            current[field] = value
                            current["memory_source_quality"] = raw.get("memory_source_quality")
                            current["dedicated_memory_source"] = raw.get("dedicated_memory_source") or raw.get("source")
                        continue
                    if field == "memory_source_quality":
                        current_quality = str(current.get(field) or "").lower()
                        incoming_quality = str(value or "").lower()
                        if not current_quality or ("truncated" in current_quality and "truncated" not in incoming_quality):
                            current[field] = value
                        continue
                    if current.get(field) in (None, "", [], {}) or field in {"name", "vendor", "vendor_id", "device_id"}:
                        current[field] = value
            if raw.get("source") and raw["source"] not in source_names:
                source_names.append(raw["source"])
            for source in raw.get("sources", []) if isinstance(raw.get("sources"), list) else []:
                if source and source not in source_names:
                    source_names.append(source)
        current["sources"] = source_names
        merged.append(current)
    return sorted(merged, key=lambda g: (str(g.get("vendor")), str(g.get("name")), str(g.get("luid"))))
def _normalize_memory_device(raw: dict[str, Any], source: str) -> dict[str, Any]:
    mem_code = _number(_first(raw, "memory_type_code", "SMBIOSMemoryType", "MemoryTypeCode"))
    mem_name = _clean_text(_first(raw, "memory_type", "MemoryTypeName", "Type"))
    wmi_mem_code = _number(_first(raw, "wmi_memory_type_code"))
    if not mem_name and mem_code is not None:
        mem_name = MEMORY_TYPES.get(int(mem_code), f"Bilinmeyen RAM tipi (kod 0x{int(mem_code):02X})")
    size = _memory_size_bytes(_first(raw, "size_bytes", "Capacity", "SizeBytes", "size"))
    if size is not None and "Capacity" in raw and "size_bytes" not in raw:
        size = int(size)
    state = _clean_text(_first(raw, "state"))
    if not state:
        state = "empty" if size == 0 else "unknown" if size is None else "installed"
    form_code = _number(_first(raw, "form_factor_code", "FormFactor"))
    form = _clean_text(_first(raw, "form_factor", "FormFactorName"))
    if not form and form_code is not None:
        form = MEMORY_FORM_FACTORS.get(int(form_code), f"Unknown form factor (code 0x{int(form_code):02X})")
    speed = _number(_first(raw, "speed_mts", "Speed", "speed"))
    configured = _number(_first(raw, "configured_speed_mts", "ConfiguredClockSpeed", "ConfiguredMemorySpeed"))
    return {"locator": _clean_text(_first(raw, "locator", "DeviceLocator", "slot", "Slot")),
            "bank_locator": _clean_text(_first(raw, "bank_locator", "BankLabel", "BankLocator", "bank")),
            "state": state, "size_bytes": int(size) if size is not None else None,
            "memory_type_code": int(mem_code) if mem_code is not None else None,
            "memory_type": mem_name or "Unknown",
            "wmi_memory_type_code": int(wmi_mem_code) if wmi_mem_code is not None else None,
            "form_factor_code": int(form_code) if form_code is not None else None,
            "form_factor": form or "Unknown", "speed_mts": int(speed) if speed is not None else None,
            "configured_speed_mts": int(configured) if configured is not None else None,
            "manufacturer": _clean_text(_first(raw, "manufacturer", "Manufacturer")),
            "part_number": _clean_text(_first(raw, "part_number", "PartNumber")),
            "serial_number": _clean_text(_first(raw, "serial_number", "SerialNumber")),
            "total_width_bits": _number(_first(raw, "total_width_bits", "TotalWidth")),
            "data_width_bits": _number(_first(raw, "data_width_bits", "DataWidth")),
            "ecc": _first(raw, "ecc", "ECC"), "rank": _number(_first(raw, "rank", "Rank")),
            "array_handle": _first(raw, "array_handle"), "source": source}
def _reported_memory_slot_count(arrays: list[dict[str, Any]]) -> int:
    totals: dict[str, int] = {}
    for array in arrays:
        count = int(_number(array.get("memory_devices_reported")) or 0)
        if count <= 0:
            continue
        source = str(array.get("source") or "unknown").lower()
        if "win32" in source or "cim/wmi" in source:
            group = "windows-cim"
        elif "smbios" in source:
            group = "smbios"
        elif "dmidecode" in source:
            group = "dmidecode"
        else:
            group = source
        totals[group] = totals.get(group, 0) + count
    return max(totals.values(), default=0)
def _merge_memory_devices(smbios_devices: list[dict[str, Any]], native_devices: list[dict[str, Any]],
                          arrays: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    result: list[dict[str, Any]] = []
    slot_index: dict[str, list[int]] = {}
    for raw in smbios_devices:
        item = _normalize_memory_device(raw, str(raw.get("source") or "SMBIOS Type 17"))
        key = str(item.get("locator") or item.get("bank_locator") or f"smbios-slot-{len(result)+1}").strip().lower()
        item["sources"] = [item["source"]]
        slot_index.setdefault(key, []).append(len(result))
        result.append(item)
    consumed: set[int] = set()
    for raw in native_devices:
        item = _normalize_memory_device(raw, str(raw.get("source") or "OS physical-memory provider"))
        key = str(item.get("locator") or item.get("bank_locator") or "").strip().lower()
        candidates_by_locator = slot_index.get(key, []) if key else []
        idx = candidates_by_locator[0] if len(candidates_by_locator) == 1 and candidates_by_locator[0] not in consumed else None
        if idx is None and item.get("size_bytes") is not None:
            part = str(item.get("part_number") or "").strip().lower()
            if part:
                candidate = next((i for i, existing in enumerate(result) if i not in consumed
                                  and existing.get("state") == "installed"
                                  and existing.get("size_bytes") == item.get("size_bytes")
                                  and str(existing.get("part_number") or "").strip().lower() == part), None)
                if candidate is not None:
                    idx = candidate
        if idx is not None:
            current = result[idx]
            consumed.add(idx)
            native_is_populated = item.get("state") == "installed" and int(item.get("size_bytes") or 0) > 0
            stale_empty = current.get("state") == "empty" or current.get("size_bytes") == 0
            if native_is_populated and stale_empty:
                for field, value in current.items():
                    if field not in {"sources", "source"} and value not in (None, "", [], {}):
                        item.setdefault(f"firmware_{field}", value)
                current.update({k: v for k, v in item.items() if v not in (None, "", [], {})})
                current["state"] = "installed"
            else:
                for field, value in item.items():
                    if (value not in (None, "", [], {}) and current.get(field) in (None, "", [], {})) or (field == "state" and current.get("state") == "unknown" and value != "unknown"):
                        current[field] = value
            if item.get("source") not in current["sources"]:
                current["sources"].append(item["source"])
        else:
            item["sources"] = [item["source"]]
            if key:
                slot_index.setdefault(key, []).append(len(result))
            result.append(item)
    reported = _reported_memory_slot_count(arrays)
    if reported > len(result):
        for idx in range(reported - len(result)):
            result.append({"locator": f"Location information was not reported #{len(result)+1}", "bank_locator": None,
                           "state": "not_reported_by_firmware", "size_bytes": None, "memory_type_code": None,
                           "memory_type": "Unknown", "form_factor_code": None, "form_factor": "Unknown",
                           "speed_mts": None, "configured_speed_mts": None, "manufacturer": None,
                           "part_number": None, "serial_number": None, "total_width_bits": None,
                           "data_width_bits": None, "ecc": None, "rank": None, "array_handle": None,
                           "source": "Memory array slot count inference", "sources": ["Memory array slot count inference"],
                           "inferred": True})
    return result, arrays
def _merge_storage_devices(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    def add_unique(target: list, value: Any) -> None:
        if value in (None, "", [], {}):
            return
        if value not in target:
            target.append(value)
    def path_values(record: dict[str, Any]) -> list[str]:
        values = []
        for field in ("device_path", "device_id"):
            value = record.get(field)
            if isinstance(value, str) and value.strip() and not value.strip().isdigit():
                add_unique(values, value.strip())
        for field in ("device_paths",):
            for value in record.get(field, []) if isinstance(record.get(field), (list, tuple, set)) else []:
                if isinstance(value, str) and value.strip():
                    add_unique(values, value.strip())
        return values
    def pnp_values(record: dict[str, Any]) -> list[str]:
        values = []
        add_unique(values, record.get("pnp_device_id"))
        for value in record.get("pnp_device_ids", []) if isinstance(record.get("pnp_device_ids"), (list, tuple, set)) else []:
            add_unique(values, value)
        return [str(value).strip() for value in values if str(value).strip()]

    def model_values(record: dict[str, Any]) -> set[str]:
        values = set()
        for field in ("model", "name", "friendly_name", "FriendlyName", "model_aliases"):
            raw_values = record.get(field, []) if field == "model_aliases" else [record.get(field)]
            if not isinstance(raw_values, (list, tuple, set)):
                raw_values = [raw_values]
            values.update(_storage_identity_key(value) for value in raw_values if value)
        values.discard("")
        return values
    def values_for_group(record: dict[str, Any], field: str, plural: str) -> set[str]:
        values = set()
        if record.get(field):
            values.add(_storage_identity_key(record[field]))
        items = record.get(plural, [])
        if isinstance(items, (list, tuple, set)):
            values.update(_storage_identity_key(value) for value in items if value)
        values.discard("")
        return values
    def match_score(left: dict[str, Any], right: dict[str, Any]) -> int:
        left_serial = _storage_serial_key(left.get("serial_number"))
        right_serial = _storage_serial_key(right.get("serial_number"))
        left_size = _number(left.get("size_bytes"))
        right_size = _number(right.get("size_bytes"))
        capacity_ok = _storage_capacity_compatible(left_size, right_size)
        if not capacity_ok:
            return 0
        if left_serial and right_serial and left_serial != right_serial:
            return 0
        left_indices = _storage_disk_indices(left)
        right_indices = _storage_disk_indices(right)
        if left_indices and right_indices and left_indices.isdisjoint(right_indices):
            return 0
        if left_serial and left_serial == right_serial:
            return 120
        left_wwn = values_for_group(left, "wwn", "wwns")
        right_wwn = values_for_group(right, "wwn", "wwns")
        if left_wwn & right_wwn:
            return 115
        left_pnp = {_storage_identity_key(value) for value in pnp_values(left)}
        right_pnp = {_storage_identity_key(value) for value in pnp_values(right)}
        if left_pnp & right_pnp:
            return 110
        left_paths = path_values(left)
        right_paths = path_values(right)
        if any(_storage_path_equivalent(a, b) for a in left_paths for b in right_paths):
            return 105
        if left_indices and right_indices and not left_indices.isdisjoint(right_indices):
            return 100
        left_models = model_values(left)
        right_models = model_values(right)
        if left_models & right_models and left_size is not None and right_size is not None and capacity_ok:
            return 40
        return 0
    for raw_record in records:
        if not isinstance(raw_record, dict):
            continue
        item = dict(raw_record)
        candidates = [(match_score(current, item), index) for index, current in enumerate(merged)]
        strong = [(score, index) for score, index in candidates if score >= 100]
        if strong:
            best_score = max(score for score, _ in strong)
            best = [index for score, index in strong if score == best_score]
            match_index = best[0] if len(best) == 1 else None
        else:
            incoming_source = item.get("source")
            fuzzy = [index for score, index in candidates
                     if score == 40 and incoming_source not in (merged[index].get("sources") or [merged[index].get("source")])]
            match_index = fuzzy[0] if len(fuzzy) == 1 else None
        if match_index is None:
            item["sources"] = list(item.get("sources") or ([item["source"]] if item.get("source") else []))
            item["device_paths"] = path_values(item)
            item["pnp_device_ids"] = pnp_values(item)
            item["model_aliases"] = sorted(model_values(item))
            item["device_indices"] = sorted(_storage_disk_indices(item))
            item["capacity_observations"] = ([{"source": item.get("source"), "size_bytes": int(_number(item.get("size_bytes")))}]
                                             if _number(item.get("size_bytes")) else [])
            merged.append(item)
            continue
        current = merged[match_index]
        current_sources = current.setdefault("sources", [current.get("source")] if current.get("source") else [])
        source_name = item.get("source")
        add_unique(current_sources, source_name)
        for field in ("device_paths",):
            aliases = current.setdefault(field, [])
            for value in path_values(item):
                add_unique(aliases, value)
        aliases = current.setdefault("pnp_device_ids", [])
        for value in pnp_values(item):
            add_unique(aliases, value)
        model_aliases = current.setdefault("model_aliases", [])
        for value in model_values(item):
            add_unique(model_aliases, value)
        ids = current.setdefault("device_ids", [])
        for value in (item.get("device_id"), *(item.get("device_ids", []) if isinstance(item.get("device_ids"), list) else [])):
            add_unique(ids, value)
        indices = current.setdefault("device_indices", [])
        for value in _storage_disk_indices(item):
            add_unique(indices, value)
        capacities = current.setdefault("capacity_observations", [])
        item_size = _number(item.get("size_bytes"))
        if item_size is not None:
            observation = {"source": source_name, "size_bytes": int(item_size)}
            if observation not in capacities:
                capacities.append(observation)
            current_size = _number(current.get("size_bytes"))
            if current_size is None or item_size > current_size:
                current["size_bytes"] = int(item_size)
        for field, value in item.items():
            if field in {"sources", "device_paths", "pnp_device_ids", "model_aliases", "device_ids", "device_indices", "capacity_observations"}:
                continue
            if value in (None, "", [], {}):
                continue
            if current.get(field) in (None, "", [], {}):
                current[field] = value
        aliases = current.get("device_paths", [])
        physical_path = next((path for path in aliases
                              if re.search(r"physicaldrive\d+$", str(path), re.I)), None)
        if physical_path:
            current["device_path"] = physical_path
            current["device_id"] = physical_path
        current_kind = str(current.get("kind") or "")
        incoming_kind = str(item.get("kind") or "")
        def kind_rank(value: str) -> int:
            lower = value.casefold()
            if "nvme" in lower: return 90
            if "emmc" in lower or "mmc/sd" in lower: return 85
            if "optik" in lower: return 80
            if 'virtual/mapped' in lower: return 80
            if "ssd" in lower or "flash" in lower: return 70
            if "hdd" in lower: return 70
            if "usb/harici" in lower or "harici depolama" in lower: return 60
            if "sas/scsi" in lower or "fibre channel" in lower: return 35
            if any(token in lower for token in ("unknown", "unknown", "media type not reported")): return 0
            return 20 if value else 0
        if kind_rank(incoming_kind) > kind_rank(current_kind):
            current["kind"] = incoming_kind
        if item.get("media_type") and (not current.get("media_type") or current.get("media_type") == "Unknown"):
            current["media_type"] = item["media_type"]
        if item.get("firmware") and not current.get("firmware"):
            current["firmware"] = item["firmware"]
    serial_counts: dict[str, int] = {}
    for item in merged:
        serial = _storage_serial_key(item.get("serial_number"))
        if serial:
            serial_counts[serial] = serial_counts.get(serial, 0) + 1
    identity_candidates: list[tuple[dict[str, Any], str, str]] = []
    identity_counts: dict[str, int] = {}
    for item in merged:
        serial = _storage_serial_key(item.get("serial_number"))
        model = _storage_identity_key(item.get("model") or item.get("name"))
        wwn = values_for_group(item, "wwn", "wwns")
        pnp = {_storage_identity_key(value) for value in pnp_values(item)}
        paths = path_values(item)
        if serial and serial_counts.get(serial) == 1:
            identity = f"serial|{serial}"
            identity_method = "serial_number"
        elif wwn:
            identity = "wwn|" + sorted(wwn)[0]
            identity_method = "wwn"
        elif pnp:
            identity = "pnp|" + sorted(pnp)[0]
            identity_method = "pnp_device_id"
        elif paths:
            identity = "path|" + _storage_identity_key(paths[0])
            identity_method = "device_path"
        else:
            identity = "model-capacity-index|{}|{}|{}".format(
                model, int(_number(item.get("size_bytes")) or 0),
                ",".join(str(value) for value in sorted(_storage_disk_indices(item))))
            identity_method = "model_capacity_index_fallback"
        identity_candidates.append((item, identity, identity_method))
        identity_counts[identity] = identity_counts.get(identity, 0) + 1

    for item, identity, identity_method in identity_candidates:
        if identity_counts[identity] > 1:
            item["physical_device_id"] = None
            item["physical_identity_method"] = "ambiguous_identity"
            continue
        item["physical_device_id"] = "disk-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]
        item["physical_identity_method"] = identity_method
    return merged
def _windows_inventory(native: dict[str, Any], smbios: dict[str, Any], existing_cpu: dict[str, Any] | None,
                       existing_gpu: dict[str, Any] | None, existing_storage: dict[str, Any] | None,
                       probe_smart: bool = False) -> dict[str, Any]:
    native = native if isinstance(native, dict) else {}
    smbios = smbios if isinstance(smbios, dict) else {}
    windows_smbios = native.get("smbios_inventory") or {}
    processors_raw = _records(_first(native, "processors", "Processors"))
    processors = [_normalize_cpu(r, platform.machine(), "Win32_Processor") for r in processors_raw]
    if not processors and isinstance(existing_cpu, dict):
        source_cpu = {"Name": existing_cpu.get("name"), "Manufacturer": existing_cpu.get("vendor"),
                      "Architecture": platform.machine(), "NumberOfCores": dig_value(existing_cpu, "topology.physical_cores"),
                      "NumberOfLogicalProcessors": dig_value(existing_cpu, "topology.logical"),
                      "MaxClockSpeed": existing_cpu.get("reg_mhz")}
        processors = [_normalize_cpu(source_cpu, platform.machine(), "existing CPU collector")]
    memory_arrays = []
    for raw in _records(_first(native, "memory_arrays", "MemoryArrays")):
        max_cap_bytes = _first(raw, "MaxCapacity", "max_capacity")
        max_cap_ex_kib = _first(raw, "MaxCapacityEx", "max_capacity_ex")
        capacity = _bytes_from_wmi_size(max_cap_bytes, max_cap_ex_kib)
        memory_arrays.append({"location": _clean_text(_first(raw, "Location", "location")),
            "use": _first(raw, "Use", "use"), "error_correction": _first(raw, "MemoryErrorCorrection", "error_correction"),
            "max_capacity_bytes": capacity, "memory_devices_reported": int(_number(_first(raw, "MemoryDevices", "memory_devices_reported")) or 0),
            "handle": _first(raw, "Tag", "tag"), "source": "Win32_PhysicalMemoryArray"})
    smbi_arrays = windows_smbios.get("memory_arrays") or smbios.get("memory_arrays") or []
    if smbi_arrays:
        memory_arrays.extend(dict(raw) for raw in smbi_arrays if isinstance(raw, dict))
    native_modules = []
    for raw in _records(_first(native, "memory_modules", "physical_memory", "PhysicalMemory")):
        item = dict(raw)
        if "Capacity" in item and "size_bytes" not in item:
            item["size_bytes"] = _number(item.get("Capacity"))
        smbios_memory_code = _number(item.get("SMBIOSMemoryType"))
        legacy_wmi_memory_code = _number(item.get("MemoryType"))
        item["memory_type_code"] = int(smbios_memory_code) if smbios_memory_code is not None else None
        item["wmi_memory_type_code"] = int(legacy_wmi_memory_code) if legacy_wmi_memory_code is not None else None
        if smbios_memory_code is None and legacy_wmi_memory_code is not None:
            item["memory_type"] = WMI_MEMORY_TYPES.get(
                int(legacy_wmi_memory_code), f"Bilinmeyen WMI RAM tipi (kod {int(legacy_wmi_memory_code)})")
        item["form_factor_code"] = _first(item, "FormFactor")
        wmi_form = _number(item.get("FormFactor"))
        if wmi_form is not None:
            item["form_factor"] = WMI_MEMORY_FORM_FACTORS.get(int(wmi_form), f"Unknown WMI RAM form factor ({int(wmi_form)})")
        item["source"] = "Win32_PhysicalMemory"
        native_modules.append(item)
    memory_devices_smbios = windows_smbios.get("memory_devices") or smbios.get("memory_devices") or []
    if not memory_devices_smbios:
        for raw in smbios.get("dimms", []) if isinstance(smbios.get("dimms"), list) else []:
            item = dict(raw)
            item.update({"locator": raw.get("slot"), "bank_locator": raw.get("bank"),
                         "state": "empty" if raw.get("empty") else "installed", "source": "decoded SMBIOS"})
            memory_devices_smbios = list(memory_devices_smbios) + [item]
    memory_slots, memory_arrays = _merge_memory_devices(memory_devices_smbios, native_modules, memory_arrays)
    gpu_records = []
    for gpu in (existing_gpu or {}).get("gpus", []) if isinstance(existing_gpu, dict) else []:
        gpu_source = _clean_text(gpu.get("source")) or "DXGI"
        gpu_records.append(_normalize_gpu(gpu, gpu_source))
    for gpu in _records(_first(native, "displays", "video_controllers", "VideoControllers")):
        gpu_records.append(_normalize_gpu(gpu, "Win32_VideoController"))
    for gpu in _records(_first(native, "pnp_display_devices", "display_devices")):
        gpu_records.append(_normalize_gpu(gpu, "Windows PnP Display"))
    for gpu in _records(windows_smbios.get("gpus", [])):
        gpu_records.append(_normalize_gpu(gpu, "SMBIOS onboard graphics"))
    gpu_records = _merge_gpus(gpu_records)
    storage_devices: list[dict[str, Any]] = []
    seen_storage: set[tuple[Any, ...]] = set()
    for raw in _records(_first(native, "disk_drives", "physical_drives", "DiskDrives")):
        name = _clean_text(_first(raw, "Model", "FriendlyName", "Name", "DeviceID")) or "Unknown disk"
        size = _number(_first(raw, "Size", "size_bytes", "Capacity"))
        pnp = _clean_text(_first(raw, "PNPDeviceID", "pnp_device_id"))
        serial = _clean_text(_first(raw, "SerialNumber", "serial_number"))
        bus = _clean_text(_first(raw, "InterfaceType", "BusType", "bus", "MediaType"))
        kind = classify_storage_kind(name=name, model=name, bus=bus, rotational=_first(raw, "Rotational", "SpindleSpeed"), device_type=_first(raw, "MediaType"))
        device_id = _clean_text(_first(raw, "DeviceID", "DeviceId"))
        record = {"name": name, "model": name, "index": _number(_first(raw, "Index", "index")),
                  "device_id": device_id, "device_path": device_id,
                  "pnp_device_id": pnp, "serial_number": serial, "firmware": _clean_text(_first(raw, "FirmwareRevision", "Firmware")),
                  "size_bytes": int(size) if size is not None and size > 0 else None, "bus": bus, "kind": kind,
                  "media_type": _clean_text(_first(raw, "MediaType")), "rotational": _first(raw, "Rotational"),
                  "status": _clean_text(_first(raw, "Status", "HealthStatus")), "source": "Win32_DiskDrive"}
        key = (pnp.lower() if pnp else None, serial.lower() if serial else None, name.lower(), record["size_bytes"])
        if key not in seen_storage:
            seen_storage.add(key)
            storage_devices.append(record)
    for raw in _records(_first(native, "physical_disks", "disks", "PhysicalDisks")):
        name = _clean_text(_first(raw, "FriendlyName", "Name")) or "Unknown physical disk"
        size = _number(_first(raw, "Size", "size_bytes"))
        serial = _clean_text(_first(raw, "SerialNumber", "serial_number"))
        bus = _clean_text(_first(raw, "BusType", "bus"))
        media = _clean_text(_first(raw, "MediaType", "media_type"))
        kind = classify_storage_kind(name=name, model=name, bus=bus, transport=bus,
                                     rotational=_first(raw, "SpindleSpeed"), device_type=media)
        record = {"name": name, "model": name, "serial_number": serial,
                  "device_id": _clean_text(_first(raw, "DeviceId", "id")),
                  "firmware": _clean_text(_first(raw, "FirmwareVersion", "Firmware")),
                  "size_bytes": int(size) if size is not None and size > 0 else None, "bus": bus,
                  "kind": kind, "media_type": media, "status": _clean_text(_first(raw, "HealthStatus", "OperationalStatus")),
                  "source": "Get-PhysicalDisk"}
        key = (str(record.get("device_id") or "").lower(), serial.lower() if serial else None, name.lower(), record["size_bytes"])
        if key not in seen_storage:
            seen_storage.add(key)
            storage_devices.append(record)
    for raw in _records(_first(native, "storage_disks", "managed_disks", "GetDisk")):
        name = _clean_text(_first(raw, "FriendlyName", "Name")) or "Windows managed disk"
        size = _number(_first(raw, "Size", "size_bytes"))
        serial = _clean_text(_first(raw, "SerialNumber", "serial_number"))
        bus = _clean_text(_first(raw, "BusType", "bus"))
        number = _number(_first(raw, "Number", "DiskNumber", "index"))
        device_id = _clean_text(_first(raw, "UniqueId", "Path", "DeviceId")) or (f"\\\\.\\PhysicalDrive{int(number)}" if number is not None else None)
        kind = classify_storage_kind(name=name, model=name, bus=bus,
                                     is_virtual=str(_first(raw, "BusType", default="")).lower() in {"spaces", "virtual"})
        storage_devices.append({"name": name, "model": name, "index": number, "device_id": device_id,
            "device_path": _clean_text(_first(raw, "Path", "device_path")), "serial_number": serial,
            "size_bytes": int(size) if size is not None and size > 0 else None, "bus": bus, "kind": kind,
            "partition_style": _clean_text(_first(raw, "PartitionStyle")),
            "number_of_partitions": _number(_first(raw, "NumberOfPartitions")),
            "boot_disk": _first(raw, "IsBoot"), "system_disk": _first(raw, "IsSystem"),
            "offline": _first(raw, "IsOffline"), "read_only": _first(raw, "IsReadOnly"),
            "status": _clean_text(_first(raw, "OperationalStatus", "HealthStatus")), "source": "Get-Disk"})
    virtual_disks = []
    for raw in _records(_first(native, "virtual_disks", "storage_virtual_disks")):
        name = _clean_text(_first(raw, "FriendlyName", "Name")) or "Windows virtual disk"
        size = _number(_first(raw, "Size", "size_bytes"))
        virtual_disks.append({"name": name, "model": name,
            "device_id": _clean_text(_first(raw, "UniqueId", "Id")),
            "size_bytes": int(size) if size is not None and size > 0 else None,
            "kind": 'Virtual/mapped storage', "virtual": True,
            "resiliency": _clean_text(_first(raw, "ResiliencySettingName")),
            "footprint_bytes": _number(_first(raw, "FootprintOnPool")),
            "columns": _number(_first(raw, "NumberOfColumns")),
            "data_copies": _number(_first(raw, "NumberOfDataCopies")),
            "status": _clean_text(_first(raw, "OperationalStatus", "HealthStatus")),
            "source": "Get-VirtualDisk"})
    storage_pools = []
    for raw in _records(_first(native, "storage_pools", "pools")):
        storage_pools.append({"name": _clean_text(_first(raw, "FriendlyName", "Name")) or "Windows storage pool",
            "pool_id": _clean_text(_first(raw, "UniqueId", "Id")),
            "primordial": _first(raw, "IsPrimordial"), "size_bytes": _number(_first(raw, "Size")),
            "allocated_bytes": _number(_first(raw, "AllocatedSize")),
            "physical_disk_count": _number(_first(raw, "NumberOfPhysicalDisks")),
            "status": _clean_text(_first(raw, "OperationalStatus", "HealthStatus")), "source": "Get-StoragePool"})
    storage_devices.extend(virtual_disks)
    for raw in _records(_first(native, "optical_drives", "cdroms", "CDROMDrives")):
        name = _clean_text(_first(raw, "Name", "Caption", "Drive")) or "Optical drive"
        storage_devices.append({"name": name, "model": name, "kind": 'Optical drive', "bus": _first(raw, "InterfaceType"),
                                "device_id": _first(raw, "DeviceID"), "size_bytes": None, "source": "Win32_CDROMDrive"})
    partition_records: list[dict[str, Any]] = []
    partition_by_letter: dict[str, dict[str, Any]] = {}
    for raw in _records(_first(native, "partitions", "Partitions")):
        letter = _clean_text(_first(raw, "DriveLetter", "drive_letter"))
        letter_key = (letter or "").rstrip(":\\").upper()
        partition = {"disk_number": _number(_first(raw, "DiskNumber", "disk_number")),
            "partition_number": _number(_first(raw, "PartitionNumber", "partition_number")),
            "drive_letter": letter_key or None, "size_bytes": _number(_first(raw, "Size", "size_bytes")),
            "partition_type": _clean_text(_first(raw, "Type", "GptType", "partition_type")),
            "gpt_type": _clean_text(_first(raw, "GptType", "gpt_type")),
            "guid": _clean_text(_first(raw, "Guid", "guid")),
            "access_paths": _first(raw, "AccessPaths", "access_paths", default=[]),
            "is_boot": _first(raw, "IsBoot", "is_boot"), "is_system": _first(raw, "IsSystem", "is_system"),
            "source": "Get-Partition"}
        partition_records.append(partition)
        if letter_key:
            partition_by_letter[letter_key] = partition

    for disk in (existing_storage or {}).get("disks", []) if isinstance(existing_storage, dict) else []:
        name = disk.get("name") or "Unknown disk"
        if any(str(x.get("name", "")).lower() == str(name).lower() for x in storage_devices):
            continue
        size = _number(disk.get("size"))
        storage_devices.append({"name": name, "model": name, "kind": disk.get("kind") or 'Unknown storage type',
                                "bus": disk.get("bus"), "serial_number": disk.get("serial"),
                                "size_bytes": int(size) if size else None, "status": disk.get("health"),
                                "source": "Get-PhysicalDisk (existing collector)"})
    storage_devices = _merge_storage_devices(storage_devices)
    smart_results: list[dict[str, Any]] = []
    smart_status = "not requested"
    if probe_smart:
        smart_results, smart_status = _probe_storage_health(storage_devices)
        _attach_smart_data(storage_devices, smart_results)
    baseboards = _records(_first(native, "baseboards", "baseboard", "BaseBoards")) or _records(smbios.get("baseboards"))
    motherboard = dict(baseboards[0]) if baseboards else dict(smbios.get("board") or {})
    bios_records = _records(_first(native, "bios", "BIOS"))
    bios = dict(bios_records[0]) if bios_records else dict(smbios.get("bios") or {})
    if not motherboard.get("manufacturer"):
        motherboard["manufacturer"] = _first(motherboard, "Manufacturer", "manufacturer")
    if not motherboard.get("product"):
        motherboard["product"] = _first(motherboard, "Product", "product")
    system_slots = _records(windows_smbios.get("system_slots") or smbios.get("system_slots"))
    system_slots += [{"name": _first(x, "SlotDesignation", "Name"), "usage": _first(x, "CurrentUsage", "usage"),
                      "slot_type": _first(x, "SlotType", "slot_type"), "source": "Win32_SystemSlot"}
                     for x in _records(_first(native, "system_slots", "SystemSlots"))]
    onboard = _records(windows_smbios.get("onboard_devices") or smbios.get("onboard_devices"))
    controllers = []
    for item in _records(_first(native, "controllers", "storage_controllers", "Controllers")):
        controllers.append({"name": _clean_text(_first(item, "FriendlyName", "Name", "Caption", "DeviceName")) or "Unknown controller",
                            "manufacturer": _clean_text(_first(item, "Manufacturer")),
                            "device_id": _clean_text(_first(item, "PNPDeviceID", "DeviceID")),
                            "class": _clean_text(_first(item, "PNPClass", "DeviceClass", "Class")),
                            "status": _clean_text(_first(item, "Status")), "source": "Windows CIM/PnP"})
    disk_by_number: dict[int, dict[str, Any]] = {}
    for disk in storage_devices:
        idx = _number(disk.get("index"))
        if idx is None:
            match_id = re.search(r"physicaldrive(\d+)$", str(disk.get("device_id") or ""), re.I)
            idx = int(match_id.group(1)) if match_id else _number(disk.get("device_id"))
        if idx is not None:
            disk_by_number[int(idx)] = disk
    volume_records: list[dict[str, Any]] = []
    seen_volumes: set[str] = set()
    for raw in _records(_first(native, "volumes", "Volumes")):
        letter = _clean_text(_first(raw, "DriveLetter", "drive_letter"))
        letter_key = (letter or "").rstrip(":\\").upper()
        path = _clean_text(_first(raw, "Path", "UniqueId", "VolumePath", "path"))
        mount = f"{letter_key}:\\" if letter_key else path
        identity = (mount or path or str(_first(raw, "FileSystemLabel", "label", default="unknown"))).lower()
        if identity in seen_volumes:
            continue
        seen_volumes.add(identity)
        partition = partition_by_letter.get(letter_key or "")
        disk_number = _number((partition or {}).get("disk_number")) if partition else None
        parent_disk = disk_by_number.get(int(disk_number)) if disk_number is not None else None
        volume_records.append({"mount": mount, "device": parent_disk.get("name") if parent_disk else (f"disk {disk_number}" if disk_number is not None else path),
            "disk_number": int(disk_number) if disk_number is not None else None,
            "partition_number": (partition or {}).get("partition_number"),
            "drive_letter": letter_key or None, "label": _clean_text(_first(raw, "FileSystemLabel", "label")),
            "filesystem": _clean_text(_first(raw, "FileSystem", "FileSystemType", "filesystem")),
            "size_bytes": _number(_first(raw, "Size", "size_bytes")),
            "free_bytes": _number(_first(raw, "SizeRemaining", "free_bytes")),
            "status": _clean_text(_first(raw, "HealthStatus", "OperationalStatus", "status")),
            "volume_id": path, "source": "Get-Volume"})
    for raw in _records((existing_storage or {}).get("volumes") if isinstance(existing_storage, dict) else []):
        mount = _clean_text(_first(raw, "mount", "mountpoint"))
        identity = (mount or "").lower()
        if identity and identity not in seen_volumes:
            volume_records.append({"mount": mount, "device": _clean_text(_first(raw, "device", "device_path")),
                "size_bytes": _number(_first(raw, "total", "size_bytes")), "free_bytes": _number(_first(raw, "free", "free_bytes")),
                "filesystem": _clean_text(_first(raw, "fs", "filesystem")), "source": "psutil mounted filesystem"})
            seen_volumes.add(identity)
    slots_count = _reported_memory_slot_count(memory_arrays)
    if not slots_count:
        slots_count = len(memory_slots) if memory_slots else None
    memory = _memory_summary(memory_slots, memory_arrays, slots_count, _number(_first(native.get("computer") or {}, "TotalPhysicalMemory")))
    smart_summary = {
        "source": "smartctl", "source_type": "SMART", "status": smart_status,
        "device_count": len(smart_results), "devices": smart_results,
        "matched_device_count": sum(1 for item in smart_results if item.get("matched_physical_device_id") or item.get("matched_device_path")),
        "unmatched_device_count": sum(1 for item in smart_results if item.get("query_status") == "not_matched"),
        "successful_device_count": sum(1 for item in smart_results if item.get("query_status") == "success"),
        "unsupported_device_count": sum(1 for item in smart_results if item.get("query_status") == "unsupported"),
        "failed_device_count": sum(1 for item in smart_results if item.get("query_status") == "failed"),
        "read_only": True,
    }
    return {"motherboard": {**motherboard, "bios": bios, "system": smbios.get("system") or {}, "chassis": smbios.get("chassis") or {}},
            "cpu": _cpu_summary(processors, existing_cpu), "gpu": {"adapters": gpu_records, "onboard_devices": onboard},
            "memory": memory, "storage": {"devices": sorted(storage_devices, key=lambda x: str(x.get("name"))),
                                               "controllers": controllers, "volumes": volume_records,
                                               "partitions": partition_records, "pools": storage_pools,
                                               "smartctl": smart_summary},
            "sources": [{"name": "Windows CIM/WMI", "status": "available" if native else "unavailable",
                         "detail": "Win32_Processor, Win32_PhysicalMemory, Win32_PhysicalMemoryArray, Win32_VideoController, Win32_DiskDrive, Win32_BaseBoard" if native else 'PowerShell/CIM inventory could not be collected'}]}
def dig_value(data: dict[str, Any], path: str) -> Any:
    value: Any = data
    for key in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value
def _cpu_summary(processors: list[dict[str, Any]], existing_cpu: dict[str, Any] | None) -> dict[str, Any]:
    existing_cpu = existing_cpu or {}
    arch = (processors[0].get("architecture") if processors and processors[0].get("architecture")
            else canonical_architecture(platform.machine()))
    logical = dig_value(existing_cpu, "topology.logical")
    cores = dig_value(existing_cpu, "topology.physical_cores")
    if not logical:
        logical = sum(int(x.get("logical_processors") or 0) for x in processors) or (os.cpu_count() or 0) or None
    if not cores:
        cores = sum(int(x.get("cores") or 0) for x in processors) or None
    vendor = processors[0].get("vendor") if processors else _clean_text(existing_cpu.get("vendor"))
    name = processors[0].get("name") if processors else _clean_text(existing_cpu.get("name"))
    isa = existing_cpu.get("isa") or {}
    if isinstance(isa, dict) and isinstance(isa.get("present"), list):
        flags = set(str(x) for x in isa["present"])
    elif isinstance(isa, dict):
        flags = {str(k) for k, value in isa.items() if value is True}
    else:
        flags = set()
    for proc in processors:
        flags.update(proc.get("feature_flags") or [])
    return {"architecture": arch, "vendor": vendor, "name": name, "processors": processors,
            "physical_cores": cores, "logical_processors": logical,
            "processor_count": len(processors) or None,
            "feature_flags": sorted(flags),
            "topology_source": dig_value(existing_cpu, "topology_source") or (processors[0].get("source") if processors else "runtime fallback")}
def _memory_summary(slots: list[dict[str, Any]], arrays: list[dict[str, Any]], slot_count: int | None,
                    total_physical_bytes: int | float | None = None) -> dict[str, Any]:
    installed = [x for x in slots if x.get("state") == "installed" and (x.get("size_bytes") or 0) > 0]
    empty = [x for x in slots if x.get("state") == "empty"]
    installed_bytes = sum(int(x.get("size_bytes") or 0) for x in installed)
    known_types = sorted({str(x.get("memory_type")) for x in installed if x.get("memory_type") and x.get("memory_type") != "Unknown"})
    return {"arrays": arrays, "slots": slots, "modules_installed": installed,
            "reported_slot_count": slot_count, "enumerated_slot_records": len(slots),
            "populated_slot_count": len(installed), "empty_slot_count": len(empty),
            "unlocated_slot_count": sum(1 for x in slots if x.get("inferred")),
            "installed_bytes_from_modules": installed_bytes or None,
            "os_total_physical_bytes": int(total_physical_bytes) if total_physical_bytes else None,
            "memory_types_seen": known_types,
            "max_capacity_bytes": max((int(a.get("max_capacity_bytes") or 0) for a in arrays), default=0) or None,
            "slot_count_confidence": "firmware per-slot records" if slots and not any(x.get("inferred") for x in slots) else
                                     "array count with inferred unknown locations" if slot_count else "not reported",
            "note": 'RAM slot and maximum-capacity information depends on firmware/SMBIOS vendor data; platforms with soldered or unified memory may not expose physical slot counts.'}
def _parse_lscpu(value: Any) -> dict[str, Any]:
    parsed = {}
    rows = value.get("lscpu") if isinstance(value, dict) else None
    if not isinstance(rows, list):
        return parsed
    for item in rows:
        if isinstance(item, dict) and item.get("field"):
            parsed[str(item["field"]).rstrip(":")] = item.get("data")
    return parsed
def _read_proc_cpuinfo() -> tuple[dict[str, str], list[str]]:
    try:
        text = Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}, []
    first: dict[str, str] = {}
    flags: set[str] = set()
    for line in text.splitlines():
        if not line.strip():
            continue
        if ":" not in line:
            continue
        key, value = [p.strip() for p in line.split(":", 1)]
        first.setdefault(key.lower(), value)
        if key.lower() in {"flags", "features"}:
            flags.update(value.split())
    return first, sorted(flags)
def _linux_pci_devices(sources: list[dict[str, Any]], root: Path | str = "/sys/bus/pci/devices") -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    gpus: list[dict[str, Any]] = []
    controllers: list[dict[str, Any]] = []
    root = Path(root)
    if root.is_dir():
        for device_path in sorted(root.iterdir()):
            try:
                cls_text = (device_path / "class").read_text().strip()
                vendor_id = int((device_path / "vendor").read_text().strip(), 16)
                device_id = int((device_path / "device").read_text().strip(), 16)
                cls = int(cls_text, 16)
                driver_link = device_path / "driver"
                driver = driver_link.resolve().name if driver_link.exists() else None
                known_vendor, known_device = pci_display_names(vendor_id, device_id)
                vendor_name = known_vendor or f"PCI vendor 0x{vendor_id:04X}"
                device_name = known_device or f"PCI device 0x{device_id:04X}"
                record = {"name": f"{vendor_name} {device_name}", "vendor_id": vendor_id,
                          "device_id": device_id, "bus": str(device_path.name), "driver_version": driver,
                          "source": "Linux PCI sysfs", "pci_class": f"0x{cls:06X}",
                          "vendor_name": vendor_name, "device_name": device_name,
                          "pci_id_database": "local pci.ids" if known_device else "built-in/fallback"}
                if cls >> 16 == 0x03:
                    record["vendor"] = identify_gpu_vendor(vendor_id, vendor_name, record["name"])
                    record["pnp_device_id"] = device_path.name
                    vram_path = device_path / "mem_info_vram_total"
                    try:
                        record["dedicated_memory_bytes"] = int(vram_path.read_text().strip())
                    except (OSError, ValueError):
                        pass
                    reported_vram = record.get("dedicated_memory_bytes")
                    record["integrated"] = (False if isinstance(reported_vram, int) and reported_vram > 0
                                             else infer_integrated_gpu(record["vendor"], device_name))
                    gpus.append(_normalize_gpu(record, "Linux PCI sysfs"))
                elif cls >> 16 == 0x01:
                    controllers.append({"name": record["name"], "vendor": vendor_name, "device_id": device_path.name,
                                        "class": "Storage controller", "driver": driver, "source": "Linux PCI sysfs"})
            except (OSError, ValueError):
                continue
        _source(sources, "Linux PCI sysfs", "available", count=len(gpus) + len(controllers))
    else:
        lspci = shutil.which("lspci")
        if lspci:
            rc, out, err = _run([lspci, "-Dnnk"], timeout=20)
            if rc == 0:
                current: dict[str, Any] | None = None
                for line in out.splitlines():
                    if line and not line[0].isspace():
                        match = re.match(r"^([0-9a-fA-F:.]+)\s+([^:]+):\s+(.*)$", line)
                        ids = re.search(r"\[([0-9a-fA-F]{4}):([0-9a-fA-F]{4})\]", line)
                        if match:
                            kind = match.group(2).lower()
                            current = {"address": match.group(1), "name": match.group(3), "source": "lspci"}
                            if ids:
                                current["vendor_id"] = int(ids.group(1), 16)
                                current["device_id"] = int(ids.group(2), 16)
                            if any(x in kind for x in ("vga", "3d controller", "display controller")):
                                gpus.append(_normalize_gpu(current, "lspci"))
                            elif "storage" in kind or "non-volatile memory" in kind or "sata" in kind:
                                controllers.append({"name": current["name"], "class": match.group(2), "device_id": current.get("address"),
                                                    "source": "lspci"})
                        else:
                            current = None
                    elif current and "Kernel driver in use:" in line:
                        current["driver_version"] = line.split(":", 1)[1].strip()
                _source(sources, "lspci", "available", count=len(gpus) + len(controllers))
            else:
                _source(sources, "lspci", "failed", err)
        else:
            _source(sources, "PCI inventory", "unavailable", 'sysfs and lspci are not available')
    return gpus, controllers
def _parse_dmidecode(text: str) -> dict[str, Any]:
    result: dict[str, Any] = {"baseboards": [], "memory_arrays": [], "memory_devices": [], "system_slots": [], "onboard_devices": []}
    current_title: str | None = None
    current: dict[str, str] = {}
    blocks: list[tuple[str, dict[str, str]]] = []
    section_titles = {
        "Base Board Information", "Physical Memory Array", "Memory Device",
        "System Slot", "On Board Device Information",
    }
    for line in text.splitlines():
        title = line.strip()
        if line and not line[0].isspace() and title in section_titles:
            if current_title:
                blocks.append((current_title, current))
            current_title, current = title, {}
            continue
        if ":" in line and current_title:
            key, value = line.strip().split(":", 1)
            current[key.strip()] = value.strip()
    if current_title:
        blocks.append((current_title, current))
    for title, fields in blocks:
        if title == "Base Board Information":
            result["baseboards"].append({"manufacturer": fields.get("Manufacturer"), "product": fields.get("Product Name"),
                                         "version": fields.get("Version"), "asset_tag": fields.get("Asset Tag"), "source": "dmidecode"})
        elif title == "Physical Memory Array":
            cap = None
            match = re.search(r"([0-9]+)\s*(?:MB|GB|TB|kB|KB)", fields.get("Maximum Capacity", ""), re.I)
            if match:
                value = int(match.group(1)); unit = fields["Maximum Capacity"].lower()
                cap = value * (1024**3 if "gb" in unit else 1024**4 if "tb" in unit else 1024 if "kb" in unit else 1024**2)
            result["memory_arrays"].append({"location": fields.get("Location"), "use": fields.get("Use"),
                "error_correction": fields.get("Error Correction Type"), "max_capacity_bytes": cap,
                "memory_devices_reported": _number(fields.get("Number Of Devices")), "source": "dmidecode Physical Memory Array"})
        elif title == "Memory Device":
            size_text = fields.get("Size", "Unknown")
            size = 0 if "no module installed" in size_text.lower() else None
            match = re.search(r"([0-9]+)\s*(kB|KB|MB|GB|TB)", size_text, re.I)
            if match:
                value = int(match.group(1)); unit = match.group(2).lower()
                size = value * (1024 if unit == "kb" else 1024**2 if unit == "mb" else 1024**3 if unit == "gb" else 1024**4)
            type_text = fields.get("Type", "Unknown")
            form_text = fields.get("Form Factor", "Unknown")
            state = "empty" if size == 0 else "installed" if size is not None else "unknown"
            speed = _number(re.search(r"\d+", fields.get("Speed", "")).group(0)) if re.search(r"\d+", fields.get("Speed", "")) else None
            configured_text = fields.get("Configured Memory Speed", fields.get("Configured Clock Speed", ""))
            configured = _number(re.search(r"\d+", configured_text).group(0)) if re.search(r"\d+", configured_text) else None
            result["memory_devices"].append({"locator": fields.get("Locator"), "bank_locator": fields.get("Bank Locator"),
                "state": state, "size_bytes": size, "memory_type": type_text, "form_factor": form_text,
                "speed_mts": speed, "configured_speed_mts": configured, "manufacturer": fields.get("Manufacturer"),
                "part_number": fields.get("Part Number"), "serial_number": fields.get("Serial Number"),
                "total_width_bits": _number(fields.get("Total Width", "").split()[0]) if fields.get("Total Width") else None,
                "data_width_bits": _number(fields.get("Data Width", "").split()[0]) if fields.get("Data Width") else None,
                "ecc": fields.get("Total Width") != fields.get("Data Width"), "source": "dmidecode Memory Device"})
        elif title == "System Slot":
            result["system_slots"].append({"name": fields.get("Designation"), "slot_type": fields.get("Type"),
                "usage": fields.get("Current Usage"), "bus_address": fields.get("Bus Address"), "source": "dmidecode System Slot"})
        elif title == "On Board Device Information":
            result["onboard_devices"].append({"name": fields.get("Type"), "device_type": fields.get("Type"),
                "enabled": fields.get("Status", "").lower() == "enabled", "source": "dmidecode On Board Device"})
    return result
def _linux_drm_devices(existing_gpus: list[dict[str, Any]], sources: list[dict[str, Any]],
                       root: Path | str = "/sys/class/drm") -> list[dict[str, Any]]:
    root = Path(root)
    found: list[dict[str, Any]] = []
    if not root.is_dir():
        _source(sources, "Linux DRM sysfs", "unavailable")
        return found
    seen_paths: set[str] = set()
    for card in sorted(root.glob("card[0-9]*")):
        if not re.fullmatch(r"card\d+", card.name):
            continue
        dev = card / "device"
        if not dev.exists():
            dev = card
        try:
            resolved = str(dev.resolve())
        except OSError:
            resolved = str(dev)
        if resolved in seen_paths:
            continue
        seen_paths.add(resolved)
        if any(token in resolved.lower() for token in ("/pci", "pci0000:")):
            continue
        driver = None
        driver_link = dev / "driver"
        try:
            if driver_link.exists():
                driver = driver_link.resolve().name
        except OSError:
            pass
        compatibles: list[str] = []
        for base in (dev / "of_node" / "compatible", dev / "of_node" / "name"):
            try:
                raw = base.read_bytes().replace(b"\x00", b" ").decode("utf-8", "replace")
                compatibles.extend(x.strip() for x in raw.split() if x.strip())
            except OSError:
                continue
        compatible = " ".join(compatibles)
        identity = f"{compatible} {driver or ''}".lower()
        if any(x in identity for x in ("nvidia", "nouveau")):
            vendor = "NVIDIA"
        elif any(x in identity for x in ("amd", "radeon", "amdgpu")):
            vendor = "AMD/ATI"
        elif any(x in identity for x in ("intel", "i915", "xe-gpu")):
            vendor = "Intel"
        elif any(x in identity for x in ("qcom", "qualcomm", "adreno")):
            vendor = "Qualcomm"
        elif any(x in identity for x in ("arm,mali", "mali", "panfrost", "panthor")):
            vendor = "ARM"
        elif any(x in identity for x in ("apple", "agx")):
            vendor = "Apple"
        elif any(x in identity for x in ("powervr", "img,", "imagination")):
            vendor = "Imagination Technologies"
        elif "vivante" in identity:
            vendor = "Vivante"
        elif "mediatek" in identity or "mtk," in identity:
            vendor = "MediaTek/SoC"
        elif "rockchip" in identity or "rk3" in identity:
            vendor = "Rockchip/SoC"
        else:
            vendor = "Unknown (Linux DRM/SoC)"
        name = compatible or driver or card.name
        if name.startswith("arm,mali"):
            name = "ARM " + name
        record = {"name": name, "vendor_name": vendor, "vendor": vendor, "bus": "Linux DRM/SoC platform",
                  "integrated": True, "virtual": False, "driver_version": driver,
                  "pnp_device_id": resolved, "compatible_raw": compatible or None,
                  "source": "Linux DRM sysfs"}
        found.append(_normalize_gpu(record, "Linux DRM sysfs"))
    if found:
        merged = _merge_gpus(existing_gpus + found)
        _source(sources, "Linux DRM sysfs", "available", 'non-PCI/SoC graphics devices', len(found))
        return merged
    _source(sources, "Linux DRM sysfs", "available", 'no additional non-PCI/SoC GPUs found', 0)
    return existing_gpus
def _collect_linux(sources: list[dict[str, Any]], existing_cpu: dict[str, Any] | None,
                   existing_gpu: dict[str, Any] | None, existing_storage: dict[str, Any] | None,
                   probe_smart: bool) -> dict[str, Any]:
    lscpu_data: dict[str, Any] = {}
    lscpu = shutil.which("lscpu")
    if lscpu:
        raw, err = _cmd_json([lscpu, "-J"], timeout=20)
        if isinstance(raw, dict):
            lscpu_data = _parse_lscpu(raw)
            _source(sources, "lscpu -J", "available", count=len(lscpu_data))
        else:
            _source(sources, "lscpu -J", "failed", err)
    else:
        _source(sources, "lscpu", "unavailable", "util-linux is not installed")
    proc, flags = _read_proc_cpuinfo()
    machine = platform.machine()
    cpu_raw = {"Name": lscpu_data.get("Model name") or lscpu_data.get("Model name:" ) or proc.get("model name") or proc.get("hardware") or platform.processor(),
               "Manufacturer": lscpu_data.get("Vendor ID") or proc.get("vendor_id") or proc.get("cpu implementer"),
               "Architecture": lscpu_data.get("Architecture") or machine,
               "NumberOfCores": lscpu_data.get("Core(s) per socket"),
               "NumberOfLogicalProcessors": lscpu_data.get("CPU(s)") or os.cpu_count(),
               "Socket": lscpu_data.get("Socket(s)"), "MaxClockSpeed": _number(lscpu_data.get("CPU max MHz"))}
    cpu_record = _normalize_cpu(cpu_raw, machine, "Linux lscpu/procfs")
    topology = existing_cpu.get("topology") if isinstance(existing_cpu, dict) else {}
    cpu_record["cores"] = cpu_record.get("cores") or dig_value(topology or {}, "physical_cores")
    cpu_record["logical_processors"] = cpu_record.get("logical_processors") or dig_value(topology or {}, "logical") or os.cpu_count()
    cpu_record["feature_flags"] = flags
    cpu_record["cache_topology"] = dig_value(topology or {}, "cache_summary")
    cpu_record["numa_nodes"] = dig_value(topology or {}, "numa_nodes")
    cpus = [cpu_record]
    if proc:
        _source(sources, "/proc/cpuinfo", "available", count=len(flags))
    else:
        _source(sources, "/proc/cpuinfo", "unavailable")

    gpus, controllers = _linux_pci_devices(sources)
    for g in (existing_gpu or {}).get("gpus", []) if isinstance(existing_gpu, dict) else []:
        gpus.append(_normalize_gpu(g, "existing generic GPU collector"))
    gpus = _merge_gpus(gpus)
    gpus = _linux_drm_devices(gpus, sources)
    storage_devices: list[dict[str, Any]] = []
    partitions: list[dict[str, Any]] = []
    volumes: list[dict[str, Any]] = []
    lsblk = shutil.which("lsblk")
    if lsblk:
        data, err = _cmd_json([lsblk, "-J", "-b", "-O"], timeout=20)
        if isinstance(data, dict):
            def visit(nodes: list[dict[str, Any]], parent: str | None = None) -> None:
                for node in nodes:
                    name = str(node.get("name") or node.get("kname") or "unknown")
                    dtype = str(node.get("type") or "unknown").lower()
                    size = _number(node.get("size"))
                    tran = _clean_text(node.get("tran"))
                    rota_raw = node.get("rota")
                    rotational = _optional_bool(rota_raw)
                    virtual = dtype in {"loop", "zram", "dm", "lvm", "raid", "raid0", "raid1", "raid4", "raid5", "raid6", "raid10", "md", "mpath", "crypt"} or name.startswith(("loop", "zram", "dm-", "md", "mdraid", "mpath"))
                    record = {"name": name, "model": _clean_text(node.get("model")), "vendor": _clean_text(node.get("vendor")),
                        "serial_number": _clean_text(node.get("serial")), "wwn": _clean_text(node.get("wwn")),
                        "firmware": _clean_text(node.get("rev")), "device_path": "/dev/" + name,
                        "parent": parent, "device_type": dtype, "size_bytes": int(size) if size is not None else None,
                        "bus": tran or _clean_text(node.get("subsystems")), "transport": tran, "rotational": rotational,
                        "kind": classify_storage_kind(name=name, model=node.get("model"), bus=node.get("subsystems"),
                            transport=tran, rotational=rotational, device_type=dtype, is_virtual=virtual),
                        "logical_sector_bytes": _number(node.get("log-sec")), "physical_sector_bytes": _number(node.get("phy-sec")),
                        "read_only": _optional_bool(node.get("ro")),
                        "removable": _optional_bool(node.get("rm")),
                        "mountpoints": [m for m in node.get("mountpoints", []) if m] if isinstance(node.get("mountpoints"), list) else [],
                        "source": "lsblk"}
                    if dtype == "part":
                        partitions.append({"name": name, "device_path": "/dev/" + name, "parent_disk": parent,
                            "size_bytes": record["size_bytes"], "partition_type": _clean_text(node.get("parttype")),
                            "partition_label": _clean_text(node.get("partlabel")), "partition_uuid": _clean_text(node.get("partuuid")),
                            "filesystem": _clean_text(node.get("fstype")), "label": _clean_text(node.get("label")),
                            "uuid": _clean_text(node.get("uuid")), "mountpoints": record["mountpoints"],
                            "read_only": record["read_only"], "source": "lsblk"})
                    else:
                        storage_devices.append(record)
                    for mount in record["mountpoints"]:
                        volumes.append({"mount": mount, "device": "/dev/" + name, "size_bytes": record["size_bytes"],
                                        "filesystem": _clean_text(node.get("fstype")), "label": _clean_text(node.get("label")),
                                        "uuid": _clean_text(node.get("uuid")), "source": "lsblk"})
                    visit(node.get("children") or [], name)
            visit(data.get("blockdevices") or [])
            _source(sources, "lsblk -J -b -O", "available", count=len(storage_devices))
        else:
            _source(sources, "lsblk", "failed", err)
    else:
        _source(sources, "lsblk", "unavailable")
    existing_mounts = {str(x.get("mount") or "").lower() for x in volumes}
    if isinstance(existing_storage, dict):
        for part in existing_storage.get("volumes", []):
            mount = _clean_text(part.get("mount"))
            if mount and mount.lower() not in existing_mounts:
                device = part.get("device") or part.get("mount") or "filesystem"
                volumes.append({"mount": mount, "device": device, "size_bytes": part.get("total"),
                    "free_bytes": part.get("free"), "filesystem": part.get("fs"), "source": "psutil mounted filesystem"})
                existing_mounts.add(mount.lower())
    if probe_smart:
        smart, status = _probe_storage_health(storage_devices)
        _attach_smart_data(storage_devices, smart)
        _source(sources, "storage_health", "available" if status == "ok" else "partial/unavailable", f"probe status: {status}", len(smart))
    else:
        _source(sources, "storage_health", "not requested", 'Use --storage-health-probe for an optional read-only SMART query')
    dmidecode = shutil.which("dmidecode")
    smbios = {"baseboards": [], "memory_arrays": [], "memory_devices": [], "system_slots": [], "onboard_devices": []}
    if dmidecode:
        rc, out, err = _run([dmidecode, "--type", "baseboard,memory,slot,onboard"], timeout=25)
        if rc == 0:
            smbios = _parse_dmidecode(out)
            _source(sources, "dmidecode", "available", count=len(smbios.get("memory_devices", [])))
        else:
            _source(sources, "dmidecode", "permission/unavailable", err)
    else:
        _source(sources, "dmidecode", "unavailable", "Memory slot/board detail may require dmidecode and elevated privileges")
    memory_slots, arrays = _merge_memory_devices(smbios.get("memory_devices") or [], [], smbios.get("memory_arrays") or [])
    memory = _memory_summary(memory_slots, arrays, _reported_memory_slot_count(arrays) or (len(memory_slots) or None))
    try:
        meminfo = Path("/proc/meminfo").read_text(encoding="ascii", errors="replace")
        total_kib = next((int(m.group(1)) for line in meminfo.splitlines() if (m := re.match(r"MemTotal:\s+(\d+)", line))), None)
        if total_kib:
            memory["os_total_physical_bytes"] = total_kib * 1024
    except OSError:
        pass
    baseboards = smbios.get("baseboards", [])
    return {"motherboard": {**(baseboards[0] if baseboards else {}), "bios": {}, "system": {}, "chassis": {}},
            "cpu": _cpu_summary(cpus, existing_cpu), "gpu": {"adapters": gpus, "onboard_devices": smbios.get("onboard_devices", [])},
            "memory": memory, "storage": {"devices": storage_devices, "controllers": controllers,
                                               "volumes": volumes, "partitions": partitions, "pools": []},
            "sources": [{"name": "Linux sysfs/procfs", "status": "available"}, {"name": "firmware memory/board inventory", "status": "available" if memory_slots or baseboards else "partial/unavailable"}]}
def _walk_system_profiler(obj: Any, path: tuple[str, ...] = ()) -> Iterable[tuple[tuple[str, ...], dict[str, Any]]]:
    if isinstance(obj, dict):
        yield path, obj
        for key, value in obj.items():
            yield from _walk_system_profiler(value, path + (str(key),))
    elif isinstance(obj, list):
        for idx, value in enumerate(obj):
            yield from _walk_system_profiler(value, path + (str(idx),))
def _parse_diskutil_layout(layout: dict[str, Any]) -> tuple[list[str], list[dict[str, Any]]]:
    whole_disks = [str(x) for x in (layout.get("WholeDisks") or []) if x]
    roots = _records(layout.get("AllDisksAndPartitions"))
    if not whole_disks:
        whole_disks = [str(value) for item in roots
                       if (value := _first(item, "DeviceIdentifier", "DeviceNode"))]
    collected: list[dict[str, Any]] = []
    seen: set[str] = set()
    child_keys = ("Partitions", "APFSVolumes", "Volumes", "Children", "APFSPhysicalStores")
    def visit(node: dict[str, Any], parent_id: str | None) -> None:
        identifier = _clean_text(_first(node, "DeviceIdentifier", "DeviceNode", "BSDName"))
        current_parent = parent_id
        if identifier and parent_id and identifier != parent_id and identifier not in seen:
            record = dict(node)
            record["_ParentDiskIdentifier"] = parent_id
            record["_DeviceIdentifier"] = identifier
            collected.append(record)
            seen.add(identifier)
        if identifier:
            current_parent = identifier
        for key in child_keys:
            for child in _records(node.get(key)):
                visit(child, current_parent)
    for root in roots:
        root_id = _clean_text(_first(root, "DeviceIdentifier", "DeviceNode", "BSDName"))
        if root_id:
            for key in child_keys:
                for child in _records(root.get(key)):
                    visit(child, root_id)
    return whole_disks, collected
def _collect_macos(sources: list[dict[str, Any]], existing_cpu: dict[str, Any] | None,
                   existing_gpu: dict[str, Any] | None, existing_storage: dict[str, Any] | None,
                   probe_smart: bool) -> dict[str, Any]:
    profiler: dict[str, Any] = {}
    system_profiler = shutil.which("system_profiler")
    if system_profiler:
        types = "SPHardwareDataType SPDisplaysDataType SPMemoryDataType SPStorageDataType SPNVMeDataType SPSerialATADataType SPPCIDataType SPCardReaderDataType"
        raw, err = _cmd_json([system_profiler, "-json", *types.split()], timeout=90)
        if isinstance(raw, dict):
            profiler = raw
            _source(sources, "system_profiler -json", "available", count=len(raw))
        else:
            core_types = "SPHardwareDataType SPDisplaysDataType SPMemoryDataType SPStorageDataType"
            core, core_err = _cmd_json([system_profiler, "-json", *core_types.split()], timeout=90)
            if isinstance(core, dict):
                profiler = core
                _source(sources, "system_profiler -json", "partial",
                        f"optional categories failed; core categories recovered: {err or 'unknown error'}", len(core))
            else:
                _source(sources, "system_profiler -json", "failed",
                        f"full query: {err or 'unknown error'}; core retry: {core_err or 'unknown error'}")
    else:
        _source(sources, "system_profiler", "unavailable")
    hardware = next(iter(_records(profiler.get("SPHardwareDataType"))), {})
    cpu_name = _first(hardware, "chip_type", "cpu_type", "machine_model", "CPU Type", "Chip") or platform.processor()
    cpu_raw = {"Name": cpu_name, "Manufacturer": "Apple" if "apple" in str(cpu_name).lower() or platform.machine().lower() in {"arm64", "aarch64"} else None,
               "Architecture": platform.machine(), "NumberOfLogicalProcessors": os.cpu_count()}
    cpus = [_normalize_cpu(cpu_raw, platform.machine(), "macOS system_profiler/sysctl")]
    sysctl = shutil.which("sysctl")
    if sysctl:
        rc, out, err = _run([sysctl, "-n", "machdep.cpu.brand_string"], timeout=5)
        if rc == 0 and out.strip() and not cpu_name:
            cpus[0]["name"] = out.strip()
        _source(sources, "sysctl", "available" if rc == 0 else "partial", err if rc else None)
    gpus: list[dict[str, Any]] = []
    for _, obj in _walk_system_profiler(profiler):
        name = _first(obj, "sppci_model", "spdisplays_model", "Chipset Model", "chipset_model", "spdisplays_device-id", "_name")
        if name and any(k in obj for k in ("spdisplays_vram", "spdisplays_vendor", "sppci_bus", "spdisplays_mtlgpu")):
            item = {"name": name, "vendor_name": _first(obj, "spdisplays_vendor", "sppci_vendor", "manufacturer"),
                    "bus": _first(obj, "sppci_bus", "spdisplays_bus"),
                    "dedicated_vram": _first(obj, "spdisplays_vram", "VRAM", "vram"),
                    "driver_version": _first(obj, "spdisplays_driver_version", "driver_version"),
                    "integrated": True if "apple" in str(name).lower() or "apple" in str(_first(obj, "spdisplays_vendor", "sppci_vendor", default="")).lower() else None,
                    "source": "macOS system_profiler"}
            gpus.append(_normalize_gpu(item, "macOS system_profiler"))
    for g in (existing_gpu or {}).get("gpus", []) if isinstance(existing_gpu, dict) else []:
        gpus.append(_normalize_gpu(g, "existing GPU collector"))
    gpus = _merge_gpus(gpus)
    baseboards = []
    board_name = _first(hardware, "machine_model", "machine_name", "model_name", "Model Name")
    if board_name:
        baseboards.append({"manufacturer": "Apple" if "apple" in str(cpu_name).lower() else None,
                           "product": board_name, "source": "macOS system_profiler (platform model; not a replaceable motherboard model)"})
    storage: list[dict[str, Any]] = []
    partitions: list[dict[str, Any]] = []
    volumes: list[dict[str, Any]] = []
    diskutil = shutil.which("diskutil")
    if diskutil:
        rc, out, err = _run([diskutil, "list", "-plist"], timeout=25)
        try:
            layout = plistlib.loads(out.encode("utf-8")) if rc == 0 else None
        except (plistlib.InvalidFileException, ValueError):
            layout = None
        if isinstance(layout, dict):
            def read_disk_info(identifier: str) -> dict[str, Any]:
                info_rc, info_out, _info_err = _run([diskutil, "info", "-plist", identifier], timeout=20)
                try:
                    parsed = plistlib.loads(info_out.encode("utf-8")) if info_rc == 0 else {}
                except (plistlib.InvalidFileException, ValueError):
                    parsed = {}
                return parsed if isinstance(parsed, dict) else {}

            whole_disks, partition_nodes = _parse_diskutil_layout(layout)
            for disk_id in whole_disks:
                info = read_disk_info(disk_id)
                size = _number(_first(info, "TotalSize", "DiskSize", "Size"))
                model = _clean_text(_first(info, "MediaName", "DeviceModel", "Model", "IORegistryEntryName")) or str(disk_id)
                bus = _clean_text(_first(info, "BusProtocol", "Protocol", "DeviceLocation"))
                internal = _first(info, "Internal")
                virtual = str(_first(info, "VirtualOrPhysical", default="")).lower() == "virtual"
                storage.append({"name": model, "model": model, "device_id": str(disk_id), "device_path": "/dev/" + str(disk_id),
                    "size_bytes": int(size) if size is not None else None, "bus": bus,
                    "kind": classify_storage_kind(name=model, model=model, bus=bus, is_virtual=virtual),
                    "internal": internal, "virtual": virtual,
                    "serial_number": _clean_text(_first(info, "Serial Number", "SerialNumber")),
                    "firmware": _clean_text(_first(info, "Device Revision", "Revision")),
                    "solid_state": _first(info, "Solid State", "SolidState"), "source": "diskutil"})
            for raw_part in partition_nodes:
                parent_id = _clean_text(raw_part.get("_ParentDiskIdentifier"))
                part_id = _clean_text(raw_part.get("_DeviceIdentifier"))
                if not part_id:
                    continue
                info = read_disk_info(part_id)
                size = _number(_first(info, "TotalSize", "VolumeTotalSpace", "Size"))
                if size is None:
                    size = _number(_first(raw_part, "Size", "size_bytes"))
                mount = _clean_text(_first(info, "MountPoint", "MountPath"))
                label = _clean_text(_first(info, "VolumeName", "MediaName", default=_first(raw_part, "VolumeName", "Name")))
                filesystem = _clean_text(_first(info, "FilesystemType", "FileSystemType", "FilesystemName"))
                partition = {"name": label or part_id, "device_id": part_id, "device_path": "/dev/" + part_id,
                    "parent_disk": parent_id, "size_bytes": int(size) if size is not None else None,
                    "partition_type": _clean_text(_first(raw_part, "Content", "PartitionType")),
                    "partition_uuid": _clean_text(_first(raw_part, "DiskUUID", "PartitionUUID", "VolumeUUID")),
                    "filesystem": filesystem, "label": label, "mountpoints": [mount] if mount else [],
                    "source": "diskutil partition layout"}
                partitions.append(partition)
                volume_uuid = _clean_text(_first(info, "VolumeUUID", "VolumeUUIDString", "APFSVolumeUUID"))
                has_volume_metadata = bool(mount or filesystem or volume_uuid or _first(info, "VolumeName"))
                if has_volume_metadata:
                    volumes.append({"mount": mount, "device": "/dev/" + part_id, "device_id": part_id,
                        "parent_disk": parent_id, "label": label, "filesystem": filesystem,
                        "size_bytes": int(size) if size is not None else None,
                        "free_bytes": _number(_first(info, "VolumeFreeSpace", "FreeSpace", "AvailableSpace")),
                        "uuid": volume_uuid, "content": partition["partition_type"],
                        "source": "diskutil info"})
            _source(sources, "diskutil plist", "available", f"{len(storage)} disk, {len(partitions)} partition", len(storage))
        else:
            _source(sources, "diskutil", "failed", err or "plist output could not be parsed")
    else:
        _source(sources, "diskutil", "unavailable")
    profiler_storage: list[dict[str, Any]] = []
    for path_parts, obj in _walk_system_profiler(profiler):
        name = _first(obj, "bsd_name", "device_name", "_name", "sppci_model")
        model = _first(obj, "medium_type", "physical_drive", "device_model", "nvme_model", "sppci_model", "model")
        path_text = "/".join(path_parts).lower()
        if not name or not any(token in path_text for token in ("spstorage", "spnvme", "spserialata", "sppci")):
            continue
        device_name = _clean_text(model or name)
        profiler_storage.append({"name": device_name, "model": device_name,
            "device_id": _clean_text(_first(obj, "bsd_name", "device_name")),
            "device_path": "/dev/" + str(_first(obj, "bsd_name", "device_name")) if _first(obj, "bsd_name", "device_name") else None,
            "size_bytes": _memory_size_bytes(_first(obj, "size", "capacity", "physical_drive")),
            "bus": _clean_text(_first(obj, "protocol", "bus_protocol", "sppci_bus")),
            "kind": classify_storage_kind(name=device_name, model=device_name,
                bus=_first(obj, "protocol", "bus_protocol", "sppci_bus")),
            "source": "macOS system_profiler storage"})
    if not storage:
        storage = profiler_storage
    elif profiler_storage:
        storage = _merge_storage_devices(storage + profiler_storage)
    if probe_smart:
        smart, status = _probe_storage_health(storage)
        _attach_smart_data(storage, smart)
        _source(sources, "storage_health", "available" if status == "ok" else "partial/unavailable", f"probe status: {status}", len(smart))
    else:
        _source(sources, "storage_health", "not requested")
    arrays, devices = [], []
    for _, obj in _walk_system_profiler(profiler.get("SPMemoryDataType", [])):
        size = _first(obj, "_items", "size", "dimm_size")
        if any(key in obj for key in ("dimm_size", "dimm_type", "dimm_speed", "dimm_status")):
            devices.append({"locator": _first(obj, "_name", "dimm_name", "locator"), "size_bytes": _memory_size_bytes(size),
                "memory_type": _first(obj, "dimm_type", "type"), "speed_mts": _number(_first(obj, "dimm_speed", "speed")),
                "state": "installed", "source": "macOS system_profiler memory"})
    mem_raw = _first(hardware, "physical_memory", "memory")
    mem_total = _number(mem_raw)
    if mem_total is None:
        mem_total = _memory_size_bytes(mem_raw)
    memory = _memory_summary(devices, arrays, len(devices) or None, mem_total)
    _source(sources, "macOS memory inventory", "partial", "Unified memory / soldered RAM may not expose DIMM slots or module data")
    return {"motherboard": {**(baseboards[0] if baseboards else {}), "bios": {}, "system": hardware, "chassis": {}},
            "cpu": _cpu_summary(cpus, existing_cpu), "gpu": {"adapters": gpus, "onboard_devices": []},
            "memory": memory, "storage": {"devices": storage, "controllers": [], "volumes": volumes,
                                               "partitions": partitions}}
def _storage_path_equivalent(left: Any, right: Any) -> bool:
    def normal(value: Any) -> str:
        text = str(value or "").strip().replace("\\", "/").lower()
        text = re.sub(r"/+", "/", text)
        return text.rstrip("/")
    a, b = normal(left), normal(right)
    if not a or not b:
        return False
    if a == b:
        return True
    ba, bb = a.rsplit("/", 1)[-1], b.rsplit("/", 1)[-1]
    nvme_ctrl = re.compile(r"^(nvme\d+)$")
    nvme_namespace = re.compile(r"^(nvme\d+n\d+)(?:p\d+)?$")
    ma, mb = nvme_ctrl.fullmatch(ba), nvme_ctrl.fullmatch(bb)
    na, nb = nvme_namespace.fullmatch(ba), nvme_namespace.fullmatch(bb)
    if na and nb and na.group(1) == nb.group(1):
        return True
    if ma and nb:
        return nb.group(1).startswith(ma.group(1) + "n")
    if mb and na:
        return na.group(1).startswith(mb.group(1) + "n")
    return bool(re.fullmatch(r"(?:\\\.\\)?physicaldrive\d+", ba) and
                re.fullmatch(r"(?:\\\.\\)?physicaldrive\d+", bb) and ba.replace("\\.\\", "") == bb.replace("\\.\\", ""))
def _storage_identity_key(value: Any) -> str:
    return "".join(char for char in str(value or "").casefold() if char.isalnum())
def _storage_serial_key(value: Any) -> str | None:
    key = _storage_identity_key(value)
    if not key or key in {"unknown", "none", "null", "na", "n/a", "serialnumber", "default", "tobefilledbyoem"}:
        return None
    if len(key) < 4 or len(set(key)) == 1:
        return None
    return key
def _storage_capacity_compatible(left: Any, right: Any) -> bool:
    left_size, right_size = _number(left), _number(right)
    if left_size is None or right_size is None:
        return True
    if left_size <= 0 or right_size <= 0:
        return False
    tolerance = max(16 * 1024 * 1024, int(max(left_size, right_size) * 0.01))
    return abs(int(left_size) - int(right_size)) <= tolerance
def _storage_disk_indices(device: dict[str, Any]) -> set[int]:
    values: set[int] = set()
    for field in ("index", "Index", "disk_number", "DiskNumber", "number", "Number"):
        raw = device.get(field)
        number = _number(raw)
        if number is not None and number >= 0 and float(number).is_integer():
            values.add(int(number))
    for field in ("device_id", "DeviceID"):
        raw = str(device.get(field) or "").strip()
        match = re.search(r"(?:physicaldrive|^)(\d+)$", raw, re.I)
        if match:
            values.add(int(match.group(1)))
    for raw in device.get("device_indices", []) if isinstance(device.get("device_indices"), (list, tuple, set)) else []:
        number = _number(raw)
        if number is not None and number >= 0 and float(number).is_integer():
            values.add(int(number))
    return values
def _storage_device_paths(device: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    for field in ("device_path", "device_id"):
        value = device.get(field)
        if isinstance(value, str) and value.strip() and not value.strip().isdigit() and value not in paths:
            paths.append(value.strip())
    for value in device.get("device_paths", []) if isinstance(device.get("device_paths"), (list, tuple, set)) else []:
        if isinstance(value, str) and value.strip() and value not in paths:
            paths.append(value.strip())
    return paths
def _smartctl_capacity_bytes(raw: dict[str, Any]) -> int | None:
    user_capacity = raw.get("user_capacity") if isinstance(raw.get("user_capacity"), dict) else {}
    capacity = _number(_first(user_capacity, "bytes"))
    if capacity is not None and capacity > 0:
        return int(capacity)
    blocks = _number(_first(user_capacity, "blocks"))
    block_size = _number(_first(user_capacity, "block_size", default=512))
    if blocks is not None and block_size is not None and blocks > 0 and block_size > 0:
        return int(blocks * block_size)
    return None
def _match_smartctl_identity(identity: dict[str, Any], devices: list[dict[str, Any]]) -> tuple[dict[str, Any] | None, str]:
    candidates = [device for device in devices
                  if isinstance(device, dict) and not device.get("virtual")
                  and str(device.get("kind") or "").casefold() != 'optical drive']
    serial = _storage_serial_key(_first(identity, "serial_number", "serial"))
    capacity = _smartctl_capacity_bytes(identity)
    if serial:
        serial_matches = [device for device in candidates
                          if _storage_serial_key(_first(device, "serial_number", "SerialNumber")) == serial]
        if len(serial_matches) > 1:
            return None, "ambiguous_serial_number"
        if len(serial_matches) == 1:
            match = serial_matches[0]
            inventory_capacity = _number(_first(match, "size_bytes", "Size", "Capacity"))
            if not _storage_capacity_compatible(capacity, inventory_capacity):
                return None, "serial_capacity_mismatch"
            return match, "serial_number"

    model = _storage_identity_key(_first(identity, "model_name", "model_family", "product"))
    if model and capacity:
        matches = []
        for device in candidates:
            aliases = {
                _storage_identity_key(value)
                for value in [device.get("model"), device.get("name"),
                              *(device.get("model_aliases", []) if isinstance(device.get("model_aliases"), (list, tuple, set)) else [])]
                if value
            }
            device_capacity = _number(_first(device, "size_bytes", "Size", "Capacity"))
            if model in aliases and _storage_capacity_compatible(capacity, device_capacity):
                matches.append(device)
        if len(matches) == 1:
            return matches[0], "model_and_capacity"
        if len(matches) > 1:
            return None, "ambiguous_model_and_capacity"
    return None, "no_unique_identity_match"
def _smartctl_device_args(exe: str, item: dict[str, Any], options: list[str]) -> list[str]:
    args = [exe, *options]
    dtype = _clean_text(_first(item, "type"))
    if dtype:
        args.extend(["-d", dtype])
    name = str(_first(item, "name", "device", default=""))
    args.append(name)
    return args
def _smartctl_exit_status_details(value: Any) -> dict[str, Any]:
    try:
        status = int(value)
    except (TypeError, ValueError, OverflowError):
        status = 0
    bit_definitions = (
        (1, "command_line_error", 'smartctl command-line parsing/execution error'),
        (2, "device_open_or_identity_error", 'device could not be opened, its identity could not be read, or it is in a low-power state'),
        (4, "smart_command_or_checksum_error", 'SMART command failed or the SMART data structure has a checksum error'),
        (8, "smart_status_failing", 'SMART health status reported DISK FAILING'),
        (16, "prefail_attribute_threshold", 'a pre-fail attribute is at or below its threshold'),
        (32, "attribute_failed_in_past", 'an attribute has been at or below its threshold in the past'),
        (64, "error_log_records", 'the SMART device error log contains an error record'),
        (128, "self_test_log_errors", 'the SMART self-test log contains a failed test record'),
    )
    flags = [
        {"bit": bit, "code": code, "message": message}
        for bit, code, message in bit_definitions if status & bit
    ]
    return {
        "raw": status,
        "flags": flags,
        "codes": [item["code"] for item in flags],
        "messages": [item["message"] for item in flags],
        "error_log_present": bool(status & 64),
        "self_test_log_errors": bool(status & 128),
        "current_prefail_threshold": bool(status & 16),
        "past_attribute_failure": bool(status & 32),
    }
def _smartctl_ata_log_details(raw: dict[str, Any]) -> dict[str, Any]:
    error_log = raw.get("ata_smart_error_log") if isinstance(raw.get("ata_smart_error_log"), dict) else {}
    error_summary = error_log.get("summary") if isinstance(error_log.get("summary"), dict) else {}
    error_table = error_summary.get("table") if isinstance(error_summary.get("table"), list) else []
    error_count = _number(_first(error_summary, "count", "logged_count"))
    logged_count = _number(error_summary.get("logged_count"))
    if logged_count is None and error_table:
        logged_count = len(error_table)
    if error_count is None:
        error_count = logged_count
    if error_count is None and error_table:
        error_count = len(error_table)
    compact_errors = []
    for entry in error_table[:8]:
        if not isinstance(entry, dict):
            continue
        registers = entry.get("completion_registers") if isinstance(entry.get("completion_registers"), dict) else {}
        command_trail = []
        for command in (entry.get("previous_commands") if isinstance(entry.get("previous_commands"), list) else [])[:5]:
            if not isinstance(command, dict):
                continue
            command_registers = command.get("registers") if isinstance(command.get("registers"), dict) else {}
            command_trail.append({
                "command_name": _first(command, "command_name"),
                "command": _first(command_registers, "command"),
                "features": _first(command_registers, "features"),
                "count": _first(command_registers, "count"),
                "lba": _first(command_registers, "lba"),
                "device": _first(command_registers, "device"),
                "powerup_milliseconds": _first(command, "powerup_milliseconds"),
            })
        latest_history_command = command_trail[0] if command_trail else None
        decoder_context = command_trail[0] if len(command_trail) == 5 else None
        decoder_opcode = decoder_context.get("command") if isinstance(decoder_context, dict) else None
        lba_is_command_address = False if decoder_opcode == 0xEF else None
        compact_errors.append({
            "error_number": _first(entry, "error_number"),
            "lifetime_hours": _first(entry, "lifetime_hours"),
            "error_description": _first(entry, "error_description"),
            "lba": _first(registers, "lba"),
            "lba_is_command_address": lba_is_command_address,
            "lba_interpretation": ("not_an_address_for_set_features" if decoder_opcode == 0xEF else
                                   "raw_register_value_command_semantics_unknown" if decoder_opcode is None else
                                   "command_context_available_interpret_per_ata_command"),
            "latest_history_command": latest_history_command,
            "decoder_command_context": decoder_context,
            "decoder_command_context_source": "smartmontools_commands_slot_4_full_five_entry_history" if decoder_context else None,
            "completion_registers": {key: _first(registers, key) for key in ("error", "status", "count", "lba", "device")
                                     if registers.get(key) is not None},
            "previous_commands": command_trail,
        })
    self_test_log = raw.get("ata_smart_self_test_log") if isinstance(raw.get("ata_smart_self_test_log"), dict) else {}
    standard = self_test_log.get("standard") if isinstance(self_test_log.get("standard"), dict) else {}
    self_test_table = standard.get("table") if isinstance(standard.get("table"), list) else []
    total_self_test_errors = _number(standard.get("error_count_total"))
    outdated_self_test_errors = _number(standard.get("error_count_outdated"))
    active_self_test_errors = None
    compact_self_tests = []
    table_failed_count = 0
    for entry in self_test_table[:8]:
        if not isinstance(entry, dict):
            continue
        test_type = entry.get("type") if isinstance(entry.get("type"), dict) else {}
        test_status = entry.get("status") if isinstance(entry.get("status"), dict) else {}
        if test_status.get("passed") is False:
            table_failed_count += 1
        compact_self_tests.append({
            "type": _first(test_type, "string"),
            "status": _first(test_status, "string"),
            "passed": _first(test_status, "passed"),
            "lifetime_hours": _first(entry, "lifetime_hours"),
        })
    if total_self_test_errors is not None:
        active_self_test_errors = max(0, int(total_self_test_errors) - int(outdated_self_test_errors or 0))
    elif table_failed_count:
        active_self_test_errors = table_failed_count
    return {
        "error_log_count": int(error_count) if error_count is not None else None,
        "error_log_logged_count": int(logged_count) if logged_count is not None else None,
        "error_log_present": bool(error_count or logged_count or compact_errors),
        "error_log_entries": compact_errors,
        "self_test_error_count": int(total_self_test_errors) if total_self_test_errors is not None else table_failed_count or None,
        "self_test_outdated_error_count": int(outdated_self_test_errors) if outdated_self_test_errors is not None else None,
        "self_test_active_error_count": active_self_test_errors,
        "self_test_log_errors": bool(active_self_test_errors),
        "self_test_log_entries": compact_self_tests,
    }
def _smartctl_decoder_context(error_entry: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(error_entry, dict):
        return None
    explicit = error_entry.get("decoder_command_context")
    if isinstance(explicit, dict):
        return explicit
    trail = error_entry.get("previous_commands")
    if isinstance(trail, list) and len(trail) == 5 and isinstance(trail[0], dict):
        return trail[0]
    return None
def smartctl_is_single_boot_write_cache_abort(smart: dict[str, Any]) -> bool:
    if not isinstance(smart, dict) or smart.get("smart_passed") is not True:
        return False
    media_errors = smart.get("media_errors")
    if isinstance(media_errors, (int, float)) and not isinstance(media_errors, bool) and media_errors > 0:
        return False
    entries = as_list(smart.get("error_log_entries"))
    if len(entries) != 1 or not isinstance(entries[0], dict):
        return False
    count = smart.get("error_log_count")
    if count is None:
        count = smart.get("num_err_log_entries")
    if count is not None:
        try:
            if int(count) != 1:
                return False
        except (TypeError, ValueError, OverflowError):
            return False
    entry = entries[0]
    if entry.get("lifetime_hours") is None:
        return False
    try:
        if int(entry["lifetime_hours"]) != 0:
            return False
    except (TypeError, ValueError, OverflowError):
        return False
    if "ABRT" not in str(entry.get("error_description") or "").upper():
        return False
    context = _smartctl_decoder_context(entry)
    if not isinstance(context, dict):
        return False
    command = context.get("command")
    features = context.get("features")
    try:
        return int(command) == 0xEF and int(features) == 0x02
    except (TypeError, ValueError, OverflowError):
        return False
def _smartctl_ata_power_on_hours(ata_attributes: Any) -> int | None:
    if not isinstance(ata_attributes, dict):
        return None
    table = ata_attributes.get("table") if isinstance(ata_attributes.get("table"), list) else []
    for attribute in table:
        if not isinstance(attribute, dict):
            continue
        name = str(attribute.get("name") or "").casefold().replace("-", "_").replace(" ", "_")
        if attribute.get("id") != 9 and name not in {"power_on_hours", "power_on_time"}:
            continue
        raw_value = attribute.get("raw") if isinstance(attribute.get("raw"), dict) else {}
        candidate = _first(raw_value, "value", "string")
        parsed = _number(candidate)
        if parsed is not None and parsed >= 0:
            return int(parsed)
        if isinstance(candidate, str):
            match = re.match(r"\s*(\d+)", candidate)
            if match:
                return int(match.group(1))
    return None
def _smartctl_payload_status(raw: dict[str, Any]) -> tuple[str, str | None]:
    smart_status = raw.get("smart_status") if isinstance(raw.get("smart_status"), dict) else {}
    if isinstance(smart_status.get("passed"), bool):
        return "success", None
    ata = raw.get("ata_smart_attributes") if isinstance(raw.get("ata_smart_attributes"), dict) else {}
    table = ata.get("table") if isinstance(ata.get("table"), list) else []
    if table:
        return "success", None
    nvme = raw.get("nvme_smart_health_information_log")
    if isinstance(nvme, dict):
        health_fields = (
            "critical_warning", "available_spare", "available_spare_threshold", "percentage_used",
            "data_units_read", "data_units_written", "host_reads", "host_writes",
            "controller_busy_time", "power_cycles", "power_on_hours", "unsafe_shutdowns",
            "media_errors", "num_err_log_entries", "warning_temp_time", "critical_comp_time",
        )
        if any(nvme.get(field) is not None for field in health_fields):
            return "success", None
    scsi_fields = ("scsi_percentage_used_endurance_indicator", "scsi_grown_defect_list")
    if any(raw.get(field) is not None for field in scsi_fields):
        return "success", None
    return "unsupported", 'smartctl returned JSON but no SMART health/attribute data; the device or USB bridge may not support SMART pass-through.'
def _smartctl_results_status(records: list[dict[str, Any]]) -> str:
    statuses = [
        str(row.get("query_status") or "unknown")
        for row in records
        if isinstance(row, dict) and row.get("query_status") != "duplicate_scan_entry"
    ]
    if not statuses:
        return "unavailable"
    successful = sum(status == "success" for status in statuses)
    if successful == len(statuses):
        return "ok"
    if successful:
        return "partial"
    return "unavailable"
def _attach_smart_data(devices: list[dict[str, Any]], smart_records: list[dict[str, Any]]) -> None:
    for smart in smart_records:
        physical_id = smart.get("matched_physical_device_id")
        path_candidates = [smart.get("matched_device_path"), smart.get("matched_device_id")]
        path_candidates.extend(
            value for value in smart.get("matched_device_paths", [])
            if isinstance(value, str) and value.strip()
        )
        serial = _storage_serial_key(smart.get("matched_serial_number") or smart.get("serial_number"))
        matches = []
        for device in devices:
            physical_match = bool(physical_id and device.get("physical_device_id") == physical_id)
            device_paths = _storage_device_paths(device)
            path_match = any(_storage_path_equivalent(path, candidate)
                             for path in path_candidates if path
                             for candidate in device_paths)
            device_serial = _storage_serial_key(device.get("serial_number"))
            serial_match = bool(serial and device_serial and serial == device_serial)
            if physical_match or path_match or serial_match:
                matches.append(device)
        if len(matches) == 1:
            matches[0]["smart"] = smart
        elif not smart.get("attachment_status"):
            smart["attachment_status"] = (
                'The SMART result could not be mapped to exactly one OS physical-disk group; no data was copied to any disk.'
            )
def _known_storage_paths(devices: list[dict[str, Any]]) -> list[str]:
    return [path for device in devices for path in _storage_device_paths(device)]
def _path_matches_known(path: str, known: list[str]) -> bool:
    return bool(path and known and any(_storage_path_equivalent(path, item) for item in known))
def _probe_storage_health(devices: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], str]:
    return _probe_smartctl(devices)
def _probe_smartctl(devices: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], str]:
    exe = shutil.which("smartctl")
    if not exe:
        return [], "smartctl not installed"
    rc, out, err = _run([exe, "--scan-open", "-j"], timeout=25)
    if not out.strip():
        return [], "device scan failed: " + (err or f"exit {rc}")
    try:
        scan = json.loads(out)
    except json.JSONDecodeError:
        return [], "scan JSON parse failed: " + (err or f"exit {rc}")
    found = _records(scan.get("devices"))
    if not found:
        return [], "no SMART-capable devices found"
    jobs: dict[Any, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    claimed_physical_ids: set[str] = set()
    with ThreadPoolExecutor(max_workers=4) as pool:
        for item in found:
            name = str(_first(item, "name", "device", default="")).strip()
            direct_matches = [device for device in devices
                              if any(_storage_path_equivalent(name, path)
                                     for path in _storage_device_paths(device))]
            matched_device = direct_matches[0] if len(direct_matches) == 1 else None
            match_method = "device_path" if matched_device is not None else None
            identity_raw: dict[str, Any] = {}
            identity_error = None
            if matched_device is None:
                identify_args = _smartctl_device_args(exe, item, ["-i", "-j", "-n", "standby"])
                identify_rc, identify_out, identify_stderr = _run(identify_args, 15)
                try:
                    parsed_identity = json.loads(identify_out) if identify_out.strip() else None
                except json.JSONDecodeError:
                    parsed_identity = None
                if isinstance(parsed_identity, dict):
                    identity_raw = parsed_identity
                    matched_device, match_method = _match_smartctl_identity(identity_raw, devices)
                else:
                    identity_error = identify_stderr or f"Could not read smartctl identity JSON (exit {identify_rc})"
            if matched_device is None:
                identity_device = identity_raw.get("device") if isinstance(identity_raw.get("device"), dict) else {}
                unmatched_reason = (
                    'the smartctl device path matched more than one OS disk group'
                    if len(direct_matches) > 1 else
                    identity_error or 'The physical device could not be uniquely matched by serial number, model, and capacity.'
                )
                results.append({
                    "device_path": name or None,
                    "query_status": "not_matched",
                    "health_status": "unknown",
                    "source": "smartctl", "source_type": "SMART",
                    "identity_model": _first(identity_raw, "model_name", "model_family", "product"),
                    "identity_serial_number": _first(identity_raw, "serial_number"),
                    "identity_size_bytes": _smartctl_capacity_bytes(identity_raw) if identity_raw else None,
                    "identity_probe_status": "failed" if identity_error else "completed",
                    "identity_probe_error": identity_error,
                    "identity_match_status": match_method or ("ambiguous_device_path" if len(direct_matches) > 1 else "not_matched"),
                    "device_protocol": _first(identity_device, "protocol"),
                    "attachment_status": unmatched_reason,
                    "error": unmatched_reason,
                })
                continue
            physical_id = matched_device.get("physical_device_id")
            if physical_id and physical_id in claimed_physical_ids:
                results.append({
                    "device_path": name or None,
                    "matched_physical_device_id": physical_id,
                    "matched_device_path": _first(matched_device, "device_path", "device_id"),
                    "matched_model": _first(matched_device, "model", "name"),
                    "identity_match_method": "duplicate_scan_alias",
                    "query_status": "duplicate_scan_entry",
                    "health_status": "unknown",
                    "source": "smartctl", "source_type": "SMART",
                    "unsupported_reason": 'The same physical disk was already listed in the smartctl scan; the duplicate query was skipped.',
                })
                continue
            if physical_id:
                claimed_physical_ids.add(str(physical_id))
            matched_paths = _storage_device_paths(matched_device)
            matched_path = _first(matched_device, "device_path", "device_id")
            identity_info = {
                "matched_physical_device_id": physical_id,
                "matched_device_id": _first(matched_device, "device_id", "DeviceId", "index", "Index"),
                "matched_device_path": matched_path,
                "matched_device_paths": matched_paths,
                "matched_serial_number": _first(matched_device, "serial_number", "SerialNumber"),
                "matched_model": _first(matched_device, "model", "name", "FriendlyName"),
                "identity_match_method": match_method,
                "identity_probe_status": "not_needed" if match_method == "device_path" else "matched",
            }
            query_item = {**item, **identity_info}
            args = _smartctl_device_args(exe, item, ["-a", "-j", "-n", "standby"])
            jobs[pool.submit(_run, args, 20)] = query_item
        for future in as_completed(jobs):
            info = jobs[future]
            rc, out, stderr = future.result()
            try:
                raw = json.loads(out) if out.strip() else None
            except json.JSONDecodeError:
                raw = None
            if not isinstance(raw, dict):
                results.append({
                    "device_path": _first(info, "name"),
                    "error": stderr or f"Could not read SMART JSON (exit {rc})",
                    "smartctl_exit_status": rc, "query_status": "failed",
                    "matched_physical_device_id": info.get("matched_physical_device_id"),
                    "matched_device_id": info.get("matched_device_id"),
                    "matched_device_path": info.get("matched_device_path"),
                    "matched_serial_number": info.get("matched_serial_number"),
                    "matched_model": info.get("matched_model"),
                    "identity_match_method": info.get("identity_match_method"),
                    "source": "smartctl", "source_type": "SMART",
                })
                continue
            payload_status, payload_reason = _smartctl_payload_status(raw)
            smart_status = _first(raw.get("smart_status") or {}, "passed")
            nvme = raw.get("nvme_smart_health_information_log") or {}
            ata = raw.get("ata_smart_attributes") or {}
            exit_status_details = _smartctl_exit_status_details(rc)
            ata_log_details = _smartctl_ata_log_details(raw)
            temperature_c = _number(_first(nvme, "temperature", default=_first(raw.get("temperature") or {}, "current")))
            if temperature_c is not None and not (0.0 < temperature_c <= 200.0):
                temperature_c = None
            temperature_channels = []
            for field, value in (nvme.items() if isinstance(nvme, dict) else ()):
                if not str(field).casefold().startswith("temperature_sensor_"):
                    continue
                channel_value = _number(value)
                if channel_value is None or not (0.0 < channel_value <= 200.0):
                    continue
                temperature_channels.append({
                    "sensor_identifier": f"smartctl:{_first(info, 'name')}:{field}",
                    "name": str(field).replace("_", " "),
                    "temperature_c": channel_value,
                    "source": "smartctl",
                })
            query_status = payload_status
            health_status = "passed" if smart_status is True else "failed" if smart_status is False else "unknown"
            result = {
                "device_path": _first(info, "name"),
                "matched_physical_device_id": info.get("matched_physical_device_id"),
                "matched_device_id": info.get("matched_device_id"),
                "matched_device_path": info.get("matched_device_path"),
                "matched_device_paths": info.get("matched_device_paths"),
                "matched_serial_number": info.get("matched_serial_number"),
                "matched_model": info.get("matched_model"),
                "identity_match_method": info.get("identity_match_method"),
                "model": _first(raw, "model_name", "model_family", "product"),
                "serial_number": _first(raw, "serial_number"),
                "firmware": _first(raw, "firmware_version"),
                "protocol": _first(raw.get("device") or {}, "protocol"),
                "smart_passed": smart_status if isinstance(smart_status, bool) else None,
                "health_status": health_status,
                "query_status": query_status,
                "query_status_reason": payload_reason,
                "unsupported_reason": payload_reason if query_status == "unsupported" else None,
                "temperature_c": temperature_c,
                "temperature_channels": temperature_channels,
                "power_on_hours": _first(nvme, "power_on_hours", default=_first(
                    raw.get("power_on_time") or {}, "hours", default=_smartctl_ata_power_on_hours(ata))),
                "percentage_used": _first(nvme, "percentage_used"),
                "media_errors": _first(nvme, "media_errors"),
                "num_err_log_entries": _first(nvme, "num_err_log_entries", default=ata_log_details["error_log_count"]),
                **ata_log_details,
                "exit_status_flags": exit_status_details["flags"],
                "exit_status_codes": exit_status_details["codes"],
                "exit_status_messages": exit_status_details["messages"],
                "error_log_present": exit_status_details["error_log_present"] or ata_log_details["error_log_present"],
                "self_test_log_errors": exit_status_details["self_test_log_errors"] or ata_log_details["self_test_log_errors"],
                "current_prefail_threshold": exit_status_details["current_prefail_threshold"],
                "past_attribute_failure": exit_status_details["past_attribute_failure"],
                "smartctl_exit_status": rc,
                "exit_status_explanation": _first(raw.get("smartctl") or {}, "exit_status"),
                "source": "smartctl", "source_detail": "smartctl -a -j -n standby", "source_type": "SMART",
            }
            results.append(result)
    results.sort(key=lambda row: (str(row.get("device_path") or ""), str(row.get("query_status") or "")))
    return results, _smartctl_results_status(results)
def empty_inventory(system: str | None = None, machine: str | None = None) -> dict[str, Any]:
    arch = canonical_architecture(machine or platform.machine())
    return {"schema_version": SCHEMA_VERSION, "collected_at_epoch": time.time(),
            "platform": {"system": system or platform.system(), "release": platform.release(), "machine": arch},
            "motherboard": {"manufacturer": None, "product": None, "version": None, "bios": {}, "system": {}, "chassis": {}},
            "cpu": {"architecture": arch, "processors": [], "physical_cores": None, "logical_processors": os.cpu_count()},
            "gpu": {"adapters": [], "onboard_devices": []},
            "memory": _memory_summary([], [], None),
            "storage": {"devices": [], "controllers": [], "volumes": [], "partitions": [], "pools": [],
                        "smartctl": {"source": "smartctl", "source_type": "SMART", "status": "not requested", "device_count": 0, "devices": [], "read_only": True}}, "sources": [],
            "limitations": ['Hardware discovery is limited to data exposed by the operating system, drivers, firmware/SMBIOS, and permissions.']}
def collect_hardware_inventory(*, system: str | None = None, machine: str | None = None,
                                smbios: dict[str, Any] | None = None,
                                smbios_structs: list[dict[str, Any]] | None = None,
                                windows_data: dict[str, Any] | None = None,
                                existing_cpu: dict[str, Any] | None = None,
                                existing_gpu: dict[str, Any] | None = None,
                                existing_storage: dict[str, Any] | None = None,
                                probe_smart: bool = False,
                                psutil_module: Any = None) -> dict[str, Any]:
    started = time.perf_counter()
    system_was_explicit = system is not None
    system = system or platform.system()
    machine = machine or platform.machine()
    smbios = smbios or {}
    smbios_detail = extract_smbios_inventory(smbios_structs)
    if not smbios_detail.get("baseboards") and smbios.get("board"):
        smbios_detail["baseboards"] = [dict(smbios["board"])]
    if not smbios_detail.get("memory_devices") and smbios.get("dimms"):
        smbios_detail["memory_devices"] = [{**d, "locator": d.get("slot"), "bank_locator": d.get("bank"),
                                            "state": "empty" if d.get("empty") else "installed", "source": "decoded SMBIOS"}
                                           for d in smbios.get("dimms", [])]
    sources: list[dict[str, Any]] = []
    context = {
        "system": system, "machine": machine, "smbios": smbios,
        "smbios_detail": smbios_detail, "smbios_structs": smbios_structs or [],
        "windows_data": windows_data or {}, "existing_cpu": existing_cpu,
        "existing_gpu": existing_gpu, "existing_storage": existing_storage,
        "probe_smart": probe_smart,
    }
    with _PROVIDER_LOCK:
        custom_platform = _PLATFORM_PROVIDERS.get(system.strip().lower())
    if custom_platform is not None:
        try:
            supplied = custom_platform(context)
            if not isinstance(supplied, dict):
                raise TypeError('platform collector must return a dict')
            json.dumps(supplied, ensure_ascii=False, allow_nan=False)
            inv = dict(supplied)
            provided_sources = inv.pop("sources", [])
            if isinstance(provided_sources, list):
                sources.extend(x for x in provided_sources if isinstance(x, dict))
            _source(sources, f"custom platform provider:{system}", "available")
        except Exception as exc:
            _source(sources, f"custom platform provider:{system}", "failed", f"{type(exc).__name__}: {exc}")
            inv = None
    else:
        inv = None
    if inv is None:
        if system.lower() == "windows":
            inv = _windows_inventory(windows_data or {}, smbios_detail, existing_cpu, existing_gpu, existing_storage, probe_smart)
            sources.extend(inv.pop("sources", []))
            for group, label in (("cpu", "CPU"), ("gpu", "GPU"), ("storage", "Storage")):
                _source(sources, f"existing {label} collectors", "available" if inv.get(group) else "partial")
        elif system.lower() == "linux" or (not system_was_explicit and Path("/proc/cpuinfo").exists()):
            inv = _collect_linux(sources, existing_cpu, existing_gpu, existing_storage, probe_smart)
        elif system.lower() == "darwin":
            inv = _collect_macos(sources, existing_cpu, existing_gpu, existing_storage, probe_smart)
        else:
            inv = {"motherboard": {**(smbios.get("board") or {}), "bios": smbios.get("bios") or {},
                                    "system": smbios.get("system") or {}, "chassis": smbios.get("chassis") or {}},
                   "cpu": _cpu_summary([], existing_cpu), "gpu": {"adapters": [], "onboard_devices": []},
                   "memory": _memory_summary(smbios_detail.get("memory_devices") or [], smbios_detail.get("memory_arrays") or [], None),
                   "storage": {"devices": [], "controllers": [], "volumes": [], "partitions": [], "pools": []}}
            _source(sources, "platform adapter", "not implemented", f"{system}; generic CPU/runtime fallback only")
    defaults = empty_inventory(system=system, machine=machine)
    for group in ("motherboard", "cpu", "gpu", "memory", "storage"):
        if not isinstance(inv.get(group), dict):
            inv[group] = defaults[group]
        else:
            for key, value in defaults[group].items():
                inv[group].setdefault(key, value)
    if smbios_detail.get("system_slots") and not inv.get("gpu", {}).get("system_slots"):
        inv["system_slots"] = smbios_detail["system_slots"]
    if not inv.get("motherboard", {}).get("manufacturer") and smbios_detail.get("baseboards"):
        inv["motherboard"].update(smbios_detail["baseboards"][0])
    if not inv.get("motherboard", {}).get("bios") and smbios_detail.get("bios"):
        inv["motherboard"]["bios"] = smbios_detail["bios"]
    if not inv.get("gpu", {}).get("onboard_devices") and smbios_detail.get("onboard_devices"):
        inv["gpu"]["onboard_devices"] = smbios_detail["onboard_devices"]
    inv.setdefault("storage", {}).setdefault("controllers", [])
    inv.setdefault("storage", {}).setdefault("volumes", [])
    inv.setdefault("storage", {}).setdefault("partitions", [])
    inv.setdefault("storage", {}).setdefault("pools", [])
    inv.setdefault("extensions", {})
    with _PROVIDER_LOCK:
        providers = list(_INVENTORY_PROVIDERS.items())
    for provider_name, (collector, allowed_systems) in providers:
        if allowed_systems is not None and system.strip().lower() not in allowed_systems:
            continue
        try:
            extension_data = collector(dict(context, inventory=inv))
            if not isinstance(extension_data, dict):
                raise TypeError('inventory provider must return a dict')
            json.dumps(extension_data, ensure_ascii=False, allow_nan=False)
            inv["extensions"][provider_name] = {"status": "available", "data": extension_data}
            _source(sources, f"inventory provider:{provider_name}", "available", count=len(extension_data))
        except Exception as exc:
            inv["extensions"][provider_name] = {"status": "failed", "error": f"{type(exc).__name__}: {exc}"}
            _source(sources, f"inventory provider:{provider_name}", "failed", f"{type(exc).__name__}: {exc}")
    storage = inv.setdefault("storage", {})
    storage_devices = _records(storage.get("devices"))
    attached_smart_devices = [dict(device["smart"]) for device in storage_devices
                              if isinstance(device.get("smart"), dict)]
    existing_smart_summary = storage.get("smartctl") if isinstance(storage.get("smartctl"), dict) else {}
    existing_smart_devices = _records(existing_smart_summary.get("devices"))
    smart_devices = existing_smart_devices or attached_smart_devices
    if not probe_smart:
        smart_status = "not requested"
    elif existing_smart_summary.get("status") not in (None, "not requested"):
        smart_status = str(existing_smart_summary.get("status"))
    elif not smart_devices:
        smart_status = "unavailable"
    else:
        smart_status = _smartctl_results_status(smart_devices)
    def summary_count(name: str, fallback: int) -> int:
        if not existing_smart_devices and existing_smart_summary.get("status") in (None, "not requested"):
            return fallback
        value = existing_smart_summary.get(name)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
        return fallback
    storage["smartctl"] = {
        "source": "smartctl", "source_type": "SMART", "status": smart_status,
        "device_count": summary_count("device_count", len(smart_devices)),
        "devices": smart_devices,
        "matched_device_count": summary_count("matched_device_count", len(attached_smart_devices)),
        "unmatched_device_count": summary_count("unmatched_device_count", sum(
            1 for item in smart_devices if item.get("query_status") == "not_matched")),
        "successful_device_count": summary_count("successful_device_count", sum(
            1 for item in smart_devices if item.get("query_status") == "success")),
        "unsupported_device_count": summary_count("unsupported_device_count", sum(
            1 for item in smart_devices if item.get("query_status") == "unsupported")),
        "failed_device_count": summary_count("failed_device_count", sum(
            1 for item in smart_devices if item.get("query_status") == "failed")),
        "read_only": True,
    }
    _source(sources, "SMART (smartctl)",
            "not requested" if smart_status == "not requested" else
            "available" if smart_status == "ok" else "partial/unavailable",
            f"status: {smart_status}; smartctl scan record: {len(smart_devices)}", len(smart_devices))
    inv["schema_version"] = SCHEMA_VERSION
    inv["collected_at_epoch"] = time.time()
    inv["platform"] = {"system": system, "release": platform.release(), "machine": canonical_architecture(machine)}
    inv["sources"] = sources
    inv["limitations"] = [
        'The inventory collects hardware exposed by the operating system and firmware; disabled devices, virtualization layers, and incorrect SMBIOS fields may not be visible.',
        'SMBIOS slot counts rely on vendor data. Individual empty RAM slot names are definitive only when reported by firmware Type 17/WMI.',
        'The Windows Win32_VideoController.AdapterRAM field is 32-bit and is not reliable on its own for GPU memory size; prefer DXGI when available, or NVML when no DXGI adapter list is available.',
        'Unknown vendor/model/enum codes are preserved; raw identifiers and source information are retained.',
    ]
    inv["collection_duration_s"] = round(time.perf_counter() - started, 3)
    return inv
IS_WINDOWS = os.name == "nt"
_INVALID_TEMPERATURE_LABELS = (
    "warning temperature",
    "critical temperature",
    "temperature warning",
    "temperature critical",
    "temperature threshold",
    "upper limit",
    "lower limit",
    "high limit",
    "low limit",
    "shutdown limit",
    "temperature limit",
)
def _enum_text(value: Any) -> str:
    if value is None:
        return ""
    try:
        to_string = getattr(value, "ToString", None)
        if callable(to_string):
            return str(to_string())
    except Exception:
        pass
    return str(value)
def _hardware_category(hardware_type: Any, parent: Any = None) -> str:
    raw = _enum_text(hardware_type).rsplit(".", 1)[-1].strip().casefold()
    parent_text = _enum_text(parent).casefold()
    text = f"{raw} {parent_text}"
    aliases = (
        (("cpu", "processor"), "CPU"),
        (("gpu", "graphics", "video"), "GPU"),
        (("motherboard", "mainboard", "system board"), "Motherboard"),
        (("storage", "drive", "disk", "nvme", "sata"), "Storage"),
        (("controller", "embedded controller"), "Controller"),
        (("memory", "ram", "dimm"), "Memory"),
        (("network", "ethernet", "wireless"), "Network"),
        (("battery", "smart battery"), "Battery"),
    )
    for tokens, category in aliases:
        if any(token in text for token in tokens):
            return category
    return _enum_text(hardware_type).rsplit(".", 1)[-1].strip() or "Unknown"
def _temperature_role(hardware_type: Any, name: Any) -> str:
    category = _hardware_category(hardware_type)
    label = _enum_text(name).casefold()
    if any(token in label for token in ("vrm", "mos", "voltage regulator", "vr vcc")):
        return "VRM"
    if category in {"CPU", "GPU", "Storage", "Motherboard"}:
        return category
    return "Other"
def sensor_component_identifier(hardware_type: Any, parent: Any) -> str | None:
    category = _hardware_category(hardware_type, parent)
    if category.casefold() in {"acpi thermal zone", "unknown", "other"}:
        return None
    parent_text = _enum_text(parent).strip().casefold()
    parent_text = re.sub(r"\s+", " ", parent_text)
    parent_text = re.sub(r"[^a-z0-9]+", "_", parent_text, flags=re.IGNORECASE).strip("_")
    if not parent_text:
        return None
    return f"{category.casefold()}:{parent_text}"
def sensor_deduplication_channel(hardware_type: Any, sensor_name: Any) -> str:
    category = _hardware_category(hardware_type).casefold()
    label = re.sub(r"\s+", " ", _enum_text(sensor_name).strip().casefold())
    if category == "gpu":
        if any(token in label for token in ("hotspot", "hot spot", "junction")):
            return "gpu_hotspot_temperature"
        if any(token in label for token in ("gpu core", "gpu edge", "gpu temperature", "edge temperature")) or label == "core":
            return "gpu_edge_temperature"
    if category == "storage":
        if any(token in label for token in ("composite temperature", "storage reliability temperature")) or label == "temperature":
            return "storage_composite_temperature"
    return label
def normalize_temperature(
    sensor_type: Any,
    name: Any,
    parent: Any,
    value: Any,
    source: str,
    *,
    hardware_type: Any = None,
    sensor_identifier: Any = None,
    timestamp: str | None = None,
) -> dict[str, Any] | None:
    type_name = _enum_text(sensor_type).rsplit(".", 1)[-1].strip().lower()
    if type_name != "temperature" and not type_name.endswith("temperature"):
        return None
    sensor_name = _enum_text(name).strip() or "Temperature"
    label = sensor_name.casefold()
    if any(token in label for token in _INVALID_TEMPERATURE_LABELS):
        return None
    try:
        temperature = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(temperature) or temperature <= 0.0 or temperature > 200.0:
        return None
    parent_name = _enum_text(parent).strip() or "Unknown hardware"
    category = _hardware_category(hardware_type, parent_name)
    return {
        "SensorType": "Temperature",
        "Name": sensor_name,
        "Parent": parent_name,
        "HardwareType": category,
        "SensorRole": _temperature_role(category, sensor_name),
        "SensorIdentifier": _enum_text(sensor_identifier).strip() or None,
        "SensorComponentIdentifier": sensor_component_identifier(category, parent_name),
        "Value": temperature,
        "source": source,
        "unit": "°C",
        "timestamp": timestamp or dt.datetime.now().astimezone().isoformat(timespec="milliseconds"),
    }
def normalize_windows_acpi_thermal_zones(
    rows: Any,
    source: str = "Windows ACPI/WMI",
) -> list[dict[str, Any]]:
    if rows is None:
        return []
    if isinstance(rows, Mapping):
        raw_rows = [rows]
    elif isinstance(rows, (list, tuple)):
        raw_rows = list(rows)
    else:
        try:
            raw_rows = list(rows)
        except TypeError:
            return []
    result: list[dict[str, Any]] = []
    for index, row in enumerate(raw_rows):
        if not isinstance(row, Mapping):
            continue
        instance = _enum_text(row.get("InstanceName") or row.get("instance_name")).strip()
        if not instance:
            instance = f"ThermalZone{index}"
        raw_value = row.get("CurrentTemperature", row.get("current_temperature"))
        try:
            temperature_c = (float(raw_value) / 10.0) - 273.15
        except (TypeError, ValueError, OverflowError):
            continue
        zone_label = instance.rsplit("\\", 1)[-1] or instance
        normalized = normalize_temperature(
            "Temperature",
            f"Thermal Zone {zone_label}",
            "Windows ACPI/WMI",
            temperature_c,
            source,
            hardware_type="ACPI Thermal Zone",
            sensor_identifier=f"acpi:{instance}",
            timestamp=row.get("timestamp"),
        )
        if normalized:
            result.append(normalized)
    return _deduplicate_rows(result)
def normalize_sensor_rows(rows: Any, source: str = "Windows WMI") -> list[dict[str, Any]]:
    if rows is None:
        return []
    if isinstance(rows, Mapping):
        raw_rows = [rows]
    elif isinstance(rows, (list, tuple)):
        raw_rows = list(rows)
    else:
        try:
            raw_rows = list(rows)
        except TypeError:
            return []
    result: list[dict[str, Any]] = []
    for row in raw_rows:
        if not isinstance(row, Mapping):
            continue
        sensor_type = row.get("SensorType", row.get("sensor_type", ""))
        name = row.get("Name", row.get("name", "Temperature"))
        parent = row.get("Parent", row.get("parent", "Unknown hardware"))
        value = row.get("Value", row.get("value"))
        type_name = _enum_text(sensor_type).rsplit(".", 1)[-1].strip().lower()
        if type_name == "temperature" or type_name.endswith("temperature"):
            normalized = normalize_temperature(
                sensor_type, name, parent, value, str(row.get("source") or source),
                hardware_type=row.get("HardwareType", row.get("hardware_type")),
                sensor_identifier=row.get("SensorIdentifier", row.get("sensor_identifier")),
                timestamp=row.get("timestamp"),
            )
            if normalized:
                result.append(normalized)
        else:
            copied = dict(row)
            copied.setdefault("source", source)
            result.append(copied)
    return result
def _children(hardware: Any) -> list[Any]:
    try:
        return list(getattr(hardware, "SubHardware", None) or [])
    except Exception:
        return []
def extract_hardwaremonitor_temperatures(
    computer: Any,
    source: str = "HardwareMonitor/pythonnet",
    visitor: Any = None,
) -> tuple[list[dict[str, Any]], int]:
    update = getattr(computer, "Update", None)
    if callable(update):
        update()
    else:
        accept = getattr(computer, "Accept", None)
        if callable(accept) and visitor is not None:
            accept(visitor)
    try:
        hardware_roots = list(getattr(computer, "Hardware", None) or [])
    except Exception:
        hardware_roots = []
    result: list[dict[str, Any]] = []
    raw_temperature_count = 0
    stack = list(hardware_roots)
    seen: set[int] = set()
    while stack:
        hardware = stack.pop(0)
        identity = id(hardware)
        if identity in seen:
            continue
        seen.add(identity)
        stack.extend(_children(hardware))
        hardware_name = _enum_text(getattr(hardware, "Name", None)) or "Unknown hardware"
        hardware_type = _enum_text(getattr(hardware, "HardwareType", None))
        hardware_identifier = _enum_text(getattr(hardware, "Identifier", None))
        try:
            sensors = list(getattr(hardware, "Sensors", None) or [])
        except Exception:
            sensors = []
        for sensor_index, sensor in enumerate(sensors):
            try:
                sensor_type = getattr(sensor, "SensorType", None)
                sensor_type_text = _enum_text(sensor_type).rsplit(".", 1)[-1].strip().lower()
                if sensor_type_text != "temperature" and not sensor_type_text.endswith("temperature"):
                    continue
                raw_temperature_count += 1
                sensor_name = getattr(sensor, "Name", None)
                sensor_identifier = _enum_text(getattr(sensor, "Identifier", None))
                if not sensor_identifier:
                    sensor_identifier = f"{hardware_identifier}/{_enum_text(sensor_name) or sensor_index}"
                row = normalize_temperature(
                    sensor_type,
                    sensor_name,
                    hardware_name,
                    getattr(sensor, "Value", None),
                    source,
                    hardware_type=hardware_type,
                    sensor_identifier=sensor_identifier,
                )
                if row:
                    result.append(row)
            except Exception:
                continue
    return _deduplicate_rows(result), raw_temperature_count
def extract_pylibre_temperatures(computer: Any, source: str = "PyLibreHardwareMonitor") -> tuple[list[dict[str, Any]], int]:
    result: list[dict[str, Any]] = []
    raw_temperature_count = 0
    for component in ("cpu", "gpu", "motherboard", "controller", "storage", "memory", "network"):
        try:
            devices = getattr(computer, component, None)
        except Exception:
            continue
        if not isinstance(devices, Mapping):
            continue
        for device_name, groups in devices.items():
            if not isinstance(groups, Mapping):
                continue
            for group_name, values in groups.items():
                if _enum_text(group_name).strip().casefold() != "temperature":
                    continue
                if not isinstance(values, Mapping):
                    continue
                for sensor_name, value in values.items():
                    raw_temperature_count += 1
                    row = normalize_temperature(
                        "Temperature", sensor_name, device_name, value, source,
                        hardware_type=component,
                        sensor_identifier=f"{component}/{device_name}/{group_name}/{sensor_name}",
                    )
                    if row:
                        result.append(row)
    return _deduplicate_rows(result), raw_temperature_count
def _deduplicate_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for row in rows:
        key = (str(row.get("Parent", "")).casefold(), str(row.get("Name", "")).casefold(),
               str(row.get("HardwareType", "")).casefold(),
               str(row.get("SensorIdentifier") or "").casefold())
        if key in seen:
            continue
        seen.add(key)
        result.append(row)
    return result
def _module_available(module_name: str) -> bool:
    try:
        return importlib.util.find_spec(module_name) is not None
    except (ImportError, ValueError, ModuleNotFoundError, AttributeError):
        return False
def sensor_provider_package_status() -> list[dict[str, Any]]:
    return [
        {"name": "HardwareMonitor", "module": "HardwareMonitor", "available": _module_available("HardwareMonitor"),
         "purpose": "LibreHardwareMonitor .NET API"},
        {"name": "pythonnet", "module": "clr", "available": _module_available("clr"),
         "purpose": '.NET CLR connection'},
        {"name": "PyLibreHardwareMonitor", "module": "PyLibreHardwareMonitor", "available": _module_available("PyLibreHardwareMonitor"),
         "purpose": 'Fallback sensor provider'},
        {"name": "ADLXPybind", "module": "ADLXPybind", "available": _module_available("ADLXPybind"),
         "purpose": 'AMD ADLX legacy/custom Python binding (optional)'},
        {"name": "amd-adlx", "module": "adlx", "available": _module_available("adlx"),
         "purpose": 'Official AMD ADLX Python binding (optional)'},
    ]
def pawnio_driver_status() -> dict[str, Any]:
    if not IS_WINDOWS:
        return {"status": "unsupported", "details": 'PawnIO is checked only on Windows targets.'}
    sc_path = shutil.which("sc.exe")
    if not sc_path:
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        candidate = os.path.join(system_root, "System32", "sc.exe")
        sc_path = candidate if os.path.isfile(candidate) else None
    if not sc_path:
        return {"status": "unknown", "details": 'sc.exe was not found; driver status could not be checked.'}
    try:
        result = subprocess.run(
            [sc_path, "query", "PawnIO"], capture_output=True, text=True,
            encoding="mbcs" if IS_WINDOWS else "utf-8", errors="replace", timeout=4, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"status": "unknown", "details": f"{type(exc).__name__}: {exc}"}
    output = f"{result.stdout}\n{result.stderr}".strip()
    upper = output.upper()
    if result.returncode == 0 and "RUNNING" in upper:
        return {"status": "running", "details": 'PawnIO service is running.'}
    if result.returncode == 0 and "STOPPED" in upper:
        return {"status": "stopped", "details": 'PawnIO is installed, but its service is not running. Run install_pawnio.ps1 from an elevated PowerShell window or inspect the service status.'}
    if "1060" in output or "DOES NOT EXIST" in upper or "NOT EXIST" in upper:
        return {"status": "not_installed", "details": 'The external PawnIO Windows driver is not installed. Run install_pawnio.ps1 from elevated PowerShell or use winget install -e --id namazso.PawnIO.'}
    return {"status": "unknown", "details": output[:400] or f"sc.exe exit code: {result.returncode}"}
class LibreHardwareMonitorProvider:
    def __init__(self) -> None:
        self.backend: str | None = None
        self._computer: Any = None
        self._visitor: Any = None
        self._pylibre_attempted = False
        self._attempts: list[str] = []
        self._messages: list[str] = []
        self._last_status: dict[str, Any] = {
            "status": "unavailable", "backend": None, "temperature_count": 0,
            "raw_temperature_count": 0, "attempts": self._attempts, "messages": self._messages,
        }
        if IS_WINDOWS:
            if not self._open_hardwaremonitor():
                self._open_pylibre()
        else:
            self._attempts.append('The sensor provider is available only on Windows.')
    @staticmethod
    def _run_quietly(function):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            result = function()
        return result, output.getvalue().strip()
    def _open_hardwaremonitor(self) -> bool:
        try:
            def factory():
                import clr
                from HardwareMonitor.Util import OpenComputer
                return OpenComputer(all=True)
            self._computer, message = self._run_quietly(factory)
            self._visitor = None
            self.backend = "HardwareMonitor/pythonnet"
            if message:
                self._messages.append(message[:600])
            return True
        except Exception as first_exc:
            self._attempts.append(f"HardwareMonitor/OpenComputer: {type(first_exc).__name__}: {first_exc}")
        try:
            def direct_factory():
                import clr
                from HardwareMonitor.Hardware import Computer, IVisitor
                class UpdateVisitor(IVisitor):
                    __namespace__ = "SistemAnaliziV11.SensorUpdateVisitor"
                    def VisitComputer(self, computer):
                        computer.Traverse(self)
                    def VisitHardware(self, hardware):
                        hardware.Update()
                        for subhardware in hardware.SubHardware:
                            subhardware.Update()
                    def VisitParameter(self, parameter):
                        return None
                    def VisitSensor(self, sensor):
                        return None
                computer = Computer()
                for option in ("Cpu", "Gpu", "Motherboard", "Controller", "Storage", "Memory", "Network", "Battery"):
                    try:
                        setattr(computer, f"Is{option}Enabled", True)
                    except Exception:
                        pass
                computer.Open()
                visitor = UpdateVisitor()
                computer.Accept(visitor)
                return computer, visitor
            direct_result, message = self._run_quietly(direct_factory)
            self._computer, self._visitor = direct_result
            self.backend = "HardwareMonitor.Computer/pythonnet"
            if message:
                self._messages.append(message[:600])
            return True
        except Exception as second_exc:
            self._attempts.append(f"HardwareMonitor.Computer/pythonnet: {type(second_exc).__name__}: {second_exc}")
            self._computer = None
            self.backend = None
            return False
    def _open_pylibre(self) -> bool:
        if self._pylibre_attempted:
            return self._computer is not None and self.backend == "PyLibreHardwareMonitor"
        self._pylibre_attempted = True
        try:
            def factory():
                from PyLibreHardwareMonitor import Computer
                return Computer(
                    IsCpuEnabled=True,
                    IsGpuEnabled=True,
                    IsMotherboardEnabled=True,
                    IsControllerEnabled=True,
                    IsStorageEnabled=True,
                )
            self._computer, message = self._run_quietly(factory)
            self.backend = "PyLibreHardwareMonitor"
            if message:
                self._messages.append(message[:600])
            return True
        except Exception as exc:
            self._attempts.append(f"PyLibreHardwareMonitor: {type(exc).__name__}: {exc}")
            self._computer = None
            self.backend = None
            return False
    def _close_computer(self) -> None:
        computer, self._computer = self._computer, None
        self._visitor = None
        close = getattr(computer, "Close", None) if computer is not None else None
        if callable(close):
            try:
                self._run_quietly(close)
            except Exception as exc:
                self._messages.append(f"Sensor provider shutdown warning: {type(exc).__name__}: {exc}")
    def _read_hardwaremonitor(self) -> tuple[list[dict[str, Any]], int]:
        if self._computer is None:
            return [], 0
        rows, raw_count = self._run_quietly(lambda: extract_hardwaremonitor_temperatures(
            self._computer, self.backend or "HardwareMonitor/pythonnet", visitor=self._visitor
        ))[0]
        return rows, raw_count
    def _read_pylibre(self) -> tuple[list[dict[str, Any]], int]:
        if self._computer is None:
            return [], 0
        rows, raw_count = self._run_quietly(lambda: extract_pylibre_temperatures(self._computer))[0]
        return rows, raw_count
    def read_temperatures(self) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        raw_count = 0
        if self.backend and self.backend.startswith("HardwareMonitor"):
            try:
                rows, raw_count = self._read_hardwaremonitor()
            except Exception as exc:
                self._attempts.append(f"{self.backend} read error: {type(exc).__name__}: {exc}")
            if not rows:
                self._close_computer()
                if self._open_pylibre():
                    try:
                        rows, fallback_raw_count = self._read_pylibre()
                        raw_count += fallback_raw_count
                    except Exception as exc:
                        self._attempts.append(f"PyLibreHardwareMonitor read error: {type(exc).__name__}: {exc}")
        elif self.backend == "PyLibreHardwareMonitor":
            try:
                rows, raw_count = self._read_pylibre()
            except Exception as exc:
                self._attempts.append(f"PyLibreHardwareMonitor read error: {type(exc).__name__}: {exc}")
        state = "available" if rows else "no_live_readings" if self.backend else "unavailable"
        temperature_rows = [row for row in rows if str(row.get("SensorType", "")).casefold() == "temperature"]
        hardware_types = sorted({str(row.get("HardwareType") or "Unknown") for row in temperature_rows})
        self._last_status = {
            "status": state,
            "backend": self.backend,
            "temperature_count": len(rows),
            "raw_temperature_count": raw_count,
            "hardware_types": hardware_types,
            "sensor_roles": sorted({str(row.get("SensorRole") or "Other") for row in temperature_rows}),
            "sources": sorted({str(row.get("source") or "Unknown") for row in temperature_rows}),
            "vrm_sensor_count": sum(1 for row in temperature_rows
                                     if str(row.get("SensorRole", "")).casefold() == "vrm"),
            "sensor_counts_by_hardware_type": {
                hardware_type: sum(1 for row in temperature_rows
                                   if str(row.get("HardwareType") or "Unknown") == hardware_type)
                for hardware_type in hardware_types
            },
            "attempts": list(self._attempts[-8:]),
            "messages": list(self._messages[-8:]),
        }
        if not rows and not self._attempts and not self._messages:
            self._last_status["details"] = 'The sensor provider did not return a valid temperature value.'
        elif not rows:
            self._last_status["details"] = 'Providers were attempted, but no valid live temperature value was obtained; 0 °C and threshold values were discarded.'
        return rows, dict(self._last_status)
    def close(self) -> None:
        self._close_computer()
def probe_live_temperatures() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not IS_WINDOWS:
        return [], {"status": "unsupported", "backend": None, "temperature_count": 0,
                    "details": 'LibreHardwareMonitor temperature probing is performed only on Windows.'}
    provider = LibreHardwareMonitorProvider()
    try:
        rows, status = provider.read_temperatures()
        return rows, dict(status)
    except Exception as exc:
        return [], {"status": "failed", "backend": provider.backend, "temperature_count": 0,
                    "details": f"{type(exc).__name__}: {exc}"}
    finally:
        provider.close()
def probe_pylibre_temperatures() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not IS_WINDOWS:
        return [], {"status": "unsupported", "backend": "PyLibreHardwareMonitor", "temperature_count": 0,
                    "details": 'PyLibreHardwareMonitor hardware probing is performed only on Windows.'}
    provider = LibreHardwareMonitorProvider.__new__(LibreHardwareMonitorProvider)
    provider.backend = None
    provider._computer = None
    provider._visitor = None
    provider._pylibre_attempted = False
    provider._attempts = []
    provider._messages = []
    provider._last_status = {}
    try:
        if not provider._open_pylibre():
            return [], {"status": "unavailable", "backend": "PyLibreHardwareMonitor", "temperature_count": 0,
                        "attempts": list(provider._attempts),
                        "details": 'PyLibreHardwareMonitor could not be started independently.'}
        rows, status = provider.read_temperatures()
        status = dict(status)
        status["probe"] = "standalone_fallback_validation"
        return rows, status
    except Exception as exc:
        return [], {"status": "failed", "backend": "PyLibreHardwareMonitor", "temperature_count": 0,
                    "details": f"{type(exc).__name__}: {exc}"}
    finally:
        provider.close()
def collect_sensor_readings(
    existing_rows: Any = None,
    sensor_provider: LibreHardwareMonitorProvider | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    normalized = normalize_sensor_rows(existing_rows)
    snapshot_timestamp = dt.datetime.now().astimezone().isoformat(timespec="milliseconds")
    for row in normalized:
        row.setdefault("timestamp", snapshot_timestamp)
        row.setdefault("HardwareType", _hardware_category(row.get("HardwareType"), row.get("Parent")))
        row.setdefault("SensorRole", _temperature_role(row.get("HardwareType"), row.get("Name")))
    owns_provider = sensor_provider is None
    provider = sensor_provider
    status: dict[str, Any] = {"status": "not_attempted", "backend": None, "temperature_count": 0}
    if IS_WINDOWS:
        if provider is None:
            provider = LibreHardwareMonitorProvider()
        try:
            live_rows, status = provider.read_temperatures()
        except Exception as exc:
            live_rows = []
            status = {"status": "failed", "backend": getattr(provider, "backend", None),
                      "temperature_count": 0, "details": f"{type(exc).__name__}: {exc}"}
        known = {
            (str(row.get("Parent", "")).casefold(), str(row.get("Name", "")).casefold(),
             str(row.get("HardwareType", "")).casefold(),
             str(row.get("SensorIdentifier") or "").casefold())
            for row in normalized
            if str(row.get("SensorType", "")).casefold() == "temperature"
        }
        for row in live_rows:
            row.setdefault("timestamp", snapshot_timestamp)
            row.setdefault("HardwareType", _hardware_category(row.get("HardwareType"), row.get("Parent")))
            row.setdefault("SensorRole", _temperature_role(row.get("HardwareType"), row.get("Name")))
            key = (str(row.get("Parent", "")).casefold(), str(row.get("Name", "")).casefold(),
                   str(row.get("HardwareType", "")).casefold(),
                   str(row.get("SensorIdentifier") or "").casefold())
            if key not in known:
                normalized.append(row)
                known.add(key)
        status = dict(status)
        status["temperature_count"] = sum(
            1 for row in normalized if str(row.get("SensorType", "")).casefold() == "temperature"
        )
        if status.get("status") != "available" and status["temperature_count"]:
            status["status"] = "partial"
        if not live_rows and any(str(row.get("SensorType", "")).casefold() == "temperature" for row in normalized):
            status["existing_source"] = "Windows WMI/OS"
            status["status"] = "available"
        temperature_rows = [row for row in normalized
                            if str(row.get("SensorType", "")).casefold() == "temperature"]
        status["hardware_types"] = sorted({str(row.get("HardwareType") or "Unknown") for row in temperature_rows})
        status["sensor_roles"] = sorted({str(row.get("SensorRole") or "Other") for row in temperature_rows})
        status["sources"] = sorted({str(row.get("source") or "Unknown") for row in temperature_rows})
        status["vrm_sensor_count"] = sum(1 for row in temperature_rows
                                         if str(row.get("SensorRole", "")).casefold() == "vrm")
        status["sensor_counts_by_hardware_type"] = {
            hardware_type: sum(1 for row in temperature_rows
                               if str(row.get("HardwareType") or "Unknown") == hardware_type)
            for hardware_type in status["hardware_types"]
        }
    else:
        status = {"status": "unsupported", "backend": None, "temperature_count": 0,
                  "details": 'The LibreHardwareMonitor integration is designed for Windows.'}
    if owns_provider and provider is not None:
        provider.close()
    return normalized, status
IS_WIN = os.name == "nt"
if IS_WIN:
    import winreg
    from ctypes import wintypes

__version__ = "1.0"
SCHEMA_VERSION = 4
_T0 = time.perf_counter()
WARNINGS: list = []
GIB = 1024 ** 3
MIB = 1024 ** 2
def log(msg: str) -> None:
    print(f"[{time.perf_counter() - _T0:6.1f}s] {msg}", file=sys.stderr, flush=True)
def warn(label: str, exc) -> None:
    WARNINGS.append(f"{label}: {type(exc).__name__}: {exc}")
def safe(label: str, fn, *args, default=None, **kw):
    'Runs fn; if it fails, adds a warning without breaking the report.'
    try:
        return fn(*args, **kw)
    except Exception as exc:
        warn(label, exc)
        return default
def valid_temperature_value(value, name: str = "") -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    temperature = float(value)
    if not math.isfinite(temperature) or not (0.0 < temperature <= 200.0):
        return None
    label = str(name or "").strip().casefold()
    if any(token in label for token in _INVALID_TEMPERATURE_LABELS):
        return None
    return temperature
def clamp(x, lo=0.0, hi=100.0):
    return max(lo, min(hi, x))
def avg(xs):
    xs = [x for x in xs if x is not None]
    return sum(xs) / len(xs) if xs else None
def as_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]
def lerp_score(x, anchors):
    'Linear interpolation between (value, score) anchors; clamped at the endpoints.'
    if x is None:
        return None
    pts = sorted(anchors)
    if x <= pts[0][0]:
        return float(pts[0][1])
    for (x0, y0), (x1, y1) in zip(pts, pts[1:]):
        if x <= x1:
            return y0 + (y1 - y0) * (x - x0) / (x1 - x0)
    return float(pts[-1][1])
def wavg(pairs):
    '[(value, weight)] -> weighted average (skips None values and redistributes their weights).'
    pairs = [(v, w) for v, w in pairs if v is not None]
    tw = sum(w for _, w in pairs)
    return sum(v * w for v, w in pairs) / tw if tw else None
def fmt_bytes(n, digits=2):
    if n is None:
        return "—"
    n = float(n)
    units = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")
    i = 0
    while abs(n) >= 1024 and i < len(units) - 1:
        n /= 1024
        i += 1
    return f"{n:.0f} {units[i]}" if i == 0 else f"{n:.{digits}f} {units[i]}"
_DOTNET_JSON_DATE_RE = re.compile(r"^/Date\((-?\d+)(?:[+-]\d+)?\)/$")
def format_report_date(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, dict):
        rendered = value.get("DateTime") or value.get("datetime")
        if rendered not in (None, ""):
            return str(rendered)
        value = value.get("value", value.get("Value", value.get("date", value.get("Date"))))
        if value is None:
            return "—"
    if isinstance(value, dt.datetime):
        local_value = value.astimezone() if value.tzinfo else value
        return local_value.strftime("%d.%m.%Y %H:%M" if local_value.time() != dt.time() else "%d.%m.%Y")
    if isinstance(value, dt.date):
        return value.strftime("%d.%m.%Y")
    raw = str(value).strip()
    if not raw:
        return "—"
    match = _DOTNET_JSON_DATE_RE.fullmatch(raw)
    if match:
        try:
            parsed = dt.datetime.fromtimestamp(int(match.group(1)) / 1000.0, tz=dt.timezone.utc).astimezone()
            return parsed.strftime("%d.%m.%Y")
        except (OverflowError, OSError, ValueError):
            return raw
    for date_format in ("%m-%d-%Y", "%Y-%m-%d"):
        try:
            return dt.datetime.strptime(raw, date_format).strftime("%d.%m.%Y")
        except ValueError:
            pass
    return raw
def _display_label(value: Any, width: int) -> str:
    label = " ".join(str(value or "").split())
    if width <= 0:
        return ""
    if len(label) <= width:
        return label
    if width == 1:
        return "…"
    return label[:width - 1] + "…"
def fmt_ghz(mhz, digits=2):
    return "—" if not mhz else f"{mhz / 1000:.{digits}f} GHz"
def fmt_pct(p, digits=1):
    return "—" if p is None else f"%{p:.{digits}f}"
def fmt_dur(sec):
    sec = int(sec)
    d, r = divmod(sec, 86400)
    h, r = divmod(r, 3600)
    m, s = divmod(r, 60)
    parts = []
    if d:
        parts.append(f"{d} days")
    if h:
        parts.append(f"{h} hours")
    if m or not parts:
        parts.append(f"{m} min")
    return " ".join(parts)
class UI:
    color = False
    ascii = False
_ANSI = {"ok": "32", "warn": "33", "bad": "31", "info": "36", "dim": "90",
         "bold": "1", "head": "1;96", "title": "1;97;44"}
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
def paint(text, style):
    if not UI.color or style not in _ANSI:
        return str(text)
    return f"\x1b[{_ANSI[style]}m{text}\x1b[0m"
def strip_ansi(s):
    return _ANSI_RE.sub("", s)
def vlen(s):
    return len(strip_ansi(s))
def normalize_display_level(level) -> str:
    value = str(level or "info").strip().casefold()
    aliases = {"warning": "warn", "critical": "bad", "error": "bad", "success": "ok"}
    value = aliases.get(value, value)
    return value if value in {"ok", "warn", "bad", "info"} else "info"
def icon(level):
    level = normalize_display_level(level)
    if UI.ascii:
        return {"ok": "[OK]", "warn": "[!]", "bad": "[X]", "info": "[i]"}[level]
    return {"ok": "●", "warn": "▲", "bad": "■", "info": "•"}[level]
def level_for(score, good=70, mid=45):
    if score is None:
        return "info"
    return "ok" if score >= good else ("warn" if score >= mid else "bad")
def bar(pct, width=22, high_is_good=True):
    p = clamp(0.0 if pct is None else pct)
    n = int(round(width * p / 100))
    full, empty = ("#", "-") if UI.ascii else ("█", "░")
    good = p if high_is_good else 100 - p
    style = "ok" if good >= 66 else ("warn" if good >= 33 else "bad")
    return paint(full * n, style) + paint(empty * (width - n), "dim")
def setup_console(no_color=False, ascii_mode=False):
    'UTF-8 output + ANSI colors when available.'
    UI.ascii = ascii_mode
    vt_ok = False
    if IS_WIN:
        try:
            k = ctypes.WinDLL("kernel32", use_last_error=True)
            k.SetConsoleOutputCP(65001)
            k.SetConsoleCP(65001)
            k.GetStdHandle.restype = wintypes.HANDLE
            k.GetStdHandle.argtypes = [wintypes.DWORD]
            k.GetConsoleMode.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
            k.SetConsoleMode.argtypes = [wintypes.HANDLE, wintypes.DWORD]
            h = k.GetStdHandle(0xFFFFFFF5)
            mode = wintypes.DWORD()
            if k.GetConsoleMode(h, ctypes.byref(mode)):
                vt_ok = bool(k.SetConsoleMode(h, mode.value | 0x0004))
        except Exception:
            vt_ok = False
    else:
        vt_ok = True
    UI.color = bool(vt_ok and sys.stdout.isatty() and not no_color and not os.environ.get("NO_COLOR"))
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
def launched_from_explorer() -> bool:
    'Returns True when launched by double-clicking in File Explorer so the window stays open; False when launched from a terminal.'
    if not IS_WIN or psutil is None:
        return False
    shells = {"cmd.exe", "powershell.exe", "pwsh.exe", "windowsterminal.exe", "code.exe", "bash.exe", "wsl.exe"}
    try:
        p = psutil.Process().parent()
        for _ in range(3):
            if p is None:
                return False
            name = (p.name() or "").lower()
            if name == "explorer.exe":
                return True
            if name in shells:
                return False
            p = p.parent()
    except Exception:
        pass
    return False
def run_cmd(args, timeout=20, encoding=None):
    '(returncode, output text). Tries the local OEM code page and UTF-8.'
    try:
        cp = subprocess.run(args, capture_output=True, timeout=timeout,
                            creationflags=0x08000000 if IS_WIN else 0)
    except (OSError, subprocess.SubprocessError):
        return -1, ""
    raw = cp.stdout or b""
    for enc in ([encoding] if encoding else (["oem", "utf-8"] if IS_WIN else ["utf-8"])):
        try:
            return cp.returncode, raw.decode(enc)
        except (LookupError, UnicodeDecodeError):
            continue
    return cp.returncode, raw.decode("utf-8", "replace")
_PS_PRE = ("$ErrorActionPreference='SilentlyContinue'; $ProgressPreference='SilentlyContinue'; "
           "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); ")
def ps_json(script: str, timeout: int = 30):
    'Runs a one-line PowerShell script and converts its JSON output to a Python object.'
    if not IS_WIN:
        return None
    exe = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
    if not exe:
        return None
    rc, out = run_cmd([exe, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                       "-Command", _PS_PRE + script], timeout, "utf-8-sig")
    out = out.strip()
    if not out or out == "null":
        return None
    try:
        return json.loads(out)
    except ValueError:
        starts = [i for i in (out.find("{"), out.find("[")) if i >= 0]
        if starts:
            try:
                return json.loads(out[min(starts):])
            except ValueError:
                return None
    return None
def reg_get(hive, path, name, default=None):
    if not IS_WIN:
        return default
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return default
def reg_subkeys(hive, path):
    if not IS_WIN:
        return []
    out = []
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            i = 0
            while True:
                try:
                    out.append(winreg.EnumKey(k, i))
                    i += 1
                except OSError:
                    break
    except OSError:
        pass
    return out
def _native_windows_machine() -> str | None:
    if os.name != "nt":
        return None
    machine_names = {0x014C: "x86", 0x8664: "AMD64", 0xAA64: "ARM64", 0x01C4: "ARM"}
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        is_wow64_process2 = getattr(kernel32, "IsWow64Process2", None)
        if is_wow64_process2 is not None:
            process_machine = ctypes.c_ushort()
            native_machine = ctypes.c_ushort()
            kernel32.GetCurrentProcess.restype = wintypes.HANDLE
            is_wow64_process2.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_ushort),
                                          ctypes.POINTER(ctypes.c_ushort)]
            is_wow64_process2.restype = wintypes.BOOL
            if is_wow64_process2(kernel32.GetCurrentProcess(), ctypes.byref(process_machine),
                                 ctypes.byref(native_machine)):
                code = native_machine.value or process_machine.value
                if code in machine_names:
                    return machine_names[code]
    except (AttributeError, OSError, TypeError, ctypes.ArgumentError):
        pass
    fallback = (os.environ.get("PROCESSOR_ARCHITEW6432") or
                os.environ.get("PROCESSOR_ARCHITECTURE") or platform.machine())
    normalized = fallback.strip().lower()
    return {"amd64": "AMD64", "x86_64": "AMD64", "arm64": "ARM64",
            "aarch64": "ARM64", "x86": "x86", "i386": "x86"}.get(normalized, fallback)
def evaluate_supported_environment(*, system: str, process_machine: str, bitness: int,
                                   native_machine: str | None, build: int | None,
                                   edition_id: str | None) -> dict:
    errors: list[str] = []
    if str(system).strip().lower() != "windows":
        errors.append('The operating system must be Windows.')
    if str(process_machine).strip().lower() not in {"amd64", "x86_64", "x64"}:
        errors.append('The Python process must use the x64 (AMD64) architecture.')
    if bitness != 64:
        errors.append('A 64-bit Python interpreter is required.')
    if str(native_machine or "").strip().lower() not in {"amd64", "x86_64", "x64"}:
        errors.append('The native operating-system architecture must be AMD64/x64; ARM64 is not supported.')
    try:
        numeric_build = int(build) if build is not None else None
    except (TypeError, ValueError):
        numeric_build = None
    if numeric_build is None:
        errors.append('The Windows edition could not be verified from the registry.')
    elif numeric_build < 22000:
        errors.append(f"Windows 11 is required (detected build: {numeric_build}).")
    if str(edition_id or "").strip().lower() != "professional":
        errors.append('Windows 11 Pro is required (EditionID=Professional); Home, Enterprise, and other editions are not supported.')
    return {
        "supported": not errors,
        "target": "Windows 11 Pro x64",
        "errors": errors,
        "detected": {"system": system, "process_machine": process_machine, "bitness": bitness,
                     "native_machine": native_machine, "build": numeric_build, "edition_id": edition_id},
    }
def supported_platform_status() -> dict:
    build = None
    edition_id = None
    if IS_WIN:
        cv = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        raw_build = reg_get(_HKLM, cv, "CurrentBuildNumber")
        try:
            build = int(raw_build) if raw_build is not None else None
        except (TypeError, ValueError):
            build = None
        edition_id = reg_get(_HKLM, cv, "EditionID")
    return evaluate_supported_environment(
        system=platform.system(), process_machine=platform.machine(),
        bitness=struct.calcsize("P") * 8,
        native_machine=_native_windows_machine() if IS_WIN else platform.machine(),
        build=build, edition_id=edition_id,
    )
def _unsupported_platform_message(status: dict) -> str:
    reasons = "\n".join(f"  - {item}" for item in status.get("errors", []))
    return ('This program is supported on Windows 11 Pro x64 only and requires 64-bit Python.\n'
            f"Detected environment: {json.dumps(status.get('detected', {}), ensure_ascii=False)}\n{reasons}\n"
            'To check system support: python system_analyses.py --diagnostics')
_K32 = None
def k32():
    'kernel32 (argtypes are defined). Called only on Windows.'
    global _K32
    if _K32 is None:
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.GetLogicalProcessorInformationEx.argtypes = [wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)]
        k.GetLogicalProcessorInformationEx.restype = wintypes.BOOL
        k.IsProcessorFeaturePresent.argtypes = [wintypes.DWORD]
        k.IsProcessorFeaturePresent.restype = wintypes.BOOL
        k.GetFirmwareType.argtypes = [ctypes.POINTER(ctypes.c_int)]
        k.GetFirmwareType.restype = wintypes.BOOL
        k.GetSystemFirmwareTable.argtypes = [wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD]
        k.GetSystemFirmwareTable.restype = wintypes.UINT
        k.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
        k.VirtualAlloc.restype = ctypes.c_void_p
        k.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        k.VirtualProtect.restype = wintypes.BOOL
        k.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD]
        k.VirtualFree.restype = wintypes.BOOL
        k.FlushInstructionCache.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t]
        k.FlushInstructionCache.restype = wintypes.BOOL
        k.GetCurrentProcess.restype = wintypes.HANDLE
        _K32 = k
    return _K32
def is_admin() -> bool:
    try:
        if IS_WIN:
            return bool(ctypes.WinDLL("shell32").IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False
def read_glpie_raw() -> bytes:
    k = k32()
    length = wintypes.DWORD(0)
    k.GetLogicalProcessorInformationEx(0xFFFF, None, ctypes.byref(length))
    if length.value == 0:
        return b""
    buf = ctypes.create_string_buffer(length.value)
    if not k.GetLogicalProcessorInformationEx(0xFFFF, buf, ctypes.byref(length)):
        raise OSError(ctypes.get_last_error(), 'GetLogicalProcessorInformationEx failed')
    return buf.raw[:length.value]
def parse_glpie(raw: bytes) -> dict:
    'Parses the SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX array (x64 layout).'
    cores, caches, packages, numa = [], [], [], []
    groups = 0
    n = len(raw)
    def masks(pos, count):
        out = []
        for _ in range(max(1, count)):
            if pos + 10 > n:
                break
            mask, grp = struct.unpack_from("<QH", raw, pos)
            out.extend(grp * 64 + b for b in range(64) if (mask >> b) & 1)
            pos += 16
        return out
    off = 0
    while off + 8 <= n:
        rel, size = struct.unpack_from("<II", raw, off)
        if size < 8 or off + size > n:
            break
        if rel in (0, 3):
            flags, eff = raw[off + 8], raw[off + 9]
            gcount = struct.unpack_from("<H", raw, off + 30)[0]
            rec = {"eff": eff, "smt": bool(flags & 1), "logical": masks(off + 32, gcount)}
            (cores if rel == 0 else packages).append(rec)
        elif rel == 1:
            node = struct.unpack_from("<I", raw, off + 8)[0]
            gcount = struct.unpack_from("<H", raw, off + 30)[0]
            numa.append({"node": node, "logical": masks(off + 32, gcount)})
        elif rel == 2:
            level, assoc = raw[off + 8], raw[off + 9]
            line = struct.unpack_from("<H", raw, off + 10)[0]
            csize, ctype = struct.unpack_from("<II", raw, off + 12)
            gcount = struct.unpack_from("<H", raw, off + 38)[0]
            caches.append({"level": level, "assoc": assoc, "line": line, "size": csize, "type": ctype,
                           "logical": masks(off + 40, gcount)})
        elif rel == 4:
            groups = struct.unpack_from("<H", raw, off + 10)[0]
        off += size
    return {"cores": cores, "caches": caches, "packages": packages, "numa": numa, "groups": groups}
def _cache_key(ch):
    t = ch["type"]
    return f"L{ch['level']}" + ("i" if t == 1 else "d" if t == 2 else "t" if t == 3 else "")
def build_topology(parsed: dict) -> dict:
    'Extracts P/E core classes, SMT, and cache summaries from raw GLPIE data.'
    cores, caches = parsed["cores"], parsed["caches"]
    effs = sorted({c["eff"] for c in cores})
    labels = {}
    if len(effs) == 1:
        labels[effs[0]] = "Standard"
    elif len(effs) == 2:
        labels[effs[1]], labels[effs[0]] = "P", "E"
    elif len(effs) >= 3:
        labels[effs[-1]], labels[effs[0]] = "P", "LP-E"
        for e in effs[1:-1]:
            labels[e] = "E"
    for i, c in enumerate(cores):
        c["id"] = i
        c["cls"] = labels.get(c["eff"], "Standard")
        lset = set(c["logical"])
        c["caches"] = {}
        for ch in caches:
            if lset & set(ch["logical"]):
                c["caches"][_cache_key(ch)] = {"size": ch["size"], "shared_logical": len(ch["logical"]),
                                               "assoc": ch["assoc"], "line": ch["line"]}
    order = [l for l in ("P", "E", "LP-E", "Standard") if l in labels.values()]
    classes = {}
    for lab in order:
        cs = [c for c in cores if c["cls"] == lab]
        logical = sorted(x for c in cs for x in c["logical"])
        classes[lab] = {"cores": len(cs), "threads": len(logical), "smt": any(c["smt"] for c in cs),
                        "logical": logical, "rep_logical": cs[0]["logical"][0] if cs and cs[0]["logical"] else 0,
                        "cache": cs[0]["caches"] if cs else {}}
    summary = {}
    for key in ("L1d", "L1i", "L2", "L3"):
        inst = [ch for ch in caches if _cache_key(ch) == key or (key == "L1d" and _cache_key(ch) == "L1")]
        if inst:
            sizes = sorted({ch["size"] for ch in inst})
            summary[key] = {"instances": len(inst), "sizes": sizes, "total": sum(ch["size"] for ch in inst)}
    return {"packages": max(1, len(parsed["packages"])), "numa_nodes": max(1, len(parsed["numa"])),
            "groups": parsed["groups"] or 1, "physical_cores": len(cores),
            "logical": sum(len(c["logical"]) for c in cores), "hybrid": len(effs) > 1,
            "classes": classes, "cores": cores, "cache_summary": summary}
def topology_fallback(psutil_mod) -> dict:
    'Provides a basic topology through psutil and /sys for non-Windows test environments.'
    phys = psutil_mod.cpu_count(logical=False) or 1
    logi = psutil_mod.cpu_count(logical=True) or phys
    tpc = max(1, logi // phys)
    cores = [{"eff": 0, "smt": tpc > 1, "logical": list(range(i * tpc, (i + 1) * tpc))} for i in range(phys)]
    caches = []
    base = "/sys/devices/system/cpu/cpu0/cache"
    try:
        for d in sorted(os.listdir(base)):
            if not d.startswith("index"):
                continue
            def rd(filename):
                with open(os.path.join(base, d, filename), encoding="utf-8") as handle:
                    return handle.read().strip()
            size = rd("size").upper()
            mult = 1024 if size.endswith("K") else MIB if size.endswith("M") else 1
            ctype = {"Data": 2, "Instruction": 1, "Unified": 0}.get(rd("type"), 0)
            caches.append({"level": int(rd("level")), "assoc": 0, "line": 64, "type": ctype,
                           "size": int(size.rstrip("KM")) * mult, "logical": list(range(logi))})
    except (OSError, ValueError):
        pass
    return build_topology({"cores": cores, "caches": caches, "packages": [{}], "numa": [], "groups": 1})
if IS_WIN:
    class _PERFINFO(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("CommitTotal", ctypes.c_size_t), ("CommitLimit", ctypes.c_size_t),
                    ("CommitPeak", ctypes.c_size_t), ("PhysicalTotal", ctypes.c_size_t),
                    ("PhysicalAvailable", ctypes.c_size_t), ("SystemCache", ctypes.c_size_t),
                    ("KernelTotal", ctypes.c_size_t), ("KernelPaged", ctypes.c_size_t),
                    ("KernelNonpaged", ctypes.c_size_t), ("PageSize", ctypes.c_size_t),
                    ("HandleCount", wintypes.DWORD), ("ProcessCount", wintypes.DWORD),
                    ("ThreadCount", wintypes.DWORD)]
    class _PPI(ctypes.Structure):
        _fields_ = [("Number", ctypes.c_ulong), ("MaxMhz", ctypes.c_ulong), ("CurrentMhz", ctypes.c_ulong),
                    ("MhzLimit", ctypes.c_ulong), ("MaxIdleState", ctypes.c_ulong),
                    ("CurrentIdleState", ctypes.c_ulong)]
def perf_info() -> dict:
    psapi = ctypes.WinDLL("psapi")
    psapi.GetPerformanceInfo.argtypes = [ctypes.POINTER(_PERFINFO), wintypes.DWORD]
    psapi.GetPerformanceInfo.restype = wintypes.BOOL
    pi = _PERFINFO()
    pi.cb = ctypes.sizeof(pi)
    if not psapi.GetPerformanceInfo(ctypes.byref(pi), pi.cb):
        raise OSError('GetPerformanceInfo failed')
    ps = pi.PageSize
    return {"commit_total": pi.CommitTotal * ps, "commit_limit": pi.CommitLimit * ps,
            "commit_peak": pi.CommitPeak * ps, "phys_total": pi.PhysicalTotal * ps,
            "phys_avail": pi.PhysicalAvailable * ps, "system_cache": pi.SystemCache * ps,
            "kernel_total": pi.KernelTotal * ps, "kernel_paged": pi.KernelPaged * ps,
            "kernel_nonpaged": pi.KernelNonpaged * ps, "handles": pi.HandleCount,
            "processes": pi.ProcessCount, "threads": pi.ThreadCount}
def ntpower_cpu(n: int) -> list:
    'The OS-reported MaxMhz / CurrentMhz / MhzLimit for each logical processor.'
    pw = ctypes.WinDLL("powrprof")
    pw.CallNtPowerInformation.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong]
    pw.CallNtPowerInformation.restype = ctypes.c_long
    arr = (_PPI * n)()
    st = pw.CallNtPowerInformation(11, None, 0, ctypes.byref(arr), ctypes.sizeof(arr))
    if st != 0:
        raise OSError(f"CallNtPowerInformation NTSTATUS 0x{st & 0xFFFFFFFF:08X}")
    return [{"cpu": p.Number, "max": p.MaxMhz, "cur": p.CurrentMhz, "limit": p.MhzLimit} for p in arr]
_PF = {"MMX": 3, "SSE": 6, "SSE2": 10, "SSE3": 13, "CMPXCHG16B": 14, "NX": 12, "SLAT": 20, "SANAL_FIRMWARE": 21,
       "SSSE3": 36, "SSE4.1": 37, "SSE4.2": 38, "AVX": 39, "AVX2": 40, "AVX512F": 41, "ERMS": 42}
def os_cpu_features() -> dict:
    k = k32()
    return {name: bool(k.IsProcessorFeaturePresent(code)) for name, code in _PF.items()}
def firmware_type() -> str:
    ft = ctypes.c_int(0)
    if k32().GetFirmwareType(ctypes.byref(ft)):
        return {1: "BIOS (Legacy)", 2: "UEFI"}.get(ft.value, "Unknown")
    return "Unknown"
def read_smbios_raw() -> bytes:
    k = k32()
    sig = 0x52534D42
    size = k.GetSystemFirmwareTable(sig, 0, None, 0)
    if not size:
        return b""
    buf = ctypes.create_string_buffer(size)
    got = k.GetSystemFirmwareTable(sig, 0, buf, size)
    raw = buf.raw[:got]
    return raw[8:8 + struct.unpack_from("<I", raw, 4)[0]] if len(raw) > 8 else b""
def parse_smbios(table: bytes) -> list:
    out, i, n = [], 0, len(table)
    while i + 4 <= n:
        typ, length = table[i], table[i + 1]
        handle = struct.unpack_from("<H", table, i + 2)[0]
        if length < 4:
            break
        data = table[i:i + length]
        j = i + length
        strings = []
        if table[j:j + 2] == b"\x00\x00":
            j += 2
        else:
            while j < n and table[j] != 0:
                k = table.find(b"\x00", j)
                if k < 0:
                    k = n
                strings.append(table[j:k].decode("utf-8", "replace").strip())
                j = k + 1
            j += 1
        out.append({"type": typ, "handle": handle, "data": data, "strings": strings})
        i = j
        if typ == 127:
            break
    return out
_MEM_TYPES = {0x01: 'Other', 0x02: "Unknown", 0x03: "DRAM", 0x04: "EDRAM", 0x05: "VRAM",
              0x06: "SRAM", 0x07: "RAM", 0x08: "ROM", 0x09: "Flash", 0x0A: "EEPROM",
              0x0B: "FEPROM", 0x0C: "EPROM", 0x0D: "CDRAM", 0x0E: "3DRAM", 0x0F: "SDRAM",
              0x10: "SGRAM", 0x11: "RDRAM", 0x12: "DDR", 0x13: "DDR2", 0x14: "DDR2 FB-DIMM",
              0x18: "DDR3", 0x19: "FBD2", 0x1A: "DDR4", 0x1B: "LPDDR", 0x1C: "LPDDR2",
              0x1D: "LPDDR3", 0x1E: "LPDDR4", 0x1F: 'Logical persistent memory', 0x20: "HBM",
              0x21: "HBM2", 0x22: "DDR5", 0x23: "LPDDR5", 0x24: "HBM3", 0x25: "MRDIMM"}
_FORM = {0x01: 'Other', 0x02: "Unknown", 0x03: "SIMM", 0x04: "SIP", 0x05: "Chip",
         0x06: "DIP", 0x07: "ZIP", 0x08: 'Proprietary card', 0x09: "DIMM", 0x0A: "TSOP",
         0x0B: 'Chip rank', 0x0C: "RIMM", 0x0D: "SO-DIMM", 0x0E: "SRIMM",
         0x0F: "FB-DIMM", 0x10: "Die", 0x11: "CAMM", 0x12: "CUDIMM", 0x13: "CSODIMM"}
_CHASSIS = {1: 'Other', 2: "Unknown", 3: 'Desktop', 4: 'Slim Desktop', 5: "Pizza Box", 6: "Mini Kule",
            7: "Kule", 8: 'Portable', 9: 'Laptop', 10: 'Laptop (Notebook)', 11: 'Handheld', 12: 'Docking Station',
            13: "Hepsi Bir Arada", 14: 'Subnotebook', 15: "Uzay Tasarruflu", 16: "Lunch Box", 17: "Ana Sunucu",
            23: "Raf Sunucu", 24: "Blade", 30: "Tablet", 31: 'Convertible', 32: 'Detachable', 33: 'IoT Gateway',
            35: "Mini PC", 36: "Stick PC"}
_LAPTOP_CH = {8, 9, 10, 14, 30, 31, 32}
def decode_smbios(structs: list) -> dict:
    def mk(s):
        d, strs = s["data"], s["strings"]
        L = len(d)
        def u8(o): return d[o] if o < L else 0
        def u16(o): return struct.unpack_from("<H", d, o)[0] if o + 2 <= L else 0
        def u32(o): return struct.unpack_from("<I", d, o)[0] if o + 4 <= L else 0
        def u64(o): return struct.unpack_from("<Q", d, o)[0] if o + 8 <= L else 0
        def st(o):
            idx = u8(o)
            return strs[idx - 1].strip() if 0 < idx <= len(strs) else ""
        return u8, u16, u32, u64, st
    res = {"bios": {}, "system": {}, "board": {}, "chassis": {}, "processors": [], "mem_array": {}, "dimms": [],
           "slots_total": 0}
    for s in structs:
        u8, u16, u32, u64, st = mk(s)
        t = s["type"]
        if t == 0 and not res["bios"]:
            res["bios"] = {"vendor": st(0x04), "version": st(0x05), "date": st(0x08)}
        elif t == 1 and not res["system"]:
            res["system"] = {"manufacturer": st(0x04), "product": st(0x05), "version": st(0x06),
                             "serial": st(0x07), "family": st(0x1A)}
        elif t == 2 and not res["board"]:
            res["board"] = {"manufacturer": st(0x04), "product": st(0x05), "version": st(0x06), "serial": st(0x07)}
        elif t == 3 and not res["chassis"]:
            ct = u8(0x05) & 0x7F
            res["chassis"] = {"type": ct, "type_name": _CHASSIS.get(ct, f"Type {ct}"), "laptop": ct in _LAPTOP_CH}
        elif t == 4:
            cores = u8(0x23)
            if cores == 255:
                cores = u16(0x2A)
            threads = u8(0x25)
            if threads == 255:
                threads = u16(0x2E)
            res["processors"].append({"socket": st(0x04), "manufacturer": st(0x07), "version": st(0x10),
                                      "ext_clock_mhz": u16(0x12), "max_speed_mhz": u16(0x14),
                                      "cur_speed_mhz": u16(0x16), "cores": cores, "threads": threads})
        elif t == 16 and u8(0x05) == 0x03 and not res["mem_array"]:
            cap_kb = u32(0x07)
            cap = u64(0x0F) if cap_kb == 0x80000000 else cap_kb * 1024
            res["mem_array"] = {"max_capacity": cap, "slots": u16(0x0D),
                                "ecc": u8(0x06) in (0x04, 0x05, 0x06, 0x07)}
        elif t == 17:
            res["slots_total"] += 1
            raw_size = u16(0x0C)
            slot = {"slot": st(0x10), "bank": st(0x11)}
            if raw_size == 0:
                slot["empty"] = True
                slot["size_bytes"] = 0
                res["dimms"].append(slot)
                continue
            if raw_size == 0xFFFF:
                size_bytes = None
            elif raw_size == 0x7FFF:
                extended_mb = u32(0x1C) & 0x7FFFFFFF
                size_bytes = int(extended_mb) * MIB if extended_mb else None
            elif raw_size & 0x8000:
                size_bytes = int(raw_size & 0x7FFF) * 1024
            else:
                size_bytes = int(raw_size) * MIB
            speed = u16(0x15)
            if speed == 0xFFFF:
                speed = u32(0x54)
            cfg = u16(0x20)
            if cfg == 0xFFFF:
                cfg = u32(0x58)
            tw, dw = u16(0x08), u16(0x0A)
            slot.update({"size_bytes": size_bytes, "type": _MEM_TYPES.get(u8(0x12), f"Type 0x{u8(0x12):02X}"),
                         "form": _FORM.get(u8(0x0E), f"0x{u8(0x0E):02X}"), "speed_mts": speed or None,
                         "configured_mts": cfg or None, "manufacturer": st(0x17), "part": st(0x1A),
                         "serial": st(0x18), "rank": u8(0x1B) & 0x0F, "total_width": tw, "data_width": dw,
                         "ecc": bool(dw and tw > dw), "volt_cfg_mv": u16(0x26) or None})
            res["dimms"].append(slot)
    return res
_CH_PATTERNS = [re.compile(r"channel[\s_\-]*([a-z0-9]+)", re.I),
                re.compile(r"dimm[\s_\-]*([a-h])[\s_\-]*\d", re.I)]
def infer_channels(dimms: list):
    'Infers the channel count from DIMM locator names -> (channel, source).'
    keys = []
    for d in dimms:
        text = f"{d.get('slot', '')} {d.get('bank', '')}"
        key = None
        for rx in _CH_PATTERNS:
            m = rx.search(text)
            if m:
                ctrl = re.search(r"controller[\s_\-]*(\d+)", text, re.I)
                key = (ctrl.group(1) if ctrl else "") + ":" + m.group(1).upper()
                break
        keys.append(key)
    if keys and all(keys):
        return len(set(keys)), 'from SMBIOS locator names'
    n = len(dimms)
    return (min(n, 2) if n else 0), 'inferred (locator name could not be parsed)'
if IS_WIN:
    class _PdhUnion(ctypes.Union):
        _fields_ = [("longValue", ctypes.c_long), ("doubleValue", ctypes.c_double),
                    ("largeValue", ctypes.c_longlong), ("AnsiStringValue", ctypes.c_char_p),
                    ("WideStringValue", ctypes.c_wchar_p)]
    class _PdhValue(ctypes.Structure):
        _fields_ = [("CStatus", wintypes.DWORD), ("u", _PdhUnion)]
    class _PdhItem(ctypes.Structure):
        _fields_ = [("szName", ctypes.c_wchar_p), ("FmtValue", _PdhValue)]
class Pdh:
    'PdhAddEnglishCounterW wrapper: uses English counter names even on localized Windows installations.'
    FMT = 0x200 | 0x8000
    MORE_DATA = 0x800007D2
    def __init__(self):
        L = ctypes.WinDLL("pdh")
        H = wintypes.HANDLE
        L.PdhOpenQueryW.argtypes = [wintypes.LPCWSTR, ctypes.c_size_t, ctypes.POINTER(H)]
        L.PdhAddEnglishCounterW.argtypes = [H, wintypes.LPCWSTR, ctypes.c_size_t, ctypes.POINTER(H)]
        L.PdhCollectQueryData.argtypes = [H]
        L.PdhGetFormattedCounterValue.argtypes = [H, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                                                  ctypes.POINTER(_PdhValue)]
        L.PdhGetFormattedCounterArrayW.argtypes = [H, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                                                   ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
        L.PdhCloseQuery.argtypes = [H]
        for f in (L.PdhOpenQueryW, L.PdhAddEnglishCounterW, L.PdhCollectQueryData,
                  L.PdhGetFormattedCounterValue, L.PdhGetFormattedCounterArrayW, L.PdhCloseQuery):
            f.restype = ctypes.c_long
        self.L = L
        self.q = H()
        if L.PdhOpenQueryW(None, 0, ctypes.byref(self.q)) != 0:
            raise OSError('PdhOpenQueryW failed')
        self.h = {}
    def add(self, key: str, path: str) -> bool:
        hc = wintypes.HANDLE()
        if self.L.PdhAddEnglishCounterW(self.q, path, 0, ctypes.byref(hc)) != 0:
            return False
        self.h[key] = hc
        return True
    def collect(self) -> bool:
        return (self.L.PdhCollectQueryData(self.q) & 0xFFFFFFFF) in (0, 0x800007D5)
    def value(self, key):
        hc = self.h.get(key)
        if hc is None:
            return None
        v, t = _PdhValue(), wintypes.DWORD()
        if self.L.PdhGetFormattedCounterValue(hc, self.FMT, ctypes.byref(t), ctypes.byref(v)) != 0:
            return None
        return v.u.doubleValue if v.CStatus in (0, 1) else None
    def array(self, key) -> dict:
        hc = self.h.get(key)
        if hc is None:
            return {}
        for _ in range(3):
            size, count = wintypes.DWORD(0), wintypes.DWORD(0)
            st = self.L.PdhGetFormattedCounterArrayW(hc, self.FMT, ctypes.byref(size), ctypes.byref(count), None)
            if (st & 0xFFFFFFFF) != self.MORE_DATA or size.value == 0:
                return {}
            buf = ctypes.create_string_buffer(size.value)
            st = self.L.PdhGetFormattedCounterArrayW(hc, self.FMT, ctypes.byref(size), ctypes.byref(count), buf)
            if (st & 0xFFFFFFFF) == self.MORE_DATA:
                continue
            if st != 0:
                return {}
            items = ctypes.cast(buf, ctypes.POINTER(_PdhItem))
            out = {}
            for i in range(count.value):
                it = items[i]
                if it.FmtValue.CStatus in (0, 1):
                    out[it.szName] = it.FmtValue.u.doubleValue
            return out
        return {}
    def close(self):
        try:
            self.L.PdhCloseQuery(self.q)
        except Exception:
            pass
def dxgi_adapters() -> list:
    class GUID(ctypes.Structure):
        _fields_ = [("Data1", ctypes.c_uint32), ("Data2", ctypes.c_uint16), ("Data3", ctypes.c_uint16),
                    ("Data4", ctypes.c_ubyte * 8)]
    class DESC1(ctypes.Structure):
        _fields_ = [("Description", ctypes.c_wchar * 128), ("VendorId", ctypes.c_uint), ("DeviceId", ctypes.c_uint),
                    ("SubSysId", ctypes.c_uint), ("Revision", ctypes.c_uint),
                    ("DedicatedVideoMemory", ctypes.c_size_t), ("DedicatedSystemMemory", ctypes.c_size_t),
                    ("SharedSystemMemory", ctypes.c_size_t), ("LuidLow", ctypes.c_uint32),
                    ("LuidHigh", ctypes.c_int32), ("Flags", ctypes.c_uint)]
    dxgi = ctypes.WinDLL("dxgi")
    dxgi.CreateDXGIFactory1.argtypes = [ctypes.POINTER(GUID), ctypes.POINTER(ctypes.c_void_p)]
    dxgi.CreateDXGIFactory1.restype = ctypes.c_long
    iid = GUID(0x770AAE78, 0xF26F, 0x4DBA, (ctypes.c_ubyte * 8)(0xA8, 0x29, 0x25, 0x3C, 0x83, 0xD1, 0xB3, 0x87))
    factory = ctypes.c_void_p()
    hr = dxgi.CreateDXGIFactory1(ctypes.byref(iid), ctypes.byref(factory))
    if hr != 0:
        raise OSError(f"CreateDXGIFactory1 HRESULT 0x{hr & 0xFFFFFFFF:08X}")
    def method(obj, idx, restype, *argtypes):
        vt = ctypes.cast(obj, ctypes.POINTER(ctypes.c_void_p))[0]
        fn = ctypes.cast(vt, ctypes.POINTER(ctypes.c_void_p))[idx]
        return ctypes.WINFUNCTYPE(restype, ctypes.c_void_p, *argtypes)(fn)
    out = []
    try:
        enum_adapters = method(factory.value, 12, ctypes.c_long, ctypes.c_uint, ctypes.POINTER(ctypes.c_void_p))
        for i in range(16):
            ad = ctypes.c_void_p()
            if enum_adapters(factory.value, i, ctypes.byref(ad)) != 0:
                break
            try:
                d = DESC1()
                if method(ad.value, 10, ctypes.c_long, ctypes.POINTER(DESC1))(ad.value, ctypes.byref(d)) == 0:
                    out.append({"name": d.Description, "vendor_id": d.VendorId, "device_id": d.DeviceId,
                                "dedicated_vram": int(d.DedicatedVideoMemory),
                                "dedicated_sys": int(d.DedicatedSystemMemory), "shared_sys": int(d.SharedSystemMemory),
                                "luid": f"luid_0x{d.LuidHigh & 0xFFFFFFFF:08x}_0x{d.LuidLow:08x}",
                                "software": bool(d.Flags & 2)})
            finally:
                method(ad.value, 2, ctypes.c_ulong)(ad.value)
    finally:
        method(factory.value, 2, ctypes.c_ulong)(factory.value)
    return out
RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15 = range(16)
def _rex(w, reg, rm):
    return 0x40 | (w << 3) | (((reg >> 3) & 1) << 2) | ((rm >> 3) & 1)
def _add_rr(dst, src):
    return bytes([_rex(1, src, dst), 0x01, 0xC0 | ((src & 7) << 3) | (dst & 7)])
def _mov_rr(dst, src):
    return bytes([_rex(1, src, dst), 0x89, 0xC0 | ((src & 7) << 3) | (dst & 7)])
def _sub_ri8(dst, imm):
    return bytes([_rex(1, 0, dst), 0x83, 0xE8 | (dst & 7), imm & 0xFF])
def _mov_r32_imm(dst, imm):
    return (b"\x41" if dst >= 8 else b"") + bytes([0xB8 + (dst & 7)]) + struct.pack("<I", imm)
def _push(r):
    return (b"\x41" if r >= 8 else b"") + bytes([0x50 + (r & 7)])
def _pop(r):
    return (b"\x41" if r >= 8 else b"") + bytes([0x58 + (r & 7)])
def _loop(prologue, body, counter, epilogue):
    sub = _sub_ri8(counter, 1)
    rel = -(len(body) + len(sub) + 6)
    return prologue + body + sub + b"\x0F\x85" + struct.pack("<i", rel) + epilogue + b"\xC3"
_CHAIN = [RCX, RDX, RBX, RSI, RDI, R9, R10, R11, R12, R13, R14, R15]
_SAVED = [RBX, RSI, RDI, R12, R13, R14, R15]
def _arg1_to_rax():
    return _mov_rr(RAX, RCX if IS_WIN else RDI)
def code_dep_chain(unroll=32):
    'Dependent `add` chain: one cycle per instruction -> core clock. rax = repetition count.'
    return _loop(_arg1_to_rax() + _mov_r32_imm(R8, 1), _add_rr(RDX, R8) * unroll, RAX, b"")
def code_independent(unroll=48):
    'Twelve independent `add` chains: peak integer ALU throughput (IPC).'
    pro = b"".join(_push(r) for r in _SAVED) + _arg1_to_rax() + _mov_r32_imm(R8, 1)
    body = b"".join(_add_rr(_CHAIN[i % len(_CHAIN)], R8) for i in range(unroll))
    return _loop(pro, body, RAX, b"".join(_pop(r) for r in reversed(_SAVED)))
def code_chase(unroll=16):
    'Pointer chasing: arg1 = base address, arg2 = repetition count (latency measurement).'
    pro = _mov_rr(RAX, RCX if IS_WIN else RDI)
    if not IS_WIN:
        pro += _mov_rr(RDX, RSI) 
    return _loop(pro, b"\x48\x8B\x00" * unroll, RDX, b"")
def jit_supported() -> bool:
    return platform.machine().lower() in ("amd64", "x86_64") and sys.maxsize > 2 ** 32
class Jit:
    'Places generated machine code in executable memory and makes it callable.'
    def __init__(self, code: bytes):
        self._mm = self._addr = None
        if IS_WIN:
            k = k32()
            self._addr = k.VirtualAlloc(None, len(code), 0x3000, 0x04)
            if not self._addr:
                raise OSError('VirtualAlloc failed')
            ctypes.memmove(self._addr, code, len(code))
            old = wintypes.DWORD()
            if not k.VirtualProtect(self._addr, len(code), 0x20, ctypes.byref(old)):
                raise OSError('VirtualProtect failed')
            k.FlushInstructionCache(k.GetCurrentProcess(), self._addr, len(code))
            addr = self._addr
        else:
            self._mm = mmap.mmap(-1, max(4096, len(code)), prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
            self._mm.write(code)
            self._buf = ctypes.c_char.from_buffer(self._mm)
            addr = ctypes.addressof(self._buf)
        self.fn = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64)(addr)
    def close(self):
        if IS_WIN and self._addr:
            k32().VirtualFree(self._addr, 0, 0x8000)
            self._addr = None
try:
    import psutil
except ImportError:
    psutil = None
_GUID_RX = re.compile(r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}")
_PLANS = {"381b4222-f694-41f0-9685-ff5bb260df2e": "Dengeli", "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c": 'High performance',
          "a1841308-3541-4fab-bc81-f71556f20b4a": 'Power saver', "e9a42b02-d5df-448d-aa00-03f14749eb61": "Ultimate performance"}
_OVERLAYS = {"00000000-0000-0000-0000-000000000000": "Dengeli", "961cc777-2547-4f9d-8174-7d86181b8a7a": 'Best power efficiency',
             "3af9b8d9-7c97-431d-ad78-34a8bfea439f": "Daha iyi pil", "ded574b5-45a0-4f42-8737-46345c09c238": "En iyi performans"}
_HKLM = winreg.HKEY_LOCAL_MACHINE if IS_WIN else None
_HKCU = winreg.HKEY_CURRENT_USER if IS_WIN else None
def collect_power(plugged: bool) -> dict:
    d = {}
    rc, out = run_cmd(["powercfg", "/getactivescheme"])
    m = _GUID_RX.search(out)
    guid = m.group(0).lower() if m else None
    name = _PLANS.get(guid)
    if not name:
        mm = re.search(r"\(([^)]+)\)", out)
        name = mm.group(1) if mm else "Unknown"
    d.update({"scheme_guid": guid, "scheme": name})
    ov = reg_get(_HKLM, r"SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes",
                 "ActiveOverlayAcPowerScheme" if plugged else "ActiveOverlayDcPowerScheme")
    d["overlay"] = _OVERLAYS.get(str(ov).lower()) if ov else None
    def q(alias):
        _, o = run_cmd(["powercfg", "/q", "SCHEME_CURRENT", "SUB_PROCESSOR", alias])
        vals = re.findall(r"0x[0-9a-fA-F]{8}", o)
        return int(vals[-2 if plugged else -1], 16) if len(vals) >= 2 else None
    d["min_state"], d["max_state"] = q("PROCTHROTTLEMIN"), q("PROCTHROTTLEMAX")
    d["boost_mode"], d["epp"], d["min_cores_active"] = q("PERFBOOSTMODE"), q("PERFEPP"), q("CPMINCORES")
    return d
def pending_reboot() -> list:
    flags = []
    for path, label in ((r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending", 'Windows components'),
                        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired", "Windows Update")):
        try:
            winreg.CloseKey(winreg.OpenKey(_HKLM, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY))
            flags.append(label)
        except OSError:
            pass
    return flags
def normalize_windows_battery_health(payload: Any) -> dict:
    if not isinstance(payload, dict):
        payload = {}
    static_rows = [row for row in as_list(payload.get("static")) if isinstance(row, dict)]
    full_rows = [row for row in as_list(payload.get("full_charge")) if isinstance(row, dict)]
    cycle_rows = [row for row in as_list(payload.get("cycles")) if isinstance(row, dict)]
    def instance(row: dict) -> str:
        return str(row.get("InstanceName") or "").strip().casefold()
    def match(rows: list[dict], target: dict) -> dict | None:
        target_id = instance(target)
        exact = [row for row in rows if target_id and instance(row) == target_id]
        if len(exact) == 1:
            return exact[0]
        if not target_id and len(static_rows) == 1 and len(rows) == 1:
            return rows[0]
        return None
    batteries = []
    for index, static in enumerate(static_rows):
        full = match(full_rows, static)
        cycles = match(cycle_rows, static)
        designed = _number(static.get("DesignedCapacity"))
        charged = _number(full.get("FullChargedCapacity")) if full else None
        cycle_count = _number(cycles.get("CycleCount")) if cycles else None
        designed = int(designed) if designed is not None and designed > 0 else None
        charged = int(charged) if charged is not None and charged > 0 else None
        cycle_count = int(cycle_count) if cycle_count is not None and cycle_count >= 0 else None
        health_pct = None
        wear_pct = None
        capacity_note = 'Capacity data is missing or could not be matched'
        if designed and charged:
            health_pct = round(charged / designed * 100.0, 1)
            wear_pct = round(max(0.0, 100.0 - health_pct), 1)
            capacity_note = ('Full-charge capacity was reported above design capacity; wear was clamped to zero.'
                             if health_pct > 100.0 else 'Calculated from Windows root/wmi capacity counters')
        name = _clean_text(_first(static, "DeviceName", "Manufacturer", "ManufactureName")) or f"Batarya {index + 1}"
        batteries.append({
            "name": name,
            "manufacturer": _clean_text(_first(static, "Manufacturer", "ManufactureName")),
            "identity_hash": _stable_change_identity("battery", instance(static)) if instance(static) else None,
            "chemistry": _clean_text(static.get("Chemistry")),
            "designed_capacity_mwh": designed,
            "full_charge_capacity_mwh": charged,
            "health_pct": min(100.0, health_pct) if health_pct is not None else None,
            "wear_pct": wear_pct,
            "cycle_count": cycle_count,
            "designed_voltage_mv": int(_number(static.get("DesignedVoltage"))) if _number(static.get("DesignedVoltage")) is not None else None,
            "capacity_note": capacity_note,
            "capacity_source": "Windows root/wmi BatteryStaticData/BatteryFullChargedCapacity" if designed and charged else None,
            "cycle_source": "Windows root/wmi BatteryCycleCount" if cycle_count is not None else None,
        })
    if not batteries:
        return {"status": "unavailable", "batteries": [],
                "note": 'Windows root/wmi battery capacity/cycle classes returned no data on this device; the current charge percentage cannot be used as a substitute for capacity health.'}
    available_capacity = any(item.get("health_pct") is not None for item in batteries)
    available_cycles = any(item.get("cycle_count") is not None for item in batteries)
    return {"status": "available" if available_capacity or available_cycles else "partial",
            "batteries": batteries,
            "note": 'Capacity wear is calculated only when both design and full-charge capacity are available; cycle count is a separate firmware/WMI field.'}
def collect_os() -> dict:
    d = {"system": platform.system(), "machine": platform.machine(), "admin": is_admin(),
         "python": {"version": platform.python_version(), "bits": 64 if sys.maxsize > 2 ** 32 else 32,
                    "impl": platform.python_implementation()}}
    bt = psutil.boot_time()
    d["boot_epoch"], d["uptime_s"] = bt, max(0.0, time.time() - bt)
    bat = safe("battery", psutil.sensors_battery) if hasattr(psutil, "sensors_battery") else None
    d["battery"] = ({"percent": bat.percent, "plugged": bat.power_plugged, "secs_left": bat.secsleft}
                    if bat else None)
    if not IS_WIN:
        d["product"] = f"{platform.system()} {platform.release()}"
        return d
    cv = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    build = int(reg_get(_HKLM, cv, "CurrentBuildNumber", 0) or 0)
    ubr = reg_get(_HKLM, cv, "UBR")
    product = str(reg_get(_HKLM, cv, "ProductName", "Windows"))
    if build >= 22000:
        product = product.replace("Windows 10", "Windows 11")
    d.update({"product": product, "edition_id": reg_get(_HKLM, cv, "EditionID"),
              "display_version": reg_get(_HKLM, cv, "DisplayVersion") or reg_get(_HKLM, cv, "ReleaseId"),
              "build": build, "ubr": ubr, "build_full": f"{build}.{ubr}" if ubr is not None else str(build),
              "install_epoch": reg_get(_HKLM, cv, "InstallDate")})
    d["firmware"] = safe('firmware type', firmware_type, default="Unknown")
    sb = reg_get(_HKLM, r"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled")
    d["secure_boot"] = None if sb is None else bool(sb)
    pm = r"SYSTEM\CurrentControlSet\Control\Session Manager"
    d["fast_startup"] = bool(reg_get(_HKLM, pm + r"\Power", "HiberbootEnabled", 0))
    hags = reg_get(_HKLM, r"SYSTEM\CurrentControlSet\Control\GraphicsDrivers", "HwSchMode")
    d["hags"] = None if hags is None else (hags == 2)
    gm = reg_get(_HKCU, r"Software\Microsoft\GameBar", "AutoGameModeEnabled")
    d["game_mode"] = None if gm is None else bool(gm)
    d["hvci_config"] = bool(reg_get(_HKLM, r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled", 0))
    d["vbs_config"] = bool(reg_get(_HKLM, r"SYSTEM\CurrentControlSet\Control\DeviceGuard", "EnableVirtualizationBasedSecurity", 0))
    pf = reg_get(_HKLM, pm + r"\Memory Management", "PagingFiles")
    d["pagefile_cfg"] = [str(x) for x in as_list(pf)] if pf else []
    d["pagefile"] = safe("Win32_PageFileUsage/Setting", collect_pagefile_info,
                         default={"status": "failed", "usage": [], "settings": []})
    d["pending_reboot"] = pending_reboot()
    d["pending_rename"] = bool(reg_get(_HKLM, pm, "PendingFileRenameOperations"))
    d["power"] = safe('power plan', collect_power, bool(d["battery"] is None or d["battery"]["plugged"] in (None, True)),
                      default={})
    d["system_drive"] = os.environ.get("SystemDrive", "C:")
    return d
_ISA_CHECKS = [("SSE4.2", ("sse42",)), ("AVX", ("avx",)), ("AVX2", ("avx2",)), ("FMA3", ("fma", "fma3")),
               ("F16C", ("f16c",)), ("BMI2", ("bmi2",)), ("AES-NI", ("aes", "aesni")), ("SHA", ("sha", "shani", "shaext")),
               ("VAES", ("vaes",)), ("AVX-VNNI", ("avxvnni",)), ("AVX-512F", ("avx512f",)), ("AVX-512DQ", ("avx512dq",)),
               ("AVX-512BW", ("avx512bw",)), ("AVX-512VL", ("avx512vl",)), ("AVX-512 VNNI", ("avx512vnni",)),
               ("AVX-512 BF16", ("avx512bf16",)), ("AVX-512 FP16", ("avx512fp16",)),
               ("AMX", ("amxtile", "amxbf16", "amxint8")), ("POPCNT", ("popcnt",)), ("ADX", ("adx",)),
               ("VT-x/AMD-V", ("vmx", "svm")), ("Hypervisor", ("hypervisor",))]
def isa_summary(flags, os_feat) -> dict:
    f = {x.lower().replace("_", "").replace(".", "") for x in (flags or [])}
    present = [name for name, keys in _ISA_CHECKS if any(k in f for k in keys)] if f else []
    if not f:
        present = [n for n in ("SSE4.2", "AVX", "AVX2") if os_feat.get(n)] + (["AVX-512F"] if os_feat.get("AVX512F") else [])
    simd = 512 if "AVX-512F" in present else 256 if ("AVX2" in present or "AVX" in present) else 128
    return {"present": present, "simd_bits": simd, "source": "py-cpuinfo (CPUID)" if f else "Windows IsProcessorFeaturePresent"}
def collect_cpuinfo_lib() -> dict:
    import cpuinfo
    info = cpuinfo.get_cpu_info()
    keys = ("brand_raw", "vendor_id_raw", "family", "model", "stepping", "hz_advertised_friendly",
            "hz_actual_friendly", "arch", "flags")
    return {k: info.get(k) for k in keys}
def collect_cpu_static(sm: dict) -> dict:
    d = {}
    if IS_WIN:
        key = r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"
        d["name"] = " ".join(str(reg_get(_HKLM, key, "ProcessorNameString", "")).split())
        d["vendor"] = reg_get(_HKLM, key, "VendorIdentifier", "")
        ident = str(reg_get(_HKLM, key, "Identifier", ""))
        m = re.search(r"Family\s+(\d+)\s+Model\s+(\d+)\s+Stepping\s+(\d+)", ident)
        d["family"], d["model"], d["stepping"] = (int(m.group(i)) for i in (1, 2, 3)) if m else (None, None, None)
        d["reg_mhz"] = reg_get(_HKLM, key, "~MHz")
        raw = safe("GetLogicalProcessorInformationEx", read_glpie_raw, default=b"")
        topo_ = safe('topology parsing', lambda: build_topology(parse_glpie(raw))) if raw else None
        d["topology_source"] = "Windows API (GetLogicalProcessorInformationEx)" if topo_ else 'fallback (psutil) — P/E and cache information is limited'
        d["topology"] = topo_ or topology_fallback(psutil)
        d["os_features"] = safe("IsProcessorFeaturePresent", os_cpu_features, default={})
    else:
        d["name"] = platform.processor() or platform.machine()
        d["vendor"], d["family"], d["model"], d["stepping"], d["reg_mhz"] = "", None, None, None, None
        d["topology"] = topology_fallback(psutil)
        d["topology_source"] = 'psutil (non-Windows environment)'
        d["os_features"] = {}
    n_logical = d["topology"]["logical"] or (psutil.cpu_count() or 1)
    if IS_WIN:
        d["ntpower"] = safe("CallNtPowerInformation", ntpower_cpu, n_logical, default=[])
    else:
        d["ntpower"] = []
    procs = sm.get("processors") or []
    d["smbios"] = procs[0] if procs else {}
    if not d["name"] and d["smbios"]:
        d["name"] = d["smbios"].get("version", "")
    return d
def collect_memory_static(sm: dict) -> dict:
    populated = [x for x in sm.get("dimms", []) if not x.get("empty")]
    d = {"slots_total": sm.get("slots_total") or len(sm.get("dimms", [])), "modules": [],
         "max_capacity": (sm.get("mem_array") or {}).get("max_capacity"),
         "array_ecc": (sm.get("mem_array") or {}).get("ecc")}
    for x in populated:
        t = x.get("type", "")
        for k in ("speed_mts", "configured_mts"):
            v = x.get(k)
            if v and ((t == "DDR4" and v < 1500) or (t == "DDR5" and v < 3000)):
                x[k] = v * 2
        d["modules"].append(x)
    d["populated"] = len(populated)
    d["total_installed"] = sum(x.get("size_bytes") or 0 for x in populated)
    ch, src = infer_channels(populated)
    d["channels"], d["channels_source"] = ch, src
    speeds = [x.get("configured_mts") or x.get("speed_mts") for x in populated if x.get("configured_mts") or x.get("speed_mts")]
    rated = [x.get("speed_mts") for x in populated if x.get("speed_mts")]
    d["run_mts"] = min(speeds) if speeds else None
    d["rated_mts"] = min(rated) if rated else None
    types = sorted({x.get("type") for x in populated if x.get("type")})
    d["type"] = "/".join(types) if types else None
    lp = bool(types) and all(t.startswith("LPDDR") for t in types)
    if d["run_mts"] and populated:
        if lp:
            bw = sum(((x.get("data_width") or 32) / 8) * (x.get("configured_mts") or x.get("speed_mts") or 0) for x in populated) / 1000
        else:
            bw = ch * d["run_mts"] * 8 / 1000
        d["theoretical_gbs"] = bw
    else:
        d["theoretical_gbs"] = None
    return d
_VENDORS = {0x10DE: "NVIDIA", 0x1002: "AMD", 0x1022: "AMD", 0x8086: "Intel", 0x1414: "Microsoft", 0x5143: "Qualcomm"}
_NV_ARCH = {2: "Kepler", 3: "Maxwell", 4: "Pascal", 5: "Volta", 6: "Turing", 7: "Ampere", 8: "Ada Lovelace", 9: "Hopper", 10: "Blackwell"}
_THROTTLE = {0x1: 'GPU idle', 0x4: 'Power limit (SW)', 0x8: 'Hardware throttling', 0x20: 'Thermal throttling (SW)',
             0x40: 'Thermal throttling (HW)', 0x80: 'Power brake (HW)'}
_NVML_ADAPTER_APPLICABILITY: bool | None = None
def _nv_str(x):
    return x.decode("utf-8", "replace") if isinstance(x, bytes) else x
def _nv_call(fn, *a):
    try:
        return fn(*a)
    except Exception:
        return None
def _has_nvidia_adapter(adapters) -> bool | None:
    active = [adapter for adapter in (adapters or [])
              if isinstance(adapter, dict) and not adapter.get("software")
              and adapter.get("vendor_id") != 0x1414]
    if not active:
        return None
    vendor_ids = [adapter.get("vendor_id") for adapter in active]
    known_vendor_ids = [value for value in vendor_ids if isinstance(value, int) and value > 0]
    if not known_vendor_ids:
        return None
    return 0x10DE in known_vendor_ids
def nvml_collect(adapters=None):
    global _NVML_ADAPTER_APPLICABILITY
    if adapters is not None:
        applicable = _has_nvidia_adapter(adapters)
        if applicable is not None:
            _NVML_ADAPTER_APPLICABILITY = applicable
    else:
        applicable = _NVML_ADAPTER_APPLICABILITY
        if applicable is None and IS_WIN:
            try:
                detected_adapters = dxgi_adapters()
            except Exception:
                detected_adapters = []
            applicable = _has_nvidia_adapter(detected_adapters)
            if applicable is not None:
                _NVML_ADAPTER_APPLICABILITY = applicable
    if applicable is False:
        return {"driver": None, "cuda": None, "devices": [], "available": False,
                "status": "not_applicable", "details": 'No NVIDIA adapter was found in the DXGI inventory; the NVML query was skipped.'}
    try:
        import pynvml as nv
    except ImportError:
        return None
    try:
        nv.nvmlInit()
    except Exception as exc:
        warn('NVML could not be initialized', exc)
        return None
    try:
        cuda_fn = getattr(nv, "nvmlSystemGetCudaDriverVersion_v2", None) or getattr(nv, "nvmlSystemGetCudaDriverVersion", None)
        cv = _nv_call(cuda_fn) if cuda_fn else None
        res = {"driver": _nv_str(_nv_call(nv.nvmlSystemGetDriverVersion)),
               "cuda": f"{cv // 1000}.{(cv % 1000) // 10}" if cv else None, "devices": []}
        thr_fn = getattr(nv, "nvmlDeviceGetCurrentClocksEventReasons", None) or getattr(nv, "nvmlDeviceGetCurrentClocksThrottleReasons", None)
        for i in range(nv.nvmlDeviceGetCount()):
            h = nv.nvmlDeviceGetHandleByIndex(i)
            d = {"index": i, "name": _nv_str(_nv_call(nv.nvmlDeviceGetName, h))}
            mi = _nv_call(nv.nvmlDeviceGetMemoryInfo, h)
            if mi:
                d.update(vram_total=mi.total, vram_used=mi.used, vram_free=mi.free)
            ut = _nv_call(nv.nvmlDeviceGetUtilizationRates, h)
            if ut:
                d.update(util_gpu=ut.gpu, util_mem=ut.memory)
            for nm, cid in (("gfx", 0), ("sm", 1), ("mem", 2), ("video", 3)):
                d[f"clk_{nm}"] = _nv_call(nv.nvmlDeviceGetClockInfo, h, cid)
                d[f"clk_{nm}_max"] = _nv_call(nv.nvmlDeviceGetMaxClockInfo, h, cid)
            d["temp"] = _nv_call(nv.nvmlDeviceGetTemperature, h, 0)
            d["temp_slowdown"] = _nv_call(nv.nvmlDeviceGetTemperatureThreshold, h, 1)
            d["fan"] = _nv_call(nv.nvmlDeviceGetFanSpeed, h)
            pw = _nv_call(nv.nvmlDeviceGetPowerUsage, h)
            d["power_w"] = pw / 1000 if pw is not None else None
            lim = _nv_call(nv.nvmlDeviceGetEnforcedPowerLimit, h)
            d["power_limit_w"] = lim / 1000 if lim is not None else None
            dflt = _nv_call(nv.nvmlDeviceGetPowerManagementDefaultLimit, h)
            d["power_default_w"] = dflt / 1000 if dflt is not None else None
            cons = _nv_call(nv.nvmlDeviceGetPowerManagementLimitConstraints, h)
            d["power_max_w"] = cons[1] / 1000 if cons else None
            d["pcie_gen"], d["pcie_gen_max"] = (_nv_call(nv.nvmlDeviceGetCurrPcieLinkGeneration, h),
                                                _nv_call(nv.nvmlDeviceGetMaxPcieLinkGeneration, h))
            d["pcie_width"], d["pcie_width_max"] = (_nv_call(nv.nvmlDeviceGetCurrPcieLinkWidth, h),
                                                    _nv_call(nv.nvmlDeviceGetMaxPcieLinkWidth, h))
            cc = _nv_call(nv.nvmlDeviceGetCudaComputeCapability, h)
            d["compute_cap"] = f"{cc[0]}.{cc[1]}" if cc else None
            d["bus_width"] = _nv_call(nv.nvmlDeviceGetMemoryBusWidth, h)
            d["cuda_cores"] = _nv_call(getattr(nv, "nvmlDeviceGetNumGpuCores", None), h) if hasattr(nv, "nvmlDeviceGetNumGpuCores") else None
            d["pstate"] = _nv_call(nv.nvmlDeviceGetPerformanceState, h)
            arch = _nv_call(nv.nvmlDeviceGetArchitecture, h)
            d["arch"] = _NV_ARCH.get(arch)
            enc, dec = _nv_call(nv.nvmlDeviceGetEncoderUtilization, h), _nv_call(nv.nvmlDeviceGetDecoderUtilization, h)
            d["util_enc"], d["util_dec"] = (enc[0] if enc else None), (dec[0] if dec else None)
            dm = _nv_call(nv.nvmlDeviceGetDriverModel, h)
            d["driver_model"] = {0: "WDDM", 1: "TCC/WDM"}.get(dm[0] if isinstance(dm, (tuple, list)) else dm)
            bar = _nv_call(nv.nvmlDeviceGetBAR1MemoryInfo, h)
            d["bar1_total"] = bar.bar1Total if bar else None
            mask = _nv_call(thr_fn, h) if thr_fn else None
            d["throttle"] = [name for bit, name in _THROTTLE.items() if mask and mask & bit and bit != 0x1]
            d["gpu_idle_flag"] = bool(mask and mask & 0x1)
            if d.get("cuda_cores") and d.get("clk_sm_max"):
                d["fp32_tflops"] = d["cuda_cores"] * 2 * d["clk_sm_max"] / 1e6
            if d.get("bus_width") and d.get("clk_mem_max"):
                d["mem_bw_gbs"] = d["bus_width"] / 8 * d["clk_mem_max"] * 2 / 1000
            res["devices"].append(d)
        res["available"] = True
        res["status"] = "available" if res["devices"] else "no_devices"
        return res
    finally:
        try:
            nv.nvmlShutdown()
        except Exception:
            pass
def nvml_live() -> list:
    'Live (variable) values: utilization, clock, power, temperature, VRAM.'
    res = safe('NVML live', nvml_collect)
    return (res or {}).get("devices", [])
def _is_integrated(name: str, vendor: int, dedicated: int) -> bool:
    n = name.lower()
    if vendor == 0x8086:
        return "arc" not in n
    if vendor in (0x1002, 0x1022):
        return bool(re.search(r"radeon\(tm\) graphics|radeon graphics|\b\d{3}m\b|vega \d|radeon 8\d{3}s", n)) or "rx" not in n and dedicated < GIB
    if vendor == 0x10DE:
        return False
    return dedicated < 2 * GIB
def collect_gpu_registry() -> list:
    cls = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
    out = []
    for sub in reg_subkeys(_HKLM, cls):
        if not sub.isdigit():
            continue
        p = cls + "\\" + sub
        desc = reg_get(_HKLM, p, "DriverDesc")
        if not desc:
            continue
        mem = reg_get(_HKLM, p, "HardwareInformation.qwMemorySize")
        if isinstance(mem, (bytes, bytearray)):
            mem = int.from_bytes(mem[:8], "little")
        out.append({"desc": str(desc), "driver_version": reg_get(_HKLM, p, "DriverVersion"),
                    "driver_date": reg_get(_HKLM, p, "DriverDate"), "provider": reg_get(_HKLM, p, "ProviderName"),
                    "vram": mem, "match": str(reg_get(_HKLM, p, "MatchingDeviceId", "")).lower()})
    return out
def collect_gpu_static() -> dict:
    adapters = safe("DXGI", dxgi_adapters, default=[]) if IS_WIN else []
    regs = safe('GPU registry', collect_gpu_registry, default=[]) if IS_WIN else []
    nvml = safe("NVML", nvml_collect, adapters)
    gpus, nv_left = [], list((nvml or {}).get("devices", []))
    for a in adapters:
        if a["software"] or a["vendor_id"] == 0x1414:
            continue
        g = {"name": a["name"], "vendor": _VENDORS.get(a["vendor_id"], f"0x{a['vendor_id']:04X}"),
             "vendor_id": a["vendor_id"], "device_id": a["device_id"], "luid": a["luid"],
             "dedicated_vram": a["dedicated_vram"], "shared_sys": a["shared_sys"], "source": "DXGI"}
        tag = f"ven_{a['vendor_id']:04x}&dev_{a['device_id']:04x}"
        for r in regs:
            if tag in r["match"]:
                g.update(driver_version=r["driver_version"], driver_date=r["driver_date"], provider=r["provider"])
                if r["vram"] and r["vram"] > g["dedicated_vram"]:
                    g["dedicated_vram"] = int(r["vram"])
                    g["dedicated_memory_source"] = "Windows GPU registry"
                break
        g["integrated"] = _is_integrated(g["name"], a["vendor_id"], g["dedicated_vram"])
        if a["vendor_id"] == 0x10DE:
            for nd in nv_left:
                if nd["name"] and (nd["name"] in g["name"] or g["name"] in nd["name"]):
                    g["nvml"] = nd
                    nv_left.remove(nd)
                    break
        gpus.append(g)
    if not adapters and nvml:
        for nd in nvml["devices"]:
            gpus.append({"name": nd["name"], "vendor": "NVIDIA", "vendor_id": 0x10DE, "luid": None,
                         "dedicated_vram": nd.get("vram_total", 0), "shared_sys": 0, "integrated": False,
                         "source": "NVML", "nvml": nd})
    return {"gpus": gpus, "nvml_driver": (nvml or {}).get("driver"), "cuda": (nvml or {}).get("cuda"),
            "nvml_available": bool((nvml or {}).get("available")),
            "nvml_status": (nvml or {}).get("status", "unavailable"),
            "nvml_details": (nvml or {}).get("details")}
PS_DISKS = ("Get-PhysicalDisk | Select-Object @{n='Name';e={[string]$_.FriendlyName}},@{n='Media';e={[string]$_.MediaType}},"
            "@{n='Bus';e={[string]$_.BusType}},@{n='Size';e={[int64]$_.Size}},@{n='Health';e={[string]$_.HealthStatus}},"
            "@{n='Op';e={[string]($_.OperationalStatus -join ',')}},@{n='Spindle';e={[int64]$_.SpindleSpeed}},"
            "@{n='LSect';e={[int64]$_.LogicalSectorSize}},@{n='PSect';e={[int64]$_.PhysicalSectorSize}},"
            "@{n='Firmware';e={[string]$_.FirmwareVersion}},@{n='Id';e={[string]$_.DeviceId}} | ConvertTo-Json -Compress")
PS_PARTS = ("Get-Partition | Where-Object {$_.DriveLetter} | Select-Object @{n='Drive';e={[string]$_.DriveLetter}},"
            "@{n='Disk';e={[string]$_.DiskNumber}} | ConvertTo-Json -Compress")
PS_GUARD = (r"Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard | Select-Object "
            r"@{n='Vbs';e={[int]$_.VirtualizationBasedSecurityStatus}},@{n='Running';e={@($_.SecurityServicesRunning)}},"
            r"@{n='Configured';e={@($_.SecurityServicesConfigured)}} | ConvertTo-Json -Compress")
PS_TPM = (r"$t=Get-CimInstance -Namespace root\cimv2\Security\MicrosoftTpm -ClassName Win32_Tpm; if($t){[pscustomobject]@{"
          r"Enabled=[bool]$t.IsEnabled_InitialValue;Activated=[bool]$t.IsActivated_InitialValue;Spec=[string]$t.SpecVersion} "
          r"| ConvertTo-Json -Compress}")
PS_CPUWMI = ("Get-CimInstance Win32_Processor | Select-Object @{n='MaxClock';e={[int]$_.MaxClockSpeed}},"
             "@{n='VirtFw';e={$_.VirtualizationFirmwareEnabled}},@{n='SLAT';e={$_.SecondLevelAddressTranslationExtensions}},"
             "@{n='VMX';e={$_.VMMonitorModeExtensions}},@{n='Socket';e={[string]$_.SocketDesignation}} | ConvertTo-Json -Compress")
PS_ACPI_THERMAL_ZONES = (
    "Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature "
    "-ErrorAction SilentlyContinue | Select-Object InstanceName,CurrentTemperature | ConvertTo-Json -Compress"
)
PS_PAGEFILE = (
    "$cs=Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue; "
    "$u=@(Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue | Select-Object Name,AllocatedBaseSize,CurrentUsage,PeakUsage,TempPageFile); "
    "$s=@(Get-CimInstance Win32_PageFileSetting -ErrorAction SilentlyContinue | Select-Object Name,InitialSize,MaximumSize); "
    "[pscustomobject]@{AutomaticManagedPagefile=$(if($cs){[bool]$cs.AutomaticManagedPagefile}else{$null});Usage=$u;Settings=$s} "
    "| ConvertTo-Json -Compress -Depth 5"
)
def collect_pagefile_info() -> dict[str, Any]:
    if not IS_WIN:
        return {"status": "unsupported", "usage": [], "settings": []}
    try:
        raw = ps_json(PS_PAGEFILE, timeout=6)
        if isinstance(raw, list):
            raw = raw[0] if raw and isinstance(raw[0], Mapping) else {}
        if not isinstance(raw, Mapping):
            return {"status": "unsupported_or_empty", "usage": [], "settings": []}
        usage = raw.get("Usage")
        settings = raw.get("Settings")
        usage_rows = [dict(x) for x in as_list(usage) if isinstance(x, Mapping)]
        setting_rows = [dict(x) for x in as_list(settings) if isinstance(x, Mapping)]
        auto = raw.get("AutomaticManagedPagefile")
        return {"status": "available", "automatic_managed": auto if isinstance(auto, bool) else None,
                "usage": usage_rows, "settings": setting_rows}
    except Exception as exc:
        return {"status": "inaccessible", "automatic_managed": None, "usage": [], "settings": [],
                "error": f"{type(exc).__name__}: {exc}"}
def assess_pagefile_configuration(os_data: dict[str, Any] | None, memory_dynamic: dict[str, Any] | None,
                                  commit_pct: float | None, available_pct: float | None) -> dict[str, Any]:
    os_data = os_data if isinstance(os_data, dict) else {}
    memory_dynamic = memory_dynamic if isinstance(memory_dynamic, dict) else {}
    info = os_data.get("pagefile") if isinstance(os_data.get("pagefile"), dict) else {}
    usage_rows = [row for row in as_list(info.get("usage")) if isinstance(row, dict)]
    allocated_mb = 0
    for row in usage_rows:
        try:
            allocated_mb += max(0, int(row.get("AllocatedBaseSize") or 0))
        except (TypeError, ValueError, OverflowError):
            continue
    swap_total = memory_dynamic.get("swap_total") or 0
    try:
        swap_total = max(0, int(swap_total))
    except (TypeError, ValueError, OverflowError):
        swap_total = 0
    active = bool(allocated_mb > 0 or swap_total > 0)
    auto = info.get("automatic_managed")
    settings = [row for row in as_list(info.get("settings")) if isinstance(row, dict)]
    if auto is True:
        mode = "system_managed"
    elif active or settings:
        mode = "custom"
    elif info.get("status") == "available" and auto is False and not usage_rows and not settings:
        mode = "disabled"
    else:
        mode = "unknown"
    try:
        peak = int(memory_dynamic.get("commit_peak") or 0)
        limit = int(memory_dynamic.get("commit_limit") or 0)
        peak_pct = peak / limit * 100 if peak > 0 and limit > 0 else None
    except (TypeError, ValueError, OverflowError):
        peak_pct = None
    pressure = ((commit_pct is not None and commit_pct >= 80)
                or (peak_pct is not None and peak_pct >= 90)
                or (available_pct is not None and available_pct < 15))
    if mode == "disabled":
        if pressure:
            severity = "warn"
            recommendation = ('Commit pressure is high and the page file is disabled. Consider enabling the Windows system-managed '
                              'page file; check available storage and organizational policies first.')
        else:
            severity = "info"
            recommendation = ('The page file is disabled; current commit/memory samples do not show acute pressure. '
                              'For large video projects, rendering, virtual machines, and memory-intensive applications, consider the Windows '
                              'system-managed page file.')
    elif mode == "system_managed":
        severity = "ok"
        recommendation = 'Windows manages the page file automatically; there is no evidence to change the current setting.'
    elif mode == "custom":
        severity = "ok" if not pressure else "info"
        recommendation = ('A custom page-file configuration was detected; monitor commit pressure and assess the size against the workload.'
                          if pressure else 'A custom page-file configuration was detected; there is no evidence to change the current setting.')
    else:
        severity = "unknown"
        recommendation = 'The page-file configuration could not be verified through Windows CIM; no assumption was made about the setting.'
    return {"mode": mode, "active": active, "automatic_managed": auto,
            "allocated_mb": allocated_mb, "commit_peak_pct": peak_pct,
            "commit_pressure": pressure, "severity": severity, "recommendation": recommendation,
            "wmi_status": info.get("status", "not_collected")}
PS_SENSORS = (
    "$s=Get-CimInstance -Namespace root/LibreHardwareMonitor -ClassName Sensor -ErrorAction SilentlyContinue; "
    "if(-not $s){$s=Get-CimInstance -Namespace root/OpenHardwareMonitor -ClassName Sensor -ErrorAction SilentlyContinue}; "
    "$w=@(); if($s){$w=@($s | Select-Object Name,SensorType,@{n='Value';e={[double]$_.Value}},Parent,@{n='source';e={'LibreHardwareMonitor/WMI'}})}; "
    "$a=Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue; "
    "$z=@(); if($a){$z=@($a | Select-Object @{n='SensorType';e={'ACPI_ThermalZone'}},InstanceName,CurrentTemperature)}; "
    "$all=@($w)+@($z); if($all.Count -gt 0){ConvertTo-Json -InputObject $all -Compress -Depth 4}"
)
PS_DISK_RELIABILITY = (r"$out=@(Get-PhysicalDisk -ErrorAction SilentlyContinue | ForEach-Object { $p=$_; "
    r"try { $c=Get-StorageReliabilityCounter -PhysicalDisk $p -ErrorAction Stop; "
    r"[pscustomobject]@{Name=[string]$p.FriendlyName;DeviceId=[string]$p.DeviceId;SerialNumber=[string]$p.SerialNumber; "
    r"Temperature= $(if($null -ne $c.Temperature){[double]$c.Temperature}else{$null}); "
    r"TemperatureMax= $(if($null -ne $c.TemperatureMax){[double]$c.TemperatureMax}else{$null}); "
    r"Wear= $(if($null -ne $c.Wear){[double]$c.Wear}else{$null}); "
    r"PowerOnHours= $(if($null -ne $c.PowerOnHours){[int64]$c.PowerOnHours}else{$null}); "
    r"ReadErrorsTotal= $(if($null -ne $c.ReadErrorsTotal){[int64]$c.ReadErrorsTotal}else{$null}); "
    r"WriteErrorsTotal= $(if($null -ne $c.WriteErrorsTotal){[int64]$c.WriteErrorsTotal}else{$null}); "
    r"ReadErrorsUncorrected= $(if($null -ne $c.ReadErrorsUncorrected){[int64]$c.ReadErrorsUncorrected}else{$null}); "
    r"WriteErrorsUncorrected= $(if($null -ne $c.WriteErrorsUncorrected){[int64]$c.WriteErrorsUncorrected}else{$null}); "
    r"StartStopCycleCount= $(if($null -ne $c.StartStopCycleCount){[int64]$c.StartStopCycleCount}else{$null}); "
    r"LoadUnloadCycleCount= $(if($null -ne $c.LoadUnloadCycleCount){[int64]$c.LoadUnloadCycleCount}else{$null})} } "
    r"catch { [pscustomobject]@{Name=[string]$p.FriendlyName;DeviceId=[string]$p.DeviceId;Error=$_.Exception.Message} } }); "
    r"ConvertTo-Json -InputObject $out -Compress -Depth 4")
PS_SECURITY = (r"$d=Get-MpComputerStatus -ErrorAction SilentlyContinue; "
    r"$f=@(Get-NetFirewallProfile -ErrorAction SilentlyContinue | Select-Object Name,Enabled); "
    r"$b=@(Get-BitLockerVolume -ErrorAction SilentlyContinue | Select-Object MountPoint,VolumeStatus,ProtectionStatus,EncryptionPercentage); "
    r"[pscustomobject]@{Defender=$(if($d){[pscustomobject]@{AntivirusEnabled=[bool]$d.AntivirusEnabled;RealTimeProtectionEnabled=[bool]$d.RealTimeProtectionEnabled; "
    r"AntivirusSignatureLastUpdated=[string]$d.AntivirusSignatureLastUpdated;AMServiceEnabled=[bool]$d.AMServiceEnabled}}else{$null});Firewall=$f;BitLocker=$b} "
    r"| ConvertTo-Json -Compress -Depth 5")
PS_DEVICES = (r"@(Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object {$_.Status -ne 'OK'} "
    r"| Select-Object -First 30 Class,FriendlyName,Status,InstanceId) | ConvertTo-Json -Compress -Depth 3")
PS_STARTUP = (r"@(Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue | Select-Object Name,Command,Location,User) "
    r"| ConvertTo-Json -Compress -Depth 3")
PS_UPDATES = (r"@(Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending "
              r"| Select-Object -First 12 HotFixID,InstalledOn,Description,InstalledBy) | ConvertTo-Json -Compress -Depth 3")
PS_DRIVERS = (r"@(Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue "
              r"| Where-Object {$_.DeviceClass -in @('DISPLAY','SCSIADAPTER','DISKDRIVE','NET','SYSTEM','MEDIA')} "
              r"| Select-Object -First 80 DeviceName,DeviceClass,DeviceID,DriverVersion,DriverDate,Manufacturer,InfName,IsSigned) "
              r"| ConvertTo-Json -Compress -Depth 3")
PS_BATTERY = (r"$s=@();$f=@();$c=@(); "
    r"try {$s=@(Get-CimInstance -Namespace root/wmi -ClassName BatteryStaticData -ErrorAction Stop "
    r"| Select-Object InstanceName,DeviceName,ManufactureName,Manufacturer,SerialNumber,DesignedCapacity,DesignedVoltage,Chemistry)} catch {}; "
    r"try {$f=@(Get-CimInstance -Namespace root/wmi -ClassName BatteryFullChargedCapacity -ErrorAction Stop "
    r"| Select-Object InstanceName,FullChargedCapacity)} catch {}; "
    r"try {$c=@(Get-CimInstance -Namespace root/wmi -ClassName BatteryCycleCount -ErrorAction Stop "
    r"| Select-Object InstanceName,CycleCount)} catch {}; "
    r"[pscustomobject]@{static=$s;full_charge=$f;cycles=$c} | ConvertTo-Json -Compress -Depth 4")
PS_HW_INVENTORY = (r"$ErrorActionPreference='SilentlyContinue'; "
    r"$cpu=@(Get-CimInstance Win32_Processor | Select-Object Name,Manufacturer,Architecture,Family,Model,Stepping,NumberOfCores,NumberOfLogicalProcessors,SocketDesignation,MaxClockSpeed,CurrentClockSpeed,L2CacheSize,L3CacheSize,VirtualizationFirmwareEnabled); "
    r"$mem=@(Get-CimInstance Win32_PhysicalMemory | Select-Object DeviceLocator,BankLabel,Capacity,SMBIOSMemoryType,MemoryType,FormFactor,Speed,ConfiguredClockSpeed,Manufacturer,PartNumber,SerialNumber,TotalWidth,DataWidth,Tag); "
    r"$arr=@(Get-CimInstance Win32_PhysicalMemoryArray | Select-Object Location,Use,MemoryErrorCorrection,MaxCapacity,MaxCapacityEx,MemoryDevices,Tag); "
    r"$board=@(Get-CimInstance Win32_BaseBoard | Select-Object Manufacturer,Product,Version,Model,Tag,Location); "
    r"$bios=@(Get-CimInstance Win32_BIOS | Select-Object Manufacturer,SMBIOSBIOSVersion,Version,ReleaseDate); "
    r"$display=@(Get-CimInstance Win32_VideoController | Select-Object Name,AdapterCompatibility,PNPDeviceID,AdapterRAM,DriverVersion,DriverDate,VideoProcessor,Status,Availability); "
    r"$pnpdisplay=@(Get-PnpDevice -Class Display -ErrorAction SilentlyContinue | Select-Object FriendlyName,Class,InstanceId,Status,Problem); "
    r"$drives=@(Get-CimInstance Win32_DiskDrive | Select-Object Index,Model,DeviceID,PNPDeviceID,SerialNumber,FirmwareRevision,Size,InterfaceType,MediaType,Status,Capabilities); "
    r"$physical=@(Get-PhysicalDisk | Select-Object FriendlyName,BusType,MediaType,Size,HealthStatus,OperationalStatus,SpindleSpeed,FirmwareVersion,DeviceId,SerialNumber); "
    r"$disks=@(Get-Disk -ErrorAction SilentlyContinue | Select-Object Number,FriendlyName,SerialNumber,UniqueId,Path,Location,BusType,PartitionStyle,OperationalStatus,HealthStatus,Size,IsBoot,IsSystem,IsOffline,IsReadOnly,NumberOfPartitions); "
    r"$virtual=@(Get-VirtualDisk -ErrorAction SilentlyContinue | Select-Object FriendlyName,UniqueId,Size,FootprintOnPool,ResiliencySettingName,OperationalStatus,HealthStatus,NumberOfColumns,NumberOfDataCopies); "
    r"$pools=@(Get-StoragePool -ErrorAction SilentlyContinue | Select-Object FriendlyName,UniqueId,IsPrimordial,HealthStatus,OperationalStatus,Size,AllocatedSize,NumberOfPhysicalDisks); "
    r"$optical=@(Get-CimInstance Win32_CDROMDrive | Select-Object Name,Drive,DeviceID,MediaType,Status); "
    r"$parts=@(Get-Partition -ErrorAction SilentlyContinue | Select-Object DiskNumber,PartitionNumber,DriveLetter,Size,Type,GptType,Guid,AccessPaths,IsBoot,IsSystem); "
    r"$volumes=@(Get-Volume -ErrorAction SilentlyContinue | Select-Object DriveLetter,FileSystemLabel,FileSystem,Size,SizeRemaining,HealthStatus,OperationalStatus,Path,UniqueId,DriveType); "
    r"$slots=@(Get-CimInstance Win32_SystemSlot | Select-Object SlotDesignation,SlotType,CurrentUsage,BusNumber,PCIDeviceID,Status); "
    r"$controllers=@(Get-PnpDevice -PresentOnly | Where-Object {$_.Class -match 'SCSIAdapter|HDC|Storage'} | Select-Object -First 200 FriendlyName,Class,InstanceId,Status); "
    r"$computer=Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model,SystemType,TotalPhysicalMemory,NumberOfProcessors,NumberOfLogicalProcessors; "
    r"[pscustomobject]@{processors=$cpu;memory_modules=$mem;memory_arrays=$arr;baseboards=$board;bios=$bios;displays=$display;pnp_display_devices=$pnpdisplay;disk_drives=$drives;physical_disks=$physical;storage_disks=$disks;virtual_disks=$virtual;storage_pools=$pools;optical_drives=$optical;partitions=$parts;volumes=$volumes;system_slots=$slots;controllers=$controllers;computer=$computer} | ConvertTo-Json -Compress -Depth 7")
PS_RELIABILITY = (r"$since=(Get-Date).AddDays(-30); $e=@(Get-WinEvent -FilterHashtable @{LogName='System';StartTime=$since;Level=1,2} -MaxEvents 500 -ErrorAction SilentlyContinue "
    r"| Where-Object {$_.ProviderName -match 'WHEA-Logger|BugCheck|Disk|Ntfs|stornvme|storahci|iaStor|volmgr'} "
    r"| Select-Object TimeCreated,ProviderName,Id,LevelDisplayName,Message); "
    r"$u=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WindowsUpdateClient/Operational';StartTime=$since;Level=2,3} -MaxEvents 200 -ErrorAction SilentlyContinue "
    r"| Select-Object TimeCreated,Id,LevelDisplayName,Message); "
    r"[pscustomobject]@{WindowDays=30;Count=$e.Count;WHEA=@($e|Where-Object {$_.ProviderName -match 'WHEA-Logger'}).Count; "
    r"BugCheck=@($e|Where-Object {$_.ProviderName -match 'BugCheck|volmgr'}).Count; "
    r"Storage=@($e|Where-Object {$_.ProviderName -match 'Disk|Ntfs|stornvme|storahci|iaStor'}).Count; "
    r"UpdateEvents=$u.Count;Latest=@($e|Select-Object -First 12);LatestUpdate=@($u|Select-Object -First 10)} | ConvertTo-Json -Compress -Depth 5")
def run_ps_batch() -> dict:
    'Runs PowerShell queries in parallel (a failure in one does not affect the others).'
    jobs = {"disks": PS_DISKS, "parts": PS_PARTS, "guard": PS_GUARD, "tpm": PS_TPM, "cpu_wmi": PS_CPUWMI,
            "sensors": PS_SENSORS, "disk_reliability": PS_DISK_RELIABILITY, "security": PS_SECURITY,
            "reliability": PS_RELIABILITY, "devices": PS_DEVICES, "startup": PS_STARTUP, "drivers": PS_DRIVERS,
            "battery": PS_BATTERY,
            "updates": PS_UPDATES, "hardware_inventory": PS_HW_INVENTORY}
    if not IS_WIN:
        return {}
    out = {}
    with cf.ThreadPoolExecutor(max_workers=len(jobs)) as ex:
        futs = {ex.submit(ps_json, s, 40): k for k, s in jobs.items()}
        for f in cf.as_completed(futs):
            out[futs[f]] = safe(f"PowerShell:{futs[f]}", f.result)
    return out
class ADLXGpuTemperatureProvider:
    def __init__(self) -> None:
        self.module = None
        self.helper = None
        self.performance = None
        self.gpus: list[Any] = []
        self._holder = None
        self._module_label = "ADLX"
        self.status = {"status": "optional_missing", "backend": "AMD ADLX", "temperature_count": 0,
                       "details": 'A compatible AMD ADLX Python binding was not found.'}
        if not IS_WINDOWS:
            self.status.update(status="unsupported", details='ADLX is attempted only in a Windows AMD driver environment.')
            return
        try:
            if _module_available("adlx"):
                self.module = importlib.import_module("adlx")
                namespace = getattr(self.module, "ADLX", self.module)
                self._module_label = "amd-adlx"
            elif _module_available("ADLXPybind"):
                self.module = importlib.import_module("ADLXPybind")
                namespace = self.module
                self._module_label = "ADLXPybind"
            else:
                return
            helper_type = getattr(namespace, "ADLXHelper", None)
            if helper_type is None:
                raise RuntimeError('The ADLXHelper class was not found in the binding')
            self.helper = helper_type()
            init_result = self.helper.Initialize()
            if not self._result_ok(init_result):
                raise RuntimeError(f"ADLX could not be initialized (result={init_result!r})")
            system = self._payload(self._first_call(self.helper, ("GetSystemServices", "getSystemServices")))
            if system is None:
                raise RuntimeError('ADLX system services could not be obtained')

            self.performance = self._payload(self._first_call(
                system, ("GetPerformanceMonitoringServices", "getPerformanceMonitoringServices")
            ))
            if self.performance is None:
                raise RuntimeError('The binding does not expose the ADLX Performance Monitoring service')
            gpu_result = self._first_call(system, ("GetGPUs", "getGPUs"))
            self.gpus = self._sequence_payload(gpu_result)
            if not self.gpus:
                holder_type = getattr(namespace, "ADLXGPUHolder", None)
                if holder_type is not None:
                    for args in ((system,), ()):
                        try:
                            self._holder = holder_type(*args)
                            break
                        except TypeError:
                            continue
                    if self._holder is not None:
                        self.gpus = self._sequence_payload(self._first_call(
                            self._holder, ("getGPUList", "GetGPUList")
                        ))
            if not self.gpus:
                raise RuntimeError('The ADLX GPU list could not be obtained or is empty')
            self.status = {"status": "ready", "backend": self._module_label,
                           "temperature_count": 0,
                           "details": f"ADLX GPU adedi={len(self.gpus)}; edge/hotspot support will be checked per adapter."}
        except Exception as exc:
            self.status = {"status": "unavailable", "backend": self._module_label,
                           "temperature_count": 0, "details": f"{type(exc).__name__}: {exc}"}
            self.close()
    @staticmethod
    def _first_call(obj: Any, names: tuple[str, ...], *args):
        if obj is None:
            return None
        for name in names:
            member = getattr(obj, name, None)
            if callable(member):
                try:
                    return member(*args)
                except TypeError:
                    continue
        return None
    @staticmethod
    def _payload(value: Any) -> Any:
        if isinstance(value, tuple) and len(value) >= 2:
            for item in reversed(value):
                if not isinstance(item, (bool, int, float, str, bytes)):
                    return item
        return value
    @classmethod
    def _sequence_payload(cls, value: Any) -> list:
        value = cls._payload(value)
        if value is None:
            return []
        if isinstance(value, (list, tuple)):
            return list(value)
        try:
            return list(value)
        except TypeError:
            return [value]
    @staticmethod
    def _result_ok(value: Any) -> bool:
        if isinstance(value, tuple):
            value = value[0] if value else None
        if value is None or value is True:
            return True
        enum_name = getattr(value, "name", None)
        if enum_name is not None:
            return str(enum_name).casefold().rsplit(".", 1)[-1] == "adlx_ok"
        try:
            return int(getattr(value, "value", value)) == 0
        except (TypeError, ValueError, OverflowError):
            return str(value).casefold().rsplit(".", 1)[-1] == "adlx_ok"
    @staticmethod
    def _bool_payload(value: Any) -> bool | None:
        if isinstance(value, bool):
            return value
        if isinstance(value, tuple):
            for item in reversed(value):
                if isinstance(item, bool):
                    return item
        return None
    @staticmethod
    def _number_payload(value: Any) -> float | None:
        candidates = reversed(value) if isinstance(value, tuple) else (value,)
        for item in candidates:
            if isinstance(item, (int, float)) and not isinstance(item, bool):
                number = float(item)
                if math.isfinite(number) and 0.0 < number <= 200.0:
                    return number
        return None
    @staticmethod
    def _gpu_name(gpu: Any, index: int) -> str:
        for name in ("Name", "name", "getName", "GetName", "Model", "model"):
            member = getattr(gpu, name, None)
            try:
                value = member() if callable(member) else member
            except Exception:
                value = None
            if value:
                return str(value)
        return f"AMD GPU {index + 1}"
    def read_temperatures(self) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        rows = []
        if self.performance is None:
            return rows, dict(self.status)
        timestamp = dt.datetime.now().astimezone().isoformat(timespec="milliseconds")
        for index, gpu in enumerate(self.gpus):
            name = self._gpu_name(gpu, index)
            support = self._payload(self._first_call(
                self.performance, ("GetSupportedGPUMetrics", "getSupportedGPUMetrics"), gpu
            ))
            metrics = self._payload(self._first_call(
                self.performance, ("GetCurrentGPUMetrics", "getCurrentGPUMetrics"), gpu
            ))
            if metrics is None:
                continue
            for sensor_name, support_method, metric_method in (
                ("GPU edge temperature", "IsSupportedGPUTemperature", "GPUTemperature"),
                ("GPU hotspot temperature", "IsSupportedGPUHotspotTemperature", "GPUHotspotTemperature"),
            ):
                supported = (self._bool_payload(self._first_call(support, (support_method,)))
                             if support is not None else None)
                if supported is False:
                    continue
                value = self._number_payload(self._first_call(metrics, (metric_method,)))
                if value is None:
                    continue
                row = normalize_temperature(
                    "Temperature", sensor_name, name, value, f"AMD ADLX/{self._module_label}",
                    hardware_type="GPU", sensor_identifier=f"adlx:{index}:{metric_method}",
                    timestamp=timestamp,
                )
                if row:
                    rows.append(row)
        self.status = {"status": "available" if rows else "unsupported_or_empty",
                       "backend": self._module_label, "temperature_count": len(rows),
                       "details": (f"{len(rows)} GPU edge/hotspot temperature channel was obtained through ADLX."
                                   if rows else 'ADLX started, but the driver did not expose edge/hotspot temperature metrics.')}
        return rows, dict(self.status)
    def close(self) -> None:
        helper, self.helper = self.helper, None
        self.performance = None
        self.gpus = []
        self._holder = None
        if helper is not None:
            try:
                helper.Terminate()
            except Exception:
                pass
def probe_adlx_gpu_temperatures() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    provider = ADLXGpuTemperatureProvider()
    try:
        return provider.read_temperatures()
    except Exception as exc:
        return [], {"status": "failed", "backend": "ADLXPybind", "temperature_count": 0,
                    "details": f"{type(exc).__name__}: {exc}"}
    finally:
        provider.close()
def collect_sensor_snapshot(
    elapsed_s: float | None = None,
    sample_gpu: bool = True,
    sensor_provider: LibreHardwareMonitorProvider | None = None,
    adlx_provider: ADLXGpuTemperatureProvider | None = None,
) -> dict:
    raw_sensors = []
    if IS_WIN and (shutil.which("powershell.exe") or shutil.which("pwsh.exe")):
        try:
            windows_sensor_rows = as_list(ps_json(PS_SENSORS, timeout=6))
            for raw_row in windows_sensor_rows:
                if isinstance(raw_row, Mapping) and str(raw_row.get("SensorType", "")).casefold() == "acpi_thermalzone":
                    raw_sensors.extend(normalize_windows_acpi_thermal_zones([raw_row]))
                else:
                    raw_sensors.append(raw_row)
        except Exception as exc:
            sensor_wmi_error = f"{type(exc).__name__}: {exc}"
        else:
            sensor_wmi_error = None
    else:
        sensor_wmi_error = None

    if psutil is not None and hasattr(psutil, "sensors_temperatures"):
        try:
            readings = psutil.sensors_temperatures(fahrenheit=False) or {}
            for chip, entries in readings.items():
                for entry in entries or []:
                    value = getattr(entry, "current", None)
                    if value is not None:
                        raw_sensors.append({
                            "SensorType": "Temperature",
                            "Name": getattr(entry, "label", None) or str(chip),
                            "Parent": str(chip),
                            "Value": value,
                            "source": "psutil.sensors_temperatures",
                        })
        except Exception:
            pass
    sensors, provider_status = collect_sensor_readings(raw_sensors, sensor_provider=sensor_provider)
    adlx_status = {"status": "not_attempted", "backend": "ADLXPybind", "temperature_count": 0}
    if adlx_provider is not None:
        try:
            adlx_rows, adlx_status = adlx_provider.read_temperatures()
            known = {(str(row.get("Parent", "")).casefold(), str(row.get("Name", "")).casefold(),
                      str(row.get("SensorIdentifier") or "").casefold()) for row in sensors}
            for row in adlx_rows:
                key = (str(row.get("Parent", "")).casefold(), str(row.get("Name", "")).casefold(),
                       str(row.get("SensorIdentifier") or "").casefold())
                if key not in known:
                    sensors.append(row)
                    known.add(key)
        except Exception as exc:
            adlx_status = {"status": "failed", "backend": "ADLXPybind", "temperature_count": 0,
                           "details": f"{type(exc).__name__}: {exc}"}
    if adlx_provider is not None:
        provider_status = dict(provider_status)
        provider_status.setdefault("additional_providers", []).append(adlx_status)
        temperature_rows = [row for row in sensors if str(row.get("SensorType", "")).casefold() == "temperature"]
        provider_status["temperature_count"] = len(temperature_rows)
        provider_status["hardware_types"] = sorted({str(row.get("HardwareType") or "Unknown") for row in temperature_rows})
        provider_status["sources"] = sorted({str(row.get("source") or "Unknown") for row in temperature_rows})
    if sensor_wmi_error:
        provider_status = dict(provider_status)
        provider_status.setdefault("wmi_error", sensor_wmi_error)
    cpu_percent = memory_percent = None
    disk_io = None
    battery = None
    if psutil is not None:
        try:
            cpu_percent = psutil.cpu_percent(interval=None)
        except Exception:
            pass
        try:
            memory_percent = psutil.virtual_memory().percent
        except Exception:
            pass
        try:
            counters = psutil.disk_io_counters(perdisk=False)
            if counters:
                disk_io = {"read_bytes": getattr(counters, "read_bytes", None),
                           "write_bytes": getattr(counters, "write_bytes", None),
                           "read_count": getattr(counters, "read_count", None),
                           "write_count": getattr(counters, "write_count", None)}
        except Exception:
            pass
        if hasattr(psutil, "sensors_battery"):
            try:
                item = psutil.sensors_battery()
                if item:
                    battery = {"percent": getattr(item, "percent", None),
                               "plugged": getattr(item, "power_plugged", None),
                               "seconds_left": getattr(item, "secsleft", None)}
            except Exception:
                pass
    gpus = nvml_live() if sample_gpu else []
    return {"timestamp": dt.datetime.now().astimezone().isoformat(timespec="milliseconds"),
            "elapsed_s": round(float(elapsed_s), 3) if elapsed_s is not None else None,
            "sensors": sensors, "sensor_provider": provider_status, "gpus": gpus,
            "cpu_percent": cpu_percent, "memory_percent": memory_percent,
            "disk_io": disk_io, "battery": battery}
class SensorSampler:
    def __init__(self, interval_s: float = 1.5, sample_gpu: bool = False,
                 critical_cpu_c: float = 100.0, critical_gpu_c: float = 95.0,
                 duration_s: float | None = None):
        self.interval_s = max(0.5, float(interval_s))
        self.sample_gpu = bool(sample_gpu)
        self.critical_cpu_c = float(critical_cpu_c)
        self.critical_gpu_c = float(critical_gpu_c)
        self.duration_s = None if duration_s is None else max(0.5, float(duration_s))
        self.samples = []
        self._stop = threading.Event()
        self._started_event = threading.Event()
        self._finished_event = threading.Event()
        self.abort_requested = threading.Event()
        self._thread = None
        self._thread_started_at = None
        self._started_at = None
        self.startup_error: str | None = None
        self.runtime_error: str | None = None
        self.shutdown_timed_out = False
        self._sensor_provider: LibreHardwareMonitorProvider | None = None
        self._adlx_provider: ADLXGpuTemperatureProvider | None = None
    @property
    def started_at(self) -> float | None:
        return self._started_at
    @property
    def startup_delay_s(self) -> float | None:
        if self._thread_started_at is None or self._started_at is None:
            return None
        return max(0.0, self._started_at - self._thread_started_at)
    def wait_until_started(self, timeout: float | None = None) -> bool:
        if self._thread is None:
            return False
        if not self._started_event.wait(timeout):
            return False
        return self._started_at is not None
    def wait_until_finished(self, timeout: float | None = None) -> bool:
        if self._thread is None:
            return True
        return self._finished_event.wait(timeout)
    def _run(self):
        self._thread_started_at = time.perf_counter()
        try:
            try:
                if psutil is not None:
                    psutil.cpu_percent(interval=None)
            except (OSError, RuntimeError):
                pass
            if IS_WIN:
                self._sensor_provider = LibreHardwareMonitorProvider()
                self._adlx_provider = ADLXGpuTemperatureProvider()
            self._started_at = time.perf_counter()
            self._started_event.set()
            next_sample_at = self._started_at
            while not self._stop.is_set():
                now = time.perf_counter()
                elapsed = max(0.0, now - self._started_at)
                if self.duration_s is not None and elapsed >= self.duration_s:
                    break
                elapsed = round(elapsed, 3)
                try:
                    snapshot = collect_sensor_snapshot(
                        elapsed, sample_gpu=self.sample_gpu, sensor_provider=self._sensor_provider,
                        adlx_provider=self._adlx_provider
                    )
                except Exception as exc:
                    snapshot = {"timestamp": dt.datetime.now().astimezone().isoformat(timespec="milliseconds"),
                                "elapsed_s": elapsed, "sensors": [], "sensor_provider": {
                                    "status": "failed", "details": f"{type(exc).__name__}: {exc}"},
                                "gpus": [], "cpu_percent": None, "memory_percent": None,
                                "disk_io": None, "battery": None,
                                "sampling_error": f"{type(exc).__name__}: {exc}"}
                self.samples.append(snapshot)
                wmi_readings = snapshot.get("sensors") or []
                gpu_readings = snapshot.get("gpus") or []
                for sensor in wmi_readings:
                    try:
                        if str(sensor.get("SensorType", "")).lower() != "temperature" or sensor.get("Value") is None:
                            continue
                        name = f"{sensor.get('Parent', '')} {sensor.get('Name', '')}".lower()
                        limit = self.critical_gpu_c if "gpu" in name or "graphics" in name else self.critical_cpu_c
                        if float(sensor["Value"]) >= limit:
                            self.abort_requested.set()
                    except (TypeError, ValueError, AttributeError):
                        continue
                for gpu in gpu_readings:
                    try:
                        if gpu.get("temp") is not None and float(gpu["temp"]) >= self.critical_gpu_c:
                            self.abort_requested.set()
                    except (TypeError, ValueError, AttributeError):
                        continue
                next_sample_at += self.interval_s
                now = time.perf_counter()
                if next_sample_at < now:
                    next_sample_at = now
                self._stop.wait(max(0.0, next_sample_at - now))
        except Exception as exc:
            message = f"{type(exc).__name__}: {exc}"
            if self._started_at is None:
                self.startup_error = message
            else:
                self.runtime_error = message
        finally:
            self._started_event.set()
            if self._sensor_provider is not None:
                try:
                    self._sensor_provider.close()
                except Exception as exc:
                    if self.runtime_error is None:
                        self.runtime_error = f"provider close {type(exc).__name__}: {exc}"
            if self._adlx_provider is not None:
                try:
                    self._adlx_provider.close()
                except Exception as exc:
                    if self.runtime_error is None:
                        self.runtime_error = f"ADLX provider close {type(exc).__name__}: {exc}"
            self._finished_event.set()
    def start(self) -> bool:
        if psutil is None:
            return False
        self._thread = threading.Thread(target=self._run, name="system-sensor-sampler", daemon=True)
        self._thread.start()
        return True
    def finish(self) -> list:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=15)
            self.shutdown_timed_out = self._thread.is_alive()
        return list(self.samples)
def collect_storage_static(ps: dict) -> dict:
    vols = []
    for p in psutil.disk_partitions(all=False):
        if IS_WIN and ("cdrom" in p.opts or "remote" in p.opts or not p.fstype):
            continue
        try:
            u = psutil.disk_usage(p.mountpoint)
        except OSError:
            continue
        vols.append({"mount": p.mountpoint, "fs": p.fstype, "total": u.total, "used": u.used, "free": u.free, "pct": u.percent})
    letter_to_disk = {str(x.get("Drive", "")).upper(): str(x.get("Disk")) for x in as_list((ps or {}).get("parts"))}
    disks = []
    for x in as_list((ps or {}).get("disks")):
        letters = sorted(l for l, dn in letter_to_disk.items() if dn == str(x.get("Id")))
        media, bus = str(x.get("Media") or ""), str(x.get("Bus") or "")
        kind = ("NVMe SSD" if bus.lower() == "nvme" else "SSD" if media.upper() == "SSD" else
                "HDD" if media.upper() == "HDD" else f"{bus or '?'} ({media or 'unknown type'})")
        disks.append({"name": x.get("Name"), "kind": kind, "bus": bus, "media": media, "size": x.get("Size"),
                      "health": x.get("Health"), "status": x.get("Op"), "spindle": x.get("Spindle"),
                      "logical_sector_size": x.get("LSect"), "physical_sector_size": x.get("PSect"),
                      "firmware_version": x.get("Firmware"), "drives": letters, "id": x.get("Id")})
    return {"volumes": vols, "disks": disks}
def collect_network_static() -> list:
    out = []
    try:
        counters = psutil.net_io_counters(pernic=True) or {}
    except (AttributeError, OSError, psutil.Error if psutil is not None else OSError):
        counters = {}
    for name, st in psutil.net_if_stats().items():
        if not st.isup:
            continue
        c = counters.get(name)
        item = {"name": name, "speed_mbps": st.speed or None, "mtu": st.mtu}
        if c:
            item.update({"bytes_sent": c.bytes_sent, "bytes_recv": c.bytes_recv,
                         "packets_sent": c.packets_sent, "packets_recv": c.packets_recv,
                         "errors_in": c.errin, "errors_out": c.errout,
                         "drops_in": c.dropin, "drops_out": c.dropout})
        out.append(item)
    return out
def measure_network(host="1.1.1.1", dns_host="example.com", count=5, timeout_ms=1500, speed_test=False) -> dict:
    'Optional latency/loss/jitter and DNS measurements; network packets are sent only when requested by the user.'
    count = max(1, min(int(count), 20))
    timeout_ms = max(250, min(int(timeout_ms), 10000))
    result = {"target": host, "count": count, "rtt_ms": [], "loss_pct": None, "jitter_ms": None,
              "min_ms": None, "avg_ms": None, "max_ms": None, "dns_host": dns_host, "dns_ms": None,
              "dns_addresses": [], "error": None, "download_mbps": None, "upload_mbps": None,
              "speed_test_bytes": {"download": 0, "upload": 0}}
    try:
        t0 = time.perf_counter()
        infos = socket.getaddrinfo(dns_host, None, type=socket.SOCK_STREAM)
        result["dns_ms"] = (time.perf_counter() - t0) * 1000
        result["dns_addresses"] = sorted({x[4][0] for x in infos})[:8]
    except (OSError, socket.gaierror) as exc:
        result["dns_error"] = f"{type(exc).__name__}: {exc}"
    if IS_WIN:
        args = ["ping", "-n", str(count), "-w", str(timeout_ms), host]
    else:
        args = ["ping", "-c", str(count), "-W", str(max(1, math.ceil(timeout_ms / 1000))), host]
    rc, output = run_cmd(args, timeout=max(5, count * (timeout_ms / 1000 + 1) + 3))
    if rc < 0:
        result["error"] = 'The ping command could not be run'
        output = ""
    times = [float(x) for x in re.findall(r"time=\s*([0-9]+(?:\.[0-9]+)?)\s*ms", output, re.I)]
    times.extend([0.5] * len(re.findall(r"time<1\s*ms", output, re.I)))
    times = times[:count]
    result["rtt_ms"] = times
    result["loss_pct"] = max(0.0, 100.0 * (count - len(times)) / count)
    if times:
        result["min_ms"], result["avg_ms"], result["max_ms"] = min(times), sum(times) / len(times), max(times)
        result["jitter_ms"] = (sum(abs(b-a) for a, b in zip(times, times[1:])) / (len(times)-1)) if len(times) > 1 else 0.0
    if not times:
        result["error"] = 'No ping response was received; ICMP may be blocked.'
    if speed_test:
        base = "https://speed.cloudflare.com"
        download_bytes = 5 * MIB
        upload_bytes = 1 * MIB
        try:
            req = urllib.request.Request(f"{base}/__down?bytes={download_bytes}", headers={"User-Agent": "yigitsapa-system-analyses/" + __version__})
            t0 = time.perf_counter()
            with urllib.request.urlopen(req, timeout=20) as response:
                received = 0
                while True:
                    chunk = response.read(256 * 1024)
                    if not chunk:
                        break
                    received += len(chunk)
            elapsed = max(time.perf_counter() - t0, 1e-6)
            result["download_mbps"] = received * 8 / elapsed / 1e6
            result["speed_test_bytes"]["download"] = received
        except (OSError, urllib.error.URLError, TimeoutError) as exc:
            result["download_error"] = f"{type(exc).__name__}: {exc}"
        try:
            body = os.urandom(upload_bytes)
            req = urllib.request.Request(f"{base}/__up", data=body, method="POST",
                                         headers={"Content-Type": "application/octet-stream", "User-Agent": "yigitsapa-system-analyses/" + __version__})
            t0 = time.perf_counter()
            with urllib.request.urlopen(req, timeout=20) as response:
                response.read(1024)
            elapsed = max(time.perf_counter() - t0, 1e-6)
            result["upload_mbps"] = upload_bytes * 8 / elapsed / 1e6
            result["speed_test_bytes"]["upload"] = upload_bytes
        except (OSError, urllib.error.URLError, TimeoutError) as exc:
            result["upload_error"] = f"{type(exc).__name__}: {exc}"
    return result
def memory_integrity_smoke_test(size_mib: int, passes: int = 2) -> dict:
    'A low-risk, page-sampled check in allocated memory; it is not a substitute for MemTest86 or ECC testing.'
    if psutil is None:
        return {"error": "psutil is required"}
    if size_mib < 16:
        return {"error": 'test size must be at least 16 MiB'}
    available = int(psutil.virtual_memory().available)
    reserve = 1 * GIB
    requested = min(int(size_mib) * MIB, 256 * MIB, max(0, available - reserve))
    requested = requested // MIB * MIB
    if requested < 16 * MIB:
        return {"error": 'Not enough free RAM could be allocated while preserving the operating-system reserve'}
    passes = max(1, min(int(passes), 4))
    buf = bytearray(requested)
    ptr = ctypes.addressof(ctypes.c_ubyte.from_buffer(buf))
    checked = 0
    started = time.perf_counter()
    patterns = (0x00, 0xFF, 0xAA, 0x55)
    for p in patterns[:passes]:
        ctypes.memset(ptr, p, requested)
        for offset in range(0, requested, 4096):
            if buf[offset] != p:
                return {"passed": False, "error": f"sample mismatch, offset={offset}",
                        "tested_bytes": requested, "checked_samples": checked, "elapsed_s": time.perf_counter()-started}
            checked += 1
        if buf[-1] != p:
            return {"passed": False, "error": 'last-byte mismatch', "tested_bytes": requested,
                    "checked_samples": checked, "elapsed_s": time.perf_counter()-started}
        checked += 1
    return {"passed": True, "tested_bytes": requested, "checked_samples": checked,
            "patterns": list(patterns[:passes]), "elapsed_s": time.perf_counter()-started,
            "note": 'page-sampled smoke test; not a full memory-stability certification'}
def bench_gpu_torch(seconds: float = 2.0, sensor_sampling: bool = False) -> dict:
    'Optional PyTorch CUDA or DirectML matrix multiplication; dependencies are not installed automatically.'
    try:
        import torch
    except ImportError:
        return {"available": False, "reason": 'PyTorch is not installed; it must be installed separately for GPU testing'}
    try:
        free_bytes = total_bytes = None
        torch_directml = None
        if torch.cuda.is_available():
            device = torch.device("cuda")
            backend = "PyTorch CUDA"
            device_name = torch.cuda.get_device_name(0)
            free_bytes, total_bytes = (int(x) for x in torch.cuda.mem_get_info())
            budget = min(int(free_bytes * 0.10), 256 * MIB)
            def synchronize(tensor=None):
                torch.cuda.synchronize()
        else:
            try:
                import torch_directml as torch_directml_module
                torch_directml = torch_directml_module
                device = torch_directml.device()
                backend = "PyTorch DirectML"
                device_name = 'Default DirectML device'
                budget = 48 * MIB
                def synchronize(tensor=None):
                    if tensor is not None:
                        _ = tensor[0, 0].item()
            except ImportError:
                return {"available": False, "reason": 'No CUDA device is available and torch-directml is not installed'}
        n = max(256, min(2048 if backend.endswith("CUDA") else 1024, int(math.sqrt(max(1, budget) / 12))))
        a = torch.randn((n, n), device=device, dtype=torch.float32)
        b = torch.randn((n, n), device=device, dtype=torch.float32)
        for _ in range(3):
            c = a @ b
        synchronize(c)
        end = time.perf_counter() + max(0.5, min(float(seconds), 10.0))
        iterations = 0
        sampler = SensorSampler(sample_gpu=True, critical_gpu_c=95.0) if sensor_sampling else None
        if sampler:
            sampler.start()
        started = time.perf_counter()
        try:
            while time.perf_counter() < end:
                for _ in range(5):
                    c = a @ b
                    iterations += 1
                    if sampler and sampler.abort_requested.is_set():
                        break
                synchronize(c)
                if sampler and sampler.abort_requested.is_set():
                    break
        finally:
            elapsed = time.perf_counter() - started
            thermal_series = sampler.finish() if sampler else []
        flops = iterations * 2.0 * n**3
        out = {"available": True, "backend": backend, "device": device_name,
               "matrix_size": n, "iterations": iterations, "elapsed_s": elapsed,
               "gflops": flops / max(elapsed, 1e-9) / 1e9,
               "thermal_series": thermal_series,
               "thermal_sampling_available": bool(thermal_series),
               "safety_abort": bool(sampler and sampler.abort_requested.is_set()),
               "note": ('The test was stopped early because a thermal threshold was observed; ' if sampler and sampler.abort_requested.is_set() else "") +
                       'FP32 matrix multiplication; it is not representative of games or every GPU workload' +
                       ('; no thermal sample was obtained in this run, so a safe temperature could not be verified' if sensor_sampling and not thermal_series else "") +
                       ('; load safety could not be verified automatically because no thermal sensor source was found' if not sensor_sampling else "")}
        if free_bytes is not None:
            out["vram_free_before"], out["vram_total"] = free_bytes, total_bytes
        return out
    except Exception as exc:
        return {"available": False, "error": f"{type(exc).__name__}: {exc}"}
def bench_video_encoders(seconds: float = 3.0) -> dict:
    exe = shutil.which("ffmpeg")
    if not exe:
        return {"available": False, "reason": 'FFmpeg was not found; no automatic installation was performed'}
    try:
        probe = subprocess.run([exe, "-hide_banner", "-encoders"], capture_output=True, text=True,
                               errors="replace", timeout=10, creationflags=0x08000000 if IS_WIN else 0)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"available": False, "reason": f"Could not read FFmpeg encoder list: {type(exc).__name__}: {exc}"}
    listing = (probe.stdout or "") + "\n" + (probe.stderr or "")
    preferred = ("h264_nvenc", "h264_amf", "h264_qsv", "libx264")
    available = [name for name in preferred if re.search(r"\b" + re.escape(name) + r"\b", listing)]
    if not available:
        return {"available": False, "reason": 'No H.264 encoder was found; check the FFmpeg build components'}
    frames = max(15, min(300, int(round(max(0.5, min(float(seconds), 10.0)) * 30))))
    results = []
    for encoder in available:
        command = [exe, "-hide_banner", "-loglevel", "error", "-f", "lavfi", "-i",
                   "testsrc2=size=1280x720:rate=30", "-frames:v", str(frames), "-an", "-c:v", encoder]
        if encoder == "libx264":
            command += ["-preset", "veryfast", "-threads", "0"]
        command += ["-f", "null", ("NUL" if IS_WIN else os.devnull)]
        started = time.perf_counter()
        try:
            cp = subprocess.run(command, capture_output=True, text=True, errors="replace",
                                timeout=max(15, min(70, float(seconds) * 6 + 10)),
                                creationflags=0x08000000 if IS_WIN else 0)
            elapsed = max(time.perf_counter() - started, 1e-6)
            ok = cp.returncode == 0
            results.append({"encoder": encoder, "passed": ok, "frames": frames, "elapsed_s": elapsed,
                            "fps": frames / elapsed if ok else None,
                            "realtime_factor": (frames / elapsed / 30.0) if ok else None,
                            "error": (cp.stderr or "").strip()[-1200:] if not ok else None})
        except (OSError, subprocess.SubprocessError) as exc:
            results.append({"encoder": encoder, "passed": False, "frames": frames, "elapsed_s": time.perf_counter()-started,
                            "fps": None, "realtime_factor": None, "error": f"{type(exc).__name__}: {exc}"})
    return {"available": any(x["passed"] for x in results), "ffmpeg": exe, "width": 1280, "height": 720,
            "target_fps": 30, "frames_per_encoder": frames, "encoders": results,
            "note": 'A synthetic testsrc2 source is used; no output file is created. The result applies only to the tested FFmpeg encoder path.'}
PDH_ARRAYS = {
    "cpu_perf": r"\Processor Information(*)\% Processor Performance",
    "cpu_freq": r"\Processor Information(*)\Processor Frequency",
    "cpu_park": r"\Processor Information(*)\Parking Status",
    "gpu_eng": r"\GPU Engine(*)\Utilization Percentage",
    "gpu_ded": r"\GPU Adapter Memory(*)\Dedicated Usage",
    "gpu_shr": r"\GPU Adapter Memory(*)\Shared Usage",
    "gpu_proc": r"\GPU Process Memory(*)\Dedicated Usage",
}
PDH_SINGLES = {
    "dpc": r"\Processor Information(_Total)\% DPC Time",
    "intr": r"\Processor Information(_Total)\% Interrupt Time",
    "priv": r"\Processor Information(_Total)\% Privileged Time",
    "queue": r"\System\Processor Queue Length",
    "ctx": r"\System\Context Switches/sec",
    "syscalls": r"\System\System Calls/sec",
    "mem_avail": r"\Memory\Available Bytes",
    "mem_free": r"\Memory\Free & Zero Page List Bytes",
    "mem_modified": r"\Memory\Modified Page List Bytes",
    "mem_sb_normal": r"\Memory\Standby Cache Normal Priority Bytes",
    "mem_sb_reserve": r"\Memory\Standby Cache Reserve Bytes",
    "mem_sb_core": r"\Memory\Standby Cache Core Bytes",
    "mem_commit": r"\Memory\Committed Bytes",
    "mem_commit_limit": r"\Memory\Commit Limit",
    "mem_faults": r"\Memory\Page Faults/sec",
    "mem_pages_in": r"\Memory\Pages Input/sec",
    "mem_pages_out": r"\Memory\Pages Output/sec",
    "mem_pool_paged": r"\Memory\Pool Paged Bytes",
    "mem_pool_nonpaged": r"\Memory\Pool Nonpaged Bytes",
    "pagefile": r"\Paging File(_Total)\% Usage",
    "disk_busy": r"\PhysicalDisk(_Total)\% Disk Time",
    "disk_queue": r"\PhysicalDisk(_Total)\Avg. Disk Queue Length",
    "disk_rd": r"\PhysicalDisk(_Total)\Disk Read Bytes/sec",
    "disk_wr": r"\PhysicalDisk(_Total)\Disk Write Bytes/sec",
    "disk_lat_r": r"\PhysicalDisk(_Total)\Avg. Disk sec/Read",
    "disk_lat_w": r"\PhysicalDisk(_Total)\Avg. Disk sec/Write",
}
_GPU_ENG_RX = re.compile(r"luid_(0x[0-9a-f]+_0x[0-9a-f]+)_phys_\d+_eng_(\d+)_engtype_([A-Za-z0-9_]+)", re.I)
_LUID_RX = re.compile(r"luid_(0x[0-9a-f]+_0x[0-9a-f]+)", re.I)
_PID_RX = re.compile(r"pid_(\d+)", re.I)
def _mean(vals):
    v = [x for x in vals if x is not None]
    return sum(v) / len(v) if v else None
def _cpu_instances(arr: dict) -> list:
    "Sorts 'group,processor' samples by logical-processor order ('_Total' is skipped)."
    items = []
    for name, v in arr.items():
        m = re.fullmatch(r"(\d+),(\d+)", name.strip())
        if m:
            items.append(((int(m.group(1)), int(m.group(2))), v))
    items.sort()
    return [v for _, v in items]
def _mean_lists(lists):
    lists = [l for l in lists if l]
    if not lists:
        return []
    n = min(len(l) for l in lists)
    return [sum(l[i] for l in lists) / len(lists) for i in range(n)]
def gpu_engine_summary(arr: dict) -> dict:
    eng = {}
    for name, v in arr.items():
        m = _GPU_ENG_RX.search(name)
        if m:
            key = (m.group(1).lower(), m.group(2), m.group(3))
            eng[key] = eng.get(key, 0.0) + v
    out = {}
    for (luid, _idx, typ), v in eng.items():
        d = out.setdefault("luid_" + luid, {"max": 0.0, "by_type": {}})
        v = min(100.0, v)
        d["max"] = max(d["max"], v)
        d["by_type"][typ] = max(d["by_type"].get(typ, 0.0), v)
    return out
def gpu_mem_summary(ded: dict, shr: dict) -> dict:
    out = {}
    for kind, arr in (("dedicated", ded), ("shared", shr)):
        for name, v in arr.items():
            m = _LUID_RX.search(name)
            if m:
                out.setdefault("luid_" + m.group(1).lower(), {})[kind] = v
    return out
def gpu_proc_top(arr: dict, topn=5) -> list:
    by_pid = {}
    for name, v in arr.items():
        m = _PID_RX.search(name)
        if m:
            by_pid[int(m.group(1))] = by_pid.get(int(m.group(1)), 0.0) + v
    rows = []
    for pid, v in sorted(by_pid.items(), key=lambda kv: -kv[1])[:topn]:
        if v <= 0:
            continue
        try:
            nm = psutil.Process(pid).name()
        except Exception:
            nm = "?"
        rows.append({"pid": pid, "name": nm, "vram": v})
    return rows
class CpuFreqReader:
    "Per-processor actual frequency: use wildcard (*) samples first, then individual '0,i' samples, or empty if neither is available."
    def __init__(self, pdh, n_logical):
        self.p, self.n = pdh, n_logical
        a, b = pdh.add("cpu_perf", PDH_ARRAYS["cpu_perf"]), pdh.add("cpu_freq", PDH_ARRAYS["cpu_freq"])
        self.wild = bool(a and b)
        ok = 0
        if 0 < n_logical <= 64:
            for i in range(n_logical):
                x = pdh.add(f"xperf{i}", rf"\Processor Information(0,{i})\% Processor Performance")
                y = pdh.add(f"xfreq{i}", rf"\Processor Information(0,{i})\Processor Frequency")
                ok += int(bool(x and y))
        self.explicit = n_logical > 0 and ok == n_logical
    def read(self):
        P = self.p
        perf, nom = _cpu_instances(P.array("cpu_perf")), _cpu_instances(P.array("cpu_freq"))
        if perf and nom:
            return perf, nom, 'PDH (wildcard samples)'
        if self.explicit:
            perf = [P.value(f"xperf{i}") for i in range(self.n)]
            nom = [P.value(f"xfreq{i}") for i in range(self.n)]
            if all(v is not None for v in perf + nom):
                return perf, nom, 'PDH (individual samples)'
        return [], [], None
def psutil_freq_list(n):
    'If PDH is unavailable, use psutil: on Windows it returns one value, which is applied to all logical processors.'
    try:
        fr = psutil.cpu_freq(percpu=True)
    except Exception:
        return None, None
    if not fr:
        return None, None
    n = n or len(fr)
    cur = [x.current for x in fr]
    mx = [(x.max or x.current) for x in fr]
    if len(cur) < n:
        cur, mx = (cur * n)[:n], (mx * n)[:n]
    return cur, mx
class Telemetry:
    'Periodic sampling with psutil + PDH; produces average/peak values.'
    def __init__(self):
        self.pdh = None
        self.freq_reader = None
        self.missing = []
        if IS_WIN:
            try:
                self.pdh = Pdh()
                for k, p in {**PDH_ARRAYS, **PDH_SINGLES}.items():
                    if k in ("cpu_perf", "cpu_freq"):
                        continue
                    if not self.pdh.add(k, p):
                        self.missing.append(k)
                self.freq_reader = CpuFreqReader(self.pdh, psutil.cpu_count() or 0)
                if not self.freq_reader.wild:
                    self.missing.append("cpu_perf/cpu_freq (joker)")
            except Exception as exc:
                warn('PDH could not be initialized', exc)
                self.pdh = None
    def close(self):
        if self.pdh:
            self.pdh.close()
    def prime(self):
        psutil.cpu_percent(None, percpu=True)
        for p in psutil.process_iter():
            try:
                p.cpu_percent(None)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        if self.pdh:
            self.pdh.collect()
    def snap(self) -> dict:
        s = {"t": time.time(), "cpu_util": psutil.cpu_percent(None, percpu=True)}
        if self.pdh and self.pdh.collect():
            P = self.pdh
            perf, nom, src = self.freq_reader.read() if self.freq_reader else ([], [], None)
            s["perf_pct"], s["nominal_mhz"], s["freq_src"] = perf, nom, src
            s["freq_mhz"] = [n * p / 100.0 for n, p in zip(nom, perf)]
            s["parked"] = _cpu_instances(P.array("cpu_park"))
            for k in PDH_SINGLES:
                s[k] = P.value(k)
            s["gpu_eng"] = gpu_engine_summary(P.array("gpu_eng"))
            s["gpu_mem"] = gpu_mem_summary(P.array("gpu_ded"), P.array("gpu_shr"))
            s["gpu_proc"] = P.array("gpu_proc")
        if not s.get("freq_mhz"):
            cur, mx = psutil_freq_list(psutil.cpu_count())
            if cur:
                s["freq_mhz"], s["nominal_mhz"], s["freq_src"] = cur, mx, "psutil (fallback)"
                s["perf_pct"] = [c / m * 100 if m else None for c, m in zip(cur, mx)]
        return s
    def baseline(self, duration=4.0, interval=0.5) -> dict:
        n_logical = psutil.cpu_count() or 1
        io0, net0 = safe('disk counters', psutil.disk_io_counters), psutil.net_io_counters()
        cs0 = psutil.cpu_stats()
        self.prime()
        t0 = time.time()
        snaps = []
        while time.time() - t0 < duration:
            time.sleep(interval)
            snaps.append(self.snap())
        elapsed = max(1e-6, time.time() - t0)
        io1, net1, cs1 = safe('disk counters', psutil.disk_io_counters), psutil.net_io_counters(), psutil.cpu_stats()
        res = {"duration": elapsed, "samples": len(snaps), "pdh": bool(self.pdh), "pdh_missing": self.missing}

        per_cpu = _mean_lists([s["cpu_util"] for s in snaps])
        means = [_mean(s["cpu_util"]) for s in snaps]
        res["cpu"] = {"util_avg": _mean(per_cpu), "util_per_cpu": per_cpu, "util_peak_cpu": max(per_cpu) if per_cpu else None,
                      "util_max_sample": max([m for m in means if m is not None], default=None)}
        fm, nm, pm = (_mean_lists([s.get("freq_mhz") for s in snaps]), _mean_lists([s.get("nominal_mhz") for s in snaps]),
                      _mean_lists([s.get("perf_pct") for s in snaps]))
        res["freq"] = {"source": next((s.get("freq_src") for s in snaps if s.get("freq_src")), None),
                       "per_cpu_mhz": fm, "nominal_per_cpu_mhz": nm, "perf_pct_per_cpu": pm,
                       "avg_mhz": _mean(fm), "max_mhz": max(fm) if fm else None, "perf_pct_avg": _mean(pm)}
        parked = _mean_lists([s.get("parked") for s in snaps])
        res["parked_cpus"] = sum(1 for x in parked if x >= 0.5) if parked else None
        def pm_(k):
            return _mean([s.get(k) for s in snaps])

        res["sys"] = {"dpc_pct": pm_("dpc"), "intr_pct": pm_("intr"), "priv_pct": pm_("priv"), "queue": pm_("queue"),
                      "ctx_per_s": pm_("ctx") if self.pdh else (cs1.ctx_switches - cs0.ctx_switches) / elapsed,
                      "syscalls_per_s": pm_("syscalls") if self.pdh else (cs1.syscalls - cs0.syscalls) / elapsed}
        res["mem"] = {k: pm_(k) for k in ("mem_avail", "mem_free", "mem_modified", "mem_sb_normal", "mem_sb_reserve", "mem_sb_core",
                                          "mem_commit", "mem_commit_limit", "mem_faults", "mem_pages_in", "mem_pages_out",
                                          "mem_pool_paged", "mem_pool_nonpaged", "pagefile")}
        res["disk"] = {"busy_pct": pm_("disk_busy"), "queue": pm_("disk_queue"), "lat_read_ms": (pm_("disk_lat_r") or 0) * 1000,
                       "lat_write_ms": (pm_("disk_lat_w") or 0) * 1000,
                       "read_bps": pm_("disk_rd") if self.pdh else ((io1.read_bytes - io0.read_bytes) / elapsed if io0 and io1 else None),
                       "write_bps": pm_("disk_wr") if self.pdh else ((io1.write_bytes - io0.write_bytes) / elapsed if io0 and io1 else None)}
        res["net"] = {"rx_mbps": (net1.bytes_recv - net0.bytes_recv) * 8 / elapsed / 1e6,
                      "tx_mbps": (net1.bytes_sent - net0.bytes_sent) * 8 / elapsed / 1e6}
        engs = {}
        for s in snaps:
            for luid, d in (s.get("gpu_eng") or {}).items():
                e = engs.setdefault(luid, {"max": [], "types": {}})
                e["max"].append(d["max"])
                for t, v in d["by_type"].items():
                    e["types"].setdefault(t, []).append(v)
        res["gpu_eng"] = {l: {"util": _mean(e["max"]), "by_type": {t: _mean(v) for t, v in e["types"].items()}} for l, e in engs.items()}
        mems = {}
        for s in snaps:
            for luid, d in (s.get("gpu_mem") or {}).items():
                m = mems.setdefault(luid, {})
                for k, v in d.items():
                    m.setdefault(k, []).append(v)
        res["gpu_mem"] = {l: {k: _mean(v) for k, v in m.items()} for l, m in mems.items()}
        last_proc = next((s.get("gpu_proc") for s in reversed(snaps) if s.get("gpu_proc")), {})
        res["gpu_proc"] = gpu_proc_top(last_proc)
        res["procs"] = self.top_processes(n_logical)
        return res
    @staticmethod
    def top_processes(n_logical, topn=8) -> dict:
        me, rows = os.getpid(), []
        for p in psutil.process_iter():
            try:
                if p.pid in (0, me):
                    continue
                cpu = p.cpu_percent(None) / n_logical
                rows.append({"pid": p.pid, "name": p.name(), "cpu": cpu, "rss": p.memory_info().rss})
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return {"count": len(rows),
                "top_cpu": sorted(rows, key=lambda r: -r["cpu"])[:topn],
                "top_mem": sorted(rows, key=lambda r: -r["rss"])[:topn]}
class FreqSampler(threading.Thread):
    'Samples the actual frequency (MHz) of each logical processor during benchmarking.'
    def __init__(self, interval=0.4):
        super().__init__(daemon=True)
        self.interval, self.samples, self._stop_evt, self.ok = interval, [], threading.Event(), True
    def run(self):
        q = reader = None
        try:
            n = psutil.cpu_count() or 0
            if IS_WIN:
                try:
                    q = Pdh()
                    reader = CpuFreqReader(q, n)
                    q.collect()
                except Exception as exc:
                    warn("FreqSampler PDH", exc)
                    q = reader = None
            while not self._stop_evt.wait(self.interval):
                arr = None
                if q is not None and q.collect():
                    perf, nom, _src = reader.read()
                    if perf and nom:
                        arr = [a * b / 100.0 for a, b in zip(nom, perf)]
                if arr is None:
                    cur, _mx = psutil_freq_list(n)
                    arr = cur
                if arr:
                    self.samples.append((time.time(), arr))
        except Exception as exc:
            self.ok = False
            warn("FreqSampler", exc)
        finally:
            if q is not None:
                q.close()
    def finish(self) -> list:
        self._stop_evt.set()
        self.join(3)
        return self.samples
def freq_stats(samples, cpus, skip_first=1):
    'Average/peak frequency for the specified logical processors from [(t, [MHz...])].'
    series = []
    for _, arr in samples[skip_first:] if len(samples) > skip_first else samples:
        vals = [arr[c] for c in cpus if c < len(arr)]
        if vals:
            series.append(sum(vals) / len(vals))
    if not series:
        return {"avg": None, "max": None, "series": []}
    return {"avg": sum(series) / len(series), "max": max(series), "series": series}
def _wait_until(t):
    while True:
        d = t - time.time()
        if d <= 0:
            return
        if d > 0.005:
            time.sleep(d - 0.003)
def k_py(duration, t_start):
    'Pure-Python mixed integer/floating-point loop (general-purpose scalar performance).'
    _wait_until(t_start)
    x, acc, n = 1, 0.0, 0
    t0 = time.perf_counter()
    end = t0 + duration
    while True:
        for _ in range(20000):
            x = (x * 1103515245 + 12345) & 0x7FFFFFFF
            acc += (x & 1023) * 0.5
            if x % 7 == 0:
                acc -= 1.0
        n += 20000
        if time.perf_counter() >= end:
            break
    el = time.perf_counter() - t0
    return {"ops_per_s": n / el, "elapsed": el, "chk": acc}
def k_gemm(duration, t_start, dtype="float64", n=256):
    'Single-threaded BLAS GEMM: SIMD/FMA floating-point throughput (GFLOPS).'
    import numpy as np
    rng = np.random.default_rng(1)
    a, b = rng.random((n, n)).astype(dtype), rng.random((n, n)).astype(dtype)
    c = np.empty((n, n), dtype=dtype)
    np.dot(a, b, out=c)
    _wait_until(t_start)
    flops, t0 = 0.0, time.perf_counter()
    end = t0 + duration
    while True:
        for _ in range(8):
            np.dot(a, b, out=c)
        flops += 8 * 2.0 * n ** 3
        if time.perf_counter() >= end:
            break
    el = time.perf_counter() - t0
    return {"gflops": flops / el / 1e9, "elapsed": el}
def k_alu(duration, t_start):
    'Machine code: core clock speed (dependent chain) and peak integer IPC (independent chains).'
    if not jit_supported():
        return {"error": 'machine-code measurement is not supported on this platform'}
    jd, ji = Jit(code_dep_chain(32)), Jit(code_independent(48))
    try:
        def timed(j, iters):
            t0 = time.perf_counter()
            j.fn(iters, 0)
            return time.perf_counter() - t0
        timed(jd, 20000)
        iters = max(20000, int(200000 * 0.05 / max(timed(jd, 200000), 1e-6)))
        warm_end = time.perf_counter() + 0.2
        while time.perf_counter() < warm_end:
            timed(jd, iters)
        _wait_until(t_start)
        t_dep = min(timed(jd, iters) for _ in range(6))
        t_ind = min(timed(ji, iters) for _ in range(6))
        cycles_per_s = iters * 32 / t_dep
        instr_per_s = iters * 50 / t_ind
        return {"ghz": cycles_per_s / 1e9, "ipc": instr_per_s / cycles_per_s, "ginstr_s": instr_per_s / 1e9}
    finally:
        jd.close()
        ji.close()
def k_lat(duration, t_start, sizes):
    'Pointer chasing: random-access latency (ns) by working-set size.'
    import numpy as np
    if not jit_supported():
        return {"error": 'machine-code measurement is not supported'}
    jc = Jit(code_chase(16))
    out = []
    try:
        for size in sizes:
            m = size // 64
            if m < 16:
                continue
            perm = np.random.permutation(m)
            nxt = np.empty(m, dtype=np.int64)
            nxt[perm[:-1]] = perm[1:]
            nxt[perm[-1]] = perm[0]
            buf = np.zeros(size // 8, dtype=np.int64)
            base = buf.ctypes.data
            buf[np.arange(m, dtype=np.int64) * 8] = base + nxt * 64
            start = base + int(perm[0]) * 64
            t0 = time.perf_counter()
            jc.fn(start, 20000)
            t = max(time.perf_counter() - t0, 1e-6)
            count = max(500, int(20000 * 0.04 / t))
            best = min(_time_call(jc.fn, start, count) for _ in range(3))
            out.append((size, best / (count * 16) * 1e9))
            del buf, nxt, perm
    finally:
        jc.close()
    return {"points": out}
def _time_call(fn, a, b):
    t0 = time.perf_counter()
    fn(a, b)
    return time.perf_counter() - t0
KERNELS = {"py": k_py, "gemm": k_gemm, "alu": k_alu, "lat": k_lat}
def _set_worker_affinity(cpu_id: int) -> bool:
    'Pin a worker to one logical processor while supporting Windows processor groups.'
    try:
        p = psutil.Process()
        p.cpu_affinity([cpu_id])
        return True
    except Exception:
        if not IS_WIN:
            return False
    try:
        class GROUP_AFFINITY(ctypes.Structure):
            _fields_ = [("Mask", ctypes.c_size_t), ("Group", wintypes.WORD), ("Reserved", wintypes.WORD * 3)]
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentThread.restype = wintypes.HANDLE
        kernel.SetThreadGroupAffinity.argtypes = [wintypes.HANDLE, ctypes.POINTER(GROUP_AFFINITY), ctypes.c_void_p]
        kernel.SetThreadGroupAffinity.restype = wintypes.BOOL
        group, bit = divmod(int(cpu_id), 64)
        affinity = GROUP_AFFINITY(1 << bit, group, (wintypes.WORD * 3)(0, 0, 0))
        return bool(kernel.SetThreadGroupAffinity(kernel.GetCurrentThread(), ctypes.byref(affinity), None))
    except Exception:
        return False
def _worker_main(cpu_id, conn):
    for var in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS", "NUMEXPR_NUM_THREADS",
                "VECLIB_MAXIMUM_THREADS"):
        os.environ[var] = "1"
    try:
        p = psutil.Process()
        _set_worker_affinity(cpu_id)
        try:
            p.nice(psutil.ABOVE_NORMAL_PRIORITY_CLASS if IS_WIN else 0)
        except Exception:
            pass
        conn.send(("ready", cpu_id))
        while True:
            msg = conn.recv()
            if msg is None:
                break
            kind, kw = msg
            try:
                res = KERNELS[kind](**kw)
            except Exception as exc:
                res = {"error": f"{type(exc).__name__}: {exc}"}
            conn.send(("result", res))
    except (EOFError, KeyboardInterrupt, OSError):
        pass
class CpuLab:
    'Persistent worker processes pinned to each logical processor; measured with simultaneous startup.'
    def __init__(self, cpus):
        ctx = mp.get_context("spawn")
        self.workers = {}
        for c in cpus:
            parent, child = ctx.Pipe()
            proc = ctx.Process(target=_worker_main, args=(c, child), daemon=True)
            proc.start()
            child.close()
            self.workers[c] = (proc, parent)
        for c in list(self.workers):
            proc, conn = self.workers[c]
            try:
                if conn.poll(40) and conn.recv()[0] == "ready":
                    continue
            except (EOFError, OSError):
                pass
            self._drop(c)
    def _drop(self, c):
        proc, conn = self.workers.pop(c, (None, None))
        try:
            if proc is not None and proc.is_alive():
                proc.terminate()
        except Exception:
            pass
    def run(self, cpus, kind, duration=1.0, timeout=25.0, **kw) -> dict:
        cpus = [c for c in cpus if c in self.workers]
        t_start = time.time() + 0.3 + 0.012 * len(cpus)
        msg = (kind, dict(kw, duration=duration, t_start=t_start))
        out = {}
        for c in cpus:
            try:
                self.workers[c][1].send(msg)
            except (OSError, ValueError):
                self._drop(c)
                out[c] = {"error": 'worker process is not responding'}
        deadline = t_start + duration + timeout
        for c in [c for c in cpus if c in self.workers]:
            conn = self.workers[c][1]
            try:
                if conn.poll(max(0.5, deadline - time.time())):
                    out[c] = conn.recv()[1]
                else:
                    out[c] = {"error": 'timed out'}
                    self._drop(c)
            except (EOFError, OSError):
                out[c] = {"error": 'worker process exited'}
                self._drop(c)
        return out
    def close(self):
        for c in list(self.workers):
            proc, conn = self.workers[c]
            try:
                conn.send(None)
            except Exception:
                pass
        for c in list(self.workers):
            proc, _ = self.workers[c]
            proc.join(1.5)
            self._drop(c)
def _sum_key(results, key):
    vals = [r[key] for r in results.values() if isinstance(r, dict) and key in r]
    return (sum(vals), len(vals)) if vals else (None, 0)
def _first_ok(results, key):
    for r in results.values():
        if isinstance(r, dict) and key in r:
            return r[key]
    return None
def _timed_phase(lab, cpus, kind, duration, **kw):
    fs = FreqSampler(0.3)
    fs.start()
    try:
        res = lab.run(cpus, kind, duration, **kw)
    finally:
        samples = fs.finish()
    return res, freq_stats(samples, cpus), samples
def run_cpu_benchmarks(topo: dict, mode: str, use_jit: bool, max_workers: int, say=log, sensor_sampling: bool = False) -> dict:
    deep = mode == "deep"
    d1, d2 = (2.4, 3.0) if deep else (1.2, 1.6)
    classes = topo["classes"]
    pc = classes.get("P") or classes.get("Standart") or next(iter(classes.values()))
    ec = classes.get("E")
    p_rep, e_rep = pc["rep_logical"], (ec["rep_logical"] if ec else None)
    all_logical = sorted({int(x) for c in topo.get("cores", []) for x in c.get("logical", [])})
    if not all_logical:
        all_logical = list(range(int(topo.get("logical") or 1)))
    phys_first = [int(c["logical"][0]) for c in topo.get("cores", []) if c.get("logical")]
    if len(all_logical) > max_workers:
        all_logical = phys_first[:max_workers]
    phys_first = [c for c in phys_first if c in all_logical] or all_logical
    try:
        import numpy
        have_np = True
    except ImportError:
        have_np = False
    out = {"p_rep": p_rep, "e_rep": e_rep, "workers": len(all_logical), "numpy": have_np, "jit": bool(use_jit and jit_supported()),
           "partial_workers": len(all_logical) < topo["logical"], "phys_cpus": phys_first, "all_cpus": all_logical}
    say(f"CPU benchmark: {len(all_logical)} worker processes are starting...")
    lab = CpuLab(sorted(set(all_logical + [p_rep] + ([e_rep] if e_rep is not None else []))))
    try:
        if p_rep not in lab.workers:
            return {**out, "error": 'worker processes could not be started'}
        py = {}
        say('CPU: Python core benchmark (single core / all cores)...')
        r, f, _ = _timed_phase(lab, [p_rep], "py", d1)
        py["single_p"] = {"ops": _first_ok(r, "ops_per_s"), "mhz": f["avg"], "mhz_max": f["max"]}
        if e_rep is not None:
            r, f, _ = _timed_phase(lab, [e_rep], "py", d1)
            py["single_e"] = {"ops": _first_ok(r, "ops_per_s"), "mhz": f["avg"], "mhz_max": f["max"]}
        r, f, _ = _timed_phase(lab, phys_first, "py", d2)
        tot, n = _sum_key(r, "ops_per_s")
        py["all_phys"] = {"ops": tot, "n": n, "mhz": f["avg"], "mhz_max": f["max"]}
        if len(all_logical) > len(phys_first):
            r, f, _ = _timed_phase(lab, all_logical, "py", d2)
            tot, n = _sum_key(r, "ops_per_s")
            py["all_logical"] = {"ops": tot, "n": n, "mhz": f["avg"], "mhz_max": f["max"]}
        out["py"] = py
        if have_np:
            say("CPU: BLAS GEMM (SIMD/FMA) testi...")
            gm = {}
            for dtype in (("float64", "float32") if not deep else ("float64", "float32")):
                g = {}
                r, f, _ = _timed_phase(lab, [p_rep], "gemm", d1, dtype=dtype)
                g["single_p"] = {"gflops": _first_ok(r, "gflops"), "mhz": f["avg"]}
                if dtype == "float64":
                    if e_rep is not None:
                        r, f, _ = _timed_phase(lab, [e_rep], "gemm", d1, dtype=dtype)
                        g["single_e"] = {"gflops": _first_ok(r, "gflops"), "mhz": f["avg"]}
                    allc = all_logical
                    r, f, _ = _timed_phase(lab, phys_first, "gemm", d2, dtype=dtype)
                    tot, n = _sum_key(r, "gflops")
                    g["all_phys"] = {"gflops": tot, "n": n, "mhz": f["avg"]}
                    if len(allc) > len(phys_first):
                        r, f, _ = _timed_phase(lab, allc, "gemm", d2, dtype=dtype)
                        tot, n = _sum_key(r, "gflops")
                        g["all_logical"] = {"gflops": tot, "n": n, "mhz": f["avg"]}
                gm[dtype] = g
            out["gemm"] = gm
        if use_jit and jit_supported():
            say('CPU: measuring core clock and integer IPC (machine code)...')
            alu = {}
            r = lab.run([p_rep], "alu", 1.0, timeout=30)
            alu["P"] = r.get(p_rep)
            if e_rep is not None:
                alu["E"] = lab.run([e_rep], "alu", 1.0, timeout=30).get(e_rep)
            out["alu"] = alu
        if deep:
            say('CPU: sustained-load (thermal/power limit) test...')
            seg = []
            fs = FreqSampler(0.5)
            sampler = SensorSampler(sample_gpu=False, critical_cpu_c=100.0) if sensor_sampling else None
            if sampler:
                sampler.start()
            fs.start()
            try:
                for _ in range(5):
                    if sampler and sampler.abort_requested.is_set():
                        break
                    r = lab.run(all_logical, "gemm" if have_np else "py", 4.0, **({"dtype": "float64"} if have_np else {}))
                    seg.append(_sum_key(r, "gflops" if have_np else "ops_per_s")[0])
                    if sampler and sampler.abort_requested.is_set():
                        break
            finally:
                samples = fs.finish()
                thermal_series = sampler.finish() if sampler else []
            out["sustained"] = {"metric": "gflops" if have_np else "ops_per_s", "segments": seg,
                                "freq_series": freq_stats(samples, all_logical, 0)["series"],
                                "thermal_series": thermal_series,
                                "thermal_sampling_available": bool(thermal_series),
                                "safety_abort": bool(sampler and sampler.abort_requested.is_set()),
                                "note": ('New load slices were stopped because a thermal threshold was observed' if sampler and sampler.abort_requested.is_set() else
                                         'No thermal sensor sample was obtained; thermal safety could not be verified' if sensor_sampling and not thermal_series else
                                         'No automatic thermal cutoff is available for this test because no thermal sensor source was found' if not sensor_sampling else "") }
    finally:
        lab.close()
    return out
def run_latency_benchmark(topo: dict, mode: str, avail_ram: int, max_workers: int, say=log) -> dict:
    'Memory/cache latency curve (only when numpy + machine code are available).'
    sizes = [16 << 10, 32 << 10, 64 << 10, 128 << 10, 256 << 10, 512 << 10, 1 << 20, 2 << 20, 4 << 20, 8 << 20,
             16 << 20, 32 << 20, 64 << 20, 128 << 20] + ([256 << 20] if mode == "deep" else [])
    sizes = [s for s in sizes if s * 1.3 <= avail_ram * 0.15]
    classes = topo["classes"]
    pc = classes.get("P") or classes.get("Standart") or next(iter(classes.values()))
    out = {}
    lab = CpuLab([pc["rep_logical"]])
    try:
        say('Measuring memory latency (L1/L2/L3/RAM)...')
        r = lab.run([pc["rep_logical"]], "lat", 1.0, timeout=60, sizes=sizes)
        res = r.get(pc["rep_logical"]) or {}
        out["P" if topo["hybrid"] else "all"] = res
    finally:
        lab.close()
    return out
def bench_memory(total_bytes: int, threads_list: list, per_run=0.5) -> dict:
    try:
        import numpy as np
    except ImportError:
        np = None
    S = max(8 * MIB, min((total_bytes // 2) // MIB * MIB, 256 * MIB))
    if np is not None:
        src, dst = np.ones(S, dtype=np.uint8), np.zeros(S, dtype=np.uint8)
        def copy_(a, b):
            np.copyto(dst[a:b], src[a:b])
        def fill_(a, b):
            dst[a:b].fill(7)
    else:
        src, dst = (ctypes.c_char * S)(), (ctypes.c_char * S)()
        sa, da = ctypes.addressof(src), ctypes.addressof(dst)
        def copy_(a, b):
            ctypes.memmove(da + a, sa + a, b - a)
        def fill_(a, b):
            ctypes.memset(da + a, 7, b - a)
    CH = 8 * MIB
    def measure(op, nt):
        stop, counts = threading.Event(), [0] * nt
        def work(i):
            a0, b0 = (S // nt) * i, (S // nt) * (i + 1)
            pos = a0
            while not stop.is_set():
                e = min(pos + CH, b0)
                op(pos, e)
                counts[i] += e - pos
                pos = e if e < b0 else a0
        ths = [threading.Thread(target=work, args=(i,)) for i in range(nt)]
        t0 = time.perf_counter()
        for t in ths:
            t.start()
        time.sleep(per_run)
        stop.set()
        for t in ths:
            t.join()
        return sum(counts) / (time.perf_counter() - t0)
    copy_res = {}
    for nt in threads_list:
        copy_res[nt] = 2 * measure(copy_, nt) / 1e9
    best_nt = max(copy_res, key=copy_res.get)
    fill_gbs = measure(fill_, best_nt) / 1e9
    return {"copy_gbs": copy_res, "best_copy_gbs": copy_res[best_nt], "best_threads": best_nt, "fill_gbs": fill_gbs,
            "buffer_bytes": S, "numpy": np is not None}
def _disk_bench_win(fn: str, size: int, rand_secs: float) -> dict:
    k = k32()
    k.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                              wintypes.DWORD, wintypes.HANDLE]
    k.CreateFileW.restype = wintypes.HANDLE
    for f in (k.WriteFile, k.ReadFile):
        f.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
        f.restype = wintypes.BOOL
    k.SetFilePointerEx.argtypes = [wintypes.HANDLE, ctypes.c_longlong, ctypes.POINTER(ctypes.c_longlong), wintypes.DWORD]
    k.SetFilePointerEx.restype = wintypes.BOOL
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    k.CloseHandle.restype = wintypes.BOOL
    invalid = ctypes.c_void_p(-1).value
    CH = 4 * MIB
    mm = mmap.mmap(-1, CH)
    mm.write(os.urandom(CH))
    cbuf = ctypes.c_char.from_buffer(mm)
    addr = ctypes.addressof(cbuf)
    res, n = {}, wintypes.DWORD()
    def open_(access, share, disp, flags):
        h = k.CreateFileW(fn, access, share, None, disp, flags, None)
        if h in (None, invalid):
            raise OSError(ctypes.get_last_error(), 'Disk test file could not be opened')
        return h
    try:
        h = open_(0xC0000000, 0, 2, 0x20000000 | 0x80000000)
        total, t0 = 0, time.perf_counter()
        try:
            while total < size:
                if not k.WriteFile(h, addr, CH, ctypes.byref(n), None):
                    raise OSError(ctypes.get_last_error(), 'WriteFile failed')
                total += n.value
        finally:
            el = time.perf_counter() - t0
            k.CloseHandle(h)
        res["seq_write_mbs"] = total / el / 1e6
        h = open_(0x80000000, 1, 3, 0x20000000 | 0x08000000)
        total, t0 = 0, time.perf_counter()
        try:
            while total < size:
                if not k.ReadFile(h, addr, CH, ctypes.byref(n), None) or n.value == 0:
                    break
                total += n.value
        finally:
            el = time.perf_counter() - t0
            k.CloseHandle(h)
        res["seq_read_mbs"] = total / el / 1e6
        import random
        h = open_(0x80000000, 1, 3, 0x20000000 | 0x10000000)
        nblocks, lat, dist = size // 4096, [], ctypes.c_longlong()
        t_begin = time.perf_counter()
        try:
            while time.perf_counter() - t_begin < rand_secs:
                off = random.randrange(nblocks) * 4096
                t1 = time.perf_counter()
                k.SetFilePointerEx(h, off, ctypes.byref(dist), 0)
                k.ReadFile(h, addr, 4096, ctypes.byref(n), None)
                lat.append(time.perf_counter() - t1)
        finally:
            k.CloseHandle(h)
        res.update(_lat_stats(lat, time.perf_counter() - t_begin))
        h = open_(0x40000000, 3, 3, 0x20000000 | 0x10000000 | 0x80000000)
        nblocks, latw, dist = size // 4096, [], ctypes.c_longlong()
        t_begin = time.perf_counter()
        try:
            while time.perf_counter() - t_begin < rand_secs:
                off = random.randrange(nblocks) * 4096
                if not k.SetFilePointerEx(h, off, ctypes.byref(dist), 0):
                    raise OSError(ctypes.get_last_error(), 'SetFilePointerEx (random write) failed')
                t1 = time.perf_counter()
                if not k.WriteFile(h, addr, 4096, ctypes.byref(n), None) or n.value != 4096:
                    raise OSError(ctypes.get_last_error(), 'WriteFile (random 4K) failed')
                latw.append(time.perf_counter() - t1)
        finally:
            k.CloseHandle(h)
        ws = _lat_stats(latw, time.perf_counter() - t_begin)
        res.update({f"{key}_write": val for key, val in ws.items()})
        for qd in (4, 8):
            for writing in (False, True):
                handles = []
                try:
                    flags = 0x20000000 | 0x10000000 | (0x80000000 if writing else 0)
                    access = 0x40000000 if writing else 0x80000000
                    share = 3
                    for _ in range(qd):
                        handles.append(open_(access, share, 3, flags))
                    deadline = time.perf_counter() + rand_secs
                    def queued_worker(handle, seed):
                        rng = random.Random(seed)
                        local_lat = []
                        local_dist, transferred = ctypes.c_longlong(), wintypes.DWORD()
                        while time.perf_counter() < deadline:
                            offset = rng.randrange(nblocks) * 4096
                            if not k.SetFilePointerEx(handle, offset, ctypes.byref(local_dist), 0):
                                raise OSError(ctypes.get_last_error(), 'SetFilePointerEx (queued I/O) failed')
                            start_io = time.perf_counter()
                            ok = (k.WriteFile(handle, addr, 4096, ctypes.byref(transferred), None) if writing
                                  else k.ReadFile(handle, addr, 4096, ctypes.byref(transferred), None))
                            if not ok or transferred.value != 4096:
                                raise OSError(ctypes.get_last_error(), '4K queued I/O failed')
                            local_lat.append(time.perf_counter() - start_io)
                        return local_lat
                    t_queued = time.perf_counter()
                    with cf.ThreadPoolExecutor(max_workers=qd) as pool:
                        future_lat = [pool.submit(queued_worker, h, 700 + qd * 10 + i) for i, h in enumerate(handles)]
                        lat_all = [sample for future in future_lat for sample in future.result()]
                    elapsed_qd = max(time.perf_counter() - t_queued, 1e-9)
                    qstats = _lat_stats(lat_all, elapsed_qd)
                    prefix = f"rand4k_qd{qd}_{'write' if writing else 'read'}"
                    res.update({f"{prefix}_{key.removeprefix('rand4k_')}": val for key, val in qstats.items()})
                finally:
                    for handle in handles:
                        try:
                            k.CloseHandle(handle)
                        except Exception:
                            pass
        res["queued_io_method"] = "QD4/QD8 approximately measured with concurrent synchronous workers"
    finally:
        del cbuf
        mm.close()
    return res
def _lat_stats(lat, elapsed):
    if not lat:
        return {}
    s = sorted(lat)
    return {"rand4k_iops": len(lat) / elapsed, "rand4k_median_us": s[len(s) // 2] * 1e6,
            "rand4k_p99_us": s[min(len(s) - 1, int(len(s) * 0.99))] * 1e6}
def _disk_bench_posix(fn: str, size: int, rand_secs: float) -> dict:
    import random
    CH = 4 * MIB
    blob = os.urandom(CH)
    res = {}
    t0 = time.perf_counter()
    with open(fn, "wb", buffering=0) as f:
        for _ in range(size // CH):
            f.write(blob)
        os.fsync(f.fileno())
    res["seq_write_mbs"] = size / (time.perf_counter() - t0) / 1e6
    fd = os.open(fn, os.O_RDWR)
    try:
        if hasattr(os, "posix_fadvise"):
            os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
        t0, total = time.perf_counter(), 0
        while total < size:
            chunk = os.read(fd, CH)
            if not chunk:
                break
            total += len(chunk)
        res["seq_read_mbs"] = total / (time.perf_counter() - t0) / 1e6
        lat, nblocks, tb = [], size // 4096, time.perf_counter()
        while time.perf_counter() - tb < rand_secs:
            t1 = time.perf_counter()
            os.pread(fd, 4096, random.randrange(nblocks) * 4096)
            lat.append(time.perf_counter() - t1)
        res.update(_lat_stats(lat, time.perf_counter() - tb))
        latw, tw = [], time.perf_counter()
        while time.perf_counter() - tw < rand_secs:
            off = random.randrange(nblocks) * 4096
            t1 = time.perf_counter()
            written = os.pwrite(fd, blob[:4096], off)
            if written != 4096:
                raise OSError('random 4K write completed incompletely')
            latw.append(time.perf_counter() - t1)
        os.fsync(fd)
        ws = _lat_stats(latw, time.perf_counter() - tw)
        res.update({f"{key}_write": val for key, val in ws.items()})
        for qd in (4, 8):
            for writing in (False, True):
                deadline = time.perf_counter() + rand_secs

                def queued_worker(seed):
                    rng = random.Random(seed)
                    local_lat = []
                    while time.perf_counter() < deadline:
                        off = rng.randrange(nblocks) * 4096
                        t1 = time.perf_counter()
                        if writing:
                            done = os.pwrite(fd, blob[:4096], off)
                            if done != 4096:
                                raise OSError('queued random 4K write completed incompletely')
                        else:
                            done = os.pread(fd, 4096, off)
                            if len(done) != 4096:
                                raise OSError('queued random 4K read completed incompletely')
                        local_lat.append(time.perf_counter() - t1)
                    return local_lat
                t_queued = time.perf_counter()
                with cf.ThreadPoolExecutor(max_workers=qd) as pool:
                    future_lat = [pool.submit(queued_worker, 900 + qd * 10 + i) for i in range(qd)]
                    lat_all = [sample for future in future_lat for sample in future.result()]
                elapsed_qd = max(time.perf_counter() - t_queued, 1e-9)
                qstats = _lat_stats(lat_all, elapsed_qd)
                prefix = f"rand4k_qd{qd}_{'write' if writing else 'read'}"
                res.update({f"{prefix}_{key.removeprefix('rand4k_')}": val for key, val in qstats.items()})
                if writing:
                    os.fsync(fd)
        res["queued_io_method"] = 'QD4/QD8 is approximate; concurrent positional I/O threads'
    finally:
        os.close(fd)
    res["note"] = 'Non-Windows: the OS cache may inflate results; the test writes to a file.'
    return res
def bench_disk(dirpath: str, size: int, rand_secs=1.5) -> dict:
    free = shutil.disk_usage(dirpath).free
    size = int(min(size, max(0, free - GIB)) // (4 * MIB) * (4 * MIB))
    if size < 64 * MIB:
        return {"error": 'Not enough free space for the disk test', "path": dirpath}
    fn = os.path.join(dirpath, f"system_analyses_disk_{os.getpid()}.tmp")
    res = {"path": dirpath, "size": size}
    try:
        res.update(_disk_bench_win(fn, size, rand_secs) if IS_WIN else _disk_bench_posix(fn, size, rand_secs))
    finally:
        try:
            os.remove(fn)
        except OSError:
            pass
    return res
def dig(d, path, default=None):
    cur = d
    for k in path.split("."):
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return default
    return default if cur is None else cur
class Findings:
    def __init__(self):
        self.items = []

    def add(self, level, area, title, detail="", action="", impact=0):
        self.items.append({"level": level, "area": area, "title": title, "detail": detail, "action": action,
                           "impact": impact})
def grade(score):
    if score is None:
        return 'not measured'
    return 'Very good' if score >= 85 else 'Good' if score >= 70 else "Medium" if score >= 50 else 'Weak'
def power_tier(score):
    if score is None:
        return "belirsiz"
    return ('High-end' if score >= 90 else 'Very powerful (workstation/enthusiast)' if score >= 78 else 'Powerful' if score >= 62 else
            "Medium" if score >= 45 else 'Entry-level' if score >= 28 else 'Low')
class Comp:
    'List of weighted score components (to explain the score in the report).'
    def __init__(self):
        self.rows = []
    def add(self, name, value, weight, note=""):
        self.rows.append({"name": name, "value": None if value is None else clamp(value), "weight": weight, "note": note})
    def score(self, min_weight=None):
        'Weighted average; if min_weight is set, returns None when the measurable components account for less than that share of the weights.'
        rows = [(r["value"], r["weight"]) for r in self.rows]
        if min_weight is not None:
            total = sum(w for _, w in rows)
            have = sum(w for v, w in rows if v is not None)
            if not total or have / total < min_weight:
                return None
        return wavg(rows)
def _latency_summary(points, cache):
    pts = sorted(points or [])
    if not pts:
        return None
    l1 = (cache.get("L1d") or {}).get("size", 32 << 10)
    l2 = (cache.get("L2") or {}).get("size", 1 << 20)
    l3 = (cache.get("L3") or {}).get("size", 16 << 20)
    def pick(max_size, min_size=0):
        c = [(s, ns) for s, ns in pts if min_size < s <= max_size]
        return c[-1][1] if c else None
    return {"l1_ns": pick(l1 // 2) or pts[0][1], "l2_ns": pick(l2 // 2, 2 * l1),
            "l3_ns": pick(min(l3 // 2, pts[-1][0] // 2), 2 * l2),
            "dram_ns": pts[-1][1] if pts[-1][0] >= 4 * l3 or pts[-1][0] >= (64 << 20) else None,
            "dram_size": pts[-1][0], "points": pts}
def analyze_cpu(data, F):
    cpu, topo = data["cpu"], data["cpu"]["topology"]
    base, bc = data.get("baseline") or {}, dig(data, "bench.cpu", {}) or {}
    classes = topo["classes"]
    pc = classes.get("P") or classes.get("Standart") or next(iter(classes.values()))
    ec = classes.get("E")
    p_rep, e_rep = bc.get("p_rep", pc["rep_logical"]), bc.get("e_rep", ec["rep_logical"] if ec else None)
    nom = dig(base, "freq.nominal_per_cpu_mhz", []) or []
    ntp = cpu.get("ntpower") or []
    w0 = (as_list(dig(data, "ps.cpu_wmi")) or [{}])[0] or {}
    def base_for(idx):
        if idx is not None and idx < len(nom) and nom[idx]:
            return nom[idx], ('Windows counter (Processor Frequency)' if base.get("pdh") else "psutil cpu_freq")
        if idx is not None and idx < len(ntp) and ntp[idx]["max"]:
            return ntp[idx]["max"], "CallNtPowerInformation"
        if w0.get("MaxClock"):
            return w0["MaxClock"], "WMI MaxClockSpeed"
        if cpu.get("reg_mhz"):
            return cpu["reg_mhz"], 'Registry (~MHz)'
        sm = cpu.get("smbios") or {}
        return (sm.get("cur_speed_mhz"), "SMBIOS") if sm.get("cur_speed_mhz") else (None, None)
    base_p, base_src = base_for(p_rep)
    base_e = base_for(e_rep)[0] if e_rep is not None else None
    core_equivalent_label = 'P-core equivalent' if topo.get("hybrid") else 'standard-core equivalent'
    core_equivalent_unit = 'P-core' if topo.get("hybrid") else 'standard-core'
    sampled_freq_max = dig(base, "freq.max_mhz")
    sampled_freq_source = dig(base, "freq.source")
    py, gm, alu = bc.get("py") or {}, (bc.get("gemm") or {}).get("float64") or {}, bc.get("alu") or {}
    gm32 = (bc.get("gemm") or {}).get("float32") or {}
    cands_p = [dig(py, "single_p.mhz_max"), dig(gm, "single_p.mhz"),
               (alu.get("P") or {}).get("ghz", 0) * 1000 or None]
    boost_p = max([x for x in cands_p if x], default=None)
    cands_e = [dig(py, "single_e.mhz_max"), dig(gm, "single_e.mhz"), ((alu.get("E") or {}).get("ghz", 0) * 1000) or None]
    boost_e = max([x for x in cands_e if x], default=None)
    allcore = (dig(gm, "all_logical.mhz") or dig(py, "all_logical.mhz") or dig(gm, "all_phys.mhz") or dig(py, "all_phys.mhz"))
    all_ratio = None
    if allcore:
        used = bc.get("all_cpus") or list(range(len(nom)))
        bases = [nom[i] for i in used if i < len(nom) and nom[i]] or ([base_p] if base_p else [])
        if bases:
            all_ratio = allcore / (sum(bases) / len(bases))
    t_p, t_e = dig(py, "single_p.ops"), dig(py, "single_e.ops")
    scaling = e_vs_p = smt_gain = p_equiv = None
    if t_p and dig(py, "all_phys.ops"):
        used = set(bc.get("phys_cpus") or [])
        n_p = sum(1 for c in topo["cores"] if c["cls"] in ("P", "Standart") and (not used or c["logical"][0] in used))
        n_e = sum(1 for c in topo["cores"] if c["cls"] not in ("P", "Standart") and (not used or c["logical"][0] in used))
        ideal = n_p * t_p + n_e * (t_e if t_e else t_p * 0.5)
        scaling = py["all_phys"]["ops"] / ideal if ideal and (n_p + n_e) >= 2 else None
        if t_e:
            e_vs_p = t_e / t_p
        top = dig(py, "all_logical.ops") or py["all_phys"]["ops"]
        p_equiv = top / t_p
        if dig(py, "all_logical.ops") and n_p:
            smt_gain = clamp((py["all_logical"]["ops"] - py["all_phys"]["ops"]) / (n_p * t_p), 0, 0.6)
    def fpc(g, ghz):
        v = dig(g, "single_p.gflops")
        pdh_mhz = dig(g, "single_p.mhz") if base.get("pdh") else None
        f = pdh_mhz or (ghz * 1000 if ghz else None) or dig(g, "single_p.mhz")
        return v / (f / 1000) if v and f else None
    jit_p = (alu.get("P") or {}).get("ghz")
    fp64_fpc, fp32_fpc = fpc(gm, jit_p), fpc(gm32, jit_p)
    mt64 = dig(gm, "all_logical.gflops") or dig(gm, "all_phys.gflops")
    mt32 = dig(gm32, "all_logical.gflops") or dig(gm32, "all_phys.gflops")
    fma_note = None
    if fp64_fpc:
        fma_note = ('≈32 FLOP/cycle class: 2×512-bit FMA' if fp64_fpc >= 24 else
                    '≈16 FLOP/cycle class: 2×256-bit or 1×512-bit FMA' if fp64_fpc >= 12 else
                    '≈8 FLOP/cycle class: 1×256-bit or 2×128-bit FMA' if fp64_fpc >= 6 else 'limited vector pipeline (SSE class)')
    lat = None
    lb = dig(data, "bench.latency", {}) or {}
    pts = (lb.get("P") or lb.get("all") or {}).get("points")
    if pts:
        lat = _latency_summary(pts, pc.get("cache") or {})
    pw = dig(data, "os.power", {}) or {}
    util = dig(base, "cpu.util_per_cpu", []) or []
    sib_w = smt_gain if smt_gain is not None else 0.25
    w_e = e_vs_p if e_vs_p else 0.55
    weights = {}
    for c in topo["cores"]:
        cw = 1.0 if c["cls"] in ("P", "Standart") else (w_e if c["cls"] == "E" else w_e * 0.6)
        for j, lg in enumerate(c["logical"]):
            weights[lg] = cw if j == 0 else cw * sib_w
    total_eq = sum(weights.values()) or 1.0
    free_eq = sum(w * (1 - (util[i] if i < len(util) else 0) / 100.0) for i, w in weights.items())
    free_cores = 0.0
    for c in topo["cores"]:
        us = [util[i] for i in c["logical"] if i < len(util)]
        free_cores += 1 - (sum(us) / len(us) / 100.0 if us else 0)
    limit_ratio = None
    lims = [x["limit"] / x["max"] for x in ntp if x.get("max") and x.get("limit")]
    if lims:
        limit_ratio = min(lims)
    ipc_p = (alu.get("P") or {}).get("ipc")
    st_ghz = (jit_p or (boost_p or 0) / 1000) or None
    st_gops = st_ghz * ipc_p if st_ghz and ipc_p else (st_ghz * 3.5 if st_ghz else None)
    cls_out = {}
    for lab, c in classes.items():
        key = "P" if lab in ("P", "Standart") else lab
        a = alu.get(key if key in alu else "P") if lab in ("P", "Standart", "E") else None
        cls_out[lab] = {"cores": c["cores"], "threads": c["threads"], "smt": c["smt"], "cache": c["cache"],
                        "base_mhz": base_p if lab in ("P", "Standart") else base_e,
                        "boost_mhz": boost_p if lab in ("P", "Standart") else boost_e,
                        "jit_ghz": (a or {}).get("ghz"), "ipc": (a or {}).get("ipc"),
                        "py_ops": t_p if lab in ("P", "Standart") else t_e,
                        "gflops64": dig(gm, "single_p.gflops") if lab in ("P", "Standart") else dig(gm, "single_e.gflops")}
    comp = Comp()
    if mt64:
        mt_score = lerp_score(mt64, [(25, 10), (100, 30), (250, 50), (500, 70), (900, 90), (1500, 100)])
        mt_note = f"BLAS FP64 multi-core ≈ {mt64:.0f} GFLOPS"
    else:
        eq = (p_equiv or sum(weights.values())) * ((boost_p or base_p or 3000) / 1000)
        mt_score = lerp_score(eq, [(4, 10), (10, 30), (24, 50), (48, 70), (90, 90), (150, 100)])
        mt_note = f"estimated: ≈ {eq:.0f} {core_equivalent_unit}·GHz (no benchmark)"
    comp.add('Multi-core throughput', mt_score, 0.55, mt_note)
    if st_gops:
        comp.add('Single-core performance', lerp_score(st_gops, [(8, 10), (12, 30), (16, 50), (20, 70), (24, 85), (28, 97)]), 0.45,
                 f"≈ {st_gops:.1f} G integer operations/s" + ("" if ipc_p else ' (IPC estimated)'))
    cpu_power = comp.score()
    if all_ratio is not None and all_ratio < 0.9:
        F.add("bad", "CPU", 'Frequency drops below base clock under full load',
              f"Average under all-core load {fmt_ghz(allcore)} (temel ≈ %{all_ratio * 100:.0f}).",
              'Check cooling/dust filters, power limits (PL1/PL2), and the power plan.', 35)
    elif all_ratio is not None and all_ratio < 0.97:
        F.add("warn", "CPU", 'Frequency is very close to base clock under full load', f"All-core average {fmt_ghz(allcore)}.",
              'The power/thermal budget may be at its limit.', 10)
    if limit_ratio is not None and limit_ratio < 0.95:
        F.add("warn", "CPU", 'Windows is limiting processor frequency',
              f"MhzLimit/MaxMhz ≈ {limit_ratio * 100:.0f}% (power policy or thermal throttling).",
              "Set 'Maximum processor state' to 100% in the power plan; check thermal conditions.", 30)
    if pw.get("max_state") is not None and pw["max_state"] < 100:
        F.add("bad", "CPU", f"Maximum processor state %{pw['max_state']}",
              'The power plan is preventing the CPU from reaching its maximum frequency.', 'Set it to 100% using powercfg or Power Options.',
              100 - pw["max_state"])
    if pw.get("boost_mode") == 0:
        F.add("warn", "CPU", 'Processor turbo/boost mode is disabled', "'Performance boost mode' is set to Disabled in the power plan.",
              "Set it to 'Enabled/Aggressive' if you want turbo.", 25)
    if pw.get("overlay") == 'Best power efficiency' or pw.get("scheme") == 'Power saver':
        F.add("warn", "CPU", 'Power mode favors efficiency/power saving',
              f"Aktif: {pw.get('overlay') or pw.get('scheme')}.", "Windows Settings > Power mode: 'Best performance'.", 20)
    if scaling is not None and scaling < 0.7:
        F.add("warn", "CPU", 'Multi-core scaling is below expectations',
              f"All-core total is % of the sum of individual (single-core turbo) speeds{scaling * 100:.0f}' (including frequency drop).",
              'Background load, a shared power/thermal budget, or memory contention may be responsible.', 15)
    if dig(base, "sys.dpc_pct") is not None and (dig(base, "sys.dpc_pct", 0) + dig(base, "sys.intr_pct", 0)) > 5:
        F.add("warn", "CPU", 'High DPC/interrupt time',
              f"DPC {base['sys']['dpc_pct']:.1f}% + interrupt {base['sys']['intr_pct']:.1f}%.",
              'Driver-related latency may be present (update audio/network/GPU drivers).', 20)
    if dig(base, "cpu.util_avg", 0) > 25:
        top = (dig(base, "procs.top_cpu") or [{}])[0]
        F.add("warn", "CPU", f"Background CPU load is high (%{base['cpu']['util_avg']:.0f})",
              f"Top process: {top.get('name', '?')} (%{top.get('cpu', 0):.1f}).", 'Close unnecessary processes.', 25)
    if dig(data, "cpu.os_features.SANAL_FIRMWARE") is False:
        F.add("info", "CPU", 'Virtualization (VT-x/AMD-V) appears disabled in BIOS', "", 'Enable it in BIOS for VM/WSL2.', 3)
    return {"name": cpu.get("name"), "base_p": base_p, "base_e": base_e, "base_source": base_src, "boost_p": boost_p,
            "boost_e": boost_e, "sampled_freq_max_mhz": sampled_freq_max, "sampled_freq_source": sampled_freq_source,
            "core_equivalent_label": core_equivalent_label, "core_equivalent_unit": core_equivalent_unit,
            "allcore_mhz": allcore, "allcore_ratio": all_ratio, "limit_ratio": limit_ratio,
            "scaling": scaling, "e_vs_p": e_vs_p, "smt_gain": smt_gain, "p_equiv": p_equiv, "fp64_fpc": fp64_fpc,
            "fp32_fpc": fp32_fpc, "fma_note": fma_note, "mt_gflops64": mt64, "mt_gflops32": mt32, "st_gops": st_gops,
            "st_gops_measured": ipc_p is not None,
            "st_gops_source": "measured_ipc" if ipc_p is not None else "estimated_ipc_proxy" if st_gops is not None else "unavailable",
            "mt_gflops64_measured": mt64 is not None,
            "latency": lat, "classes": cls_out, "free_equiv": free_eq, "total_equiv": total_eq, "free_cores": free_cores,
            "sustained": _sustained(bc.get("sustained")), "power": cpu_power, "power_comp": comp.rows,
            "isa": cpu.get("isa"), "weights": weights}
def _sustained(s):
    if not s or not s.get("segments") or len(s["segments"]) < 3 or not s["segments"][0]:
        return None
    seg = [x for x in s["segments"] if x]
    ratio = seg[-1] / seg[0]
    fs = s.get("freq_series") or []
    f_ratio = None
    if len(fs) >= 6:
        k = max(2, len(fs) // 4)
        f_ratio = (sum(fs[-k:]) / k) / (sum(fs[:k]) / k)
    return {"segments": seg, "ratio": ratio, "freq_ratio": f_ratio}
def analyze_memory(data, F):
    ms, dyn = data["memory"], data["memory"].get("dynamic") or {}
    base = dig(data, "baseline.mem", {}) or {}
    total, avail = dyn.get("total") or 0, dyn.get("available") or 0
    used = total - avail
    standby = sum(base.get(k) or 0 for k in ("mem_sb_normal", "mem_sb_reserve", "mem_sb_core")) or None
    comp = {"in_use": used, "modified": base.get("mem_modified"), "standby": standby, "free": base.get("mem_free"),
            "compressed": dyn.get("compressed")}
    commit_total = dyn.get("commit_total") or base.get("mem_commit")
    commit_limit = dyn.get("commit_limit") or base.get("mem_commit_limit")
    commit_pct = commit_total / commit_limit * 100 if commit_total and commit_limit else None
    bw = dig(data, "bench.memory", {}) or {}
    theo = ms.get("theoretical_gbs")
    bw_ratio = bw["best_copy_gbs"] / theo if bw.get("best_copy_gbs") and theo else None
    xmp_ratio = ms["run_mts"] / ms["rated_mts"] if ms.get("run_mts") and ms.get("rated_mts") else None
    lat = dig(data, "bench.latency", {}) or {}
    dram_ns = _latency_summary((lat.get("P") or lat.get("all") or {}).get("points"),
                               (list(data["cpu"]["topology"]["classes"].values())[0].get("cache") or {}))
    dram_ns = dram_ns["dram_ns"] if dram_ns else None
    total_gib = total / GIB if total else 0
    avail_pct = avail / total * 100 if total else None
    reserve = max(2 * GIB, int(0.10 * total))
    usable_safe = max(0, avail - reserve)
    c = Comp()
    c.add("Capacity", lerp_score(total_gib, [(4, 10), (8, 30), (16, 55), (32, 78), (64, 92), (128, 100)]), 0.45, f"{total_gib:.1f} GiB")
    bw_for_score = bw.get("best_copy_gbs") or (theo * 0.65 if theo else None)
    c.add('Bandwidth', lerp_score(bw_for_score, [(10, 15), (20, 35), (35, 55), (55, 75), (80, 92), (110, 100)]), 0.35,
          f"{bw_for_score:.1f} GB/s" + ("" if bw.get("best_copy_gbs") else " (estimated)") if bw_for_score else "")
    if dram_ns:
        c.add("Latency", lerp_score(dram_ns, [(130, 20), (100, 40), (80, 60), (65, 80), (50, 95)]), 0.20, f"{dram_ns:.0f} ns")
    power = c.score()
    is_lp = (ms.get("type") or "").startswith("LPDDR")
    if not is_lp and ms.get("populated") and ms.get("channels") == 1 and ms["populated"] >= 1:
        F.add("bad", "RAM", 'Single-channel memory configuration',
              f"{ms['populated']} module(s), one memory channel ({ms.get('channels_source')}).",
              'Install the second module in a dual-channel slot (A2/B2 layout in the manual).', 35)
    if xmp_ratio is not None and xmp_ratio < 0.9:
        F.add("warn", "RAM", 'XMP/EXPO profile may be disabled',
              f"Operating speed {ms['run_mts']} MT/s, module rating {ms['rated_mts']} MT/s.", 'Enable XMP/EXPO in BIOS.', 20)
    if total_gib and total_gib < 8:
        F.add("bad", "RAM", f"Very low memory ({total_gib:.1f} GiB)", "", 'At least 16 GiB is recommended.', 40)
    elif total_gib and total_gib < 16:
        F.add("warn", "RAM", f"Memory is borderline ({total_gib:.1f} GiB)", 'Limited for modern workloads.', 'Consider upgrading to 32 GiB.', 15)
    if avail_pct is not None and avail_pct < 15:
        F.add("bad", "RAM", f"Free memory is critically low (%{avail_pct:.0f})", "", 'Close memory-intensive applications.', 35)
    elif avail_pct is not None and avail_pct < 30:
        F.add("warn", "RAM", f"Available memory is low (%{avail_pct:.0f})", "", 'Reduce background applications.', 15)
    pagefile_assessment = assess_pagefile_configuration(data.get("os"), dyn, commit_pct, avail_pct)
    if commit_pct is not None and commit_pct > 85 and pagefile_assessment["mode"] != "disabled":
        F.add("warn", "RAM", f"Commit ratio is high (%{commit_pct:.0f})", 'Approaching the virtual-memory limit.',
              'Reduce memory usage; review Windows page-file management and the commit limit.', 20)
    if pagefile_assessment["mode"] == "disabled":
        if pagefile_assessment["severity"] == "warn":
            F.add("warn", "RAM", 'The page file is disabled and memory commit pressure is high',
                  pagefile_assessment["recommendation"], 'Consider enabling the Windows system-managed page file.', 18)
        elif pagefile_assessment["severity"] == "info":
            F.add("info", "RAM", 'The page file is disabled (current pressure is low)',
                  pagefile_assessment["recommendation"], 'Consider a system-managed page file for memory-intensive professional workloads.', 3)
    if (base.get("mem_pages_in") or 0) > 100:
        F.add("warn", "RAM", 'Sustained page reads (hard faults)', f"{base['mem_pages_in']:.0f} pages/s are being read from disk.",
              "Physical memory may be insufficient.", 20)
    if bw_ratio is not None and bw_ratio < 0.4 and (ms.get("channels") or 0) >= 2:
        F.add("warn", "RAM", 'Measured memory bandwidth is far below the theoretical value',
              f"{bw_ratio * 100:.0f}% (typical: 55–75%).", 'Check BIOS memory settings and module placement.', 15)
    types = {m.get("size_bytes") for m in (ms.get("modules") or [])}
    if len(types) > 1:
        F.add("info", "RAM", 'Modules with different capacities', 'Equal capacity per channel provides the best balance.', "", 3)
    return {"total": total, "available": avail, "used": used, "avail_pct": avail_pct, "composition": comp,
            "commit_total": commit_total, "commit_limit": commit_limit, "commit_pct": commit_pct, "usable_safe": usable_safe,
            "reserve": reserve, "bw_ratio": bw_ratio, "xmp_ratio": xmp_ratio, "dram_ns": dram_ns, "power": power,
            "power_comp": c.rows, "bw": bw, "pagefile": pagefile_assessment}
def analyze_gpu(data, F):
    gpus = dig(data, "gpu.gpus", []) or []
    base = data.get("baseline") or {}
    out = []
    for g in gpus:
        nv = g.get("nvml") or {}
        eng = (base.get("gpu_eng") or {}).get(g.get("luid")) or {}
        mem = (base.get("gpu_mem") or {}).get(g.get("luid")) or {}
        vram_total = nv.get("vram_total") or g.get("dedicated_vram") or 0
        vram_used = nv.get("vram_used") if nv.get("vram_used") is not None else mem.get("dedicated")
        util = nv.get("util_gpu") if nv.get("util_gpu") is not None else eng.get("util")
        item = {**{k: g.get(k) for k in ("name", "vendor", "integrated", "driver_version", "driver_date", "shared_sys")},
                "vram_total": vram_total, "vram_used": vram_used,
                "vram_free": (vram_total - vram_used) if vram_used is not None and vram_total else None,
                "util": util, "engines": eng.get("by_type") or {}, "shared_used": mem.get("shared"),
                "nvml": nv or None, "fp32_tflops": nv.get("fp32_tflops"), "mem_bw_gbs": nv.get("mem_bw_gbs")}
        c = Comp()
        if g.get("integrated"):
            c.add('Integrated GPU', 22, 1.0, 'uses shared system memory')
        else:
            c.add("VRAM", lerp_score(vram_total / GIB, [(2, 10), (4, 28), (8, 50), (12, 66), (16, 78), (24, 92), (32, 100)]), 0.3,
                  f"{vram_total / GIB:.1f} GiB")
            if item["fp32_tflops"]:
                c.add('FP32 performance', lerp_score(item["fp32_tflops"], [(1, 10), (4, 30), (10, 55), (20, 75), (40, 92), (80, 100)]), 0.5,
                      f"≈ {item['fp32_tflops']:.1f} TFLOPS")
            if item["mem_bw_gbs"]:
                c.add('Memory bandwidth', lerp_score(item["mem_bw_gbs"], [(50, 10), (150, 30), (300, 55), (500, 78), (800, 95), (1000, 100)]),
                      0.2, f"≈ {item['mem_bw_gbs']:.0f} GB/s")
            if not item["fp32_tflops"] and not item["mem_bw_gbs"]:
                c.rows = [{"name": 'VRAM-based estimate', "value": clamp(lerp_score(vram_total / GIB, [(2, 10), (4, 28), (8, 50), (12, 66), (16, 78), (24, 92), (32, 100)]) * 0.9),
                           "weight": 1.0, "note": 'no detailed GPU metric (NVML)'}]
        item["power"], item["power_comp"] = c.score(), c.rows
        pen, notes = 0, []
        if nv.get("throttle"):
            pen += 25
            F.add("warn", "GPU", f"{g['name']}: active throttling", ", ".join(nv["throttle"]),
                  'Check cooling/power limits.', 25)
            notes.append('throttling')
        if nv.get("power_limit_w") and nv.get("power_default_w") and nv["power_limit_w"] < 0.9 * nv["power_default_w"]:
            pen += 15
            F.add("warn", "GPU", 'GPU power limit is below default',
                  f"{nv['power_limit_w']:.0f} W (default {nv['power_default_w']:.0f} W).", 'Check the power limit.', 15)
        if nv.get("temp") and nv.get("temp_slowdown") and nv["temp"] >= nv["temp_slowdown"] - 5:
            pen += 15
            F.add("warn", "GPU", 'GPU temperature is near the throttling threshold', f"{nv['temp']}°C / threshold {nv['temp_slowdown']}°C", "", 20)
        if nv.get("driver_model") == "TCC/WDM":
            F.add("info", "GPU", f"{g['name']} TCC (hesaplama) modunda", 'WDDM is required for display output/gaming.', "", 5)
        item["eff"] = min(90, 100 - pen) if not g.get("integrated") else None
        out.append(item)
    best = None
    discrete = [x for x in out if not x["integrated"]]
    if discrete:
        best = max(discrete, key=lambda x: x["vram_total"] or 0)
    elif out:
        best = out[0]
    if out and not discrete:
        F.add("info", "GPU", 'No discrete graphics card', 'Only an integrated GPU was detected; graphics/GPU workloads are limited.', "", 5)
    return {"list": out, "best": best, "has_discrete": bool(discrete)}
def analyze_storage(data, F):
    st = data.get("storage") or {}
    sysdrv = (dig(data, "os.system_drive", "C:") or "C:").upper().rstrip("\\")
    vols = st.get("volumes") or []
    sysvol = next((v for v in vols if v["mount"].upper().startswith(sysdrv)), vols[0] if vols else None)
    disk_of_sys = next((d for d in (st.get("disks") or []) if sysdrv[:1] in (d.get("drives") or [])), None)
    db = dig(data, "bench.disk", {}) or {}
    c = Comp()
    target_mount = (db.get("target_mount") or "").upper().rstrip("\\")
    sys_mount = (sysvol.get("mount") or "").upper().rstrip("\\") if sysvol else ""
    benchmark_matches_system = bool(target_mount and sys_mount and target_mount == sys_mount)
    use_bench = benchmark_matches_system
    if use_bench and db.get("seq_read_mbs"):
        c.add('Sequential read', lerp_score(db["seq_read_mbs"], [(100, 10), (500, 35), (1500, 55), (3000, 72), (5000, 85), (7000, 95), (12000, 100)]), 0.40,
              f"{db['seq_read_mbs']:.0f} MB/s")
    if use_bench and db.get("seq_write_mbs"):
        c.add('Sequential write', lerp_score(db["seq_write_mbs"], [(80, 10), (300, 30), (1000, 55), (2500, 75), (5000, 92), (10000, 100)]), 0.25,
              f"{db['seq_write_mbs']:.0f} MB/s")
    if use_bench and db.get("rand4k_iops"):
        c.add("Random 4K read (QD1)", lerp_score(db["rand4k_iops"], [(150, 10), (5000, 35), (10000, 50), (18000, 70), (30000, 88), (50000, 100)]),
              0.20, f"{db['rand4k_iops']:.0f} IOPS")
    if use_bench and db.get("rand4k_iops_write"):
        c.add("Random 4K write (QD1)", lerp_score(db["rand4k_iops_write"], [(100, 10), (3000, 30), (8000, 50), (15000, 70), (25000, 88), (40000, 100)]),
              0.15, f"{db['rand4k_iops_write']:.0f} IOPS")
    if not c.rows and disk_of_sys:
        k = disk_of_sys.get("kind") or ""
        c.add('Type-based estimate', 70 if "NVMe" in k else 40 if "SSD" in k else 15, 1.0, k)
    power = c.score()
    if db.get("seq_read_mbs") and not benchmark_matches_system:
        if target_mount and sys_mount:
            title = 'The disk benchmark ran on a different drive'
            detail = f"Test: {target_mount}; sistem birimi: {sys_mount}. The measurement was excluded from the system-disk score."
        else:
            title = 'The disk benchmark target volume could not be verified'
            detail = f"Test path: {db.get('path') or 'unknown'}; the test volume could not be matched to the system volume. The measurement was excluded from the system-disk score."
        F.add("info", "Disk", title, detail,
              'To measure the system drive, specify a folder on that volume with --disk-path.', 5)
    if sysvol:
        free_pct = 100 - sysvol["pct"]
        if free_pct < 8:
            F.add("bad", "Disk", f"Free space on the system drive is critically low (%{free_pct:.0f})", f"{fmt_bytes(sysvol['free'])} free.",
                  'Remove unnecessary files; space is needed for virtual memory and updates.', 35)
        elif free_pct < 15:
            F.add("warn", "Disk", f"Free space on the system drive is low (%{free_pct:.0f})", f"{fmt_bytes(sysvol['free'])} free.", 'Free up space.', 15)
    if disk_of_sys and (disk_of_sys.get("kind") or "").startswith("HDD"):
        F.add("warn", "Disk", 'System drive is an HDD', 'Boot and application-loading times are much slower than on an SSD.', 'Consider switching to an SSD.', 30)
    for d in (st.get("disks") or []):
        if d.get("health") and str(d["health"]).lower() not in ("healthy", "0"):
            F.add("bad", "Disk", f"{d['name']}: health status '{d['health']}'", "", "Verileri yedekleyin, diski kontrol edin.", 50)
    if db.get("rand4k_median_us") and db["rand4k_median_us"] > 500 and (not disk_of_sys or "HDD" not in (disk_of_sys.get("kind") or "")):
        F.add("info", "Disk", '4K random-read latency is high', f"Medyan {db['rand4k_median_us']:.0f} µs.", "", 5)
    return {"sysvol": sysvol, "sys_disk": disk_of_sys, "power": power, "power_comp": c.rows, "bench": db}
def analyze_os(data, F):
    o = data["os"]
    health = 100.0
    if o.get("pending_reboot"):
        health -= 8
        F.add("warn", "OS", 'Restart pending', ", ".join(o["pending_reboot"]), 'Restart the computer.', 12)
    up_days = (o.get("uptime_s") or 0) / 86400
    if up_days > 14:
        health -= 5
        F.add("info", "OS", f"Long system uptime ({up_days:.0f} days)",
              'When Fast Startup is enabled, shutdown/power-on does not reset the session.' if o.get("fast_startup") else "", 'A restart clears accumulated memory/driver state.', 8)
    if o.get("fast_startup"):
        F.add("info", "OS", 'Fast Startup is enabled', 'Shutdown/power-on is not a full restart.', "Use 'Restart' for a full reset.", 3)
    if o.get("secure_boot") is False:
        F.add("info", "OS", 'Secure Boot is disabled', 'Windows 11 requirement/security layer.', "", 3)
    if o.get("firmware") == "BIOS (Legacy)":
        F.add("info", "OS", "Legacy BIOS modu", "Windows 11 UEFI gerektirir.", "", 4)
    tpm = dig(data, "ps.tpm")
    if IS_WIN and tpm is None and not o.get("admin"):
        F.add("info", "OS", 'TPM status could not be read', 'Administrator permission is required.', "", 1)
    g = dig(data, "ps.guard")
    g = (as_list(g) or [{}])[0] or {}
    vbs_run = g.get("Vbs") == 2
    hvci = 2 in as_list(g.get("Running"))
    if hvci:
        F.add("info", "OS", 'Memory integrity (HVCI) is running', 'Security is improved; some workloads may incur a small performance cost.', "", 4)
    if (o.get("python") or {}).get("bits") == 32:
        F.add("warn", "OS", '32-bit Python is in use', 'Memory and benchmark accuracy are limited.', "64-bit Python kurun.", 20)
    if IS_WIN and not o.get("admin"):
        F.add("info", "OS", 'Run without administrator privileges', 'Some fields, such as TPM, cannot be read.', "", 1)
    return {"health": max(40.0, health), "vbs_running": vbs_run, "hvci_running": hvci, "uptime_days": up_days}
def compute_scores(data, A, F):
    cpu, ram, gpu, sto, osa = A["cpu"], A["memory"], A["gpu"], A["storage"], A["os"]
    base = data.get("baseline") or {}
    best = gpu.get("best")
    power_parts = {"CPU": cpu["power"], "RAM": ram["power"], "GPU": best["power"] if best else None, "Disk": sto["power"]}
    power = wavg([(power_parts["CPU"], 0.35), (power_parts["RAM"], 0.20), (power_parts["GPU"], 0.25), (power_parts["Disk"], 0.20)])
    av = Comp()
    cpu_av = cpu["free_equiv"] / cpu["total_equiv"] * 100 if cpu["total_equiv"] else None
    q = dig(base, "sys.queue")
    if cpu_av is not None and q and q > 2 * (data["cpu"]["topology"]["logical"] or 1):
        cpu_av *= 0.8
    core_equivalent_label = cpu.get("core_equivalent_label") or 'standard-core equivalent'
    av.add('CPU idle capacity', cpu_av, 0.30,
           f"≈ {cpu['free_equiv']:.1f} / {cpu['total_equiv']:.1f} {core_equivalent_label} free")
    ram_av = lerp_score(ram["avail_pct"], [(0, 0), (10, 25), (25, 60), (40, 85), (60, 100)]) if ram["avail_pct"] is not None else None
    if ram_av is not None:
        if (ram["commit_pct"] or 0) > 90:
            ram_av *= 0.8
        if (dig(base, "mem.mem_pages_in") or 0) > 200:
            ram_av *= 0.9
    av.add('RAM idle capacity', ram_av, 0.30, f"{fmt_bytes(ram['available'])} available (%{ram['avail_pct']:.0f})" if ram["avail_pct"] is not None else "")
    gpu_av = None
    if best:
        parts = []
        if best.get("util") is not None:
            parts.append(100 - best["util"])
        if not best["integrated"] and best.get("vram_free") is not None and best["vram_total"]:
            parts.append(lerp_score(best["vram_free"] / best["vram_total"] * 100, [(0, 0), (10, 30), (30, 70), (60, 100)]))
        gpu_av = sum(parts) / len(parts) if parts else None
    gpu_av_name = 'GPU engine idle capacity' if best and best.get("integrated") else 'GPU idle capacity'
    gpu_av_note = ""
    if best and best.get("integrated"):
        note_parts = []
        if best.get("util") is not None:
            note_parts.append(f"engine utilization {best['util']:.1f}%")
        if best.get("vram_free") is not None:
            note_parts.append(f"dedicated segment free {fmt_bytes(best['vram_free'])}")
        if best.get("shared_used") is not None:
            note_parts.append(f"shared memory utilization {fmt_bytes(best['shared_used'])}")
        if best.get("shared_sys") is not None:
            note_parts.append(f"DXGI shared-memory limit {fmt_bytes(best['shared_sys'])} (not an available budget)")
        gpu_av_note = "; ".join(note_parts)
    elif best and best.get("vram_free") is not None:
        gpu_av_note = f"Free VRAM: {fmt_bytes(best['vram_free'])}"
    av.add(gpu_av_name, gpu_av, 0.12, gpu_av_note)
    d_av = None
    if sto["sysvol"]:
        free_pct = 100 - sto["sysvol"]["pct"]
        d_av = lerp_score(free_pct, [(3, 10), (10, 40), (20, 75), (30, 100)])
        busy = dig(base, "disk.busy_pct")
        if busy is not None:
            d_av = 0.6 * d_av + 0.4 * (100 - min(100, busy))
    av.add('Disk availability', d_av, 0.16, f"system drive at %{100 - sto['sysvol']['pct']:.0f} free" if sto["sysvol"] else "")
    av.add('OS health', osa["health"], 0.12)
    availability = av.score()
    ef = Comp()
    ce = Comp()
    if cpu["allcore_ratio"] is not None:
        ce.add('Frequency under load', lerp_score(cpu["allcore_ratio"], [(0.6, 10), (0.8, 40), (0.95, 85), (1.0, 100)]), 0.30,
               f"all cores {fmt_ghz(cpu['allcore_mhz'])} (of the base ratio %{cpu['allcore_ratio'] * 100:.0f})")
    if cpu["scaling"] is not None:
        ce.add('Multi-core scaling', lerp_score(cpu["scaling"], [(0.5, 20), (0.7, 55), (0.85, 85), (0.95, 100)]), 0.30,
               f"%{cpu['scaling'] * 100:.0f}")
    pw = dig(data, "os.power", {}) or {}
    pol, notes = 100.0, []
    if pw.get("max_state") is not None and pw["max_state"] < 100:
        pol -= (100 - pw["max_state"])
        notes.append(f"maximum state %{pw['max_state']}")
    if pw.get("boost_mode") == 0:
        pol -= 25
        notes.append('boost disabled')
    if pw.get("epp") is not None and pw["epp"] > 50:
        pol -= 10
        notes.append(f"EPP {pw['epp']}")
    if pw.get("overlay") == 'Best power efficiency':
        pol -= 20
        notes.append('power mode: efficiency')
    if pw.get("scheme") == 'Power saver':
        pol -= 30
        notes.append('power-saving plan')
    if cpu["limit_ratio"] is not None and cpu["limit_ratio"] < 0.95:
        pol -= (1 - cpu["limit_ratio"]) * 100
        notes.append('OS frequency limit')
    if pw:
        ce.add('Power policy', pol, 0.20, ", ".join(notes) or 'no restriction')
    if cpu["sustained"]:
        ce.add('Sustained-load stability', lerp_score(cpu["sustained"]["ratio"], [(0.7, 20), (0.85, 60), (0.95, 95), (1.0, 100)]), 0.10,
               f"last/first slice throughput ratio %{cpu['sustained']['ratio'] * 100:.0f}")
    over = dig(base, "sys.dpc_pct")
    if over is not None:
        ce.add('Driver/interrupt load', 100 - 12 * max(0, (over + dig(base, "sys.intr_pct", 0)) - 1), 0.10,
               f"DPC+kesme %{over + dig(base, 'sys.intr_pct', 0):.1f}")
    cpu_eff = ce.score()
    re_ = Comp()
    if ram["bw_ratio"] is not None:
        re_.add('Bandwidth efficiency', lerp_score(ram["bw_ratio"], [(0.25, 20), (0.45, 55), (0.6, 85), (0.7, 100)]), 0.45,
                f"measured/theoretical = %{ram['bw_ratio'] * 100:.0f}")
    ch = data["memory"].get("channels")
    if ch and not (data["memory"].get("type") or "").startswith("LPDDR"):
        channel_note = f"{ch} channel(s) ({data['memory'].get('channels_source')})"
        module_sizes = {m.get("size_bytes") for m in (data["memory"].get("modules") or []) if m.get("size_bytes")}
        if len(module_sizes) > 1:
            channel_note += '; module capacities are asymmetric'
        re_.add("Channel configuration", 100 if ch >= 2 else 45, 0.30, channel_note)
    if ram["xmp_ratio"] is not None:
        re_.add('Operating speed / module speed', lerp_score(ram["xmp_ratio"], [(0.7, 40), (0.85, 55), (0.95, 100)]), 0.25,
                f"{data['memory'].get('run_mts')} / {data['memory'].get('rated_mts')} MT/s")
    ram_eff = re_.score()
    gpu_eff = best["eff"] if best and best.get("eff") is not None else (
        (100 if (data["memory"].get("channels") or 0) >= 2 else 55) if best and best["integrated"] else None)
    os_eff = 100 - (4 if osa["hvci_running"] else 0) - (2 if osa["vbs_running"] else 0)
    ef.add("CPU", cpu_eff, 0.40, 'frequency, scaling, power policy')
    ef.add("RAM", ram_eff, 0.30, 'bandwidth, channel, speed')
    ef.add("GPU", gpu_eff, 0.20, 'throttling/power limit; no load test performed, maximum 90' if best else "")
    ef.add('OS layer', os_eff, 0.10)
    efficiency = ef.score(min_weight=0.5)
    eff_partial = any(x is None for x in (cpu["allcore_ratio"], cpu["scaling"], ram["bw_ratio"]))
    eff_cap = power * (availability or 0) / 100 * (efficiency or 0) / 100 if None not in (power, availability, efficiency) else None
    return {"power": power, "availability": availability, "efficiency": efficiency, "effective": eff_cap,
            "efficiency_partial": eff_partial,
            "power_parts": power_parts, "avail_comp": av.rows, "eff_comp": ef.rows,
            "eff_sub": {"CPU": {"score": cpu_eff, "rows": ce.rows}, "RAM": {"score": ram_eff, "rows": re_.rows}}}
def analyze_balance(A):
    parts = {k: v for k, v in A["scores"]["power_parts"].items() if v is not None}
    if len(parts) < 2:
        return None
    lo, hi = min(parts, key=parts.get), max(parts, key=parts.get)
    return {"weakest": lo, "strongest": hi, "gap": parts[hi] - parts[lo], "parts": parts}
def rate_workloads(data, A):
    cpu, ram, gpu, sto = A["cpu"], A["memory"], A["gpu"], A["storage"]
    best = gpu.get("best") or {}
    st_measured = cpu.get("st_gops_measured") is True or cpu.get("st_gops_source") == "measured_ipc"
    st = (lerp_score(cpu["st_gops"], [(8, 10), (12, 30), (16, 50), (20, 70), (24, 85), (28, 97)])
          if st_measured and cpu.get("st_gops") is not None else None)
    if cpu.get("mt_gflops64_measured") is True and cpu.get("mt_gflops64") is not None:
        mt = lerp_score(cpu["mt_gflops64"], [(25, 10), (100, 30), (250, 50), (500, 70), (900, 90), (1500, 100)])
        mt_measured = True
    else:
        mt_component = next((row for row in cpu.get("power_comp", [])
                             if row.get("name") == 'Multi-core throughput'), None)
        mt = mt_component.get("value") if isinstance(mt_component, dict) else None
        mt_measured = False
    ram_gib = ram["total"] / GIB if ram.get("total") else None
    vram_gib = ((best.get("vram_total") or 0) / GIB if not best.get("integrated") else 0) if best else None
    gscore = best.get("power") if best else None
    seq = dig(sto, "bench.seq_read_mbs")
    virt = dig(data, "cpu.os_features.SANAL_FIRMWARE")
    virt_rating = 1 if virt is True else 0 if virt is False else None
    def rate(conds, estimated_factors=None):
        usable = []
        unmeasured = []
        lv, lim = 2, ""
        for name, val, ok, good in conds:
            if val is None:
                unmeasured.append(name)
                continue
            x = 2 if val >= good else 1 if val >= ok else 0 if val >= 0.6 * ok else -1
            usable.append((name, x))
            if x < lv:
                lv, lim = x, name
        for factor in (estimated_factors or []):
            if factor not in unmeasured:
                unmeasured.append(factor)
        if not usable:
            return 'Not measured', 'insufficient measurements', "Insufficient data: " + ", ".join(unmeasured)
        if unmeasured and lv > 1:
            lv = 1
        rating = {2: 'Very good', 1: "Suitable", 0: 'Borderline', -1: "Insufficient"}[lv]
        scope = "Complete" if not unmeasured else 'Partial — not measured/estimated: ' + ", ".join(unmeasured)
        return rating, lim if lv < 2 else "", scope
    wl = [
        ('Office / web / everyday use', [("RAM", ram_gib, 8, 16), ('CPU single-core', st, 25, 40), ('Disk speed', seq, 400, 1500)]),
        ('Video editing / color grading (4K, RAW, 3D LUT)', [("RAM", ram_gib, 16, 32), ("VRAM", vram_gib, 6, 12), ('CPU multi-core', mt, 45, 65), ('Disk speed', seq, 1000, 3000), ("GPU", gscore, 45, 65)]),
        ("Gaming (1080p / 60 FPS target; estimated)", [("GPU", gscore, 35, 55), ('CPU single-core', st, 25, 45), ("RAM", ram_gib, 8, 16), ("VRAM", vram_gib, 4, 8)]),
        ('Gaming (1440p high settings; estimated)', [("GPU", gscore, 50, 70), ('CPU single-core', st, 45, 65), ("RAM", ram_gib, 16, 32), ("VRAM", vram_gib, 8, 12)]),
        ('Gaming (4K high settings; estimated)', [("GPU", gscore, 70, 90), ('CPU single-core', st, 50, 75), ("RAM", ram_gib, 32, 64), ("VRAM", vram_gib, 12, 16)]),
        ('Multi-core computing / compilation / rendering', [('CPU multi-core', mt, 50, 70), ("RAM", ram_gib, 16, 32)]),
        ('Local AI (LLM / image generation)', [("VRAM", vram_gib, 8, 16), ("RAM", ram_gib, 16, 32), ("GPU", gscore, 50, 70)]),
        ('Local LLM (approximately 7B–13B class; depends on quantization)', [("VRAM", vram_gib, 8, 16), ("RAM", ram_gib, 16, 32), ("GPU", gscore, 45, 65)]),
        ('Photo editing', [("RAM", ram_gib, 16, 32), ('CPU single-core', st, 20, 35), ('Disk speed', seq, 300, 1000)]),
        ('DaVinci Resolve / 4K color grading (approximate profile)', [("RAM", ram_gib, 32, 64), ("VRAM", vram_gib, 8, 16), ('CPU multi-core', mt, 45, 75), ("GPU", gscore, 50, 75), ('Disk speed', seq, 1000, 3000)]),
        ('Premiere Pro / 4K editing (approximate profile)', [("RAM", ram_gib, 32, 64), ("VRAM", vram_gib, 6, 12), ('CPU multi-core', mt, 45, 75), ("GPU", gscore, 45, 70), ('Disk speed', seq, 1000, 3000)]),
        ('Blender / GPU rendering (approximate profile)', [("GPU", gscore, 55, 75), ("VRAM", vram_gib, 8, 16), ("RAM", ram_gib, 16, 32), ('CPU multi-core', mt, 40, 65)]),
        ('Unreal Engine / 3D editor (approximate profile)', [("RAM", ram_gib, 32, 64), ("GPU", gscore, 55, 75), ("VRAM", vram_gib, 8, 12), ('CPU multi-core', mt, 50, 75), ('Disk speed', seq, 1000, 3000)]),
        ('Audio production / low latency', [('CPU single-core', st, 25, 40), ("RAM", ram_gib, 8, 16)]),
        ('Large software compilation', [('CPU multi-core', mt, 60, 100), ("RAM", ram_gib, 16, 32), ('Disk speed', seq, 500, 2000)]),
        ('Virtual machine / development environment', [("RAM", ram_gib, 16, 32), ('CPU multi-core', mt, 40, 60), ('Virtualization', virt_rating, 1, 1)]),
    ]
    result = []
    for name, conds in wl:
        estimated = []
        if any(row[0] == 'CPU multi-core' for row in conds) and not mt_measured and mt is not None:
            estimated.append('CPU multi-core estimate')
        rating, limit, scope = rate(conds, estimated)
        result.append({"name": name, "rating": rating, "limit": limit, "measurement_scope": scope})
    return result
def recommend_upgrades(data, A):
    recs = []
    def add(priority, title, reason, benefit, confidence="medium"):
        recs.append({"priority": priority, "title": title, "reason": reason,
                     "expected_benefit": benefit, "confidence": confidence})
    R, M, G, S = A["memory"], data.get("memory") or {}, A["gpu"], A["storage"]
    ram_gib = R["total"] / GIB if R.get("total") else None
    mem_type = str(M.get("type") or "")
    sysvol, sysdisk = S.get("sysvol"), S.get("sys_disk")
    best = G.get("best") or {}
    vram_gib = best.get("vram_total") / GIB if best.get("vram_total") and not best.get("integrated") else 0 if best else None
    if sysdisk and str(sysdisk.get("kind") or "").startswith("HDD"):
        add(100, 'Consider replacing the system disk with an SSD/NVMe drive',
            'The system volume was detected as an HDD; random-access latency and application loading may be limiting factors.',
            'Potentially high benefit for everyday use and application startup', 'high')
    if sysvol and sysvol.get("pct") is not None and 100 - sysvol["pct"] < 15:
        add(95, 'Free up space on the system drive or increase its capacity',
            f"Only % free space is available on the system volume{100 - sysvol['pct']:.1f} free space is available.",
            'More space for updates, temporary files, and the page file', 'high')
    if ram_gib is not None and ram_gib < 8:
        add(92, 'Consider upgrading RAM to at least 16 GiB',
            f"Detected RAM: {ram_gib:.1f} GiB; multiple applications may create memory pressure.",
            'Potentially high benefit for multitasking and memory-intensive applications', 'high')
    elif ram_gib is not None and ram_gib < 16:
        add(82, 'Consider upgrading RAM to 16–32 GiB',
            f"Detected RAM: {ram_gib:.1f} GiB; this may limit editing, virtual machines, and large projects.",
            'Medium-to-high benefit for multitasking and mid-sized productivity workloads', "medium")
    elif ram_gib is not None and ram_gib < 32:
        profile_needs_more = any(w["name"].startswith(("DaVinci Resolve", "Premiere Pro", "Unreal Engine")) and w["rating"] in ("Insufficient", 'Borderline') for w in A.get("workloads", []))
        if profile_needs_more:
            add(68, 'Consider 32 GiB or more of RAM for editing/3D workflows',
                f"Detected RAM: {ram_gib:.1f} GiB, and at least one productivity profile is borderline/insufficient.",
                'Potentially medium benefit for large timelines, scenes, and multiple applications', "medium")
    channels = M.get("channels")
    if channels == 1 and not mem_type.startswith("LPDDR") and (M.get("populated") or 0) > 0:
        add(78, 'Verify the RAM channel layout using the motherboard manual',
            f"estimated from SMBIOS/slot labels {M.get('channels_source') or 'single-channel'}; this information may not be definitive.",
            'If dual-channel is supported but memory runs in single-channel mode, memory bandwidth may improve', "estimated")
    if best and not best.get("integrated") and vram_gib is not None and vram_gib < 8:
        add(72, 'Assess GPU memory requirements based on the workload',
            f"Approximately {vram_gib:.1f} GiB of VRAM is reported for the discrete GPU.",
            'Medium-to-high benefit for high-resolution editing, complex 3D scenes, and local AI', "medium")
    elif not best or best.get("integrated"):
        if any(w["name"].startswith(("DaVinci Resolve", "Blender", "Unreal Engine", "Local AI")) and w["rating"] in ("Insufficient", 'Borderline') for w in A.get("workloads", [])):
            add(70, 'Assess the need for a discrete GPU for productivity/3D/AI',
                'No suitable discrete GPU or GPU compute measurement was found; the workload limits of integrated graphics depend on the project.',
                'Potentially high benefit for GPU-accelerated workloads', 'workload-dependent')
    balance = A.get("balance") or {}
    weakest = balance.get("weakest")
    if weakest == "CPU" and A["cpu"].get("power") is not None and A["cpu"]["power"] < 45:
        add(60, 'Consider a CPU/platform upgrade only when measured workloads justify it',
            'The CPU is the weakest link in component scores; motherboard/socket and power/cooling compatibility must also be checked.',
            'Potentially medium benefit for CPU-heavy compilation, rendering, and computing', "medium")
    if weakest == "GPU" and best and A["gpu"].get("has_discrete"):
        add(58, 'Compare GPU upgrades if graphics/AI workloads are your priority',
            'The GPU appears to be the weakest link among current component performance scores.',
            'Potential benefit in gaming, GPU rendering, and AI; not guaranteed for every usage profile', "medium")
    recs.sort(key=lambda r: r["priority"], reverse=True)
    return recs[:6]
def resource_budget(data, A, worker_mb=None):
    cpu, ram, gpu = A["cpu"], A["memory"], A["gpu"]
    topo = data["cpu"]["topology"]
    reserve_cores = 1 if topo.get("physical_cores", 0) >= 6 else 0
    cpu_workers = max(0, int(math.floor((cpu.get("free_cores") or 0.0) + 0.25)) - reserve_cores)
    workers = min(int(topo.get("logical") or 0), cpu_workers)
    safe_ram = max(0, int(ram.get("usable_safe") or 0))
    out = {"physical_cores": topo.get("physical_cores", 0), "logical_threads": topo.get("logical", 0),
           "recommended_workers": workers, "free_physical_core_equiv": round(cpu.get("free_cores") or 0.0, 2),
           "ram_budget_safe_bytes": safe_ram,
           "ram_budget_aggressive_bytes": int(max(0, (ram.get("available") or 0) - GIB)),
           "os_ram_reserve_bytes": int(ram.get("reserve") or 0),
           "worker_recommendation_status": "suitable" if workers > 0 else 'insufficient resources; do not start parallel jobs'}
    if worker_mb is not None:
        if int(worker_mb) <= 0:
            raise ValueError('worker_mb must be a positive MiB value')
        by_ram = int(safe_ram // (int(worker_mb) * MIB))
        out["max_workers_by_ram"] = by_ram
        workers = min(workers, by_ram)
        out["recommended_workers"] = workers
        out["worker_recommendation_status"] = "suitable" if workers > 0 else 'The RAM budget is insufficient even for one worker'
    chunk = min(float(GIB), safe_ram / workers / 4) if workers > 0 else 0
    out["suggested_chunk_bytes"] = int(chunk // MIB * MIB) if workers > 0 else 0
    best = gpu.get("best")
    out["vram_budget_bytes"] = int(best["vram_free"] * 0.85) if best and best.get("vram_free") is not None and not best.get("integrated") else None
    tmp = tempfile.gettempdir()
    try:
        out["temp_dir"], out["temp_free_bytes"] = tmp, shutil.disk_usage(tmp).free
        out["temp_budget_bytes"] = int(out["temp_free_bytes"] * 0.5)
    except OSError:
        pass
    return out
def build_verdict(A):
    s = A["scores"]
    lines = []
    lines.append(f"Hardware power: {power_tier(s['power'])} (Power score {s['power']:.0f}/100)." if s["power"] is not None else 'Hardware performance could not be calculated.')
    if s["availability"] is not None:
        lines.append(f"Current availability: {grade(s['availability'])} — approximately % of resources{s['availability']:.0f}' is idle/available for use.")
    if s["efficiency"] is not None:
        lines.append(f"Verimlilik: {grade(s['efficiency'])} — approximately % of hardware potential{s['efficiency']:.0f}' can be used efficiently."
                     + (' (partial data: some benchmarks were skipped or could not be measured)' if s.get("efficiency_partial") else ""))
    else:
        lines.append('Efficiency: could not be calculated due to insufficient measurements (run again in standard mode).')
    if s["effective"] is not None:
        lines.append(f"Effective usable capacity ≈ {s['effective']:.0f}/100  (Power × Availability × Efficiency).")
    if s.get("health") is not None:
        lines.append(f"Hardware/stability indicator: {s['health']:.0f}/100; evaluated when sensor and event-log data were available.")
    if s.get("data_quality") is not None:
        lines.append(f"Data coverage: {s['data_quality']:.0f}/100; this is the completion ratio of measurements, not an accuracy guarantee.")
    return lines
def analyze_hardware_health(data, F):
    score, details = 100.0, []
    temperature_peaks, telemetry_peaks = {}, {}
    temperature_observations: list[float] = []
    cross_provider_observations: dict[tuple, list[tuple[str, float]]] = {}
    duplicate_source_observations_suppressed = 0
    temperature_global_phase_counts: dict[str, int] = {}
    ambiguous_component_identifiers: set[str] = set()
    gpu_rows = as_list(dig(data, "gpu.gpus", []))
    gpu_name_counts: dict[str, int] = {}
    for gpu_row in gpu_rows:
        if isinstance(gpu_row, dict):
            gpu_name = str(gpu_row.get("name") or gpu_row.get("Name") or "").strip()
            if gpu_name:
                gpu_name_counts[gpu_name.casefold()] = gpu_name_counts.get(gpu_name.casefold(), 0) + 1
    for gpu_row in gpu_rows:
        if isinstance(gpu_row, dict):
            gpu_name = str(gpu_row.get("name") or gpu_row.get("Name") or "").strip()
            if gpu_name and gpu_name_counts.get(gpu_name.casefold(), 0) > 1:
                identifier = sensor_component_identifier("GPU", gpu_name)
                if identifier:
                    ambiguous_component_identifiers.add(identifier)
    storage_rows = as_list(dig(data, "inventory.storage.devices", []))
    storage_name_counts: dict[str, int] = {}
    for disk_row in storage_rows:
        if isinstance(disk_row, dict):
            disk_name = str(disk_row.get("name") or disk_row.get("model") or "").strip()
            if disk_name:
                storage_name_counts[disk_name.casefold()] = storage_name_counts.get(disk_name.casefold(), 0) + 1
    for disk_row in storage_rows:
        if isinstance(disk_row, dict):
            disk_name = str(disk_row.get("name") or disk_row.get("model") or "").strip()
            if disk_name and storage_name_counts.get(disk_name.casefold(), 0) > 1:
                identifier = sensor_component_identifier("Storage", disk_name)
                if identifier:
                    ambiguous_component_identifiers.add(identifier)
    cpu_packages = _number(dig(data, "cpu.topology.packages"))
    if cpu_packages is not None and cpu_packages > 1:
        cpu_name = str(dig(data, "cpu.name", "")).strip()
        identifier = sensor_component_identifier("CPU", cpu_name)
        if identifier:
            ambiguous_component_identifiers.add(identifier)
    sensor_units = {"temperature": "°C", "power": "W", "fan": "RPM", "clock": "MHz", "voltage": "V", "load": "%"}
    def resolve_component_identifier(hardware_type: Any, parent: Any, provider_identity: Any = None) -> str | None:
        category = _hardware_category(hardware_type, parent).casefold()
        parent_key = re.sub(r"\s+", " ", _enum_text(parent).strip()).casefold()
        fallback = sensor_component_identifier(hardware_type, parent)
        supplied = str(provider_identity or "").strip()
        if supplied:
            return None if supplied in ambiguous_component_identifiers else supplied
        if not fallback or fallback in ambiguous_component_identifiers:
            return None
        if category == "gpu" and parent_key:
            matches = [row for row in gpu_rows if isinstance(row, dict) and
                       re.sub(r"\s+", " ", str(row.get("name") or row.get("Name") or "").strip()).casefold() == parent_key]
            if len(matches) == 1:
                luid = str(matches[0].get("luid") or matches[0].get("Luid") or "").strip()
                if luid:
                    return f"gpu:luid:{luid.casefold()}"
        elif category == "storage" and parent_key:
            matches = [row for row in storage_rows if isinstance(row, dict) and
                       re.sub(r"\s+", " ", str(row.get("name") or row.get("model") or "").strip()).casefold() == parent_key]
            if len(matches) == 1:
                physical_id = str(matches[0].get("physical_device_id") or "").strip()
                if physical_id:
                    return f"storage:{physical_id.casefold()}"
        elif category == "cpu" and cpu_packages == 1:
            cpu_name = re.sub(r"\s+", " ", str(dig(data, "cpu.name", "") or "").strip()).casefold()
            if parent_key and parent_key == cpu_name:
                return "cpu:package:0"
        return fallback
    def add_metric(parent, name, metric, value, unit, phase, elapsed_s=None, source=None, timestamp=None,
                   min_is_peak=False):
        try:
            value = float(value)
        except (TypeError, ValueError, OverflowError):
            return
        if not math.isfinite(value):
            return
        key = (str(parent).casefold(), str(name).casefold(), str(metric).casefold())
        item = telemetry_peaks.setdefault(key, {"parent": str(parent), "name": str(name), "metric": str(metric),
                                                "unit": unit, "value": value, "phases": [], "sample_count": 0,
                                                "sources": [], "first_timestamp": timestamp,
                                                "last_timestamp": timestamp})
        item["sample_count"] += 1
        if phase not in item["phases"]:
            item["phases"].append(phase)
        if source and source not in item["sources"]:
            item["sources"].append(source)
        if timestamp:
            item["first_timestamp"] = min(filter(None, (item.get("first_timestamp"), timestamp)), default=timestamp)
            item["last_timestamp"] = max(filter(None, (item.get("last_timestamp"), timestamp)), default=timestamp)
        if (value <= item["value"]) if min_is_peak else (value >= item["value"]):
            item["value"], item["phase"] = value, phase
            if elapsed_s is not None:
                item["elapsed_s"] = elapsed_s
            if timestamp:
                item["peak_timestamp"] = timestamp
    def ingest_sensors(raw, phase, elapsed_s=None, sample_timestamp=None):
        nonlocal duplicate_source_observations_suppressed
        for sensor in as_list(raw):
            try:
                stype = str(sensor.get("SensorType", "")).casefold()
                if stype not in sensor_units or sensor.get("Value") is None:
                    continue
                value = float(sensor["Value"])
                if not math.isfinite(value):
                    continue
                name = str(sensor.get("Name") or "")
                if stype == "temperature":
                    value = valid_temperature_value(value, name)
                    if value is None:
                        continue
                parent = str(sensor.get("Parent") or "")
                source = str(sensor.get("source") or sensor.get("Source") or "Unknown source")
                timestamp = str(sample_timestamp or sensor.get("timestamp") or "") or None
                hardware_type = str(sensor.get("HardwareType") or sensor.get("hardware_type") or "Unknown")
                role = str(sensor.get("SensorRole") or sensor.get("sensor_role") or hardware_type)
                component_identifier = resolve_component_identifier(
                    hardware_type, parent, sensor.get("SensorComponentIdentifier")
                )
                if stype == "temperature" and (value <= 0.0 or value > 200.0):
                    continue
                add_metric(parent, name, stype, value, sensor_units[stype], phase, elapsed_s,
                           source=source, timestamp=timestamp, min_is_peak=(stype == "voltage"))
                if stype != "temperature":
                    continue
                sensor_identifier = str(sensor.get("SensorIdentifier") or sensor.get("sensor_identifier") or "")
                key = (hardware_type.casefold(), parent.casefold(), name.casefold(), sensor_identifier.casefold())
                item = temperature_peaks.setdefault(key, {
                    "name": name, "parent": parent, "hardware_type": hardware_type,
                    "sensor_role": role, "sensor_identifier": sensor_identifier or None,
                    "component_identifier": component_identifier,
                    "value_c": value, "min_c": value, "max_c": value, "mean_c": value,
                    "_sum_c": 0.0, "_observations": set(), "sources": [], "phases": [],
                    "sample_count": 0, "sample_counts_by_phase": {},
                    "first_timestamp": timestamp, "last_timestamp": timestamp,
                })
                observation_key = (timestamp, round(value, 6), source)
                if observation_key in item["_observations"]:
                    continue
                item["_observations"].add(observation_key)
                duplicate_key = None
                if component_identifier and timestamp:
                    duplicate_key = (component_identifier,
                                     sensor_deduplication_channel(hardware_type, name), timestamp)
                duplicate_observation = False
                if duplicate_key is not None:
                    prior = cross_provider_observations.setdefault(duplicate_key, [])
                    duplicate_observation = any(
                        prior_source != source and abs(prior_value - value) <= 0.25
                        for prior_source, prior_value in prior
                    )
                    if duplicate_observation:
                        duplicate_source_observations_suppressed += 1
                    else:
                        prior.append((source, value))
                if not duplicate_observation:
                    temperature_observations.append(value)
                    temperature_global_phase_counts[phase] = temperature_global_phase_counts.get(phase, 0) + 1
                item["sample_count"] += 1
                phase_counts = item.setdefault("sample_counts_by_phase", {})
                phase_counts[phase] = phase_counts.get(phase, 0) + 1
                item["_sum_c"] += value
                item["min_c"] = min(item["min_c"], value)
                item["max_c"] = max(item["max_c"], value)
                item["mean_c"] = item["_sum_c"] / item["sample_count"]
                item["value_c"] = item["max_c"]
                if source not in item["sources"]:
                    item["sources"].append(source)
                if phase not in item["phases"]:
                    item["phases"].append(phase)
                if timestamp:
                    old_first, old_last = item.get("first_timestamp"), item.get("last_timestamp")
                    item["first_timestamp"] = min(filter(None, (old_first, timestamp)), default=timestamp)
                    item["last_timestamp"] = max(filter(None, (old_last, timestamp)), default=timestamp)
                if value >= item["max_c"]:
                    item["peak_phase"] = phase
                    if elapsed_s is not None:
                        item["peak_elapsed_s"] = elapsed_s
                    if timestamp:
                        item["peak_timestamp"] = timestamp
                if value <= item["min_c"]:
                    item["minimum_timestamp"] = timestamp
            except (TypeError, ValueError, AttributeError, OverflowError):
                continue
    def ingest_nvml(raw, phase, elapsed_s=None, sample_timestamp=None):
        for gpu_sample in as_list(raw):
            parent = str(gpu_sample.get("name") or gpu_sample.get("index") or "GPU")
            timestamp = str(gpu_sample.get("timestamp") or sample_timestamp or "") or None
            gpu_temp = gpu_sample.get("temp")
            if gpu_temp is not None:
                ingest_sensors([{"SensorType": "Temperature", "Name": "GPU temperature", "Parent": parent,
                                 "HardwareType": "GPU", "SensorRole": "GPU", "Value": gpu_temp,
                                 "source": "NVIDIA NVML", "timestamp": timestamp}], phase, elapsed_s, timestamp)
            add_metric(parent, 'GPU power', "power", gpu_sample.get("power_w"), "W", phase, elapsed_s,
                       source="NVIDIA NVML", timestamp=timestamp)
            add_metric(parent, "GPU fan", "fan", gpu_sample.get("fan"), "%", phase, elapsed_s,
                       source="NVIDIA NVML", timestamp=timestamp)
            add_metric(parent, "GPU grafik hoursi", "clock", gpu_sample.get("clk_gfx"), "MHz", phase, elapsed_s,
                       source="NVIDIA NVML", timestamp=timestamp)
            add_metric(parent, "GPU memory clock", "clock", gpu_sample.get("clk_mem"), "MHz", phase, elapsed_s,
                       source="NVIDIA NVML", timestamp=timestamp)
            add_metric(parent, 'GPU utilization', "load", gpu_sample.get("util_gpu"), "%", phase, elapsed_s,
                       source="NVIDIA NVML", timestamp=timestamp)
    ingest_sensors(data.get("sensors"), 'baseline')
    ingest_sensors(data.get("sensors_after_benchmark"), 'after benchmark')
    for sample in as_list(data.get("sensor_history")):
        if isinstance(sample, dict):
            ingest_sensors(sample.get("sensors"), 'sensor sampling', sample.get("elapsed_s"), sample.get("timestamp"))
            ingest_nvml(sample.get("gpus"), 'sensor sampling', sample.get("elapsed_s"), sample.get("timestamp"))
    for phase_key, phase_label in (("cpu", 'CPU sustained load'), ("gpu", 'GPU benchmark load')):
        series = dig(data, "bench.cpu.sustained.thermal_series", []) if phase_key == "cpu" else dig(data, "bench.gpu.thermal_series", [])
        for sample in as_list(series):
            if isinstance(sample, dict):
                ingest_sensors(sample.get("sensors"), phase_label, sample.get("elapsed_s"), sample.get("timestamp"))
                ingest_nvml(sample.get("gpus"), phase_label, sample.get("elapsed_s"), sample.get("timestamp"))
    for gpu in ((data.get("gpu") or {}).get("gpus") or []):
        nv = gpu.get("nvml") or {}
        if nv:
            ingest_nvml([{**nv, "name": gpu.get("name") or "GPU"}], 'NVML last sample')
    disks = (data.get("storage") or {}).get("disks") or []
    for disk in disks:
        reliability = disk.get("windows_storage_reliability") or disk.get("reliability") or {}
        disk_temperature = reliability.get("Temperature")
        if disk_temperature is not None:
            disk_name = disk.get("name") or "Disk"
            ingest_sensors([{"SensorType": "Temperature", "Name": "Storage reliability temperature",
                             "Parent": disk_name, "HardwareType": "Storage", "SensorRole": "Storage",
                             "Value": disk_temperature, "source": "Windows Storage Reliability",
                             "SensorIdentifier": f"windows-storage-reliability:{disk.get('id') or disk_name}",
                             "timestamp": dig(data, "meta.timestamp")}], 'disk health counters')

    for disk in as_list(dig(data, "inventory.storage.devices", [])):
        if not isinstance(disk, dict):
            continue
        smart = disk.get("smart") or {}
        if not isinstance(smart, dict):
            continue
        disk_name = str(disk.get("name") or disk.get("model") or smart.get("model") or "Disk")
        smart_path = str(smart.get("device_path") or disk.get("device_path") or disk_name)
        smart_temperature = smart.get("temperature_c")
        if smart_temperature is not None:
            ingest_sensors([{"SensorType": "Temperature", "Name": "SMART composite temperature",
                             "Parent": disk_name, "HardwareType": "Storage", "SensorRole": "Storage",
                             "Value": smart_temperature, "source": "smartctl",
                             "SensorIdentifier": f"smartctl:{smart_path}:temperature",
                             "timestamp": dig(data, "meta.timestamp")}], "smartctl SMART")
        for channel in as_list(smart.get("temperature_channels")):
            if not isinstance(channel, dict):
                continue
            ingest_sensors([{"SensorType": "Temperature", "Name": channel.get("name") or "SMART temperature channel",
                             "Parent": disk_name, "HardwareType": "Storage", "SensorRole": "Storage",
                             "Value": channel.get("temperature_c"), "source": "smartctl",
                             "SensorIdentifier": channel.get("sensor_identifier") or f"smartctl:{smart_path}:temperature-channel",
                             "timestamp": dig(data, "meta.timestamp")}], "smartctl SMART")
    temps = list(temperature_peaks.values())
    for temp in temps:
        temp.pop("_observations", None)
        temp.pop("_sum_c", None)
        label = f"{temp['parent']} {temp['name']}".strip()
        lower = label.casefold()
        role = str(temp.get("sensor_role") or temp.get("hardware_type") or "").casefold()
        threshold = 90.0 if role == "gpu" or "gpu" in lower or "graphics" in lower else 95.0
        if temp["max_c"] >= 100:
            score -= 20
            F.add("bad", "Termal", f"Very high temperature: {label or 'sensor'}",
                  f"{temp['max_c']:.1f} °C; peak phase: {temp.get('peak_phase', 'unknown')}.",
                  'Stop the load test; check cooling, fans, and airflow.', 35)
            details.append({"kind": "temperature", **temp, "status": "critical"})
        elif temp["max_c"] >= threshold:
            score -= 8
            F.add("warn", "Termal", f"High temperature: {label or 'sensor'}",
                  f"{temp['max_c']:.1f} °C; peak phase: {temp.get('peak_phase', 'unknown')}.",
                  'Check cooling, the fan curve, and frequency drops under sustained load.', 18)
            details.append({"kind": "temperature", **temp, "status": "warning"})
    disks = (data.get("storage") or {}).get("disks") or []
    for disk in disks:
        rel = disk.get("windows_storage_reliability") or disk.get("reliability") or {}
        name = disk.get("name") or "Disk"
        temperature = valid_temperature_value(rel.get("Temperature", rel.get("temperature_c")),
                                              "Storage reliability temperature")
        wear = rel.get("Wear", rel.get("wear_pct"))
        error_values = []
        for field in ("ReadErrorsUncorrected", "WriteErrorsUncorrected"):
            raw_counter = rel.get(field)
            if raw_counter is None or isinstance(raw_counter, bool):
                continue
            try:
                parsed_counter = int(raw_counter)
            except (TypeError, ValueError, OverflowError):
                continue
            error_values.append(parsed_counter)
        bad_errors = sum(error_values) if error_values else None
        if temperature is not None and temperature >= 70:
            score -= 10
            F.add("warn", "Disk", f"{name}: disk temperature is high", f"{temperature} °C.",
                  'Check disk cooling and airflow.', 20)
        if wear is not None and float(wear) >= 90:
            score -= 20
            F.add("warn", "Disk", f"{name}: reported SSD wear is high", f"Wear={wear}.",
                  'Back up your data and verify life/health status using the manufacturer tool.', 30)
        if bad_errors is not None and bad_errors > 0:
            score -= 25
            F.add("bad", "Disk", f"{name}: uncorrectable read/write errors were reported", f"Counter total {bad_errors}.",
                  'Back up your data first, then check disk/connection health.', 45)
        if rel:
            details.append({"kind": "disk", "name": name, "source": "Windows Storage Reliability",
                            "temperature_c": temperature, "wear": wear,
                            "power_on_hours": rel.get("PowerOnHours"), "uncorrected_errors": bad_errors})
    for disk in as_list(dig(data, "inventory.storage.devices", [])):
        if not isinstance(disk, dict):
            continue
        smart = disk.get("smart") or {}
        if not isinstance(smart, dict) or not smart:
            continue
        name = str(disk.get("name") or disk.get("model") or "Disk")
        passed = smart.get("smart_passed")
        wear = smart.get("percentage_used")
        media_errors = smart.get("media_errors")
        error_log_entries = smart.get("num_err_log_entries")
        if passed is False:
            score -= 30
            F.add("bad", "SMART", f"{name}: smartctl reports a failed health status",
                  f"SMART health status failed; smartctl exit code {smart.get('smartctl_exit_status')!s}.",
                  'Back up your data first; inspect the device and manufacturer diagnostics.', 50)
        if isinstance(wear, (int, float)) and not isinstance(wear, bool) and wear >= 90:
            score -= 15
            F.add("warn", "SMART", f"{name}: NVMe wear percentage is high",
                  f"smartctl percentage_used={wear}.",
                  'Ensure backups are current and monitor SSD life.', 30)
        decoded_exit_status = _smartctl_exit_status_details(smart.get("smartctl_exit_status"))
        error_log_present = bool(smart.get("error_log_present")) or decoded_exit_status["error_log_present"]
        self_test_log_errors = bool(smart.get("self_test_log_errors")) or decoded_exit_status["self_test_log_errors"]
        startup_write_cache_abort = error_log_present and smartctl_is_single_boot_write_cache_abort(smart)
        if error_log_present:
            score -= 2 if startup_write_cache_abort else 8
            log_count = smart.get("error_log_count", error_log_entries)
            entry_note = f"Number of log entries: {log_count}." if log_count is not None else 'The error-log flag is active.'
            last_entries = as_list(smart.get("error_log_entries"))
            if last_entries:
                recent = last_entries[0]
                event_hours = recent.get("lifetime_hours")
                entry_note += (f" Error description in the newest entry: {recent.get('error_description') or 'no details'}; "
                               f"disk power-on hours at event time: {event_hours if event_hours is not None else 'unknown'}.")
                command_trail = as_list(recent.get("previous_commands"))
                decoder_context = _smartctl_decoder_context(recent)
                latest_history_command = recent.get("latest_history_command") or (command_trail[0] if command_trail else None)
                if isinstance(decoder_context, dict):
                    context_name = decoder_context.get("command_name") or "ATA command"
                    context_opcode = decoder_context.get("command")
                    context_features = decoder_context.get("features")
                    context_suffix = f" (CR=0x{context_opcode:02X}" if isinstance(context_opcode, int) else " (CR=unknown"
                    if isinstance(context_features, int):
                        context_suffix += f", FR=0x{context_features:02X}"
                    context_suffix += ")"
                    entry_note += f" smartmontools interprets the error register in the context of the newest entry in the five-entry command history: {context_name}{context_suffix}."
                elif isinstance(latest_history_command, dict):
                    history_name = latest_history_command.get("command_name") or "ATA command"
                    entry_note += f" Newest recorded command-history entry: {history_name}; because the JSON does not expose five raw history slots, the error-register history slot could not be identified with certainty."
                if recent.get("lba") is not None:
                    lba_is_address = recent.get("lba_is_command_address")
                    if lba_is_address is None and isinstance(decoder_context, dict) and decoder_context.get("command") == 0xEF:
                        lba_is_address = False
                    lba_note = 'The LBA register field is not an address for this command' if lba_is_address is False else 'The LBA register field is a raw value; it was not verified as a sector address'
                    entry_note += f" ATA LBA register (raw)={recent.get('lba')} ({lba_note})."
                if command_trail:
                    names = [str(item.get("command_name")) for item in command_trail
                             if isinstance(item, dict) and item.get("command_name")]
                    if names:
                        entry_note += ' Command context recorded before the error: ' + ", ".join(names[:5]) + "."
            if startup_write_cache_abort:
                F.add("info", "SMART", f"{name}: one historical ABRT entry during write-cache setting at startup",
                      entry_note + ' The record was associated with a single SET FEATURES [Enable write cache] command at disk power-on hour 0; the SMART health summary reported PASS and no positive media errors. This classification alone is not evidence of a failure.',
                      'Keep your backups up to date. Recheck the disk/connection if the record recurs, a new SMART error-log entry appears, or media errors increase.', 5)
            else:
                F.add("warn", "SMART", f"{name}: historical entry in the SMART error log",
                      entry_note + ' The overall SMART health summary may be PASS; log records should be reviewed separately.',
                      'Back up important data. Review the SMART error-log entry, its error type, LBA field, and power-on hours; diagnose the disk/connection if the error recurs.', 28)
        if self_test_log_errors:
            score -= 12
            F.add("warn", "SMART", f"{name}: a failed test entry exists in the SMART self-test log",
                  f"Active self-test error count: {smart.get('self_test_active_error_count')!s}; "
                  f"total entries: {smart.get('self_test_error_count')!s}.",
                  'Back up important data; review the test type, status, and LBA information in the self-test log. Assess the existing record before starting another long test.', 32)
        non_log_errors = (isinstance(media_errors, (int, float)) and not isinstance(media_errors, bool) and media_errors > 0)
        if non_log_errors or (isinstance(error_log_entries, (int, float)) and not isinstance(error_log_entries, bool)
                              and error_log_entries > 0 and not error_log_present):
            score -= 10
            F.add("warn", "SMART", f"{name}: SMART error counters are greater than zero",
                  f"media_errors={media_errors}; num_err_log_entries={error_log_entries}.",
                  'Monitor SMART logs and disk behavior; back up important data.', 25)
        smart_power_on_hours = smart.get("power_on_hours")
        if smart_power_on_hours is None:
            smart_power_on_hours = _smartctl_ata_power_on_hours({"table": as_list(smart.get("ata_attributes"))})
        latest_error_entry = dict((as_list(smart.get("error_log_entries")) or [{}])[0])
        latest_context = _smartctl_decoder_context(latest_error_entry)
        if isinstance(latest_context, dict) and latest_error_entry.get("lba_is_command_address") is None:
            if latest_context.get("command") == 0xEF:
                latest_error_entry["lba_is_command_address"] = False
        details.append({"kind": "smartctl", "name": name, "source": "smartctl",
                        "smart_passed": passed, "health_status": smart.get("health_status"),
                        "temperature_c": valid_temperature_value(smart.get("temperature_c"), "SMART composite temperature"),
                        "wear_pct": wear,
                        "power_on_hours": smart_power_on_hours,
                        "media_errors": media_errors, "num_err_log_entries": error_log_entries,
                        "error_log_present": error_log_present,
                        "startup_write_cache_abort": startup_write_cache_abort,
                        "error_log_count": smart.get("error_log_count"),
                        "error_log_entries": as_list(smart.get("error_log_entries")),
                        "error_command_context": latest_context,
                        "self_test_log_errors": self_test_log_errors,
                        "self_test_active_error_count": smart.get("self_test_active_error_count"),
                        "smartctl_exit_status": smart.get("smartctl_exit_status"),
                        "exit_status_codes": as_list(smart.get("exit_status_codes")) or decoded_exit_status["codes"],
                        "query_status": smart.get("query_status")})
    events = (data.get("ps") or {}).get("reliability") or {}
    if int(events.get("WHEA") or 0) > 0:
        score -= min(25, int(events["WHEA"]) * 5)
        F.add("warn", 'Windows events', 'A WHEA hardware-error record exists within the last 30 days',
              f"Record count: {events['WHEA']}.", 'Review event details; verify CPU/RAM/PCIe stability and BIOS.', 30)
    if int(events.get("BugCheck") or 0) > 0:
        score -= min(25, int(events["BugCheck"]) * 8)
        F.add("warn", 'Windows events', 'A BugCheck/volmgr record exists within the last 30 days',
              f"Record count: {events['BugCheck']}.", 'Review minidump and Event Viewer records.', 25)
    if int(events.get("UpdateEvents") or 0) > 0:
        F.add("info", "Windows Update", 'An update warning/error record exists within the last 30 days',
              f"Record count: {events['UpdateEvents']}.", 'Compare event details with Windows Update history.', 6)
    problem_devices = as_list((data.get("ps") or {}).get("devices"))
    if problem_devices:
        F.add("warn", 'Device drivers', 'Windows reports a problematic device',
              "; ".join(f"{x.get('FriendlyName') or x.get('Class')}: {x.get('Status')}" for x in problem_devices[:8]),
              'Review the driver and device status in Device Manager.', 15)
    memory_test = dig(data, "bench.memory_integrity")
    if memory_test and memory_test.get("passed") is False:
        score -= 35
        F.add("bad", "RAM", 'Mismatch detected in memory sampling test', memory_test.get("error", ""),
              'Back up important data; verify RAM stability with a memory diagnostic tool.', 50)
    sec = (data.get("ps") or {}).get("security") or {}
    defender = sec.get("Defender")
    if isinstance(defender, list):
        defender = defender[0] if defender else None
    firewall = as_list(sec.get("Firewall"))
    firewall_disabled = [x.get("Name") for x in firewall if x.get("Enabled") is False]
    bitlocker = as_list(sec.get("BitLocker"))
    if isinstance(defender, dict) and defender.get("RealTimeProtectionEnabled") is False:
        F.add("warn", 'Security', 'Microsoft Defender real-time protection is disabled', "", 
              'Verify Defender protection unless you use another security product.', 15)
    if firewall_disabled:
        F.add("warn", 'Security', 'A Windows Firewall profile is disabled', ", ".join(str(x) for x in firewall_disabled),
              'Check the firewall settings for the network profile.', 15)
    unencrypted = [x for x in bitlocker if str(x.get("VolumeStatus", "")).lower() in ("fullydecrypted", "decrypted")
                   and x.get("MountPoint")]
    if unencrypted:
        F.add("info", 'Security', 'BitLocker encryption is not visible on the reported volumes',
              ", ".join(str(x.get("MountPoint")) for x in unencrypted),
              'Consider disk encryption if device loss/theft is a risk.', 4)
    health_sources = []
    if temps:
        health_sources.append('thermal sensors')
    if any(
        valid_temperature_value(rel.get("Temperature", rel.get("temperature_c")),
                                "Storage reliability temperature") is not None
        or any(rel.get(k) is not None for k in ("Wear", "wear_pct", "PowerOnHours", "power_on_hours",
                                                 "ReadErrorsUncorrected", "WriteErrorsUncorrected"))
        for rel in (d.get("windows_storage_reliability") or d.get("reliability") or {} for d in disks)
        if isinstance(rel, dict)
    ):
        health_sources.append("Windows Storage Reliability")
    if any(
        isinstance(disk.get("smart"), dict)
        and disk["smart"].get("query_status") == "success"
        for disk in as_list(dig(data, "inventory.storage.devices", []))
        if isinstance(disk, dict)
    ):
        health_sources.append("smartctl SMART")
    if events.get("WindowDays") is not None and events.get("QueryAvailable", True):
        health_sources.append('Windows event logs')
    if memory_test:
        health_sources.append('RAM sampling test')
    health_score = clamp(score, 0, 100) if health_sources else None
    temperature_summary = {
        "sample_count": len(temperature_observations),
        "duplicate_source_observations_suppressed": duplicate_source_observations_suppressed,
        "sample_counts_by_phase": temperature_global_phase_counts,
        "min_c": min(temperature_observations) if temperature_observations else None,
        "max_c": max(temperature_observations) if temperature_observations else None,
        "mean_c": statistics.fmean(temperature_observations) if temperature_observations else None,
    }
    return {"score": health_score, "temperature_sensors": sorted(temps, key=lambda x: -x["max_c"]),
            "temperature_summary": temperature_summary,
            "telemetry_metrics": sorted(telemetry_peaks.values(), key=lambda x: (x["metric"], x["parent"], x["name"])),
            "safety_abort": {"cpu": bool(dig(data, "bench.cpu.sustained.safety_abort")),
                             "gpu": bool(dig(data, "bench.gpu.safety_abort"))},
            "details": details, "windows_events": events, "sources": health_sources,
            "sensor_sampling": {"sample_count": len(as_list(data.get("sensor_history"))),
                                "first_timestamp": (as_list(data.get("sensor_history")) or [{}])[0].get("timestamp"),
                                "last_timestamp": (as_list(data.get("sensor_history")) or [{}])[-1].get("timestamp"),
                                **{key: value for key, value in (data.get("sensor_sampling") or {}).items()
                                   if key not in {"sample_count", "first_timestamp", "last_timestamp"}}},
            "security": {"defender": defender, "firewall_profiles_disabled": firewall_disabled,
                         "firewall_query_available": "Firewall" in sec, "bitlocker": bitlocker}, "memory_test": memory_test}
def analyze_network(data, F):
    net = data.get("bench", {}).get("network_test")
    if not net:
        return {"measured": False, "result": None}
    if net.get("loss_pct") is not None and net["loss_pct"] >= 5:
        F.add("warn", 'Network', 'High packet loss in ping test', f"%{net['loss_pct']:.1f} lost ({net.get('target')}).",
              'Check the Wi-Fi signal, cable, router, and network path to the target.', 15)
    if net.get("avg_ms") is not None and net["avg_ms"] >= 100:
        F.add("info", 'Network', 'High ping latency', f"Average {net['avg_ms']:.1f} ms ({net.get('target')}).",
              "The target's geographic distance affects latency; test the local gateway separately.", 5)
    return {"measured": True, "result": net}
def assess_data_quality(data, A):
    'Not a score; this describes analysis data coverage and distinguishes unmeasured/optional modules.'
    checks = []
    checks.append(('Operating system', bool((data.get("os") or {}).get("system"))))
    checks.append(("CPU topology", bool(dig(data, "cpu.topology.logical"))))
    checks.append(("RAM capacity", bool(dig(data, "memory.dynamic.total"))))
    checks.append(('GPU adapter discovery', bool(dig(data, "gpu.gpus"))))
    checks.append(("Storage volumes", bool(dig(data, "storage.volumes"))))
    inv = data.get("inventory") or {}
    checks.append(('Full hardware inventory', bool(inv) and any(
        bool(dig(inv, path)) for path in ("cpu.processors", "gpu.adapters", "memory.slots", "storage.devices"))))
    checks.append(('Live sampling', bool(dig(data, "baseline.samples", 0))))
    requested = data.get("meta", {}).get("requested_tests") or {}
    if requested.get("sensor_sampling"):
        history = as_list(data.get("sensor_history"))
        sampling_meta = data.get("sensor_sampling") if isinstance(data.get("sensor_sampling"), dict) else {}
        if "status" in sampling_meta:
            sampling_complete = (sampling_meta.get("status") == "completed"
                                 and sampling_meta.get("window_complete") is True
                                 and bool(history))
        else:
            sampling_complete = bool(history)
        checks.append(('Timestamped sensor sampling', sampling_complete))
        valid_temperatures = []
        for sample in history:
            if not isinstance(sample, dict):
                continue
            for sensor in as_list(sample.get("sensors")):
                if not isinstance(sensor, dict) or str(sensor.get("SensorType") or "").casefold() != "temperature":
                    continue
                sensor_label = str(sensor.get("Name") or sensor.get("name") or "")
                if valid_temperature_value(sensor.get("Value"), sensor_label) is not None:
                    valid_temperatures.append(sensor)
            for gpu in as_list(sample.get("gpus")):
                if not isinstance(gpu, dict):
                    continue
                value = gpu.get("temp")
                if valid_temperature_value(value, "GPU temperature") is not None:
                    valid_temperatures.append(gpu)
        checks.append(('Valid live temperature sensors', bool(valid_temperatures)))
    if requested.get("storage_health_probe"):
        smart_summary = dig(data, "inventory.storage.smartctl", {}) or dig(data, "storage.smartctl", {}) or {}
        smart_devices = as_list(smart_summary.get("devices")) if isinstance(smart_summary, dict) else []
        queried_devices = [device for device in smart_devices
                           if isinstance(device, dict) and device.get("query_status") == "success"]
        checks.append(("SMART query (smartctl)", bool(queried_devices)
                       and smart_summary.get("status") in {"ok", "partial"}))
    if requested.get("cpu_benchmark"):
        checks.append(("CPU benchmark", bool(dig(data, "bench.cpu.py")) and not bool(dig(data, "bench.cpu.error"))))
    if requested.get("memory_bandwidth"):
        checks.append(('RAM bandwidth', bool(dig(data, "bench.memory.best_copy_gbs"))))
    if requested.get("disk_benchmark"):
        checks.append(("Disk benchmark", bool(dig(data, "bench.disk.seq_read_mbs")) and not bool(dig(data, "bench.disk.error"))))
    if requested.get("gpu_benchmark"):
        checks.append(("GPU benchmark", bool(dig(data, "bench.gpu.available"))))
    if requested.get("encoder_benchmark"):
        encoder = data.get("bench", {}).get("encoder") or {}
        checks.append(("Video encoder benchmark", bool(encoder.get("available") and any(x.get("passed") for x in encoder.get("encoders", [])))))
    if requested.get("network_test"):
        checks.append(('Network test', bool(dig(data, "bench.network_test")) and not bool(dig(data, "bench.network_test.error"))))
    if requested.get("memory_integrity"):
        checks.append(('RAM sampling test', bool(dig(data, "bench.memory_integrity.passed")) and not bool(dig(data, "bench.memory_integrity.error"))))
    passed = sum(1 for _, ok in checks if ok)
    missing = [name for name, ok in checks if not ok]
    return {"score": round(100 * passed / len(checks), 1) if checks else None,
            "passed": passed, "total": len(checks), "checks": [{"name": n, "ok": ok} for n, ok in checks],
            "missing": missing, "note": 'This ratio is not an accuracy guarantee; it indicates source and measurement coverage.'}
def build_workload_profiles(data: dict, analysis: dict) -> list[dict]:
    workloads = analysis.get("workloads") or []
    bench = data.get("bench") or {}
    def find_rating(prefixes: tuple[str, ...]) -> dict:
        return next((row for row in workloads if str(row.get("name", "")).startswith(prefixes)), {})
    def measured(label: str, value: Any, unit: str, source: str) -> dict:
        valid = _is_finite_measurement(value)
        return {"name": label, "value": float(value) if valid else None, "unit": unit,
                "source": source, "measured": valid}
    cpu_single = measured('CPU single-core', dig(bench, "cpu.py.single_p.ops"), 'operations/sec', "CPU Python benchmark")
    cpu_multi = measured('CPU multi-core FP64', dig(bench, "cpu.gemm.float64.all_phys.gflops"), "GFLOPS", "CPU GEMM benchmark")
    memory = measured("RAM copy", dig(bench, "memory.best_copy_gbs"), "GB/s", 'RAM bandwidth benchmark')
    disk_read = measured('Disk sequential read', dig(bench, "disk.seq_read_mbs"), "MB/s", "Disk benchmark")
    gpu = measured("GPU FP32", dig(bench, "gpu.gflops"), "GFLOPS", "PyTorch CUDA/DirectML benchmark")
    encoders = [dict(row) for row in as_list(dig(bench, "encoder.encoders", []))
                if isinstance(row, dict) and row.get("passed") is True and _is_finite_measurement(row.get("fps"))]
    definitions = [
        ("Video encoding", ('Video editing', "DaVinci Resolve", "Premiere Pro"),
         [cpu_multi, memory, disk_read],
         'The FFmpeg result measures a real encoder path only when --encoder-bench is run; the synthetic 720p test is not a real editing timeline.'),
        ("3D rendering", ('Multi-core computing', "Blender"),
         [cpu_multi, gpu, memory],
         'CPU/GPU benchmark components are real measurements; no scene render time is measured in Blender or another rendering engine.'),
        ("Gaming", ("Gaming (1080p", "Gaming (1440p", "Gaming (4K"),
         [cpu_single, gpu, memory],
         'This is a hardware suitability profile; game FPS, frametime, and real gameplay are not measured.'),
        ('General productivity', ("Office / web", 'Photo editing', 'Large software compilation'),
         [cpu_single, cpu_multi, memory, disk_read],
         'CPU/RAM/disk microbenchmarks are shown; task-completion time in a specific application is not measured.'),
    ]
    result = []
    for name, prefixes, metrics, limitation in definitions:
        rating = find_rating(prefixes)
        valid_metrics = [metric for metric in metrics if metric["measured"]]
        profile = {
            "name": name,
            "suitability": rating.get("rating", 'Not measured'),
            "limiting_factor": rating.get("limit") or None,
            "heuristic_scope": rating.get("measurement_scope") or 'No suitability input was found',
            "measurement_status": "measured" if len(valid_metrics) == len(metrics) else "partial" if valid_metrics else "not_measured",
            "benchmark_metrics": metrics,
            "limitations": limitation,
        }
        if name == "Video encoding":
            profile["encoder_results"] = [{"encoder": row.get("encoder"), "fps": row.get("fps"),
                                            "realtime_factor": row.get("realtime_factor"),
                                            "frames": row.get("frames")}
                                           for row in encoders]
            profile["encoder_test_status"] = "measured" if encoders else "not_requested_or_unavailable"
        result.append(profile)
    return result
def build_health_alerts(data: dict, analysis: dict) -> dict:
    alerts: list[dict] = []
    seen: set[tuple[str, str]] = set()
    def add(key: str, severity: str, title: str, detail: str, source: str) -> None:
        identity = (key.casefold(), title.casefold())
        if identity in seen:
            return
        seen.add(identity)
        alerts.append({"severity": severity, "key": key, "title": title,
                       "detail": detail, "source": source, "automatic_action": False})
    sensor_rows, _status = collect_report_sensor_observations(data)
    for row in sensor_rows:
        if str(row.get("SensorType") or "").casefold() != "temperature":
            continue
        value = row.get("Value")
        if not _is_finite_measurement(value):
            continue
        component = str(row.get("HardwareType") or row.get("hardware_type") or "").casefold()
        label = f"{row.get('Parent') or 'Hardware'} / {row.get('Name') or 'Temperature'}"
        if component in {"storage", "disk"}:
            warning, critical = 65.0, 75.0
        elif component == "gpu":
            warning, critical = 85.0, 95.0
        elif component == "cpu":
            warning, critical = 90.0, 100.0
        else:
            warning, critical = 90.0, 100.0
        if float(value) >= critical:
            add("temperature:" + label, "critical", 'High temperature', f"{label}: {float(value):.1f} °C (application critical threshold {critical:.0f} °C).",
                str(row.get("source") or 'Sensor provider'))
        elif float(value) >= warning:
            add("temperature:" + label, "warning", 'Temperature warning', f"{label}: {float(value):.1f} °C (application warning threshold {warning:.0f} °C).",
                str(row.get("source") or 'Sensor provider'))
    for disk in as_list(dig(data, "inventory.storage.devices", [])):
        if not isinstance(disk, dict):
            continue
        smart = disk.get("smart") if isinstance(disk.get("smart"), dict) else {}
        name = str(disk.get("name") or disk.get("model") or 'Storage device')
        if smart.get("smart_passed") is False or str(smart.get("health_status") or "").casefold() in {"failed", "failing", "critical"}:
            add("smart-fail:" + name, "critical", 'SMART health failure', f"{name}: SMART source reported a failed health status.", "smartctl SMART")
        for field in ("media_errors", "uncorrected_errors"):
            count = smart.get(field)
            if _is_finite_measurement(count) and float(count) > 0:
                add(f"smart:{name}:{field}", "critical", 'Storage media error', f"{name}: {field}={count}; counter is greater than zero.", "smartctl SMART")
        wear = smart.get("percentage_used", smart.get("wear_pct"))
        if _is_finite_measurement(wear):
            if float(wear) >= 95:
                add("wear:" + name, "critical", 'SSD wear is very high', f"{name}: manufacturer-reported usage/wear counter %{float(wear):.1f}.", "smartctl SMART")
            elif float(wear) >= 80:
                add("wear:" + name, "warning", 'SSD wear is increasing', f"{name}: manufacturer-reported usage/wear counter %{float(wear):.1f}.", "smartctl SMART")
        log_count = smart.get("num_err_log_entries")
        if _is_finite_measurement(log_count) and float(log_count) > 0:
            add("smart-log:" + name, "warning", 'SMART error log contains records', f"{name}: error log contains {int(log_count)} entries; this is not the same as a current media error.", "smartctl SMART")
    commit_pct = dig(analysis, "memory.commit_pct")
    if _is_finite_measurement(commit_pct):
        if float(commit_pct) >= 90:
            add("memory-commit", "critical", 'Memory commit pressure is critical', f"Commit utilization %{float(commit_pct):.1f}; approaching the virtual-memory limit.", 'Windows/psutil memory counters')
        elif float(commit_pct) >= 80:
            add("memory-commit", "warning", 'Memory commit pressure is high', f"Commit utilization %{float(commit_pct):.1f}.", 'Windows/psutil memory counters')
    battery = dig(data, "os.battery_health", {}) or {}
    for item in as_list(battery.get("batteries")):
        if not isinstance(item, dict) or not _is_finite_measurement(item.get("health_pct")):
            continue
        health = float(item["health_pct"])
        name = str(item.get("name") or "Battery")
        if health <= 50:
            add("battery:" + name, "warning", 'Battery capacity has decreased significantly', f"{name}: full-charge capacity is % of design capacity{health:.1f}'i.", str(item.get("capacity_source") or "Battery capacity data"))
    comparison = analysis.get("comparison") or {}
    if comparison.get("previous_mode") == comparison.get("current_mode") and comparison.get("previous_mode"):
        for metric in as_list(comparison.get("metrics")):
            change = metric.get("delta_pct") if isinstance(metric, dict) else None
            if (isinstance(metric, dict) and str(metric.get("label", "")).startswith(("CPU", "RAM", "Disk", "GPU"))
                    and _is_finite_measurement(change) and float(change) <= -20.0):
                add("benchmark-regression:" + str(metric.get("label")), "warning", 'Benchmark performance has declined',
                    f"{metric.get('label')}: compared with the previous report in the same analysis mode, {abs(float(change)):.1f} decrease. This alone is not evidence of failure.",
                    'Comparison with previous JSON report')
    order = {"critical": 0, "warning": 1, "info": 2}
    alerts.sort(key=lambda item: (order.get(item["severity"], 9), item["title"], item["key"]))
    return {"count": len(alerts), "critical_count": sum(x["severity"] == "critical" for x in alerts),
            "warning_count": sum(x["severity"] == "warning" for x in alerts), "items": alerts,
            "note": 'Thresholds are application-level early warnings; they do not replace manufacturer thermal limits or authorized service diagnostics. The absence of warnings does not prove that hardware is healthy.'}
def _stable_change_identity(kind: str, value: Any) -> str:
    token = re.sub(r"\s+", " ", str(value or "").strip()).casefold()
    return hashlib.sha256(f"{kind}:{token}".encode("utf-8", errors="replace")).hexdigest() if token else ""
def build_driver_firmware_snapshot(data: dict) -> dict:
    records: list[dict] = []
    for row in as_list(dig(data, "ps.drivers", [])):
        if not isinstance(row, dict):
            continue
        version = _clean_text(row.get("DriverVersion"))
        if not version:
            continue
        device_id = _clean_text(_first(row, "DeviceID", "DeviceId", "InstanceId"))
        fallback = "|".join(str(row.get(k) or "") for k in ("DeviceClass", "DeviceName", "Manufacturer"))
        identity_value = device_id or fallback
        identity = _stable_change_identity("driver", identity_value)
        if not identity:
            continue
        records.append({"identity": identity, "category": "driver", "name": _clean_text(row.get("DeviceName")) or 'Unknown device',
                        "device_class": _clean_text(row.get("DeviceClass")), "version": version,
                        "date": _clean_text(row.get("DriverDate")), "provider": _clean_text(row.get("Manufacturer")),
                        "inf_name": _clean_text(row.get("InfName")),
                        "identity_confidence": "device_id" if device_id else "name_class_fallback"})

    bios_candidates = [dig(data, "inventory.motherboard.bios", {}), dig(data, "smbios.bios", {})]
    bios_candidates.extend(as_list(dig(data, "ps.hardware_inventory.bios", [])))
    bios = next((candidate for candidate in bios_candidates if isinstance(candidate, dict)
                 and _clean_text(_first(candidate, "version", "SMBIOSBIOSVersion", "Version"))), {})
    if isinstance(bios, dict):
        version = _clean_text(_first(bios, "version", "SMBIOSBIOSVersion", "Version"))
        if version:
            vendor = _clean_text(_first(bios, "vendor", "Manufacturer")) or 'Unknown manufacturer'
            product = _clean_text(dig(data, "inventory.motherboard.product")) or _clean_text(dig(data, "smbios.system.product")) or "Sistem BIOS"
            records.append({"identity": _stable_change_identity("bios", vendor + "|" + product),
                            "category": "firmware", "name": f"BIOS/UEFI — {vendor} {product}",
                            "device_class": "BIOS", "version": version,
                            "date": _clean_text(_first(bios, "release_date", "ReleaseDate", "date")),
                            "provider": vendor, "identity_confidence": "platform_identity"})
    for device in as_list(dig(data, "inventory.storage.devices", [])):
        if not isinstance(device, dict):
            continue
        version = _clean_text(_first(device, "firmware", "firmware_version", "FirmwareVersion"))
        if not version:
            continue
        stable_id = _clean_text(_first(device, "serial_number", "serial", "device_id", "device_path"))
        if not stable_id:
            continue
        name = _clean_text(_first(device, "name", "model")) or 'Storage device'
        records.append({"identity": _stable_change_identity("storage_firmware", stable_id),
                        "category": "firmware", "name": name, "device_class": "storage",
                        "version": version, "date": None, "provider": _clean_text(device.get("source")),
                        "identity_confidence": "physical_device_id"})
    counts: dict[str, int] = {}
    for record in records:
        counts[record["identity"]] = counts.get(record["identity"], 0) + 1
    ambiguous = sum(count > 1 for count in counts.values())
    unique_records = [record for record in records if counts[record["identity"]] == 1]
    unique_records.sort(key=lambda row: (row["category"], row["name"].casefold(), row["identity"]))
    return {"records": unique_records, "ambiguous_records_omitted": ambiguous,
            "note": 'Driver/firmware versions are compared only when the same stable device identifier matches; name-based matches have lower confidence.'}
def compare_driver_firmware_snapshots(current_data: dict, previous_data: dict) -> dict:
    current = build_driver_firmware_snapshot(current_data)
    previous = build_driver_firmware_snapshot(previous_data)
    old_records = {row["identity"]: row for row in previous["records"]}
    new_records = {row["identity"]: row for row in current["records"]}
    changes = []
    for identity in sorted(set(old_records) & set(new_records)):
        before, after = old_records[identity], new_records[identity]
        fields = {field: {"previous": before.get(field), "current": after.get(field)}
                  for field in ("version", "date", "provider") if before.get(field) != after.get(field)}
        if fields:
            changes.append({"status": "changed", "category": after["category"], "name": after["name"], "fields": fields,
                            "identity_confidence": after.get("identity_confidence")})
    for identity in sorted(set(new_records) - set(old_records)):
        item = new_records[identity]
        changes.append({"status": "newly_observed", "category": item["category"], "name": item["name"],
                        "current": item, "identity_confidence": item.get("identity_confidence")})
    return {"current": current, "previous": previous, "changes": changes,
            "note": 'Only matches with a proven version change are marked as changed. Newly observed devices are not considered removed merely because they were absent from the previous scan.'}
def analyze(data, worker_mb=None):
    F = Findings()
    A = {"cpu": analyze_cpu(data, F), "memory": analyze_memory(data, F), "gpu": analyze_gpu(data, F),
         "storage": analyze_storage(data, F), "os": analyze_os(data, F)}
    A["scores"] = compute_scores(data, A, F)
    A["balance"] = analyze_balance(A)
    A["workloads"] = rate_workloads(data, A)
    A["upgrades"] = recommend_upgrades(data, A)
    A["budget"] = resource_budget(data, A, worker_mb)
    A["health"] = analyze_hardware_health(data, F)
    A["network"] = analyze_network(data, F)
    A["quality"] = assess_data_quality(data, A)
    A["scores"]["data_quality"] = A["quality"]["score"]
    A["scores"]["health"] = A["health"]["score"]
    A["workload_profiles"] = build_workload_profiles(data, A)
    A["alerts"] = build_health_alerts(data, A)
    A["battery_health"] = dig(data, "os.battery_health", {"status": "unavailable", "batteries": []})
    A["findings"] = sorted(F.items, key=lambda x: -x["impact"])
    A["verdict"] = build_verdict(A)
    return A
def _health_history_snapshot(data: dict) -> dict:
    temperatures, powers, gpu_loads, cpu_loads, memory_loads = [], [], [], [], []
    per_sensor_temperatures = {}
    def numeric(value):
        return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(float(value)) else None
    def add_temperature(value, *, parent, name, hardware_type="Unknown", source="Unknown", timestamp=None,
                        sensor_identifier=None):
        value = valid_temperature_value(value, name)
        if value is None:
            return
        identifier = str(sensor_identifier or "")
        key = (str(hardware_type).casefold(), str(parent).casefold(), str(name).casefold(), identifier.casefold())
        item = per_sensor_temperatures.setdefault(key, {
            "hardware_type": str(hardware_type), "parent": str(parent), "name": str(name),
            "sensor_identifier": identifier or None,
            "min_c": value, "max_c": value, "_sum_c": 0.0, "sample_count": 0,
            "sources": [], "first_timestamp": timestamp, "last_timestamp": timestamp,
            "_observations": set(),
        })
        observation = (timestamp, round(value, 6), str(source))
        if observation in item["_observations"]:
            return
        item["_observations"].add(observation)
        temperatures.append(value)
        item["sample_count"] += 1
        item["_sum_c"] += value
        item["min_c"] = min(item["min_c"], value)
        item["max_c"] = max(item["max_c"], value)
        item["mean_c"] = item["_sum_c"] / item["sample_count"]
        if source not in item["sources"]:
            item["sources"].append(str(source))
        if timestamp:
            item["first_timestamp"] = min(filter(None, (item.get("first_timestamp"), timestamp)), default=timestamp)
            item["last_timestamp"] = max(filter(None, (item.get("last_timestamp"), timestamp)), default=timestamp)
    def ingest_sensors(rows, sample_timestamp=None):
        for row in as_list(rows):
            if not isinstance(row, dict) or row.get("Value") is None:
                continue
            value = numeric(row.get("Value"))
            if value is None:
                continue
            sensor_type = str(row.get("SensorType") or "").casefold()
            if sensor_type == "temperature":
                add_temperature(
                    value, parent=row.get("Parent") or "Unknown hardware",
                    name=row.get("Name") or "Temperature",
                    hardware_type=row.get("HardwareType") or row.get("hardware_type") or "Unknown",
                    source=row.get("source") or row.get("Source") or "Unknown",
                    timestamp=row.get("timestamp") or sample_timestamp,
                    sensor_identifier=row.get("SensorIdentifier") or row.get("sensor_identifier"),
                )
            elif sensor_type == "power":
                powers.append(value)
    def ingest_gpus(rows, sample_timestamp=None):
        for row in as_list(rows):
            if not isinstance(row, dict):
                continue
            value = numeric(row.get("temp"))
            if value is not None:
                add_temperature(value, parent=row.get("name") or row.get("index") or "GPU",
                                name="GPU temperature", hardware_type="GPU", source="NVIDIA NVML",
                                timestamp=row.get("timestamp") or sample_timestamp,
                                sensor_identifier=f"nvml:{row.get('index', row.get('name') or 'gpu')}:temperature")
            value = numeric(row.get("power_w"))
            if value is not None:
                powers.append(value)
            value = numeric(row.get("util_gpu"))
            if value is not None:
                gpu_loads.append(value)
    ingest_sensors(data.get("sensors"))
    ingest_sensors(data.get("sensors_after_benchmark"))
    gpu_root = data.get("gpu") or {}
    ingest_gpus(gpu_root.get("gpus") or [])
    for sample in as_list(data.get("sensor_history")):
        if not isinstance(sample, dict):
            continue
        ingest_sensors(sample.get("sensors"), sample.get("timestamp"))
        ingest_gpus(sample.get("gpus"), sample.get("timestamp"))
        value = numeric(sample.get("cpu_percent"))
        if value is not None:
            cpu_loads.append(value)
        value = numeric(sample.get("memory_percent"))
        if value is not None:
            memory_loads.append(value)
    for bench_key in ("cpu", "gpu"):
        for sample in as_list(dig(data, f"bench.{bench_key}.thermal_series", [])):
            if isinstance(sample, dict):
                ingest_sensors(sample.get("sensors"), sample.get("timestamp"))
                ingest_gpus(sample.get("gpus"), sample.get("timestamp"))
    for disk in as_list(dig(data, "storage.disks", [])):
        if not isinstance(disk, dict):
            continue
        rel = disk.get("windows_storage_reliability") or disk.get("reliability") or {}
        if isinstance(rel, dict):
            value = numeric(rel.get("Temperature"))
            if value is not None:
                add_temperature(value, parent=disk.get("name") or "Disk",
                                name="Storage reliability temperature", hardware_type="Storage",
                                source="Windows Storage Reliability", timestamp=dig(data, "meta.timestamp"),
                                sensor_identifier=f"windows-storage-reliability:{disk.get('id') or disk.get('name') or 'disk'}")
    for disk in as_list(dig(data, "inventory.storage.devices", [])):
        if not isinstance(disk, dict):
            continue
        smart = disk.get("smart") or {}
        if not isinstance(smart, dict):
            continue
        parent = disk.get("name") or disk.get("model") or "Disk"
        smart_path = smart.get("device_path") or disk.get("device_path") or parent
        value = numeric(smart.get("temperature_c"))
        if value is not None:
            add_temperature(value, parent=parent, name="SMART composite temperature", hardware_type="Storage",
                            source="smartctl", timestamp=dig(data, "meta.timestamp"),
                            sensor_identifier=f"smartctl:{smart_path}:temperature")
        for channel in as_list(smart.get("temperature_channels")):
            if isinstance(channel, dict):
                value = numeric(channel.get("temperature_c"))
                if value is not None:
                    add_temperature(value, parent=parent, name=channel.get("name") or "SMART temperature channel",
                                    hardware_type="Storage", source="smartctl", timestamp=dig(data, "meta.timestamp"),
                                    sensor_identifier=channel.get("sensor_identifier"))
    base_cpu = numeric(dig(data, "baseline.cpu.util_avg"))
    if not cpu_loads and base_cpu is not None:
        cpu_loads.append(base_cpu)
    def summary(values):
        vals = [x for x in values if numeric(x) is not None]
        if not vals:
            return {"sample_count": 0, "min": None, "max": None, "mean": None, "median": None}
        return {"sample_count": len(vals), "min": min(vals), "max": max(vals),
                "mean": statistics.fmean(vals), "median": statistics.median(vals)}
    io_samples = [row.get("disk_io") for row in as_list(data.get("sensor_history"))
                  if isinstance(row, dict) and isinstance(row.get("disk_io"), dict)]
    def io_delta(field):
        values = [numeric(row.get(field)) for row in io_samples]
        values = [value for value in values if value is not None]
        if len(values) < 2 or values[-1] < values[0]:
            return None
        return values[-1] - values[0]
    disk_map = {}
    disk_alias_index = {}
    def disk_aliases(disk, windows_reliability, smart):
        aliases = []
        for value in (disk.get("id"), disk.get("index"), disk.get("device_id"),
                      windows_reliability.get("DeviceId"), windows_reliability.get("device_id")):
            if value is None or str(value).strip() == "":
                continue
            text = str(value).strip().casefold()
            alias = f"index:{int(text)}" if text.isdecimal() else f"id:{text}"
            if alias not in aliases:
                aliases.append(alias)
        for value in (disk.get("serial_number"), disk.get("serial"),
                      smart.get("serial_number")):
            if value is not None and str(value).strip():
                alias = "serial:" + re.sub(r"\s+", "", str(value)).casefold()
                if alias not in aliases:
                    aliases.append(alias)
        for value in (disk.get("device_path"), disk.get("path"), smart.get("device_path")):
            if value is not None and str(value).strip():
                text = str(value).strip().replace("/", "\\").casefold()
                text = text.replace("\\.\\", "").replace("\\?\\", "")
                alias = "path:" + text.rstrip("\\")
                if alias not in aliases:
                    aliases.append(alias)
        for value in (disk.get("pnp_device_id"),):
            if value is not None and str(value).strip():
                alias = "pnp:" + str(value).strip().casefold()
                if alias not in aliases:
                    aliases.append(alias)
        if not aliases:
            name = str(disk.get("name") or disk.get("model") or "").strip()
            if name:
                aliases.append("name:" + name.casefold())
        return aliases
    for source_name, devices in (("storage", dig(data, "storage.disks", [])),
                                 ("inventory", dig(data, "inventory.storage.devices", []))):
        for disk in as_list(devices):
            if not isinstance(disk, dict):
                continue
            windows_reliability = disk.get("windows_storage_reliability") or disk.get("reliability") or {}
            if not isinstance(windows_reliability, dict):
                windows_reliability = {}
            smart = disk.get("smart") if isinstance(disk.get("smart"), dict) else {}
            name = str(disk.get("name") or disk.get("model") or disk.get("device_path") or "Unknown disk")
            aliases = disk_aliases(disk, windows_reliability, smart)
            matched_keys = [disk_alias_index[alias] for alias in aliases if alias in disk_alias_index]
            ident = matched_keys[0] if matched_keys else (aliases[0] if aliases else name.casefold())
            row = disk_map.setdefault(ident, {
                "name": name, "id": disk.get("id") or disk.get("device_id") or disk.get("device_path"),
                "source": source_name, "sources": [],
                "health": None, "temperature_c": None, "wear_pct": None,
                "power_on_hours": None, "uncorrected_errors": None,
                "windows_storage_reliability": None, "smartctl": None,
            })
            for alias in aliases:
                disk_alias_index[alias] = ident
            if source_name not in row["sources"]:
                row["sources"].append(source_name)
            wsr_health = windows_reliability.get("HealthStatus", windows_reliability.get("health"))
            wsr_wear = numeric(windows_reliability.get("Wear", windows_reliability.get("wear_pct")))
            wsr_power_on = numeric(windows_reliability.get("PowerOnHours", windows_reliability.get("power_on_hours")))
            wsr_error_values = [numeric(windows_reliability.get(field))
                                for field in ("ReadErrorsUncorrected", "WriteErrorsUncorrected")]
            wsr_error_values = [value for value in wsr_error_values if value is not None]
            wsr_uncorrected = sum(wsr_error_values) if wsr_error_values else None
            if windows_reliability:
                row.update({
                    "health": wsr_health,
                    "temperature_c": valid_temperature_value(
                        windows_reliability.get("Temperature", windows_reliability.get("temperature_c")),
                        "Storage reliability temperature"),
                    "wear_pct": wsr_wear,
                    "power_on_hours": wsr_power_on,
                    "uncorrected_errors": wsr_uncorrected,
                })
                row["windows_storage_reliability"] = {
                    "source": "Windows Storage Reliability",
                    "health": wsr_health,
                    "temperature_c": valid_temperature_value(
                        windows_reliability.get("Temperature", windows_reliability.get("temperature_c")),
                        "Storage reliability temperature"),
                    "wear_pct": wsr_wear,
                    "power_on_hours": wsr_power_on,
                    "uncorrected_errors": wsr_uncorrected,
                }
            if smart:
                row["smartctl"] = {
                    "source": "smartctl", "query_status": smart.get("query_status"),
                    "smart_passed": smart.get("smart_passed"),
                    "health_status": smart.get("health_status"),
                    "temperature_c": valid_temperature_value(smart.get("temperature_c"), "SMART composite temperature"),
                    "wear_pct": numeric(smart.get("percentage_used")),
                    "power_on_hours": numeric(smart.get("power_on_hours")),
                    "media_errors": numeric(smart.get("media_errors")),
                    "num_err_log_entries": numeric(smart.get("num_err_log_entries")),
                }
    disk_rows = list(disk_map.values())
    temperature_sensor_rows = []
    for item in per_sensor_temperatures.values():
        item.pop("_observations", None)
        item["mean_c"] = item.pop("mean_c", item["_sum_c"] / item["sample_count"] if item["sample_count"] else None)
        item.pop("_sum_c", None)
        temperature_sensor_rows.append(item)
    temperature_sensor_rows.sort(key=lambda row: (row["hardware_type"].casefold(), row["parent"].casefold(),
                                                  row["name"].casefold(), str(row.get("sensor_identifier") or "").casefold()))
    battery_health = []
    for battery in as_list(dig(data, "os.battery_health.batteries", [])):
        if not isinstance(battery, dict):
            continue
        battery_health.append({
            "name": str(battery.get("name") or "Battery"),
            "manufacturer": str(battery.get("manufacturer") or ""),
            "identity_hash": str(battery.get("identity_hash") or ""),
            "health_pct": numeric(battery.get("health_pct")),
            "wear_pct": numeric(battery.get("wear_pct")),
            "cycle_count": numeric(battery.get("cycle_count")),
            "designed_capacity_mwh": numeric(battery.get("designed_capacity_mwh")),
            "full_charge_capacity_mwh": numeric(battery.get("full_charge_capacity_mwh")),
        })
    benchmark_values = {
        "cpu_single_core_ops": numeric(dig(data, "bench.cpu.py.single_p.ops")),
        "cpu_multi_core_gflops": numeric(dig(data, "bench.cpu.gemm.float64.all_phys.gflops")),
        "memory_copy_gbs": numeric(dig(data, "bench.memory.best_copy_gbs")),
        "disk_read_mbs": numeric(dig(data, "bench.disk.seq_read_mbs")),
        "disk_write_mbs": numeric(dig(data, "bench.disk.seq_write_mbs")),
        "gpu_gflops": numeric(dig(data, "bench.gpu.gflops")),
    }
    return {
        "timestamp": dig(data, "meta.timestamp"),
        "temperature_c": summary(temperatures), "temperature_sensors": temperature_sensor_rows,
        "power_w": summary(powers),
        "usage_pct": {"cpu": summary(cpu_loads), "memory": summary(memory_loads), "gpu": summary(gpu_loads)},
        "disk_health": disk_rows, "battery_health": battery_health,
        "disk_io_delta_bytes": {"read": io_delta("read_bytes"), "write": io_delta("write_bytes"),
                                "sample_count": len(io_samples)},
        "benchmark_values": benchmark_values,
        "sensor_sample_count": len(as_list(data.get("sensor_history"))),
        "benchmark_reliability": dig(data, "bench.reliability"),
    }
def _compare_health_history(current_data: dict, previous_data: dict) -> dict:
    old, new = _health_history_snapshot(previous_data), _health_history_snapshot(current_data)
    metric_paths = [
        ('Minimum temperature', "temperature_c.min", "°C"),
        ('Average temperature', "temperature_c.mean", "°C"),
        ('Peak temperature', "temperature_c.max", "°C"),
        ('Peak power', "power_w.max", "W"),
        ('Average CPU utilization', "usage_pct.cpu.mean", "%"),
        ('Average RAM utilization', "usage_pct.memory.mean", "%"),
        ('Peak GPU utilization', "usage_pct.gpu.max", "%"),
    ]
    deltas = []
    for label, path, unit in metric_paths:
        previous, current = dig(old, path), dig(new, path)
        delta = current - previous if _is_finite_measurement(previous) and _is_finite_measurement(current) else None
        deltas.append({"label": label, "unit": unit, "previous": previous, "current": current, "delta": delta})
    def disk_map(snapshot):
        out = {}
        for disk in snapshot.get("disk_health", []):
            key = str(disk.get("id") or disk.get("name") or "").casefold()
            if key:
                out[key] = disk
        return out
    old_disks, new_disks = disk_map(old), disk_map(new)
    disk_changes = []
    for key in sorted(set(old_disks) | set(new_disks)):
        before, after = old_disks.get(key), new_disks.get(key)
        if before is None or after is None:
            disk_changes.append({"name": (after or before).get("name"), "status": "added" if before is None else "removed",
                                 "previous": before, "current": after})
        else:
            fields = ("health", "temperature_c", "wear_pct", "power_on_hours", "uncorrected_errors")
            changed = {field: {"previous": before.get(field), "current": after.get(field)}
                       for field in fields if before.get(field) != after.get(field)}
            source_fields = {
                "windows_storage_reliability": ("health", "temperature_c", "wear_pct", "power_on_hours", "uncorrected_errors"),
                "smartctl": ("query_status", "smart_passed", "health_status", "temperature_c", "wear_pct",
                             "power_on_hours", "media_errors", "num_err_log_entries"),
            }
            for source_key, nested_fields in source_fields.items():
                before_source = before.get(source_key) if isinstance(before.get(source_key), dict) else {}
                after_source = after.get(source_key) if isinstance(after.get(source_key), dict) else {}
                for field in nested_fields:
                    previous_value, current_value = before_source.get(field), after_source.get(field)
                    if previous_value != current_value:
                        changed[f"{source_key}.{field}"] = {
                            "previous": previous_value, "current": current_value,
                            "delta": (current_value - previous_value
                                      if _is_finite_measurement(previous_value) and _is_finite_measurement(current_value)
                                      else None),
                        }
            if changed:
                disk_changes.append({"name": after.get("name"), "status": "changed", "fields": changed})
    def temperature_sensor_map(snapshot):
        result = {}
        for sensor in snapshot.get("temperature_sensors") or []:
            key = (str(sensor.get("hardware_type", "")).casefold(),
                   str(sensor.get("parent", "")).casefold(),
                   str(sensor.get("name", "")).casefold(),
                   str(sensor.get("sensor_identifier") or "").casefold())
            result[key] = sensor
        return result
    def battery_map(snapshot):
        grouped = {}
        for battery in snapshot.get("battery_health") or []:
            identity_hash = str(battery.get("identity_hash") or "")
            manufacturer = str(battery.get("manufacturer") or "").casefold()
            name = str(battery.get("name") or "").casefold()
            key = ("identity", identity_hash) if identity_hash else ("label", manufacturer + "|" + name)
            if key[1] and (identity_hash or (manufacturer and name)):
                grouped.setdefault(key, []).append(battery)
        return {key: rows[0] for key, rows in grouped.items() if len(rows) == 1}
    previous_batteries = battery_map(old)
    current_batteries = battery_map(new)
    battery_changes = []
    for key in sorted(set(previous_batteries) & set(current_batteries)):
        before, after = previous_batteries[key], current_batteries[key]
        changed = {field: {"previous": before.get(field), "current": after.get(field),
                           "delta": (after.get(field) - before.get(field)
                                     if _is_finite_measurement(before.get(field)) and _is_finite_measurement(after.get(field))
                                     else None)}
                   for field in ("health_pct", "wear_pct", "cycle_count", "full_charge_capacity_mwh")
                   if before.get(field) != after.get(field)}
        if changed:
            battery_changes.append({"name": after.get("name"), "manufacturer": after.get("manufacturer"),
                                    "status": "changed", "fields": changed})
    previous_temperatures = temperature_sensor_map(old)
    current_temperatures = temperature_sensor_map(new)
    temperature_sensor_changes = []
    for key in sorted(set(previous_temperatures) | set(current_temperatures)):
        before, after = previous_temperatures.get(key), current_temperatures.get(key)
        if before is None or after is None:
            temperature_sensor_changes.append({
                "status": "added" if before is None else "removed",
                "sensor": after or before, "previous": before, "current": after,
            })
            continue
        fields = ("min_c", "mean_c", "max_c")
        changed = {
            field: {"previous": before.get(field), "current": after.get(field),
                    "delta": (after.get(field) - before.get(field)
                              if _is_finite_measurement(before.get(field)) and _is_finite_measurement(after.get(field))
                              else None)}
            for field in fields
        }
        temperature_sensor_changes.append({"status": "compared", "sensor": after, "fields": changed})
    return {"previous": old, "current": new, "metric_deltas": deltas,
            "temperature_sensor_changes": temperature_sensor_changes,
            "disk_changes": disk_changes, "battery_changes": battery_changes,
            "note": 'Sensor and SMART fields are compared only when reported by the source. Sampling interval, workload, and ambient temperature affect results.'}
def build_health_history_series(current_data: dict, directory: str | os.PathLike, limit: int = 20,
                                exclude_paths=()) -> dict:
    if not 1 <= int(limit) <= 500:
        raise ValueError('health history limit must be between 1 and 500')
    root = os.path.abspath(os.path.expanduser(os.fspath(directory)))
    if not os.path.isdir(root):
        return {"status": "directory_missing", "directory": root, "report_count": 0, "reports": [],
                "note": 'Health-history folder was not found; previous JSON reports could not be read.'}
    excluded = set()
    for item in exclude_paths:
        try:
            excluded.add(os.path.normcase(os.path.abspath(os.path.expanduser(os.fspath(item)))))
        except (OSError, TypeError, ValueError):
            continue
    candidates = []
    skipped = []
    try:
        filenames = os.listdir(root)
    except OSError as exc:
        return {"status": "directory_unreadable", "directory": root, "report_count": 0, "reports": [],
                "note": f"Could not read the health-history folder: {type(exc).__name__}: {exc}"}
    for filename in filenames:
        if not filename.lower().endswith(".json") or filename.endswith("_raw.json"):
            continue
        full_path = os.path.join(root, filename)
        if os.path.normcase(os.path.abspath(full_path)) in excluded:
            continue
        try:
            if not os.path.isfile(full_path):
                continue
            with open(full_path, "r", encoding="utf-8-sig") as stream:
                payload = json.load(stream)
            previous_data = payload.get("data", payload) if isinstance(payload, dict) else None
            if not isinstance(previous_data, dict) or not isinstance(previous_data.get("meta"), dict):
                continue
            if not any(key in previous_data for key in ("cpu", "storage", "inventory", "sensor_history", "bench")):
                continue
            snapshot = _health_history_snapshot(previous_data)
            stamp = str(snapshot.get("timestamp") or previous_data.get("meta", {}).get("timestamp") or "")
            try:
                modified = os.path.getmtime(full_path)
            except OSError:
                modified = 0.0
            candidates.append((modified, stamp, filename, snapshot, previous_data))
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            skipped.append({"file": filename, "reason": f"{type(exc).__name__}: {exc}"})
    candidates.sort(key=lambda row: (row[0], row[1], row[2]))
    candidates = candidates[-int(limit):]
    reports = []
    current_snapshot = _health_history_snapshot(current_data)
    for _modified, stamp, filename, snapshot, previous_data in candidates:
        comparison = _compare_health_history(current_data, previous_data)
        deltas = {row["label"]: row.get("delta") for row in comparison.get("metric_deltas", [])}
        current_bench = current_snapshot.get("benchmark_values") or {}
        previous_bench = snapshot.get("benchmark_values") or {}
        benchmark_deltas = {
            key: (current_bench.get(key) - previous_bench.get(key)
                  if isinstance(current_bench.get(key), (int, float)) and isinstance(previous_bench.get(key), (int, float))
                  else None)
            for key in sorted(set(current_bench) | set(previous_bench))
        }
        reports.append({"timestamp": stamp or None, "file": filename, "is_current": False,
                        "temperature_min_c": dig(snapshot, "temperature_c.min"),
                        "temperature_mean_c": dig(snapshot, "temperature_c.mean"),
                        "temperature_peak_c": dig(snapshot, "temperature_c.max"),
                        "temperature_sensors": snapshot.get("temperature_sensors") or [],
                        "gpu_power_peak_w": dig(snapshot, "power_w.max"),
                        "cpu_usage_mean_pct": dig(snapshot, "usage_pct.cpu.mean"),
                        "memory_usage_mean_pct": dig(snapshot, "usage_pct.memory.mean"),
                        "gpu_usage_peak_pct": dig(snapshot, "usage_pct.gpu.max"),
                        "disk_count": len(snapshot.get("disk_health") or []),
                        "disk_read_mib": (snapshot.get("disk_io_delta_bytes", {}).get("read") / MIB
                                          if snapshot.get("disk_io_delta_bytes", {}).get("read") is not None else None),
                        "disk_write_mib": (snapshot.get("disk_io_delta_bytes", {}).get("write") / MIB
                                           if snapshot.get("disk_io_delta_bytes", {}).get("write") is not None else None),
                        "disk_health": snapshot.get("disk_health") or [],
                        "battery_health": snapshot.get("battery_health") or [],
                        "benchmark_values": snapshot.get("benchmark_values") or {},
                        "sensor_sample_count": snapshot.get("sensor_sample_count", 0),
                        "delta_to_current": deltas, "benchmark_deltas_to_current": benchmark_deltas,
                        "disk_health_changes_to_current": comparison.get("disk_changes") or []})
    reports.append({"timestamp": current_snapshot.get("timestamp") or dig(current_data, "meta.timestamp"),
                    "file": '(current measurement)', "is_current": True,
                    "temperature_min_c": dig(current_snapshot, "temperature_c.min"),
                    "temperature_mean_c": dig(current_snapshot, "temperature_c.mean"),
                    "temperature_peak_c": dig(current_snapshot, "temperature_c.max"),
                    "temperature_sensors": current_snapshot.get("temperature_sensors") or [],
                    "gpu_power_peak_w": dig(current_snapshot, "power_w.max"),
                    "cpu_usage_mean_pct": dig(current_snapshot, "usage_pct.cpu.mean"),
                    "memory_usage_mean_pct": dig(current_snapshot, "usage_pct.memory.mean"),
                    "gpu_usage_peak_pct": dig(current_snapshot, "usage_pct.gpu.max"),
                    "disk_count": len(current_snapshot.get("disk_health") or []),
                    "disk_read_mib": (current_snapshot.get("disk_io_delta_bytes", {}).get("read") / MIB
                                      if current_snapshot.get("disk_io_delta_bytes", {}).get("read") is not None else None),
                    "disk_write_mib": (current_snapshot.get("disk_io_delta_bytes", {}).get("write") / MIB
                                       if current_snapshot.get("disk_io_delta_bytes", {}).get("write") is not None else None),
                    "disk_health": current_snapshot.get("disk_health") or [],
                    "battery_health": current_snapshot.get("battery_health") or [],
                    "benchmark_values": current_snapshot.get("benchmark_values") or {},
                    "sensor_sample_count": current_snapshot.get("sensor_sample_count", 0),
                    "delta_to_current": {}})
    return {"status": "ok" if candidates else "no_previous_reports", "directory": root,
            "report_count": len(candidates), "limit": int(limit), "reports": reports,
            "skipped_files": skipped[:20],
            "note": 'The time series contains only data present in the reports and supplied by the sources. Missing sensor/SMART fields are not treated as zero; results may not be directly comparable when benchmark modes differ.'}
def normalize_report_payload(payload: Any, *, context: str = "Report: ") -> tuple[dict, dict | None]:
    if not isinstance(payload, dict):
        raise ValueError(f"{context} JSON root value must be an object")
    data = payload.get("data", payload)
    if not isinstance(data, dict) or not data:
        raise ValueError(f"{context}No valid 'data' object was found in the JSON")
    meta = data.get("meta")
    if meta is None:
        meta = {}
        data["meta"] = meta
    elif not isinstance(meta, dict):
        raise ValueError(f"{context}The 'meta' field in the JSON must be an object")
    if meta.get("schema_version") is None:
        meta["schema_version"] = 1
    requested_tests = meta.get("requested_tests")
    if requested_tests is None:
        meta["requested_tests"] = {}
    elif not isinstance(requested_tests, dict):
        raise ValueError(f"{context}The 'meta.requested_tests' field in the JSON must be an object")
    analysis = payload.get("analysis") if "data" in payload else None
    return data, analysis if isinstance(analysis, dict) else None
def build_comparison(current_data: dict, current_analysis: dict, previous_payload: dict) -> dict:
    previous_data, previous_analysis = normalize_report_payload(previous_payload, context='Comparison')
    if not isinstance(previous_analysis, dict) or not previous_analysis.get("scores"):
        previous_analysis = analyze(previous_data)
    labels = [
        ('Performance score', "analysis.scores.power", "points", True),
        ('Availability score', "analysis.scores.availability", "points", True),
        ("Efficiency score", "analysis.scores.efficiency", "points", True),
        ('Health score', "analysis.scores.health", "points", True),
        ('Data coverage', "analysis.scores.data_quality", "points", True),
        ("Effective score", "analysis.scores.effective", "points", True),
        ('CPU single-core Python', "data.bench.cpu.py.single_p.ops", 'operations/sec', True),
        ('CPU multi-core FP64', "data.bench.cpu.gemm.float64.all_phys.gflops", "GFLOPS", True),
        ("RAM copy", "data.bench.memory.best_copy_gbs", "GB/s", True),
        ('Disk sequential read', "data.bench.disk.seq_read_mbs", "MB/s", True),
        ('Disk sequential write', "data.bench.disk.seq_write_mbs", "MB/s", True),
        ("GPU FP32 benchmark", "data.bench.gpu.gflops", "GFLOPS", True),
        ('Average network RTT', "data.bench.network_test.avg_ms", "ms", False),
    ]
    metric_rows = []
    for label, path, unit, higher_is_better in labels:
        old_path = path.replace("analysis.", "analysis.", 1)
        old = dig({"data": previous_data, "analysis": previous_analysis}, old_path)
        new = dig({"data": current_data, "analysis": current_analysis}, old_path)
        if not _is_finite_measurement(old) or not _is_finite_measurement(new):
            metric_rows.append({"label": label, "unit": unit, "previous": old if _is_finite_measurement(old) else None,
                                "current": new if _is_finite_measurement(new) else None, "delta": None,
                                "delta_pct": None, "higher_is_better": higher_is_better})
            continue
        delta = float(new) - float(old)
        metric_rows.append({"label": label, "unit": unit, "previous": old, "current": new, "delta": delta,
                            "delta_pct": (delta / abs(old) * 100) if old else None,
                            "higher_is_better": higher_is_better})
    def signature(data):
        mem = data.get("memory") or {}
        gpu_names = sorted(str(g.get("name")) for g in ((data.get("gpu") or {}).get("gpus") or []) if g.get("name"))
        disks = sorted(f"{d.get('name') or '?'} ({d.get('kind') or '?'}, {fmt_bytes(d.get('size'), 0)})"
                       for d in ((data.get("storage") or {}).get("disks") or []))
        os_info = data.get("os") or {}
        return {
            "CPU": dig(data, "cpu.name"),
            "RAM GiB": round((dig(data, "memory.dynamic.total") or mem.get("total_installed") or 0) / GIB, 2) or None,
            "RAM type": mem.get("type"),
            "GPU": gpu_names,
            "Disk": disks,
            "Windows": f"{os_info.get('product') or os_info.get('system') or '?'} {os_info.get('build_full') or ''}".strip(),
        }
    old_sig, new_sig = signature(previous_data), signature(current_data)
    changes = [{"item": key, "previous": old_sig[key], "current": new_sig[key]}
               for key in old_sig if old_sig[key] != new_sig[key]]
    return {"previous_timestamp": dig(previous_data, "meta.timestamp"),
            "current_timestamp": dig(current_data, "meta.timestamp"),
            "previous_mode": dig(previous_data, "meta.mode"), "current_mode": dig(current_data, "meta.mode"),
            "metrics": metric_rows, "hardware_changes": changes,
            "driver_firmware_changes": compare_driver_firmware_snapshots(current_data, previous_data),
            "health_history": _compare_health_history(current_data, previous_data),
            "note": 'Benchmark differences can be affected by mode, power plan, temperature, background load, and driver changes; a change alone is not evidence of hardware failure or causation.'}
import textwrap
WIDTH = 92
class Out:
    def __init__(self):
        self.lines = []
    def add(self, s=""):
        self.lines.append(s)
    def h1(self, title):
        self.add("")
        line = ("=" if UI.ascii else "═") * WIDTH
        self.add(paint(line, "head"))
        self.add(paint(f"  {title}", "head"))
        self.add(paint(line, "head"))
    def h2(self, title):
        self.add("")
        self.add(paint(f"▌ {title}" if not UI.ascii else f"> {title}", "bold"))
    def kv(self, k, v, ind=2, kw=34):
        if v is None or v == "":
            return
        self.add(f"{' ' * ind}{k:<{kw}}: {v}")
    def item(self, level, text, ind=2):
        display_level = normalize_display_level(level)
        self.add(f"{' ' * ind}{paint(icon(display_level), display_level)} {text}")
    def para(self, text, ind=4, style=None):
        for ln in textwrap.wrap(text, WIDTH - ind) or [""]:
            self.add(" " * ind + (paint(ln, style) if style else ln))
    def table(self, headers, rows, ind=2, align=None):
        rows = [[("—" if c is None else str(c)) for c in r] for r in rows]
        widths = [max(vlen(h), *(vlen(r[i]) for r in rows)) if rows else vlen(h) for i, h in enumerate(headers)]
        align = align or ["<"] * len(headers)
        def fmt(cells, bold=False):
            out = []
            for c, w, a in zip(cells, widths, align):
                pad = w - vlen(c)
                out.append(c + " " * pad if a == "<" else " " * pad + c)
            s = "  ".join(out)
            return " " * ind + (paint(s, "bold") if bold else s)
        self.add(fmt(headers, True))
        self.add(" " * ind + paint(("-" if UI.ascii else "─") * (sum(widths) + 2 * (len(widths) - 1)), "dim"))
        for r in rows:
            self.add(fmt(r))
    def text(self):
        return "\n".join(self.lines)
def f1(x, d=1, suf=""):
    return "—" if x is None else f"{x:.{d}f}{suf}"
def sc(v):
    return "     —   " if v is None else f"{v:>4.0f}/100"
def lvl_for_ratio(r, good=0.9, mid=0.7):
    return "info" if r is None else ("ok" if r >= good else "warn" if r >= mid else "bad")
def _ts(epoch):
    try:
        return dt.datetime.fromtimestamp(int(epoch)).strftime("%d.%m.%Y %H:%M")
    except (TypeError, ValueError, OSError):
        return None
def _score_line(o, name, score, extra=""):
    o.add(f"  {name:<36} {bar(score, 24)} {sc(score)}  {paint(grade(score), level_for(score))}  {extra}")
def collect_report_sensor_observations(data: dict) -> tuple[list[dict], dict]:
    observations: list[dict] = []
    status_candidates: list[dict] = []
    for key in ("sensors", "sensors_after_benchmark"):
        observations.extend(as_list(data.get(key)))
    for key in ("sensor_provider", "sensor_provider_after_benchmark"):
        value = data.get(key)
        if isinstance(value, dict):
            status_candidates.append(value)
    for sample in as_list(data.get("sensor_history")):
        if not isinstance(sample, dict):
            continue
        observations.extend(as_list(sample.get("sensors")))
        if isinstance(sample.get("sensor_provider"), dict):
            status_candidates.append(sample["sensor_provider"])
    for phase_key in ("cpu", "gpu"):
        for sample in as_list(dig(data, f"bench.{phase_key}.thermal_series", [])):
            if isinstance(sample, dict):
                observations.extend(as_list(sample.get("sensors")))
    unique: list[dict] = []
    seen: set[tuple] = set()
    for row in observations:
        if not isinstance(row, dict):
            continue
        sensor_type = str(row.get("SensorType", "")).casefold()
        if sensor_type not in ("temperature", "power"):
            continue
        try:
            value = float(row.get("Value"))
        except (TypeError, ValueError, OverflowError):
            continue
        if not math.isfinite(value):
            continue
        if sensor_type == "temperature" and (value <= 0.0 or value > 200.0):
            continue
        key = (sensor_type, str(row.get("Parent", "")).casefold(),
               str(row.get("Name", "")).casefold(), str(row.get("timestamp", "")),
               round(value, 6), str(row.get("source", "")))
        if key in seen:
            continue
        seen.add(key)
        unique.append(row)
    provider_status = max(
        status_candidates,
        key=lambda item: (1 if item.get("status") in ("available", "partial") else 0,
                          int(item.get("temperature_count") or 0)),
        default={},
    )
    return unique, dict(provider_status) if provider_status else {}
def collect_sensor_telemetry_rows(data: dict) -> list[dict]:
    fields = ("timestamp", "elapsed_s", "metric", "hardware_type", "component", "sensor_type",
              "value", "unit", "source", "sensor_identifier")
    rows: list[dict] = []
    seen: set[tuple] = set()
    default_timestamp = dig(data, "meta.timestamp")
    units = {"temperature": "°C", "power": "W", "fan": "RPM", "clock": "MHz",
             "load": "%", "voltage": "V", "data": "", "small_data": ""}
    def add(timestamp: Any, elapsed: Any, metric: str, hardware_type: Any, component: Any,
            sensor_type: str, value: Any, unit: str, source: Any, identifier: Any = None) -> None:
        if not _is_finite_measurement(value):
            return
        row = {"timestamp": timestamp or default_timestamp, "elapsed_s": elapsed,
               "metric": metric, "hardware_type": hardware_type or "Unknown",
               "component": component or "", "sensor_type": sensor_type,
               "value": float(value), "unit": unit, "source": source or "Unknown",
               "sensor_identifier": identifier or ""}
        key = tuple(str(row[field]) for field in fields)
        if key not in seen:
            seen.add(key)
            rows.append(row)
    def ingest_sensors(items: Any, timestamp: Any = None, elapsed: Any = None) -> None:
        for sensor in as_list(items):
            if not isinstance(sensor, dict):
                continue
            kind = str(sensor.get("SensorType") or sensor.get("sensor_type") or "unknown").casefold()
            name = str(sensor.get("Name") or sensor.get("name") or kind)
            parent = sensor.get("Parent") or sensor.get("parent") or ""
            add(sensor.get("timestamp") or timestamp, elapsed, name,
                sensor.get("HardwareType") or sensor.get("hardware_type"), parent,
                kind, sensor.get("Value", sensor.get("value")), units.get(kind, ""),
                sensor.get("source") or sensor.get("Source"),
                sensor.get("SensorIdentifier") or sensor.get("sensor_identifier"))
    def ingest_sample(sample: Any, phase: str = 'sensor sampling') -> None:
        if not isinstance(sample, dict):
            return
        timestamp, elapsed = sample.get("timestamp"), sample.get("elapsed_s")
        ingest_sensors(sample.get("sensors"), timestamp, elapsed)
        for gpu in as_list(sample.get("gpus")):
            if not isinstance(gpu, dict):
                continue
            parent = gpu.get("name") or gpu.get("index") or "GPU"
            for key, label, unit in (("temp", 'GPU temperature', "°C"),
                                     ("power_w", 'GPU power', "W"),
                                     ("util_gpu", 'GPU utilization', "%")):
                add(timestamp, elapsed, label, "GPU", parent, key, gpu.get(key), unit,
                    gpu.get("source") or "NVML", f"gpu:{gpu.get('index', parent)}:{key}")
        add(timestamp, elapsed, 'CPU utilization', "CPU", "", "utilization",
            sample.get("cpu_percent"), "%", "psutil")
        add(timestamp, elapsed, 'Memory utilization', "Memory", "", "utilization",
            sample.get("memory_percent"), "%", "psutil")
        disk_io = sample.get("disk_io") if isinstance(sample.get("disk_io"), dict) else {}
        for key, label in (("read_bytes", 'Total disk reads'), ("write_bytes", 'Total disk writes')):
            add(timestamp, elapsed, label, "Storage", "PhysicalDisk total", "cumulative_bytes",
                disk_io.get(key), "byte", "psutil.disk_io_counters")
        battery = sample.get("battery") if isinstance(sample.get("battery"), dict) else {}
        add(timestamp, elapsed, "Batarya seviyesi", "Battery", "System battery", "level",
            battery.get("percent"), "%", "psutil.sensors_battery")
    ingest_sensors(data.get("sensors"))
    ingest_sensors(data.get("sensors_after_benchmark"))
    for battery in as_list(dig(data, "os.battery_health.batteries", [])):
        if not isinstance(battery, dict):
            continue
        battery_name = battery.get("name") or "System battery"
        add(default_timestamp, None, 'Battery capacity health', "Battery", battery_name,
            "capacity_health", battery.get("health_pct"), "%", battery.get("capacity_source") or "Windows root/wmi")
        add(default_timestamp, None, 'Battery capacity wear', "Battery", battery_name,
            "capacity_wear", battery.get("wear_pct"), "%", battery.get("capacity_source") or "Windows root/wmi")
        add(default_timestamp, None, 'Battery charge cycles', "Battery", battery_name,
            "charge_cycles", battery.get("cycle_count"), "cycle", battery.get("cycle_source") or "Windows root/wmi")
    for sample in as_list(data.get("sensor_history")):
        ingest_sample(sample)
    for phase in ("cpu", "gpu"):
        for sample in as_list(dig(data, f"bench.{phase}.thermal_series", [])):
            ingest_sample(sample, f"{phase} benchmark")
    rows.sort(key=lambda row: (str(row.get("timestamp") or ""), str(row.get("component") or ""),
                               str(row.get("metric") or ""), str(row.get("source") or "")))
    return rows
def _atomic_write(path: str | os.PathLike, writer, *, encoding: str = "utf-8", newline: str | None = None) -> str:
    destination = Path(path).expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding=encoding, newline=newline, dir=destination.parent,
                                         prefix=f".{destination.name}.", suffix=".tmp", delete=False) as stream:
            temporary = stream.name
            writer(stream)
        os.replace(temporary, destination)
        temporary = None
    finally:
        if temporary and os.path.exists(temporary):
            try:
                os.remove(temporary)
            except OSError:
                pass
    return str(destination)
def export_sensor_history_csv(data: dict, output_path: str | os.PathLike) -> dict:
    rows = collect_sensor_telemetry_rows(data)
    headers = ("timestamp", "elapsed_s", "metric", "hardware_type", "component", "sensor_type",
               "value", "unit", "source", "sensor_identifier")
    def spreadsheet_safe_text(value: Any) -> Any:
        if not isinstance(value, str):
            return value
        probe = value.lstrip("\ufeff \t\r\n")
        if value.startswith(("\t", "\r", "\n")) or probe.startswith(("=", "+", "-", "@")):
            return "'" + value
        return value
    def write(stream) -> None:
        writer = csv.DictWriter(stream, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()
        text_fields = set(headers) - {"elapsed_s", "value"}
        safe_rows = ({key: spreadsheet_safe_text(value) if key in text_fields else value
                      for key, value in row.items()} for row in rows)
        writer.writerows(safe_rows)
    path = _atomic_write(output_path, write, encoding="utf-8-sig", newline="")
    return {"path": path, "row_count": len(rows), "format": "CSV UTF-8-SIG",
            "note": 'Disk I/O fields are cumulative counters at the sample time, not speeds. Unmeasured channels are not fabricated as rows.'}
def export_html_report(data: dict, analysis: dict, report_text: str, output_path: str | os.PathLike) -> dict:
    meta = data.get("meta") or {}
    alerts = (analysis.get("alerts") or {}).get("items") or []
    alert_markup = "".join(
        '<li class="' + html_lib.escape(str(item.get("severity") or "info"), quote=True) + '"><strong>' +
        html_lib.escape(str(item.get("title") or 'Warning')) + '</strong> — ' +
        html_lib.escape(str(item.get("detail") or "")) +
        '<small>Source: ' + html_lib.escape(str(item.get("source") or "Unknown")) + '</small></li>'
        for item in alerts if isinstance(item, dict))
    if not alert_markup:
        alert_markup = '<li>No threshold-based warning was generated from this report data.</li>'
    title = f"System Analysis Report — {meta.get('timestamp') or 'date unavailable'}"
    document = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>""" + html_lib.escape(title) + """</title>
<style>
:root{color-scheme:light dark;font-family:Segoe UI,Arial,sans-serif}body{margin:2rem auto;padding:0 1rem;max-width:1100px;line-height:1.5}
h1,h2{line-height:1.2}pre{white-space:pre-wrap;overflow-wrap:anywhere;padding:1rem;border:1px solid #8886;border-radius:.6rem;background:#8881;font: .9rem/1.45 ui-monospace,Consolas,monospace}
li{margin:.7rem 0;padding:.55rem;border-left:4px solid #888}li.critical{border-color:#c33}li.warning{border-color:#c90}small{display:block;opacity:.75}
</style></head><body><h1>""" + html_lib.escape(title) + '</h1>\n<p>Application version: ' + html_lib.escape(str(meta.get("version") or __version__)) + """ · Analysis mode: """ + html_lib.escape(str(meta.get("mode") or "—")) + '</p>\n<h2>Smart health alerts</h2><ul>' + alert_markup + """</ul>
<h2>Text report</h2><pre>""" + html_lib.escape(strip_ansi(report_text)) + """</pre>
</body></html>"""
    path = _atomic_write(output_path, lambda stream: stream.write(document), encoding="utf-8")
    return {"path": path, "format": "HTML", "alert_count": len(alerts),
            "note": 'A single-file offline HTML output; it does not load external resources, scripts, or analysis services.'}
def render_report(data, A) -> str:
    o = Out()
    S, meta = A["scores"], data["meta"]
    o.add(paint(' SYSTEM ANALYSIS REPORT '.center(WIDTH, "="), "title"))
    o.add(f"  Version {meta['version']}  |  {meta['timestamp']}  |  mode: {meta['mode']}  |  duration: {meta['elapsed_s']:.0f} s")
    o.add(f"  Summary: Power {f1(S['power'], 0)}/100 · Availability {f1(S['availability'], 0)}/100 · "
          f"Efficiency {f1(S['efficiency'], 0)}/100 · Health {f1(S.get('health'), 0)}/100 · Data coverage {f1(S.get('data_quality'), 0)}/100 · "
          f"Effective {f1(S['effective'], 0)}/100   (detailed results are at the end of the report)")
    def _guard(label, fn):
        try:
            fn()
        except Exception as exc:
            warn(f"report section {label}", exc)
            o.add(paint(f"  (this section could not be generated: {type(exc).__name__}: {exc})", "bad"))
    base = data.get("baseline") or {}
    C, topo = A["cpu"], data["cpu"]["topology"]
    mem, R = data["memory"], A["memory"]
    dyn = mem.get("dynamic") or {}
    Gp = A["gpu"]
    def _s1():
        os_, sm = data["os"], data.get("smbios", {})
        o.h1('1. OPERATING SYSTEM AND PLATFORM')
        o.kv('Operating system', f"{os_.get('product')}  {os_.get('display_version') or ''}".strip())
        o.kv("Build / architecture", f"{os_.get('build_full') or os_.get('build') or '—'}  /  {os_.get('machine')}  ({os_.get('edition_id') or '—'})")
        o.kv("Installation date", _ts(os_.get("install_epoch")))
        o.kv('Uptime', f"{fmt_dur(os_.get('uptime_s') or 0)}  (startup: {_ts(os_.get('boot_epoch'))})")
        o.kv('Manufacturer / model', " ".join(x for x in (dig(sm, "system.manufacturer"), dig(sm, "system.product")) if x))
        o.kv("Motherboard", " ".join(x for x in (dig(sm, "board.manufacturer"), dig(sm, "board.product")) if x))
        _bios = " ".join(x for x in (dig(sm, "bios.vendor"), dig(sm, "bios.version")) if x)
        bios_date = format_report_date(dig(sm, "bios.date"))
        o.kv("BIOS", f"{_bios}  ({bios_date})" if _bios and bios_date != "—" else _bios)
        o.kv('Chassis type', dig(sm, "chassis.type_name"))
        o.kv("Firmware / Secure Boot", f"{os_.get('firmware', '—')}  /  " + ('enabled' if os_.get("secure_boot") else 'disabled' if os_.get("secure_boot") is False else "unknown"))
        tpm = dig(data, "ps.tpm")
        tpm = (as_list(tpm) or [None])[0]
        o.kv("TPM", (f"v{tpm.get('Spec', '?').split(',')[0]} enabled={tpm.get('Enabled')}" if tpm else 'could not be read (administrator permission required)') if IS_WIN else None)
        g = (as_list(dig(data, "ps.guard")) or [None])[0]
        if g:
            o.kv('VBS / Memory integrity', f"VBS {'running' if g.get('Vbs') == 2 else 'disabled'} / HVCI {'running' if 2 in as_list(g.get('Running')) else 'disabled'}")
        o.kv('Fast Startup', 'enabled' if os_.get("fast_startup") else 'disabled' if IS_WIN else None)
        o.kv("HAGS (GPU scheduling)", {True: 'enabled', False: 'disabled', None: None}.get(os_.get("hags")))
        o.kv("Game Mode", {True: 'enabled', False: 'disabled', None: None}.get(os_.get("game_mode")))
        pw = os_.get("power") or {}
        if pw:
            o.kv('Power plan / mode', f"{pw.get('scheme')}  /  {pw.get('overlay') or 'default'}")
            o.kv('Processor state min/max', f"%{pw.get('min_state')} / %{pw.get('max_state')}" if pw.get("max_state") is not None else None)
            o.kv("Boost modu / EPP", f"{pw.get('boost_mode')} / {pw.get('epp')}" if pw.get("boost_mode") is not None else None)
        b = os_.get("battery")
        o.kv("Battery", f"%{b['percent']:.0f}  ({'plugged in' if b['plugged'] else 'on battery'})" if b else 'not applicable (desktop)')
        battery_health = os_.get("battery_health") or {}
        for battery_item in as_list(battery_health.get("batteries")):
            if not isinstance(battery_item, dict):
                continue
            label = battery_item.get("name") or "Battery"
            capacity_text = (f"health %{battery_item['health_pct']:.1f} / wear %{battery_item['wear_pct']:.1f}"
                             if _is_finite_measurement(battery_item.get("health_pct")) else "capacity data unavailable")
            cycle_text = (f" / {battery_item['cycle_count']} cycles" if battery_item.get("cycle_count") is not None else "")
            o.kv(f"{label} health", capacity_text + cycle_text)
        if battery_health.get("status") not in (None, "available"):
            o.kv('Battery health data', battery_health.get("note"))
        o.kv('Restart pending', ", ".join(os_["pending_reboot"]) if os_.get("pending_reboot") else 'no')
        o.kv('Page-file setting', "; ".join(os_.get("pagefile_cfg") or []) or None)
        pagefile_os = os_.get("pagefile") or {}
        if pagefile_os.get("status") == "available":
            auto_text = {True: 'Managed automatically by Windows', False: 'automatic management disabled'}.get(pagefile_os.get("automatic_managed"), 'automatic management unknown')
            o.kv('Page-file management (WMI)', auto_text)
            usage_rows = pagefile_os.get("usage") or []
            if usage_rows:
                o.kv('Page-file allocation / peak usage', "; ".join(
                    f"{row.get('Name')}: {row.get('AllocatedBaseSize')} / {row.get('PeakUsage')} MiB"
                    for row in usage_rows if isinstance(row, dict)))
        py = os_.get("python") or {}
        o.kv("Python / permissions", f"{py.get('impl')} {py.get('version')} ({py.get('bits')}-bit)  /  {'administrator' if os_.get('admin') else 'standard user'}")
        sec = A.get("health", {}).get("security", {})
        defender = sec.get("defender") or {}
        if defender:
            o.kv('Defender / real-time protection', f"antivirus={defender.get('AntivirusEnabled')} / real-time={defender.get('RealTimeProtectionEnabled')}")
            o.kv('Defender signature update', defender.get("AntivirusSignatureLastUpdated"))
        fw = sec.get("firewall_profiles_disabled") or []
        o.kv('Firewall', 'disabled profiles: ' + ", ".join(fw) if fw else ('all reported profiles enabled' if sec.get("firewall_query_available") else None))
        bl = sec.get("bitlocker") or []
        if bl:
            o.kv("BitLocker", "; ".join(f"{x.get('MountPoint')}: {x.get('VolumeStatus')}/{x.get('ProtectionStatus')} (%{x.get('EncryptionPercentage')})" for x in bl))
        ev = A.get("health", {}).get("windows_events") or {}
        if ev:
            o.kv('Critical events in the last 30 days', f"WHEA {ev.get('WHEA', 0)} / BugCheck-volmgr {ev.get('BugCheck', 0)} / storage {ev.get('Storage', 0)} / Windows Update {ev.get('UpdateEvents', 0)}")
        devices = as_list(data.get("ps", {}).get("devices"))
        if devices:
            o.kv('Problem devices', len(devices))
            for device in devices[:6]:
                o.kv(f"Device: {device.get('FriendlyName') or device.get('Class')}", f"{device.get('Status')} / {device.get('Class')}")
        startup = as_list(data.get("ps", {}).get("startup"))
        if startup:
            o.kv('Startup applications', len(startup))
            o.para('Startup entries: ' + "; ".join(str(x.get("Name") or x.get("Command") or "?") for x in startup[:8]), 2, "dim")
        updates = as_list((data.get("ps") or {}).get("updates"))
        if updates:
            o.h2('Recently installed Windows hotfixes (Get-HotFix; may not include updates for all components)')
            o.table(["KB", 'Installed on', 'Description', 'Installed by'],
                    [[x.get("HotFixID") or "—", format_report_date(x.get("InstalledOn")), x.get("Description") or "—",
                      x.get("InstalledBy") or "—"] for x in updates[:8]])
        drivers = as_list((data.get("ps") or {}).get("drivers"))
        if drivers:
            o.h2('Important device drivers (inventory; an old version alone is not evidence of a security vulnerability)')
            o.table(['Device', 'Class', 'Driver version', "Tarih", 'Manufacturer', 'Signed'],
                    [[x.get("DeviceName") or "—", x.get("DeviceClass") or "—", x.get("DriverVersion") or "—",
                      format_report_date(x.get("DriverDate")), x.get("Manufacturer") or "—", x.get("IsSigned")] for x in drivers[:18]])
    _guard('1. Operating system', _s1)
    def _s2():
        cpu, C = data["cpu"], A["cpu"]
        topo = cpu["topology"]
        o.h1('2. PROCESSOR (CPU)')
        o.kv("Model", cpu.get("name"))
        o.kv('Vendor / Family-Model-Stepping', f"{cpu.get('vendor')}  /  {cpu.get('family')}-{cpu.get('model')}-{cpu.get('stepping')}" if cpu.get("family") is not None else cpu.get("vendor"))
        o.kv('Socket / NUMA / processor group', f"{topo['packages']} / {topo['numa_nodes']} / {topo['groups']}")
        smt = any(c["smt"] for c in topo["cores"])
        o.kv('Physical cores', topo["physical_cores"])
        o.kv('Logical processors (threads)', f"{topo['logical']}  (SMT/Hyper-Threading: {'yes' if smt else 'no'})")
        o.kv("Architecture type", 'Hybrid (P + E cores)' if topo["hybrid"] else 'Standard (single core class)')
        sm_cpu = cpu.get("smbios") or {}
        o.kv('BCLK / SMBIOS speeds', f"{sm_cpu.get('ext_clock_mhz')} MHz / maks {sm_cpu.get('max_speed_mhz')} MHz, mevcut {sm_cpu.get('cur_speed_mhz')} MHz  (BIOS report)" if sm_cpu.get("ext_clock_mhz") else None)
        o.h2('Core classes')
        rows = []
        for lab, c in C["classes"].items():
            ca = c["cache"]
            sz = lambda k: fmt_bytes((ca.get(k) or {}).get("size"), 0) if ca.get(k) else "—"
            l2 = ca.get("L2")
            l2s = f"{fmt_bytes(l2['size'], 0)}" + (f" (/{l2['shared_logical']} thread)" if l2 and l2["shared_logical"] > 2 else "") if l2 else "—"
            rows.append([{"P": "P (Performance)", "E": "E (Efficiency)", "LP-E": 'LP-E (Low power)', "Standart": 'All cores'}.get(lab, lab),
                         c["cores"], c["threads"], fmt_ghz(c["base_mhz"]), fmt_ghz(c["boost_mhz"]),
                         f"{c['jit_ghz']:.2f} GHz" if c.get("jit_ghz") else "—", f1(c.get("ipc"), 2), sz("L1d"), sz("L1i"), l2s])
        o.table(['Class', 'Core', "Thread", "Base", 'Boost (single-core load test)', 'Measured clock', "IPC (ALU)", "L1d", "L1i", "L2"], rows,
                align=["<", ">", ">", ">", ">", ">", ">", ">", ">", ">"])
        if C.get("base_source"):
            o.para(f"Base source: {C['base_source']}. Boost is the peak frequency measured only during a single-core load test; "
                   f"an empty value means no load test was run in this mode. Live PDH frequency samples are not used as boost measurements. "
                   f"IPC = peak instructions/cycle measured in an independent integer instruction stream (ALU width); real application IPC cannot be measured without hardware counters "
                   f"in user mode.", 2, "dim")
        o.h2('Cache')
        rows = []
        for key, lbl in (("L1d", "L1 Data"), ("L1i", "L1 Instruction"), ("L2", "L2"), ("L3", "L3")):
            cs = topo["cache_summary"].get(key)
            if cs:
                sizes = " / ".join(fmt_bytes(s, 0) for s in cs["sizes"])
                rows.append([lbl, cs["instances"], sizes, fmt_bytes(cs["total"], 1)])
        o.table(["Level", "Count", 'Size (per instance)', "Total"], rows, align=["<", ">", ">", ">"]) if rows else o.add('  (cache information could not be read)')
        o.h2("Instruction sets")
        isa = cpu.get("isa") or {}
        o.kv('Detected', ", ".join(isa.get("present") or []) or "—", kw=14)
        o.kv('Vector width', f"{isa.get('simd_bits')}-bit  (source: {isa.get('source')})", kw=14)
        if C.get("fma_note"):
            o.kv('FMA pipeline inference', f"{C['fma_note']}  (FP64 ≈ {C['fp64_fpc']:.1f} FLOP/cycle, FP32 ≈ {f1(C['fp32_fpc'])})", kw=14)
        base = data.get("baseline") or {}
        o.h2('Frequency (clock speed)')
        fm = base.get("freq") or {}
        o.kv('Current average frequency (now)', f"{fmt_ghz(fm.get('avg_mhz'))}  (of the nominal ratio %{f1(fm.get('perf_pct_avg'), 0)})" if fm.get("avg_mhz") else 'could not be read')
        primary_core_label = "P" if topo.get("hybrid") else "standard"
        if C["boost_p"]:
            o.kv(f"Under single-core load ({primary_core_label})",
                 f"avg. {fmt_ghz(dig(data, 'bench.cpu.py.single_p.mhz'))}, peak {fmt_ghz(C['boost_p'])}")
        else:
            o.kv(f"Single-core load test ({primary_core_label})", 'not measured (no CPU load benchmark in this run)')
        if C["boost_e"]:
            o.kv('Under single-core load (E)', f"peak {fmt_ghz(C['boost_e'])}")
        if C.get("sampled_freq_max_mhz"):
            sample_source = f" · source={C['sampled_freq_source']}" if C.get("sampled_freq_source") else ""
            o.kv('Peak frequency observed in live samples (not a load test)',
                 f"{fmt_ghz(C['sampled_freq_max_mhz'])}{sample_source}")
        o.kv('With all cores under load', f"{fmt_ghz(C['allcore_mhz'])}  (of base clock %{C['allcore_ratio'] * 100:.0f})" if C["allcore_mhz"] and C["allcore_ratio"] else None)
        o.kv('Windows frequency limit', f"%{C['limit_ratio'] * 100:.0f} (MhzLimit/MaxMhz)" if C["limit_ratio"] else None)
        if C["sustained"]:
            s_ = C["sustained"]
            o.kv('Sustained load (5×4 sec)', f"throughput last/first = {s_['ratio'] * 100:.0f}%" + (f", frequency last/first = {s_['freq_ratio'] * 100:.0f}%" if s_["freq_ratio"] else ""))
        if not (dig(data, "bench.cpu") or {}).get("alu"):
            o.add(paint('  (core clock/IPC measurement was not run in this mode)', "dim"))
        bc = dig(data, "bench.cpu", {}) or {}
        if bc.get("py"):
            o.h2('CPU benchmark results')
            py, gm, g32 = bc["py"], dig(bc, "gemm.float64", {}) or {}, dig(bc, "gemm.float32", {}) or {}
            rows = []
            single_primary_label = "P / primary" if topo.get("hybrid") else "standard / primary"
            for key, lbl in (("single_p", f"Single core ({single_primary_label})"), ("single_e", 'Single core (E)'), ("all_phys", 'All physical cores'), ("all_logical", 'All logical processors')):
                if key in py or key in gm:
                    rows.append([lbl, f1((py.get(key) or {}).get("ops", 0) / 1e6 if (py.get(key) or {}).get("ops") else None, 2),
                                 f1((gm.get(key) or {}).get("gflops"), 1), f1((g32.get(key) or {}).get("gflops"), 1) if key == "single_p" else "—",
                                 fmt_ghz((py.get(key) or {}).get("mhz"))])
            o.table(["Test", "Python (M iter/s)", "BLAS FP64 GFLOPS", "BLAS FP32 GFLOPS", "Avg. frequency"], rows, align=["<", ">", ">", ">", ">"])
            o.kv('Multi-core scaling efficiency', f"%{C['scaling'] * 100:.0f}" if C["scaling"] else None)
            smt_core_label = 'P cores' if topo.get("hybrid") else 'standard core'
            o.kv('SMT (Hyper-Threading) gain', f"+%{C['smt_gain'] * 100:.0f} ({smt_core_label} per core)" if C["smt_gain"] is not None else None)
            o.kv('E-core / P-core ratio', f"%{C['e_vs_p'] * 100:.0f}" if C["e_vs_p"] else None)
            o.kv(f"{C['core_equivalent_label']} (entire CPU)", f"{C['p_equiv']:.1f}" if C["p_equiv"] else None)
            if bc.get("partial_workers"):
                o.add(paint('  Note: Due to insufficient memory, only a subset of cores was measured.', "warn"))
        lat = C.get("latency")
        if lat:
            o.h2('Cache / memory latency (random access, pointer chasing)')
            o.kv("L1", f1(lat["l1_ns"], 2, " ns"), kw=14)
            o.kv("L2", f1(lat["l2_ns"], 2, " ns"), kw=14)
            o.kv("L3", f1(lat["l3_ns"], 1, " ns"), kw=14)
            o.kv("RAM", f"{lat['dram_ns']:.0f} ns  ({fmt_bytes(lat['dram_size'], 0)} working set, including TLB)" if lat.get("dram_ns") else None, kw=14)
            curve = "  ".join(f"{fmt_bytes(s, 0)}:{ns:.1f}" for s, ns in lat["points"])
            o.para('Curve (size:ns) → ' + curve, 2, "dim")
        o.h2('Current load and idle capacity')
        cb = base.get("cpu") or {}
        o.kv('Average CPU utilization', f"{fmt_pct(cb.get('util_avg'))}  {bar(cb.get('util_avg') or 0, 20, False)}" if cb else None)
        o.kv('Busiest single logical processor', fmt_pct(cb.get("util_peak_cpu")) if cb else None)
        o.kv('Idle capacity', f"≈ {C['free_equiv']:.1f} / {C['total_equiv']:.1f} {C['core_equivalent_label']}  ({C['free_cores']:.1f} / {topo['physical_cores']} physical cores idle)")
        sy = base.get("sys") or {}
        o.kv('Ready queue length', f1(sy.get("queue"), 1))
        o.kv('Context switches / system calls', f"{sy['ctx_per_s']:,.0f}/s  /  {sy['syscalls_per_s']:,.0f}/s" if sy.get("ctx_per_s") is not None and sy.get("syscalls_per_s") is not None else None)
        o.kv('DPC / interrupt / privileged time', f"%{f1(sy.get('dpc_pct'))} / %{f1(sy.get('intr_pct'))} / %{f1(sy.get('priv_pct'))}" if sy.get("dpc_pct") is not None else None)
        o.kv('Parked (sleeping) cores', base.get("parked_cpus"))
        u = cb.get("util_per_cpu") or []
        if u:
            cells = [f"{i:>2}:{v:>3.0f}%" for i, v in enumerate(u)]
            for i in range(0, len(cells), 8):
                o.add("    " + "  ".join(cells[i:i + 8]))
        if dig(data, "bench.cpu.repeat_count"):
            o.kv('Benchmark repeat count', dig(data, "bench.cpu.repeat_count"))
            rep = dig(data, "bench.cpu.repeatability") or {}
            py_summary = rep.get("python_single_p_ops_summary") or {}
            if py_summary.get("count"):
                o.kv('Single-core measurement distribution', f"median {py_summary.get('median'):.0f} ops/s; min–max {py_summary.get('min'):.0f}–{py_summary.get('max'):.0f}; variation {py_summary.get('cv_pct'):.2f}%")
            gm_summary = rep.get("gemm_single_p_gflops_summary") or {}
            if gm_summary.get("count"):
                o.kv('FP64 GEMM repeat distribution', f"median {gm_summary.get('median'):.2f} GFLOPS; min–max {gm_summary.get('min'):.2f}–{gm_summary.get('max'):.2f}; variation {gm_summary.get('cv_pct'):.2f}%")
        reliability = dig(data, "bench.reliability") or {}
        if reliability:
            o.h2('Benchmark reliability')
            o.kv('Warm-up runs / successful repeats', f"{reliability.get('warmup_count', 0)} / {reliability.get('successful_repeat_count', 0)}")
            o.kv('Pre-load CPU utilization', fmt_pct(reliability.get("ambient_cpu_percent")))
            o.kv('Distribution status', reliability.get("status"))
            for metric in reliability.get("metrics") or []:
                summary = metric.get("summary") or {}
                if summary.get("count"):
                    o.kv(metric.get("label", 'CPU measurement'),
                         f"median {f1(summary.get('median'), 2)} {metric.get('unit')}; min–max {f1(summary.get('min'), 2)}–{f1(summary.get('max'), 2)}; σ {f1(summary.get('stdev'), 2)}; CV {f1(summary.get('cv_pct'), 2)}")
            for warning in (reliability.get("warnings") or [])[:6]:
                o.para("• " + warning, 4, "warn")
            o.para(reliability.get("scope_note") or "", 2, "dim")
        o.h2('CPU performance score')
        for r in C["power_comp"]:
            o.add(f"    {r['name']:<26} {sc(r['value'])}   {r.get('note') or ''}")
    _guard("2. CPU", _s2)
    def _s3():
        mem, R = data["memory"], A["memory"]
        o.h1("3. MEMORY (RAM)")
        o.kv("Installed memory", f"{fmt_bytes(mem.get('total_installed') or R['total'])}  ({mem.get('populated')} module(s) / {mem.get('slots_total')} slot)" if mem.get("slots_total") else fmt_bytes(R["total"]))
        o.kv('Visible to Windows', fmt_bytes(R["total"]))
        o.kv('Type / operating speed', f"{mem.get('type')}  /  {mem.get('run_mts')} MT/s (module rating: {mem.get('rated_mts')} MT/s)" if mem.get("type") else None)
        o.kv('Channel count', (f"{mem.get('channels')}  ({mem.get('channels_source')})" + ('  — soldered LPDDR: layout is fixed' if (mem.get("type") or "").startswith("LPDDR") else "")) if mem.get("channels") else None)
        module_sizes = {m.get("size_bytes") for m in (mem.get("modules") or []) if m.get("size_bytes")}
        if len(module_sizes) > 1 and mem.get("channels") and mem.get("channels") >= 2:
            channel_names = ", ".join(str(m.get("bank") or m.get("slot") or "channel count unknown") for m in mem.get("modules") or [])
            o.para('SMBIOS reports two memory channels, but module capacities are not equal. Channel labels: '
                   f"({channel_names}) is a physical placement description; SMBIOS cannot verify dual-channel operation across the entire address range or determine the limits of asymmetric memory operation.", 2, "dim")
        o.kv("ECC", {True: "Yes", False: "no", None: None}.get(any(m.get("ecc") for m in mem.get("modules", [])) if mem.get("modules") else None))
        o.kv("Maximum motherboard capacity", fmt_bytes(mem.get("max_capacity"), 0) if mem.get("max_capacity") else None)
        if mem.get("modules"):
            rows = [[m.get("slot"), fmt_bytes(m.get("size_bytes"), 0), m.get("type"), f"{m.get('speed_mts') or '—'}", f"{m.get('configured_mts') or '—'}",
                     m.get("manufacturer") or "—", m.get("part") or "—", m.get("rank") or "—"] for m in mem["modules"]]
            o.table(["Slot", "Capacity", "Type", 'Module MT/s', 'Operating MT/s', 'Manufacturer', 'Part number', "Rank"], rows, align=["<", ">", "<", ">", ">", "<", "<", ">"])
        o.h2('Usage')
        o.kv('In use', f"{fmt_bytes(R['used'])}  (%{R['used'] / R['total'] * 100:.1f})  {bar(R['used'] / R['total'] * 100, 20, False)}" if R["total"] else None)
        o.kv('Available (free + standby)', f"{fmt_bytes(R['available'])}  (%{R['avail_pct']:.1f})" if R["avail_pct"] is not None else None)
        cp = R["composition"]
        o.kv("Composition", "  ".join(f"{k}: {fmt_bytes(v, 1)}" for k, v in (('modified', cp["modified"]), ("standby", cp["standby"]),
                                                                              ('zeroed/free', cp["free"]), ('compressed', cp["compressed"])) if v is not None) or None)
        o.kv("Commit (virtual memory)", f"{fmt_bytes(R['commit_total'])} / {fmt_bytes(R['commit_limit'])}  (%{R['commit_pct']:.0f})" if R["commit_pct"] is not None else None)
        dyn = mem.get("dynamic") or {}
        pagefile_assessment = R.get("pagefile") or {}
        pagefile_mode = pagefile_assessment.get("mode", "unknown")
        if dyn.get("swap_total"):
            pagefile_runtime_text = (f"{fmt_bytes(dyn.get('swap_used'))} / {fmt_bytes(dyn.get('swap_total'))}  "
                                    f"(%{dyn.get('swap_percent') or 0:.0f})")
        elif pagefile_mode == "disabled":
            pagefile_runtime_text = 'not present / disabled (verified through Windows CIM)'
        elif pagefile_mode == "system_managed":
            pagefile_runtime_text = 'Managed by Windows; current usage counter is empty'
        elif pagefile_mode == "custom":
            pagefile_runtime_text = 'Custom configuration detected; current usage counter is empty'
        else:
            pagefile_runtime_text = 'status unknown / usage counter unavailable'
        o.kv('Page file', pagefile_runtime_text)
        if pagefile_assessment.get("mode"):
            o.kv('Page-file assessment', pagefile_assessment.get("recommendation"))
        o.kv('Page faults / hard faults (pages/sec)', f"{f1(dig(base, 'mem.mem_faults'), 0)} / {f1(dig(base, 'mem.mem_pages_in'), 0)}" if dig(base, "mem.mem_faults") is not None else None)
        o.kv('Kernel pools', f"paged {fmt_bytes(dyn.get('kernel_paged'), 0)}, nonpaged {fmt_bytes(dyn.get('kernel_nonpaged'), 0)}" if dyn.get("kernel_paged") else None)
        o.h2('Bandwidth')
        bw = R.get("bw") or {}
        o.kv("Theoretical (estimated)", f"{mem['theoretical_gbs']:.1f} GB/s  ({mem.get('channels')} channel × {mem.get('run_mts')} MT/s × 8 bytes)" if mem.get("theoretical_gbs") else None)
        if bw.get("best_copy_gbs"):
            o.kv('Measured copy (read+write)', f"{bw['best_copy_gbs']:.1f} GB/s  ({bw.get('best_threads')} thread(s) -> efficiency %{R['bw_ratio'] * 100:.0f}" if R["bw_ratio"] else f"{bw['best_copy_gbs']:.1f} GB/s")
            o.kv('Measured write (fill)', f"{f1(bw.get('fill_gbs'))} GB/s")
            o.para('Copy by thread (GB/s): ' + "  ".join(f"{k}→{v:.1f}" for k, v in (bw.get("copy_gbs") or {}).items()), 2, "dim")
        else:
            o.add(paint('  (bandwidth benchmark was not run in this mode)', "dim"))
        o.kv('RAM access latency', f"{R['dram_ns']:.0f} ns" if R["dram_ns"] else None)
        memtest = dig(data, "bench.memory_integrity")
        if memtest:
            o.kv('RAM sampling test', ('passed' if memtest.get("passed") else 'failed / not run') +
                 f" — {fmt_bytes(memtest.get('tested_bytes'), 0)}; {memtest.get('checked_samples', 0)} sample(s); {memtest.get('elapsed_s', 0):.1f} s" if memtest.get("tested_bytes") else memtest.get("error"))
            o.para(memtest.get("note") or 'Low-risk smoke test; not a substitute for a full memory test.', 2, "dim")
        o.h2('RAM performance score')
        for r in R["power_comp"]:
            o.add(f"    {r['name']:<26} {sc(r['value'])}   {r.get('note') or ''}")
    _guard("3. RAM", _s3)
    def _s4():
        Gp = A["gpu"]
        o.h1("4. GRAPHICS ADAPTER (GPU)")
        if not Gp["list"]:
            o.add('  GPU information could not be obtained.')
        for g in Gp["list"]:
            o.h2(f"{g['name']}  [{g['vendor']}, {'integrated' if g['integrated'] else 'discrete'}]")
            o.kv('Dedicated GPU memory' if g["integrated"] else "VRAM",
                 f"{fmt_bytes(g['vram_total'])}" + (f"  (in use {fmt_bytes(g['vram_used'])}, free {fmt_bytes(g['vram_free'])})" if g.get("vram_used") is not None else ""))
            if g["integrated"]:
                o.kv('DXGI shared system memory limit', fmt_bytes(g.get("shared_sys")))
                o.kv('Sampled shared GPU memory usage', fmt_bytes(g.get("shared_used")))
                o.para('An integrated GPU can dynamically use system memory when needed. The DXGI shared-memory value is not fixed/guaranteed VRAM or the GPU budget currently available.', 2, "dim")
            o.kv('Driver', f"{g.get('driver_version') or '—'}  ({format_report_date(g.get('driver_date'))})")
            o.kv('GPU utilization', f"{fmt_pct(g['util'])}" + ("  " + ", ".join(f"{k}:{v:.0f}%" for k, v in g["engines"].items() if v and v >= 1) if g["engines"] else "") if g.get("util") is not None else None)
            nv = g.get("nvml")
            if nv:
                o.kv('Architecture / compute capability', f"{nv.get('arch') or '—'} / CC {nv.get('compute_cap') or '—'}")
                o.kv('CUDA cores', nv.get("cuda_cores"))
                o.kv("Clock (graphics / memory)", f"{nv.get('clk_gfx')}/{nv.get('clk_gfx_max')} MHz  /  {nv.get('clk_mem')}/{nv.get('clk_mem_max')} MHz")
                o.kv("Theoretical FP32 / memory bandwidth", f"{f1(g['fp32_tflops'])} TFLOPS / {f1(g['mem_bw_gbs'], 0)} GB/s ({nv.get('bus_width')}-bit)" if g.get("fp32_tflops") or g.get("mem_bw_gbs") else None)
                o.kv('Power / limit (default)', f"{f1(nv.get('power_w'), 0)} W / {f1(nv.get('power_limit_w'), 0)} W ({f1(nv.get('power_default_w'), 0)} W)" if nv.get("power_limit_w") else None)
                o.kv('Temperature / fan', f"{nv.get('temp')}°C (throttling threshold {nv.get('temp_slowdown')}°C) / %{nv.get('fan')}" if nv.get("temp") is not None else None)
                o.kv('PCIe link (current / maximum)', f"Gen{nv.get('pcie_gen')} x{nv.get('pcie_width')}  /  Gen{nv.get('pcie_gen_max')} x{nv.get('pcie_width_max')}  (may be lower to save power while idle)" if nv.get("pcie_gen") else None)
                o.kv('Driver model / BAR1 / enc-dec', f"{nv.get('driver_model')} / {fmt_bytes(nv.get('bar1_total'), 0)} / {nv.get('util_enc')}% - {nv.get('util_dec')}%" if nv.get("bar1_total") else None)
                o.kv('Active throttling', ", ".join(nv["throttle"]) if nv.get("throttle") else "no")
            else:
                if dig(data, "gpu.nvml_status") == "not_applicable":
                    o.add(paint('  (NVML not applicable: no NVIDIA adapter was found in the DXGI inventory.)', "dim"))
                else:
                    o.add(paint('  (NVML unavailable: nvidia-ml-py and a compatible NVIDIA driver are required for detailed NVIDIA telemetry.)', "dim"))
            for r in g["power_comp"]:
                o.add(f"      {r['name']:<24} {sc(r['value'])}   {r.get('note') or ''}")
        gpu_b = dig(data, "bench.gpu")
        if gpu_b:
            if gpu_b.get("available"):
                o.kv('Measured GPU benchmark', f"{gpu_b.get('backend')} / {gpu_b.get('device')} — {f1(gpu_b.get('gflops'), 0)} GFLOPS FP32, matrix {gpu_b.get('matrix_size')}², {gpu_b.get('iterations')} iterations")
                o.para(gpu_b.get("note") or "", 2, "dim")
            else:
                o.kv("GPU benchmark", gpu_b.get("reason") or gpu_b.get("error") or 'could not be run')
        enc = dig(data, "bench.encoder")
        if enc:
            o.h2('Synthetic H.264 video encoder test')
            if enc.get("encoders"):
                o.table(["Encoder", "Status", "FPS", 'Real-time factor', 'Duration / error'],
                        [[e.get("encoder"), 'passed' if e.get("passed") else 'failed',
                          f1(e.get("fps"), 1) if e.get("fps") is not None else "—",
                          f"{f1(e.get('realtime_factor'), 2)}×" if e.get("realtime_factor") is not None else "—",
                          f"{f1(e.get('elapsed_s'), 2)} s" + (f" · {e.get('error')}" if e.get("error") else "")]
                         for e in enc.get("encoders", [])])
                o.para(enc.get("note") or "", 2, "dim")
            else:
                o.kv("Encoder testi", enc.get("reason") or 'FFmpeg/compatible encoder not found')
        if dig(base, "gpu_proc"):
            o.kv('Processes using the most VRAM', ", ".join(f"{p['name']} ({fmt_bytes(p['vram'], 0)})" for p in base["gpu_proc"]), kw=34)
    _guard("4. GPU", _s4)
    def _s5():
        st = data["storage"]
        o.h1("5. STORAGE")
        if st.get("disks"):
            o.table(["Disk", 'Type', "Size", "Windows status", "Firmware", 'Drivers'],
                    [[d["name"], d["kind"], fmt_bytes(d["size"], 0), d.get("health"), d.get("firmware_version") or "—",
                      " ".join(f"{l}:" for l in d["drives"])] for d in (st.get("disks") or [])],
                    align=["<", "<", ">", "<", "<", "<"])
            for disk in (st.get("disks") or []):
                if disk.get("logical_sector_size") or disk.get("physical_sector_size"):
                    o.kv(f"Sector size: {disk.get('name')}",
                         f"logical {disk.get('logical_sector_size') or '—'} B / physical {disk.get('physical_sector_size') or '—'} B")
        rows = [[v["mount"], v["fs"], fmt_bytes(v["total"], 1), fmt_bytes(v["used"], 1), fmt_bytes(v["free"], 1), f"{bar(v['pct'], 14, False)} %{v['pct']:.0f}"] for v in (st.get("volumes") or [])]
        o.add("")
        o.table(['Driver', "File system", "Total", 'Used', 'Free', "Occupancy"], rows, align=["<", "<", ">", ">", ">", "<"])
        d = A["storage"]["bench"]
        if d.get("seq_read_mbs") or d.get("error"):
            o.h2(f"Disk speed test ({d.get('path')}, {fmt_bytes(d.get('size'), 0) if d.get('size') else ''})")
            if d.get("error"):
                o.add(f"  {d['error']}")
            else:
                o.kv('Sequential read / write', f"{f1(d.get('seq_read_mbs'), 0)} MB/s  /  {f1(d.get('seq_write_mbs'), 0)} MB/s (uncached; the first GiB may be served from the SLC cache)")
                o.kv("Random 4K read (QD1)", f"{f1(d.get('rand4k_iops'), 0)} IOPS, median {f1(d.get('rand4k_median_us'), 0)} µs, p99 {f1(d.get('rand4k_p99_us'), 0)} µs" if d.get("rand4k_iops") else None)
                o.kv("Random 4K write (QD1)", f"{f1(d.get('rand4k_iops_write'), 0)} IOPS, median {f1(d.get('rand4k_median_us_write'), 0)} µs, p99 {f1(d.get('rand4k_p99_us_write'), 0)} µs" if d.get("rand4k_iops_write") else None)
                for qd in (4, 8):
                    for direction in ("read", "write"):
                        key = f"rand4k_qd{qd}_{direction}_iops"
                        o.kv(f"Random 4K {direction} (concurrent QD≈{qd})",
                             f"{f1(d.get(key), 0)} IOPS · median {f1(d.get(f'rand4k_qd{qd}_{direction}_median_us'), 0)} µs · p99 {f1(d.get(f'rand4k_qd{qd}_{direction}_p99_us'), 0)} µs" if d.get(key) else None)
                if d.get("queued_io_method"):
                    o.para("Kuyruk notu: " + d["queued_io_method"], 2, "dim")
                if d.get("target_mount"):
                    o.kv('Test volume / physical disk', f"{d.get('target_mount')} / {d.get('target_disk_name') or 'could not be matched'}")
                if d.get("target_mount") and A["storage"].get("sysvol") and d["target_mount"].upper().rstrip("\\") != A["storage"]["sysvol"]["mount"].upper().rstrip("\\"):
                    o.para('Warning: This measurement does not belong to the system drive; it was not included in the system-disk score.', 2, "warn")
                o.kv("Not", d.get("note"))
        for disk in (st.get("disks") or []):
            rel = disk.get("windows_storage_reliability") or disk.get("reliability") or {}
            if rel:
                raw_temp = rel.get("Temperature", rel.get("temperature_c"))
                try:
                    temp_value = float(raw_temp) if raw_temp is not None and not isinstance(raw_temp, bool) else None
                except (TypeError, ValueError, OverflowError):
                    temp_value = None
                temp_text = f"{temp_value:.1f}" if temp_value is not None and math.isfinite(temp_value) and 0.0 < temp_value <= 200.0 else "—"
                o.kv(f"Health counters: {disk.get('name')}",
                     f"Windows Storage Reliability: temperature {temp_text} °C; wear {rel.get('Wear', rel.get('wear_pct', '—'))}; power-on time {rel.get('PowerOnHours', rel.get('power_on_hours', '—'))} h; uncorrectable read/write {rel.get('ReadErrorsUncorrected', '—')}/{rel.get('WriteErrorsUncorrected', '—')}")
        smartctl_summary = st.get("smartctl") or dig(data, "inventory.storage.smartctl", {}) or {}
        if isinstance(smartctl_summary, dict) and smartctl_summary:
            o.kv('SMART source / query status',
                 f"{smartctl_summary.get('source', 'smartctl')} / {smartctl_summary.get('status', 'unknown')}; "
                 f"scan record={smartctl_summary.get('device_count', 0)}; read-only={bool(smartctl_summary.get('read_only', True))}")
            for smart_device in as_list(smartctl_summary.get("devices")):
                if not isinstance(smart_device, dict):
                    continue
                path = smart_device.get("device_path") or smart_device.get("model") or "Disk"
                temp = smart_device.get("temperature_c")
                temp_text = f"{float(temp):.1f} °C" if isinstance(temp, (int, float)) and not isinstance(temp, bool) and math.isfinite(float(temp)) and 0.0 < float(temp) <= 200.0 else "—"
                o.kv(f"SMART (smartctl): {path}",
                     f"query={smart_device.get('query_status', 'unknown')}; health={smart_device.get('health_status', 'unknown')}; "
                     f"match={smart_device.get('identity_match_method') or smart_device.get('identity_match_status') or '—'}; "
                     f"temperature={temp_text}; wear={smart_device.get('percentage_used', '—')}; "
                     f"power_on_hours={smart_device.get('power_on_hours', '—')} h; media errors={smart_device.get('media_errors', '—')}")
                startup_write_cache_abort = smartctl_is_single_boot_write_cache_abort(smart_device)
                exit_messages = as_list(smart_device.get("exit_status_messages"))
                if not exit_messages:
                    exit_messages = _smartctl_exit_status_details(smart_device.get("smartctl_exit_status"))["messages"]
                if startup_write_cache_abort:
                    exit_messages = [message for message in exit_messages
                                     if not ('error log' in str(message).casefold()
                                             and 'error record' in str(message).casefold())]
                if exit_messages:
                    o.para('SMART exit warning: ' + "; ".join(str(x) for x in exit_messages), 4, "warn")
                smart_power_on_hours = smart_device.get("power_on_hours")
                if smart_power_on_hours is None:
                    smart_power_on_hours = _smartctl_ata_power_on_hours({"table": as_list(smart_device.get("ata_attributes"))})
                if smart_power_on_hours is not None:
                    o.para(f"SMART total disk power-on hours: {smart_power_on_hours} hours", 4, "dim")
                error_entries = as_list(smart_device.get("error_log_entries"))
                if error_entries:
                    latest = error_entries[0]
                    lba_value = latest.get("lba")
                    log_heading = ('SMART initial configuration record (newest): '
                                   if startup_write_cache_abort else 'SMART error log (latest): ')
                    log_style = "dim" if startup_write_cache_abort else "warn"
                    o.para(log_heading
                           + f"{latest.get('error_description') or 'no description'}; "
                           + f"power-on hours at event time={latest.get('lifetime_hours') if latest.get('lifetime_hours') is not None else 'unknown'}", 4, log_style)
                    command_trail = as_list(latest.get("previous_commands"))
                    decoder_context = _smartctl_decoder_context(latest)
                    if isinstance(decoder_context, dict):
                        command_name = decoder_context.get("command_name") or "ATA command"
                        command_opcode = decoder_context.get("command")
                        feature_reg = decoder_context.get("features")
                        command_detail = f"{command_name} (CR=0x{command_opcode:02X}" if isinstance(command_opcode, int) else command_name + " (CR=unknown"
                        if isinstance(feature_reg, int):
                            command_detail += f", FR=0x{feature_reg:02X}"
                        command_detail += ")"
                        o.para('smartmontools error interpretation context (newest entry in the five-command history): ' + command_detail, 4, "dim")
                    elif command_trail:
                        latest_record = command_trail[0] if isinstance(command_trail[0], dict) else {}
                        latest_name = latest_record.get("command_name") or "ATA command"
                        o.para(f"Newest recorded command history: {latest_name}; command interpretation is uncertain because five raw history slots were not provided.", 4, "dim")
                    if lba_value is not None:
                        lba_is_address = latest.get("lba_is_command_address")
                        if lba_is_address is None and isinstance(decoder_context, dict) and decoder_context.get("command") == 0xEF:
                            lba_is_address = False
                        lba_note = 'not an address field for this command' if lba_is_address is False else 'raw register; not verified as a sector address'
                        o.para(f"ATA LBA register (raw)={lba_value} ({lba_note})", 4, "dim")
                    completion = latest.get("completion_registers") or {}
                    if completion:
                        register_parts = []
                        for key, value in completion.items():
                            if key in {"error", "status", "device"} and isinstance(value, int):
                                register_parts.append(f"{key}=0x{value:02X}")
                            else:
                                register_parts.append(f"{key}={value}")
                        o.para('ATA error completion registers: ' + ", ".join(register_parts), 4, "dim")
                    for command in command_trail[:5]:
                        if not isinstance(command, dict):
                            continue
                        command_name = command.get("command_name") or "ATA command"
                        registers = command.get("registers") or command
                        command_code = registers.get("command")
                        code_text = f" (CR=0x{int(command_code):02X})" if isinstance(command_code, int) else ""
                        command_lba = registers.get("lba")
                        lba_text = f", command LBA={command_lba}" if command_lba is not None else ""
                        o.para(f"Command record before the error: {command_name}{code_text}{lba_text}", 4, "dim")
                    o.para('Note: An ATA log LBA field alone is not evidence of a bad sector; it must be evaluated with the failing command and raw-register context.', 4, "dim")
                reason = smart_device.get("unsupported_reason") or smart_device.get("query_status_reason") or smart_device.get("error")
                if reason and smart_device.get("query_status") in {"unsupported", "not_matched", "failed"}:
                    o.para("SMART note: " + str(reason), 4, "dim")
        db_ = base.get("disk") or {}
        o.kv('Current disk activity / queue', f"%{f1(db_.get('busy_pct'))} / {f1(db_.get('queue'), 2)}" if db_.get("busy_pct") is not None else None)
        o.kv('Current read / write', f"{fmt_bytes(db_.get('read_bps'), 1)}/s / {fmt_bytes(db_.get('write_bps'), 1)}/s" if db_.get("read_bps") is not None else None)
        if A["storage"]["power_comp"]:
            o.h2('Disk performance score')
            for r in A["storage"]["power_comp"]:
                o.add(f"    {r['name']:<26} {sc(r['value'])}   {r.get('note') or ''}")
    _guard("5. Storage", _s5)
    def _s6():
        o.h1('6. NETWORK AND SYSTEM LOAD')
        for n in (data.get("network") or []):
            o.kv(f"Network: {n['name']}", f"{n['speed_mbps']} Mbit/s" if n.get("speed_mbps") else f"MTU {n.get('mtu') or '—'}")
            err_in, err_out = n.get("errors_in"), n.get("errors_out")
            drop_in, drop_out = n.get("drops_in"), n.get("drops_out")
            if any(v not in (None, 0) for v in (err_in, err_out, drop_in, drop_out)):
                o.kv(f"Network errors/drops: {n['name']}", f"cumulative errors RX/TX {err_in or 0}/{err_out or 0}; cumulative packet drops RX/TX {drop_in or 0}/{drop_out or 0}")
        nt = base.get("net") or {}
        o.kv('Current network traffic', f"↓ {f1(nt.get('rx_mbps'), 2)} / ↑ {f1(nt.get('tx_mbps'), 2)} Mbit/s" if nt else None)
        net_test = dig(data, "bench.network_test")
        if net_test:
            o.h2('Optional network quality test')
            o.kv('Target / packet loss', f"{net_test.get('target')} / %{f1(net_test.get('loss_pct'))}")
            o.kv("RTT min / avg. / max", f"{f1(net_test.get('min_ms'))} / {f1(net_test.get('avg_ms'))} / {f1(net_test.get('max_ms'))} ms")
            o.kv('Jitter / DNS resolution', f"{f1(net_test.get('jitter_ms'))} ms / {f1(net_test.get('dns_ms'))} ms")
            o.kv('Download / upload', f"{f1(net_test.get('download_mbps'), 2)} / {f1(net_test.get('upload_mbps'), 2)} Mbit/s" if net_test.get("download_mbps") is not None or net_test.get("upload_mbps") is not None else None)
            o.kv('Transfer amount', f"↓ {fmt_bytes(dig(net_test, 'speed_test_bytes.download'), 1)} / ↑ {fmt_bytes(dig(net_test, 'speed_test_bytes.upload'), 1)}")
            o.kv("DNS adresleri", ", ".join(net_test.get("dns_addresses") or []) or net_test.get("dns_error"))
            o.kv('Network test note', net_test.get("error") or net_test.get("download_error") or net_test.get("upload_error"))
        pr = base.get("procs") or {}
        pf = dyn
        o.kv('Process / thread / handle', f"{pf.get('processes')} / {pf.get('threads')} / {pf.get('handles')}" if pf.get("processes") else f"{pr.get('count')} process(es)")
        if pr.get("top_cpu"):
            o.h2('Processes using the most CPU')
            o.table(['Process', "PID", "CPU %"], [[p["name"], p["pid"], f"{(p.get('cpu') or 0):.1f}"] for p in (pr.get("top_cpu") or [])[:6]], align=["<", ">", ">"])
            o.h2('Processes using the most RAM')
            o.table(['Process', "PID", "Memory"], [[p["name"], p["pid"], fmt_bytes(p.get("rss"), 0)] for p in (pr.get("top_mem") or [])[:6]], align=["<", ">", ">"])
        display_rows, provider_status = collect_report_sensor_observations(data)
        display_rows = [(row, float(row["Value"])) for row in display_rows]
        if display_rows:
            o.h2('Temperature / power sensors (combined hardware providers)')
            for row, value in display_rows[-12:]:
                unit = "°C" if str(row.get("SensorType", "")).casefold() == "temperature" else "W"
                category = row.get("SensorRole") or row.get("HardwareType") or ""
                source = row.get("source") or "source unknown"
                stamp = row.get("timestamp") or "time unknown"
                sensor_identifier = str(row.get("SensorIdentifier") or "")
                zone_id = sensor_identifier.rsplit("\\", 1)[-1] if str(row.get("HardwareType", "")).casefold() == "acpi thermal zone" else ""
                name_width = 16 if zone_id else 24
                live_name = _display_label(row.get("Name") or 'Sensor', name_width)
                live_id = f" [{zone_id}]" if zone_id else ""
                o.add(f"    {_display_label(row.get('Parent'), 24):<24} {live_name:<{name_width}}{live_id:<16} {value:>7.1f} {unit}  [{category}]  source={source}  time={stamp}")
        else:
            o.add(paint('  No usable live temperature or power measurement was obtained; check hardware/driver/permission status with --diagnostics.', "dim"))
        if provider_status:
            status_text = f"  Sensor provider: {provider_status.get('status', 'unknown')}"
            if provider_status.get("backend"):
                status_text += f" ({provider_status['backend']})"
            o.add(paint(status_text, "dim"))
            details = provider_status.get("details")
            if details:
                o.add(paint(f"  Details: {details}", "dim"))
            for extra_provider in provider_status.get("additional_providers") or []:
                extra_name = extra_provider.get("backend") or 'Additional provider'
                extra_state = extra_provider.get("status", "unknown")
                extra_details = extra_provider.get("details") or f"temperature={extra_provider.get('temperature_count', 0)}"
                o.add(paint(f"  Additional sensor provider: {extra_name} / {extra_state} — {extra_details}", "dim"))
            for message in (provider_status.get("messages") or [])[-3:]:
                o.add(paint(f"  Provider note: {message}", "dim"))
    _guard('6. Network / processes', _s6)
    def _s7():
        o.h1('7. IDLE AND AVAILABLE CAPACITY')
        best = Gp.get("best")
        rows = [["CPU", f"{topo['logical']} thread / {topo['physical_cores']} core(s)", fmt_pct(100 - (C['free_equiv'] / C['total_equiv'] * 100) if C["total_equiv"] else None),
                 fmt_pct(C["free_equiv"] / C["total_equiv"] * 100 if C["total_equiv"] else None), f"≈ {A['budget']['recommended_workers']} worker(s) (processes)"],
                ["RAM", fmt_bytes(R["total"]), fmt_bytes(R["used"]), fmt_bytes(R["available"]), f"{fmt_bytes(R['usable_safe'])} (safe)"]]
        if best:
            rows.append(["VRAM" if not best["integrated"] else 'GPU dedicated memory', fmt_bytes(best["vram_total"]), fmt_bytes(best.get("vram_used")), fmt_bytes(best.get("vram_free")),
                         fmt_bytes(A["budget"]["vram_budget_bytes"]) if A["budget"].get("vram_budget_bytes") else "—"])
        if A["storage"]["sysvol"]:
            sv = A["storage"]["sysvol"]
            rows.append([f"Disk {sv['mount']}", fmt_bytes(sv["total"], 1), fmt_bytes(sv["used"], 1), fmt_bytes(sv["free"], 1), fmt_bytes(sv["free"] * 0.5, 1) + ' (half of free space)'])
        o.table(['Component', "Total", 'In use', 'Idle', 'Safely available'], rows, align=["<", ">", ">", ">", ">"])
        if best and best.get("integrated"):
            o.para('The integrated GPU row shows only the dedicated-memory segment. Because shared system memory is dynamic and the available GPU budget was not measured, safely available GPU memory was not calculated.', 2, "dim")
    _guard('7. Idle / available table', _s7)
    def _s8():
        o.h1('8. BALANCE, BOTTLENECKS, AND WORKLOAD SUITABILITY')
        bl = A["balance"]
        if bl:
            o.kv('Component performance scores', "  ".join(f"{k}: {v:.0f}" for k, v in bl["parts"].items()))
            o.kv('Weakest link', f"{bl['weakest']}  ({bl['parts'][bl['weakest']]:.0f}/100)")
            o.kv("Balance", ("balanced" if bl["gap"] < 25 else "moderate imbalance" if bl["gap"] < 45 else "significant imbalance") + f"  (strongest {bl['strongest']} by {bl['gap']:.0f} points)")
        o.add("")
        colors = {'Very good': "ok", "Suitable": "ok", 'Borderline': "warn", "Insufficient": "bad", 'Not measured': "dim"}
        o.table(['Workload', "Suitability", 'Limiting factor', 'Measurement scope'],
                [[w["name"], paint(w["rating"], colors[w["rating"]]), w["limit"] or "—", w.get("measurement_scope", "belirtilmedi")]
                 for w in A["workloads"]])
        o.para('Profile ratings are approximate assessments based on hardware capability; they do not guarantee a specific application version, codec, scene, or target FPS.', 2, "dim")
        upgrades = A.get("upgrades") or []
        if upgrades:
            o.h2('Prioritized upgrade recommendations')
            o.table(['Priority', 'Recommendation', "Reason", 'Expected potential benefit', 'Confidence'],
                    [[i + 1, u["title"], u["reason"], u["expected_benefit"], u["confidence"]] for i, u in enumerate(upgrades[:6])])
    _guard('8. Balance & workloads', _s8)
    def _s9():
        o.h1('9. FINDINGS AND RECOMMENDATIONS (ranked by impact)')
        if not A["findings"]:
            o.item("ok", 'No significant issues were detected.')
        for f_ in A["findings"]:
            o.item(f_["level"], f"[{f_['area']}] {f_['title']}")
            if f_["detail"]:
                o.para(f_["detail"], 6)
            if f_["action"]:
                o.para("→ " + f_["action"], 6, "info")
    _guard("9. Bulgular", _s9)
    def _s10():
        Bd = A["budget"]
        o.h1('10. RESOURCE BUDGET (other programs can safely use these values)')
        o.kv('Recommended parallel workers', f"{Bd['recommended_workers']} ({Bd.get('worker_recommendation_status', 'status unknown')})")
        o.kv('Safe RAM budget', f"{fmt_bytes(Bd['ram_budget_safe_bytes'])}   (agresif: {fmt_bytes(Bd['ram_budget_aggressive_bytes'])}; OS reserve {fmt_bytes(Bd['os_ram_reserve_bytes'])})")
        o.kv('Recommended data chunk', fmt_bytes(Bd["suggested_chunk_bytes"], 0))
        o.kv('VRAM budget', fmt_bytes(Bd["vram_budget_bytes"]) if Bd.get("vram_budget_bytes") else None)
        o.kv('Temporary disk budget', f"{fmt_bytes(Bd.get('temp_budget_bytes'))}  ({Bd.get('temp_dir')})" if Bd.get("temp_budget_bytes") else None)
        if "max_workers_by_ram" in Bd:
            o.kv('Maximum workers based on RAM', Bd["max_workers_by_ram"])
    _guard('10. Resource budget', _s10)
    def _s_quality():
        q = A.get("quality") or {}
        h = A.get("health") or {}
        o.h1('11. DATA QUALITY AND HARDWARE HEALTH')
        o.kv('Analysis data coverage', f"{q.get('score', 0):.1f}/100 ({q.get('passed', 0)}/{q.get('total', 0)} kontrol mevcut)")
        o.para(q.get("note") or "", 2, "dim")
        if q.get("missing"):
            o.kv('Missing / unmeasured checks', ", ".join(q["missing"]))
        o.kv('Hardware health indicator', f"{h['score']:.1f}/100" if h.get("score") is not None else 'not measured (insufficient sensor/event data)')
        o.kv('Sources used for health assessment', ", ".join(h.get("sources") or []) or "no")
        sample_meta = h.get("sensor_sampling") or {}
        sample_text = (f"{sample_meta.get('sample_count', 0)} records · "
                       f"{sample_meta.get('first_timestamp') or '—'} → {sample_meta.get('last_timestamp') or '—'}")
        if sample_meta.get("duration_s") is not None:
            sample_text += f" · sampling window={sample_meta['duration_s']:.1f} s"
        if sample_meta.get("sample_span_s") is not None:
            sample_text += f" · first/last sample interval={sample_meta['sample_span_s']:.1f} s"
        if sample_meta.get("requested_interval_s") is not None:
            sample_text += f" · requested interval={sample_meta['requested_interval_s']:.2f} s"
        if sample_meta.get("observed_interval_median_s") is not None:
            sample_text += f" · observed median interval={sample_meta['observed_interval_median_s']:.2f} s"
        if sample_meta.get("observed_interval_max_s") is not None:
            sample_text += f" · longest interval={sample_meta['observed_interval_max_s']:.2f} s"
        if sample_meta.get("provider_startup_s") is not None:
            sample_text += f" · provider readiness={sample_meta['provider_startup_s']:.1f} s"
        if sample_meta.get("status") is not None:
            sample_text += f" · status={sample_meta['status']}"
        if sample_meta.get("window_complete") is not None:
            sample_text += f" · window complete={bool(sample_meta['window_complete'])}"
        o.kv('Timestamped sensor samples', sample_text)
        o.kv('Temperature sensor count', len(h.get("temperature_sensors") or []))
        temperature_summary = h.get("temperature_summary") or {}
        if temperature_summary.get("sample_count"):
            summary_text = (f"{temperature_summary.get('min_c'):.1f} / {temperature_summary.get('mean_c'):.1f} / "
                            f"{temperature_summary.get('max_c'):.1f} °C · {temperature_summary.get('sample_count')} observation(s)")
            summary_phase_counts = temperature_summary.get("sample_counts_by_phase") or {}
            if summary_phase_counts:
                phase_text = ", ".join(f"{phase}={count}" for phase, count in sorted(summary_phase_counts.items()))
                summary_text += f" (phase distribution: {phase_text})"
            suppressed = int(temperature_summary.get("duplicate_source_observations_suppressed") or 0)
            if suppressed:
                summary_text += f" · {suppressed} matching component/channel observation(s) from different sources counted once in the overall total"
            o.kv('All temperature observations (min / avg / max)', summary_text)
        for t in (h.get("temperature_sensors") or [])[:12]:
            stats_text = (f"min {t.get('min_c', t.get('value_c')):.1f} / avg. {t.get('mean_c', t.get('value_c')):.1f} / "
                          f"max {t.get('max_c', t.get('value_c')):.1f} °C · n={t.get('sample_count', 1)}")
            sensor_phase_counts = t.get("sample_counts_by_phase") or {}
            if sensor_phase_counts:
                phase_text = ", ".join(f"{phase}={count}" for phase, count in sorted(sensor_phase_counts.items()))
                stats_text += f" (phase distribution: {phase_text})"
            stats_text += f" · type={t.get('hardware_type', 'Unknown')} · source={', '.join(t.get('sources') or []) or 'unknown'}"
            if t.get("component_identifier"):
                stats_text += f" · component key={t['component_identifier']}"
            if t.get("sensor_identifier"):
                stats_text += f" · sensor ID={t['sensor_identifier']}"
            stats_text += f" · time={t.get('first_timestamp') or '—'} → {t.get('last_timestamp') or '—'}"
            o.kv(f"Temperature: {_display_label(t.get('parent', ''), 22)} {t.get('name')}", stats_text)
        metrics = [m for m in (h.get("telemetry_metrics") or []) if m.get("metric") != "temperature"]
        if metrics:
            o.h2('Power / fan / clock telemetry (when supported by sensors)')
            o.table(['Component', "Metrik", 'Value', 'Observed stage', 'Sample'],
                    [[f"{m.get('parent')} {m.get('name')}", m.get("metric"), f"{m.get('value'):.1f} {m.get('unit')}",
                      m.get("phase") or ", ".join(m.get("phases") or []), m.get("sample_count", 1)] for m in metrics[:20]])
        aborts = h.get("safety_abort") or {}
        if aborts.get("cpu") or aborts.get("gpu"):
            o.item("bad", 'Load test stopped due to a thermal threshold: ' + ", ".join(k.upper() for k, v in aborts.items() if v))
    _guard('11. Data quality and hardware health', _s_quality)
    def _s11():
        o.h1('12. CONCLUSION: HOW CAPABLE IS THE SYSTEM, AND HOW EFFICIENTLY CAN IT BE USED?')
        _score_line(o, 'PERFORMANCE (hardware capability)', S["power"], power_tier(S["power"]))
        _score_line(o, 'AVAILABILITY (currently idle)', S["availability"])
        _score_line(o, 'EFFICIENCY (potential/measured)', S["efficiency"], '(partial data)' if S.get("efficiency_partial") else "")
        _score_line(o, 'EFFECTIVE USABLE PERFORMANCE', S["effective"])
        o.add("")
        for ln in A["verdict"]:
            o.para(ln, 2)
        o.h2('Score rationale')
        for title, rows in (('Performance', [{"name": k, "value": v, "weight": 0, "note": ""} for k, v in S["power_parts"].items()]),
                            ('Availability', S["avail_comp"]), ("Efficiency", S["eff_comp"])):
            o.add(f"    {paint(title, 'bold')}")
            for r in rows:
                o.add(f"      {r['name']:<28} {sc(r['value'])}" + (f"  (weight {r['weight']:.2f})" if r["weight"] else "") + f"  {r.get('note') or ''}")
        for part, title in (("CPU", 'CPU efficiency details'), ("RAM", 'RAM efficiency details')):
            if S["eff_sub"][part]["rows"]:
                o.add(f"    {paint(title, 'bold')}")
                for r in S["eff_sub"][part]["rows"]:
                    o.add(f"      {r['name']:<28} {sc(r['value'])}  {r.get('note') or ''}")
        top = [f_ for f_ in A["findings"] if f_["level"] in ("bad", "warn") and f_["action"]][:3]
        if top:
            o.h2('Highest-impact first steps')
            for i, f_ in enumerate(top, 1):
                o.para(f"{i}. {f_['title']} — {f_['action']}", 4)
    _guard('12. Conclusion', _s11)
    def _s12():
        o.h2('Methodology and limitations')
        for t in ('Performance = measured/detected hardware capability; Availability = unused capacity at measurement time; Efficiency = how much of the hardware potential is achieved after software/configuration losses. Score thresholds are heuristic; component evidence is listed above.',
                  'Frequency/IPC metrics rely on counters exposed by the tools and synthetic workloads; when no hardware retired-instruction counter is available, IPC must not be interpreted as actual application IPC.',
                  'The standard GPU score may use theoretical specifications. --gpu-bench runs an optional PyTorch CUDA FP32 matrix test; it is not a direct proxy for gaming, video encoding, or all GPU workloads.',
                  'SMART/thermal/Windows event fields depend on hardware, drivers, permissions, and sensor support; missing data is normal and data coverage is shown separately.',
                  '--memory-test-mb is only a limited, page-sampled smoke test; it does not verify full RAM stability or ECC error correction.',
                  '--network-test is based on ping/DNS; --network-speed-test estimates bandwidth using a small Cloudflare download/upload transfer. This data is sent to an external service and may vary by provider.'):
            o.para("• " + t, 2, "dim")
        if meta.get("sources"):
            o.h2('Data sources (diagnostics)')
            for name, status in meta["sources"]:
                o.kv(name, status, ind=4, kw=26)
        if WARNINGS:
            o.h2('Unavailable data (debugging)')
            for w in WARNINGS[:25]:
                o.para("• " + w, 2, "dim")
    _guard("Notlar", _s12)
    comparison = A.get("comparison")
    if comparison:
        o.h1('13. COMPARISON WITH PREVIOUS REPORT')
        o.kv('Previous / current measurement', f"{comparison.get('previous_timestamp') or 'tarih no'} / {comparison.get('current_timestamp') or meta.get('timestamp')}")
        o.kv('Previous / current mode', f"{comparison.get('previous_mode') or 'unknown'} / {comparison.get('current_mode') or meta.get('mode')}")
        metrics = comparison.get("metrics") or []
        o.table(["Metrik", 'Previous', 'Current', "Fark", "Fark %"],
                [[m["label"], f1(m.get("previous"), 2) + (f" {m['unit']}" if m.get("previous") is not None else ""),
                  f1(m.get("current"), 2) + (f" {m['unit']}" if m.get("current") is not None else ""),
                  f1(m.get("delta"), 2) + (f" {m['unit']}" if m.get("delta") is not None else "—"),
                  f1(m.get("delta_pct"), 1) + "%" if m.get("delta_pct") is not None else "—"] for m in metrics])
        changes = comparison.get("hardware_changes") or []
        if changes:
            o.h2('Detected hardware / platform changes')
            o.table(["Alan", 'Previous', 'Current'], [[c["item"], str(c.get("previous") or "—"), str(c.get("current") or "—")] for c in changes])
        else:
            o.kv('Hardware / platform difference', 'No changes were detected in the compared fields')
        version_tracking = comparison.get("driver_firmware_changes") or {}
        version_changes = version_tracking.get("changes") or []
        if version_changes:
            o.h2('Driver / firmware change tracking')
            o.table(["Status", 'Device', "Kategori", 'Previous', 'Current', 'Identity confidence'],
                    [[item.get("status"), item.get("name"), item.get("category"),
                      (item.get("fields") or {}).get("version", {}).get("previous", "—"),
                      (item.get("fields") or {}).get("version", {}).get("current", "—"),
                      item.get("identity_confidence")] for item in version_changes[:40]])
        o.para(version_tracking.get("note") or "", 2, "dim")
        history = comparison.get("health_history") or {}
        deltas = history.get("metric_deltas") or []
        if deltas:
            o.h2('Hardware health history / telemetry changes')
            o.table(["Metrik", 'Previous', 'Current', "Fark"],
                    [[row["label"], f1(row.get("previous"), 2) + (f" {row['unit']}" if row.get("previous") is not None else ""),
                      f1(row.get("current"), 2) + (f" {row['unit']}" if row.get("current") is not None else ""),
                      f1(row.get("delta"), 2) + (f" {row['unit']}" if row.get("delta") is not None else "—")] for row in deltas])
        disk_changes = history.get("disk_changes") or []
        if disk_changes:
            o.h2('Disk health history changes')
            for disk_change in disk_changes[:12]:
                o.para(f"• {disk_change.get('name')}: {disk_change.get('status')} — {json.dumps(disk_change.get('fields') or {}, ensure_ascii=False, default=str)}", 4)
        battery_changes = history.get("battery_changes") or []
        if battery_changes:
            o.h2('Battery capacity / cycle history changes')
            for battery_change in battery_changes[:8]:
                o.para(f"• {battery_change.get('name')}: {json.dumps(battery_change.get('fields') or {}, ensure_ascii=False, default=str)}", 4)
        o.para(history.get("note") or "", 2, "dim")
        o.para(comparison.get("note") or "", 2, "dim")
    health_series = A.get("health_history_series")
    if health_series:
        o.h1('HEALTH HISTORY / MULTI-REPORT TIME SERIES')
        o.kv('Source folder', health_series.get("directory"))
        o.kv('Previous report count', health_series.get("report_count", 0))
        health_rows = []
        benchmark_rows = []
        for entry in health_series.get("reports", []):
            bench = entry.get("benchmark_values") or {}
            timestamp = 'CURRENT' if entry.get("is_current") else (entry.get("timestamp") or "date unavailable")
            health_rows.append([timestamp, f1(entry.get("temperature_peak_c"), 1),
                                f1(entry.get("gpu_power_peak_w"), 1), f1(entry.get("cpu_usage_mean_pct"), 1),
                                f1(entry.get("memory_usage_mean_pct"), 1), f1(entry.get("disk_read_mib"), 1),
                                f1(entry.get("disk_write_mib"), 1), str(entry.get("disk_count", 0))])
            benchmark_rows.append([timestamp, f1(bench.get("cpu_single_core_ops"), 0),
                                   f1(bench.get("cpu_multi_core_gflops"), 2), f1(bench.get("memory_copy_gbs"), 2),
                                   f1(bench.get("disk_read_mbs"), 1), f1(bench.get("disk_write_mbs"), 1),
                                   f1(bench.get("gpu_gflops"), 1)])
        if health_rows:
            o.h2('Health and utilization trends')
            o.table(["Time", "Peak °C", "GPU W", "CPU avg. %", "RAM avg. %", "Disk R MiB", "Disk W MiB", 'Disk records'], health_rows)
        if benchmark_rows:
            o.h2("Benchmark time series")
            o.table(["Time", "CPU op/s", "CPU GFLOPS", "RAM GB/s", "Disk R MB/s", "Disk W MB/s", "GPU GFLOPS"], benchmark_rows)
        disk_rows = []
        for entry in health_series.get("reports", []):
            when = 'CURRENT' if entry.get("is_current") else (entry.get("timestamp") or "date unavailable")
            for disk in entry.get("disk_health") or []:
                disk_rows.append([when, disk.get("name") or "Unknown disk", disk.get("health") or "—",
                                  f1(disk.get("temperature_c"), 1), f1(disk.get("wear_pct"), 1),
                                  f1(disk.get("power_on_hours"), 0), f1(disk.get("uncorrected_errors"), 0)])
        if disk_rows:
            o.h2('Disk health time series')
            o.table(["Time", "Disk", 'Health', 'Temperature °C', 'Wear %', 'Power-on hours', 'Uncorrectable errors'], disk_rows[:100])
        battery_rows = []
        for entry in health_series.get("reports", []):
            when = 'CURRENT' if entry.get("is_current") else (entry.get("timestamp") or "date unavailable")
            for battery in entry.get("battery_health") or []:
                battery_rows.append([when, battery.get("name") or "Battery",
                                     f1(battery.get("health_pct"), 1), f1(battery.get("wear_pct"), 1),
                                     f1(battery.get("cycle_count"), 0),
                                     f1(battery.get("full_charge_capacity_mwh"), 0)])
        if battery_rows:
            o.h2('Battery capacity and cycle time series')
            o.table(["Time", "Battery", 'Health %', 'Wear %', 'Cycles', 'Full-charge capacity (mWh)'], battery_rows[:100])
        if health_series.get("skipped_files"):
            o.kv('Skipped malformed JSON file', len(health_series["skipped_files"]))
        o.para(health_series.get("note") or "", 2, "dim")
    inv = data.get("inventory") or {}
    def _inventory_section():
        o.h1('14. COMPLETE HARDWARE INVENTORY (CPU / GPU / RAM SLOTS / STORAGE)')
        plat = inv.get("platform") or {}
        arch = plat.get("machine") or {}
        o.kv("Platform", f"{plat.get('system') or platform.system()} {plat.get('release') or platform.release()}")
        if isinstance(arch, dict):
            o.kv('Processor architecture', f"{arch.get('canonical') or arch.get('reported')} ({arch.get('family') or 'family unknown'})")
        else:
            o.kv('Processor architecture', str(arch))
        o.kv('Collection duration', f"{inv.get('collection_duration_s')} s" if inv.get("collection_duration_s") is not None else None)
        board = inv.get("motherboard") or {}
        bios = board.get("bios") or {}
        board_name = " ".join(str(x) for x in (board.get("manufacturer") or board.get("Manufacturer"),
                            board.get("product") or board.get("Product"), board.get("version") or board.get("Version")) if x)
        o.h2("Motherboard, system, and firmware")
        o.kv("Motherboard", board_name or 'Not reported by firmware/OS')
        o.kv("BIOS/UEFI", " ".join(str(x) for x in (bios.get("vendor") or bios.get("Manufacturer"),
                            bios.get("version") or bios.get("SMBIOSBIOSVersion") or bios.get("Version"),
                            format_report_date(bios.get("release_date") or bios.get("ReleaseDate"))
                            if (bios.get("release_date") or bios.get("ReleaseDate")) else None) if x) or None)
        system_info = board.get("system") or {}
        o.kv("System model", " ".join(str(x) for x in (system_info.get("manufacturer") or system_info.get("Manufacturer"),
                            system_info.get("product") or system_info.get("Product") or system_info.get("Model")) if x) or None)
        cpu_inv = inv.get("cpu") or {}
        o.h2('CPU and processor architecture')
        o.kv('CPU summary', f"{cpu_inv.get('vendor') or 'Unknown manufacturer'} — {cpu_inv.get('name') or 'Model not reported'}")
        o.kv('Cores / logical processors', f"{cpu_inv.get('physical_cores') or '—'} / {cpu_inv.get('logical_processors') or '—'}")
        cpu_rows = []
        for proc in cpu_inv.get("processors") or []:
            proc_arch = proc.get("architecture") or {}
            proc_arch_text = proc_arch.get("canonical") if isinstance(proc_arch, dict) else str(proc_arch)
            cpu_rows.append([proc.get("socket") or "—", proc.get("vendor") or "—", proc.get("name") or "—",
                             f"{proc.get('cores') or '—'} / {proc.get('logical_processors') or '—'}",
                             f"{proc.get('max_clock_mhz'):.0f} MHz" if _is_finite_measurement(proc.get("max_clock_mhz")) else "—",
                             proc_arch_text or "—", proc.get("source") or "—"])
        if cpu_rows:
            o.table(["Socket", 'Manufacturer', 'Processor', 'Cores/threads', "Maximum clock", "Architecture", "Source"], cpu_rows)
        features = cpu_inv.get("feature_flags") or []
        o.kv('Detected ISA features', ", ".join(features[:100]) + (f" … (+{len(features)-100})" if len(features) > 100 else "") if features else 'Not reported by the source')
        gpu_inv = inv.get("gpu") or {}
        gpu_rows = []
        for gpu in gpu_inv.get("adapters") or []:
            vram = gpu.get("dedicated_memory_bytes")
            integrated = 'Integrated' if gpu.get("integrated") is True else 'Discrete' if gpu.get("integrated") is False else "Unknown"
            if gpu.get("virtual"):
                integrated = 'Virtual/software-based'
            gpu_rows.append([gpu.get("vendor") or "Unknown", gpu.get("name") or "Unknown GPU", integrated,
                             fmt_bytes(vram, 1) if vram is not None else "—", gpu.get("dedicated_memory_source") or "—",
                             (f"{gpu.get('vendor_id'):04X}:{gpu.get('device_id'):04X}" if isinstance(gpu.get("vendor_id"), int) and isinstance(gpu.get("device_id"), int) else "—"),
                             gpu.get("driver_version") or "—", ", ".join(gpu.get("sources") or [gpu.get("source") or "—"])])
        o.h2('All graphics adapters (discrete, integrated, and virtual) ')
        if gpu_rows:
            o.table(['Manufacturer', "GPU", 'Class', 'Dedicated memory', 'VRAM source', "PCI ID", 'Driver', "Source(s)"], gpu_rows)
        else:
            o.para('The operating system did not return a visible GPU list; this does not mean that no physical GPU is present.', 4, "dim")
        onboard = gpu_inv.get("onboard_devices") or []
        if onboard:
            o.h2('On-board devices reported by SMBIOS')
            o.table(['Device', 'Type', "Enabled", "Source"], [[x.get("name") or "—", x.get("device_type") or x.get("device_type_code") or "—",
                "Yes" if x.get("enabled") is True else 'No' if x.get("enabled") is False else "Unknown", x.get("source") or "—"] for x in onboard])
        mem_inv = inv.get("memory") or {}
        o.h2('RAM modules and motherboard memory slots')
        o.kv('RAM visible to the operating system', fmt_bytes(mem_inv.get("os_total_physical_bytes"), 1) if mem_inv.get("os_total_physical_bytes") else None)
        o.kv('Module total (from firmware records)', fmt_bytes(mem_inv.get("installed_bytes_from_modules"), 1) if mem_inv.get("installed_bytes_from_modules") else None)
        o.kv('Slots: reported / populated / empty / location unknown',
             f"{mem_inv.get('reported_slot_count') if mem_inv.get('reported_slot_count') is not None else '—'} / {mem_inv.get('populated_slot_count', 0)} / {mem_inv.get('empty_slot_count', 0)} / {mem_inv.get('unlocated_slot_count', 0)}")
        o.kv('Slot-count confidence', mem_inv.get("slot_count_confidence"))
        o.kv('Memory types', ", ".join(mem_inv.get("memory_types_seen") or []) or 'Not reported by firmware')
        arrays = mem_inv.get("arrays") or []
        if arrays:
            o.table(["Memory array", "Slot count", "Maximum capacity", 'Usage', 'Error correction', "Source"],
                [[x.get("location") or "—", x.get("memory_devices_reported") or "—", fmt_bytes(x.get("max_capacity_bytes"), 1) if x.get("max_capacity_bytes") else "—",
                  x.get("use") or "—", x.get("error_correction") or x.get("error_correction_code") or "—", x.get("source") or "—"] for x in arrays])
        slots = mem_inv.get("slots") or []
        if slots:
            o.table(["Slot/locator", "Status", "Capacity", 'Type', "Raw type code", 'Form factor', 'MT/s (current)', 'Manufacturer', 'Part number', "Source"],
                [[x.get("locator") or x.get("bank_locator") or "—",
                  {"installed": "Populated", "empty": 'Free', "unknown": "Unknown", "not_reported_by_firmware": 'Name not available in firmware'}.get(x.get("state"), x.get("state") or "—"),
                  fmt_bytes(x.get("size_bytes"), 1) if x.get("size_bytes") is not None and x.get("size_bytes") > 0 else ("0" if x.get("size_bytes") == 0 else "—"),
                  x.get("memory_type") or "—",
                  (f"SMBIOS 0x{x.get('memory_type_code'):02X}" if isinstance(x.get("memory_type_code"), int) else
                   f"WMI {x.get('wmi_memory_type_code')}" if isinstance(x.get("wmi_memory_type_code"), int) else "—"),
                  x.get("form_factor") or "—",
                  str(x.get("configured_speed_mts") or x.get("speed_mts") or "—"), x.get("manufacturer") or "—", x.get("part_number") or "—",
                  ", ".join(x.get("sources") or [x.get("source") or "—"]) ] for x in slots])
        else:
            o.para('Physical slot/module details are not exposed by this platform firmware interface. Total OS-visible memory is measured separately.', 4, "dim")
        storage_inv = inv.get("storage") or {}
        devices = storage_inv.get("devices") or []
        o.h2('All storage devices and controllers')
        o.kv('Physical/virtual device count', len(devices))
        if devices:
            o.table(['Device', 'Type', 'Interface/bus', "Capacity", "Status", 'Device path', 'Health', "Source"],
                [[x.get("name") or x.get("model") or 'Unknown device', x.get("kind") or 'Unknown type', x.get("bus") or x.get("transport") or "—",
                  fmt_bytes(x.get("size_bytes"), 1) if x.get("size_bytes") is not None else "—", x.get("status") or "—",
                  x.get("device_path") or x.get("device_id") or "—",
                  (f"SMART={'PASS' if (x.get('smart') or {}).get('smart_passed') is True else 'FAIL' if (x.get('smart') or {}).get('smart_passed') is False else '—'}" +
                   (f" , temperature {(x.get('smart') or {}).get('temperature_c')}°C" if (x.get('smart') or {}).get('temperature_c') is not None else "") +
                   (f", wear %{(x.get('smart') or {}).get('percentage_used')}" if (x.get('smart') or {}).get('percentage_used') is not None else "")) if x.get("smart") else "—", x.get("source") or "—"] for x in devices])
        pools = storage_inv.get("pools") or []
        if pools:
            o.h2('Storage pools / Storage Spaces')
            o.table(["Pool", "ID", "Physical disk", "Capacity", 'Reserved', "Status", "Source"],
                [[x.get("name") or "—", x.get("pool_id") or "—",
                  str(x.get("physical_disk_count")) if x.get("physical_disk_count") is not None else "—",
                  fmt_bytes(x.get("size_bytes"), 1) if x.get("size_bytes") is not None else "—",
                  fmt_bytes(x.get("allocated_bytes"), 1) if x.get("allocated_bytes") is not None else "—",
                  x.get("status") or "—", x.get("source") or "—"] for x in pools])
        controllers = storage_inv.get("controllers") or []
        if controllers:
            o.h2("Storage controllers")
            o.table(["Controller", 'Manufacturer', 'Class', 'Driver', "Status", "Source"],
                [[x.get("name") or "—", x.get("manufacturer") or x.get("vendor") or "—", x.get("class") or "—",
                  x.get("driver") or "—", x.get("status") or "—", x.get("source") or "—"] for x in controllers])
        volumes = storage_inv.get("volumes") or []
        if volumes:
            o.h2('Volume / mount-point mapping')
            o.table(['Volume/mount point', "Label", "File system", "Size", 'Free', 'Device', "Source"],
                [[x.get("mount") or "—", x.get("label") or "—", x.get("filesystem") or "—",
                  fmt_bytes(x.get("size_bytes"), 1) if x.get("size_bytes") is not None else "—",
                  fmt_bytes(x.get("free_bytes"), 1) if x.get("free_bytes") is not None else "—",
                  x.get("device") or x.get("device_id") or "—", x.get("source") or "—"] for x in volumes])
        partitions = storage_inv.get("partitions") or []
        if partitions:
            o.h2('All partitions and child devices')
            o.table(['Partition/device', 'Parent disk', "Size", "File system", 'Partition type', "UUID/GUID", 'Mount point', "Source"],
                [[x.get("name") or x.get("device_path") or x.get("drive_letter") or "—",
                  x.get("parent_disk") or (f"disk {x.get('disk_number')}" if x.get("disk_number") is not None else "—"),
                  fmt_bytes(x.get("size_bytes"), 1) if x.get("size_bytes") is not None else "—",
                  x.get("filesystem") or "—", x.get("partition_type") or x.get("gpt_type") or x.get("partition_label") or "—",
                  x.get("partition_uuid") or x.get("guid") or x.get("uuid") or "—",
                  ", ".join(x.get("mountpoints") or []) or x.get("drive_letter") or "—", x.get("source") or "—"] for x in partitions])
        sys_slots = inv.get("system_slots") or []
        if sys_slots:
            o.h2('Motherboard expansion slots (separate from RAM slots)')
            o.table(["Slot", 'Type', 'Usage', "Bus/segment", "Source"],
                [[x.get("name") or "—", x.get("slot_type") or x.get("slot_type_code") or "—", x.get("usage") or "—",
                  ":".join(str(v) for v in (x.get("segment"), x.get("bus"), x.get("device_function")) if v is not None) or x.get("bus_address") or "—",
                  x.get("source") or "—"] for x in sys_slots])
        source_rows = [[x.get("name") or "—", x.get("status") or "—", x.get("detail") or "—", x.get("count") if x.get("count") is not None else "—"] for x in inv.get("sources") or []]
        if source_rows:
            o.h2('Inventory sources and coverage status')
            o.table(["Source", "Status", 'Description', 'Record'], source_rows)
        for limitation in inv.get("limitations") or []:
            o.para("• " + str(limitation), 2, "dim")
    _guard('Full hardware inventory', _inventory_section)
    profiles = A.get("workload_profiles") or []
    if profiles:
        o.h1('WORKLOAD PROFILES / ACTUAL BENCHMARK COVERAGE')
        o.table(["Profile", "Suitability (heuristic)", 'Measurement scope', 'Actual measurement'],
                [[item.get("name"), item.get("suitability"), item.get("measurement_status"),
                  "; ".join(f"{m.get('name')}: {f1(m.get('value'), 2)} {m.get('unit')}" for m in item.get("benchmark_metrics", []) if m.get("measured")) or 'not measured']
                 for item in profiles])
        for item in profiles:
            if item.get("encoder_results"):
                o.kv("FFmpeg encoder", "; ".join(f"{row.get('encoder')}: {f1(row.get('fps'), 1)} FPS" for row in item["encoder_results"]))
            o.para(item.get("limitations") or "", 2, "dim")
    alerts = A.get("alerts") or {}
    o.h1('SMART HEALTH ALERTS')
    o.kv('Alert count', f"{alerts.get('count', 0)} (critical {alerts.get('critical_count', 0)} / warning {alerts.get('warning_count', 0)})")
    for alert in as_list(alerts.get("items"))[:30]:
        if isinstance(alert, dict):
            o.item(alert.get("severity") or "info", f"{alert.get('title')}: {alert.get('detail')} [Source: {alert.get('source')}]")
    o.para(alerts.get("note") or "", 2, "dim")
    return o.text()
def collect_memory_dynamic() -> dict:
    vm, sw = psutil.virtual_memory(), psutil.swap_memory()
    d = {"total": vm.total, "available": vm.available, "percent": vm.percent,
         "swap_total": sw.total, "swap_used": sw.used, "swap_percent": sw.percent}
    if IS_WIN:
        d.update(safe("GetPerformanceInfo", perf_info, default={}))
    for p in psutil.process_iter(["name", "memory_info"]):
        if p.info.get("name") == "Memory Compression" and p.info.get("memory_info"):
            d["compressed"] = p.info["memory_info"].rss
            break
    return d
def normalize_windows_storage_reliability(rows) -> list[dict]:
    normalized = []
    for raw in as_list(rows):
        if not isinstance(raw, dict):
            continue
        item = dict(raw)
        temperature = item.get("Temperature")
        try:
            temperature = float(temperature) if temperature is not None and not isinstance(temperature, bool) else None
        except (TypeError, ValueError, OverflowError):
            temperature = None
        if temperature is None or not math.isfinite(temperature) or not (0.0 < temperature <= 200.0):
            item["Temperature"] = None
        else:
            item["Temperature"] = temperature
        item["source"] = "Windows Storage Reliability"
        item["source_type"] = "OS_STORAGE_RELIABILITY"
        normalized.append(item)
    return normalized
def refresh_nvml(gpu: dict) -> None:
    'Refreshes NVML live values (clock, power, temperature, utilization) after the static query.'
    live = nvml_live()
    for g in gpu.get("gpus", []):
        nv = g.get("nvml")
        if nv:
            match = next((d for d in live if d.get("index") == nv.get("index") and d.get("name") == nv.get("name")), None)
            if match:
                g["nvml"] = match
def _is_finite_measurement(value: Any) -> bool:
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and math.isfinite(float(value)))
def summarize_repeated_values(values) -> dict:
    'Summarizes numeric measurement repeats; missing/failed repeats are not counted.'
    xs = [float(v) for v in values if _is_finite_measurement(v)]
    if not xs:
        return {"count": 0, "min": None, "max": None, "mean": None, "median": None, "stdev": None, "cv_pct": None}
    mean = statistics.fmean(xs)
    stdev = statistics.stdev(xs) if len(xs) > 1 else 0.0
    return {"count": len(xs), "min": min(xs), "max": max(xs), "mean": mean,
            "median": statistics.median(xs), "stdev": stdev, "cv_pct": stdev / mean * 100 if mean else None}
def evaluate_benchmark_reliability(cpu_runs, warmup_count: int, ambient_cpu_pct: float | None) -> dict:
    metric_specs = [
        ('CPU single-core Python', "py.single_p.ops", 'operations/sec'),
        ('CPU multi-core FP64', "gemm.float64.all_phys.gflops", "GFLOPS"),
    ]
    metric_results = []
    warnings = []
    measured_runs = [row for row in cpu_runs if isinstance(row, dict) and not row.get("error") and any(
        _is_finite_measurement(dig(row, path))
        for _, path, _ in metric_specs)]
    for label, path, unit in metric_specs:
        values = [dig(row, path) for row in measured_runs]
        summary = summarize_repeated_values(values)
        metric_results.append({"label": label, "path": path, "unit": unit,
                               "values": [v for v in values if _is_finite_measurement(v)],
                               "summary": summary})
        if summary["count"] >= 2 and summary.get("cv_pct") is not None and summary["cv_pct"] >= 5:
            warnings.append(f"{label}: repeat variability %{summary['cv_pct']:.1f}; background load, power/thermal limits, or frequency scaling may affect the result.")
    if warmup_count <= 0:
        warnings.append('No warm-up run was performed; the first measurement may be affected by cold-start behavior.')
    if len(measured_runs) < 2:
        warnings.append('At least 2 successful measurements are recommended for a reliable distribution assessment; the current repeat count is limited.')
    if ambient_cpu_pct is not None and ambient_cpu_pct >= 20:
        warnings.append(f"CPU utilization before the benchmark %{ambient_cpu_pct:.1f}; background load may reduce comparability.")
    return {"warmup_count": int(warmup_count), "repeat_count": len(cpu_runs),
            "successful_repeat_count": len(measured_runs), "ambient_cpu_percent": ambient_cpu_pct,
            "metrics": metric_results, "warnings": warnings,
            "status": "insufficient_data" if not any(m["summary"]["count"] for m in metric_results)
                      else "review" if warnings else "acceptable",
            "scope_note": 'Distribution is calculated only for reported CPU sub-measurements; if GPU, memory, and disk were run once, their repeatability is not verified.'}
def _cpu_default() -> dict:
    return {"name": "", "vendor": "", "family": None, "model": None, "stepping": None, "reg_mhz": None,
            "topology": topology_fallback(psutil), "os_features": {}, "ntpower": [], "smbios": {}}
def collect_all(mode="standard", no_jit=False, no_disk=False, disk_path=None, disk_mb=None, serials=False, say=log,
                network_test=False, network_speed_test=False, network_host="1.1.1.1", dns_host="example.com", gpu_bench=False,
                gpu_bench_seconds=2.0, memory_test_mb=0, memory_test_passes=2, bench_repeats=1,
                encoder_bench=False, encoder_bench_seconds=3.0, storage_health_probe=False,
                bench_warmups=1, sensor_sampling=False, sensor_duration_s=30.0, sensor_interval_s=1.0) -> dict:
    platform_status = supported_platform_status()
    if not platform_status["supported"]:
        raise RuntimeError(_unsupported_platform_message(platform_status))
    global _T0
    _T0 = time.perf_counter()
    WARNINGS.clear()
    if psutil is None:
        raise RuntimeError("psutil is required: pip install psutil")
    quick, deep = mode == "quick", mode == "deep"
    if memory_test_mb < 0:
        raise ValueError("memory_test_mb negatif olamaz")
    if bench_repeats < 1 or bench_repeats > 5:
        raise ValueError('bench_repeats must be between 1 and 5')
    if not 0 <= int(bench_warmups) <= 3:
        raise ValueError('bench_warmups must be between 0 and 3')
    if not 1 <= float(sensor_duration_s) <= 600:
        raise ValueError('sensor_duration_s must be between 1 and 600 seconds')
    if not 0.5 <= float(sensor_interval_s) <= 30:
        raise ValueError('sensor_interval_s must be between 0.5 and 30 seconds')
    if disk_mb is not None and not 64 <= int(disk_mb) <= 16384:
        raise ValueError('disk_mb must be between 64 and 16384 MiB')
    if mode not in ("quick", "standard", "deep"):
        raise ValueError("mode must be 'quick', 'standard', or 'deep'")
    sensor_sampler = None
    sensor_sampler_started = False
    data = {"meta": {"version": __version__, "schema_version": SCHEMA_VERSION, "mode": mode,
                     "timestamp": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                     "requested_tests": {"cpu_benchmark": not quick, "memory_bandwidth": not quick,
                                         "disk_benchmark": not quick and not no_disk, "gpu_benchmark": bool(gpu_bench),
                                         "network_test": bool(network_test or network_speed_test), "network_speed_test": bool(network_speed_test),
                                         "memory_integrity": bool(memory_test_mb),
                                         "encoder_benchmark": bool(encoder_bench),
                                         "storage_health_probe": bool(storage_health_probe),
                                         "sensor_sampling": bool(sensor_sampling),
                                         "hardware_inventory": True, "bench_repeats": bench_repeats,
                                         "bench_warmups": int(bench_warmups)},
                     "parameters": {"disk_path": disk_path, "disk_mb": disk_mb, "network_host": network_host,
                                    "dns_host": dns_host, "gpu_bench_seconds": gpu_bench_seconds,
                                    "memory_test_mb": memory_test_mb, "memory_test_passes": memory_test_passes,
                                    "encoder_bench_seconds": encoder_bench_seconds,
                                    "sensor_duration_s": float(sensor_duration_s),
                                    "sensor_interval_s": float(sensor_interval_s)}}}
    if sensor_sampling:
        sensor_sampler = SensorSampler(interval_s=sensor_interval_s, sample_gpu=True, duration_s=sensor_duration_s)
        sensor_sampler_started = sensor_sampler.start()
        if not sensor_sampler_started:
            warn('sensor sampling', RuntimeError('psutil was not found; the sampler could not be started'))
    say('Reading operating-system and platform information...')
    data["os"] = safe('operating system', collect_os, default={"system": platform.system(), "admin": is_admin(), "python": {}})
    sm = {}
    smbios_structs = []
    if IS_WIN:
        raw = safe("SMBIOS read", read_smbios_raw, default=b"")
        if raw:
            smbios_structs = safe('Decoding SMBIOS records', parse_smbios, raw, default=[]) or []
            sm = safe('SMBIOS parsing', decode_smbios, smbios_structs, default={})
    data["smbios"] = {k: sm.get(k, {}) for k in ("bios", "system", "board", "chassis")}
    say('Reading processor topology, cache, and memory modules...')
    data["cpu"] = safe("CPU information", collect_cpu_static, sm) or _cpu_default()
    data["memory"] = safe("RAM information", collect_memory_static, sm) or collect_memory_static({})
    say('Reading graphics-card information (DXGI/NVML)...')
    data["gpu"] = safe("GPU", collect_gpu_static, default={"gpus": []})
    data["network"] = safe('network', collect_network_static, default=[])
    say(f"Sampling current system load ({'2.5' if quick else '6' if deep else '4'} s; avoid using the computer during this period if possible)...")
    tele = safe('telemetry startup', Telemetry)
    try:
        data["baseline"] = (safe('live sampling', tele.baseline, 2.5 if quick else 6.0 if deep else 4.0, default={})
                            if tele else {})
    finally:
        if tele:
            tele.close()
    refresh_nvml(data["gpu"])
    say('Running PowerShell/CPUID queries...')
    with cf.ThreadPoolExecutor(max_workers=2) as ex:
        f_ci = ex.submit(lambda: safe("py-cpuinfo", collect_cpuinfo_lib))
        f_ps = ex.submit(lambda: safe("PowerShell", run_ps_batch, default={}))
        ci, ps = f_ci.result(), f_ps.result() or {}
    data["ps"] = ps
    data["os"]["battery_health"] = normalize_windows_battery_health(ps.get("battery"))
    if sensor_sampler_started:
        data["sensors"] = normalize_sensor_rows(ps.get("sensors"))
        data["sensor_provider"] = {"status": "sampling_active", "backend": None,
                                   "details": 'The live temperature provider is managed by the sampling thread.'}
    else:
        data["sensors"], data["sensor_provider"] = collect_sensor_readings(ps.get("sensors"))
    cpu = data["cpu"]
    cpu["cpuinfo"] = {k: v for k, v in (ci or {}).items() if k != "flags"}
    cpu["isa"] = isa_summary((ci or {}).get("flags"), cpu.get("os_features") or {})
    if ci and ci.get("brand_raw") and (not cpu.get("name") or cpu["name"] == platform.machine()):
        cpu["name"] = ci["brand_raw"]
    data["storage"] = safe("Storage", collect_storage_static, ps, default={"volumes": [], "disks": []})
    reliabilities = normalize_windows_storage_reliability(ps.get("disk_reliability"))
    data["storage"]["windows_storage_reliability"] = reliabilities
    for disk in data["storage"].get("disks", []):
        match = next((r for r in reliabilities if (r.get("DeviceId") is not None and str(r.get("DeviceId")) == str(disk.get("id")))
                      or (r.get("Name") and r.get("Name") == disk.get("name"))), None)
        if match:
            disk["windows_storage_reliability"] = match
    data["memory"]["dynamic"] = safe('memory (live)', collect_memory_dynamic, default={})
    say('Combining the inventory of all visible CPU/GPU/RAM slots/storage devices...')
    data["inventory"] = safe(
        'cross-platform hardware inventory', collect_hardware_inventory,
        system=platform.system(), machine=platform.machine(), smbios=sm, smbios_structs=smbios_structs,
        windows_data=ps.get("hardware_inventory") or {}, existing_cpu=data.get("cpu"),
        existing_gpu=data.get("gpu"), existing_storage=data.get("storage"),
        probe_smart=bool(storage_health_probe), default=empty_inventory(),
    )
    inventory_storage = data["inventory"].setdefault("storage", {})
    smartctl_summary = inventory_storage.get("smartctl")
    if not isinstance(smartctl_summary, dict):
        smartctl_summary = {"source": "smartctl", "source_type": "SMART",
                            "status": "not requested" if not storage_health_probe else "unavailable",
                            "device_count": 0, "devices": [], "read_only": True}
        inventory_storage["smartctl"] = smartctl_summary
    data["storage"]["smartctl"] = smartctl_summary
    bench = {}
    if not quick:
        topo = cpu["topology"]
        avail = psutil.virtual_memory().available
        try:
            ambient_cpu_pct = float(psutil.cpu_percent(interval=0.3))
        except (OSError, RuntimeError):
            ambient_cpu_pct = None
        warmup_records = []
        if avail < 512 * MIB:
            bench["cpu"] = {"error": 'benchmark skipped for safety: available RAM is below 512 MiB'}
            bench["memory"] = {"error": 'benchmark skipped for safety: available RAM is below 512 MiB'}
        else:
            worker_mem_limit = max(1, int(max(0, avail - 2 * GIB) // (100 * MIB)))
            max_workers = max(1, min(int(topo.get("logical") or 1), worker_mem_limit))
            warmup_aborted = False
            for warmup in range(int(bench_warmups)):
                say(f"CPU benchmark warm-up pass {warmup + 1}/{bench_warmups}...")
                warm_started = time.perf_counter()
                warm_result = safe('CPU benchmark warm-up', run_cpu_benchmarks, topo, mode, not no_jit, max_workers,
                                   say=lambda _message: None, sensor_sampling=bool(deep and data.get("sensors")), default={})
                warmup_records.append({"elapsed_s": round(time.perf_counter() - warm_started, 3),
                                       "safety_abort": bool(dig(warm_result, "sustained.safety_abort")),
                                       "error": warm_result.get("error") if isinstance(warm_result, dict) else 'invalid result'})
                if dig(warm_result, "sustained.safety_abort"):
                    warmup_aborted = True
                    warn("CPU benchmark", RuntimeError('thermal safety limit exceeded during warm-up; measured repetitions were skipped'))
                    break
            cpu_runs = []
            if warmup_aborted:
                cpu_runs.append({"error": 'measured benchmark skipped because the thermal safety limit was exceeded during warm-up',
                                 "sustained": {"safety_abort": True}})
            else:
                for repeat in range(bench_repeats):
                    if bench_repeats > 1:
                        say(f"CPU benchmark repetition {repeat + 1}/{bench_repeats}...")
                    run_result = safe('CPU benchmark', run_cpu_benchmarks, topo, mode, not no_jit, max_workers,
                                      say=say, sensor_sampling=bool(deep and data.get("sensors")), default={})
                    cpu_runs.append(run_result)
                    if dig(run_result, "sustained.safety_abort"):
                        say('Additional CPU benchmark repetitions were stopped due to the thermal safety threshold.')
                        break
            bench["cpu"] = dict(cpu_runs[0]) if cpu_runs else {}
            bench["cpu"]["warmup_count"] = len(warmup_records)
            bench["cpu"]["warmup_runs"] = warmup_records
            if len(cpu_runs) > 1:
                bench["cpu"]["repeat_runs"] = [dict(x) for x in cpu_runs]
                bench["cpu"]["repeat_count"] = len(cpu_runs)
                py_values = [dig(x, "py.single_p.ops") for x in cpu_runs]
                gemm_values = [dig(x, "gemm.float64.single_p.gflops") for x in cpu_runs]
                bench["cpu"]["repeatability"] = {
                    "python_single_p_ops": py_values,
                    "python_single_p_ops_summary": summarize_repeated_values(py_values),
                    "gemm_single_p_gflops": gemm_values,
                    "gemm_single_p_gflops_summary": summarize_repeated_values(gemm_values),
                }
            bench["reliability"] = evaluate_benchmark_reliability(cpu_runs, len(warmup_records), ambient_cpu_pct)
            try:
                import numpy
                have_np = True
            except ImportError:
                have_np = False
            if have_np and not no_jit and jit_supported():
                bench["latency"] = safe('latency benchmark', run_latency_benchmark, topo, mode, avail, max_workers, say=say, default={})
            say('Measuring memory bandwidth...')
            l3 = (topo["cache_summary"].get("L3") or {}).get("total") or 32 * MIB
            size = int(clamp(8 * l3, 256 * MIB, GIB))
            size = min(max(32 * MIB, min(size, int(avail * 0.2))), max(8 * MIB, int(avail * 0.2)))
            tl = sorted({t for t in (1, 2, 4, topo["physical_cores"], topo["logical"]) if 1 <= t <= topo["logical"]})
            bench["memory"] = safe('memory bandwidth', bench_memory, size, tl, 1.0 if deep else 0.5, default={})
            if not no_disk:
                say('Measuring disk speed (temporary file is deleted at the end of the test)...')
                path = disk_path or tempfile.gettempdir()
                nbytes = (disk_mb or (4096 if deep else 1024)) * MIB
                bench["disk"] = safe('disk benchmark', bench_disk, path, nbytes, 3.0 if deep else 1.5, default={})
                if bench.get("disk"):
                    target_mount = os.path.splitdrive(os.path.abspath(path))[0].upper().rstrip("\\") if IS_WIN else None
                    if not target_mount:
                        abs_test_path = os.path.realpath(os.path.abspath(path))
                        matches = []
                        for volume in (data.get("storage", {}).get("volumes") or []):
                            mount = os.path.realpath(os.path.abspath(volume.get("mount") or os.path.sep))
                            try:
                                inside = os.path.commonpath([abs_test_path, mount]) == mount
                            except ValueError:
                                inside = False
                            if inside:
                                matches.append(volume)
                        target_mount = max(matches, key=lambda v: len(os.path.realpath(os.path.abspath(v.get("mount") or os.path.sep)))).get("mount") if matches else None
                    bench["disk"]["target_mount"] = target_mount
                    target_disk = next((d for d in (data.get("storage", {}).get("disks") or [])
                                        if target_mount and target_mount.upper().rstrip("\\").startswith(tuple(x.upper() for x in (d.get("drives") or [])))), None)
                    bench["disk"]["target_disk_name"] = target_disk.get("name") if target_disk else None
                    bench["disk"]["target_disk_id"] = target_disk.get("id") if target_disk else None
        if "reliability" not in bench:
            bench["reliability"] = evaluate_benchmark_reliability([], 0, ambient_cpu_pct)
    if memory_test_mb:
        say('Running RAM sampling check...')
        bench["memory_integrity"] = safe('RAM sampling check', memory_integrity_smoke_test,
                                         memory_test_mb, memory_test_passes, default={"error": 'test could not be started'})
    if gpu_bench:
        say('GPU compute test requested; checking PyTorch CUDA availability...')
        bench["gpu"] = safe("GPU benchmark", bench_gpu_torch, gpu_bench_seconds, sensor_sampling=bool(data.get("sensors") or (data.get("gpu") or {}).get("nvml_available")), default={"available": False, "error": 'test could not be started'})
    if encoder_bench:
        say('FFmpeg synthetic video encoder test requested...')
        bench["encoder"] = safe("video encoder benchmark", bench_video_encoders, encoder_bench_seconds,
                                default={"available": False, "reason": 'test could not be started'})
    if network_test or network_speed_test:
        say(f"Running network latency/loss test: {network_host}...")
        bench["network_test"] = safe('network test', measure_network, network_host, dns_host,
                                     speed_test=network_speed_test, default={"error": 'test could not be started'})
    if gpu_bench:
        refresh_nvml(data["gpu"])
    data["bench"] = bench
    if sensor_sampling:
        if sensor_sampler_started and sensor_sampler is not None:
            say('Finalizing timestamped sensor samples collected during the analysis...')
            if sensor_sampler.wait_until_started(timeout=15.0):
                sampling_started_at = sensor_sampler.started_at
                remaining = float(sensor_duration_s) - (time.perf_counter() - sampling_started_at)
                if remaining > 0:
                    sensor_sampler.wait_until_finished(timeout=remaining)
                data["sensor_history"] = sensor_sampler.finish()
                elapsed_sampling = max(0.0, time.perf_counter() - sampling_started_at)
                elapsed_points = [float(row.get("elapsed_s")) for row in data["sensor_history"]
                                  if isinstance(row, dict) and _is_finite_measurement(row.get("elapsed_s"))]
                intervals = [b - a for a, b in zip(elapsed_points, elapsed_points[1:]) if b > a]
                window_complete = elapsed_sampling >= float(sensor_duration_s) - 0.05
                sampling_status = ("empty" if not data["sensor_history"] else
                                   "completed" if window_complete and not sensor_sampler.runtime_error and not sensor_sampler.shutdown_timed_out
                                   else "partial")
                sample_span = max(elapsed_points) - min(elapsed_points) if len(elapsed_points) >= 2 else 0.0
                data["sensor_sampling"] = {
                    "status": sampling_status,
                    "sample_count": len(data["sensor_history"]),
                    "duration_s": round(min(float(sensor_duration_s), elapsed_sampling), 3),
                    "sample_span_s": round(sample_span, 3),
                    "window_complete": bool(window_complete),
                    "requested_duration_s": float(sensor_duration_s),
                    "interval_s": float(sensor_interval_s),
                    "requested_interval_s": float(sensor_interval_s),
                    "observed_interval_median_s": round(statistics.median(intervals), 3) if intervals else None,
                    "observed_interval_max_s": round(max(intervals), 3) if intervals else None,
                    "provider_startup_s": round(sensor_sampler.startup_delay_s, 3) if sensor_sampler.startup_delay_s is not None else None,
                    "runtime_error": sensor_sampler.runtime_error,
                    "shutdown_timed_out": bool(sensor_sampler.shutdown_timed_out),
                    "scope": "provider_ready_window",
                }
                if sensor_sampler.runtime_error:
                    warn('sensor sampling runtime', RuntimeError(sensor_sampler.runtime_error))
                if sensor_sampler.shutdown_timed_out:
                    warn('sensor sampling shutdown', TimeoutError('sampler thread did not stop within 15 seconds'))
            else:
                data["sensor_history"] = sensor_sampler.finish()
                data["sensor_sampling"] = {
                    "status": "unavailable", "sample_count": len(data["sensor_history"]),
                    "reason": sensor_sampler.startup_error or 'sensor provider did not become ready within 15 seconds',
                    "requested_duration_s": float(sensor_duration_s),
                    "requested_interval_s": float(sensor_interval_s),
                    "provider_startup_s": round(sensor_sampler.startup_delay_s, 3) if sensor_sampler.startup_delay_s is not None else None,
                    "scope": "provider_ready_window",
                }
                warn('sensor sampling provider', RuntimeError(data["sensor_sampling"]["reason"]))
        else:
            data["sensor_history"] = []
            data["sensor_sampling"] = {"status": "unavailable", "sample_count": 0,
                                        "reason": 'psutil was not found; timestamped sampling could not be started',
                                        "requested_duration_s": float(sensor_duration_s),
                                        "requested_interval_s": float(sensor_interval_s),
                                        "scope": "provider_ready_window"}
    else:
        data["sensor_history"] = []
        data["sensor_sampling"] = {"status": "not_requested", "sample_count": 0}
    if sensor_sampling and data.get("sensor_history"):
        provider_statuses = [row.get("sensor_provider") for row in data["sensor_history"]
                             if isinstance(row.get("sensor_provider"), dict)]
        if provider_statuses:
            data["sensor_provider"] = provider_statuses[-1]
    if IS_WIN:
        post_benchmark_wmi = safe('WMI sensors after benchmark', ps_json, PS_SENSORS, default=[])
        data["sensors_after_benchmark"], data["sensor_provider_after_benchmark"] = collect_sensor_readings(post_benchmark_wmi)
    data["meta"]["sources"] = build_sources(data, ci, ps)
    data["meta"]["elapsed_s"] = time.perf_counter() - _T0
    data["meta"]["warnings"] = list(WARNINGS)
    return data
def build_sources(data, ci, ps) -> list:
    'Diagnostic list showing which data sources were active [(name, status)].'
    base, bc = data.get("baseline") or {}, dig(data, "bench.cpu", {}) or {}
    try:
        import numpy
        np_ok = True
    except ImportError:
        np_ok = False
    miss = base.get("pdh_missing") or []
    gp = dig(data, "gpu", {}) or {}
    sensor_provider = data.get("sensor_provider") if isinstance(data.get("sensor_provider"), dict) else {}
    additional_providers = sensor_provider.get("additional_providers") or []
    adlx_provider = next((row for row in additional_providers if isinstance(row, dict) and
                          "adlx" in str(row.get("backend") or "").casefold()), None)
    adlx_state = (f"{adlx_provider.get('status', 'unknown')}; temperature={adlx_provider.get('temperature_count', 0)}"
                  if adlx_provider else 'optional / not attempted during sensor sampling')
    pagefile_info = dig(data, "os.pagefile", {}) or {}
    pagefile_state = str(pagefile_info.get("status") or "not_collected")
    jit_state = ('ran' if (bc.get("alu") or {}).get("P") and "error" not in (bc["alu"]["P"] or {}) else
                 'skipped (--quick/--no-jit/not supported)' if not bc.get("jit") else 'failed (details: Unavailable data)')
    return [['Windows counters (PDH)', ("active" if base.get("pdh") else "no") + (f"; missing: {', '.join(miss)}" if miss else "")],
            ['CPU frequency source', dig(base, "freq.source") or 'could not be read'],
            ['Processor topology', dig(data, "cpu.topology_source") or "fallback"],
            ["SMBIOS (RAM/BIOS/motherboard)", (f"{data['memory'].get('populated')} module(s) / {data['memory'].get('slots_total')} slot" if data["memory"].get("slots_total") else 'could not be read')],
            ["GPU list (DXGI)", f"{len(gp.get('gpus') or [])} adapter(s)"],
            ["NVML (NVIDIA)", 'not applicable (no NVIDIA adapter found)' if gp.get("nvml_status") == "not_applicable" else "Yes" if gp.get("nvml_available") else 'not present/could not be started'],
            ['AMD ADLX GPU temperature', adlx_state],
            ['Windows page file (WMI/CIM)', pagefile_state],
            ['PowerShell queries', ", ".join(f"{k}:{'dolu' if ps.get(k) else 'empty'}" for k in ("disks", "parts", "guard", "tpm", "cpu_wmi", "sensors", "disk_reliability", "security", "reliability", "devices", "startup", "drivers", "updates"))],
            ["py-cpuinfo (CPUID)", "Yes" if ci else 'not present/failed'], ["numpy", "Yes" if np_ok else "no"],
            ['Machine-code measurement', jit_state],
            ["SMART (smartctl)", dig(data, "inventory.storage.smartctl.status") or 'not present/inaccessible'],
            ["Windows Storage Reliability", "Yes" if ps.get("disk_reliability") else 'not present or unsupported by driver'],
            ['Windows security status', "Yes" if ps.get("security") else 'not present/inaccessible'],
            ['Windows hardware events', "Yes" if ps.get("reliability") else 'not present/inaccessible'],
            ["FFmpeg video encoder test", 'ran' if dig(data, "bench.encoder.available") else 'optional / not run or no encoder available']]
def analyze_system(mode="standard", worker_mb=None, **opts) -> dict:
    'Module usage: runs a full analysis only on Windows 11 Pro x64.'
    platform_status = supported_platform_status()
    if not platform_status["supported"]:
        raise RuntimeError(_unsupported_platform_message(platform_status))
    if worker_mb is not None and int(worker_mb) <= 0:
        raise ValueError('worker_mb must be a positive MiB value')
    opts.setdefault("say", lambda _m: None)
    data = collect_all(mode, **opts)
    A = analyze(data, worker_mb)
    return {"data": data, "analysis": A, "scores": A["scores"], "budget": A["budget"]}
def collect_diagnostics() -> dict:
    import importlib.util
    dependency_specs = [
        ("psutil", True, 'CPU/RAM/disk/network telemetry'),
        ("numpy", False, 'some numeric benchmarks'),
        ("cpuinfo", False, 'CPUID / CPU feature names'),
        ("pynvml", False, "NVIDIA GPU telemetry"),
        ("torch", False, 'optional GPU benchmark'),
        ("HardwareMonitor", False, 'LibreHardwareMonitor .NET sensor access'),
        ("pythonnet", False, ' .NET CLR bridge (clr module)'),
        ("PyLibreHardwareMonitor", False, 'Fallback LibreHardwareMonitor sensor provider'),
        ("ADLXPybind", False, 'AMD ADLX custom Python binding (GPU edge/hotspot temperature)'),
        ("amd-adlx", False, 'Official AMD ADLX Python binding (GPU edge/hotspot temperature)'),
    ]
    dependencies = []
    for name, required, purpose in dependency_specs:
        module_name = {"pythonnet": "clr", "amd-adlx": "adlx"}.get(name, name)
        try:
            available = importlib.util.find_spec(module_name) is not None
        except (ImportError, ValueError, ModuleNotFoundError, AttributeError):
            available = False
        dependencies.append({"name": name, "required": required, "available": available, "purpose": purpose})
    tool_names = ["smartctl", "ffmpeg", "lspci", "lsblk", "dmidecode", "sensors", "nvidia-smi",
                  "powershell.exe", "pwsh.exe", "system_profiler", "diskutil", "sysctl", "wmic"]
    tools = [{"name": name, "path": shutil.which(name), "available": shutil.which(name) is not None}
             for name in tool_names]
    sources = []
    def source(name, status, details=None):
        row = {"name": name, "status": status}
        if details:
            row["details"] = str(details)[:500]
        sources.append(row)
    source('Administrator/root privileges', "available" if is_admin() else "limited",
           'Elevated permissions may be required for some SMBIOS, SMART, and device data.' if not is_admin() else 'Elevated permissions detected.')
    source("Main engine script", "available" if os.path.isfile(__file__) else "missing", __file__)
    source('Consolidated inventory/sensor code', "available", 'Embedded in system_analyses.py; no separate Python module is required.')
    source('Project-folder write permission', "available" if os.access(os.path.dirname(os.path.abspath(__file__)), os.W_OK) else "limited",
           'The temporary folder is also tried as an alternative for report writing.')
    sensor_packages = sensor_provider_package_status()
    sensor_package_summary = "; ".join(
        f"{row['name']}={'yes' if row['available'] else 'missing'}" for row in sensor_packages
    )
    pawnio = pawnio_driver_status() if IS_WIN else {"status": "unsupported", "details": 'Non-Windows'}
    has_primary = next((row["available"] for row in sensor_packages if row["name"] == "HardwareMonitor"), False)
    has_pythonnet = next((row["available"] for row in sensor_packages if row["name"] == "pythonnet"), False)
    has_fallback = next((row["available"] for row in sensor_packages if row["name"] == "PyLibreHardwareMonitor"), False)
    provider_ready = (has_primary and has_pythonnet) or has_fallback
    source('LibreHardwareMonitor Python providers', "available" if provider_ready else "optional_missing",
           f"{sensor_package_summary}; administrator={'yes' if is_admin() else 'no'}; PawnIO={pawnio['status']} ({pawnio.get('details', '')})")
    source('PawnIO driver', pawnio["status"], pawnio.get("details"))
    if IS_WIN:
        live_rows, live_status = probe_live_temperatures()
        live_count = sum(1 for row in live_rows if str(row.get("SensorType", "")).casefold() == "temperature")
        live_state = "available" if live_count else "unsupported_or_empty" if live_status.get("backend") else "optional_missing"
        live_details = [
            f"provider={live_status.get('backend') or 'no'}",
            f"valid temperature={live_count}",
            f"raw temperature records={live_status.get('raw_temperature_count', 0)}",
            f"hardware types={', '.join(live_status.get('hardware_types') or []) or '—'}",
            'sensors by component=' + (", ".join(
                f"{key}:{value}" for key, value in sorted((live_status.get("sensor_counts_by_hardware_type") or {}).items())
            ) or "—"),
            f"sensor roles={', '.join(live_status.get('sensor_roles') or []) or '—'}",
            f"VRM sensor={live_status.get('vrm_sensor_count', 0)}",
            f"sources={', '.join(live_status.get('sources') or []) or '—'}",
        ]
        if live_status.get("details"):
            live_details.append(str(live_status["details"]))
        live_details.extend(str(item) for item in (live_status.get("messages") or [])[-2:])
        live_details.extend(str(item) for item in (live_status.get("attempts") or [])[-2:])
        source('Live LibreHardwareMonitor temperature probe', live_state, "; ".join(live_details))
        fallback_rows, fallback_status = probe_pylibre_temperatures()
        fallback_count = sum(1 for row in fallback_rows if str(row.get("SensorType", "")).casefold() == "temperature")
        fallback_state = "available" if fallback_count else "unsupported_or_empty" if fallback_status.get("backend") else "optional_missing"
        fallback_details = [
            f"provider={fallback_status.get('backend') or 'PyLibreHardwareMonitor'}",
            f"valid temperature={fallback_count}",
            f"raw temperature records={fallback_status.get('raw_temperature_count', 0)}",
            f"sensors by component=" + (", ".join(
                f"{key}:{value}" for key, value in sorted((fallback_status.get("sensor_counts_by_hardware_type") or {}).items())
            ) or "—"),
        ]
        if fallback_status.get("details"):
            fallback_details.append(str(fallback_status["details"]))
        fallback_details.extend(str(item) for item in (fallback_status.get("attempts") or [])[-2:])
        source('Independent PyLibreHardwareMonitor fallback-provider probe', fallback_state, "; ".join(fallback_details))
        try:
            acpi_raw = as_list(ps_json(PS_ACPI_THERMAL_ZONES, timeout=6))
            acpi_rows = normalize_windows_acpi_thermal_zones(acpi_raw)
            source(
                "Windows ACPI thermal zones (root/wmi)",
                "available" if acpi_rows else "unsupported_or_empty",
                f"{len(acpi_rows)} valid zone temperatures; thermal zones defined by ACPI/firmware; "
                'does not replace component-specific CPU/GPU sensors.',
            )
        except Exception as exc:
            source("Windows ACPI thermal zones (root/wmi)", "inaccessible", f"{type(exc).__name__}: {exc}")
        adlx_rows, adlx_status = probe_adlx_gpu_temperatures()
        source('AMD ADLX GPU temperature telemetry',
               "available" if adlx_rows else adlx_status.get("status", "unsupported_or_empty"),
               adlx_status.get("details") or f"{len(adlx_rows)} temperature channel(s)")
    else:
        source('Live LibreHardwareMonitor temperature probe', "unsupported",
               'This diagnostic environment is not Windows; sensor hardware was not initialized.')
    try:
        import psutil as _psutil
        try:
            vm = _psutil.virtual_memory()
            source("psutil CPU/RAM", "available", f"RAM={vm.total} bytes; logical CPUs={_psutil.cpu_count()}")
        except Exception as exc:
            source("psutil CPU/RAM", "failed", f"{type(exc).__name__}: {exc}")
        try:
            temps = _psutil.sensors_temperatures() if hasattr(_psutil, "sensors_temperatures") else {}
            count = sum(len(v or []) for v in (temps or {}).values())
            source('Operating-system temperature sensors', "available" if count else "unsupported_or_empty",
                   f"{count} temperature record(s); depends on platform/driver/permission support.")
        except Exception as exc:
            source('Operating-system temperature sensors', "inaccessible", f"{type(exc).__name__}: {exc}")
    except ImportError as exc:
        source("psutil CPU/RAM", "missing", str(exc))
        source('Operating-system temperature sensors', "unavailable", 'psutil is not installed.')
    system = platform.system().lower()
    if system == "windows":
        powershell = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
        if powershell:
            try:
                wmi = ps_json("$x=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop | Select-Object Caption,BuildNumber; $x | ConvertTo-Json -Compress", timeout=8)
                source("PowerShell / WMI", "available" if wmi else "inaccessible", wmi.get("Caption") if isinstance(wmi, dict) else 'WMI did not respond.')
            except Exception as exc:
                source("PowerShell / WMI", "inaccessible", f"{type(exc).__name__}: {exc}")
        else:
            source("PowerShell / WMI", "missing", 'PowerShell was not found; WMI-based fields may be empty.')
        source("Windows SMBIOS / CIM", "available" if powershell and is_admin() else "partial",
               'Some CIM/firmware data can be read without administrator privileges.')
    elif system == "linux":
        for name, path, elevated in (
            ("Linux CPU procfs", "/proc/cpuinfo", False),
            ("Linux block/sysfs", "/sys/class/block", False),
            ("Linux GPU DRM sysfs", "/sys/class/drm", False),
            ("Linux SMBIOS/DMI sysfs", "/sys/firmware/dmi/tables", True),
        ):
            exists = os.path.exists(path)
            readable = os.access(path, os.R_OK) if exists else False
            status = "available" if exists and readable else "limited" if exists else "missing"
            details = path + ('; administrator/firmware access may be required' if elevated and not readable else "")
            source(name, status, details)
    elif system == "darwin":
        for name in ("system_profiler", "diskutil", "sysctl"):
            source(f"macOS {name}", "available" if shutil.which(name) else "missing", 'checked through command path')
    smart_path = shutil.which("smartctl")
    source('SMART health query', "available" if smart_path else "optional_missing",
           smart_path or 'smartctl from smartmontools is optional; no automatic installation or disk query was performed.')
    try:
        providers = registered_providers()
    except Exception as exc:
        providers = {"inventory": [], "platform": [], "error": f"{type(exc).__name__}: {exc}"}
    return {"diagnostics_schema_version": 1,
            "timestamp": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
            "runtime": {"python_version": platform.python_version(), "executable": sys.executable,
                        "system": platform.system(), "release": platform.release(), "machine": platform.machine(),
                        "bitness": struct.calcsize("P") * 8},
            "permissions": {"elevated": is_admin(), "report_directory_writable": os.access(os.path.dirname(os.path.abspath(__file__)), os.W_OK)},
            "dependencies": dependencies, "tools": tools, "sources": sources, "registered_providers": providers,
            "note": 'Diagnostics is a read-only check; it does not run benchmarks, network speed tests, disk write tests, or SMART device queries.'}
def render_diagnostics(report: dict) -> str:
    lines = ['SYSTEM DIAGNOSTICS', "=" * 72,
             f"Python: {report['runtime']['python_version']} ({report['runtime']['bitness']}-bit)",
             f"Platform: {report['runtime']['system']} {report['runtime']['release']} / {report['runtime']['machine']}",
             f"Elevated permissions: {'yes' if report['permissions']['elevated'] else 'no'}", ""]
    platform_support = report.get("platform_support")
    if platform_support:
        lines.append(f"Target platform compatibility: {'SUPPORTED' if platform_support.get('supported') else 'NOT SUPPORTED'} — {platform_support.get('target', 'Windows 11 Pro x64')}")
        lines.extend(f"  - {reason}" for reason in platform_support.get("errors", []))
    lines += ["", 
             'Dependencies:']
    for row in report.get("dependencies", []):
        status = "Yes" if row.get("available") else 'MISSING'
        required = "required" if row.get("required") else 'optional'
        lines.append(f"  [{status}] {row['name']} ({required}) — {row['purpose']}")
    lines.append('\nExternal tools:')
    for row in report.get("tools", []):
        lines.append(f"  [{'yes' if row.get('available') else 'no'}] {row['name']}: {row.get('path') or 'not found on PATH'}")
    lines.append('\nData sources and permissions:')
    for row in report.get("sources", []):
        details = f" — {row['details']}" if row.get("details") else ""
        lines.append(f"  [{row['status']}] {row['name']}{details}")
    providers = report.get("registered_providers") or {}
    lines.append(f"\nRegistered plugin providers: {len(providers.get('inventory') or [])} inventory; {len(providers.get('platform') or [])} platform")
    lines.append("\n" + report.get("note", ""))
    return "\n".join(lines)
def ensure_deps(install_all=False) -> None:
    global psutil
    import importlib
    import importlib.util
    need = [] if psutil is not None else ["psutil"]
    if install_all:
        optional_packages = [("numpy", "numpy"), ("py-cpuinfo", "cpuinfo"), ("nvidia-ml-py", "pynvml")]
        if IS_WIN:
            optional_packages.extend((
                ("HardwareMonitor", "HardwareMonitor"),
                ("PyLibreHardwareMonitor", "PyLibreHardwareMonitor"),
                ("pythonnet", "clr"),
            ))
        for package, module_name in optional_packages:
            try:
                present = importlib.util.find_spec(module_name) is not None
            except (ImportError, ValueError, ModuleNotFoundError, AttributeError):
                present = False
            if not present and package not in need:
                need.append(package)
    if not need:
        return
    if not install_all and psutil is None:
        if not sys.stdin.isatty():
            raise SystemExit('psutil is required:  pip install psutil   (or run with --install-deps)')
        ans = input("Required package 'psutil' is not installed. Install it now? [Y/n]: ").strip().lower() or "y"
        if ans not in ("y", "yes"):
            raise SystemExit('Cannot run without psutil:  pip install psutil')
    log("Installing with pip: " + ", ".join(need))
    rc = subprocess.call([sys.executable, "-m", "pip", "install", "--disable-pip-version-check", *need])
    importlib.invalidate_caches()
    if rc != 0 and psutil is None:
        raise SystemExit(f"Installation failed (code {rc}). Try manually:  {sys.executable} -m pip install {' '.join(need)}")
    if psutil is None:
        psutil = importlib.import_module("psutil")
        globals()["psutil"] = psutil
def request_admin_relaunch(argv=None) -> tuple[bool, str | None]:
    if not IS_WIN:
        return False, '--elevate is available only on Windows.'
    if is_admin():
        return True, None
    forwarded = list(sys.argv[1:] if argv is None else argv)
    script_path = os.path.abspath(__file__)
    python_command = subprocess.list2cmdline([sys.executable, script_path, *forwarded])
    command_shell = os.environ.get(
        "COMSPEC", os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "cmd.exe")
    )
    parameters = f'/d /k "{python_command}"'
    try:
        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        shell_execute = shell32.ShellExecuteW
        shell_execute.restype = ctypes.c_void_p
        shell_execute.argtypes = [wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR,
                                  wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_int]
        result = shell_execute(None, "runas", command_shell, parameters, os.getcwd(), 1)
        if result and int(result) > 32:
            return True, None
        return False, 'The UAC request was declined or the elevated process could not be started.'
    except Exception as exc:
        return False, f"Could not start the elevated process: {type(exc).__name__}: {exc}"
def parse_args(argv=None):
    ap = argparse.ArgumentParser(
        prog="system_analyses.py",
        description='Multi-source hardware inventory and system analysis for Windows 11 Pro x64.',
        epilog='Supported: Windows 11 Pro x64 + 64-bit Python only. Recommended packages: pip install psutil numpy py-cpuinfo nvidia-ml-py (or use --install-deps)')
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--quick", action="store_true", help='quick analysis: no benchmarks (~10 sec)')
    g.add_argument("--deep", action="store_true", help='deep analysis: sustained-load test + large disk test (~2 min)')
    ap.add_argument("--no-disk", action="store_true", help='skip disk speed test')
    ap.add_argument("--no-jit", action="store_true", help='skip machine-code measurements (core clock, IPC, latency)')
    ap.add_argument("--network-test", action="store_true", help='run optional ping loss/latency/jitter and DNS tests')
    ap.add_argument("--network-speed-test", action="store_true", help='small download/upload speed test through Cloudflare; uses approximately 6 MiB of network data')
    ap.add_argument("--network-host", default="1.1.1.1", help='ping test target (default: 1.1.1.1)')
    ap.add_argument("--dns-host", default="example.com", help='DNS lookup test name (default: example.com)')
    ap.add_argument("--gpu-bench", action="store_true", help='optional PyTorch CUDA/DirectML FP32 GPU benchmark; PyTorch is not installed automatically')
    ap.add_argument("--gpu-bench-seconds", type=float, default=2.0, help='GPU benchmark duration (0.5-10 sec; default 2)')
    ap.add_argument("--memory-test-mb", type=int, default=0, help='optional RAM page-sampling test size in MiB (16-256; disabled by default)')
    ap.add_argument("--memory-test-passes", type=int, default=2, help='RAM sampling test pattern count 1-4 (default 2)')
    ap.add_argument("--bench-warmups", type=int, default=1, help='CPU benchmark warm-up runs before measurement 0-3 (default 1; increases duration)')
    ap.add_argument("--bench-repeats", type=int, default=1, help='CPU benchmark measured repetitions 1-5 (default 1; increases duration)')
    ap.add_argument("--sensor-sampling", action="store_true", help='collect timestamped CPU/RAM/disk I/O/temperature/GPU power-utilization samples during analysis')
    ap.add_argument("--sensor-duration", type=float, default=30.0, help='--sensor-sampling duration in seconds (1-600; default 30)')
    ap.add_argument("--sensor-interval", type=float, default=1.0, help='sensor sampling interval in seconds (0.5-30; default 1)')
    ap.add_argument("--elevate", action="store_true", help='request UAC approval and relaunch in an elevated CMD window (only when explicitly requested)')
    ap.add_argument("--diagnostics", action="store_true", help='run dependency, tool, permission, and data-source diagnostics without benchmarks')
    ap.add_argument("--disk-path", help='folder for disk testing (default: TEMP)')
    ap.add_argument("--disk-mb", type=int, help="disk test file size (MiB)")
    ap.add_argument("--worker-mb", type=int, help='estimated RAM per worker for resource budgeting (MiB)')
    ap.add_argument("--out", help='report folder (default: system_analyses_reports next to the script)')
    ap.add_argument("--no-save", action="store_true", help='do not save report files')
    ap.add_argument("--json", action="store_true", help='write JSON only to the console')
    ap.add_argument("--from-json", metavar="FILE", help='rebuild a report from a previously saved JSON file')
    ap.add_argument("--compare-json", metavar="FILE", help='compare the current result with a previous system_analyses JSON report')
    ap.add_argument("--history-dir", metavar='FOLDER', help='create a health time series from previous JSON reports in the folder')
    ap.add_argument("--history-limit", type=int, default=20, help='maximum number of previous reports for health history (1-500; default 20)')
    ap.add_argument("--csv-out", metavar="FILE", help='export timestamped sensor/telemetry data as Excel-compatible CSV')
    ap.add_argument("--html-out", metavar="FILE", help='create an offline HTML report')
    ap.add_argument("--encoder-bench", action="store_true", help='optional FFmpeg synthetic 720p H.264 encoder test (NVENC/AMF/QSV/libx264)')
    ap.add_argument("--encoder-bench-seconds", type=float, default=3.0, help='test duration per encoder 0.5-10 sec (default 3)')
    ap.add_argument("--storage-health-probe", action="store_true", help='optional read-only SMART query using smartctl (smartmontools required; standby protection depends on the device)')
    ap.add_argument("--serials", action="store_true", help='backward-compatibility option; serial numbers are already included')
    ap.add_argument("--no-color", action="store_true", help="disable colors")
    ap.add_argument("--ascii", action="store_true", help='ASCII characters only')
    ap.add_argument("--no-pause", action="store_true", help='keep the window open after double-click launch')
    ap.add_argument("--install-deps", action="store_true", help='install missing recommended packages with pip')
    return ap.parse_args(argv)
def validate_export_paths(csv_out: str | None, html_out: str | None, input_paths=()) -> None:
    def normalize(value: str) -> str:
        expanded = os.path.expanduser(os.fspath(value))
        return os.path.normcase(os.path.realpath(os.path.abspath(expanded)))
    outputs = [(label, normalize(path)) for label, path in (("CSV", csv_out), ("HTML", html_out)) if path]
    if len(outputs) == 2 and outputs[0][1] == outputs[1][1]:
        raise ValueError('CSV and HTML export paths must be different')
    input_targets = {normalize(path) for path in input_paths if path}
    for label, target in outputs:
        if target in input_targets:
            raise ValueError(f"{label} export path must not overwrite the input JSON file")
def _report_dir(arg_out):
    for cand in ([arg_out] if arg_out else []) + [os.path.join(os.path.dirname(os.path.abspath(__file__)), "system_analyses_reports"),
                                                  os.path.join(tempfile.gettempdir(), "system_analyses_reports")]:
        try:
            os.makedirs(cand, exist_ok=True)
            probe = os.path.join(cand, ".w")
            with open(probe, "w", encoding="utf-8") as f:
                f.write("x")
            os.remove(probe)
            return cand
        except OSError:
            continue
    return None
def main(argv=None) -> int:
    args = parse_args(argv)
    platform_status = supported_platform_status()
    setup_console(args.no_color or args.json, args.ascii)
    pause = (not args.no_pause) and launched_from_explorer()
    try:
        validate_export_paths(args.csv_out, args.html_out, (args.from_json, args.compare_json))
    except ValueError as exc:
        print(f"Invalid export path: {exc}", file=sys.stderr)
        return 2
    try:
        if not platform_status["supported"] and not args.diagnostics:
            message = _unsupported_platform_message(platform_status)
            if args.json:
                print(json.dumps({"error": "unsupported_platform", "platform_support": platform_status},
                                 ensure_ascii=False, indent=2))
            else:
                print(message, file=sys.stderr)
            return 2
        if args.elevate and IS_WIN and not is_admin():
            launched, launch_error = request_admin_relaunch(argv)
            if launched:
                if not args.json:
                    print('The elevated process was started in a new CMD window through UAC; monitor the output in that window.')
                return 0
            print(launch_error or 'The elevated process could not be started.', file=sys.stderr)
            return 1
        if args.diagnostics:
            conflicting = (args.quick or args.deep or args.from_json or args.compare_json or args.network_test or
                           args.network_speed_test or args.gpu_bench or args.encoder_bench or args.storage_health_probe or
                           args.memory_test_mb or args.sensor_sampling or args.disk_path or args.disk_mb or args.no_disk or
                           args.no_jit or args.worker_mb is not None or args.serials or args.install_deps or
                           args.bench_warmups != 1 or args.bench_repeats != 1 or args.sensor_duration != 30.0 or
                           args.sensor_interval != 1.0 or args.history_dir is not None or args.history_limit != 20 or
                           args.csv_out is not None or args.html_out is not None)
            if conflicting:
                raise SystemExit('--diagnostics must run independently; use only --json/--no-color/--no-pause')
            diagnostic_report = collect_diagnostics()
            diagnostic_report["platform_support"] = platform_status
            print(json.dumps(diagnostic_report, ensure_ascii=False, indent=2, default=str) if args.json
                  else render_diagnostics(diagnostic_report))
            return 0 if platform_status["supported"] else 2
        ensure_deps(args.install_deps)
        if not 0.5 <= args.encoder_bench_seconds <= 10:
            raise SystemExit('--encoder-bench-seconds must be between 0.5 and 10')
        if args.worker_mb is not None and args.worker_mb <= 0:
            raise SystemExit('--worker-mb must be a positive MiB value')
        if args.disk_mb is not None and not 64 <= args.disk_mb <= 16384:
            raise SystemExit('--disk-mb must be between 64 and 16384 MiB')
        if not 1 <= args.history_limit <= 500:
            raise SystemExit('--history-limit must be between 1 and 500')
        if args.history_limit != 20 and not args.history_dir:
            raise SystemExit('specify --history-dir to use --history-limit')
        if args.from_json:
            try:
                with open(args.from_json, "r", encoding="utf-8") as f:
                    payload = json.load(f)
                data, _stored_analysis = normalize_report_payload(payload, context="Input")
            except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
                print(f"Could not read input report: {type(exc).__name__}: {exc}", file=sys.stderr)
                return 2
            try:
                A = analyze(data, args.worker_mb)
                if args.compare_json:
                    with open(args.compare_json, "r", encoding="utf-8") as f:
                        A["comparison"] = build_comparison(data, A, json.load(f))
                if args.history_dir:
                    A["health_history_series"] = build_health_history_series(
                        data, args.history_dir, args.history_limit, exclude_paths=[args.from_json])
                A["alerts"] = build_health_alerts(data, A)
                report_text = render_report(data, A) if (not args.json or args.html_out) else ""
            except (OSError, UnicodeError, ValueError, KeyError, TypeError, AttributeError, IndexError) as exc:
                print(f"Could not analyze input report: {type(exc).__name__}: {exc}", file=sys.stderr)
                return 2
            if args.json:
                output_analysis = ({k: v for k, v in A.items() if k != "cpu"} |
                                   {"cpu": {k: v for k, v in A["cpu"].items() if k != "weights"}})
                output_payload = {"data": data, "analysis": output_analysis}
                print(json.dumps(output_payload, ensure_ascii=False, indent=2, default=str))
            else:
                print(report_text)
            try:
                if args.csv_out:
                    exported = export_sensor_history_csv(data, args.csv_out)
                    print(f"CSV exported: {exported['path']} ({exported['row_count']} row(s))",
                          file=sys.stderr if args.json else sys.stdout)
                if args.html_out:
                    exported = export_html_report(data, A, report_text, args.html_out)
                    print(f"HTML report exported: {exported['path']}",
                          file=sys.stderr if args.json else sys.stdout)
            except (OSError, csv.Error, ValueError) as exc:
                print(f"Export failed: {type(exc).__name__}: {exc}", file=sys.stderr)
                return 2
            return 0
        mode = "quick" if args.quick else "deep" if args.deep else "standard"
        if args.memory_test_mb != 0 and not 16 <= args.memory_test_mb <= 256:
            raise SystemExit('--memory-test-mb must be 0 (disabled) or between 16 and 256')
        if not 1 <= args.memory_test_passes <= 4:
            raise SystemExit('--memory-test-passes must be between 1 and 4')
        if not 0.5 <= args.gpu_bench_seconds <= 10:
            raise SystemExit('--gpu-bench-seconds must be between 0.5 and 10')
        if not 0 <= args.bench_warmups <= 3:
            raise SystemExit('--bench-warmups must be between 0 and 3')
        if not 1 <= args.bench_repeats <= 5:
            raise SystemExit('--bench-repeats must be between 1 and 5')
        if not 1 <= args.sensor_duration <= 600:
            raise SystemExit('--sensor-duration must be between 1 and 600 seconds')
        if not 0.5 <= args.sensor_interval <= 30:
            raise SystemExit('--sensor-interval must be between 0.5 and 30 seconds')
        if not args.json:
            log(f"yigitsapa System Analyses Engine starting (engine version {__version__}, mode: {mode}). Python {platform.python_version()} / {platform.system()} {platform.release()}")
        data = collect_all(mode, args.no_jit, args.no_disk, args.disk_path, args.disk_mb, args.serials,
                           say=(lambda m: None) if args.json else log,
                           network_test=args.network_test, network_speed_test=args.network_speed_test,
                           network_host=args.network_host, dns_host=args.dns_host,
                           gpu_bench=args.gpu_bench, gpu_bench_seconds=args.gpu_bench_seconds,
                           memory_test_mb=args.memory_test_mb, memory_test_passes=args.memory_test_passes,
                           bench_repeats=args.bench_repeats, bench_warmups=args.bench_warmups,
                           encoder_bench=args.encoder_bench, encoder_bench_seconds=args.encoder_bench_seconds,
                           storage_health_probe=args.storage_health_probe, sensor_sampling=args.sensor_sampling,
                           sensor_duration_s=args.sensor_duration, sensor_interval_s=args.sensor_interval)
        d = None if args.no_save else _report_dir(args.out)
        stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        try:
            A = analyze(data, args.worker_mb)
            if args.compare_json:
                try:
                    with open(args.compare_json, "r", encoding="utf-8") as f:
                        A["comparison"] = build_comparison(data, A, json.load(f))
                except (OSError, UnicodeError, ValueError, KeyError, TypeError) as exc:
                    raise ValueError(f"Could not read comparison report: {type(exc).__name__}: {exc}") from exc
            if args.history_dir:
                A["health_history_series"] = build_health_history_series(data, args.history_dir, args.history_limit)
            A["alerts"] = build_health_alerts(data, A)
            text = render_report(data, A)
        except Exception:
            import traceback
            traceback.print_exc()
            if d:
                raw_path = os.path.join(d, f"system_analyses_{stamp}_raw.json")
                with open(raw_path, "w", encoding="utf-8") as f:
                    json.dump({"data": data}, f, ensure_ascii=False, indent=2, default=str)
                print(f"\nAn error occurred during analysis/reporting. Collected raw data was saved to: {raw_path}\n"
                      f"(After fixing the issue:  python system_analyses.py --from-json \"{raw_path}\")", file=sys.stderr)
            return 1
        payload = {"data": data, "analysis": {k: v for k, v in A.items() if k != "cpu"} | {"cpu": {k: v for k, v in A["cpu"].items() if k != "weights"}}}
        js = json.dumps(payload, ensure_ascii=False, indent=2, default=str)
        print(js if args.json else text)
        if not args.no_save:
            if d:
                with open(os.path.join(d, f"system_analyses_{stamp}.txt"), "w", encoding="utf-8") as f:
                    f.write(strip_ansi(text))
                with open(os.path.join(d, f"system_analyses_{stamp}.json"), "w", encoding="utf-8") as f:
                    f.write(js)
                log(f"Report saved: {d}")
        try:
            if args.csv_out:
                exported = export_sensor_history_csv(data, args.csv_out)
                message = f"CSV exported: {exported['path']} ({exported['row_count']} row(s))"
                print(message, file=sys.stderr) if args.json else log(message)
            if args.html_out:
                exported = export_html_report(data, A, text, args.html_out)
                message = f"HTML report exported: {exported['path']}"
                print(message, file=sys.stderr) if args.json else log(message)
        except (OSError, csv.Error, ValueError) as exc:
            print(f"Export failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 2
        return 0
    except KeyboardInterrupt:
        print('\nStopped by user.', file=sys.stderr)
        return 130
    finally:
        if pause:
            try:
                input('\nPress Enter to exit...')
            except EOFError:
                pass
__all__ = [
    "__version__", "SCHEMA_VERSION",
    "MEMORY_TYPES", "MEMORY_FORM_FACTORS", "WMI_MEMORY_TYPES",
    "parse_pci_ids", "pci_display_names", "canonical_architecture",
    "identify_gpu_vendor", "infer_integrated_gpu", "classify_storage_kind",
    "extract_smbios_inventory", "empty_inventory", "collect_hardware_inventory",
    "register_inventory_provider", "unregister_inventory_provider",
    "register_platform_provider", "unregister_platform_provider", "registered_providers",
    "normalize_temperature", "normalize_sensor_rows", "extract_hardwaremonitor_temperatures",
    "extract_pylibre_temperatures", "normalize_windows_acpi_thermal_zones",
    "sensor_provider_package_status", "pawnio_driver_status",
    "LibreHardwareMonitorProvider", "probe_live_temperatures", "probe_pylibre_temperatures",
    "collect_sensor_readings", "collect_all", "analyze", "analyze_system",
    "collect_diagnostics", "parse_args", "main",
]
if __name__ == "__main__":
    mp.freeze_support()
    sys.exit(main())