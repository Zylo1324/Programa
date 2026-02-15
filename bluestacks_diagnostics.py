#!/usr/bin/env python3
"""Herramienta segura de diagnóstico para BlueStacks.

Nota: Este script NO realiza inyección de código, hooks de API ni modificaciones de
registro para evadir detección. Solo ofrece inspección del proceso y un modo de
supervisión reversible.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import platform
import sys
import tempfile
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Iterable, Optional

try:
    import psutil
except ModuleNotFoundError as exc:
    print("Falta dependencia: psutil. Instala con: pip install psutil", file=sys.stderr)
    raise SystemExit(1) from exc

STATE_FILE = os.path.join(tempfile.gettempdir(), "bluestacks_diag_state.json")
DEFAULT_PROCESS_NAMES = {
    "hd-player.exe",
    "bluestacks.exe",
    "bluestackshelper.exe",
    "bstkvc.exe",
}


@dataclass
class BlueStacksProcess:
    pid: int
    name: str
    exe: str
    cmdline: list[str]


class DiagnosticsError(RuntimeError):
    """Error controlado para mostrar mensajes claros de diagnóstico."""


def _iter_bluestacks_candidates(process_names: Iterable[str]) -> Iterable[psutil.Process]:
    targets = {name.lower() for name in process_names}
    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
        name = (proc.info.get("name") or "").lower()
        exe = (proc.info.get("exe") or "").lower()
        if name in targets or any(target in exe for target in targets):
            yield proc


def find_bluestacks_process(process_names: Optional[Iterable[str]] = None) -> BlueStacksProcess:
    process_names = set(process_names or DEFAULT_PROCESS_NAMES)
    try:
        candidates = list(_iter_bluestacks_candidates(process_names))
    except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
        raise DiagnosticsError(f"No fue posible enumerar procesos: {exc}") from exc

    if not candidates:
        raise DiagnosticsError("No se encontró ningún proceso de BlueStacks en ejecución.")

    proc = max(candidates, key=lambda p: p.info.get("pid", -1))
    return BlueStacksProcess(
        pid=proc.info.get("pid", -1),
        name=proc.info.get("name") or "<desconocido>",
        exe=proc.info.get("exe") or "<ruta no disponible>",
        cmdline=proc.info.get("cmdline") or [],
    )


def collect_system_context() -> dict:
    context = {
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }

    if os.name == "nt":
        class OSVERSIONINFOEXW(ctypes.Structure):
            _fields_ = [
                ("dwOSVersionInfoSize", ctypes.c_ulong),
                ("dwMajorVersion", ctypes.c_ulong),
                ("dwMinorVersion", ctypes.c_ulong),
                ("dwBuildNumber", ctypes.c_ulong),
                ("dwPlatformId", ctypes.c_ulong),
                ("szCSDVersion", ctypes.c_wchar * 128),
            ]

        ver = OSVERSIONINFOEXW()
        ver.dwOSVersionInfoSize = ctypes.sizeof(OSVERSIONINFOEXW)
        if ctypes.windll.Ntdll.RtlGetVersion(ctypes.byref(ver)) == 0:  # type: ignore[attr-defined]
            context["windows_version"] = f"{ver.dwMajorVersion}.{ver.dwMinorVersion}.{ver.dwBuildNumber}"

    return context


def _save_state(payload: dict) -> None:
    with open(STATE_FILE, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)


def _load_state() -> Optional[dict]:
    if not os.path.exists(STATE_FILE):
        return None
    with open(STATE_FILE, "r", encoding="utf-8") as fh:
        return json.load(fh)


def activate_monitor(interval: float) -> None:
    bs_proc = find_bluestacks_process()
    payload = {
        "active": True,
        "interval": interval,
        "activated_at": datetime.utcnow().isoformat() + "Z",
        "process": asdict(bs_proc),
        "context": collect_system_context(),
    }
    _save_state(payload)
    print(f"Monitor activado para PID {bs_proc.pid}. Estado guardado en: {STATE_FILE}")


def deactivate_monitor() -> None:
    state = _load_state()
    if not state:
        print("No había monitor activo. Nada que desactivar.")
        return

    if os.path.exists(STATE_FILE):
        os.remove(STATE_FILE)
    print("Monitor desactivado y estado local eliminado.")


def show_status() -> None:
    state = _load_state()
    try:
        bs_proc = find_bluestacks_process()
        print("BlueStacks detectado:")
        print(json.dumps(asdict(bs_proc), indent=2, ensure_ascii=False))
    except DiagnosticsError as exc:
        print(f"Estado de BlueStacks: {exc}")

    print("\nContexto del sistema:")
    print(json.dumps(collect_system_context(), indent=2, ensure_ascii=False))

    print("\nMonitor local:")
    print(json.dumps(state or {"active": False}, indent=2, ensure_ascii=False))


def run_once() -> int:
    try:
        show_status()
        return 0
    except Exception as exc:  # fallback con mensaje claro
        print(f"Error inesperado: {exc}", file=sys.stderr)
        return 2


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Diagnóstico seguro de BlueStacks (sin evasión ni manipulación)."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("status", help="Muestra proceso, contexto del sistema y estado local.")

    activate = subparsers.add_parser("activate", help="Activa monitor local reversible.")
    activate.add_argument("--interval", type=float, default=3.0, help="Intervalo sugerido de monitor.")

    subparsers.add_parser("deactivate", help="Desactiva monitor y limpia el estado local.")

    args = parser.parse_args()

    try:
        if args.command == "status":
            return run_once()
        if args.command == "activate":
            activate_monitor(max(0.5, args.interval))
            return 0
        if args.command == "deactivate":
            deactivate_monitor()
            return 0
    except DiagnosticsError as exc:
        print(f"Error de diagnóstico: {exc}", file=sys.stderr)
        return 1
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Error de E/S: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
