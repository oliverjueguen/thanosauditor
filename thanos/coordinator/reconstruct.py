"""DLL reconstruction from PA30 deltas via msdelta.dll (RF-05, Phase 3).

DLLs are not shipped whole in the MSUs: they are shipped as **deltas** in PA30
format, preceded by a 4-byte CRC32 prefix. To rebuild the final binary:

  1. Strip the 4-byte CRC32 prefix (the buffer must start with "PA30").
  2. Apply the delta with ``ApplyDeltaB`` from ``msdelta.dll``:
       - ``n/`` (null) delta: applied over a NULL (empty) baseline.
       - ``f/`` (forward) delta: applied over the baseline extracted from the ISO.
  3. Persist the DLL and record its SHA-256.

This phase **requires Windows** (msdelta API). On other systems it raises a clear
error; the logic is documented here and is what runs in the coordinator environment.
"""

from __future__ import annotations

import hashlib
import platform

PA30_MAGIC = b"PA30"
_CRC32_PREFIX_LEN = 4


class ReconstructionError(RuntimeError):
    pass


def strip_crc32_prefix(delta: bytes) -> bytes:
    """Strip the 4-byte CRC32 prefix so the buffer starts with PA30."""
    if delta[:4] == PA30_MAGIC:
        return delta  # already without prefix
    body = delta[_CRC32_PREFIX_LEN:]
    if body[:4] != PA30_MAGIC:
        raise ReconstructionError(
            "the delta does not start with PA30 after stripping the CRC32 prefix"
        )
    return body


def apply_delta(delta: bytes, source: bytes = b"") -> bytes:
    """Apply a PA30 delta over `source` (empty for 'n/' deltas) and return the DLL.

    Requires Windows (msdelta.dll). Implements the ctypes binding for ApplyDeltaB.
    """
    if platform.system() != "Windows":
        raise ReconstructionError(
            "apply_delta requires Windows (msdelta.dll). Run it on the Windows Server 2022 "
            "coordinator. On other OSes use the bundles/fixtures already generated."
        )

    import ctypes
    from ctypes import wintypes

    class DELTA_INPUT(ctypes.Structure):
        _fields_ = [
            ("lpStart", ctypes.c_void_p),
            ("uSize", ctypes.c_size_t),
            ("Editable", wintypes.BOOL),
        ]

    class DELTA_OUTPUT(ctypes.Structure):
        _fields_ = [("lpStart", ctypes.c_void_p), ("uSize", ctypes.c_size_t)]

    msdelta = ctypes.WinDLL("msdelta.dll", use_last_error=True)
    msdelta.ApplyDeltaB.argtypes = [
        ctypes.c_longlong, DELTA_INPUT, DELTA_INPUT, ctypes.POINTER(DELTA_OUTPUT)
    ]
    msdelta.ApplyDeltaB.restype = wintypes.BOOL
    msdelta.DeltaFree.argtypes = [ctypes.c_void_p]

    body = strip_crc32_prefix(delta)
    src_buf = ctypes.create_string_buffer(source, len(source)) if source else None
    delta_buf = ctypes.create_string_buffer(body, len(body))

    di_source = DELTA_INPUT(ctypes.cast(src_buf, ctypes.c_void_p) if source else None,
                            len(source), False)
    di_delta = DELTA_INPUT(ctypes.cast(delta_buf, ctypes.c_void_p), len(body), False)
    out = DELTA_OUTPUT()

    ok = msdelta.ApplyDeltaB(0, di_source, di_delta, ctypes.byref(out))
    if not ok:
        err = ctypes.get_last_error()
        raise ReconstructionError(f"ApplyDeltaB failed (GetLastError={err}: {ctypes.FormatError(err).strip()})")
    try:
        result = ctypes.string_at(out.lpStart, out.uSize)
    finally:
        msdelta.DeltaFree(out.lpStart)
    if not result:
        raise ReconstructionError("ApplyDeltaB returned an empty binary")
    return result


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
