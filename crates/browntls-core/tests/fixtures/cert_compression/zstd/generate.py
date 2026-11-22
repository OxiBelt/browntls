#!/usr/bin/env python3
"""Generate the checked-in Zstandard codec fixtures with system libzstd."""

from __future__ import annotations

import ctypes
import ctypes.util
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PATTERN = b"libzstd certificate fixture: "
CONTENT = PATTERN * 1024


class InBuffer(ctypes.Structure):
    _fields_ = [
        ("src", ctypes.c_void_p),
        ("size", ctypes.c_size_t),
        ("pos", ctypes.c_size_t),
    ]


class OutBuffer(ctypes.Structure):
    _fields_ = [
        ("dst", ctypes.c_void_p),
        ("size", ctypes.c_size_t),
        ("pos", ctypes.c_size_t),
    ]


def check(lib: ctypes.CDLL, result: int) -> int:
    if lib.ZSTD_isError(result):
        error = lib.ZSTD_getErrorName(result).decode("ascii", "replace")
        raise RuntimeError(error)
    return result


def streaming_frame(lib: ctypes.CDLL) -> bytes:
    context = lib.ZSTD_createCCtx()
    if not context:
        raise MemoryError("ZSTD_createCCtx failed")
    try:
        check(lib, lib.ZSTD_CCtx_setParameter(context, 100, 3))  # compression level
        check(lib, lib.ZSTD_CCtx_setParameter(context, 101, 19))  # 512 KiB window
        check(lib, lib.ZSTD_CCtx_setParameter(context, 200, 0))  # omit content size
        check(lib, lib.ZSTD_CCtx_setParameter(context, 201, 1))  # include checksum

        source = ctypes.create_string_buffer(CONTENT)
        destination = ctypes.create_string_buffer(lib.ZSTD_CStreamOutSize())
        encoded = bytearray()
        offset = 0
        while offset < len(CONTENT):
            chunk_end = min(offset + 997, len(CONTENT))
            incoming = InBuffer(
                ctypes.cast(ctypes.byref(source, offset), ctypes.c_void_p),
                chunk_end - offset,
                0,
            )
            while incoming.pos < incoming.size:
                outgoing = OutBuffer(ctypes.cast(destination, ctypes.c_void_p), len(destination), 0)
                check(lib, lib.ZSTD_compressStream2(context, ctypes.byref(outgoing), ctypes.byref(incoming), 0))
                encoded.extend(destination.raw[: outgoing.pos])
            offset = chunk_end

        incoming = InBuffer(None, 0, 0)
        while True:
            outgoing = OutBuffer(ctypes.cast(destination, ctypes.c_void_p), len(destination), 0)
            remaining = check(
                lib,
                lib.ZSTD_compressStream2(context, ctypes.byref(outgoing), ctypes.byref(incoming), 2),
            )
            encoded.extend(destination.raw[: outgoing.pos])
            if remaining == 0:
                return bytes(encoded)
    finally:
        check(lib, lib.ZSTD_freeCCtx(context))


def main() -> None:
    library = ctypes.util.find_library("zstd")
    if library is None:
        raise SystemExit("system libzstd was not found")
    lib = ctypes.CDLL(library)
    lib.ZSTD_compressBound.argtypes = [ctypes.c_size_t]
    lib.ZSTD_compressBound.restype = ctypes.c_size_t
    lib.ZSTD_compress.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    lib.ZSTD_compress.restype = ctypes.c_size_t
    lib.ZSTD_isError.argtypes = [ctypes.c_size_t]
    lib.ZSTD_isError.restype = ctypes.c_uint
    lib.ZSTD_getErrorName.argtypes = [ctypes.c_size_t]
    lib.ZSTD_getErrorName.restype = ctypes.c_char_p
    lib.ZSTD_createCCtx.restype = ctypes.c_void_p
    lib.ZSTD_CCtx_setParameter.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
    lib.ZSTD_CCtx_setParameter.restype = ctypes.c_size_t
    lib.ZSTD_CStreamOutSize.restype = ctypes.c_size_t
    lib.ZSTD_compressStream2.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(OutBuffer),
        ctypes.POINTER(InBuffer),
        ctypes.c_int,
    ]
    lib.ZSTD_compressStream2.restype = ctypes.c_size_t
    lib.ZSTD_freeCCtx.argtypes = [ctypes.c_void_p]
    lib.ZSTD_freeCCtx.restype = ctypes.c_size_t

    source = ctypes.create_string_buffer(CONTENT)
    one_shot = ctypes.create_string_buffer(lib.ZSTD_compressBound(len(CONTENT)))
    size = check(lib, lib.ZSTD_compress(one_shot, len(one_shot), source, len(CONTENT), 3))
    lib.ZSTD_versionString.restype = ctypes.c_char_p
    print("libzstd", lib.ZSTD_versionString().decode())
    for name, data in [
        ("one-shot.zst", one_shot.raw[:size]),
        ("streaming-checksum.zst", streaming_frame(lib)),
    ]:
        (ROOT / name).write_bytes(data)
        print(hashlib.sha256(data).hexdigest(), name)


if __name__ == "__main__":
    main()
