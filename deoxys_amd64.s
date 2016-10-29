#include "textflag.h"

DATA permutation<>+0(SB)/8, $0x0e01040b0a0d0007
DATA permutation<>+8(SB)/8, $0x06090c030205080f
GLOBL permutation<>(SB), (RODATA|NOPTR), $16

TEXT ·hasAESNI(SB), NOSPLIT, $0-1
    MOVQ runtime·cpuid_ecx(SB), CX
    MOVQ CX, AX

    SHRQ $25, AX // aes (aesenc)
    SHRQ $9, CX // ssse3 (pshufb)

    ANDQ CX, AX
    ANDQ $1, AX
    MOVB AX, ret+0(FP)
    RET

TEXT ·encryptBlockAsm(SB), NOSPLIT, $0-96
    // TODO check bounds of in, out, and tweak?

    MOVQ subkey_len+8(FP), CX
    MOVQ subkey_base+0(FP), BX

    SUBQ $1, CX
    JL return

    // Load the message and tweak
    MOVQ in_base+48(FP), AX
    MOVOU (AX), X0
    MOVQ tweak_base+24(FP), AX
    MOVOU (AX), X2

    // Load the tweak permutation
    MOVOU permutation<>(SB), X4

    // XOR the first subtweakey into the message
    MOVOU (BX), X1
    PXOR X2, X1
    ADDQ $16, BX
    PXOR X1, X0

loop:
    // Permute the tweak
    PSHUFB X4, X2

    // Get the next subtweakey
    MOVOU (BX), X1
    PXOR X2, X1
    ADDQ $16, BX

    // Encrypt
    AESENC X1, X0

    SUBQ $1, CX
    JNZ loop

    // Store the result
    MOVQ out_base+72(FP), BX
    MOVOU X0, (BX)

return:
    RET
