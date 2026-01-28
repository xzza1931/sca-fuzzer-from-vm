.intel_syntax noprefix
.test_case_enter:
.section .data.main

.function_0:
.macro.measurement_start: nop qword ptr [rax + 0xff]

    mov     rax, 150
    cvtsi2ss xmm0, rax        # receiver seed (single precision)
    mov     rax, 1
    cvtsi2ss xmm1, rax        # divisor = 1.0f
    mov     rcx, 12

.recv_loop:
    divss   xmm0, xmm1        # receiver: RAW-dependent div
    dec     rcx
    jnz     .recv_loop

.bb_0:
    xorps   xmm2, xmm2        # xmm2 = 0.0f
    ucomiss xmm2, xmm0
    jne     .slow_path        # speculative heavy path

.fast_path:
    jmp     .done

.slow_path:
    mov     rcx, 100

.load_loop:
    divss   xmm3, xmm1        # sender: independent
    divss   xmm4, xmm1
    divss   xmm5, xmm1
    divss   xmm6, xmm1
    dec     rcx
    jnz     .load_loop

.done:

.section .data.main
.function_end:
.macro.measurement_end: nop qword ptr [rax + 0xff]
.test_case_exit: nop
