.intel_syntax noprefix
.test_case_enter:
.section .data.main
.function_0:
.macro.measurement_start: nop qword ptr [rax + 0xff]
and rdi, 0b1111111111111 #
setns bl
and rax, 0b1111111111000 # instrumentation
and eax, 0b111 #
and rdi, 0b1111111111000 #
and rdi, 0b1111111111111 #
and bl, dl
jz .bb_0.1
jmp .exit_0
.bb_0.1:
and rcx, 0b1111111111111 # instrumentation
cmovnbe rbx, qword ptr [r14 + rcx]
and rdx, 0b1111111111000 #
and rdi, 0b1111111111000 #
add dil, 87 # instrumentation
and rdi, 0b1111111111111 #
and rsi, 0b1111111111000 # instrumentation
and rdx, 0b111 #
and rsi, 0b1111111111111 #
and rsi, 0b1111111111000 #
and rdi, 0b1111111111000 # instrumentation
and di, 0b111 #
and rbx, 0b1111111111111 #
and rdi, 0b1111111111000 #
.exit_0:
.macro.measurement_end: nop qword ptr [rax + 0xff]
.section .data.main
.test_case_exit:nop
