.intel_syntax noprefix
.test_case_enter:
.section .data.main
.function_0:
.macro.measurement_start: nop qword ptr [rax + 0xff]
and rdi, 0b1111111111111 # instrumentation
imul word ptr [r14 + rdi]
add sil, -46 # instrumentation
and rdx, 0b1111111111111 # instrumentation
movzx si, byte ptr [r14 + rdx]
and rbx, 0b1111111111111 # instrumentation
setp byte ptr [r14 + rbx]
and rcx, 0b1111111111111 #
or rbx, 0b1000000000000000000000000000000 #
add sil, -70 # instrumentation
and rbx, 0b1111111111111 # instrumentation
adc dx, word ptr [r14 + rbx]
or bl, 2
and rcx, 0b1111111111000 # instrumentation
lock adc byte ptr [r14 + rcx], -45
and rsp, 0b1111111111111 # instrumentation
add rsp, r14 # instrumentation
call .function_1
sub rsp, r14 # instrumentation
lfence
and rsi, 0b1111111111000 # instrumentation
lock not qword ptr [r14 + rsi]
and rax, 0b1111111111111 #
and rcx, 0b1111111111111 #
and rcx, 0b1111111111111 # instrumentation
and esi, 0b111 #
and rax, 0b1111111111000 # instrumentation
lock and word ptr [r14 + rax], cx
.section .data.main
.function_1:
lea rdx, qword ptr [rip + .function_2]
and rsp, 0b1111111111111 #
and rsp, 0b1111111111111 # instrumentation
add rsp, r14 #
sub rsp, r14 # instrumentation
.section .data.main
.function_2:
add dil, 64 # instrumentation
and rbx, 0b1111111111111 #
and rdi, 0b1111111111111 #
and rdx, 0b1111111111111 # instrumentation
mov rax, qword ptr [r14 + rdx]
and rax, 0b1111111111000 # instrumentation
lock add byte ptr [r14 + rax], dil
and rsi, 0b1111111111111 #
.macro.measurement_end: nop qword ptr [rax + 0xff]
.section .data.main
.test_case_exit:nop
