.intel_syntax noprefix
.test_case_enter:
.section .data.main
.function_0:
.bb_0.0:
.macro.measurement_start: nop qword ptr [rax + 0xff]
imul eax 
dec ax 
add al, -80 
and rdi, 0b1111111111000 # instrumentation
lock sub word ptr [r14 + rdi], bx 
cmp rdx, rdx 
and rax, 0b1111111111111 # instrumentation
and rax, 0b111 # instrumentation
bt qword ptr [r14 + rax], rax 
and rdi, 0b1111111111111 # instrumentation
or dword ptr [r14 + rdi], 0b1000000000000000000000000000000 # instrumentation
bsf edi, dword ptr [r14 + rdi] 
bts esi, ecx 
and rax, 0b1111111111000 # instrumentation
lock sub qword ptr [r14 + rax], rax 
sbb rax, -64 
and rbx, 0b1111111111111 # instrumentation
bt dword ptr [r14 + rbx], 146 
and rsi, 0b1111111111111 # instrumentation
neg byte ptr [r14 + rsi] 
jmp .bb_0.1 
.bb_0.1:
and rdx, 0b1111111111111 # instrumentation
cmp qword ptr [r14 + rdx], -79 
and rsi, 0b1111111111000 # instrumentation
lock dec word ptr [r14 + rsi] 
adc bl, 32 
imul rsi, rcx, -58 
adc ebx, -32 
adc eax, 64 
sbb ebx, eax 
or rbx, 0b1000000000000000000000000000000 # instrumentation
bsf rax, rbx 
add dil, 110 # instrumentation
sbb cl, al 
and rsi, 0b1111111111111 # instrumentation
bts word ptr [r14 + rsi], 16 
and rcx, 0b1111111111111 # instrumentation
imul dx, word ptr [r14 + rcx], 90 
.exit_0:
.macro.measurement_end: nop qword ptr [rax + 0xff]
jmp .test_case_exit 
.section .data.main
.test_case_exit:
