.intel_syntax noprefix
.test_case_enter:
.section .data.main
.function_0:
.bb_0.0:
.macro.measurement_start: nop qword ptr [rax + 0xff]
imul si, cx 
bt bx, 236 
and rax, 0b1111111111111 # instrumentation
add word ptr [r14 + rax], bx 
btc edi, edx 
and rsi, 0b1111111111111 # instrumentation
btc dword ptr [r14 + rsi], 4 
adc al, 46 
btc di, cx 
btr si, 83 
and rdx, 0b1111111111111 # instrumentation
imul word ptr [r14 + rdx] 
add al, cl 
and rdi, 0b1111111111000 # instrumentation
and dx, 0b111 # instrumentation
lock bts word ptr [r14 + rdi], dx 
and rdx, 0b1111111111000 # instrumentation
lock adc qword ptr [r14 + rdx], rbx 
and rcx, 0b1111111111111 # instrumentation
neg qword ptr [r14 + rcx] 
mul rdi 
and rcx, 0b1111111111111 # instrumentation
adc rcx, qword ptr [r14 + rcx] 
and rsi, 0b1111111111111 # instrumentation
imul byte ptr [r14 + rsi] 
and rax, 0b1111111111000 # instrumentation
lock sbb byte ptr [r14 + rax], -51 
add ax, ax 
and rdx, 0b1111111111111 # instrumentation
adc dword ptr [r14 + rdx], ebx 
cmp al, cl 
sbb si, ax 
and rcx, 0b1111111111111 # instrumentation
imul cx, word ptr [r14 + rcx], 32 
adc ax, -7467 
inc rdx 
.exit_0:
.macro.measurement_end: nop qword ptr [rax + 0xff]
jmp .test_case_exit 
.section .data.main
.test_case_exit:
