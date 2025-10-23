.intel_syntax noprefix
.test_case_enter:
.section .data.main
.function_0:
.bb_0.0:
.macro.measurement_start: nop qword ptr [rax + 0xff]
add sil, -24 # instrumentation
cmp ax, 11690 
and rdi, 0b1111111111000 # instrumentation
lock add byte ptr [r14 +rdi], 117 
adc rax, 1840966365 
and rsi, 0b1111111111111 # instrumentation
xor edx, dword ptr [r14 +rsi] 
sbb ax, cx 
and rbx, 0b1111111111111 # instrumentation
imul rsi, qword ptr [r14 +rbx] 
add dil, -87 # instrumentation
setz cl 
btc rdi, rdi 
add sil, -1 # instrumentation
jp .bb_0.1 
jmp .exit_0 
.bb_0.1:
add dil, -56 # instrumentation
add dil, 38 # instrumentation
and rdx, 0b1111111111000 # instrumentation
lock adc byte ptr [r14 +rdx], dl 
neg al 
and rsi, 0b1111111111000 # instrumentation
lock sub byte ptr [r14 +rsi], dl 
and rcx, 0b1111111111111 # instrumentation
or qword ptr [r14 +rcx], rbx 
and rdi, 0b1111111111111 # instrumentation
cmovnl rcx, qword ptr [r14 +rdi] 
or al, 1 # instrumentation
mov ax, 1 # instrumentation
div al 
sub bl, cl 
sbb ecx, edi 
movsx rbx, bx 
and rsi, 0b1111111111111 # instrumentation
cmovnbe dx, word ptr [r14 +rsi] 
and rcx, 0b1111111111111 # instrumentation
mov rax, qword ptr [r14 +rcx] 
bts ecx, 139 
jz .bb_0.2 
jmp .exit_0 
.bb_0.2:
and rsi, 0b1111111111000 # instrumentation
xchg word ptr [r14 +rsi], cx 
and rsi, 0b1111111111111 # instrumentation
and cx, 0b111 # instrumentation
bt word ptr [r14 +rsi], cx 
bt rdi, 199 
and rax, 0b1111111111000 # instrumentation
lock neg qword ptr [r14 +rax] 
and rcx, 0b1111111111000 # instrumentation
lock neg word ptr [r14 +rcx] 
and rax, 0b1111111111111 # instrumentation
and word ptr [r14 +rax], 32 
and rbx, 0b1111111111111 # instrumentation
bts qword ptr [r14 +rbx], 131 
dec ax 
cmovno cx, dx 
imul rdi, rdx, 111 
and rbx, 0b1111111111000 # instrumentation
lock xadd byte ptr [r14 +rbx], cl 
and rcx, 0b1111111111111 # instrumentation
cmovnl eax, dword ptr [r14 +rcx] 
.exit_0:
.macro.measurement_end: nop qword ptr [rax + 0xff]
jmp .test_case_exit 
.section .data.main
.test_case_exit:
