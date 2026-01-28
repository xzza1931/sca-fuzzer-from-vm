.intel_syntax noprefix
.test_case_enter:
.section .data.main
.function_0:
.bb_0.0:
.macro.measurement_start: nop qword ptr [rax + 0xff]
add sil, -81 # instrumentation
cmovo edi, edx 
and rbx, 0b1111111111111 # instrumentation
test byte ptr [r14 + rbx], -23 
xchg cx, dx 
imul rsi, rdi, -4 
and rsi, 0b1111111111000 # instrumentation
lock dec dword ptr [r14 + rsi] 
btc si, 2 
adc cl, 1 
sbb cl, -85 
and rsp, 0b1111111111111 # instrumentation
add rsp, r14 # instrumentation
call .function_1 
sub rsp, r14 # instrumentation
and rdx, 0b1111111111111 # instrumentation
and edx, 0b111 # instrumentation
btc dword ptr [r14 + rdx], edx 
cmpxchg ax, bx 
btc dx, 155 
add ax, -8 
and rbx, 0b1111111111000 # instrumentation
lock inc byte ptr [r14 + rbx] 
and rsi, 0b1111111111111 # instrumentation
xor dword ptr [r14 + rsi], -16 
and rbx, 0b1111111111111 # instrumentation
cmpxchg word ptr [r14 + rbx], bx 
and rdi, 0b1111111111111 # instrumentation
add edi, dword ptr [r14 + rdi] 
.exit_0:
.section .data.main
.function_1:
.bb_1.0:
lea rdx, qword ptr [rip + .function_2] 
and rsp, 0b1111111111111 # instrumentation
mov qword ptr [r14 + rsp], rdx 
and rsp, 0b1111111111111 # instrumentation
add rsp, r14 # instrumentation
ret  
sub rsp, r14 # instrumentation
.exit_1:
.section .data.main
.function_2:
.bb_2.0:
test rax, 979634692 
and rdi, 0b1111111111111 # instrumentation
cmpxchg byte ptr [r14 + rdi], dil 
and rax, 0b1111111111111 # instrumentation
cmovz rax, qword ptr [r14 + rax] 
cmovnbe bx, di 
cmovbe ecx, esi 
and rdx, 0b1111111111111 # instrumentation
cmovle dx, word ptr [r14 + rdx] 
and rdx, rsi 
setb al 
.exit_2:
.macro.measurement_end: nop qword ptr [rax + 0xff]
jmp .test_case_exit 
.section .data.main
.test_case_exit:
