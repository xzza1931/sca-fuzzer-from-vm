.intel_syntax noprefix
.test_case_enter:
.section .data.main
lfence

# reduce the entropy of rax
and rax, 0b111111000000

# delay the cond. jump  
# lea指令不会访问内存 相当于rbx = rbx + rax + 1
lea rbx, qword ptr [rbx + rax + 1]
lea rbx, qword ptr [rbx + rax + 1]
lea rbx, qword ptr [rbx + rax + 1]
lea rbx, qword ptr [rbx + rax + 1]
lea rbx, qword ptr [rbx + rax + 1]
lea rbx, qword ptr [rbx + rax + 1]
lea rbx, qword ptr [rbx + rax + 1]
lea rbx, qword ptr [rbx + rax + 1]
lea rbx, qword ptr [rbx + rax + 1]
lea rbx, qword ptr [rbx + rax + 1]

# reduce the entropy in rbx
# rbx的结果要么是0要么是0x40
and rbx, 0b1000000

cmp rbx, 0
je .l1  # misprediction  如果 rbx == 0  跳转到 .l1
.l0:
    # rbx != 0
    mov rax, qword ptr [r14 + rax]
jmp .l2
.l1:
    # rbx == 0
    #mov rax, qword ptr [r14 + 64]
.l2:
mfence

.test_case_exit:
