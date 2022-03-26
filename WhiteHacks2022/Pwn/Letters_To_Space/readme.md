##  Challenge Description

> Welcome to our new inter-galactic mail service! Send letters to your loved aliens, and maybe even read a secret letter!
> 
> Note: flag.txt is in the home directory.
>
> [letters_to_space](letters_to_space)

## Identifying the Vulnerability
Running a `checksec` on the binary, we can see that all protections are actually enabled which makes this binary a pain to exploit.
```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Nevertheless, let's run the binary and see how it works.

<script id="asciicast-AxsL2HenIa2NiFR54Ktbb7tRU" src="https://asciinema.org/a/AxsL2HenIa2NiFR54Ktbb7tRU.js" async></script>

As you can see from the video above
