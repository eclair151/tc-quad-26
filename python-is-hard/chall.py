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
