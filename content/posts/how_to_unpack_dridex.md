+++
title = "How to ? - Unpack Dridex"
date = 2023-07-30
description = "A quick example of how to unpack Dridex"
tags = [
   "Malware",
   "Training",
   "How to ?"
]
+++

# How to ? - Unpack Dridex

Dridex a banking Trojan that first appeared in 2014. It is "an evasive, information-stealing malware variant; its goal is to acquire as many credentials as possible and return them via an encrypted tunnel to a Command-and-Control (C&C) server. These C&C servers are numerous and scattered all over the Internet, if the malware cannot reach one server it will try another. For this reason, network-based measures such as blocking the C&C IPs is effective only in the short-term."

Load the file into PEStudio :

![](/images/dridex_pestudio_1.png)

First we can see a high entropy and the debugger stamp is set in 2038.

![](/images/dridex_pestudio_2.png)

Some interesting strings.

![](/images/dridex_pestudio_3.png)

There is a suspicious `.text1` section

![](/images/dridex_pestudio_4.png)

The size of code is detected as 0 bytes. Which is also an indicator of a packed sample. The file-checksum is zeroed and does not match the expected value.

Now load the sample in x32dbg and put a breakpoint on the following functions :

- `VirtualAlloc` : Imported from `Kernel32.dll`. *Injection*. `VirtualAlloc` is often used by malware to allocate memory as part of process injection.
- `VirtualProtect` : Imported from `Kernel32.dll`. *Injection*. `VirtualProtect` is often used by malware to modify memory protection (often to allow writing or execution).
- `CreateProcessinternalW` : Imported from `Kernel32.dll`. *Injection* and *Evasion*. `CreateProcessInternal` is an undocumented API for process creation. According to Windows Internals, `CreateProcess` and `CreateProcessAsUser` actually lead to this API, which is responsible for starting the process creation in user land. Eventually it calls `NtCreateUserProcess` for the kernel land operations. This API is commonly used for spawning a suspended process to be hollowed/injected.

![](/images/dridex_x32dbg_1.png)

![](/images/dridex_x32dbg_2.png)

Follow the EAX dump until you find something that looks like a PE file loaded in memory like above.

![](/images/dridex_x32dbg_3.png)

Continue and break again, you might get the same file loaded in memory but with a twist.

![](/images/dridex_x32dbg_4.png)

If you scroll down enough, you will find what is to look like a mapped executable. There is a very high probability that it’s going to overwrite itself.

![](/images/dridex_x32dbg_6.png)

If you continue to play with the debugger, you can find another PE file that is loaded into memory completely different from the other. It can be a decoy or a needed DLL by the malware.

In order to properly unpack the malware, we need to find a `jmp EAX` after all the `VirtualProtect` call :

![](/images/dridex_x32dbg_7.png)

If you take the jump, you hit the entrypoint of the dridex loader :

![](/images/dridex_x32dbg_8.png)

The 2 pushed value are the hashing routine, one for the API to load and then for the DLL to load. 
Open Process Hacker, find the binary attached to x32dbg and the `0x1000000000` memory region.

![](/images/dridex_procexp_1.png)

You can now dump dridex. However, if you load it into PE-bear the IAT is broken, it's normal. We dumped a binary file already mapped into memory. The imports can't be resolved that way. We need to correct before to push further the analysis.

For that, you need to adapt the Raw Address related to the Virtual Address. For the last section, just allocate enough to fill the rest with memory.

![](/images/dridex_pebear_1.png)

After that you get an exploitable binary file with a visible IAT, imports and exports :

![](/images/dridex_pebear_2.png)

![](/images/dridex_pebear_3.png)
