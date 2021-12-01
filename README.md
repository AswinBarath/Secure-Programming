# Secure Programming

Secure Programming

---

## Cyber Security Documentaries

- [How Israel Rules The World Of Cyber Security | VICE on HBO](https://youtu.be/ca-C3voZwpM)
- [WANNACRY: The World's Largest Ransomware Attack (Documentary)](https://youtu.be/PKHH_gvJ_hA)

---

## Setting up Secure Programming Lab

- [Download: VirtualBox](https://www.virtualbox.org/wiki/Downloads)

<p>
<img src="https://upload.wikimedia.org/wikipedia/commons/d/d5/Virtualbox_logo.png" width="200px" >
</p>

- [Download Tutorial: Cisco Packet Tracer](https://www.packettracernetwork.com/download/download-packet-tracer.html)
- [Download: Cisco Packet Tracer](https://www.netacad.com/portal/resources/packet-tracer)

<p>
<img src="https://image.winudf.com/v2/image1/Y29tLm5ldGFjYWQuUGFja2V0VHJhY2VyTV9pY29uXzE1NjY5OTcyODdfMDgx/icon.png?w=&fakeurl=1" width="200px" >
</p>

- [Download: Kali Linux ISO File](https://www.kali.org/get-kali/#kali-live)

<p>
<img src="https://i.stack.imgur.com/Gns38.png" width="200px" >
</p>


### Kali Linux Virtual Box Setup

- [Tutorial: How to Install Kali Linux on VirtualBox](https://www.youtube.com/watch?v=ZXlDkMC9N34)

#### Errors faced while installing Kali Linux

- [Fix: Not in a hypervisor partition (HVP=0) (VERR_NEM_NOT_AVAILABLE) or VT-x is disabled in the BIOS for all CPU modes (VERR_VMX_MSR_ALL_VMX_DISABLED)](https://techsupportwhale.com/not-in-a-hypervisor-partition/)
- [Fix: Cannot install Ubuntu in VirtualBox due to "this kernel requires an x86-64 CPU, but only detects an i686 CPU, unable to boot" error](https://askubuntu.com/questions/308937/cannot-install-ubuntu-in-virtualbox-due-to-this-kernel-requires-an-x86-64-cpu)
- [Fix: Installation Step Failed (installing the system) - Kali Linux](https://unix.stackexchange.com/questions/208772/installation-step-failed-installing-the-system-kali-linux)

---

## Lab 1

**Lab 1: Format String
Vulnerabilities and Attacks**

- **Aim:** Perform the following using programming
    1) Write a secure program by avoiding vulnerable programming factors
    like Eval and printf.
    2) Demonstrate Format string vulnerabilities with example
    3) Demonstrate Format String exploit with example

- **Format String Program**

<img src="./assets/exp1 program.png" alt="Format String Program" width="600px" >

- The format string program accepts the command line arguments and
parses the input using printf function to display output.
- Three types of payloads given as inputs in the following examples

- Payload 1:
<img src="./assets/Secure Programming Exp1 01.PNG" alt="Format String Program" width="600px" >
- Output of Payload 1
<img src="./assets/Secure Programming Exp1 02.PNG" alt="Format String Program" width="600px" >
- Payload 2:
<img src="./assets/Secure Programming Exp1 11.PNG" alt="Format String Program" width="600px" >
- Output of Payload 2
<img src="./assets/Secure Programming Exp1 12.PNG" alt="Format String Program" width="600px" >
- Payload 3:
<img src="./assets/Secure Programming Exp1 21.PNG" alt="Format String Program" width="600px" >
- Output of Payload 3
<img src="./assets/Secure Programming Exp1 22.PNG" alt="Format String Program" width="600px" >


- **Observation:**

- The Safe Code from the program
    - The line printf("%s", argv[1]); in the example is safe, if you compile the program and run it:
    - `./main "%s%s%s%s%s%s"`
    - The printf in the first line will not interpret the “%s%s%s%s%s%s” in
    the input string, and the output will be:
    - `“%s%s%s%s%s%s”`

- The Vulnerable Code from the program
    - The line printf(argv[1]); in the example is vulnerable, if you compile the program and run it:
    - `./main "%s%s%s%s%s%s"`
    - The printf in the second line will interpret the %s%s%s%s%s%s in the input string as a reference to string pointers, so it will try to interpret every %s as a pointer to a string, starting from the location of the buffer (probably on the Stack).
    - At some point, it will get to an invalid address, and attempting to access it will cause the program to crash.

- Different Payloads
    - An attacker can also use this to get information, not just crash the software.
    - For example, running:
    - `./main "%p %p %p %p %p %p"`
    - Will print the lines:
    - `%p%p%p%p%p%p
    0x7fd084a750000x7fd08484f9e00x7fd08457a3c00xffffffff(nil)0x7ffdcd
    0948e8`
    - Another example:
    - `./main "%x%x%x%x%x%x"`
    - Will print the lines:
    - `%x%x%x%x%x%x
    18bfb000189d59e0187003c0ffffffff0e09496f8`
    - The first line is printed from the non-vulnerable version of printf, and the second line from the vulnerable line. The values printed are the values on the stack of my computer at the moment of running this example.
    - Also reading and writing to any memory location is possible in some conditions, and even code execution

- **Result:**
- Format string vulnerabilities and exploits are successfully demonstrated by writing a C program with a secure code and a vulnerable code using printf function and string parameters



---
