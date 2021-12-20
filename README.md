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

**Lab 1: Format String Vulnerabilities and Attacks**

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

## Lab 2

**DHCP attack, MAC flooding attack and CAM table overflow attack**

- **Aim:** Perform the following
    1) DHCP attack and prevention of DHCP attack
    2) MAC flooding attack 
    3) CAM table overflow attack

- **Notes:**

- **MAC Flooding with MACOF & some major countermeasures**
    - Macof is a member of the Dsniff suit toolset and mainly used to flood the switch on a local network with MAC addresses. 
    - The reason for this is that the switch regulates the flow of data between its ports.
    - It actively monitors (cache) the MAC address on each port, which helps it pass data only to its intended target. 
    - This is the main difference between a switch and passive hub.
    - A passive hub has no mapping, and thus broadcasts line data to every port on the device.
    - The data is typically rejected by all network cards, except the one it was intended for. 
    - However, in a hubbed network, sniffing data is very easy to accomplish by placing a network card into promiscuous mode. This allows that device to simply collect all the data passing through a hubbed network.
    - While this is nice for a hacker, most networks use switches, which inherently restrict this activity.
    - Macof can flood a switch with random MAC addresses. This is called MAC flooding.
    - This fills in the switch’s CAM table, thus new MAC addresses can not be saved, and the switch starts to send all packets to all ports, so it starts to act as a hub, and thus we can monitor all traffic passing through it.
    - Options
    - Syntax: `macof [-i interface] [-s src] [-d dst] [-e tha] [-x sport] [-y dport] [-n times]`
    ```
    -i   interface Specify the interface to send on.
    -s   src Specify source IP address.
    -d   dst Specify destination IP address.
    -e   Specify target hardware address.
    -x   sport Specify TCP source port.
    -y   dport Specify TCP destination port.
    -n   times Specify the number of packets to send.
    ```
    ```
    - `macof `
    - flood a switched LAN with random MAC addresses SYNOPSIS
    - `macof [-i interface] [-s src] [-d dst] [-e tha] [-x sport] [-y dport] [-n times]`
    ```
- LAB 2.2.1: Simple Flooding
    - Macof can flood a switch with random MAC addresses. This is called MAC flooding.
    - This fills in the switch’s CAM table, thus new MAC addresses can not be saved, and the switch starts to send all packets to all ports, so it starts to act as a hub, and thus we can monitor all traffic passing through it.
    - command: `macof -i eth1 -n 10`
- LAB 2.2.2: Targeted Flooding
    - Macof can flood a switch with random MAC addresses destinated to 192.168.1.1.
    - command: `macof -i eth1 -d 192.168.1.1`
    - While conducting a pentest, this tool comes in handy while sniffing.
    - Some switches don’t allow to spoof arp packets.
    - This tool can be used in such situations to check if the switch is overloaded. Some switches behave like hubs, transmitting all source packets to all destinations.
    - Then sniffing would be very easy.
    - Some switches tend to crash & reboot also.
    - Such kind of layer 2 stress testing can be done with this handy tool.

- **Countermeasures**
- Some of the major countermeasures against MAC Flooding are:
    1) Port Security : Limits the no of MAC addresses connecting to a single port on the Switch.
    2) Implementation of 802.1X : Allows packet filtering rules issued by a centralised AAA server based on dynamic learning of clients.
    3) MAC Filtering  : Limits the no of MAC addresses to a certain extent.

---

- **Resources** :

1) DHCP attack and prevention of DHCP attack 
- [DHCP Snooping using Packet Tracer (YouTube Tutorial)](https://youtu.be/yz8DKkjuNYc)
- [Protecting against DHCP attacks using a Cisco switch (YouTube Tutorial)](https://youtu.be/JWW4qAJJov4)
- [Cisco CCNA Packet Tracer Ultimate labs: DHCP Snooping: Answers Part 1  (YouTube Tutorial) - David Bombal](https://youtu.be/u3EmleryJ9A)
- [Cisco CCNA Packet Tracer Ultimate labs: DHCP Snooping: Answers Part 2  (YouTube Tutorial) - David Bombal](https://youtu.be/fogXBd9_Kl8)

2) MAC flooding attack (lab) 
- [MACOF attack - article](https://kalilinuxtutorials.com/macof/)
- [Kali Linux MAC flood attack (YouTube Tutorial)](https://youtu.be/ZPfDeT-QN1s)

3) CAM Table Overflow Attack (lab) 
- [CAM Overflow attack With Kali Linux and GNS3 (YouTube Tutorial)](https://youtu.be/WjZiuy_fa1M)

4) Additional resources -

- [DHCP Explanation (Youtube Tutorial)](https://www.youtube.com/watch?v=CVGUZ2XdX70)
- [DHCP Simulation - GitHub Repo](https://github.com/saravana815/dhtest) 
- [Simulation tools - Article](https://geekflare.com/cyberattack-simulation-tools/) 
- [Simulation tools - Resource](https://resources.sei.cmu.edu/library/asset-view.cfm?assetid=641262)
- MAC flooding 
    - [Kali Linux CAM Table Overflow Demo - Article](https://networkwizkid.com/2017/02/01/kali-linux-cam-table-overflow-attack-demonstration/)
    - [MAC flooding lab - Article](https://yaser-rahmati.gitbook.io/cisco-ccnp-r-s-300-115-switch/lab-mac-address-flooding#3-3-how-to-do)
- [CAM Table Overflow Attack Explained - Article](https://www.cbtnuggets.com/blog/technology/networking/cam-table-overflow-attack-explained)


---

## Lab 3

**Defeating malware**

- **Note:** *I installed Windows 10 Virtual Machine on my VirtualBox to work safely with malware in a sandbox environment.*

- **Aim:**  Defeating malware through 
    1) Building trojans
    2) Scan for Rootkits, backdoors 
    3) Exploits Using Rootkit Hunter

- **A) AIM:** To build a Trojan and know the harmness of the trojan malwares in a computer system.  

- **Notes on Trojan:**

- In computing, a Trojan horse or simply trojan is any malware which misleads users of its true intent.
- The term is derived from the Ancient Greek story of the deceptive Trojan Horse that led to the fall of the city of Troy.
- In computing, a Trojan horse, or trojan, is any malware which misleads users of its true intent.  
-	Trojans may allow an attacker to access users' personal information such as banking information, passwords, or personal identity 
- Trojans are generally spread by some form of social engineering, for example where a user is duped into executing an email attachment disguised to appear not suspicious, (e.g., a routine form to be filled in), or by clicking on some fake advertisement on social media or anywhere else. Although their payload can be anything, many modern forms act as a backdoor, contacting a controller which can then have unauthorized access to the affected computer.
- Example: Ransomware attacks are often carried out using a trojan.
- Unlike computer viruses, worms, and rogue security software, trojans generally do not attempt to inject themselves into other files or otherwise propagate themselves.

- **PROCEDURE:**
1. Create a simple trojan by using Windows Batch File (.bat) 
2. Type these below code in notepad and save it as Trojan.bat 
3. Double click on Trojan.bat file. 
4. When the trojan code executes, it will open MS-Paint, Notepad, Command Prompt, Explorer, etc., infinitely.
5. Restart the computer to stop the execution of this trojan.  

- **CODE:** 

```
Trojan.bat @echo off 
:x
start mspaint 
start notepad 
start cmd 
start explorer 
start control 
start calc 
goto x   
```

- **OUTPUT:** 

*(MS-Paint, Notepad, Command Prompt, Explorer will open infinitely)*

- **RESULT:** 
- Thus a trojan has been built and the harmness of the trojan viruses has been explored.

--

- **B) AIM:**  To install a rootkit hunter and find the malwares in a computer by scanning for rootkits, backdoors then Exploits Using Rootkit Hunter

- **Notes on Rootkit Hunter:**
-  **ROOTKIT HUNTER:**
-	rkhunter (Rootkit Hunter) is a Unix-based tool that scans for rootkits, backdoors and possible local exploits. 
-	It does this by comparing SHA-1 hashes of important files with known good ones in online databases, searching for default directories (of rootkits), wrong permissions, hidden files, suspicious strings in kernel modules, and special tests for Linux and FreeBSD.
-	rkhunter is notable due to its inclusion in popular operating systems (Fedora, Debian, etc.) 
-	The tool has been written in Bourne shell, to allow for portability. It can run on almost all UNIX-derived systems.  

- **GMER ROOTKIT TOOL:**
-	GMER is a software tool written by a Polish researcher Przemysław Gmerek, for detecting and removing rootkits.
-	It runs on Microsoft Windows and has support for Windows NT, 2000, XP, Vista, 7, 8 and 10. With version 2.0.18327 full support for Windows x64 is added.

- **PROCEDURE:**
- *STEP 1:* Visit GMER's website (see Resources) and download the GMER executable. Click the "Download EXE" button to download the program with a random file name, as some rootkits will close “gmer.exe” before you can open it.
- <img src="./assets/Secure Programming Exp3 step 1.png" alt="Step 1" width="600px" />
- *STEP 2:* Click the "Scan" button in the lower-right corner of the dialog box. Allow the program to scan your entire hard drive.
- <img src="./assets/Secure Programming Exp3 step 2.png" alt="Step 2" width="600px" />
- *STEP 3:* If the red item is a service, it may be protected. Right-click the service and select "Disable." Reboot your computer and run the scan again, this time selecting "Delete" when that service is detected. When your computer is free of Rootkits, close the program and restart your  PC.  
- <img src="./assets/Secure Programming Exp3 step 3.png" alt="Step 3" width="600px" />

- **RESULT:** 
- In this experiment a rootkit hunter software tool has been installed and the rootkits have been detected.

--

- **Resources** :
- [How to Install Windows 10 on VirtualBox (YouTube Tutorial)](https://youtu.be/JT8EXoobjSc)

---

## Lab 4

**Buffer Overflow 1**

- **Resources** :


---

## Lab 5

**Buffer Overflow 2**

- **Resources** :


---

## Lab 6

**OWASP**

- **Resources** :
- [OWASP Juice Shop (YouTube Tutorial)](https://www.youtube.com/watch?v=JI1JX0lpwNw)
- [OWASP Juice Shop (GitHub Repo)](https://github.com/juice-shop/juice-shop)


---

## Lab 7

**Web Application Assessment using i) OpenVAS ii) Vega iii) skipfish iv) Wapiti**

- **Resources** :
- [i) OpenVAS](https://www.youtube.com/watch?v=koMo_fSQGlk)
- [ii) Vega](https://www.youtube.com/watch?v=aPtJ3spzTww)
- [iii) skipfish](https://www.youtube.com/watch?v=YKILueSxLR0)
- [iv) Wapiti](https://www.youtube.com/watch?v=aPtJ3spzTww)



---

## Lab 8

**Cache poisoning**

- **Resources** :
- [What is DNS cache poisoning? | DNS spoofing](https://www.cloudflare.com/en-in/learning/dns/dns-cache-poisoning/)
- [DNS cache poisoning (Youtube Tutorial 1)](https://www.youtube.com/watch?v=1d1tUefYn4U)
- [DNS cache poisoning (Youtube Tutorial 2)](https://www.youtube.com/watch?v=c76GbfM_QsI)
- [DOS using ARP cache poisoning](https://www.youtube.com/watch?v=8SIP36Fym7U)


---

## Lab 9

**SQL Injection**

- **Resources** :
- [Refer "Experiment 9 lab material" document](#)

---

## Lab 10

**XSS Attack**

- **Resources** :
- [XSS Attack (Youtube Tutorial)](https://www.youtube.com/watch?v=oEFPFc36weY)


---

## Lab 11

**Injection attacks using webgoat**

- **Resources** :
- [XPath injection using web goat (Youtube Tutorial)](https://www.youtube.com/watch?v=C_-ea63FUto)
- [OWASP BWA WebGoat Challenge: Injection Flaws](https://spencerdodd.github.io/2017/01/30/webgoat_part_10_continued_continued/)


---

## Lab 12

**Advanced Client-Side Exploitation using BeEF**

- **Resources** :
- [Client-Side Exploitation using BeEF (Youtube Tutorial)](https://www.youtube.com/watch?v=8GNzd7EL978)
- [BeEF official website](https://beefproject.com/)



---
