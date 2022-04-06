# Lab 1-3

We are given a potentially malicious .exe file and tasked to fingerprint it. Since this is the first chapter, we'll just be doing basic static
analysis.

**1. Upload the Lab01-04.exe file to http://www.VirusTotal.com/. Does it match any existing antivirus definitions?**

Since we're using an instance of Flare VM that's not connected to the internet, we can't upload these files directly. However, we can hash them using
HashCalc (found in Flare/Utilities), then copy these hashes and check them on VirusTotal using VirtualBox's Guest -> Host clipboard transfer.

<p align="center">
  <img src="https://user-images.githubusercontent.com/86139991/161877712-3505e62c-9681-4c18-b0b5-9768a17b90e6.PNG"/>
</p>

<p align="center">
  <b>Figure 1:</b> Calculating the hash of the potentially malicious .exe file using HashCalc
</p>

Dropping this md5 hash into VirusTotal tells us the file is malicious. This time, the file is identified as a dropper -- a program whose purpose is to
download and run other malware.

<p align="center">
  <img src="https://user-images.githubusercontent.com/86139991/161877915-027b3f96-020f-4030-ab17-704e511d885f.PNG"/>
</p>

<p align="center">
  <b>Figure 2:</b> The majority of the engines used by VirusTotal detecting the md5 hash of the .exe as malicious.
</p>

**2. Are there any indications that this file is packed or obfuscated? If so, what are these indicators? If the file is packed, unpack it if possible.**

We will start with our usual `strings`. Lots of legible strings or imports could indicate that
this file is not packed; few strings and imports would suggest the opposite.

Unlike the last two labs, we get an abundance of strings. This is a very strong indicator that at least part of the malware is unpacked:

<p align="center">
  <img src="https://user-images.githubusercontent.com/86139991/161878393-ae34be75-3417-4f27-a79d-37f4e1ffa897.png"/>
</p>

<p align="center">
  <b>Figure 3:</b> This time, a much more reasonable number of human-readable strings are found in the file
</p>

Just to make sure, we can throw the file at Detect It Easy. And indeed, no packer is detected. However, it is slightly interesting that the standard PE
header strings -- `Rich`, `.rdata`, and so on -- are found twice throughout the file. This suggests that another PE might be Matryoshka dolled inside this
file.

**3. When was this program compiled?**

To check the compile time, we could use PEView to look at the IMAGE_NT_HEADERS and inspect the timestamp. However, Detect It Easy extracts this information
for us:

<p align="center">
  <img src="https://user-images.githubusercontent.com/86139991/161878864-3b54ce39-ccf8-4e05-ac82-9160363e9cb9.PNG"/>
</p>

<p align="center">
  <b>Figure 4:</b> Detect It Easy tells us the stated compile time, as well as identifying packers.
</p>

The headers tell us that this file was compiled on 2019/08/30. This is somewhat suspicious, given that Practical Malware Analysis came out in 2012. Thus we
can either conclude that this malware has been recompiled recently, or that the compile time is faked (which is not uncommon).

**4. Do any imports hint at this program’s functionality? If so, which imports are they and what do they tell you?**

We have a vast number of imported functions which hint at the malware's functionality:

- First off, the "dropper" identifications from VirusTotal and the presence of `URLDownloadToFile` strongly suggest that this malware will download more files
-- likely from the included URL `http://www.practicalmalwareanalysis.com/updater.exe`
- `WinExec` suggests that the downloaded file is then executed
- Several files related to privileges, such as `AdjustTokenPrivileges`, `LookupPrivilegeValueA`, and `SeDebugPrivilege` suggest that the malware attempts to
escalate its privileges
- Functions like `OpenProcess`, `GetProcAddress`, `CreateRemoteThread`, and `EnumProcesses` suggest that the malware will run and possibly edit other
processes
- The resource functions `FindResourceA` and `LoadResource` suggest that this .exe has resources, which means we should probably look at it with Resource
Hacker later
- Finally, file-related functions like `CreateFileA`, `WriteFile`, `GetTempPathA`, and `MoveFile` suggest that the malware will create new files (possibly in
the temp directory) and move them

Altogether, the imported functions suggest that this malware attempts to escalate its privileges, then downloads and runs other files, likely in new
processes.

**5. What host- or network-based indicators could be used to identify this malware on infected machines?**

The most obvious network-based indicator is traffic to to and from the included URL `http://www.practicalmalwareanalysis.com/updater.exe`.

As far as host-based indicators, the presence of the downloaded `updater.exe` file would be a dead giveaway. However, the functions related to moving files
suggest that the file is likely hidden. The strings `winlogon.exe` and `system/winupdmgr.exe` suggest that the malware might disguise itself as these
well-known files -- or use them to establish persistence. 

**6. This file has one resource in the resource section. Use Resource Hacker to examine that resource, and then use it to extract the resource. What
can you learn from the resource?**

In order to view the included resource, we can open the file in Resource Hacker. This will show there is one resource included:

<p align="center">
  <img src="https://user-images.githubusercontent.com/86139991/161881076-8828c4db-11f6-45d7-bbad-7017f6f913c4.PNG"/>
</p>

<p align="center">
  <b>Figure 6:</b> Resource Hacker shows an included .exe as a resource.
</p>

Aha! Just as we suspected from the multiple copies of header names in `strings`, this .exe hides another .exe inside itself as a resource!

Scrolling through the binary, we can see several strings we detected earlier, including those related to opening the URL. From this, we might guess that
this .exe is run by the initial malware (possibly with elevated privileges) and downloads and runs the file at the URL. There are also a lot of null bytes
in the embedded .exe, which suggests (together with the `WriteFile` function in the first .exe) that code might be written into this by the parent .exe.
This might be done to frustrate static analysis.
