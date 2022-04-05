# Lab 1-1

We are given a potentially malicious .exe and .dll file and tasked to fingerprint them. Since this is the first chapter, we'll just be doing basic static
analysis.

**1. Upload the Lab01-02.exe file to http://www.VirusTotal.com/. Does it match any existing antivirus definitions?**

Since we're using an instance of Flare VM that's not connected to the internet, we can't upload these files directly. However, we can hash them using
HashCalc (found in Flare/Utilities), then copy these hashes and check them on VirusTotal using VirtualBox's Guest -> Host clipboard transfer.

<p align="center">
  <img src="https://user-images.githubusercontent.com/86139991/161679931-19d02a1c-94c4-4f1a-922b-1de65614b7bb.PNG"/>
</p>

<p align="center">
  <b>Figure 1:</b> Calculating the hash of the potentially malicious .exe file using HashCalc
</p>

Dropping this md5 hash into VirusTotal tells us that this file is very definitely malicious. Interestingly, many detectors identify this as a clicker.

<p align="center">
  <img src="https://user-images.githubusercontent.com/86139991/161680015-07d7f6da-c5dc-4206-b76e-de211e9638c8.PNG"/>
</p>

<p align="center">
  <b>Figure 2:</b> The majority of the engines used by VirusTotal detecting the md5 hash of the .exe as malicious.
</p>

**2. Are there any indications that this file is packed or obfuscated? If so, what are these indicators? If the file is packed, unpack it if possible**

## Detecting the packer

As usual, we will use `strings` to check for human-readable strings and PEView to check for imports. Lots of legible strings or imports could indicate that
this file is not packed; few strings and imports would suggest the opposite.

Running `strings` on the .exe file gives very few strings (mostly DLL imports). However, there are also some lightly obfuscated strings, 
including parts of a URL:

<p align="center">
  <img src="https://user-images.githubusercontent.com/86139991/161680691-724c2d90-1d20-4984-9a6c-60fe32de5a0d.png"/>
</p>

<p align="center">
  <b>Figure 3:</b> The human-readable strings found in the file
</p>

There are two major indicators that this file is packed. First, the presence of clearly obfuscated strings is a dead (if uncommon) giveaway. Second, the few
DLL functions that are imported are those that could be used to allocate space for and run code in memory. Functions like `VirtualAlloc` 
(to allocate memory), `VirtualProtect` (to set memory as writable and executable), and LoadLibraryA (to dynamically load DLLs) are often giveaways that
code is being written into memory and executed. However, the lack of process-related imports like `WriteProcessMemory` and `CreateRemoteThread` suggest
that more advanced techniques, like process hollowing, are not used.

To confirm our suspicion that this file is packed, let's use Detect It Easy, a fantastic packer detecter inclded with Flare VM:

<p align="center">
  <img src="https://user-images.githubusercontent.com/86139991/161681283-2184c952-ad6a-4e45-baa0-be3578177410.PNG"/>
</p>

<p align="center">
  <b>Figure 4:</b> Running Detect It Easy suggests the packer that might be used to obfuscate this malware.
</p>

Bingo -- DIE detects that this malware was packed with the common packer UPX.

## Unpacking the file

Now that we know which packer is used, we can try to unpack the malware into a more understandable form. Luckily, since UPX is such a common packer,
there are many tools that can unpack it for us. We will use `upx`, the convenient command-line program that ships with Flare VM.

Running `upx` with the `-d` flag to decompress and the `-o` flag to indicate an output file, we can unpack the malware easily:

<p align="center">
  <img src="https://user-images.githubusercontent.com/86139991/161682016-7cef1bba-5f9c-4ab6-a9b3-fae500c64361.PNG"/>
</p>

<p align="center">
  <b>Figure 5:</b> UPX allows us to easily extract the malware into a more readable form
</p>

**4. Do any imports hint at this program’s functionality? If so, which imports are they and what do they tell you?**

Now that we've unpacked the malware, we can use `strings` and `PEView` to get useful information:

<p align="center">
  <img src="https://user-images.githubusercontent.com/86139991/161682668-b01dee96-8f5f-4903-8c81-ec789ff906ea.PNG"/>
</p>

<p align="center">
  <b>Figure 6:</b> Now that the malware is in the clear, `strings` provides much more helpful output
</p>

Just from `strings`, we can make several inferences as to the malware's actions:

- The imports related to services are likely a means for the malware to establish persistence, and the string `MalService` is likely the name of this
service. 
- The function `InternetOpenA`, together with the URL, the Internet Explorer string, and the VirusTotal identifications as a clicker suggest that this
malware might attempt to open this website with an Internet Explorer webagent. This could be deviously used for authors of a malware analysis book to
boost traffic to their site. The functions related to threads might suggest that these browser processes run in a separate thread.
- Furthermore, the functions `CreateWaitableTimerA` and `SetWaitableTimer` suggest that this URL might be opened repeatedly based on a timer.
- Finally, `GetModuleFileNameA` and `SystemTimeToFileTime` are a bit strange, but they might indicate that the malware runs or does not run based on some
timestamp.

For completion's sake, we can view the Import Address Table in PEView to confirm these imports, but in this case we will gain no information we didn't get
from `strings`:

<p align="center">
  <img src="https://user-images.githubusercontent.com/86139991/161683510-842d4ad8-319d-4140-9d51-ad44dcc6f56b.PNG"/>
</p>

<p align="center">
  <b>Figure 7:</b> The imported functions shown in PEView support the conclusions we drew from `strings`.
</p>

**4. What host- or network-based indicators could be used to identify this malware on infected machines?**

This time, we have both host- and network-based indicators of compromise: the service MalService that is used for persistence, and the url
`https://malwareanalysisbook.com` that the malware likely attempts to connect to. Furthermore, just for safety (and because the useragent is rare nowadays)
we might look for outgoing traffic with the useragent `Internet Explorer 8.0`.

From the strings and VirusTotal classifications, we can therefore guess that this is likely a clicker made to farm site views on a nefarious malware
analysis book's website.
