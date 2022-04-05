# Lab 1-1

We are given a potentially malicious .exe and .dll file and tasked to fingerprint them. Since this is the first chapter, we'll just be doing basic static
analysis.

**1. Upload the files to http://www.VirusTotal.com/ and view the reports. Does either file match any existing antivirus signatures?**

Since we're using an instance of Flare VM that's not connected to the internet, we can't upload these files directly. However, we can hash them using
HashCalc (found in Flare/Utilities), then copy these hashes and check them on VirusTotal using VirtualBox's Guest -> Host clipboard transfer.

<p align="center">
  <img src="https://user-images.githubusercontent.com/86139991/161670177-ca4a19ec-773d-4c45-bc5c-49fa64edf53f.PNG"/>
</p>

<p align="center">
  <b>Figure 1:</b> Calculating the hash of the potentially malicious .exe file using HashCalc
</p>

Dropping this md5 hash into VirusTotal gives us immediate results: over 2/3rds of the detectors used detect the .exe as malicious, though few of them
give us detailed information about the malware contained within:

<p align="center">
  <img src="https://user-images.githubusercontent.com/86139991/161670697-89e401bd-baf3-4287-8351-3d8f9e89d542.PNG"/>
</p>

<p align="center">
  <b>Figure 2:</b> The majority of the engines used by VirusTotal detecting the md5 hash of the .exe as malicious.
</p>

Hashing and uploading the suspected .dll gives us very similar results.

**2. When were these files compiled?**

To check the compile times, we will use PEView to inspect the headers of the .exe. Specifically, we will look at the Time Date Stamp field of the
IMAGE_FILE_HEADER:

<p align="center">
  <img src="https://user-images.githubusercontent.com/86139991/161671795-a661acac-b0b5-4858-8b2f-8240abedbb17.PNG"/>
</p>

<p align="center">
  <b>Figure 3:</b> The header viewed in PEView that tells us the .exe's compile time.
</p>

From this header, we can see that the .exe was compiled on 2010/12/19 (assuming the malware authors didn't mess with the header, which is often the case).

We can open the suspected .dll as well (note for first-time users: you will have to change the filetype in the selector of PEView to .dll to open this file)
and find that the .dll was also compiled on this date.

**3. Are there any indications that either of these files is packed or obfuscated? If so, what are these indicators?**

We will check two things to see whether the files are obfuscated. First, we will use `strings` to check for human-readable strings inside the files. Second,
we will use PEView to view the Import Address Table of each file. This will tell us which functions the files import from DLLs, which will give us important
hints as to what the files do.

Running `strings` on the .exe file gives a lot of garbage (as should be expected), but also some legible output:

<p align="center">
  <img src="https://user-images.githubusercontent.com/86139991/161676649-510b1702-88d2-420b-a4e6-6c1e508f1085.PNG"/>
</p>

<p align="center">
  <b>Figure 4:</b> The human-readable strings found in the .exe file
</p>

Since these strings seem to be relevant to more than just unpacking, their presence suggests that the .exe file is not packed.

Checking the Import Address Table in PEView also gives us a robust list of imported functions, again suggesting the file is not packed:

<p align="center">
  <img src="https://user-images.githubusercontent.com/86139991/161676851-1e90efe5-3e03-48c3-9fbe-9a3d131f7994.PNG"/>
</p>

<p align="center">
  <b>Figure 5:</b> The DLL imports of the .exe file
</p>

These strings an imports, apart from suggesting that the .exe is not packed, give us valuable insight into what this malware might do. The presence of
the string `C:/*`, together with several DLL functions that involve file operations, suggest that the .exe will perpetrate some nonsense on our files.
Furthermore, the unsubtle `WARNING_THIS_WILL_DESTROY_YOUR_COMPUTER` suggests that whatever it will do with these files will be bad for us.

The .exe also includes the string for this lab's .dll. Nonstandard .dll's by any malware included are always worth looking at, since they can often contain
a lot of the program's functionality. And indeed, running `strings` on the .dll gives us more useful information:

<p align="center">
  <img src="https://user-images.githubusercontent.com/86139991/161677371-166c3f66-9578-460e-b7a8-fabe71fd75a6.PNG"/>
</p>

<p align="center">
  <b>Figure 6:</b> The human-readable strings in the .dll file
</p>

We can see a few more DLL imports, as well as our most valuable information yet: an IP address. This might be the address of a Command & Control (C2) server
the malware connects to and receives instructions from. This theory is supported by the presence of WS2_32.dll, which is the main Windows interface for
opening network sockets.

**4. Do any imports hint at what this malware does? If so, which imports are they?**

We have already covered this a little, but we can dig into it a little further. The .exe file has several imports related to searching for and reading files
-- `CreateFileA`, `FindFirstFileA`, `MapViewOfFileA`, and so on. The malware could use these to read and edit files. Based on the presence of the string 
`C:/*`, it seems likely that the malware iterates over all files on the `C:` drive. These functions suggest the malware might read files, either to corrupt
them or to exfiltrate them to the C2 server referenced in the .dll.

The .dll file doesn't include incredibly insightful imports, but does contain the reference to MS2_32.dll, which tells us that this malware will do some
things over the network, likely related to the IP address we found.

**5. Are there any other files or host-based indicators that you could look for on infected systems?**

There is an interesting string we have so far overlooked, but which would be a dead giveaway that a computer is infected with this malware. This is the
string `C:\windows\system32\kerne132.dll`, which is disguised to be similar to the standard `kernel32.dll`. Since the malware comes with a .dll, it is
possible that it replaces `kernel32.dll` with its own DLL, allowing it to intercept calls to core kernel functions, and back up the true `kernel32.dll`
to this obfuscated file. It is also possible that the malware simply corrupts `kernel32.dll` and saves the true version, which would be a very effective
method of DESTROYING_OUR_COMPUTER.

**6. What network-based indicators could be used to find this malware on infected machines?**

Knowing what we know from `strings`, this is very simple: check for traffic to or from the IP address we found in the .dll.

**7. What would you guess is the purpose of these files?**

Based solely on the strings found in the .exe, it would seem that this is purely destructive malware. One might guess that it recursively opens files in the
C: drive and corrupts them. However, the presence of an IP address and networking components in the .dll suggests that this is not the only purpose -- after
all, there would be no point in connecting to a destroyed computer. Instead, the malware might act as spyware, stealing our files and uploading them to the
C2. Of course, it's also possible that the malware lies latent, and the C2 server only exists to give the command to wipe our computer.

From the strings and DLL imports in the two files, we can therefore guess that this is either spyware, a wiper, or both.
