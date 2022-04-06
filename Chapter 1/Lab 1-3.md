# Lab 1-3

We are given a potentially malicious .exe file and tasked to fingerprint it. Since this is the first chapter, we'll just be doing basic static
analysis.

**1. Upload the Lab01-03.exe file to http://www.VirusTotal.com/. Does it match any existing antivirus definitions?**

Since we're using an instance of Flare VM that's not connected to the internet, we can't upload these files directly. However, we can hash them using
HashCalc (found in Flare/Utilities), then copy these hashes and check them on VirusTotal using VirtualBox's Guest -> Host clipboard transfer.

<p align="center">
  <img src="https://user-images.githubusercontent.com/86139991/161874261-a2c8e4dc-ca85-4827-acc2-7cb01928e051.PNG"/>
</p>

<p align="center">
  <b>Figure 1:</b> Calculating the hash of the potentially malicious .exe file using HashCalc
</p>

Dropping this md5 hash into VirusTotal tells us that this file is malicious. As with the last lab, many detectors identify this as a clicker.

<p align="center">
  <img src="https://user-images.githubusercontent.com/86139991/161874471-036bcb6f-06bd-4299-9f4f-2aff8d7a61c7.PNG"/>
</p>

<p align="center">
  <b>Figure 2:</b> The majority of the engines used by VirusTotal detecting the md5 hash of the .exe as malicious.
</p>

**2. Are there any indications that this file is packed or obfuscated? If so, what are these indicators? If the file is packed, unpack it if possible.**

## Detecting the packer

We will start with our usual `strings`. Lots of legible strings or imports could indicate that
this file is not packed; few strings and imports would suggest the opposite.

This time, we find even fewer helpful strings. The few function imports we see are the ever-frustrating `LoadLibraryA` and `GetProcAddress` -- often
dead giveaways that the file is packed.

<p align="center">
  <img src="https://user-images.githubusercontent.com/86139991/161875190-260c5831-e639-4da5-96f6-5d2b4a712e53.PNG"/>
</p>

<p align="center">
  <b>Figure 3:</b> The few human-readable strings found in the file
</p>

To confirm our suspicions, let's throw the file at Detect It Easy:

<p align="center">
  <img src="https://user-images.githubusercontent.com/86139991/161875280-2c596564-963e-4fe3-ba22-d39b34d5d0c1.PNG"/>
</p>

<p align="center">
  <b>Figure 4:</b> Detect It Easy confirms our suspicions that the malware is packed.
</p>

As we suspected, the file is packed -- this time with the newer packer FSG.

## Unpacking the file

Once we know the packer, the next obvious step is to unpack the file. To my knowledge, there is no default installed tool on Flare VM to unpack FSG files;
however, some Googling tells us about an unpacker named Unipacker, which can be installed with `pip`.

WARNING: As always, we should fully shutdown our VM and restart with a functional network adapter before installing things from the internet. Once
Unipacker is installed, we can shutdown again, disconnect the network adapter, and -- only then -- begin to analyze. Keeping the box off the internet
while analyzing malware is of utmost importance.

To unpack, we will run `unipacker`, enter `0` for a new project and open our file. Running the informative `aaa` command tells us again that FSG has been
detected, and an unpacker has been prepared:

<p align="center">
  <img src="https://user-images.githubusercontent.com/86139991/161682016-7cef1bba-5f9c-4ab6-a9b3-fae500c64361.PNG"/>
</p>

<p align="center">
  <b>Figure 5:</b> Unipacker tells us that it has a FSG unpacker ready.
</p>

We can then run the command `r` to run the program until it's unpacked and save it to a file:

<p align="center">
  <img src="https://user-images.githubusercontent.com/86139991/161875865-3dbb4e56-2057-44d0-a089-0b1a1280ba47.PNG"/>
</p>

<p align="center">
  <b>Figure 6:</b> Using Unipacker, we can unpack the file in its full glory.
</p>

**3. Do any imports hint at this program’s functionality? If so, which imports are they and what do they tell you?**

Now that we've unpacked the malware, we can use `strings` and `PEView` to get useful information:

<p align="center">
  <img src="https://user-images.githubusercontent.com/86139991/161876143-77f3a763-d01a-4590-9658-5f67ec001577.png"/>
</p>

<p align="center">
  <b>Figure 6:</b> Now that the malware is in the clear, `strings` provides much more helpful output
</p>

This time, the strings are less immediately suggestive. However, combined with the engines' identification of this malware as a clicker, we can draw some
conclusions:

First, importing the dll `ole32.dll` suggests that the malware wants to do something with Microsoft's Component Object Model. A quick Google search
shows that this interface, particularly using the included functions `OleInitialize` and `CoCreateInstance`, can open Internet Explorer and navigate it
to a given URL. This will almost certainly be the URL we found with `strings`. Thus we can guess that this malware functions much the same as the last --
it opens Internet Explorer and feeds views to PMA's ad page.

**4. What host- or network-based indicators could be used to identify this malware on infected machines?**

Unlike the last example, the malware makes no obvious attempt at persistence. Thus finding host-based indicators would be difficult.
However, scanning for traffic to `https://malwareanalysisbook.com/ad.html` -- particularly with an Internet Explorer useragent -- would likely catch the
malware in its tracks.

From the strings and VirusTotal classifications, we can therefore guess that this is another clicker made to farm site views on a nefarious malware
analysis book's website.
