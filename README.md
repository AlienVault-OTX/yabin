# What is this?

Yabin creates Yara signatures from executable code within malware.
Given one sample of malware, you can then find other samples that share code.

It does this by looking for rare functions in a given malware sample.
It identifies functions by looking for common function "prologs" which define the start of functions (eg; 55 8B EC will often indicate the
start of a function in software compiled by Microsoft Visual Studio).
A whitelist taken from 100 Gb of non-malicious software is used to ignore common library functions.

Yabin is a *prototype* testing out an approach - rather than intended for production use.

# Running Yabin
A whitelist is included in the repository, but it's recommended you download the larger one (140Mb) from
[here](https://drive.google.com/file/d/0B8YfXb5yEBbZYjZ0VlhucUpHZlk/view?usp=sharing) and replace db.db.
 
More detailed information is below, but the help command provides an overview: 
 
```
 python yabin.py --help
 usage: yabin.py [-h] [-y YARA] [-yh YARAHUNT] [-d] [-w ADDTOWHITELIST]
                 [-f FUZZYHASH] [-m MALWAREADD] [-s MALWARESEARCH]
 
 Yabin - Signatures and searches malware
 
 optional arguments:
   -h, --help            show this help message and exit
   -y YARA, --yara YARA  Generate yara rule for the file or folder
   -yh YARAHUNT, --yaraHunt YARAHUNT
                         Generate wide yara rule (any of, not all of). Useful
                         for hunting for related samples or potentially
                         malicious files that share any of the code - but
                         liable to false positive
   -d, --deleteDatabase  Empty the whitelist and malware database
   -w ADDTOWHITELIST, --addToWhitelist ADDTOWHITELIST
                         Add a file or folder to the whitelist
   -f FUZZYHASH, --fuzzyHash FUZZYHASH
                         Generate a bad fuzzy hash for the file
   -m MALWAREADD, --malwareAdd MALWAREADD
                         Add malware file or folder to malware database to be
                         searched
   -s MALWARESEARCH, --malwareSearch MALWARESEARCH
                         Search for samples related to this file

```

# Generate Yara rules for malware

Yabin can create signatures for malware based on the rare functions they have.

For example:
```
python yabin.py -y StarsyPound_malware.bin
```

Creates the following yara rule:

```
rule StarsyPound_malware
{
strings:
    $a_2 = { 558b6c24145685ed578bf57e208b5c24 }
    $a_3 = { 558b6c24145633f6b30185ed7e24578b }
    $a_4 = { 558bec6aff685021400068601e400064 }
condition:
    3 of them
}
```

Which can be used to then identify similar samples of
malware. If you are looking for a more mature Yara rule generator see [YaraGen](https://github.com/Neo23x0/yarGen)
 and [BASS](https://github.com/Cisco-Talos/bass).

# Hunt for code re-use amongst malware

It is common to want to find malware samples that share code.
Perhaps you are researching a malware family and want to find more sample you don't know about yet.
Perhaps you want to hunt for suspicious binaries that exist on your network, and want to look at any file that shares code with a set of malware.

## Example

I generated a hunt yara rule for a sample of WannaCry like so:

```
python yabin.py -yh 3e6de9e2baacf930949647c399818e7a2caea2626df6a468407854aaa515eed9 > wanna.rule

rule hunt_558b6c241056576a208b45008d750424 {
    // File: 3e6de9e2baacf930949647c399818e7a2caea2626df6a468407854aaa515eed9
    strings:
        $a_1 = { 558b6c241056576a208b45008d750424 }
    condition:
        all of them
}
```

Running these against a database of malware samples shows a match
for [a sample](https://virustotal.com/%23/file/766d7d591b9ec1204518723a1e5940fd6ac777f606ed64e731fd91b0b4c3d9fc/details) of Contopee.
Contopee is a family of malware associated with a very interesting group of attackers called 
[Lazarus](https://otx.alienvault.com/adversary/Lazarus%2520Group/pulses/)
that are likely based out of North Korea.

However I didn't find this - that credit goes to Neel Mehta of Google and 
[further findings](https://www.symantec.com/connect/blogs/wannacry-ransomware-attacks-show-strong-links-lazarus-group) by Symantec.
The same group of attackers were also linked to attacks against the global SWIFT banking network by 
[other](http://news.softpedia.com/news/swift-bank-attacks-connected-to-north-korean-group-behind-sony-hacks-504538.shtml) code re-use.

## Another example

I ran Yara rules for possible code overlaps from Lazarus
against VirusTotal - there were a very large number of potentially related
samples.
The very first sample to match was 
[1db61ae18c85d6aca77a4a3800af07b4](https://virustotal.com/en/file/2dc4d045b8a0c66dc003a0c92c8305c53b7fc8f7b7347befdf59d4b16e26135a/analysis/).

It's a worm has been spreading since 2009 via SMB brute-forcing.
This worm might be written by Lazarus.
Or it might just share code from a common base, library or coincidence.
Further analysis would be required to confirm which is the case.

## Hunting for related samples in practice

Even with a large whitelist, it's likely some of the re-used
functions you're searching for are non malicious libraries. I'd recommend running
the Yara hunt rule against a small data-set, then prune any false positives,
before running across a large malware corpus.

When used with VirusTotal Intelligence this means running
the rules for a brief period, then pruning ones that false positive before
either leaving them running or running a retro-hunt.

If you're interested in identifying code re-use, you may
also like [Binarly](https://github.com/binarlyhq/binarly-query)
(now owned by Crowdstrike) / [VXClass](https://static.googleusercontent.com/media/www.zynamics.com/en//downloads/inbot10-vxclass.pdf)
/ [Intezer](http://www.intezer.com/) / [MalTindex](https://github.com/joxeankoret/maltindex) / [IceWater](http://icewater.io/en/hash/detail?in_hash=6310ef39464087abdc7d7251a9bce30a).

# Clustering Malware
Yabin does an "ok" job of clustering malware based on code re-use.
I generated Yara rules with Yabin for 300 samples from the attackers known as APT1.

Below you can see the results of running the Yara rules against the set, when displayed in Maltego:


## Tight Yara rules - python yabin.py -y
![](./examples/image001.png)

This shows samples with significant overlaps. For example the group at the top left are
all from the malware family "Starsypound". Many files (not shown) dont match
any other files.


## Hunt Yara rules : python yabin.py -yh
![](./examples/image002.png)

This shows samples with any overlapping code. The malware samples are significantly
more interconnected, and clusters contain a number of different malware
families.

You can view this data in the ./examples/ folder.

# Limitations

Yabin is designed to work on unpacked executables.

If you run it against packed samples, it won't be able to
signature the sample, but it may signature the packer.

The function prologs built in (stored in regex.txt) are
designed to cover VC++, Borland and MingW compilers.

Yabin isn't designed to work on .NET executables, Java
software, Word documents etc.

It might be possible to do this by extending the patterns it
looks for. There are some examples in regex.txt that can be uncommented to
attempt this.
