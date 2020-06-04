<a href="https://scan.coverity.com/projects/luke-goddard-enumy"><img alt="Coverity Scan Build Status" src="https://scan.coverity.com/projects/20962/badge.svg"/></a>
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/luke-goddard/enumy/graphs/commit-activity)
[![GitHub license](https://img.shields.io/github/license/Naereen/StrapDown.js.svg)](https://github.com/Naereen/StrapDown.js/blob/master/LICENSE)
[![Total alerts](https://img.shields.io/lgtm/alerts/g/luke-goddard/enumy.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/luke-goddard/enumy/alerts/)
[![Help Wanted](https://img.shields.io/github/issues/luke-goddard/enumy/help%20wanted?color=green)](https://github.com/luke-goddard/enumy/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22)
[![Language grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/luke-goddard/enumy.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/luke-goddard/enumy/context:cpp)

# Enumy

<img src="https://i.imgur.com/luC3mTu.png"  align="right" width="300" height="200"/>

Enumy is an __ultra fast portable executable__ that you drop on target Linux machine during a pentest or CTF in the post exploitation phase. Running enumy will enumerate the box for __common security vulnerabilities__.

## Installation

You can download the final binary from the release x86 or x64 tab. _Statically linked to musl_
Transfer the final enumy binary to the target machine.

- [latest release](https://github.com/luke-goddard/enumy/releases)

```shell
./enumy
```

## Who Should Use Enumy

- Pentester can run on a target machine raisable issues for their reports.
- CTF players can use it identify things that they might have missed.
- People who are curious to know how many isues enumy finds on their local machine?

## Options

```shell
$ ./enumy64 -h
 ▄█▀─▄▄▄▄▄▄▄─▀█▄  _____                                  
 ▀█████████████▀ |   __|___ _ _ _____ _ _ 
     █▄███▄█     |   __|   | | |     | | |
      █████      |_____|_|_|___|_|_|_|_  |
      █▀█▀█                          |___|

 https://github.com/luke-goddard/enumy

 Enumy - Used to enumerate the target the target environment & look for
 common security vulnerabilities and hostspots
 ----------------------------------------------------------------------

 Output
  -o <loc>     OUTPUT results to location (default enumy.json)

 Walking Filesystem
  -i <loc>     IGNORE files in this directory (usefull for network shares)
  -w <loc>     Only WALK files in this directory (usefull for devlopment)

 Scan Options
  -f           run FULL scans (CPU intensive scan's enabled)
  -t <num>     THREADS (default 4)

 Printing Options
  -a           Print all security AUDIT issues to screen (probably won't help duing a CTF)
               Issues are ALWAYS logged in result files regardless of this flag being set.
  -d <1|2>     Print DEBUG mode (1 low, 2 high) to enable error being printed to screen.
  -g <H|M|L>   print to screen values GREATER than or equal to high, medium & low
  -p <H|M|L|I> do not PRINT to screen high, medium, low & info issues (see below for example)
  -m 1-100     MAXIMUM number of issues with same name to print to screen default (unlimited)
 ```

## Compilation

To compile during _devlopment_, make and libcap libary is all that is required.

```shell
sudo apt-get install libcap-dev
make
```

To remove the glibc dependency and statically link all libaries/compile with musl do the following. _Note to do this you will have to have docker installed to create the apline build environment._

```shells
./build.sh 64bit
./build.sh 32bit
./build.sh all
cd output
```

## Scan Times

![enumy benchmarks](benchmark.png?raw=true)

## Scans That've Been Implemented

Below is the ever growing list of scans that have been implemented.

| Scan Type                                                    | Quick Scan         | Full Scan          | Implemented        | Printed To Screen | Save In Log        |
| ------------------------------------------------------------ | ------------------ | ------------------ | ------------------ | ----------------- | ------------------ |
| [Kernel Exploit Surgestor](#kernel-exploit-surgestor)        | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| [SUID/GUID Scan](#suid-guid-scan)                            | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| [File Capabilities Scan](#file-capabilities-scan)            | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :x:               | :heavy_check_mark: |
| [Intresting Files Scan](#intresting-files-scan)              | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| [Coredump Scan](#coredump-scan)                              | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| [Breakout Binaries Scan](#breakout-binary-scan)              | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| [SSHD Configuration Scan](#ssh-misconfiguration-scan)        | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :x:               | :heavy_check_mark: |
| [Sysctl Scan](#sysctl-parameter-hardening)                   | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| [Living Off The Land Scan](#living-off-the-land-scan)        | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| [Current User Scan](#current-user-scan)                      | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| [*.so Injection Scan](#dynamic-shared-object-injection-scan) | :x:                | :heavy_check_mark: | :heavy_check_mark: | :x:               | :heavy_check_mark: |
| [Permissions Scan](#permissions-scan)                        | :x:                | :heavy_check_mark: | :heavy_check_mark: | :x:               | :heavy_check_mark: |
| [File System Scan](#file-system-scan)                        | :x:                | :heavy_check_mark: | :heavy_check_mark: | :x:               | :heavy_check_mark: |
| Docker Scan                                                  | :heavy_check_mark: | :heavy_check_mark: | :x:                |                   | :heavy_check_mark: |
| Environment Scan                                             | :heavy_check_mark: | :heavy_check_mark: | :x:                |                   | :heavy_check_mark: |
| Privilaged Access Scan                                       | :heavy_check_mark: | :heavy_check_mark: | :x:                |                   | :heavy_check_mark: |
| Networking Scan                                              | :heavy_check_mark: | :heavy_check_mark: | :x:                |                   | :heavy_check_mark: |
| System Info Scan                                             | :heavy_check_mark: | :heavy_check_mark: | :x:                |                   | :heavy_check_mark: |
| Version Information Scan                                     | :heavy_check_mark: | :heavy_check_mark: | :x:                |                   | :heavy_check_mark: |
| Default Weak Credentials Scan                                | :heavy_check_mark: | :heavy_check_mark: | :x:                |                   | :heavy_check_mark: |
| Weak Crypto Scan                                             | :x:                | :heavy_check_mark: | :x:                |                   | :heavy_check_mark: |

Note to print results marked as :x:, enable audit mode with the `-a` flag.

## How To Contribute

- If you can think of a scan idea that has not been implemented, raise it as an issue.
- If you know how to program, make a pull request :)
- All contributions are welcome

### Scan types

#### Kernel Exploit Surgestor

This scan will check the kernel versions to see if it matches any kernel versions with known exploits.

#### SUID GUID Scan

The idea of this scan is enumerate the system looking for [SUID](https://www.hackingarticles.in/linux-privilege-escalation-using-suid-binaries/)/GUID binaries that are abnormal, or have weak permissions that can be exploited.

#### File Capabilities Scan

Recently the Linux kernel supports [capablities](https://www.man7.org/linux/man-pages/man7/capabilities.7.html), this is the prefered way to give a file a subset of root's powers to mitigate risk. Although this is a much safer way of doing things, if you're lucky enough to find abnormal capabilities set on a file then it's quite possible that you can exploit the executable to gain higher access. Enumy will check the capabilties set on all executable files on the system.

#### Interesting Files Scan

This is more of a generic scan that will try and categorize a file based off it's contents, file extension and file name. Enumy will look for files such as private keys, passwords and backup files.

#### Coredump Scan

Coredump files are a type of ELF file that contains a process's address space when the program terminates unexpectedly. Now imagine if this process's memory was readable and contained sensative information. Or even more exciting, this coredump could be for an internally developed tool that seg faulted, allowing you to develop a zero day.

#### Breakout Binary Scan

Some file should never have SUID bit set, it quite common for a lazy sys admin to give a file like docker, ionice, hexdump SUID make a bash script work or there life easier. This scan tries to find some known bad SUID binaries.

#### Sysctl Parameter Hardening

[Sysctl](https://linux.die.net/man/8/sysctl) is used to modify kernel parameters at runtime. It's also possible to query these kernel parameters and check to see if important secutiry measures like ASLR are enabled.

#### Living Off The Land scan

Living off the land is a technique used where attackers weponize what's allready on the system. They do this to remain stealthy amongst other reasons. This scan would enumerate the files that an attacker would be looking for.

#### Dynamic Shared Object Injection Scan

This scan will parse ELF files for their dependencies. If we have write access to any of these dependencies or write access to any DT_RPATH and DT_RUNPATH values then we can create our own malicious shared object into that executable potentiall compromizing the system.

#### SSH Misconfiguration Scan

SSH is one of one of the most common services that you will find in the real world. It's also quite easy to misconfigure it. This scan will check to see if it can be hardened in anyway.

#### Current User Scan

The current user scan just parses /etc/passwd. With this information we find root accounts, unprotected and missing home directories etc.

#### Permisionss Scan

This scan is going to find file that are globaly writable files, uneven permissions and unowned files. See [here](http://infosecisland.com/blogview/8494-Keeping-Linux-File-Systems-Clean-and-Secure.html) for inspiration of the scan.

#### File System Scan

This scan would be useful for people trying to harden their Linux machine. It will highlight issues such as unencrypted drives and insecure mounting configurations.
