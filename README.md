<a href="https://scan.coverity.com/projects/luke-goddard-enumy"><img alt="Coverity Scan Build Status" src="https://scan.coverity.com/projects/20962/badge.svg"/></a>
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/luke-goddard/enumy/graphs/commit-activity)
[![GitHub license](https://img.shields.io/github/license/Naereen/StrapDown.js.svg)](https://github.com/Naereen/StrapDown.js/blob/master/LICENSE)
[![Total alerts](https://img.shields.io/lgtm/alerts/g/luke-goddard/enumy.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/luke-goddard/enumy/alerts/)
[![Help Wanted](https://img.shields.io/github/issues/luke-goddard/enumy/help%20wanted?color=green)](https://github.com/luke-goddard/enumy/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22)

# Enumy

Enumy is portable executable that you drop on target Linux machine during a pentest or CTF in the post exploitation phase. Running enumy will enumerate the box for common security vulnerabilities. 

## Installation

You can download the final binary from the release x86 or x64 tab. _Statically linked to musl_
Transfer the final enum:w
y binary to the target machine

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


------------------------------------------

Enumy - Used to enumerate the target environment and look for common
security vulnerabilities and hostspots

 -o <loc>     Save results to location
 -i <loc>     Ignore files in this directory (usefull for network shares)
 -w <loc>     Only walk files in this directory (usefull for devlopment)
 -t <num>     Threads (default 4)
 -f           Run full scans
 -s           Show missing shared libaries
 -d           Debug mode
 -n           Enabled ncurses
 -h           Show help
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

## Scans That've Been Implemented

Below is the ever growing list of scans that have been implemented.

### Quck Scan

- SUID/GUID Scans
- File Capabilities scan
- Interesting Files Scan
- Coredump Scan
- Breakout Binary Scan
- Sysctl Parameter Hardening
- Living Off The Land scan

### Full Scan

- Quick Scan
- Dynamic Shared Object Injection Scan

### Scans That Will Be Implemented In The Future

Below is a list of scan ideas that is on the todo list of being implemented. 

- Current User Scans
- Default Weak Credentials Scan
- Docker Scans
- Environment Scans
- Privilaged Access Scans
- Services Scans
- Networking Scans
- System Info Scans
- Version Information Scans

## Scan Times

Changing the default number of threads is pretty pointless __unless__  you're running a full scan. A full scan will do a lot more IO so more threads greatly decrease scan times. These are the scan times with a i7-8700k and 2 million files scanned.

### Quick Scan Times

- 2 Thread  -> `system 70%  cpu 54.093 total`
- 2 Thread  -> `system 121% cpu 26.122 total`
- 4 Thread  -> `system 289% cpu 15.657 total`
- 8 Threads -> `system 468% cpu 15.863 total`
- 12 Thread -> `system 420% cpu 20.548 total`

### Full Scan Times

- 1 Thread  -> `system 50%  cpu 3:16.38 total`
- 2 Thread  -> `system 86%  cpu 1:33.95 total`
- 4 Thread  -> `system 165% cpu 47.753 total`
- 8 Threads -> `system 366% cpu 29.768 total`
- 12 Thread -> `system 467% cpu 29.815 total`

## How To Contribute

- If you can think of a scan idea that has not been implemented, raise it as an issue. 
- Make a pull request, make sure that.
  - Each scan is given a unique ID
  - Multiple related scans are in the same file.
  - No more than one scan/test per function.
