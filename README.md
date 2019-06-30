# Uncontrolled-memory-allocation-Fuzzer-TestSuite

Uncontrolled-memory-allocation testsuite used for fuzzing experiment

Seeds and POCs are in the folder

If you Cannot reproduce the bug, try to reduce the memory limit.
For example:
- `ulimit -a` to see the information of memory limit.
- `sudo ulimit -s 8192` or `sudo ulimit -s 4096` to reduce the stack size.
- `sudo ulimit -m 36700160` to reduce the memory size.

The detail information of the benchmark can be seen as follow.


### 1. [jasper 2.0.14](./jasper/README.md)
- Bug type: uncontrolled-memory-allocation, memory leak
- CVE ID: 
  - [CVE-2016-8886](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-7581)
  - [issue#207](https://github.com/libming/libming/issues/207)
  - the meory leak is very easy to find in CVE website, lots of memory leak
- Download:
  ```
  git clone https://github.com/mdadams/jasper
  git checkout commit 1a36ca39da535af2e67848f5f43ffd657746e632
  ```
- Reproduce: `jasper --input @@ --output test.bmp --output-format bmp`


### 2. [Libming 0.4.8](./libming/README.md)
- Bug type: uncontrolled-memory-allocation, memory leak
- CVE ID: 
  - [issue#155](https://github.com/libming/libming/issues/155)
  - [CVE-2019-7581](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-7581)
  - [CVE-2018-7876](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-7876)
  - [CVE-2019-7582](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-7582)
  - [CVE-2018-13251](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-13251)
  - the meory leak is very easy to find in CVE website, lots of memory leak
- Download:
  ```
  git clone https://github.com/libming/libming
  git checkout b72cc2fda0e8b3792b7b3f7361fc3f917f269433
  ```
- Reproduce: `listswf @@`


### 3. [zziplib v0.13.68](./zziplib/README.md)
- Bug type: uncontrolled-memory-allocation, memory leak
- CVE ID: 
  - [CVE-2018-6869](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6869)
  - the meory leak is very easy to find in CVE website, lots of memory leak
- Download:
  ```
  git clone https://github.com/gdraheim/zziplib
  git checkout bf4584fb06d5f9c5813616dbadc0129024c9c0f9
  ```
- Reproduce: `zzdir @@` || `unzzip @@`


### 4. [Bento4 1.5.1-627](./Bento4/README.md)
- Bug type: uncontrolled-memory-allocation, memory leak
- CVE ID: 
  - [CVE-2018-20186](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20186)
  - [CVE-2018-20659](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20659)
  - [CVE-2019-7698](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-7698)
  - [CVE-2019-6966](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-6966)
  - the meory leak is very easy to find in CVE website, lots of memory leak
- Download:
  ```
  git clone https://github.com/axiomatic-systems/Bento4
  git checkout 590312125c833bc496faf815c583cfd053509d2c
  ```
- Reproduce: `mp42hls @@`


### 5. [readelf 2.28](./readelf/README.md)
- Bug type: uncontrolled-memory-allocation
- CVE ID: 
  - [CVE-2017-15996](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-15996)
- Download:
  - https://ftp.gnu.org/gnu/binutils/
- Reproduce: `readelf -a @@`


### 6. [exiv2 0.26](./exiv2/README.md)
- Bug type: uncontrolled-memory-allocation
- CVE ID: 
  - [CVE-2018-4868](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-4868)
- Download:
	```
	git clone https://github.com/Exiv2/exiv2
	git checkout fa449a4d2c58d63f0d75ff259f25683a98a44630
	```
- Reproduce: `exiv2 -pX @@`


### 7. [openjpeg 2.3.0](./openjpeg/README.md)
- Bug type: uncontrolled-memory-allocation
- CVE ID: 
  - [CVE-2019-6988](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-6988)
  - [CVE-2017-12982](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-12982)
- Download:
	```
	git clone https://github.com/uclouvain/openjpeg
	git checkout 51f097e6d5754ddae93e716276fe8176b44ec548
	```
- Reproduce: `opj_decompress -i @@ -o ./tmp.png`

### 8. [podofo 0.9.5](./podofo/README.md)
- Bug type: uncontrolled-memory-allocation
- CVE ID: 
  - [CVE-2019-10723](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-10723)
  - [CVE-2018-20797](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20797)
  - [CVE-2018-5783](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-5783)
  - [CVE-2018-5296](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-5296)
- Download:
  - [https://sourceforge.net/projects/podofo/files/podofo/0.9.5/](https://sourceforge.net/projects/podofo/files/podofo/0.9.5/)
- Reproduce: `podofoimgextract @@ ./out`