hexagon
=======

IDA processor module for the hexagon (QDSP6v55) processor

This is the processor found in recent qualcomm basebands ( MSM9xxx )
with LTE support, like the apple iPhone5 and Samsung Galaxy s3 ( GT-i9305 )
or Galaxy S5 ( SM-G900F )

Several versions of the programmers reference manual can be found online:
 * [80-NB419-1 Rev. A Hexagon V2 Programmer’s Reference Manual](https://developer.qualcomm.com/download/80-nb419-1ahexagonv2programmersref.pdf)
 * 80-N2040-9 Rev. A Hexagon V4 Programmer’s Reference Manual
 * 80-N2040-8 Rev. H Hexagon V5/V55 Programmer’s Reference Manual
   * both the v4 and v5 refman can be found in this [zip](https://developer.qualcomm.com/download/hexagon/hexagon-sdk-programmers-reference.zip)
 * 80-N2040-9 Rev. F Hexagon V5x Programmer’s Reference Manual
 * 80-N2040-33 Rev. D Hexagon V6x Programmer’s Reference Manual
   * both the v5.x and v6.x refman can be found in the Hexagon LLVM Tools 8.0 Document Bundle, which is installed as part of the [Hexagon SDK](https://developer.qualcomm.com/download/hexagon/)
 * 80-N2040-30 Rev B Hexagon V60 HVX Programmer's Reference Manual
 * 80-N2040-37 Rev A Hexagon V62 HVX Programmer's Reference Manual
 * 80-N2040-36 Rev B Hexagon V62 Programmer's Reference Manual

check out https://developer.qualcomm.com/hexagon-processor for updates from qualcomm.

Available disassemblers:
 * [Sourcery CodeBench Lite 5.1 2012.03-151 for Hexagon ELF](http://sourcery.mentor.com/GNUToolchain/release3140)
 * lauterbach trace32
 * [codeaurora quic](https://www.codeaurora.org/patches/quic/hexagon/)
 * [Hexagon SDK v2.0](https://developer.qualcomm.com/download/hexagon/hexagon-sdk-linux.bin)
 * [llvm](https://github.com/llvm-mirror/llvm/tree/master/lib/Target/Hexagon)

Note: The Hexagon SDK uses LLVM, but with more hexagon instructions than the publicly available llvm code.


Processor Module
-------

This processor module is a wrapper for the objdump code found on [sourcery.mentor.com](http://sourcery.mentor.com/GNUToolchain/release3140)


Binary download
-------

Binaries for OSX, Linux and Windows can be found under [releases](https://github.com/gsmk/hexagon/releases):
  * [OS X](https://github.com/gsmk/hexagon/releases/download/v1.3/hexagon.dylib)
  * [Windows](https://github.com/gsmk/hexagon/releases/download/v1.3/hexagon.dll)
  * [Linux](https://github.com/gsmk/hexagon/releases/download/v1.3/hexagon.so)


Installation
-------

There are two variants of the hexagon module: one for ida and one for ida64.
Copy the hexagon{64}.{dylib,dll,so} file to the procs subdirectory of your IDA installation.
This module can probably also be used with the [IDA Evaluation](https://www.hex-rays.com/products/ida/support/download_demo.shtml) version.
The [IDA Free](https://hex-rays.com/ida-free/) version can be used to view and change existing hexagon disassemblies, but it can not be used
to start from scratch.


Usage
-------

Start IDA, select 'Qualcomm Hexagon DSP v4:QDSP6' from the processor type.

When loading an ELF binary, IDA will tell you 'Undefined or unknown machine type 164.' 
you should answer 'Yes'. Then IDA well tell you about unknown flag bits, you can ignore
that as well. IDA may also tell you the ELF has an illegal entry point.


Compiling
-------

The build uses `cmake` to generate build files for your platform.
The top level `Makefile` can call cmake in several ways.

 * On linux and MacOS build by typing `make`.
 * On Windows: either `make vc`, or `make nmake`.


You need the [IDASDK](https://www.hex-rays.com/products/ida/support/ida/idasdk77.zip) ( Password protected ).

The gnutools are automatically downloaded.

You need a c++20 compiler, like visualstudio 2019, or any recent gcc or clang.

You can point cmake to the right SDK by setting the environment variable `IDASDK` to the basepath of the sdk.
 
On windows, first run the following command, to setup the right visualstudio environment.

    vsdevcmd -arch=amd64


The sourcery gnutools
=====================

A stripped down version of the sourcery hexagon gnutools is downloaded from [my xs4all page](https://itsme.home.xs4all.nl/hx-2012.03-v2.tar.gz). This version does include some patches to silence some compiler warnings, and work around a problem in the original code where occasionally the disassembler would crash.
The original archive is quite large ( 140M ) and can be found [here](https://sourcery.sw.siemens.com/GNUToolchain/package14127/public/hexagon/sourceryg++-2012.03-151-hexagon.src.tar.bz2). 
The GPL/LGPL license files are included in the tar file.

Preconfigured bfd.h and config.h files are included in this source archive.


Bugs
-------

 * Stack variables not yet recognized
 * The first instruction of a segment is not always disassembled correctly, you can see it switch sometimes.
     ( this is because the objdump hexagon code keeps internal state in local static variables )
 * Switches are not yet recognized
 * Indirect jumps and calls are not yet marked as such
 * basic block ends are not correct in graph view
 * processor type is fixed to v5.5
 * module may crash when encountering some invalid instructions ( lumia 820 modem )
 * 'loop' instruction should have a code xref, instead of a data xref.


Building the gnutools
=====================

Note that this is NOT nescesary when using cmake.

 * create a build directory
 * Run ../pathtosource/configure with `--target=hexagon` and `--disable-werror`

Other Hexagon Processor modules
===============================

 * [nogaxeh](https://github.com/ANSSI-FR/nogaxeh)
 * [hexag00n](https://github.com/programa-stic/hexag00n)
 * [r2hexagon](https://github.com/radareorg/r2hexagon)
 * [idp\_hexagon](https://github.com/n-o-o-n/idp_hexagon)


Author
=======

Willem Hengeveld (itsme@gsmk.de)

History
-------
2013-06-10 version 1.0
 * initial public release

2016-02-01 version 1.1
 * hexagon: now supporting v5 insn set. some improved insn matching code
 * updated to latest sourcery binutils release.

2017-12-05 version 1.2 - for idapro v7
 * completely reorganised plugin structure, support idav7 plugin structure.
 * hexagon: fixed addcref bug - now keeping stack of cmd vars. 
 * fixed problem with code refs from memw[...] instructions. 
 * fixed garbage label for invalid jump addresses
 * fixed incorrect code ref from memw()
 * corrected parsing of ##@ vs ##num

2022-02-12 version 1.3 - for IDA v7.7
 * updated to support ida v7.7
 * switch to cmake for build system.

2023-03-30 version 1.4
 * fixed 'interr 1112' in ida 8+
 * improved cmake wrapper for idasdk
 * automatic download of gnutools

2023-10-03 version 1.5
 * fixed windows build


License
-------

Free


