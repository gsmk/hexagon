hexagon
=======

IDA processor module for the hexagon (QDSP6v55) processor

This is the processor found in recent qualcomm basebands ( MSM9xxx )
with LTE support, like the apple iPhone5 and Samsung Galaxy s3 ( GT-i9305 )
or Galaxy S5 ( SM-G900F )

Several versions of the programmers reference manual can be found online:
 * [80-NB419-1 Rev. A Hexagon V2 Programmer’s Reference Manual](https://developer.qualcomm.com/download/80-nb419-1ahexagonv2programmersref.pdf)
 * 80-N2040-9 Rev. A Hexagon V4 Programmer’s Reference Manual
 * 80-N2040-8 Rev. A Hexagon V5/V55 Programmer’s Reference Manual
   * both the v4 and v5 refman can be found in this [zip](https://developer.qualcomm.com/download/hexagon/hexagon-sdk-programmers-reference.zip)
 * 80-N2040-9 Rev. F Hexagon V5x Programmer’s Reference Manual
 * 80-N2040-33 Rev. B Hexagon V6x Programmer’s Reference Manual
   * both the v5.x and v6.x refman can be found in the Hexagon LLVM Tools 7.2.x Document Bundle, which is installed as part of the [Add-On for HVX](https://developer.qualcomm.com/download/hexagon/hexagon-sdk-addon-hvx-linux.bin)

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
  * [OS X](https://github.com/gsmk/hexagon/releases/download/v1.1/hexagon.imc)
  * [Linux](https://github.com/gsmk/hexagon/releases/download/v1.1/hexagon.ilx)
  * [Windows](https://github.com/gsmk/hexagon/releases/download/v1.1/hexagon.w32)

Installation
-------

Copy the hexagon.{imc,w32,ilx} file to the procs subdirectory of your IDA installation.
This module can also be used with the [IDA 6.8 Evaluation](https://www.hex-rays.com/products/ida/support/download_demo.shtml) version.


Usage
-------

Start IDA, select 'Qualcomm Hexagon DSP v4:QDSP6' from the processor type.

When loading an ELF binary, IDA will tell you 'Undefined or unknown machine type 164.' 
you should answer 'Yes'. Then IDA well tell you about unknown flag bits, you can ignore
that as well. IDA may also tell you the ELF has an illegal entry point.


Compiling
-------

Separate makefiles exist for OSX (Makefile.osx), Windows (Makefile.w32) and Linux (Makefile.linux).

You need the [IDASDK](https://www.hex-rays.com/products/ida/support/ida/idasdk69.zip) ( Password protected ).
The sourcery hexagon gnutools, install them in a subdirectory named `hx/sourceryg++-2012.03-151-hexagon/binutils-hexagon-2012.03`.
You need a c++11 compiler, like visualstudio 2015, or any recent gcc or clang.

Create a `idacfg.mk` file, containing the following variables:

 * `idasdk`, pointing to your IDASDK directory
 * `idabin`, pointing to your IDA binaries directory

Bugs
-------

 * Stack variables not yet recognized
 * The first instruction of a segment is not always disassembled correctly, you can see it switch sometimes.
     ( this is because the objdump hexagon code keeps internal state in local static variables )
 * Switches are not yet recognized
 * Indirect jumps and calls are not yet marked as such
 * basic block ends are not correct in graph view
 * processor type is fixed to v5.5

Author
=======

Willem Hengeveld (itsme@gsmk.de)

History
-------
2013-06-10 version 1.0
2016-02-01 version 1.1

License
-------

Free


