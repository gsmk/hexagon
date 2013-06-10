hexagon
=======

IDA processor module for the hexagon (QDSP6) processor

This is the processor found in recent qualcomm basebands ( MSM9xxx )
with LTE support, like the apple iphone5 and samsung galaxy s3.

This processor module is a wrapper for the objdump code
found on [codeaurora](https://www.codeaurora.org/patches/quic/hexagon/4.0/Hexagon_Tools_source.tgz)

A programmers reference manual for the hexagon CPU can be found [here](https://developer.qualcomm.com/hexagon-processor)


binary download
-------

A binary for Mac OS X can be downloaded from [bintray](https://bintray.com/itsme/hexagon-ida/hexagon-osx-binary/1.0)

A binary for Windows can be downloaded from [bintray](https://bintray.com/itsme/hexagon-ida/hexagon-win32-binary/1.0)

installation
-------

Copy the hexagon.imc file to the procs subdirectory of your IDA installation.


usage
-------

Start IDA, select 'Qualcomm Hexagon DSP v4:QDSP6' from the processor type.

When loading an ELF binary, IDA will tell you 'Undefined or unknown machine type 164.' 
you should answer 'Yes'. Then IDA well tell you about unknown flag bits, you can ignore
that as well. IDA may also tell you the ELF has an illegal entry point.


compiling
-------

Currently there is only a Makefile for OSX, you need the IDASDK, and quicinc gnutools.
then apply gnutools.patch to the quicinc gnutools,
and in hexagon_iset_v[234].h  change HEXAGON_MAP_FNAME to HEXAGON_MAP_FPTR

I used the gnutools from december 2011.

You need a c++11 compiler, like visualstudio-express 2010, or clang++3.1

bugs
-------

 * Stack variables not yet recognized
 * The first instruction of a segment is not always disassembled correctly, you can see it switch sometimes.
     ( this is because the objdump hexagon code keeps internal state in local static variables )
 * Switches are not yet recognized
 * Indirect jumps and calls are not yet marked as such
 * basic block ends are not correct in graph view

author
=======

Willem Hengeveld (itsme@gsmk.de)

history
-------
2013-06-10 version 1.0


license
-------

Free


