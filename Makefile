# the name under which this processor module is listed by IDA
DESCRIPTION=Qualcomm Hexagon DSP v4:QDSP6

all:

# I put some not yet published targets in this optional include
-include Makefile.extra

CXX=clang++
CC=clang
LD=clang++

TARGETS+=hexagon.imc

# set some paths to external libraries
idasdk=~/sources/idasdk64
idabin=/Applications/IDA Pro 6.4/idaq.app/Contents/MacOS

# where the quicinc objdump source can be found
gnutools= ~/projects/iphone/hexagon/source-wj/gnutools

gnutoolsincludes=-I $(gnutools)/include -I $(gnutools)/bfd -I $(gnutools)/build_mac/opcodes -I $(gnutools)/build_mac/bfd -I $(gnutools)/include/opcode
CFLAGS=-g -D__MAC__ -D__IDP__ -I $(idasdk)/include

CFLAGS+=-O3

# add this flag when you want verbose logging
#CFLAGS+=-DTRACELOG

all: $(TARGETS)

hexagon.imc: hexagon.o32 idadesc.o32  gt_safe-ctype.o32  gt_hexagon-dis.o32 gt_hexagon-opc.o32 bfd_funcs.o32
cflags_hexagon= $(gnutoolsincludes)
cflags_bfd_funcs= $(gnutoolsincludes)

idadesc.s: Makefile
	printf ".section .ida, data\n.ascii \"IDA_MODULE_DESC:\"\n.ascii \"$(DESCRIPTION)\"\n" > $@
GENERATEDFILES+=idadesc.s

install:  hexagon.imc
	sudo cp $^  "$(idabin)/procs"

clean:
	$(RM) $(TARGETS) $(wildcard *.o) $(wildcard *.o32) $(GENERATEDFILES)




%.o32: %.cpp
	$(CXX) -m32 -std=c++11 -c -Wall -o$@ $^ $(cflags_$(basename $(notdir $@))) $(CFLAGS)

gt_%.o32: $(gnutools)/libiberty/%.c
	$(CC) -m32 -c -Wall -o$@ $^ $(cflags_$(basename $(notdir $@)))  $(gnutoolsincludes) $(CFLAGS)

gt_%.o32: $(gnutools)/opcodes/%.c
	$(CC) -m32 -c -Wall -Wstrict-prototypes -Wmissing-prototypes -o$@ $^ $(cflags_$(basename $(notdir $@)))  $(gnutoolsincludes) $(CFLAGS)

%.o32: %.s
	$(CXX) -c -m32 -o$@ $^

%.imc: %.o32
	$(LD) -dynamiclib -m32 -o $@ $^  "$(idabin)/libida.dylib"

%: %.o
	$(CXX) -g -o $@ $^  

%32: %.o32
	$(CXX) -m32 -g -o $@ $^  

