-include ../idacfg.mk

CMAKEARGS+=$(if $(D),-DCMAKE_BUILD_TYPE=Debug,-DCMAKE_BUILD_TYPE=Release)
CMAKEARGS+=$(if $(LOG),-DOPT_LOGGING=1)
CMAKEARGS+=$(if $(COV),-DOPT_COV=1)
CMAKEARGS+=$(if $(PROF),-DOPT_PROF=1)
CMAKEARGS+=$(if $(LIBCXX),-DOPT_LIBCXX=1)
CMAKEARGS+=$(if $(STLDEBUG),-DOPT_STL_DEBUGGING=1)
CMAKEARGS+=$(if $(SANITIZE),-DOPT_SANITIZE=1)
CMAKEARGS+=$(if $(ANALYZE),-DOPT_ANALYZE=1)
CMAKEARGS+=$(if $(SYM),-DOPT_SYMBOLS=1)
MSBUILDARGS+=$(if $(D),-p:Configuration=Debug,-p:Configuration=Release)

cmake:
	cmake -B build . $(CMAKEARGS)
	$(MAKE) -C build $(if $(V),VERBOSE=1)

nmake:
	"C:/Program Files (x86)/Microsoft Visual Studio/2019/Community/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe" -G"NMake Makefiles" -B build . $(CMAKEARGS_LOCAL)
	cd build ; nmake $(if $(V),VERBOSE=1)

vc:
	"C:/Program Files (x86)/Microsoft Visual Studio/2019/Community/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe" -G"Visual Studio 16 2019" -B build . $(CMAKEARGS)
	"C:/Program Files (x86)/Microsoft Visual Studio/2019/Community/MSBuild/Current/Bin/amd64/MSBuild.exe" build/*.sln -t:Rebuild $(MSBUILDARGS)

llvm:
	CC=clang CXX=clang++ cmake -B build . $(CMAKEARGS)
	$(MAKE) -C build $(if $(V),VERBOSE=1)

SCANBUILD=$(firstword $(wildcard /usr/bin/scan-build*))
llvmscan:
	CC=clang CXX=clang++ cmake -B build . $(CMAKEARGS)
	$(SCANBUILD) $(MAKE) -C build $(if $(V),VERBOSE=1)


clean:
	$(RM) -r build CMakeFiles CMakeCache.txt CMakeOutput.log
	$(RM) $(wildcard *.gcov)


install:
	cp -a build/hexagon.so "$(idabin)/procs"
	cp -a build/hexagon64.so "$(idabin)/procs"

source-archive:
	git archive --format=zip -o source-archive.zip master
