option(OPT_STL_DEBUGGING "Build with STL debugging"  OFF)
option(OPT_PROF "Build for profiling"  OFF)
option(OPT_COV "Build for code coverage"  OFF)
option(OPT_LIBCXX "Build with libcxx"  OFF)
option(OPT_MODULES "use c++20 modules"  OFF)
option(OPT_ANALYZE "add -fanalyzer"  OFF)
option(OPT_SYMBOLS "With symbols" OFF)
option(OPT_SANITIZE "With -fsanitize" OFF)
option(OPT_TSAN "With thread sanitizer" OFF)
option(OPT_ASAN "With address sanitizer" OFF)
option(OPT_CLANG_TIDY "With clang-tidy checks" OFF)
option(OPT_COMPILE_COMMANDS "Generate compile_commands.json" OFF)
option(OPT_INSTALL_HEADERS "Export header files for INSTALL target" OFF)
option(OPT_DISABLE_CMAKE_SANITY_CHECK "Disable CMake call sanity checks (ex: OpenWrt)" OFF)
option(OPT_DISABLE_DEVEL_INSTALL "Disable all development install targets (ex: Win NSIS installer)" OFF)

if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    set(LINUX TRUE)
elseif (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    set(DARWIN TRUE)
    if (${CMAKE_OSX_SYSROOT} MATCHES "/iPhoneOS.platform")
        set(IPHONE TRUE)
    elseif (${CMAKE_OSX_SYSROOT} MATCHES "/iPhoneSimulator.platform")
        set(IPHONESIM TRUE)
    elseif (${CMAKE_OSX_SYSROOT} MATCHES "/MacOSX.platform")
        set(MACOS TRUE)
    else()
        message(FATAL_ERROR "Unsupported apple platform")
    endif()
elseif (${CMAKE_SYSTEM_NAME} MATCHES "iOS")
    set(DARWIN TRUE)
    if (${CMAKE_OSX_SYSROOT} MATCHES "/iPhoneOS.platform")
        set(IPHONE TRUE)
    elseif (${CMAKE_OSX_SYSROOT} MATCHES "/iPhoneSimulator.platform")
        set(IPHONESIM TRUE)
    endif()
elseif (${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
    set(FREEBSD TRUE)
endif()

if (NOT OPT_DISABLE_CMAKE_SANITY_CHECK)
    # checking if we are called in the correct way:
    #  with a -B argument.  and without a cache file in the source directory.
    if (CMAKE_CACHEFILE_DIR STREQUAL "${CMAKE_SOURCE_DIR}")
        message(FATAL_ERROR "\nUnexpected CMakeCache.txt file in the source directory. Please remove it.")
        return()
    endif()

    if (EXISTS ${CMAKE_BINARY_DIR}/CMakeLists.txt)
        message(FATAL_ERROR "\nRun cmake with an explicit -B buildpath")
        return()
    endif()
endif()

if (OPT_ANALYZE)
    if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fanalyzer")
    elseif (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --analyze")
    endif()
endif()

if (OPT_ASAN AND OPT_TSAN)
    message(FATAL_ERROR "Only one sanitizer can be active at a time")
elseif (OPT_ASAN)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=undefined")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address")
    #set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=thread")
    #set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=dataflow")
elseif(OPT_TSAN)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=thread")
endif()

if (OPT_CLANG_TIDY)
  # clang-tidy supports a range of different checks. For a list of all available
  # checks, check the clang-tidy website:
  #   https://clang.llvm.org/extra/clang-tidy/checks/list.html
  # To enable only certain checks, we disable all of them first and then select
  #  - clang-analyzer-*   => Clang Static Analyzer
  #  - bugprone-*         => bug-prone code constructs (except bugprone-easily-swappable-parameters, bugprone-suspicious-include)
  #  - cert-*             => CERT Secure Coding Guidelines
  #  - concurrency-*      => General concurrency checks
  #  - performance-*      => General performance checks
  #  - portability-*      => General portability checks
  set(CLANG_TIDY_CHECKS "clang-analyzer-*,bugprone-*,-bugprone-easily-swappable-parameters,-bugprone-suspicious-include,cert-*,concurrency-*,performance-*,portability=*")
  set(CMAKE_CXX_CLANG_TIDY "clang-tidy;--extra-arg-before=-std=c++${CMAKE_CXX_STANDARD};-checks=-*,${CLANG_TIDY_CHECKS}")
endif()

if (OPT_LIBCXX)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
endif()

if (OPT_STL_DEBUGGING)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_GLIBCXX_DEBUG")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_LIBCPP_DEBUG_LEVEL=1")
endif()

if (OPT_PROF)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pg ")
endif()

if (OPT_SYMBOLS)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g ")
endif()
if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-c++11-narrowing")
endif()

if (OPT_COV)
    if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        message(STATUS "gcc code coverage")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ftest-coverage -fprofile-arcs ")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -ftest-coverage -fprofile-arcs ")
    elseif (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        message(STATUS "llvm code coverage")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fprofile-instr-generate -fcoverage-mapping -fdebug-info-for-profiling")
        #set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mllvm -inline-threshold=100000")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fprofile-instr-generate -fcoverage-mapping")
    else()
        message(STATUS "don't know how to add code coverage for ${CMAKE_CXX_COMPILER_ID }")
    endif()
endif()
if(OPT_STATIC)
    set(LIBSTYLE STATIC)
    set(CMAKE_POSITION_INDEPENDENT_CODE True)
else()
    set(LIBSTYLE SHARED)
endif()

if (OPT_COMPILE_COMMANDS)
    set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
endif()

if (OPT_DISABLE_DEVEL_INSTALL)
  set(MAY_EXCLUDE_FROM_ALL EXCLUDE_FROM_ALL)
endif()


# Project wide warning/error settings
if(MSVC)
    # /W0 suppresses all warnings
    # /W1 displays level 1 (severe) warnings (default in command line)
    # /W2 displays level 1 and level 2 (significant) warnings.
    # /W3 displays level 1, level 2, and level 3 (production quality) warnings (default in IDE)
    # /W4 displays level 1, level 2, and level 3 warnings, and all level 4 (informational) warnings that aren't off by default
    add_compile_options(/W1)
else()
    # Exclude the following ones for now:
    #   -Wunused-parameter: we have delegate classes with stub methods (with unused parameters)
    #   -Wempty-body: occurs in release builds as there are if-cases which only contain a logmsg expression
    #   -Wunused-variable, -Wunused-value:  occurs in release builds for parameters of a logmsg expression
    add_compile_options(-Wall -Wextra -Wno-unused-parameter -Wno-empty-body -Wno-unused-value -Wno-unused-variable)
endif()

if(MSVC)
    # /MP = multithreaded build
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MP")
    # /utf-8 = utf8 source and execution
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /utf-8")
    # NOBITMAP - avoid error in mmreg.h
    # NOMINMAX - remove 'max()' macro from global namespace
    # NOGDI - ...
    add_definitions(-DNOMINMAX -DNOGDI -DNOBITMAP -DWIN32_LEAN_AND_MEAN)
    add_definitions(-DWIN32)
    add_definitions(-D__STDC_WANT_SECURE_LIB__=1)

    # Executables need to resolve path to dlls (RPATH is not available on Windows). This could be done
    # either by using PATH env. variable or keeping dlls alongside with executables
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG   ${CMAKE_BINARY_DIR}/bin)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/bin)
endif()
if (OPT_MODULES)
    if (CMAKE_COMPILER_IS_GNUCXX)
        set(CMAKE_CXX_FLAGS -fmodules-ts)
    else()
        set(CMAKE_CXX_FLAGS -fmodules -fbuiltin-module-map)
    endif()
endif()

