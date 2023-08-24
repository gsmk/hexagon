if (TARGET idasdk)
    return()
endif()
# note: this depends partially on my local install
find_path(IDASDK_PATH NAMES include/netnode.hpp PATHS
    $ENV{IDASDK}
    $ENV{HOME}/src/idasdk_pro82
    $ENV{HOME}/src/idasdk_pro80
    c:/local/idasdk_pro82
    c:/local/idasdk77)
if (IDASDK_PATH STREQUAL "IDASDK_PATH-NOTFOUND")
    message(FATAL_ERROR "IDASDK not found on ${CMAKE_SYSTEM_NAME}.")
endif()
if(WIN32)
    # note that for windows both libs have the same name.
    find_library(IDALIB32 ida ${IDASDK_PATH}/lib/x64_win_vc_32 ${IDASDK_PATH}/lib/x64_win_vc_32_pro)
    find_library(IDALIB64 ida ${IDASDK_PATH}/lib/x64_win_vc_64 ${IDASDK_PATH}/lib/x64_win_vc_64_pro)
elseif(LINUX)
    find_library(IDALIB32 ida   ${IDASDK_PATH}/lib/x64_linux_gcc_32 ${IDASDK_PATH}/lib/x64_linux_gcc_32_pro)
    find_library(IDALIB64 ida64 ${IDASDK_PATH}/lib/x64_linux_gcc_64 ${IDASDK_PATH}/lib/x64_linux_gcc_64_pro)
elseif(DARWIN)
    # now this depends on the host, better would be to set
    # CMAKE_OSX_ARCHITECTURES to arm64 for the arm build.
    if (CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL x86_64)
        find_library(IDALIB32 ida   ${IDASDK_PATH}/lib/x64_mac_clang_32 ${IDASDK_PATH}/lib/x64_mac_clang_32_pro)
        find_library(IDALIB64 ida64 ${IDASDK_PATH}/lib/x64_mac_clang_64 ${IDASDK_PATH}/lib/x64_mac_clang_64_pro)
    else()
        find_library(IDALIB32 ida   ${IDASDK_PATH}/lib/arm64_mac_clang_32 ${IDASDK_PATH}/lib/arm64_mac_clang_32_pro)
        find_library(IDALIB64 ida64 ${IDASDK_PATH}/lib/arm64_mac_clang_64 ${IDASDK_PATH}/lib/arm64_mac_clang_64_pro)
    endif()
endif()
if (IDALIB64 STREQUAL "IDALIB64-NOTFOUND")
    message(FATAL_ERROR "could not find libida64")
endif()
if (IDALIB32 STREQUAL "IDALIB32-NOTFOUND")
    message(FATAL_ERROR "could not find libida")
endif()
message(STATUS "found ida headers at: ${IDASDK_PATH}/include")
message(STATUS "found ida32 lib  at: ${IDALIB32}")
message(STATUS "found ida64 lib  at: ${IDALIB64}")

add_library(idasdk INTERFACE)
target_include_directories(idasdk INTERFACE ${IDASDK_PATH}/include)
target_compile_definitions(idasdk INTERFACE MAXSTR=1024)
# since ida v7 all builds are 64 bit
target_compile_definitions(idasdk INTERFACE __X64__)

if (LINUX)
    target_compile_definitions(idasdk INTERFACE __LINUX__=1)
elseif (DARWIN)
    target_compile_definitions(idasdk INTERFACE __MAC__=1)
elseif (WIN32)
    target_compile_definitions(idasdk INTERFACE __NT__=1)
endif()
# this prevents idasdk:fpro.h to redefine all stdio stuff to 'dont_use_XXX'
target_compile_definitions(idasdk INTERFACE USE_STANDARD_FILE_FUNCTIONS)
# this prevents idasdk:pro.h to redefine all string functions to 'dont_use_XXX'
target_compile_definitions(idasdk INTERFACE USE_DANGEROUS_FUNCTIONS)
# disallow obsolete sdk functions.
target_compile_definitions(idasdk INTERFACE NO_OBSOLETE_FUNCS)
target_compile_definitions(idasdk INTERFACE __DEFINE_ROOT_NODE__)
target_compile_definitions(idasdk INTERFACE __DEFINE_INF__)
target_compile_definitions(idasdk INTERFACE __DEFINE_PH__)

# __EA64__=1   - for ida64   -> handled by choosing idasdk / idasdk64
#    * this chooses between sizeof(ea_t) == 4 or 8

# __IDP__    for processor modules  -> also needs win32: -export:LPH
# __PLUGIN__ for plugins


add_library(idasdk32 INTERFACE)
target_link_libraries(idasdk32 INTERFACE idasdk ${IDALIB32})
add_library(idasdk64 INTERFACE)
target_link_libraries(idasdk64 INTERFACE idasdk ${IDALIB64})
target_compile_definitions(idasdk64 INTERFACE __EA64__=1)

