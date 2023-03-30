find_path(GNUTOOLS_PATH NAMES opcodes/hexagon-dis.c PATHS ${CMAKE_SOURCE_DIR}/hx/sourceryg++-2012.03-151-hexagon/binutils-hexagon-2012.03)
if (GNUTOOLS_PATH STREQUAL GNUTOOLS_PATH-NOTFOUND)
    include(FetchContent)
    FetchContent_Populate(gnutools
        URL https://itsme.home.xs4all.nl/hx-2012.03.tar.gz
        URL_HASH SHA256=7d2969c52f4d75d659a5b74b41c1b53f33ac83dd4b5c8e4620ed591e91ef05cb
    )
    set(GNUTOOLS_PATH ${gnutools_SOURCE_DIR}/binutils-hexagon-2012.03)
else()
    set(gnutools_BINARY_DIR ${CMAKE_BINARY_DIR}/gnutools-build)
endif()

list(APPEND GNUTOOLS_SRC ${GNUTOOLS_PATH}/bfd/cpu-hexagon.c)
list(APPEND GNUTOOLS_SRC ${GNUTOOLS_PATH}/bfd/hexagon-isa.c)
list(APPEND GNUTOOLS_SRC ${GNUTOOLS_PATH}/opcodes/hexagon-dis.c)
list(APPEND GNUTOOLS_SRC ${GNUTOOLS_PATH}/opcodes/hexagon-opc.c)
list(APPEND GNUTOOLS_SRC ${GNUTOOLS_PATH}/libiberty/safe-ctype.c)

add_library(gnutools STATIC ${GNUTOOLS_SRC})
set_target_properties(gnutools PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(gnutools PUBLIC ${GNUTOOLS_PATH}/include)
target_include_directories(gnutools PUBLIC ${GNUTOOLS_PATH}/bfd)
target_include_directories(gnutools PUBLIC ${GNUTOOLS_PATH}/include/opcode)
if (WIN32)
target_include_directories(gnutools PUBLIC ${CMAKE_SOURCE_DIR}/build-win/opcodes)
target_include_directories(gnutools PUBLIC ${CMAKE_SOURCE_DIR}/build-win/bfd)
else()
target_include_directories(gnutools PUBLIC ${CMAKE_SOURCE_DIR}/build-mac/opcodes)
target_include_directories(gnutools PUBLIC ${CMAKE_SOURCE_DIR}/build-mac/bfd)
endif()

