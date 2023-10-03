find_path(GNUTOOLS_PATH NAMES opcodes/hexagon-dis.c PATHS ${CMAKE_SOURCE_DIR}/hx/sourceryg++-2012.03-151-hexagon/binutils-hexagon-2012.03)
if (GNUTOOLS_PATH STREQUAL GNUTOOLS_PATH-NOTFOUND)
    include(FetchContent)
    # fetching a stripped down version of the gnutoolchain, so we don't need to download a 140M archive.
    # the original url: https://sourcery.sw.siemens.com/GNUToolchain/package14127/public/hexagon/sourceryg++-2012.03-151-hexagon.src.tar.bz2
    FetchContent_Populate(gnutools
        URL https://itsme.home.xs4all.nl/hx-2012.03-v2.tar.gz
        URL_HASH SHA256=deef10e66e7dcb16361043c7328d0e74b08b0fbe5cbd28fd7ac6f5966e8a12b9  
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

