#include <bfd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
//extern disassembler_ftype hexagon_get_disassembler (bfd *);

template<typename BYTEITER> inline uint8_t get8(BYTEITER p) { return *p; }
template<typename BYTEITER> inline uint16_t get16le(BYTEITER p) { return (get8(p+1)<<8)              +get8(p); }
template<typename BYTEITER> inline uint32_t get32le(BYTEITER p) { return (get16le(p+2)<<16)          +get16le(p); }
template<typename BYTEITER> inline uint16_t get16be(BYTEITER p) { return (get8(p)<<8)                +get8(p+1); }
template<typename BYTEITER> inline uint32_t get32be(BYTEITER p) { return (get16be(p)<<16)            +get16be(p+2); }

extern "C" {

bfd_vma bfd_getb16(const void *p) { return get16be((const uint8_t*)p); }
bfd_vma bfd_getl16(const void *p) { return get16le((const uint8_t*)p); }
bfd_vma bfd_getb32(const void *p) { return get32be((const uint8_t*)p); }
bfd_vma bfd_getl32(const void *p) { return get32le((const uint8_t*)p); }

unsigned long
bfd_get_mach (bfd *abfd)
{
  return abfd->arch_info->mach;
}

void *xcalloc(int n, int m)
{
    void *p= malloc(n*m);
    memset(p, 0, n*m);
    return p;
}
}

