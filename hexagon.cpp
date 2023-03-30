/*
 * A Hexagon Processor module for IDAPRO.
 *
 * Author: Willem Hengeveld <itsme@gsmk.de>
 *
 */
#include <name.hpp>
#include <idp.hpp>
#include <auto.hpp>         // atype_t
#include <loader.hpp>       // HT_IDP
#include <offset.hpp>       // HT_IDP
#include <string>
#include <vector>
#include <bfd.h>
#include <dis-asm.h>
#include <stdlib.h>
#include <stdint.h>
#include <map>
#include <list>

#include "logging.h"
#include "pmbase.h"

#ifdef TRACELOG
FILE *g_log = NULL;
#endif

#if IDA_SDK_VERSION >= 700
#ifdef IDA70BETA3
#define get_many_bytes(ea, buf, size) get_bytes(ea, buf, size)
#else
#define get_many_bytes(ea, buf, size) get_bytes(buf, size, ea)
#endif
#define procName procname
#endif

#ifdef _WIN32
#define strtoll _strtoui64
#endif

static const char *const shnames[] = { "QDSP6", NULL };
static const char *const lnames[] = { "Qualcomm Hexagon DSP v4", NULL };

// for debugging
std::string hexdump(const char*buf, size_t n)
{
    std::string s;
    s.resize(n*3);
    char *p = &s[0];
    while (n--)
        p += qsnprintf(p, 4, " %02x", (unsigned char)*buf++);
    return s;
}

// object providing an output target for the bfd code, so
// this IDA module will be able to use the output.
struct disasmoutput {

    std::string text;

    void initstream(disassemble_info*info)
    {
        info->fprintf_func = (fprintf_ftype)staticprintf;
        info->stream = this;
    }

    __attribute__((__format__ (__printf__, 2, 0)))
    int vprintf(const char*fmt, va_list va)
    {
        text.resize(text.size()+256);
        size_t n= vsnprintf(&text[text.size()-256], 256, fmt, va);
        text.resize(text.size()-256+n);
        return n;
    }
    __attribute__((__format__ (__printf__, 2, 0)))
    static int staticprintf(disasmoutput*obj, const char*fmt, ...)
    {
        va_list va;
        va_start(va, fmt);
        int rc= obj->vprintf(fmt, va);
        va_end(va);
        return rc;
    }
};

// object providing the bfd code access to bytes in the IDA database
class memory {
public:

    void initinfo(disassemble_info* info)
    {
        info->application_data       = this;
        info->read_memory_func       = staticread;
        info->memory_error_func      = staticperror;
        info->print_address_func     = staticprintaddr;
        info->symbol_at_address_func = staticsymbolataddr;
        info->symbol_is_valid        = staticsymbol_is_valid;

    }
    int read(bfd_vma memaddr, uint8_t *myaddr, unsigned int len, struct disassemble_info *info)
    {
        if (!get_many_bytes(memaddr, myaddr, len))
            return 1;
        else
            return 0;
    }
    void perror(int status, bfd_vma memaddr, struct disassemble_info *info)
    {
        hextracelog("error(%d, %08lx)\n", status, memaddr);
    }

    // defined after hexagon_disasm
    void printaddr(bfd_vma addr, struct disassemble_info *info);

    int symbolataddr(bfd_vma addr, struct disassemble_info *info)
    {
        hextracelog("symataddr(%08lx)\n", addr);
        return 0;
    }
    bfd_boolean symbol_is_valid(asymbol *sym, struct disassemble_info *info)
    {
        hextracelog("valid(%08lx, '%s', 0x%x)\n", sym->value, sym->name, sym->flags);
        return true;
    }

private:
    static int staticread(bfd_vma memaddr, uint8_t *myaddr, unsigned int len, struct disassemble_info *info)
    {
        return ((memory*)info->application_data)->read(memaddr, myaddr, len, info);
    }
    static void staticperror(int status, bfd_vma memaddr, struct disassemble_info *info)
    {
        return ((memory*)info->application_data)->perror(status, memaddr, info);
    }
    static void staticprintaddr(bfd_vma addr, struct disassemble_info *info)
    {
        return ((memory*)info->application_data)->printaddr(addr, info);
    }
    static int staticsymbolataddr(bfd_vma addr, struct disassemble_info *info)
    {
        return ((memory*)info->application_data)->symbolataddr(addr, info);
    }
    static bfd_boolean staticsymbol_is_valid(asymbol *sym, struct disassemble_info *info)
    {
        return ((memory*)info->application_data)->symbol_is_valid(sym, info);
    }
};

extern "C" const bfd_arch_info_type bfd_hexagon_arch;

// object wrapping calls to the objdump code 
struct hexagon_disasm {

    disassembler_ftype disfn;
    disasmoutput out;
    disassemble_info info;
    memory mem;

    struct state {
        state( std::vector<uint32_t> addrs, std::vector<uint32_t> imms, std::string text)
            : addrs(addrs), imms(imms), text(text)
        {
        }

        std::vector<uint32_t> addrs;
        std::vector<uint32_t> imms;
        std::string text;
    };
    std::vector<uint32_t> addrs;
    std::vector<uint32_t> imms;
    std::string text;



    int insnsize;

    const bfd_arch_info_type *find_arch(const char*arch)
    {
        for (auto p= &bfd_hexagon_arch; p ; p= p->next)
            if (strstr(p->printable_name, arch))
                return p;
        return &bfd_hexagon_arch;
    }

    hexagon_disasm()
    {
        bfd  abfd= {0};
        abfd.arch_info= find_arch("v55");
        disfn= hexagon_get_disassembler(&abfd);

        memset(&info,0,sizeof(info));

        out.initstream(&info);

        info.flavour = bfd_target_elf_flavour;
        info.arch = bfd_arch_unknown;  // bfd_arch_hexagon == 29 in hexagon source
        info.octets_per_byte = 1;

        info.endian_code = info.endian = BFD_ENDIAN_LITTLE;
        info.bytes_per_chunk= 4;
        info.display_endian= BFD_ENDIAN_LITTLE;
      
        mem.initinfo(&info);
    }

    // called from memory.printaddr
    void add_address(uint32_t addr)
    {
        addrs.push_back(addr);
        out.text += "@";
    }
    void calldisasm(ea_t ea)
    {
        static ea_t lastea;

        // note: the first instruction of a segment ( without valid preceeding instructions )
        // may be disassembled incorrectly when it uses 'immext', because static variables inside objdump
        // are not reset correctly.
        //
        // todo: process dummy NOPs to clear state.
        // then keep track of hexagon packet starts by using SetFlags(0x20000000)
        //
        // todo: always disasm complete packet, then feed ida information per packet.
        //
        // * packet ends in: insn with PP=11, or a duplexinsn: PP=00
        if (lastea!=ea && lastea!=ea-4) {
            for (int i=-12 ; i<0 ; i+=4) {
                addrs.clear();
                imms.clear();
                out.text.clear();

                dbgprintf("disfn(%08x) catchup(%d)\n", ea+i, i);
                disfn(ea+i, &info);
            }
        }
        addrs.clear();
        imms.clear();
        out.text.clear();

        dbgprintf("disfn(%08x)\n", ea);
        disfn(ea, &info);
        dbgprintf("   -> '%s'\n", out.text.c_str());

        lastea= ea;
        insnsize= 4;
    }

    int disasm(ea_t ea)
    {
        if (cachelookup(ea))
            return 4;

        calldisasm(ea);

        //std::string version1= out.text;
        text= out.text;

        check_constants();

        //dbgprintf("disasm(%08x) -> %s        ::      %s\n", ea, version1.c_str(), out.text.c_str());

        cachestate(ea);

        return insnsize;
    }
    void check_constants()
    {
        size_t pos= 0;
        while (pos != std::string::npos) {
            size_t h1= text.find('#', pos);
            if (h1==std::string::npos)
                break;
            size_t n1= text.find_first_not_of('#', h1);
            if (n1==std::string::npos)
                break;
            size_t e1= text.find_first_not_of("-0123456789abcdefx", n1);
            char *endptr=(e1==std::string::npos) ? (&text[0]+text.size()) : &text[e1];

            if (e1>n1) {

                char *p;
                int64_t value= strtoll(&text[n1], &p, 0);

                if (p!=endptr) {
                    errprintf("NOTE: strtoll decoded differently: str='%s',  num=%d..%d,  strtoll: ..%d\n",
                            text.c_str(), (int)n1, (int)e1, int(p-&text[0]));
                }
                
                //dbgprintf("const: (#)%d .. (^#)%d  (e)%d  (p)%d  (endnum)%d  '%s' -> %d\n", (int)h1, (int)n1, (int)e1, int(p-&text[0]), int(endptr-&text[0]), text.c_str(), value);

                imms.push_back(value);

                text.replace(n1, e1-n1, "$");
            }

            pos= n1+1;
        }
    }


    typedef std::map<ea_t, state> statemap_t;
    typedef std::list<ea_t>  history_t;

    statemap_t _cache;
    history_t _history;
    bool cachelookup(ea_t ea)
    {
        auto i= _cache.find(ea);
        if (i==_cache.end())
            return false;

        addrs= i->second.addrs;
        imms= i->second.imms;
        text= i->second.text;

        dbgprintf("cache found(%zd/%zd) %08x\n", _cache.size(), _history.size(), ea);
        return true;
    }
    void cachestate(ea_t ea)
    {
        _cache.insert(statemap_t::value_type(ea, state(addrs, imms, text)));
        _history.push_back(ea);
        if (_history.size()==16) {
            _cache.erase(_history.front());
            _history.pop_front();
        }
    }
};

// global object for objdump wrapper
hexagon_disasm H;

void memory::printaddr(bfd_vma addr, struct disassemble_info *info)
{
    H.add_address(addr);
    //hextracelog("addr(%08lx)", addr);
}


void dumpdb()
{
    char buf[512];
    if (get_input_file_path(buf, 512))
        hextracelog("in: %s\n", buf);
}

// -------- hexagon instruction magic
bool haspp(uint32_t w)
{
    return (w&0xc000)!=0;
}
bool is_duplex_insn(uint32_t w)
{
    return (w&0xc000)==0;
}

bool is_packet_end(uint32_t w)
{
    return ((w&0xc000)==0xc000) || is_duplex_insn(w);
}
// 01110001ii1xxxxxPPiiiiiiiiiiiiii  Rx.L=#u16
bool is_load_low(uint32_t w)
{
    return haspp(w) && ((w&0xff200000)==0x71200000);
}
// 01110010ii1xxxxxPPiiiiiiiiiiiiii  Rx.H=#u16
bool is_load_high(uint32_t w)
{
    return haspp(w) && ((w&0xff200000)==0x72200000);
}
bool isjumpfunc(ea_t ea)
{
   return (get_dword(ea   )==0xBFFD7F1D     // { r29 = add (r29, #-8)
        && get_dword(ea+ 4)==0xA79DFCFE     //   memw (r29 + #-8) = r28 }
        && is_load_high(get_dword(ea+ 8))   // r28.h = #0x42F7
        && is_load_low(get_dword(ea+ 12))   // r28.l = #0x9F10
        && get_dword(ea+16)==0xB01D411D     // { r29 = add (r29, #8)
        && get_dword(ea+20)==0x529C4000     //   jumpr r28
        && get_dword(ea+24)==0x919DC01C);   //   r28 = memw (r29 + #0) }
}
uint16_t getloadhalfword(uint32_t w)
{
    return (w&0x3fff) | ((w>>(22-14))&0xc000);
}
uint32_t getjumpfunctarget(ea_t ea)
{
        uint16_t high= getloadhalfword(get_dword(ea+ 8));
        uint16_t low = getloadhalfword(get_dword(ea+ 12));
        return (high<<16)|low;
}
int get_load_regnum(uint32_t w)
{
    return (w>>16)&0x1f;
}

//  0101101iiiiiiiiiPPiiiiiiiiiiiii0  call #r22:2
//  01011101ii0iiiiiPPi-0-uuiiiiiii-  if (Pu) call #r15:2
//  01011101ii1iiiiiPPi-0-uuiiiiiii-  if (!Pu) call #r15:2
bool is_immediate_call_insn(uint32_t w)
{
    if (is_duplex_insn(w))
        return false;
    return ((w&0xFF000800)==0x5D000000) // if ( ? Pu4 ) call #r15:2
        || ((w&0xFE000001)==0x5A000000);// call #r22:2

//        H.disasm(ea);
//        if (H.text.find("call")!=H.text.npos)
//            return 2;
}
//  01010000101sssssPP--------------  callr Rs
//  01010001000sssssPP----uu--------  if (Pu) callr Rs
//  01010001001sssssPP----uu--------  if (!Pu) callr Rs
bool is_register_call_insn(uint32_t w)
{
    if (is_duplex_insn(w))
        return false;
    return ((w&0xFFE00000)==0x50a00000) // callr Rs32
        || ((w&0xFFC00000)==0x51000000);// if ( ? Pu4 ) callr Rs32
}
// 01010010100sssssPP--------------  jumpr Rs
bool is_register_jump(uint32_t w)
{
    if (is_duplex_insn(w))
        return false;
    return (w&0xffe00000)==0x52800000;  // jumpr Rs
}
int get_jump_register(uint32_t w)
{
    return (w>>16)&0x1f;
}
// 0101100iiiiiiiiiPPiiiiiiiiiiiii-  jump #r22:2
// 0001-110--iiddddPPIIIIIIiiiiiii-  Rd=#U6 ; jump #r9:2
// 0001-111--iissssPP--ddddiiiiiii-  Rd=Rs ; jump #r9:2
bool is_relative_jump(uint32_t w)
{
    if (is_duplex_insn(w))
        return false;
    return ((w&0xfe000000)==0x58000000)   // jump #imm
        || ((w&0xf6000000)==0x16000000);  // Rd16 = [ #U6 | Rs16 ] ; jump #r9:2
}

// L2  1111101---0--   dealloc_return
// L2  1111111---0--   jumpr R31                        Return
//     2109876543210
bool is_sub_return(uint16_t w)
{
    return (w&0x1f44) == 0x1f40;
}
bool is_return(uint32_t w)
{
    if (is_register_jump(w) && get_jump_register(w)==31) // jumpr r31
        return true;
    if (!is_duplex_insn(w)) {
        return ((w&0xffff3c1f)==0x961e001e); // 1001011000011110PP0000-----11110  dealloc_return
    }
    uint8_t iclass= ((w>>29)<<1) | ((w>>13)&1);
    uint16_t ilow= w&0x1fff;
    uint16_t ihigh= (w>>16)&0x1fff;

    // note: jump ( and i assume deallocreturn )  must be in slot#0
    if (iclass==1 && is_sub_return(ilow))
        return true;
    if (iclass==2 && is_sub_return(ilow))
        return true;
    if (iclass==5 && is_sub_return(ilow))
        return true;

    return false;
}
bool is_immext(uint32_t w)
{
    return haspp(w)
        && ((w&0xf0000000)==0);
}

// note: wrong, and not yet used
//  - i should include conditional jumps as well.
bool is_basic_block_end(uint32_t w)
{
    if (is_register_jump(w))
        return true;
    if (is_relative_jump(w))
        return true;
    if (is_return(w))
        return true;
    return false;
}


enum insns {
    insn_other,
    insn_call,
    insn_jump,
    insn_stop
};

// these instructions are only used internally in this processor module, 
// they are not actually shown.
instruc_t Instructions[] = {
    { "",             0         },
    { "call",         CF_CALL   },
    { "jump",         CF_JUMP   },
    { "stop",         CF_STOP   },
};



void force_offset(const insn_t &cmd, int n, ea_t base, bool issub = false)
{
    uint32_t target= cmd.ops[0].value + base;
    if ( !is_off(get_flags(cmd.ea), n)
      || get_offbase(cmd.ea, n) != base )
    {
        if (is_mapped(target)) {
            refinfo_t ri;
            ri.init(REF_OFF32|REFINFO_NOBASE|(issub ? REFINFO_SUBTRACT : 0), base);
            int rc1= op_offset_ex(cmd.ea, n, &ri);
            dbgprintf("%08x->%08x opoff base=%08x -> %d\n", cmd.ea, target, base, rc1);
        }
        else {
            dbgprintf("%08x opoff base=%08x,  target %08x not enabled\n", cmd.ea, base, target);
        }
    }
    else {
        dbgprintf("%08x->%08x opoff already done\n", cmd.ea, target);
    }
}


// module registration

static asm_t gas = {
    ASH_HEXF3|ASD_DECF0|ASO_OCTF1|ASB_BINF3|AS_N2CHR|AS_LALIGN|AS_1TEXT|AS_ONEDUP|AS_COLON,
    1,                            // uflag
  "GNU assembler",              // name
    0,                            // help
    NULL,                         // header
  ".org",                       // origin
  ".end",                       // end

  "@",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\"'",        // special symbols in char and string constants

  ".ascii",     // ascii
  ".byte",      // byte
  ".short",     // word
  ".long",      // dword
  ".quad",      // qword
    NULL,         // oword  (16 bytes)
  ".float",     // float
  ".double",    // double
    NULL,         // tbyte (no information about this directive)
    NULL,         // packreal
  ".ds.#s(b,w,l,d) #d, #v", // arrays (#h,#d,#v,#s(...)
  ".ds.b %s",   // bss
  ".equ",       // equ
    NULL,         // seg
  ".",          // char *a_curip;
    NULL,         // function header
    NULL,         // function footer
  ".globl",     // public
    NULL,         // weak
  ".extern",    // extrn
    NULL,         // comdef
    NULL,         // get name of type
  ".align",     // align
  '(', ')',	// lbrace, rbrace
  "%",     // mod
  "&",     // and
  "|",     // or
  "^",     // xor
  "~",     // not
  ">>",    // shl
  "<<",    // shr
    NULL,    // sizeof
    0,       // flag2
    NULL,    // cmnt2
    NULL,    // low8
    NULL,    // high8
    NULL,    // low16
    NULL,    // high16
    NULL,    // include
    NULL,    // vstruc
    NULL,    // rva
    NULL,    // yword
};

asm_t *asms[]       = { &gas, NULL };


static const char *const RegNames[] =
{
"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23", "r24", "r25", "r26", "r27", "r28", "SP", "FP", "LR", 
"sa0", "lc0", "sa1", "lc1", "p3", "p2", "p1", "p0", "m0", "m1", "usr", "pc", "ugp", "gp",
"cs", "ds"
};

#define rVcs (qnumber(RegNames)-2)
#define rVds (qnumber(RegNames)-1)

//--------------------------------------------------------------------------
static const uchar retcode_jmplr[] = { 0x00, 0xc0, 0x9f, 0x52 };

static const bytes_t retcodes[] =
{
 { sizeof(retcode_jmplr), retcode_jmplr },
 { 0, NULL }
};

class hexagon_module : public processor_module {
    public:
    int ana_insn(insn_t &cmd) override
    {
        hextracelog("ana(%08x)\n", cmd.ea);
        if (cmd.ea & 3)
            return 0;

        H.disasm(cmd.ea);
        if (H.text.find("<unknown>")!=H.text.npos)
            return 0;

        static ea_t prevea;           // what instruction did we previously process?
        static int  packetflags;      // used to keep track of the current packet properties

        // when not going through the code linearly reset the flags.
        if (prevea+4!=cmd.ea) {
            packetflags= 0;
        }

        cmd.size= H.insnsize;

        uint32_t opcode= get_dword(cmd.ea);

        // handle instruction packet boundaries
        if (is_return(opcode)) {
            packetflags |= CF_STOP;
            if (is_packet_end(opcode))
                cmd.itype= insn_stop;
            else
                cmd.itype= insn_other;
        }
        else if (is_immediate_call_insn(opcode)) {
            cmd.itype= insn_call;
        }
        else if (is_relative_jump(opcode) || is_register_jump(opcode) || is_return(opcode)) {
            packetflags |= CF_STOP;
            if (is_packet_end(opcode))
                cmd.itype= insn_stop;
            else
                cmd.itype= insn_other;
        }
        else {
            if (is_packet_end(opcode)) {
                if (packetflags&CF_STOP)
                    cmd.itype= insn_stop;
                else
                    cmd.itype= insn_other;
            }
            else {
                cmd.itype= insn_other;
            }
        }
        dbgprintf("%08x -> type: %x: %s, flags=%x:  %s\n", cmd.ea, cmd.itype, Instructions[cmd.itype].name, packetflags, H.text.c_str());


        // translate operands

        op_t *op= cmd.ops;
        op_t *opend = cmd.ops+6;

        int ia= 0;
        int im= 0;
        for (std::string::iterator i= H.text.begin() ; i != H.text.end() ; ++i)
        {
            switch(*i) {
                case '@':
                    if (op==opend) {
                        errprintf("too many operands: '%s'\n", H.text.c_str());
                    }
                    else if (ia<H.addrs.size()) {
                        op->type= (cmd.itype || H.text.find("jump")!=H.text.npos) ? o_near : o_mem;
                        op->addr= H.addrs[ia++];
                        op->dtype  = dt_dword;

                        dbgprintf("ana->op%d : adr %08x, t=%d\n", op->n, op->addr, op->type);

                        op++;
                    }
                    else {
                        errprintf("too many addresses(%d>=%zd): '%s'\n", ia, H.addrs.size(), H.text.c_str());
                    }
                    break;
                case '$':
                    if (op==opend) {
                        errprintf("too many operands: '%s'\n", H.text.c_str());
                    }
                    else if (im<H.imms.size()) {
                        op->type= o_imm;
                        op->value= H.imms[im++];
                        op->dtype  = dt_dword;

                        dbgprintf("ana->op%d : imm %08x\n", op->n, op->value);

                        op++;
                    }
                    else {
                        errprintf("too many immediates: '%s'\n", H.text.c_str());
                    }

                    break;
            }
        }

        if (is_packet_end(opcode))
            packetflags= 0;
        prevea= cmd.ea;
        return cmd.size;
    }

    int emu_insn(const insn_t& cmd) override
    {
        hextracelog("emu(%08x), itype=%d\n", cmd.ea, cmd.itype);
        uint32_t insn= get_dword(cmd.ea);

        // note: insn_jump and insn_stop do not cause a cref fl_F
        if (cmd.itype==insn_call || cmd.itype==insn_other) {
            //printf("adding flow %08x -> +%d\n", cmd.ea, cmd.size);
            cmd.add_cref(cmd.ea+cmd.size, 0, fl_F);
        }

        // attempt to convert Rx32.[hl] = #u16  instruction pairs to real offsets
        // problem is that doing so causes ida to get stuck trying to 'emu'
        // the current instruction
        if (is_load_low(insn)) {
            int i=4;
            while (i<=16) {
                uint32_t previnsn= get_dword(cmd.ea-i);
                if (is_load_high(previnsn)) {
                    if (get_load_regnum(insn)==get_load_regnum(previnsn)) {
                        force_offset(cmd, 0, getloadhalfword(previnsn)<<16);
                        break;
                    }
                }
                uint32_t nextinsn= get_dword(cmd.ea+i);
                if (is_load_high(nextinsn)) {
                    if (get_load_regnum(insn)==get_load_regnum(nextinsn)) {
                        force_offset(cmd, 0, getloadhalfword(nextinsn)<<16);
                        break;
                    }
                }

                i+=4;
            }
        }

        for (int i=0 ; i<6 ; i++)
        {
            if (cmd.ops[i].type==o_near) {
                dbgprintf("adding cref\n");

                if (!is_immediate_call_insn(insn))
                    cmd.add_cref(cmd.ops[i].addr, i, fl_JN);
                else
                    cmd.add_cref(cmd.ops[i].addr, i, fl_CN);
            }
            else if (cmd.ops[i].type==o_mem) {
                dbgprintf("adding dref\n");
                // todo: figure out if we are loading or storing.
                cmd.add_dref(cmd.ops[i].addr, i, dr_R);
            }
            else if (cmd.ops[i].type==o_imm) {
                if (!is_immext(insn)) {
                    if (is_mapped(cmd.ops[i].value))
                        force_offset(cmd, i, 0);
                    if (is_off(get_flags(cmd.ea), i)) {
                        dbgprintf("adding drefs\n");
                        //cmd.add_dref(target, i, dr_O);
                        cmd.add_off_drefs(cmd.ops[i], dr_O, 0/*outflags*/);
                    }

                }
                else {
                    op_num(cmd.ea, i);
                }
            }
        }

        // trace stack pointer -> add_auto_stkpnt2(get_func(cmd.ea), cmd.ea+cmd.size, delta);
        // r29 = {add|sub}(r29, #)
        //
        // create stackvars:
        //     ua_stkvar2(x, x.addr, 0) && op_stkvar(cmd.ea, x.n)
        return 1;
    }

    void out_insn(outctx_t &ctx) override
    {
        auto &cmd = ctx.insn;

        //char buf[MAXSTR];
        //init_output_buffer(buf, sizeof(buf));
        hextracelog("out(%08x)\n", cmd.ea);

        H.disasm(cmd.ea);

        ctx.out_mnemonic();

        std::string txt= H.text;
        int io= 0;
        for (std::string::iterator i= txt.begin() ; i != txt.end() ; ++i)
        {
            //dbgprintf("%p [ %p-%p ] : %02x\n", &*i, &*txt.begin(), &*txt.end(), *i);
            switch(*i) {
                case '$':
                case '@':
                    if (io==6) {
                        errprintf("@%08x/%d: too many operands: '%s'\n", (uint32_t)cmd.ea, int(i-txt.begin()), txt.c_str());
                        return;
                    }
                    else {
                        ctx.out_one_operand(io++);
                    }
                    break;
                default:
                    ctx.out_char(*i);
            }
        }
        //term_output_buffer();

        //dbgprintf("out:%s\n", buf);
        //gl_comm = 1;                  // generate a user defined comment on this line
        //MakeLine(buf, -1);
        ctx.out_immchar_cmts();
        ctx.flush_outbuf();
    }

    int out_operand(outctx_t &ctx, const op_t &op) override
    {
        auto &cmd = ctx.insn;

        //dbgprintf("op %d: d:%x/f:%x/t:%x, value=%x, addr=%x\n", op.n, op.dtype, op.flags, op.type, op.value, op.addr);
        if (op.type==o_near || op.type==o_mem) {
            qstring symbuf;
            ssize_t n= get_name_expr(&symbuf, cmd.ea+op.offb, op.n, op.addr, op.addr);
            if (n>0)
                ctx.out_line(symbuf.c_str());
            else
                ctx.out_value(op, OOF_ADDR);
            return 1;
        }
        else {
            ctx.out_value(op, OOFW_IMM);
            return 1;
        }
        return -1;
        //ctx.gen_printf(-1, "op");
    }
    // ----- output functions
    void out_header(outctx_t &ctx) override
    {
        hextracelog("added header\n");
        ctx.gen_cmt_line("Processor       : %s", inf.procName);
        ctx.gen_cmt_line("Target assembler: %s", ash.name);
        ctx.gen_cmt_line("Byte sex        : %s", inf_is_be() ? "Big endian" : "Little endian");
        ctx.gen_cmt_line("");
        ctx.gen_cmt_line("Hexagon processor module (c) 2017 GSMK");
        ctx.gen_cmt_line("author: Willem Jan Hengeveld, itsme@gsmk.de");
    //if ( ash.header != NULL )
    //  for ( auto ptr=ash.header; *ptr != NULL; ptr++ )
    //    ctx.gen_printf(0,COLSTR("%s",SCOLOR_ASMDIR),*ptr);
    }
    void out_footer(outctx_t &ctx) override
    {
        hextracelog("added footer\n");
        qstring name = get_colored_name(BADADDR, inf.start_ea);
        ctx.gen_printf(-1,COLSTR("%s",SCOLOR_ASMDIR) " %s", ash.end, name.c_str());
    }

    int out_segstart(outctx_t &ctx, segment_t &seg) override
    {
        hextracelog("segment start(%08x)\n", seg.start_ea);
        ctx.gen_cmt_line("segstart");
        return 0;
    }
    int out_segend(outctx_t &ctx, segment_t &seg) override
    {
        hextracelog("segment end(%08x)\n", seg.start_ea);
        ctx.gen_cmt_line("segend");
        return 0;
    }
    int out_mnem(outctx_t &outctx) override
    { 
        // the hexagon instruction consists only of operands.
        return 1;
    }

    /*  code&0xFFFF0000 == 0xA09D0000  - allocframe
     *       localsize = code&0x7FF
     *
     *  subinsn: code&0x1E00 == 0x1C00
     *       localsize = (code>>4)&0x1F
     *
     *  locate __save_rX_through_rY   type functions:
     *     memd (r30 + #0xFFFFFFD0) = r27:26
     *

     A  011uuuuuudddd   Rd = add(r29,#u6:2)              Add immediate to stack pointer
    L2  1110uuuuudddd   Rd = memw(r29+#u5:2)             Load word from stack
    L2  11110uuuuuddd   Rdd = memd(r29+#u5:3)            Load pair from stack
    S2  0100uuuuutttt   memw(r29+#u5:2) = Rt             Store word to stack
    S2  0101ssssssttt   memd(r29+#s6:3) = Rtt            Store pair to stack
    S2  1110uuuuu----   allocframe(#u5:3)                Allocate stack frame

    */
    int create_func_frame(func_t &pfn) override
    {
        return 0;
    }
    void newfile(const char *fname) override
    {
        // extra linefeeds to increase visibility of this message
        msg("\n\n");
        msg("Hexagon/QDSP6 processor module v1.1 (C) 2017 GSMK, author: Willem Jan Hengeveld, itsme@gsmk.de\n");
        msg("based on hexagon objdump from https://www.codeaurora.org/patches/quic/hexagon/4.0/Hexagon_Tools_source.tgz\n");
        msg("\n");

    }


    virtual int is_sane_insn(const insn_t &cmd, int no_crefs) override
    {
        hextracelog("is_sane_insn(%08x, %d)\n", cmd.ea, no_crefs);

        // zero not an insn
        if (get_dword(cmd.ea)==0)
            return 0;

        // no more than 4 nops considered normal
        for (int i=0 ; i<4 ; i++)
            if (get_dword(cmd.ea+4*i)!=0x7f004000)
                return 1;
        return 0;
    }

    virtual int is_jump_func(func_t &pfn, ea_t *jump_target, ea_t *func_pointer) override
    {
        if (isjumpfunc(pfn.start_ea)) {
            *jump_target= getjumpfunctarget(pfn.start_ea);
            if (func_pointer)
                *func_pointer= -1;
            hextracelog("is_jump_func(%08x)-> yes: %08x\n", pfn.start_ea, *jump_target);
            return 1;
        }
        else {
            hextracelog("is_jump_func(%08x)-> no\n", pfn.start_ea);
        }

        return 0;
    }

    // only when PR_DELAYED is set in LPH.flags
    virtual int is_basic_block_end(const insn_t &insn, bool call_insn_stops_block) override
    {
        hextracelog("is_basic_block_end(%d)\n", call_insn_stops_block);
        if (::is_basic_block_end(get_dword(insn.ea)))
            return 1;

        return 0;
    }

    virtual int is_call_insn(const insn_t &insn) override
    {
        bool iscall= false;
        if (is_immediate_call_insn(get_dword(insn.ea)))
            iscall= true;
        hextracelog("is_call_insn(%08x) -> %d\n", insn.ea, iscall);
        if (iscall)
            return 1;

        return 0;
    }
    virtual int is_ret_insn(const insn_t &insn, bool strict) override
    {
        hextracelog("is_ret_insn(%08x, %d)\n", insn.ea, strict);

        uint32_t opcode= get_dword(insn.ea);
        if (is_return(opcode))
            return 1;

        return 0;
    }
    virtual int creating_segm(segment_t &seg) override
    {
        if (seg.type == SEG_CODE)
            seg.align = saRelDble;
        return 1;
    }
};

static ssize_t idaapi staticnotifyhook(void *user_data, int notification_code, va_list va)
{
    if ( notification_code == processor_t::ev_get_procmod )
    {
#ifdef TRACELOG
        g_log= qfopen("hexagon.log", "a+");
#endif
        return size_t(new hexagon_module);
    }

    return 0;
}

processor_t LPH =
{
    .version=IDP_INTERFACE_VERSION,// version
    .id=0x8666,               // id,  above 0x8000: thirdparty module
/*  flags used
= PR_USE32           // supports 32-bit addressing?
= PR_DEFSEG32        // segments are 32-bit by default

-- by hexagon
- PR_WORD_INS        // instruction codes are grouped 2bytes in binrary line prefix
h PR_NO_SEGMOVE      // the processor module doesn't support move_segm() (i.e. the user can't move segments)
h PRN_HEX            // default number representation: == hex
? PR_DELAYED         // has delayed jumps and calls if this flag is set, ph.is_basic_block_end should be implemented
-- by arm module
a PR_SEGS            // has segment registers?
a PR_RNAMESOK        // allow to user register names for location names
a PR_TYPEINFO        // the processor module supports type information callbacks ALL OF THEM SHOULD BE IMPLEMENTED!  (the ones >= decorate_name)
a PR_SGROTHER        // the segment registers don't contain the segment selectors, something else
a PR_USE_ARG_TYPES   // use ph.use_arg_types callback
a PR_CNDINSNS        // has conditional instructions
*/

    .flag=PR_CNDINSNS|PR_NO_SEGMOVE|PR_USE32|PR_DEFSEG32|PRN_HEX|PR_ALIGN,             // flags
    .flag2=0,                                                                  // flags2
    .cnbits=8,                    // int32 cnbits - 8 bits in a byte for code segments
    .dnbits=8,                    // int32 dnbits - 8 bits in a byte for other segments

    .psnames=shnames,              // char **psnames -- names shorter than 9 chars.
    .plnames=lnames,               // char **plnames

    .assemblers=asms,                 // asm_t **assemblers

    ._notify=&staticnotifyhook,        // hook_cb_t 

    .reg_names=RegNames,                     // Register names         char **reg_names;         
    .regs_num=qnumber(RegNames),            // Number of registers    int32 regs_num;                       

    .reg_first_sreg=rVcs,                         // first       int32 reg_first_sreg;                 
    .reg_last_sreg=rVds,                         // last        int32 reg_last_sreg;                  
    .segreg_size=1,                            // size of a segment register   int32 segreg_size;                    
    .reg_code_sreg=rVcs,                         // int32 reg_code_sreg;                  
    .reg_data_sreg=rVds,                         // int32 reg_data_sreg;                  

    .codestart=NULL,                         // No known code start sequences  const bytes_t *codestart;             
    .retcodes=NULL,             // const bytes_t *retcodes;              

    .instruc_start=0,                            // int32 instruc_start;                  
    .instruc_end=qnumber(Instructions),        // int32 instruc_end;                    
    .instruc=Instructions,                 // const instruc_t *instruc;             

    .tbyte_size= sizeof(long double),
    .real_width= { 2, 4, 8, 16 },
    .icode_return=0,
    .unused_slot=NULL,
};
