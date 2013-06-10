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

#ifdef _WIN32
#define strtoll _strtoui64
#endif

#ifdef TRACELOG
#define hextracelog(...)  qfprintf(g_log, __VA_ARGS__)
#define dbgprintf(...)  qfprintf(g_log, __VA_ARGS__)
#define errprintf(...)  qfprintf(g_log, "ERROR: " __VA_ARGS__)
#else
#define hextracelog(...)
#define dbgprintf(...)
#define errprintf(...)  msg("hexagon: " __VA_ARGS__)
#endif

FILE *g_log;


// object providing an output target for the bfd code, so
// this IDA module will be able to use the output.
struct disasmoutput {

    std::string text;

    void initstream(disassemble_info*info)
    {
        info->fprintf_func = (fprintf_ftype)staticprintf;
        info->stream = this;
    }

    int vprintf(const char*fmt, va_list va)
    {
        text.resize(text.size()+256);
        size_t n= vsnprintf(&text[text.size()-256], 256, fmt, va);
        text.resize(text.size()-256+n);
        return n;
    }
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

    hexagon_disasm()
    {
        disfn= hexagon_get_disassembler_from_mach(4, 0);

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

            char *p;
            int64_t value= strtoll(&text[n1], &p, 0);

            if (p!=endptr) {
                errprintf("NOTE: strtoll decoded differently: str='%s',  num=%d..%d,  strtoll: ..%d\n",
                        text.c_str(), (int)n1, (int)e1, p-&text[0]);
            }

            imms.push_back(value);

            text.replace(n1, e1-n1, "$");

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
bool is_packet_end(uint32_t w)
{
    return (w&0xc000)==0xc000;
}
bool is_load_low(uint32_t w)
{
    return haspp(w) && ((w&0xff200000)==0x71200000);
}
bool is_load_high(uint32_t w)
{
    return haspp(w) && ((w&0xff200000)==0x72200000);
}
bool isjumpfunc(ea_t ea)
{
   return (get_long(ea   )==0xBFFD7F1D     // { r29 = add (r29, #-8)
        && get_long(ea+ 4)==0xA79DFCFE     //   memw (r29 + #-8) = r28 }
        && is_load_high(get_long(ea+ 8))   // r28.h = #0x42F7
        && is_load_low(get_long(ea+ 12))   // r28.l = #0x9F10
        && get_long(ea+16)==0xB01D411D     // { r29 = add (r29, #8)
        && get_long(ea+20)==0x529C4000     //   jumpr r28
        && get_long(ea+24)==0x919DC01C);   //   r28 = memw (r29 + #0) }
}
uint16_t getloadhalfword(uint32_t w)
{
    return (w&0x3fff) | ((w>>(22-14))&0xc000);
}
uint32_t getjumpfunctarget(ea_t ea)
{
        uint16_t high= getloadhalfword(get_long(ea+ 8));
        uint16_t low = getloadhalfword(get_long(ea+ 12));
        return (high<<16)|low;
}
int get_load_regnum(uint32_t w)
{
    return (w>>16)&0x1f;
}

bool is_immediate_call_insn(uint32_t w)
{
    if (!haspp(w))
        return false;
    return ((w&0xFF001800)==0x5D000000) // if ( ? Pu4 ) call #r15:2
        || ((w&0xFE000001)==0x5A000000);// call #r22:2

//        H.disasm(ea);
//        if (H.text.find("call")!=H.text.npos)
//            return 2;
}
bool is_register_call_insn(uint32_t w)
{
    if (!haspp(w))
        return false;
    return ((w&0xFFE00000)==0x50a00000) // callr Rs32
        || ((w&0xFFC00000)==0x51000000);// if ( ? Pu4 ) callr Rs32
}
bool is_register_jump(uint32_t w)
{
    if (!haspp(w))
        return false;
    return (w&0xffe00000)==0x52800000;  // jumpr Rs
}
int get_jump_register(uint32_t w)
{
    return (w>>16)&0x1f;
}
bool is_relative_jump(uint32_t w)
{
    if (!haspp(w))
        return false;
    return ((w&0xfe000000)==0x58000000)   // jump #imm
        || ((w&0xf6000000)==0x16000000);  // Rd16 = #U6 ; jump #r9:2
}
bool is_jump_lr(uint32_t w)
{
    if (haspp(w))
        return false;

    return ((w&0xa0003fc4) == 0x00003fc0)
         || ((w&0xf0003fc4) == 0x20001fc0)
         || ((w&0xf8003fc4) == 0x30001fc0)
         || ((w&0xfe003fc4) == 0x3c001fc0)
         || ((w&0xff003fc4) == 0x3e001fc0)
         || ((w&0xffc43fc4) == 0x3f001fc0);
}

bool is_return(uint32_t w)
{
    if (!haspp(w))
        return false;
      if (is_register_jump(w) && get_jump_register(w)==31) // jumpr r31
          return true;
    return ((w&0xe0003f44)==0x00003f40) //  000- ----  ---- ----   PP11 1111  -1-- -0--
        || ((w&0xf0003f44)==0x20001f40) //  0010 ----  ---- ----   PP01 1111  -1-- -0--
        || ((w&0xf8003f44)==0x30001f40) //  0011 0---  ---- ----   PP01 1111  -1-- -0--
        || ((w&0xfe003f44)==0x3c001f40) //  0011 110-  ---- ----   PP01 1111  -1-- -0--
        || ((w&0xff003f44)==0x3e001f40) //  0011 1110  ---- ----   PP01 1111  -1-- -0--
        || ((w&0xffc43fc4)==0x3f001fc0) //  0011 1111  00-- -0--   PP01 1111  11-- -0--
        || ((w&0xe0003f44)==0x40003f40) //  010- ----  ---- ----   PP11 1111  -1-- -0--
        || ((w&0xffff3c1f)==0x961e001e);//  1001 0110  0001 1110   PP00 00--  ---1 1110 
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
    if (is_jump_lr(w))
        return true;
    if (is_return(w))
        return true;
    return false;
}



// ----- output functions
void header(void)
{
    hextracelog("added header\n");
    gen_cmt_line("Processor       : %s", inf.procName);
    gen_cmt_line("Target assembler: %s", ash.name);
    gen_cmt_line("Byte sex        : %s", inf.mf ? "Big endian" : "Little endian");
    gen_cmt_line("");
    gen_cmt_line("Hexagon processor module (c) 2013 GSMK");
    gen_cmt_line("author: Willem Jan Hengeveld, itsme@gsmk.de");
//if ( ash.header != NULL )
//  for ( auto ptr=ash.header; *ptr != NULL; ptr++ )
//    printf_line(0,COLSTR("%s",SCOLOR_ASMDIR),*ptr);
}
void footer(void)
{
    hextracelog("added footer\n");
    char name[MAXSTR];
    get_colored_name(BADADDR, inf.beginEA, name, sizeof(name));
    printf_line(-1,COLSTR("%s",SCOLOR_ASMDIR) " %s", ash.end, name);
}

void segstart(ea_t ea)
{
    hextracelog("segment start(%08x)\n", ea);
    gen_cmt_line("segstart");
}
void segend(ea_t ea)
{
    hextracelog("segment end(%08x)\n", ea);
    gen_cmt_line("segend");
}

// Analyze one instruction and fill 'cmd' structure.
// cmd.ea contains address of instruction to analyze.
// Return length of the instruction in bytes, 0 if instruction can't be decoded.
// This function shouldn't change the database, flags or anything else.
// All these actions should be performed only by u_emu() function.

enum insns {
    insn_other,
    insn_call,
    insn_jump,
    insn_stop
};
// empty for now
instruc_t Instructions[] = {
    { "",             0         },
    { "call",         CF_CALL   },
    { "jump",         CF_JUMP   },
    { "stop",         CF_STOP   },
};


int idaapi ana(void)
{
    hextracelog("ana(%08x)\n", cmd.ea);
    H.disasm(cmd.ea);
    if (H.text.find("<unknown>")!=H.text.npos)
        return 0;

    static ea_t prevea;
    static int  packetflags;
    if (prevea+4!=cmd.ea) {
        packetflags= 0;
    }

    cmd.size= H.insnsize;

    uint32_t opcode= get_long(cmd.ea);

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
    else if (is_relative_jump(opcode) || is_register_jump(opcode) || is_jump_lr(opcode)) {
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
    dbgprintf("%08x -> type: %s, flags=%x\n", cmd.ea, Instructions[cmd.itype].name, packetflags);


    // translate operands

    op_t *op= cmd.Operands;
    op_t *opend = cmd.Operands+6;

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
                    op->type= o_near;
                    op->addr= H.addrs[ia++];
                    op->dtyp  = dt_code;

                    dbgprintf("ana->op%d : adr %08x\n", op->n, op->addr);

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
                    op->dtyp  = dt_dword;

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

void force_offset(ea_t ea, int n, ea_t base, bool issub = false)
{
    uint32_t target= cmd.Operands[0].value + base;
    if ( !isOff(get_flags_novalue(ea), n)
      || get_offbase(ea, n) != base )
    {
        if (isEnabled(target)) {
            refinfo_t ri;
            ri.init(REF_OFF32|REFINFO_NOBASE|(issub ? REFINFO_SUBTRACT : 0), base);
            int rc1= op_offset_ex(ea, n, &ri);
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
//
// Emulate instruction, create cross-references, plan to analyze
// subsequent instructions, modify flags etc. Upon entrance to this function
// all information about the instruction is in 'cmd' structure.
// If zero is returned, the kernel will delete the instruction.

int idaapi emu(void)
{
    hextracelog("emu(%08x), itype=%d\n", cmd.ea, cmd.itype);
    uint32_t insn= get_long(cmd.ea);

    if (cmd.itype==insn_call || cmd.itype==insn_other) {
        printf("adding flow %08x -> +%d\n", cmd.ea, cmd.size);
        ua_add_cref(0,cmd.ea+cmd.size,fl_F);
    }

    // attempt to convert Rx32.[hl] = #u16  instruction pairs to real offsets
    // problem is that doing so causes ida to get stuck trying to 'emu'
    // the current instruction
    if (is_load_low(insn)) {
        int i=4;
        while (i<=16) {
            uint32_t previnsn= get_long(cmd.ea-i);
            if (is_load_high(previnsn)) {
                if (get_load_regnum(insn)==get_load_regnum(previnsn)) {
                    force_offset(cmd.ea, 0, getloadhalfword(previnsn)<<16);
                    break;
                }
            }
            uint32_t nextinsn= get_long(cmd.ea+i);
            if (is_load_high(nextinsn)) {
                if (get_load_regnum(insn)==get_load_regnum(nextinsn)) {
                    force_offset(cmd.ea, 0, getloadhalfword(nextinsn)<<16);
                    break;
                }
            }

            i+=4;
        }
    }

    for (int i=0 ; i<6 ; i++)
    {
        if (cmd.Operands[i].type==o_near) {
            if (!is_immediate_call_insn(insn))
                ua_add_cref(i, cmd.Operands[i].addr, fl_JN);
            else
                ua_add_cref(i, cmd.Operands[i].addr, fl_CN);
        }
        else if (cmd.Operands[i].type==o_imm) {
            if (!is_immext(insn)) {
                if (isEnabled(cmd.Operands[i].value))
                    force_offset(cmd.ea, i, 0);
                if (isOff(getFlags(cmd.ea), i)) {
                    dbgprintf("adding drefs\n");
                    //ua_add_dref(i, target, dr_O);
                    ua_add_off_drefs(cmd.Operands[i], dr_O);
                }

            }
            else {
                op_num(cmd.ea, i);
            }
        }
    }
    return 1;
}

// Generate text representation of an instruction in 'cmd' structure.
// This function shouldn't change the database, flags or anything else.
// All these actions should be performed only by u_emu() function.

void idaapi out(void)
{
    char buf[MAXSTR];
    init_output_buffer(buf, sizeof(buf));
    hextracelog("out(%08x)\n", cmd.ea);

    H.disasm(cmd.ea);

    std::string txt= H.text;
    int io= 0;
    for (std::string::iterator i= txt.begin() ; i != txt.end() ; ++i)
    {
        //dbgprintf("%p [ %p-%p ] : %02x\n", &*i, &*txt.begin(), &*txt.end(), *i);
        switch(*i) {
            case '$':
            case '@':
                if (io==6) {
                    errprintf("@%08x/%d: too many operands: '%s'\n", cmd.ea, i-txt.begin(), txt.c_str());
                    return;
                }
                else {
                    out_one_operand(io++);
                    dbgprintf("out:%d  -> %s\n", io-1, buf);
                }
                break;
            default:
                out_symbol(*i);
        }
    }
    term_output_buffer();

    dbgprintf("out:%s\n", buf);
    gl_comm = 1;                  // generate a user defined comment on this line
    MakeLine(buf, -1);
}

// Generate text representation of an instructon operand.
// This function shouldn't change the database, flags or anything else.
// All these actions should be performed only by u_emu() function.
// The output text is placed in the output buffer initialized with init_output_buffer()
// This function uses out_...() functions from ua.hpp to generate the operand text
// Returns: 1-ok, 0-operand is hidden.

bool  idaapi outop(op_t &op)
{
    //dbgprintf("op %d: d:%x/f:%x/t:%x, value=%x, addr=%x\n", op.n, op.dtyp, op.flags, op.type, op.value, op.addr);
    if (op.type==o_near) {
        char symbuf[256];
        size_t n= get_name_expr(cmd.ea+op.offb, op.n, op.addr, op.addr, symbuf, 256);
        if (n)
            OutLine(symbuf);
        else
            OutValue(op, OOF_ADDR);
        return true;
    }
    else {

        OutValue(op, OOFW_IMM);
        return true;
    }
    return false;
    //printf_line(-1, "op");
}


// registration
static int notify(processor_t::idp_notify msgid, ...) // Various messages:
{
#ifdef TRACELOG
    if (!g_log) g_log= qfopen("hexagon.log", "a+");
#endif
    va_list va;
    va_start(va, msgid);

// A well behaving processor module should call invoke_callbacks()
// in his notify() function. If this function returns 0, then
// the processor module should process the notification itself
// Otherwise the code should be returned to the caller:

    hextracelog("hexagon:notify msgid=%2d: ", msgid);
    int code = invoke_callbacks(HT_IDP, msgid, va);
    if ( code ) return code;

    switch(msgid)
    {
      case ph.init:
          hextracelog("init(%s)\n", va_arg(va, const char*));
          break;
      case ph.term:
          hextracelog("term()\n");
          if (g_log) {
              qfclose(g_log);
              g_log= NULL;
          }
          break;
      case ph.newprc:
          hextracelog("newprc(%d)\n", va_argi(va, int));
          break;
      case ph.newasm:
          hextracelog("newasm(%d)\n", va_argi(va, int));
          break;
      case ph.newfile:
          // extra linefeeds to increase visibility of this message
          msg("\n\n");
          msg("Hexagon/QDSP6 processor module v1.0 (C) 2013 GSMK, author: Willem Jan Hengeveld, itsme@gsmk.de\n");
          msg("based on hexagon objdump from https://www.codeaurora.org/patches/quic/hexagon/4.0/Hexagon_Tools_source.tgz\n");
          msg("\n");

          hextracelog("newfile(%s)\n", va_arg(va, const char*));
          break;
      case ph.oldfile:
          hextracelog("oldfile(%s)\n", va_arg(va, const char*));
          break;
      case ph.newseg:
          {
          segment_t *seg= va_arg(va, segment_t*);
          hextracelog("newseg(%08x-%08x)\n", seg->startEA, seg->endEA);
          }
          break;
      case ph.rename:
          {
              ea_t ea             = va_arg(va,ea_t );
              const char *new_name= va_arg(va,const char *);

              hextracelog("rename(%08x, '%s')\n", ea, new_name);
          }
          break;
      case ph.renamed:
          {
              ea_t ea             = va_arg(va,ea_t );
              const char *new_name= va_arg(va,const char *);
              bool localname      = va_argi(va, bool);

              hextracelog("rename(%08x, '%s', %d)\n", ea, new_name, localname);
          }
          break;

      case ph.kernel_config_loaded:
          hextracelog("kernel_config_loaded\n");
          break;
      case ph.loader_elf_machine:
          {
          /*linput_t *li             =*/ va_arg(va, linput_t *);
          int machine_type          = va_argi(va, int );
          /*const char **p_procname  =*/ va_arg(va, const char **);
          /*void **p_pd              =*/ va_arg(va, void **);  // proc_def
          /*void *set_reloc= */ va_arg(va, void *); // set_elf_reloc_t

          hextracelog("loader_elf_machine, mt=%d\n", machine_type);
          }
          break;
      case ph.str2reg:
          hextracelog("str2reg('%s')\n", va_arg(va, const char*));
          break;
      case ph.loader_finished:
          {
          /*linput_t *li           =*/ va_arg(va, linput_t *);
          uint16 neflags          = va_argi(va, uint16);
          const char *filetypename= va_arg(va, const char *);
          hextracelog("loader_finished(%04x, '%s')\n", neflags, filetypename);
          }
          break;
      case ph.savebase:
          hextracelog("savebase\n");
          break;
      case ph.closebase:
          hextracelog("closebase\n");
          break;


      case ph.gen_asm_or_lst:
          {
          bool starting= va_argi(va, bool);
          hextracelog("gen_asm_or_lst(%d)\n", starting);
          }
          break;
      case ph.outlabel:
          {
          ea_t ea = va_arg(va, ea_t );
          const char *colored_name = va_arg(va, const char *);
          hextracelog("outlabel(%08x, '%s')\n", ea, colored_name);
          }
          break;
      case ph.coagulate:
          {
          ea_t start_ea = va_arg(va, ea_t );
          hextracelog("coagulate(%08x)\n", start_ea);
          }
          break;
      case ph.auto_empty:
          {
          hextracelog("auto_empty\n");
          }
          break;
      case ph.auto_empty_finally:
          {
          hextracelog("auto_empty_finally\n");
          }
          break;
      case ph.auto_queue_empty:
          {
          atype_t type = va_arg(va, atype_t );
          hextracelog("auto_queue_empty(%d)\n", type);
          }
          break;
      case ph.custom_ana:
          {
          hextracelog("custom_ana, cmd:%08x\n", cmd.ea);
          }
          break;
      case ph.custom_emu:
          {
          hextracelog("custom_emu, cmd:%08x\n", cmd.ea);
          }
          break;
      case ph.custom_out:
          {
          hextracelog("custom_out, cmd:%08x\n", cmd.ea);
          }
          break;
      case ph.custom_outop:
          {
          op_t *op= va_arg(va, op_t*);
          hextracelog("custom_outop, cmd:%08x, n=%d   %08x\n", cmd.ea, op->n, op->addr);
          }
          break;
      case ph.custom_mnem:
          {
          /*char *outbuffer= */va_arg(va, char*);
          /*size_t bufsize= */va_arg(va, size_t);
          hextracelog("custom_mnem()\n");
          }
          break;
      case ph.make_data:
          {
          ea_t ea = va_arg(va, ea_t );
          flags_t flags = va_arg(va, flags_t );
          tid_t tid = va_arg(va, tid_t );
          asize_t len = va_arg(va, asize_t );
          hextracelog("make_data(%08x, 0x%x, %d, 0x%x)\n", ea, flags, tid, len);
          }
          break;
      case ph.set_func_start:
          {
          func_t *pfn    =va_arg(va, func_t*);
          ea_t new_start =va_arg(va, ea_t);

          hextracelog("set_func_start(%08x, -> %08x)\n", pfn->startEA, new_start);
          }
          break;
      case ph.set_func_end:
          {
          func_t *pfn    =va_arg(va, func_t*);
          ea_t new_start =va_arg(va, ea_t);

          hextracelog("set_func_end(%08x, -> %08x)\n", pfn->startEA, new_start);
          }
          break;
      case ph.make_code:
          {
          ea_t ea = va_arg(va, ea_t );
          asize_t len = va_arg(va, asize_t );
          hextracelog("make_code(%08x, 0x%x)\n", ea, len);
          }
          break;
      case ph.undefine:
          {
          ea_t ea = va_arg(va, ea_t );
          hextracelog("undefine(%08x)\n", ea);
          }
          break;
      case ph.func_bounds:
          {
          /*int *possible_return_code= */va_arg(va, int *);
          func_t *pfn= va_arg(va, func_t *);
          ea_t max_func_end_ea= va_arg(va, ea_t );
          hextracelog("func_bounds(%08x,  %08x)\n", pfn->startEA, max_func_end_ea);
          }
          break;
      case ph.may_be_func:
          {
          int state= va_arg(va, int );
          hextracelog("may_be_func(%d)\n", state);
          }
          break;
      case ph.is_sane_insn:
          {
          int no_crefs= va_arg(va, int );
          hextracelog("is_sane_insn(%d)\n", no_crefs);
          }
          break;
      case ph.is_jump_func:
          {
          func_t *pfn= va_arg(va, func_t *);
          ea_t *jump_target=  va_arg(va, ea_t *);
          ea_t *func_pointer= va_arg(va, ea_t *);
          if (isjumpfunc(pfn->startEA)) {
              *jump_target= getjumpfunctarget(pfn->startEA);
              if (func_pointer)
                  *func_pointer= -1;
              hextracelog("is_jump_func(%08x)-> yes: %08x\n", pfn->startEA, *jump_target);
              return 2;
          }
          else {
              hextracelog("is_jump_func(%08x)-> no\n", pfn->startEA);
          }
          }
          break;

      case ph.is_basic_block_end: // only when PR_DELAYED is set in LPH.flags
          {
          bool call_insn_stops_block= va_argi(va, bool );
          hextracelog("is_basic_block_end(%d)\n", call_insn_stops_block);
          if (is_basic_block_end(get_long(cmd.ea)))
              return 2;
          }
          break;

      case ph.is_call_insn:
          {
          ea_t ea= va_arg(va, ea_t );
          bool iscall= false;
          if (is_immediate_call_insn(get_long(ea)))
              iscall= true;
          hextracelog("is_call_insn(%08x) -> %d\n", ea, iscall);
          if (iscall)
              return 2;
          }
          break;
      case ph.is_ret_insn:
          {
          ea_t ea= va_arg(va, ea_t );
          bool strict= va_argi(va, bool );
          hextracelog("is_ret_insn(%08x, %d)\n", ea, strict);

          uint32_t insn= get_long(ea);
          if (is_return(insn))
              return 2;
          }
          break;
      case ph.add_func:
          {
          func_t *pfn= va_arg(va, func_t *);
          hextracelog("add_func(%08x)\n", pfn->startEA);
          }
          break;
      case ph.preprocess_chart:
          {
          /*void *fc= */va_arg(va, void*);  // qflow_chart_t 
          hextracelog("preprocess_chart()\n");
          }
          break;
      case ph.add_cref:
          {
          ea_t from= va_arg(va, ea_t );
          ea_t to= va_arg(va, ea_t );
          cref_t type= va_argi(va, cref_t );
          hextracelog("add_cref(%08x->%08x, %d)\n", from, to, type);
          }
          break;
      case ph.del_cref:
          {
          ea_t from= va_arg(va, ea_t );
          ea_t to= va_arg(va, ea_t );
          bool expand= va_argi(va, bool );
          hextracelog("del_cref(%08x->%08x, %d)\n", from, to, expand);
          }
          break;
      case ph.get_bg_color:
          {
          ea_t ea = va_arg(va, ea_t );
          /*bgcolor_t *color = */va_arg(va, bgcolor_t *);
          hextracelog("get_bg_color(%08x)\n", ea);
          }
          break;
      case ph.add_dref:
          {
          ea_t from = va_arg(va, ea_t );
          ea_t to = va_arg(va, ea_t );
          dref_t type = va_argi(va, dref_t );
          hextracelog("add_dref(%08x->%08x, %d)\n", from, to, type);
          }
          break;
      case ph.del_dref:
          {
          ea_t from= va_arg(va, ea_t );
          ea_t to= va_arg(va, ea_t );
          hextracelog("del_dref(%08x->%08x)\n", from, to);
          }
          break;

      case ph.coagulate_dref:
          {
          ea_t from = va_arg(va, ea_t );
          ea_t to = va_arg(va, ea_t );
          bool may_define = va_argi(va, bool );
          /*ea_t *code_ea =*/ va_arg(va, ea_t *);
          hextracelog("coagulate_dref(%08x->%08x, %d)\n", from, to, may_define);
          }
          break;

      case ph.get_reg_info:
          {
            const char *regname        = va_arg(va,const char *);
            /*const char **main_regname  = */va_arg(va,const char **);
            /*uint64 *mask               = */va_arg(va,uint64* );
            hextracelog("get_reg_info('%s')\n", regname);
          }
          break;
      default:
          hextracelog("unhandled notification\n");
    }
    va_end(va);

    if (g_log)
        qflush(g_log);
    return(1);
}


// module registration

static const char *const shnames[] = { "QDSP6", NULL };
static const char *const lnames[] = { "Qualcomm Hexagon DSP v4", NULL };

static asm_t gas = {
    ASH_HEXF3|ASD_DECF0|ASO_OCTF1|ASB_BINF3|AS_N2CHR|AS_LALIGN|AS_1TEXT|AS_ONEDUP|AS_COLON,
    1,                            // uflag
  "GNU assembler",              // name
    0,                            // help
    NULL,                         // header
    NULL,                         // bad instructions
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

    NULL,         // int (*checkarg_preline)(char *argstr, s_preline *S);
    NULL,         // char *(*checkarg_atomprefix)(char *operand,int *res);
    NULL,         // char *checkarg_operations;

    NULL,         // uchar *XlatAsciiOutput
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



processor_t LPH =
{
    IDP_INTERFACE_VERSION,// version
    0x8666,               // id
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

    PR_CNDINSNS|PR_NO_SEGMOVE|PR_USE32|PR_DEFSEG32|PRN_HEX,             // flags
    8,                    // 8 bits in a byte for code segments
    8,                    // 8 bits in a byte for other segments

    shnames,
    lnames,

    asms,

    notify,

    header,
    footer,

    segstart,
    segend,

    NULL,                 // assumes,

    ana,
    emu,

    out,
    outop,
    intel_data,
    NULL,                 // compare operands
    NULL,                 // can have type

    qnumber(RegNames),            // Number of registers
    RegNames,                     // Register names
    NULL,                         // get abstract register

    0,                            // Number of register files
    NULL,                         // Register file names
    NULL,                         // Register descriptions
    NULL,                         // Pointer to CPU registers

    rVcs,                         // first
    rVds,                         // last
    1,                            // size of a segment register
    rVcs,rVds,

    NULL,                         // No known code start sequences
/*    retcodes*/NULL,

    0,qnumber(Instructions),
    Instructions,
/*
    0,    //  int   (idaapi *is_far_jump)(int icode);
    0,    //  ea_t (idaapi *translate)(ea_t base, adiff_t offset);
    0,    //  size_t tbyte_size;
    0,    //  int (idaapi *realcvt)(void *m, uint16 *e, uint16 swt);
  {0},    //  char real_width[4];
    0,    //  bool (idaapi *is_switch)(switch_info_ex_t *si);
    0,    //  int32 (idaapi *gen_map_file)(FILE *fp);
    0,    //  ea_t (idaapi *extract_address)(ea_t ea,const char *string,int x);
    0,    //   int (idaapi *is_sp_based)(const op_t &x);
    0,    //   bool (idaapi *create_func_frame)(func_t *pfn);
    0,    //   int (idaapi *get_frame_retsize)(func_t *pfn);
    0,    //   void (idaapi *gen_stkvar_def)(char *buf, size_t bufsize, const member_t *mptr, sval_t v);
    0,    //   bool (idaapi *u_outspec)(ea_t ea,uchar segtype);
    0,    //   int icode_return;
    0,    //  set_options_t *set_idp_options;
    0,    //  int (idaapi *is_align_insn)(ea_t ea);
    0,    //  mvm_t *mvm;
    0,    //  int high_fixup_bits;
*/
};
