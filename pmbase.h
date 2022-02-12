/*
 * A Generic processor module base class.
 *
 * Author: Willem Hengeveld <itsme@gsmk.de>
 *
 */
#include <pro.h>
#include <idp.hpp>
#include <auto.hpp>
#include <name.hpp>
#include <loader.hpp>
#include <typeinf.hpp>

// a baseclass for processor modules.
//
// how to use:
//    * create a subclass implementing at least:
//        ana_insn, emu_insn, out_insn, out_operand
//    * define a variable for your subclass
//    * in LPH for the notifyhook use: &cpu.staticnotifyhook,

std::map<int,const char*> eventnames = {
    {0, "init"},
    {1, "term"},
    {2, "newprc"},
    {3, "newasm"},
    {4, "newfile"},
    {5, "oldfile"},
    {6, "newbinary"},
    {7, "endbinary"},
    {8, "set_idp_options"},
    {9, "set_proc_options"},
    {10, "ana_insn"},
    {11, "emu_insn"},
    {12, "out_header"},
    {13, "out_footer"},
    {14, "out_segstart"},
    {15, "out_segend"},
    {16, "out_assumes"},
    {17, "out_insn"},
    {18, "out_mnem"},
    {19, "out_operand"},
    {20, "out_data"},
    {21, "out_label"},
    {22, "out_special_item"},
    {23, "gen_stkvar_def"},
    {24, "gen_regvar_def"},
    {25, "gen_src_file_lnnum"},
    {26, "creating_segm"},
    {27, "moving_segm"},
    {28, "coagulate"},
    {29, "undefine"},
    {30, "treat_hindering_item"},
    {31, "rename"},
    {32, "is_far_jump"},
    {33, "is_sane_insn"},
    {34, "is_cond_insn"},
    {35, "is_call_insn"},
    {36, "is_ret_insn"},
    {37, "may_be_func"},
    {38, "is_basic_block_end"},
    {39, "is_indirect_jump"},
    {40, "is_insn_table_jump"},
    {41, "is_switch"},
    {42, "calc_switch_cases"},
    {43, "create_switch_xrefs"},
    {44, "is_align_insn"},
    {45, "is_alloca_probe"},
    {46, "delay_slot_insn"},
    {47, "is_sp_based"},
    {48, "can_have_type"},
    {49, "cmp_operands"},
    {50, "adjust_refinfo"},
    {51, "get_operand_string"},
    {52, "get_reg_name"},
    {53, "str2reg"},
    {54, "get_autocmt"},
    {55, "get_bg_color"},
    {56, "is_jump_func"},
    {57, "func_bounds"},
    {58, "verify_sp"},
    {59, "verify_noreturn"},
    {60, "create_func_frame"},
    {61, "get_frame_retsize"},
    {62, "get_stkvar_scale_factor"},
    {63, "demangle_name"},
    {64, "add_cref"},
    {65, "add_dref"},
    {66, "del_cref"},
    {67, "del_dref"},
    {68, "coagulate_dref"},
    {69, "may_show_sreg"},
    {70, "loader_elf_machine"},
    {71, "auto_queue_empty"},
    {72, "validate_flirt_func"},
    {73, "adjust_libfunc_ea"},
    {74, "assemble"},
    {75, "extract_address"},
    {76, "realcvt"},
    {77, "gen_asm_or_lst"},
    {78, "gen_map_file"},
    {79, "create_flat_group"},
    {80, "getreg"},
    {81, "analyze_prolog"},
    {82, "calc_spdelta"},
    {83, "calcrel"},
    {84, "find_reg_value"},
    {85, "find_op_value"},
    {86, "replaying_undo"},
    {87, "ending_undo"},
    {88, "set_code16_mode"},
    {89, "get_code16_mode"},
    {90, "get_procmod"},
    {91, "asm_installed"},
    {92, "get_reg_accesses"},
    {93, "is_control_flow_guard"},
    {94, "broadcast"},
    {95, "create_merge_handlers"},
    {96, "privrange_changed"},
    {97, "last_cb_before_debugger"},

    {1000, "next_exec_insn"},
    {1001, "calc_step_over"},
    {1002, "calc_next_eas"},
    {1003, "get_macro_insn_head"},
    {1004, "get_dbr_opnum"},
    {1005, "insn_reads_tbit"},
    {1006, "clean_tbit"},
    {1007, "get_idd_opinfo"},
    {1008, "get_reg_info"},
    {1009, "update_call_stack"},
    {1010, "last_cb_before_type_callbacks"},

    {2000, "setup_til"},
    {2001, "get_abi_info"},
    {2002, "max_ptr_size"},
    {2003, "get_default_enum_size"},
    {2004, "get_cc_regs"},
    {2005, "obsolete1"},
    {2006, "obsolete2"},
    {2007, "get_simd_types"},
    {2008, "calc_cdecl_purged_bytes"},
    {2009, "calc_purged_bytes"},
    {2010, "calc_retloc"},
    {2011, "calc_arglocs"},
    {2012, "calc_varglocs"},
    {2013, "adjust_argloc"},
    {2014, "lower_func_type"},
    {2015, "equal_reglocs"},
    {2016, "use_stkarg_type"},
    {2017, "use_regarg_type"},
    {2018, "use_arg_types"},
    {2019, "arg_addrs_ready"},
    {2020, "decorate_name"},
    {2021, "arch_changed"},
    {2022, "get_stkarg_area_info"},
    {2023, "last_cb_before_loader"},

    {3000, "loader"},

};
const char*eventname(int id)
{
    auto i = eventnames.find(id);
    if (i==eventnames.end())
        return "unknown";
    return i->second;
}

struct leavenotify {
    // help in logging the entry/exit of this function with stack level.
    inline static int _level;
    int notification_code;
    ssize_t &rc;
    leavenotify(int notification_code, ssize_t &rc)
        : notification_code(notification_code), rc(rc)
    {
        hextracelog("%*sENTER hexagon:notify msgid=%2d:%s: ", _level*3, "", notification_code, eventname(notification_code));
        _level++;
    }
    ~leavenotify() {
        _level--;
        hextracelog("%*sLEAVE hexagon:notify msgid=%2d:%s - rc=%d\n", _level*3, "", notification_code, eventname(notification_code), (int)rc);
    }
};

/*
 *  argument types:
 *    - using const (ref|ptr) when the object pointed to shall not be modified
 *    - using ref when the object must be specified
 *    - using ptr when the object is optional.
 *    - use ptr when an array of values is pointed to
 *
 *    - ptr to simple types, and qstring will be passed as ptr, not ref.
 *
 */

class processor_module : public procmod_t {
public:    

    virtual ssize_t idaapi on_event(ssize_t notification_code, va_list va) override
    {
        ssize_t rc = 0;

        leavenotify  eventlogger(notification_code, rc);

        switch(notification_code)
        {
            case processor_t::ev_init:
            {
                ///< The IDP module is just loaded.
                auto idp_modname = va_arg(va, const char *); // processor module name
                ///< \return <0 on failure

                hextracelog("modname='%s'\n", idp_modname);

                rc = init(idp_modname);
            }
            break;

            case processor_t::ev_term:
            {
                ///< The IDP module is being unloaded

                hextracelog("\n");

                term();
#ifdef TRACELOG
              if (g_log) {
                  qfclose(g_log);
                  g_log= NULL;
              }
#endif

            }
            break;

            case processor_t::ev_newprc:
            {
                ///< Before changing processor type.
                auto pnum = va_arg(va, int); // processor number in the array of processor names
                auto keep_cfg = va_argi(va, bool); // true: do not modify kernel configuration
                ///< \retval 1  ok
                ///< \retval <0  prohibit

                hextracelog("pnum=%d, keep=%d\n", pnum, keep_cfg);

                rc = newprc(pnum, keep_cfg);
            }
            break;

            case processor_t::ev_newasm:
            {
                ///< Before setting a new assembler.
                auto asmnum = va_arg(va, int);

                hextracelog("asmnum=%d\n", asmnum);

                newasm(asmnum);
                rc = 1;
            }
            break;

            case processor_t::ev_newfile:
            {
                ///< A new file has been loaded.
                auto fname = va_arg(va, char *); // input file name

                hextracelog("fname='%s'\n", fname);
                newfile(fname);
                rc = 1;
            }
            break;

            case processor_t::ev_oldfile:
            {
                ///< An old file has been loaded.
                auto fname = va_arg(va, char *); // input file name

                hextracelog("fname='%s'\n", fname);
                oldfile(fname);
                rc = 1;
            }
            break;

            case processor_t::ev_newbinary:
            {
                ///< IDA is about to load a binary file.
                auto filename = va_arg(va, char *); //   binary file name
                auto fileoff = va_arg(va, ::qoff64_t); // offset in the file
                auto basepara = va_arg(va, ::ea_t); //   base loading paragraph
                auto binoff = va_arg(va, ::ea_t); //   loader offset
                auto nbytes = va_arg(va, ::uint64); // number of bytes to load

                hextracelog("fname='%s', off=%llx, base=%08llx, binoff=%08llx, nb=%08llx\n", filename, fileoff, uint64_t(basepara), uint64_t(binoff), nbytes);

                newbinary(filename, fileoff, basepara, binoff, nbytes);
                rc = 1;
            }
            break;

            case processor_t::ev_endbinary:
            {
                ///< IDA has loaded a binary file.
                auto ok = va_argi(va, bool); // file loaded successfully?

                hextracelog("ok=%d\n", ok);

                endbinary(ok);
                rc = 1;
            }
            break;

            case processor_t::ev_set_idp_options:
            {
                ///< Set IDP-specific configuration option
                ///< Also see set_options_t above
                auto keyword = va_arg(va, const char *);
                auto value_type = va_arg(va, int);
                auto value = va_arg(va, const void *);
                auto errbuf = va_arg(va, const char **); // - a error message will be returned here (can be NULL)
                ///< \return  1  ok
                ///< \return  0  not implemented
                ///< \return -1  error (and message in errbuf)

                hextracelog("kw='%s', vt=%d, val=%p", keyword, value_type, value);

                rc = set_idp_options(keyword, value_type, value, errbuf);

                hextracelog(" -> err='%s'\n", errbuf ? *errbuf : "");
            }
            break;

            case processor_t::ev_set_proc_options:
            {
                ///< Called if the user specified an option string in the command line:
                ///<  -p<processor name>:<options>.
                ///< Can be used for setting a processor subtype.
                ///< Also called if option string is passed to set_processor_type()
                ///< and IDC's SetProcessorType().
                auto options = va_arg(va, const char *);
                auto confidence = va_arg(va, int);
                ///<          0: loader's suggestion
                ///<          1: user's decision
                ///< \return < 0 if bad option string

                hextracelog("opt='%s', conf=%d\n", options, confidence);

                rc = set_proc_options(options, confidence);

            }
            break;

            case processor_t::ev_ana_insn:
            {
                ///< Analyze one instruction and fill 'out' structure.
                ///< This function shouldn't change the database, flags or anything else.
                ///< All these actions should be performed only by emu_insn() function.
                ///< \insn_t{ea} contains address of instruction to analyze.
                auto out = va_arg(va, ::insn_t *);
                ///< \return length of the instruction in bytes, 0 if instruction can't be decoded.
                ///< \return 0 if instruction can't be decoded.

                hextracelog("ea=%08x\n", out->ea);

                rc = ana_insn(*out);
            }
            break;

            case processor_t::ev_emu_insn:
            {
                ///< Emulate instruction, create cross-references, plan to analyze
                ///< subsequent instructions, modify flags etc. Upon entrance to this function,
                ///< all information about the instruction is in 'insn' structure.
                auto insn = va_arg(va, const ::insn_t *);
                ///< \return  1 ok
                ///< \return -1 the kernel will delete the instruction

                hextracelog("ea=%08x\n", insn->ea);
                rc = emu_insn(*insn);

            }
            break;

            case processor_t::ev_out_header:
            {
                ///< Function to produce start of disassembled text
                auto outctx = va_arg(va, ::outctx_t *);
                ///< \return void

                hextracelog("ea=%08x\n", outctx->insn.ea);
                out_header(*outctx);

                rc = 1;
            }
            break;

            case processor_t::ev_out_footer:
            {
                ///< Function to produce end of disassembled text
                auto outctx = va_arg(va, ::outctx_t *);
                ///< \return void

                hextracelog("ea=%08x\n", outctx->insn.ea);
                out_footer(*outctx);

                rc = 1;
            }
            break;

            case processor_t::ev_out_segstart:
            {
                ///< Function to produce start of segment
                auto outctx = va_arg(va, ::outctx_t *);
                auto seg = va_arg(va, ::segment_t *);
                ///< \return 1 ok
                ///< \return 0 not implemented

                hextracelog("ea=%08x, seg=%08x\n", outctx->insn.ea, seg->start_ea);
                rc = out_segstart(*outctx, *seg);
            }
            break;

            case processor_t::ev_out_segend:
            {
                ///< Function to produce end of segment
                auto outctx = va_arg(va, ::outctx_t *);
                auto seg = va_arg(va, ::segment_t *);
                ///< \return 1 ok
                ///< \return 0 not implemented

                hextracelog("ea=%08x, seg=%08x\n", outctx->insn.ea, seg->start_ea);
                rc = out_segend(*outctx, *seg);
            }
            break;

            case processor_t::ev_out_assumes:
            {
                ///< Function to produce assume directives
                ///< when segment register value changes.
                auto outctx = va_arg(va, ::outctx_t *);
                ///< \return 1 ok
                ///< \return 0 not implemented

                hextracelog("ea=%08x\n", outctx->insn.ea);
                rc = out_assumes(*outctx);
            }
            break;

            case processor_t::ev_out_insn:
            {
                ///< Generate text representation of an instruction in 'ctx.insn'
                ///< outctx_t provides functions to output the generated text.
                ///< This function shouldn't change the database, flags or anything else.
                ///< All these actions should be performed only by emu_insn() function.
                auto outctx = va_arg(va, ::outctx_t *);
                ///< \return void

                hextracelog("ea=%08x\n", outctx->insn.ea);
                out_insn(*outctx);

                rc = 1;
            }
            break;

            case processor_t::ev_out_mnem:
            {
                ///< Generate instruction mnemonics.
                ///< This callback should append the colored mnemonics to ctx.outbuf
                ///< Optional notification, if absent, out_mnem will be called.
                auto outctx = va_arg(va, ::outctx_t *);
                ///< \return 1 if appended the mnemonics
                ///< \return 0 not implemented

                hextracelog("ea=%08x\n", outctx->insn.ea);
                rc = out_mnem(*outctx);
            }
            break;

            case processor_t::ev_out_operand:
            {
                ///< Generate text representation of an instruction operand
                ///< outctx_t provides functions to output the generated text.
                ///< All these actions should be performed only by emu_insn() function.
                auto outctx = va_arg(va, ::outctx_t *);
                auto op = va_arg(va, const ::op_t *);
                ///< \return  1 ok
                ///< \return -1 operand is hidden

                hextracelog("ea=%08x, op=%d:%d\n", outctx->insn.ea, op->n, op->type);
                rc = out_operand(*outctx, *op);
            }
            break;

            case processor_t::ev_out_data:
            {
                ///< Generate text representation of data items
                ///< This function may change the database and create cross-references
                ///< if analyze_only is set
                auto outctx = va_arg(va, ::outctx_t *);
                auto analyze_only = va_argi(va, bool);
                ///< \return 1 ok
                ///< \return 0 not implemented

                hextracelog("ea=%08x, ana=%d\n", outctx->insn.ea, analyze_only );
                rc = out_data(*outctx, analyze_only); 

            }
            break;

            case processor_t::ev_out_label:
            {
                ///< The kernel is going to generate an instruction
                ///< label line or a function header.
                auto outctx = va_arg(va, ::outctx_t *);
                auto colored_name = va_arg(va, const char *);
                ///< \return <0 if the kernel should not generate the label
                ///< \return 0 not implemented or continue

                hextracelog("ea=%08x cname='%s'\n", outctx->insn.ea, colored_name);
                rc = out_label(*outctx, colored_name);
            }
            break;

            case processor_t::ev_out_special_item:
            {
                ///< Generate text representation of an item in a special segment
                ///< i.e. absolute symbols, externs, communal definitions etc
                auto outctx = va_arg(va, ::outctx_t *);
                auto segtype = va_argi(va, uchar);
                ///< \return  1  ok
                ///< \return  0  not implemented
                ///< \return -1  overflow

                hextracelog("ea=%08x segtyp=%d\n", outctx->insn.ea, segtype);
                rc = out_special_item(*outctx, segtype);
            }
            break;

            case processor_t::ev_gen_stkvar_def:
            {
                ///< Generate stack variable definition line
                ///< Default line is
                ///<             varname = type ptr value,
                ///< where 'type' is one of byte,word,dword,qword,tbyte
                auto outctx = va_arg(va, ::outctx_t *);
                auto mptr = va_arg(va, const ::member_t *);
                auto v = va_arg(va, sval_t);
                ///< \return 1 - ok
                ///< \return 0 - not implemented

                hextracelog("ea=%08x mptr=%p, v=%d\n", outctx->insn.ea, mptr, v);
                rc = gen_stkvar_def(*outctx, *mptr, v);

            }
            break;

            case processor_t::ev_gen_regvar_def:
            {
                ///< Generate register variable definition line.
                auto outctx = va_arg(va, ::outctx_t *);
                auto v = va_arg(va, ::regvar_t *);
                ///< \retval >0  ok, generated the definition text
                ///< \return 0 - not implemented

                hextracelog("ea=%08x v=%p\n", outctx->insn.ea, v);
                rc = gen_regvar_def(*outctx, *v);
            }
            break;

            case processor_t::ev_gen_src_file_lnnum:
            {
                ///< Callback: generate analog of:
                ///<
                ///< #line "file.c" 123
                ///<
                ///< directive.
                auto outctx = va_arg(va, ::outctx_t *); // output context
                auto file = va_arg(va, const char *); // source file (may be NULL)
                auto lnnum = va_arg(va, size_t); // line number
                ///< \retval 1 directive has been generated
                ///< \return 0 - not implemented

                hextracelog("ea=%08x file='%s', line=%lu\n", outctx->insn.ea, file, lnnum);
                rc = gen_src_file_lnnum(*outctx, file, lnnum);
            }
            break;

            case processor_t::ev_creating_segm:
            {
                ///< A new segment is about to be created.
                auto seg = va_arg(va, ::segment_t *);
                ///< \retval 1  ok
                ///< \retval <0  segment should not be created

                hextracelog("seg=%08x\n", seg->start_ea);
                rc = creating_segm(*seg);
            }
            break;

            case processor_t::ev_moving_segm:
            {
                ///< May the kernel move the segment?
                auto seg = va_arg(va, ::segment_t *); // segment to move
                auto to = va_arg(va, ::ea_t); // new segment start address
                auto flags = va_arg(va, int); // combination of \ref MSF_
                ///< \retval 0   yes
                ///< \retval <0  the kernel should stop

                hextracelog("seg=%08x -> %08x, fl=%08x\n", seg->start_ea, to, flags);
                rc = moving_segm(*seg, to, flags);
            }
            break;

            case processor_t::ev_coagulate:
            {
                ///< Try to define some unexplored bytes.
                ///< This notification will be called if the
                ///< kernel tried all possibilities and could
                ///< not find anything more useful than to
                ///< convert to array of bytes.
                ///< The module can help the kernel and convert
                ///< the bytes into something more useful.
                auto start_ea = va_arg(va, ::ea_t);
                ///< \return number of converted bytes

                hextracelog("ea=%08x\n", start_ea);
                rc = coagulate(start_ea);
            }
            break;

            case processor_t::ev_undefine:
            {
                ///< An item in the database (insn or data) is being deleted.
                auto ea = va_arg(va, ea_t);
                ///< \return 1 do not delete srranges at the item end
                ///< \return 0 srranges can be deleted

                hextracelog("ea=%08x\n", ea);
                rc = undefine(ea);
            }
            break;

            case processor_t::ev_treat_hindering_item:
            {
                ///< An item hinders creation of another item.
                auto hindering_item_ea = va_arg(va, ::ea_t);
                auto new_item_flags = va_arg(va, ::flags_t); //  (0 for code)
                auto new_item_ea = va_arg(va, ::ea_t);
                auto new_item_length = va_arg(va, ::asize_t);
                ///< \retval 0   no reaction
                ///< \retval !=0 the kernel may delete the hindering item

                hextracelog("item=%08x, newflag=%08x, newea=%08x, newlen=%d\n", hindering_item_ea, new_item_flags, new_item_ea, new_item_length);
                rc = treat_hindering_item(hindering_item_ea, new_item_flags, new_item_ea, new_item_length);
            }
            break;

            case processor_t::ev_rename:
            {
                ///< The kernel is going to rename a byte.
                auto ea = va_arg(va, ::ea_t);
                auto new_name = va_arg(va, const char *);
                auto flags = va_arg(va, int); // \ref SN_
                ///< \return <0 if the kernel should not rename it.
                ///< \return 2 to inhibit the notification. I.e.,
                ///<           the kernel should not rename, but
                ///<           'set_name()' should return 'true'.
                ///<         also see \idpcode{renamed}
                ///< the return value is ignored when kernel is going to delete name

                hextracelog("ea=%08x, newname='%s', fl=%08x\n",ea, new_name, flags); 
                rc = rename(ea, new_name, flags);

            }
            break;

            case processor_t::ev_is_far_jump:
            {
                ///< is indirect far jump or call instruction?
                ///< meaningful only if the processor has 'near' and 'far' reference types
                auto icode = va_arg(va, int);
                ///< \return  0  not implemented
                ///< \return  1  yes
                ///< \return -1  no

                hextracelog("icode=%d\n", icode);
                rc = is_far_jump(icode);
            }
            break;

            case processor_t::ev_is_sane_insn:
            {
                ///< Is the instruction sane for the current file type?.
                auto insn = va_arg(va, const ::insn_t*); // the instruction
                auto no_crefs = va_arg(va, int);
                ///<   1: the instruction has no code refs to it.
                ///<      ida just tries to convert unexplored bytes
                ///<      to an instruction (but there is no other
                ///<      reason to convert them into an instruction)
                ///<   0: the instruction is created because
                ///<      of some coderef, user request or another
                ///<      weighty reason.
                ///< \retval >=0  ok
                ///< \retval <0   no, the instruction isn't
                ///<              likely to appear in the program

                hextracelog("ea=%08x, nocref=%d\n", insn->ea, no_crefs);
                rc = is_sane_insn(*insn, no_crefs);

            }
            break;

            case processor_t::ev_is_cond_insn:
            {
                ///< Is conditional instruction?
                auto insn = va_arg(va, const ::insn_t *); //    instruction address
                ///< \retval  1 yes
                ///< \retval -1 no
                ///< \retval  0 not implemented or not instruction

                hextracelog("ea=%08x\n", insn->ea);
                rc = is_cond_insn(*insn);

            }
            break;

            case processor_t::ev_is_call_insn:
            {
                ///< Is the instruction a "call"?
                auto insn = va_arg(va, const ::insn_t *); // instruction
                ///< \retval 0  unknown
                ///< \retval <0 no
                ///< \retval 1  yes

                hextracelog("ea=%08x\n", insn->ea);

                rc = is_call_insn(*insn);
            }
            break;

            case processor_t::ev_is_ret_insn:
            {
                ///< Is the instruction a "return"?
                auto insn = va_arg(va, const ::insn_t *); // instruction
                auto strict = va_argi(va, bool);
                ///<          1: report only ret instructions
                ///<          0: include instructions like "leave"
                ///<             which begins the function epilog
                ///< \retval 0  unknown
                ///< \retval <0 no
                ///< \retval 1  yes

                hextracelog("ea=%08x strict=%d\n", insn->ea, strict);

                rc = is_ret_insn(*insn, strict);
            }
            break;

            case processor_t::ev_may_be_func:
            {
                ///< Can a function start here?
                auto insn = va_arg(va, const ::insn_t*); // the instruction
                auto state = va_arg(va, int); //  autoanalysis phase
                ///<   0: creating functions
                ///<   1: creating chunks
                ///< \return probability 0..100

                hextracelog("ea=%08x state=%d\n", insn->ea, state);

                rc = may_be_func(*insn, state);
            }
            break;

            case processor_t::ev_is_basic_block_end:
            {
                ///< Is the current instruction end of a basic block?.
                ///< This function should be defined for processors
                ///< with delayed jump slots.
                auto insn = va_arg(va, const ::insn_t*); // the instruction
                auto call_insn_stops_block = va_argi(va, bool);
                ///< \retval  0  unknown
                ///< \retval <0  no
                ///< \retval  1  yes

                hextracelog("ea=%08x callstopsblock=%d\n", insn->ea, call_insn_stops_block);

                rc = is_basic_block_end(*insn, call_insn_stops_block);
            }
            break;

            case processor_t::ev_is_indirect_jump:
            {
                ///< Determine if instruction is an indirect jump.
                ///< If #CF_JUMP bit can not describe all jump types
                ///< jumps, please define this callback.
                auto insn = va_arg(va, const ::insn_t*); // the instruction
                ///< \retval 0  use #CF_JUMP
                ///< \retval 1  no
                ///< \retval 2  yes

                hextracelog("ea=%08x\n", insn->ea);

                rc = is_indirect_jump(*insn);
            }
            break;

            case processor_t::ev_is_insn_table_jump:
            {
                ///< Determine if instruction is a table jump or call.
                ///< If #CF_JUMP bit can not describe all kinds of table
                ///< jumps, please define this callback.
                ///< It will be called for insns with #CF_JUMP bit set.
                auto insn = va_arg(va, const ::insn_t*); // the instruction
                ///< \retval 0   yes
                ///< \retval <0  no

                hextracelog("ea=%08x\n", insn->ea);

                rc = is_insn_table_jump(*insn);
            }
            break;

            case processor_t::ev_is_switch:
            {
                ///< Find 'switch' idiom.
                ///< It will be called for instructions marked with #CF_JUMP.
                auto si = va_arg(va, switch_info_t *); // out
                auto insn = va_arg(va, const ::insn_t *); // instruction possibly belonging to a switch
                ///< \retval 1 switch is found, 'si' is filled
                ///< \retval 0 no switch found or not implemented

                hextracelog("si=%p, ea=%08x\n", si, insn->ea);

                rc = is_switch(*si, *insn);
            }
            break;

            case processor_t::ev_calc_switch_cases:
            {
                ///< Calculate case values and targets for a custom jump table.
                auto casevec = va_arg(va, ::casevec_t *); // vector of case values (may be NULL)
                auto targets = va_arg(va, ::eavec_t *); // corresponding target addresses (my be NULL)
                auto insn_ea = va_arg(va, ::ea_t); // address of the 'indirect jump' instruction
                auto si = va_arg(va, ::switch_info_t *); // switch information
                ///< \retval 1    ok
                ///< \retval <=0  failed

                hextracelog("cvec=%p, target=%p, ea=%08x, si=%p\n", casevec, targets, insn_ea, si);

                rc = calc_switch_cases(casevec, targets, insn_ea, *si);
            }
            break;

            case processor_t::ev_create_switch_xrefs:
            {
                ///< Create xrefs for a custom jump table.
                auto jumpea = va_arg(va, ::ea_t); // address of the jump insn
                auto si = va_arg(va, const ::switch_info_t *); // switch information
                ///< \return must return 1
                ///< Must be implemented if module uses custom jump tables, \ref SWI_CUSTOM

                hextracelog("jumpea=%08x, si=%p\n", jumpea, si);

                rc = create_switch_xrefs(jumpea, *si);
            }
            break;

            case processor_t::ev_is_align_insn:
            {
                ///< Is the instruction created only for alignment purposes?.
                /// Do not directly call this function, use ::is_align_insn()
                auto ea = va_arg(va, ea_t); // - instruction address
                ///< \retval number of bytes in the instruction

                hextracelog("ea=%08x\n", ea);

                rc = is_align_insn(ea);
            }
            break;

            case processor_t::ev_is_alloca_probe:
            {
                ///< Does the function at 'ea' behave as __alloca_probe?
                auto ea = va_arg(va, ::ea_t);
                ///< \retval 1  yes
                ///< \retval 0  no

                hextracelog("ea=%08x\n", ea);

                rc = is_alloca_probe(ea);
            }
            break;

            case processor_t::ev_delay_slot_insn:
            {
                ///< Get delay slot instruction
                auto ea = va_arg(va, ::ea_t *); // instruction address in question,
                ///<                         if answer is positive then set 'ea' to
                ///<                         the delay slot insn address
                auto bexec = va_arg(va, bool *); //   execute slot if jumping,
                ///<                         initially set to 'true'
                auto fexec = va_arg(va, bool *); //   execute slot if not jumping,
                ///<                         initally set to 'true'
                ///< \retval 1   positive answer
                ///< \retval <=0 ordinary insn
                ///< \note Input 'ea' may point to the instruction with a delay slot or
                ///<       to the delay slot instruction itself.

                hextracelog("ea=%p:%08x  f=%p, b=%p", ea, *ea, bexec, fexec);

                rc = delay_slot_insn(ea, bexec, fexec);

                hextracelog(" -> ea=%08x bexec=%d, fexec=%d", *ea, *bexec, *fexec);
            }
            break;

            case processor_t::ev_is_sp_based:
            {
                ///< Check whether the operand is relative to stack pointer or frame pointer
                ///< This event is used to determine how to output a stack variable
                ///< If not implemented, then all operands are sp based by default.
                ///< Implement this event only if some stack references use frame pointer
                ///< instead of stack pointer.
                auto mode = va_arg(va, int *); // out, combination of \ref OP_FP_SP
                auto insn = va_arg(va, const insn_t *);
                auto op = va_arg(va, const op_t *);
                ///< \return 0  not implemented
                ///< \return 1  ok

                hextracelog("mode=%p, insn=%08x, op=%d.%d", mode, insn->ea, op->n, op->type);

                rc = is_sp_based(mode, *insn, *op);

                hextracelog(" -> mode=%d\n", *mode);
            }
            break;

            case processor_t::ev_can_have_type:
            {
                ///< Can the operand have a type as offset, segment, decimal, etc?
                ///< (for example, a register AX can't have a type, meaning that the user can't
                ///< change its representation. see bytes.hpp for information about types and flags)
                auto op = va_arg(va, const ::op_t *);
                ///< \retval 0  unknown
                ///< \retval <0 no
                ///< \retval 1  yes

                hextracelog("op=%d.%d", op->n, op->type);

                rc = can_have_type(*op);
            }
            break;

            case processor_t::ev_cmp_operands:
            {
                ///< Compare instruction operands
                auto op1 = va_arg(va, const ::op_t*);
                auto op2 = va_arg(va, const ::op_t*);
                ///< \retval  1  equal
                ///< \retval -1  not equal
                ///< \retval  0  not implemented

                hextracelog("op1=%d.%d, op2=%d.%d", op1->n, op1->type, op2->n, op2->type);

                rc = cmp_operands(*op1, *op2);
            }
            break;

            case processor_t::ev_adjust_refinfo:
            {
                ///< Called from apply_fixup before converting operand to reference.
                ///< Can be used for changing the reference info.
                auto ri = va_arg(va, refinfo_t *);
                auto ea = va_arg(va, ::ea_t); // instruction address
                auto n = va_arg(va, int); // operand number
                auto fd = va_arg(va, const fixup_data_t *);
                ///< \return < 0 - do not create an offset
                ///< \return 0   - not implemented or refinfo adjusted

                hextracelog("ri=%p, ea=%08x, n=%d, fd=%p\n", ri, ea, n, fd);

                rc = adjust_refinfo(*ri, ea, n, *fd);
            }
            break;

            case processor_t::ev_get_operand_string:
            {
                ///< Request text string for operand (cli, java, ...).
                auto buf = va_arg(va, qstring *);
                auto insn = va_arg(va, const ::insn_t*); // the instruction
                auto opnum = va_arg(va, int); // operand number, -1 means any string operand
                ///< \return  0  no string (or empty string)
                ///<         >0  original string length without terminating zero

                hextracelog("buf=%p, insn=%08x, n=%d", buf, insn->ea, opnum);

                rc = get_operand_string(buf, *insn, opnum);

                hextracelog("  -> buf='%s'\n", buf->c_str());
            }
            break;

            case processor_t::ev_get_reg_name:
            {
                ///< Generate text representation of a register.
                ///< Most processor modules do not need to implement this callback.
                ///< It is useful only if \ph{reg_names}[reg] does not provide
                ///< the correct register name.
                auto buf = va_arg(va, qstring *); // output buffer
                auto reg = va_arg(va, int); // internal register number as defined in the processor module
                auto width = va_arg(va, size_t); // register width in bytes
                auto reghi = va_arg(va, int); // if not -1 then this function will return the register pair
                ///< \return -1 if error, strlen(buf) otherwise

                hextracelog("\n");

                rc = get_reg_name(buf, reg, width, reghi);
            }
            break;

            case processor_t::ev_str2reg:
            {
                ///< Convert a register name to a register number.
                ///< The register number is the register index in the \ph{reg_names} array
                ///< Most processor modules do not need to implement this callback
                ///< It is useful only if \ph{reg_names}[reg] does not provide
                ///< the correct register names
                auto regname = va_arg(va, const char *);
                ///< \return register number + 1
                ///< \return 0 not implemented or could not be decoded

                hextracelog(" regname='%s'\n", regname);

                rc = str2reg(regname);
            }
            break;

            case processor_t::ev_get_autocmt:
            {
                ///< Callback: get dynamic auto comment.
                ///< Will be called if the autocomments are enabled
                ///< and the comment retrieved from ida.int starts with
                ///< '$!'. 'insn' contains valid info.
                auto buf = va_arg(va, qstring *); // output buffer
                auto insn = va_arg(va, const ::insn_t*); // the instruction
                ///< \retval 1  new comment has been generated
                ///< \retval 0  callback has not been handled.
                ///<            the buffer must not be changed in this case

                hextracelog("\n");

                rc = get_autocmt(buf, *insn);
            }
            break;

            case processor_t::ev_get_bg_color:
            {
                ///< Get item background color.
                ///< Plugins can hook this callback to color disassembly lines dynamically
                auto color = va_arg(va, ::bgcolor_t *); // out
                auto ea = va_arg(va, ::ea_t);
                ///< \retval 0  not implemented
                ///< \retval 1  color set

                hextracelog("\n");

                rc = get_bg_color(color, ea);
            }
            break;

            case processor_t::ev_is_jump_func:
            {
                ///< Is the function a trivial "jump" function?.
                auto pfn = va_arg(va, ::func_t *);
                auto jump_target = va_arg(va, ::ea_t *);
                auto func_pointer = va_arg(va, ::ea_t *);
                ///< \retval <0  no
                ///< \retval 0  don't know
                ///< \retval 1  yes, see 'jump_target' and 'func_pointer'

                hextracelog("\n");

                rc = is_jump_func(*pfn, jump_target, func_pointer);
            }
            break;

            case processor_t::ev_func_bounds:
            {
                ///< find_func_bounds() finished its work.
                ///< The module may fine tune the function bounds
                auto possible_return_code = va_arg(va, int *); // in/out
                auto pfn = va_arg(va, ::func_t *);
                auto max_func_end_ea = va_arg(va, ::ea_t); // (from the kernel's point of view)
                ///< \return void

                hextracelog("\n");

                func_bounds(possible_return_code, *pfn, max_func_end_ea);

                rc = 1;
            }
            break;

            case processor_t::ev_verify_sp:
            {
                ///< All function instructions have been analyzed.
                ///< Now the processor module can analyze the stack pointer
                ///< for the whole function
                auto pfn = va_arg(va, ::func_t *);
                ///< \retval 0  ok
                ///< \retval <0 bad stack pointer

                hextracelog("\n");

                rc = verify_sp(*pfn);
            }
            break;

            case processor_t::ev_verify_noreturn:
            {
                ///< The kernel wants to set 'noreturn' flags for a function.
                auto pfn = va_arg(va, ::func_t *);
                ///< \return 0: ok. any other value: do not set 'noreturn' flag

                hextracelog("\n");

                rc = verify_noreturn(*pfn);
            }
            break;

            case processor_t::ev_create_func_frame:
            {
                ///< Create a function frame for a newly created function
                ///< Set up frame size, its attributes etc
                auto pfn = va_arg(va, ::func_t *);
                ///< \return  1  ok
                ///< \return  0  not implemented

                hextracelog("\n");

                rc = create_func_frame(*pfn);
            }
            break;

            case processor_t::ev_get_frame_retsize:
            {
                ///< Get size of function return address in bytes
                ///< If this eveny is not implemented, the kernel will assume
                ///<  - 8 bytes for 64-bit function
                ///<  - 4 bytes for 32-bit function
                ///<  - 2 bytes otherwise
                ///< If this eveny is not implemented, the kernel will assume
                auto frsize = va_arg(va, int *); // frame size (out)
                auto pfn = va_arg(va, const ::func_t *); // can't be NULL
                ///< \return  1  ok
                ///< \return  0  not implemented

                hextracelog("\n");

                rc = get_frame_retsize(frsize, *pfn);
            }
            break;

            case processor_t::ev_get_stkvar_scale_factor:
            {
                ///< Should stack variable references be multiplied by
                ///< a coefficient before being used in the stack frame?.
                ///< Currently used by TMS320C55 because the references into
                ///< the stack should be multiplied by 2
                ///< \note #PR_SCALE_STKVARS should be set to use this callback
                ///< \return scaling factor, 0-not implemented

                hextracelog("\n");

                rc = get_stkvar_scale_factor();
            }
            break;

            case processor_t::ev_demangle_name:
            {
                ///< Demangle a C++ (or another language) name into a user-readable string.
                ///< This event is called by demangle_name()
                auto res = va_arg(va, int32 *); // value to return from demangle_name()
                auto out = va_arg(va, ::qstring *); // output buffer. may be NULL
                auto name = va_arg(va, const char *); // mangled name
                auto disable_mask = va_arg(va, uint32); // flags to inhibit parts of output or compiler info/other (see MNG_)
                auto demreq = va_argi(va, demreq_type_t); // operation to perform
                ///< \return: 1 if success, 0-not implemented
                ///< \note if you call demangle_name() from the handler, protect against recursion!

                hextracelog("name='%s'\n", name);

                rc = demangle_name(res, out, name, disable_mask, demreq);
            }
            break;

                    // the following 5 events are very low level
                    // take care of possible recursion

            case processor_t::ev_add_cref:
            {
                ///< A code reference is being created.
                auto from = va_arg(va, ::ea_t);
                auto to = va_arg(va, ::ea_t);
                auto type = va_argi(va, ::cref_t);
                ///< \return < 0 - cancel cref creation
                ///< \return 0 - not implemented or continue

                hextracelog("%08llx -> %08llx t=%d\n", uint64_t(from), uint64_t(to), type);

                rc = add_cref(from, to, type);
            }
            break;

            case processor_t::ev_add_dref:
            {
                ///< A data reference is being created.
                auto from = va_arg(va, ::ea_t);
                auto to = va_arg(va, ::ea_t);
                auto type = va_argi(va, ::dref_t);
                ///< \return < 0 - cancel dref creation
                ///< \return 0 - not implemented or continue

                hextracelog("%08llx -> %08llx t=%d\n", uint64_t(from), uint64_t(to), type);

                rc = add_dref(from, to, type);
            }
            break;

            case processor_t::ev_del_cref:
            {
                ///< A code reference is being deleted.
                auto from = va_arg(va, ::ea_t);
                auto to = va_arg(va, ::ea_t);
                auto expand = va_argi(va, bool);
                ///< \return < 0 - cancel cref deletion
                ///< \return 0 - not implemented or continue

                hextracelog("%08llx -> %08llx e=%d\n", uint64_t(from), uint64_t(to), expand);

                rc = del_cref(from, to, expand);
            }
            break;

            case processor_t::ev_del_dref:
            {
                ///< A data reference is being deleted.
                auto from = va_arg(va, ::ea_t);
                auto to = va_arg(va, ::ea_t);
                ///< \return < 0 - cancel dref deletion
                ///< \return 0 - not implemented or continue

                hextracelog("%08llx -> %08llx\n", uint64_t(from), uint64_t(to));

                rc = del_dref(from, to);
            }
            break;

            case processor_t::ev_coagulate_dref:
            {
                ///< Data reference is being analyzed.
                ///< plugin may correct 'code_ea' (e.g. for thumb mode refs, we clear the last bit)
                auto from = va_arg(va, ::ea_t);
                auto to = va_arg(va, ::ea_t);
                auto may_define = va_argi(va, bool);
                auto code_ea = va_arg(va, ::ea_t *);
                ///< \return < 0 - cancel dref analysis
                ///< \return 0 - not implemented or continue

                hextracelog("%08llx -> %08llx maydef=%d, codeea=%p", uint64_t(from), uint64_t(to), may_define, code_ea);

                rc = coagulate_dref(from, to, may_define, code_ea);

                hextracelog(" -> codeea=%08llx\n", uint64_t(*code_ea));
            }
            break;

            case processor_t::ev_may_show_sreg:
            {
                ///< The kernel wants to display the segment registers
                ///< in the messages window.
                auto current_ea = va_arg(va, ::ea_t);
                ///< \return <0 if the kernel should not show the segment registers.
                ///< (assuming that the module has done it)
                ///< \return 0 - not implemented

                hextracelog("\n");

                rc = may_show_sreg(current_ea);
            }
            break;

            case processor_t::ev_loader_elf_machine:
            {
                ///< ELF loader machine type checkpoint.
                ///< A plugin check of the 'machine_type'. If it is the desired one,
                ///< the the plugin fills 'p_procname' with the processor name
                ///< (one of the names present in \ph{psnames}).
                ///< 'p_pd' is used to handle relocations, otherwise can be left untouched.
                ///< This event occurs for each newly loaded ELF file
                auto li = va_arg(va, linput_t *);
                auto machine_type = va_arg(va, int);
                auto p_procname = va_arg(va, const char **);
                auto p_pd = va_arg(va, proc_def_t **); // (see ldr\elf.h)
                ///< \return  e_machine value (if it is different from the
                ///<          original e_machine value, procname and 'p_pd' will be ignored
                ///<          and the new value will be used)

                hextracelog("\n");

                rc = loader_elf_machine(*li, machine_type, p_procname, p_pd);
            }
            break;

            case processor_t::ev_auto_queue_empty:
            {
                ///< One analysis queue is empty.
                auto type = va_arg(va, ::atype_t);
                ///< \retval >=0  yes, keep the queue empty (default)
                ///< \retval <0   no, the queue is not empty anymore
                ///< see also \ref idb_event::auto_empty_finally

                hextracelog("t=%d\n", type);

                rc = auto_queue_empty(type);
            }
            break;

            case processor_t::ev_validate_flirt_func:
            {
                ///< Flirt has recognized a library function.
                ///< This callback can be used by a plugin or proc module
                ///< to intercept it and validate such a function.
                auto start_ea = va_arg(va, ::ea_t);
                auto funcname = va_arg(va, const char *);
                ///< \retval -1  do not create a function,
                ///< \retval  0  function is validated

                hextracelog("\n");

                rc = validate_flirt_func(start_ea, funcname);
            }
            break;

            case processor_t::ev_adjust_libfunc_ea:
            {
                ///< Called when a signature module has been matched against
                ///< bytes in the database. This is used to compute the
                ///< offset at which a particular module's libfunc should
                ///< be applied.
                auto sig = va_arg(va, const idasgn_t *);
                auto libfun = va_arg(va, const libfunc_t *);
                auto ea = va_arg(va, ::ea_t *); // \note 'ea' initially contains the ea_t of the
                ///<                                 start of the pattern match
                ///< \retval 1   the ea_t pointed to by the third argument was modified.
                ///< \retval <=0 not modified. use default algorithm.

                hextracelog("\n");

                rc = adjust_libfunc_ea(*sig, *libfun, ea);
            }
            break;

            case processor_t::ev_assemble:
            {
                ///< Assemble an instruction.
                ///< (display a warning if an error is found).
                auto bin = va_arg(va, ::uchar *); // pointer to output opcode buffer
                auto ea = va_arg(va, ::ea_t); // linear address of instruction
                auto cs = va_arg(va, ::ea_t); // cs of instruction
                auto ip = va_arg(va, ::ea_t); // ip of instruction
                auto use32 = va_argi(va, bool); // is 32bit segment?
                auto line = va_arg(va, const char *); // line to assemble
                ///< \return size of the instruction in bytes

                hextracelog("\n");

                rc = assemble(bin, ea, cs, ip, use32, line);
            }
            break;

            case processor_t::ev_extract_address:
            {
                ///< Extract address from a string.
                auto out_ea = va_arg(va, ea_t *); // out
                auto screen_ea = va_arg(va, ea_t);
                auto string = va_arg(va, const char *);
                auto position = va_arg(va, size_t);
                ///< \retval  1 ok
                ///< \retval  0 kernel should use the standard algorithm
                ///< \retval -1 error

                hextracelog("\n");

                rc = extract_address(out_ea, screen_ea, string, position);
            }
            break;

            case processor_t::ev_realcvt:
            {
                ///< Floating point -> IEEE conversion
                auto m = va_arg(va, void *); //   pointer to data
                auto e = va_arg(va, uint16 *); // internal IEEE format data
                auto swt = va_argi(va, uint16); //   operation (see realcvt() in ieee.h)
                ///< \return  0  not implemented
                ///< \return  1  ok
                ///< \return  \ref REAL_ERROR_ on error

                hextracelog("\n");

                rc = realcvt(m, e, swt);
            }
            break;

            case processor_t::ev_gen_asm_or_lst:
            {
                ///< Callback: generating asm or lst file.
                ///< The kernel calls this callback twice, at the beginning
                ///< and at the end of listing generation. The processor
                ///< module can intercept this event and adjust its output
                auto starting = va_argi(va, bool); // beginning listing generation
                auto fp = va_arg(va, FILE *); // output file
                auto is_asm = va_argi(va, bool); // true:assembler, false:listing
                auto flags = va_arg(va, int); // flags passed to gen_file()
                auto outline = va_arg(va, gen_outline_t **); // ptr to ptr to outline callback.
                ///<                  if this callback is defined for this code, it will be
                ///<                  used by the kernel to output the generated lines
                ///< \return void

                hextracelog("\n");

                gen_asm_or_lst(starting, fp, is_asm, flags, outline);

                rc = 1;
            }
            break;

            case processor_t::ev_gen_map_file:
            {
                ///<  Generate map file. If not implemented
                ///< the kernel itself will create the map file.
                auto nlines = va_arg(va, int *); // number of lines in map file (-1 means write error)
                auto fp = va_arg(va, FILE *); // output file
                ///< \return  0  not implemented
                ///< \return  1  ok
                ///< \retval -1  write error

                hextracelog("\n");

                rc = gen_map_file(nlines, fp);
            }
            break;

            case processor_t::ev_create_flat_group:
            {
                ///< Create special segment representing the flat group.
                auto image_base = va_arg(va, ::ea_t);
                auto bitness = va_arg(va, int);
                auto dataseg_sel = va_arg(va, ::sel_t);
                ///< return value is ignored

                hextracelog("\n");

                create_flat_group(image_base, bitness, dataseg_sel);
            }
            break;

            case processor_t::ev_getreg:
            {
                ///< IBM PC only internal request,
                ///< should never be used for other purpose
                ///< Get register value by internal index
                auto regval = va_arg(va, uval_t *); // out
                auto regnum = va_arg(va, int);
                ///< \return  1 ok
                ///< \return  0 not implemented
                ///< \return -1 failed (undefined value or bad regnum)

                hextracelog("\n");

                rc = getreg(regval, regnum);
            }
            break;

            /* ======= START OF DEBUGGER CALLBACKS ======= */

            case processor_t::ev_next_exec_insn:
            {
                ///< Get next address to be executed
                ///< This function must return the next address to be executed.
                ///< If the instruction following the current one is executed, then it must return #BADADDR
                ///< Usually the instructions to consider are: jumps, branches, calls, returns.
                ///< This function is essential if the 'single step' is not supported in hardware.
                auto target = va_arg(va, ::ea_t *); // out: pointer to the answer
                auto ea = va_arg(va, ::ea_t); // instruction address
                auto tid = va_arg(va, int); // current therad id
                auto getreg = va_arg(va, ::processor_t::regval_getter_t *); // function to get register values
                auto regvalues = va_arg(va, const ::regval_t *); // register values array
                ///< \retval 0 unimplemented
                ///< \retval 1 implemented

                hextracelog("\n");

                rc = next_exec_insn(target, ea, tid, getreg, regvalues);
            }
            break;

            case processor_t::ev_calc_step_over:
            {
                ///< Calculate the address of the instruction which will be
                ///< executed after "step over". The kernel will put a breakpoint there.
                ///< If the step over is equal to step into or we can not calculate
                ///< the address, return #BADADDR.
                auto target = va_arg(va, ::ea_t *); // pointer to the answer
                auto ip = va_arg(va, ::ea_t); // instruction address
                ///< \retval 0 unimplemented
                ///< \retval 1 implemented

                hextracelog("\n");

                rc = calc_step_over(target, ip);
            }
            break;

            case processor_t::ev_calc_next_eas:
            {
                ///< Calculate list of addresses the instruction in 'insn'
                ///< may pass control to.
                ///< This callback is required for source level debugging.
                auto res = va_arg(va, ::eavec_t *); // out: array for the results.
                auto insn = va_arg(va, const ::insn_t*); // the instruction
                auto over = va_argi(va, bool); // calculate for step over (ignore call targets)
                ///< \retval  <0 incalculable (indirect jumps, for example)
                ///< \retval >=0 number of addresses of called functions in the array.
                ///<             They must be put at the beginning of the array (0 if over=true)

                hextracelog("\n");

                rc = calc_next_eas(*res, *insn, over);
            }
            break;

            case processor_t::ev_get_macro_insn_head:
            {
                ///< Calculate the start of a macro instruction.
                ///< This notification is called if IP points to the middle of an instruction
                auto head = va_arg(va, ::ea_t *); // out: answer, #BADADDR means normal instruction
                auto ip = va_arg(va, ::ea_t); // instruction address
                ///< \retval 0 unimplemented
                ///< \retval 1 implemented

                hextracelog("\n");

                rc = get_macro_insn_head(head, ip);
            }
            break;

            case processor_t::ev_get_dbr_opnum:
            {
                ///< Get the number of the operand to be displayed in the
                ///< debugger reference view (text mode).
                auto opnum = va_arg(va, int *); // operand number (out, -1 means no such operand)
                auto insn = va_arg(va, const ::insn_t*); // the instruction
                ///< \retval 0 unimplemented
                ///< \retval 1 implemented

                hextracelog("\n");

                rc = get_dbr_opnum(opnum, *insn);
            }
            break;

            case processor_t::ev_insn_reads_tbit:
            {
                ///< Check if insn will read the TF bit.
                auto insn = va_arg(va, const ::insn_t*); // the instruction
                auto getreg = va_arg(va, ::processor_t::regval_getter_t *); // function to get register values
                auto regvalues = va_arg(va, const ::regval_t *); // register values array
                ///< \retval 2  yes, will generate 'step' exception
                ///< \retval 1  yes, will store the TF bit in memory
                ///< \retval 0  no

                hextracelog("\n");

                rc = insn_reads_tbit(*insn, getreg, regvalues);
            }
            break;

            case processor_t::ev_clean_tbit:
            {
                ///< Clear the TF bit after an insn like pushf stored it in memory.
                auto ea = va_arg(va, ::ea_t); // instruction address
                auto getreg = va_arg(va, ::processor_t::regval_getter_t *); // function to get register values
                auto regvalues = va_arg(va, const ::regval_t *); // register values array
                ///< \retval 1  ok
                ///< \retval 0  failed

                hextracelog("\n");

                rc = clean_tbit(ea, getreg, regvalues);
            }
            break;

            case processor_t::ev_get_idd_opinfo:
            {
                ///< Get operand information.
                ///< This callback is used to calculate the operand
                ///< value for double clicking on it, hints, etc.
                auto opinf = va_arg(va, ::idd_opinfo_t *); // the output buffer
                auto ea = va_arg(va, ::ea_t); // instruction address
                auto n = va_arg(va, int); // operand number
                auto thread_id = va_arg(va, int); // current thread id
                auto getreg = va_arg(va, ::processor_t::regval_getter_t *); // function to get register values
                auto regvalues = va_arg(va, const ::regval_t *); // register values array
                ///< \return 1-ok, 0-failed

                hextracelog("\n");

                rc = get_idd_opinfo(*opinf, ea, n, thread_id, getreg, regvalues);
            }
            break;

            case processor_t::ev_get_reg_info:
            {
                ///< Get register information by its name.
                ///< example: "ah" returns:
                ///<   - main_regname="eax"
                ///<   - bitrange_t = { offset==8, nbits==8 }
                ///<
                ///< This callback may be unimplemented if the register
                ///< names are all present in \ph{reg_names} and they all have
                ///< the same size
                auto main_regname = va_arg(va, const char **); // out
                auto bitrange = va_arg(va, ::bitrange_t *); // out: position and size of the value within 'main_regname' (empty bitrange == whole register)
                auto regname = va_arg(va, const char *);
                ///< \retval  1  ok
                ///< \retval -1  failed (not found)
                ///< \retval  0  unimplemented

                hextracelog("\n");

                rc = get_reg_info(main_regname, *bitrange, regname);
            }
            break;

            /* ======== START OF TYPEINFO CALLBACKS ========= */
                    // The codes below will be called only if #PR_TYPEINFO is set.
                    // The codes ev_max_ptr_size, ev_get_default_enum_size MUST be implemented.
                    // (other codes are optional but still require for normal
                    // operation of the type system. without calc_arglocs,
                    // for example, ida will not know about the argument
                    // locations for function calls.

            case processor_t::ev_setup_til:
            {
                ///< Setup default type libraries. (called after loading
                ///< a new file into the database).
                ///< The processor module may load tils, setup memory
                ///< model and perform other actions required to set up
                ///< the type system.
                ///< This is an optional callback.
                ///< \param none
                ///< \return void

                hextracelog("\n");

                setup_til();

                rc = 1;
            }
            break;

            case processor_t::ev_get_abi_info:
            {
                ///< Get all possible ABI names and optional extensions for given compiler
                ///< abiname/option is a string entirely consisting of letters, digits and underscore
                auto abi_names = va_arg(va, qstrvec_t *); // - all possible ABis each in form abiname-opt1-opt2-...
                auto abi_opts = va_arg(va, qstrvec_t *); // - array of all possible options in form "opt:description" or opt:hint-line#description
                auto comp = va_argi(va, comp_t); // - compiler ID
                ///< \retval 0 not implemented
                ///< \retval 1 ok

                hextracelog("\n");

                rc = get_abi_info(*abi_names, *abi_opts, comp);
            }
            break;

            case processor_t::ev_max_ptr_size:
            {
                ///< Get maximal size of a pointer in bytes.
                ///< \param none
                ///< \return max possible size of a pointer

                hextracelog("\n");

                rc = max_ptr_size();
            }
            break;

            case processor_t::ev_get_default_enum_size:
            {
                ///< Get default enum size.
                auto cm = va_argi(va, ::cm_t);
                ///< \returns sizeof(enum)

                hextracelog("\n");

                rc = get_default_enum_size(cm);
            }
            break;

            case processor_t::ev_get_cc_regs:
            {
                ///< Get register allocation convention for given calling convention
                auto regs = va_arg(va, ::callregs_t *); // out
                auto cc = va_argi(va, ::cm_t);
                ///< \return 1
                ///< \return 0 - not implemented

                hextracelog("\n");

                rc = get_cc_regs(*regs, cc);
            }
            break;
#if IDA_SDK_VERSION <= 760
            case processor_t::ev_get_stkarg_offset:
            {
                ///< Get offset from SP to the first stack argument.
                ///< For example: pc: 0, hppa: -0x34, ppc: 0x38
                ///< \param none
                ///< \returns the offset

                hextracelog("\n");

                rc = get_stkarg_offset();
            }
            break;

            case processor_t::ev_shadow_args_size:
            {
                ///< Get size of shadow args in bytes.
                auto shadow_args_siz = va_arg(va, int *); // [out]
                auto pfn = va_arg(va, ::func_t *); // (may be NULL)
                ///< \return 1 if filled *shadow_args_siz
                ///< \return 0 - not implemented

                hextracelog("\n");

                rc = shadow_args_size(shadow_args_siz, pfn);
            }
            break;
#endif
            case processor_t::ev_get_simd_types:
            {
                ///< Get SIMD-related types according to given attributes ant/or argument location
                auto out = va_arg(va, ::simd_info_vec_t *);
                auto simd_attrs = va_arg(va, const ::simd_info_t *); // may be NULL
                auto argloc = va_arg(va, const ::argloc_t *); // may be NULL
                auto create_tifs = va_argi(va, bool); // return valid tinfo_t objects, create if neccessary
                ///< \return number of found types, -1-error
                ///< If name==NULL, initialize all SIMD types

                hextracelog("\n");

                rc = get_simd_types(*out, simd_attrs, argloc, create_tifs);
            }
            break;

            case processor_t::ev_calc_cdecl_purged_bytes:
            {

                ///< Calculate number of purged bytes after call.
                auto ea = va_arg(va, ::ea_t); // address of the call instruction
                ///< \returns number of purged bytes (usually add sp, N)

                hextracelog("\n");

                rc = calc_cdecl_purged_bytes(ea);
            }
            break;

            case processor_t::ev_calc_purged_bytes:
            {
                ///< Calculate number of purged bytes by the given function type.
                auto p_purged_bytes = va_arg(va, int *); // [out] ptr to output
                auto fti = va_arg(va, const ::func_type_data_t *); // func type details
                ///< \return 1
                ///< \return 0 - not implemented

                hextracelog("\n");

                rc = calc_purged_bytes(p_purged_bytes, *fti);
            }
            break;

            case processor_t::ev_calc_retloc:
            {
                ///< Calculate return value location.
                auto retloc = va_arg(va, ::argloc_t *); // [out]
                auto rettype = va_arg(va, const tinfo_t *);
                auto cc = va_argi(va, ::cm_t);
                ///< \return  0  not implemented
                ///< \return  1  ok,
                ///< \return -1  error

                hextracelog("\n");

                rc = calc_retloc(*retloc, *rettype, cc);
            }
            break;

            case processor_t::ev_calc_arglocs:
            {
                ///< Calculate function argument locations.
                ///< This callback should fill retloc, all arglocs, and stkargs.
                ///< This callback supersedes calc_argloc2.
                ///< This callback is never called for ::CM_CC_SPECIAL functions.
                auto fti = va_arg(va, ::func_type_data_t *); // points to the func type info
                ///< \retval  0  not implemented
                ///< \retval  1  ok
                ///< \retval -1  error

                hextracelog("\n");

                rc = calc_arglocs(*fti);
            }
            break;

            case processor_t::ev_calc_varglocs:
            {
                ///< Calculate locations of the arguments that correspond to '...'.
                auto ftd = va_arg(va, ::func_type_data_t *); // inout: info about all arguments (including varargs)
                auto regs = va_arg(va, ::regobjs_t *); // buffer for register values
                auto stkargs = va_arg(va, ::relobj_t *); // stack arguments
                auto nfixed = va_arg(va, int); // number of fixed arguments
                ///< \retval  0  not implemented
                ///< \retval  1  ok
                ///< \retval -1  error

                hextracelog("\n");

                rc = calc_varglocs(*ftd, *regs, *stkargs, nfixed);
            }
            break;

            case processor_t::ev_adjust_argloc:
            {
                ///< Adjust argloc according to its type/size
                ///< and platform endianess
                auto argloc = va_arg(va, argloc_t *); // inout
                auto type = va_arg(va, const tinfo_t *); // may be NULL
                ///<   NULL means primitive type of given size
                auto size = va_arg(va, int);
                ///<   'size' makes no sense if type != NULL
                ///<   (type->get_size() should be used instead)
                ///< \retval  0  not implemented
                ///< \retval  1  ok
                ///< \retval -1  error

                hextracelog("\n");

                rc = adjust_argloc(*argloc, *type, size);
            }
            break;

            case processor_t::ev_lower_func_type:
            {
                ///< Get function arguments which should be converted to pointers when lowering function prototype.
                ///<  Processor module can also modify 'fti' in
                ///< order to make a non-standard convertion for some of the arguments.
                auto argnums = va_arg(va, intvec_t *); // out - numbers of arguments to be converted to pointers in acsending order
                auto fti = va_arg(va, ::func_type_data_t *); // inout func type details
                ///< (special values -1/-2 for return value - position of hidden 'retstr' argument: -1 - at the beginning, -2 - at the end)
                ///< \retval 0 not implemented
                ///< \retval 1 argnums was filled
                ///< \retval 2 argnums was filled and made substantial changes to fti

                hextracelog("\n");

                rc = lower_func_type(*argnums, *fti);
            }
            break;

            case processor_t::ev_equal_reglocs:
            {
                ///< Are 2 register arglocs the same?.
                ///< We need this callback for the pc module.
                auto a1 = va_arg(va, ::argloc_t *);
                auto a2 = va_arg(va, ::argloc_t *);
                ///< \retval  1  yes
                ///< \retval -1  no
                ///< \retval  0  not implemented

                hextracelog("\n");

                rc = equal_reglocs(*a1, *a2);
            }
            break;

            case processor_t::ev_use_stkarg_type:
            {
                ///< Use information about a stack argument.
                auto ea = va_arg(va, ::ea_t); // address of the push instruction which
                ///<                     pushes the function argument into the stack
                auto arg = va_arg(va, const ::funcarg_t *); // argument info
                ///< \retval 1   ok
                ///< \retval <=0 failed, the kernel will create a comment with the
                ///<             argument name or type for the instruction

                hextracelog("\n");

                rc = use_stkarg_type(ea, *arg);
            }
            break;

            case processor_t::ev_use_regarg_type:
            {
                ///< Use information about register argument.
                auto idx = va_arg(va, int *); // [out] pointer to the returned value, may contain:
                ///<                         - idx of the used argument, if the argument is defined
                ///<                           in the current instruction, a comment will be applied by the kernel
                ///<                         - idx | #REG_SPOIL - argument is spoiled by the instruction
                ///<                         - -1 if the instruction doesn't change any registers
                ///<                         - -2 if the instruction spoils all registers
                auto ea = va_arg(va, ::ea_t); // address of the instruction
                auto rargs = va_arg(va, const ::funcargvec_t *); // vector of register arguments
                ///<                               (including regs extracted from scattered arguments)
                ///< \return 1
                ///< \return 0  not implemented

                hextracelog("\n");

                rc = use_regarg_type(idx, ea, *rargs);
            }
            break;

            case processor_t::ev_use_arg_types:
            {
                ///< Use information about callee arguments.
                auto ea = va_arg(va, ::ea_t); // address of the call instruction
                auto fti = va_arg(va, ::func_type_data_t *); // info about function type
                auto rargs = va_arg(va, ::funcargvec_t *); // array of register arguments
                ///< \return 1 (and removes handled arguments from fti and rargs)
                ///< \return 0  not implemented

                hextracelog("\n");

                rc = use_arg_types(ea, *fti, *rargs);
            }
            break;

            case processor_t::ev_arg_addrs_ready:
            {
                ///< Argument address info is ready.
                auto caller = va_arg(va, ::ea_t);
                auto n = va_arg(va, int); // number of formal arguments
                auto tif = va_arg(va, tinfo_t *); // call prototype
                auto addrs = va_arg(va, ::ea_t *); // argument intilization addresses
                ///< \return <0: do not save into idb; other values mean "ok to save"

                hextracelog("\n");

                rc = arg_addrs_ready(caller, n, *tif, addrs);
            }
            break;

            case processor_t::ev_decorate_name:
            {
                ///< Decorate/undecorate a C symbol name.
                auto outbuf = va_arg(va, ::qstring *); // output buffer
                auto name = va_arg(va, const char *); // name of symbol
                auto mangle = va_argi(va, bool); // true-mangle, false-unmangle
                auto cc = va_argi(va, ::cm_t); // calling convention
                auto type = va_arg(va, const ::tinfo_t *); // name type (NULL-unknown)
                ///< \return 1 if success
                ///< \return 0 not implemented or failed

                hextracelog("\n");

                rc = decorate_name(outbuf, name, mangle, cc, *type);
            }
            break;

            default:
                hextracelog(" ... unhandled event\n");

                rc = 0;

        }

#ifdef TRACELOG
        if (g_log)
            qflush(g_log);
#endif
        return rc;
    }
    //=====

    ///< The IDP module is just loaded.
    ///< \param idp_modname  (const char *) processor module name
    ///< \return <0 on failure
    virtual int init(const char *idp_modname) { return 1; }

    ///< The IDP module is being unloaded
    virtual void term() { }

    ///< Before changing processor type.
    ///< \param pnum  (int) processor number in the array of processor names
    ///< \param keep_cfg (bool) true: do not modify kernel configuration
    ///< \retval 1  ok
    ///< \retval <0  prohibit
    virtual int newprc(int pnum, bool keep_cfg) { return 1; }

    ///< Before setting a new assembler.
    ///< \param asmnum  (int)
    virtual void newasm(int asmnum) { }

    ///< A new file has been loaded.
    ///< \param fname  (char *) input file name
    virtual void newfile(const char *fname) { }

    ///< An old file has been loaded.
    ///< \param fname  (char *) input file name
    virtual void oldfile(const char *fname) { }

    ///< IDA is about to load a binary file.
    ///< \param filename  (char *)   binary file name
    ///< \param fileoff   (::qoff64_t) offset in the file
    ///< \param basepara  (::ea_t)   base loading paragraph
    ///< \param binoff    (::ea_t)   loader offset
    ///< \param nbytes    (::uint64) number of bytes to load
    virtual void newbinary(const char *filename, qoff64_t fileoff, ea_t basepara, ea_t binoff, uint64 nbytes) { }

    ///< IDA has loaded a binary file.
    ///< \param ok  (bool) file loaded successfully?
    virtual void endbinary(bool ok) { }

    ///< Set IDP-specific configuration option
    ///< Also see set_options_t above
    ///< \param keyword     (const char *)
    ///< \param value_type  (int)
    ///< \param value       (const void *)
    ///< \param errbuf      (const char **) - a error message will be returned here (can be NULL)
    ///< \return  1  ok
    ///< \return  0  not implemented
    ///< \return -1  error (and message in errbuf)
    virtual int set_idp_options(const char *keyword, int vtype, const void *value, const char**errbuf) { return 0; }

    ///< Called if the user specified an option string in the command line:
    ///<  -p<processor name>:<options>.
    ///< Can be used for setting a processor subtype.
    ///< Also called if option string is passed to set_processor_type()
    ///< and IDC's SetProcessorType().
    ///< \param options     (const char *)
    ///< \param confidence  (int)
    ///<          0: loader's suggestion
    ///<          1: user's decision
    ///< \return < 0 if bad option string
    virtual int set_proc_options(const char *options, int confidence) { return 0; }

    ///< Analyze one instruction and fill 'out' structure.
    ///< This function shouldn't change the database, flags or anything else.
    ///< All these actions should be performed only by emu_insn() function.
    ///< \insn_t{ea} contains address of instruction to analyze.
    ///< \param out           (::insn_t *)
    ///< \return length of the instruction in bytes, 0 if instruction can't be decoded.
    ///< \return 0 if instruction can't be decoded.
    virtual int ana_insn(insn_t &out) = 0;  // must override

    ///< Emulate instruction, create cross-references, plan to analyze
    ///< subsequent instructions, modify flags etc. Upon entrance to this function,
    ///< all information about the instruction is in 'insn' structure.
    ///< \param insn          (const ::insn_t *)
    ///< \return  1 ok
    ///< \return -1 the kernel will delete the instruction
    virtual int emu_insn(const insn_t &insn) = 0;  // must override

    ///< Function to produce start of disassembled text
    ///< \param outctx        (::outctx_t *)
    ///< \return void
    virtual void out_header(outctx_t &outctx) { }

    ///< Function to produce end of disassembled text
    ///< \param outctx        (::outctx_t *)
    ///< \return void
    virtual void out_footer(outctx_t &outctx) { }

    ///< Function to produce start of segment
    ///< \param outctx        (::outctx_t *)
    ///< \param seg           (::segment_t *)      <<< why no 'const'
    ///< \return 1 ok
    ///< \return 0 not implemented
    virtual int out_segstart(outctx_t &outctx, segment_t &seg) { return 0; }

    ///< Function to produce end of segment
    ///< \param outctx        (::outctx_t *)
    ///< \param seg           (::segment_t *)      <<< why no 'const'
    ///< \return 1 ok
    ///< \return 0 not implemented
    virtual int out_segend(outctx_t &outctx, segment_t &seg) { return 0; }

    ///< Function to produce assume directives
    ///< when segment register value changes.
    ///< \param outctx        (::outctx_t *)
    ///< \return 1 ok
    ///< \return 0 not implemented
    virtual int out_assumes(outctx_t &outctx) { return 0; }

    ///< Generate text representation of an instruction in 'ctx.insn'
    ///< outctx_t provides functions to output the generated text.
    ///< This function shouldn't change the database, flags or anything else.
    ///< All these actions should be performed only by emu_insn() function.
    ///< \param outctx        (::outctx_t *)
    ///< \return void
    virtual void out_insn(outctx_t &outctx) = 0;  // must override

    ///< Generate instruction mnemonics.
    ///< This callback should append the colored mnemonics to ctx.outbuf
    ///< Optional notification, if absent, out_mnem will be called.
    ///< \param outctx        (::outctx_t *)
    ///< \return 1 if appended the mnemonics
    ///< \return 0 not implemented
    virtual int out_mnem(outctx_t &outctx) { return 0; }

    ///< Generate text representation of an instruction operand
    ///< outctx_t provides functions to output the generated text.
    ///< All these actions should be performed only by emu_insn() function.
    ///< \param outctx        (::outctx_t *)
    ///< \param op            (const ::op_t *)
    ///< \return  1 ok
    ///< \return -1 operand is hidden
    virtual int out_operand(outctx_t &outctx, const op_t &op) = 0;  // must override

    ///< Generate text representation of data items
    ///< This function may change the database and create cross-references
    ///< if analyze_only is set
    ///< \param outctx        (::outctx_t *)
    ///< \param analyze_only  (bool)
    ///< \return 1 ok
    ///< \return 0 not implemented
    virtual int out_data(outctx_t &outctx, bool analyze_only) { return 0; }

    ///< The kernel is going to generate an instruction
    ///< label line or a function header.
    ///< \param outctx        (::outctx_t *)
    ///< \param colored_name  (const char *)
    ///< \return <0 if the kernel should not generate the label
    ///< \return 0 not implemented or continue
    virtual int out_label(outctx_t &outctx, const char *colored_name) { return 0; }

    ///< Generate text representation of an item in a special segment
    ///< i.e. absolute symbols, externs, communal definitions etc
    ///< \param outctx  (::outctx_t *)
    ///< \param segtype (uchar)
    ///< \return  1  ok
    ///< \return  0  not implemented
    ///< \return -1  overflow
    virtual int out_special_item(outctx_t &outctx, uchar segtype) { return 0; }

    ///< Generate stack variable definition line
    ///< Default line is
    ///<             varname = type ptr value,
    ///< where 'type' is one of byte,word,dword,qword,tbyte
    ///< \param outctx   (::outctx_t *)
    ///< \param mptr     (const ::member_t *)
    ///< \param v        (sval_t)
    ///< \return 1 - ok
    ///< \return 0 - not implemented
    virtual int gen_stkvar_def(outctx_t &outctx, const class ::member_t &mptr, sval_t v) { return 0; }

    ///< Generate register variable definition line.
    ///< \param outctx  (::outctx_t *)
    ///< \param v       (::regvar_t *)         <<< why no const?
    ///< \retval >0  ok, generated the definition text
    ///< \return 0 - not implemented
    virtual int gen_regvar_def(outctx_t &outctx, regvar_t &v) { return 0; }

    ///< Callback: generate analog of:
    ///<
    ///< #line "file.c" 123
    ///<
    ///< directive.
    ///< \param outctx  (::outctx_t *) output context
    ///< \param file    (const char *) source file (may be NULL)
    ///< \param lnnum   (size_t) line number
    ///< \retval 1 directive has been generated
    ///< \return 0 - not implemented
    virtual int gen_src_file_lnnum(outctx_t &outctx, const char *file, size_t lnnum) { return 0; }

    ///< A new segment is about to be created.
    ///< \param seg  (::segment_t *)
    ///< \retval 1  ok
    ///< \retval <0  segment should not be created
    virtual int creating_segm(segment_t &seg) { return 1; }

    ///< May the kernel move the segment?
    ///< \param seg    (::segment_t *) segment to move
    ///< \param to     (::ea_t) new segment start address
    ///< \param flags  (int) combination of \ref MSF_
    ///< \retval 0   yes
    ///< \retval <0  the kernel should stop
    virtual int moving_segm(segment_t &seg, ea_t to, int flags) { return 0; }

    ///< Try to define some unexplored bytes.
    ///< This notification will be called if the
    ///< kernel tried all possibilities and could
    ///< not find anything more useful than to
    ///< convert to array of bytes.
    ///< The module can help the kernel and convert
    ///< the bytes into something more useful.
    ///< \param start_ea  (::ea_t)
    ///< \return number of converted bytes
    virtual int coagulate(ea_t start_ea) { return 0; }

    ///< An item in the database (insn or data) is being deleted.
    ///< \param ea  (ea_t)
    ///< \return 1 do not delete srranges at the item end
    ///< \return 0 srranges can be deleted
    virtual int undefine(ea_t ea) { return 0; }

    ///< An item hinders creation of another item.
    ///< \param hindering_item_ea  (::ea_t)
    ///< \param new_item_flags     (::flags_t)  (0 for code)
    ///< \param new_item_ea        (::ea_t)
    ///< \param new_item_length    (::asize_t)
    ///< \retval 0   no reaction
    ///< \retval !=0 the kernel may delete the hindering item
    virtual int treat_hindering_item(ea_t hindering_item_ea, flags_t new_item_flags, ea_t new_item_ea, asize_t new_item_length) { return 0; }

    ///< The kernel is going to rename a byte.
    ///< \param ea       (::ea_t)
    ///< \param new_name (const char *)
    ///< \param flags    (int) \ref SN_
    ///< \return <0 if the kernel should not rename it.
    ///< \return 2 to inhibit the notification. I.e.,
    ///<           the kernel should not rename, but
    ///<           'set_name()' should return 'true'.
    ///<         also see \idpcode{renamed}
    ///< the return value is ignored when kernel is going to delete name  <<< is the 'ok' case 0, or 1?
    virtual int rename(ea_t ea, const char *new_name, int flags) { return 1; }

    ///< is indirect far jump or call instruction?
    ///< meaningful only if the processor has 'near' and 'far' reference types
    ///< \param icode (int)
    ///< \return  0  not implemented
    ///< \return  1  yes
    ///< \return -1  no
    virtual int is_far_jump(int icode) { return 0; }

    ///< Is the instruction sane for the current file type?.
    ///< \param insn      (const ::insn_t*) the instruction
    ///< \param no_crefs  (int)
    ///<   1: the instruction has no code refs to it.
    ///<      ida just tries to convert unexplored bytes
    ///<      to an instruction (but there is no other
    ///<      reason to convert them into an instruction)
    ///<   0: the instruction is created because
    ///<      of some coderef, user request or another
    ///<      weighty reason.
    ///< \retval >=0  ok
    ///< \retval <0   no, the instruction isn't
    ///<              likely to appear in the program
    virtual int is_sane_insn(const insn_t &insn, int no_crefs) { return 0; }

    ///< Is conditional instruction?
    ///< \param insn (const ::insn_t *)    instruction address
    ///< \retval  1 yes
    ///< \retval -1 no
    ///< \retval  0 not implemented or not instruction
    virtual int is_cond_insn(const insn_t &insn) { return 0; }

    ///< Is the instruction a "call"?
    ///< \param insn (const ::insn_t *) instruction
    ///< \retval 0  unknown
    ///< \retval <0 no
    ///< \retval 1  yes
    virtual int is_call_insn(const insn_t &insn) { return 0; }

    ///< Is the instruction a "return"?
    ///< \param insn    (const ::insn_t *) instruction
    ///< \param strict  (bool)
    ///<          1: report only ret instructions
    ///<          0: include instructions like "leave"
    ///<             which begins the function epilog
    ///< \retval 0  unknown
    ///< \retval <0 no
    ///< \retval 1  yes
    virtual int is_ret_insn(const insn_t &insn, bool strict) { return 0; }

    ///< Can a function start here?
    ///< \param insn  (const ::insn_t*) the instruction
    ///< \param state (int)  autoanalysis phase
    ///<   0: creating functions
    ///<   1: creating chunks
    ///< \return probability 0..100
    virtual int may_be_func(const insn_t &insn, int state) { return 0; }

    ///< Is the current instruction end of a basic block?.
    ///< This function should be defined for processors
    ///< with delayed jump slots.
    ///< \param insn                   (const ::insn_t*) the instruction
    ///< \param call_insn_stops_block  (bool)
    ///< \retval  0  unknown
    ///< \retval <0  no
    ///< \retval  1  yes
    virtual int is_basic_block_end(const insn_t &insn, bool call_insn_stops_block) { return 0; }

    ///< Determine if instruction is an indirect jump.
    ///< If #CF_JUMP bit can not describe all jump types
    ///< jumps, please define this callback.
    ///< \param insn (const ::insn_t*) the instruction
    ///< \retval 0  use #CF_JUMP
    ///< \retval 1  no
    ///< \retval 2  yes
    virtual int is_indirect_jump(const insn_t &insn) { return 0; }

    ///< Determine if instruction is a table jump or call.
    ///< If #CF_JUMP bit can not describe all kinds of table
    ///< jumps, please define this callback.
    ///< It will be called for insns with #CF_JUMP bit set.
    ///< \param insn (const ::insn_t*) the instruction
    ///< \retval 0   yes
    ///< \retval <0  no
    virtual int is_insn_table_jump(const insn_t &insn) { return 0; }

    ///< Find 'switch' idiom.
    ///< It will be called for instructions marked with #CF_JUMP.
    ///< \param si   (switch_info_t *), out
    ///< \param insn (const ::insn_t *) instruction possibly belonging to a switch
    ///< \retval 1 switch is found, 'si' is filled
    ///< \retval 0 no switch found or not implemented
    virtual int is_switch(switch_info_t &si, const insn_t &insn) { return 0; }

    ///< Calculate case values and targets for a custom jump table.
    ///< \param casevec  (::casevec_t *) vector of case values (may be NULL)
    ///< \param targets  (::eavec_t *) corresponding target addresses (my be NULL)
    ///< \param insn_ea  (::ea_t) address of the 'indirect jump' instruction
    ///< \param si       (::switch_info_t *) switch information
    ///< \retval 1    ok
    ///< \retval <=0  failed
    virtual int calc_switch_cases(casevec_t *casevec, eavec_t *targets, ea_t insn_ea, const switch_info_t &si) { return 0; }

    ///< Create xrefs for a custom jump table.
    ///< \param jumpea   (::ea_t) address of the jump insn
    ///< \param si       (const ::switch_info_t *) switch information
    ///< \return must return 1             <<< doesn't '0' mean not implemented?
    ///< Must be implemented if module uses custom jump tables, \ref SWI_CUSTOM
    virtual int create_switch_xrefs(ea_t jumpea, const switch_info_t &si) { return 0; }

    ///< Is the instruction created only for alignment purposes?.
    /// Do not directly call this function, use ::is_align_insn()
    ///< \param ea (ea_t) - instruction address
    ///< \retval number of bytes in the instruction
    virtual int is_align_insn(ea_t ea) { return 0; }

    ///< Does the function at 'ea' behave as __alloca_probe?
    ///< \param ea  (::ea_t)
    ///< \retval 1  yes
    ///< \retval 0  no
    virtual int is_alloca_probe(ea_t ea) { return 0; }

    ///< Get delay slot instruction
    ///< \param ea    (::ea_t *) instruction address in question,
    ///<                         if answer is positive then set 'ea' to
    ///<                         the delay slot insn address
    ///< \param bexec (bool *)   execute slot if jumping,
    ///<                         initially set to 'true'
    ///< \param fexec (bool *)   execute slot if not jumping,
    ///<                         initally set to 'true'
    ///< \retval 1   positive answer
    ///< \retval <=0 ordinary insn
    ///< \note Input 'ea' may point to the instruction with a delay slot or
    ///<       to the delay slot instruction itself.
    virtual int delay_slot_insn(ea_t *ea, bool *bexec, bool *fexec) { return 0; }

    ///< Check whether the operand is relative to stack pointer or frame pointer
    ///< This event is used to determine how to output a stack variable
    ///< If not implemented, then all operands are sp based by default.
    ///< Implement this event only if some stack references use frame pointer
    ///< instead of stack pointer.
    ///< \param mode  (int *) out, combination of \ref OP_FP_SP
    ///< \param insn  (const insn_t *)
    ///< \param op    (const op_t *)
    ///< \return 0  not implemented
    ///< \return 1  ok
    virtual int is_sp_based(int *mode, const insn_t &insn, const op_t &x) { return 0; }

    ///< Can the operand have a type as offset, segment, decimal, etc?
    ///< (for example, a register AX can't have a type, meaning that the user can't
    ///< change its representation. see bytes.hpp for information about types and flags)
    ///< \param op    (const ::op_t *)
    ///< \retval 0  unknown
    ///< \retval <0 no
    ///< \retval 1  yes
    virtual int can_have_type(const op_t &op) { return 0; }

    ///< Compare instruction operands
    ///< \param op1      (const ::op_t*)
    ///< \param op2      (const ::op_t*)
    ///< \retval  1  equal
    ///< \retval -1  not equal
    ///< \retval  0  not implemented
    virtual int cmp_operands(const op_t &op1, const op_t &op2) { return 0; }

    ///< Called from apply_fixup before converting operand to reference.
    ///< Can be used for changing the reference info.
    ///< \param ri      (refinfo_t *)
    ///< \param ea      (::ea_t) instruction address
    ///< \param n       (int) operand number
    ///< \param fd      (const fixup_data_t *)
    ///< \return < 0 - do not create an offset
    ///< \return 0   - not implemented or refinfo adjusted
    virtual int adjust_refinfo(refinfo_t &ri, ea_t ea, int n, const fixup_data_t &fd) { return 0; }

    ///< Request text string for operand (cli, java, ...).
    ///< \param buf    (qstring *)
    ///< \param insn   (const ::insn_t*) the instruction
    ///< \param opnum  (int) operand number, -1 means any string operand
    ///< \return  0  no string (or empty string)
    ///<         >0  original string length without terminating zero
    virtual int get_operand_string(qstring *buf, const insn_t &insn, int opnum) { return 0; }

    ///< Generate text representation of a register.
    ///< Most processor modules do not need to implement this callback.
    ///< It is useful only if \ph{reg_names}[reg] does not provide
    ///< the correct register name.
    ///< \param buf     (qstring *) output buffer
    ///< \param reg     (int) internal register number as defined in the processor module
    ///< \param width   (size_t) register width in bytes
    ///< \param reghi   (int) if not -1 then this function will return the register pair
    ///< \return -1 if error, strlen(buf) otherwise
    virtual int get_reg_name(qstring *buf, int reg, size_t width, int reghi) { return 0; }

    ///< Convert a register name to a register number.
    ///< The register number is the register index in the \ph{reg_names} array
    ///< Most processor modules do not need to implement this callback
    ///< It is useful only if \ph{reg_names}[reg] does not provide
    ///< the correct register names
    ///< \param regname  (const char *)
    ///< \return register number + 1
    ///< \return 0 not implemented or could not be decoded
    virtual int str2reg(const char *regname) { return 0; }

    ///< Callback: get dynamic auto comment.
    ///< Will be called if the autocomments are enabled
    ///< and the comment retrieved from ida.int starts with
    ///< '$!'. 'insn' contains valid info.
    ///< \param buf     (qstring *) output buffer
    ///< \param insn    (const ::insn_t*) the instruction
    ///< \retval 1  new comment has been generated
    ///< \retval 0  callback has not been handled.
    ///<            the buffer must not be changed in this case
    virtual int get_autocmt(qstring *buf, const insn_t &insn) { return 0; }

    ///< Get item background color.
    ///< Plugins can hook this callback to color disassembly lines dynamically
    ///< \param color  (::bgcolor_t *), out
    ///< \param ea     (::ea_t)
    ///< \retval 0  not implemented
    ///< \retval 1  color set
    virtual int get_bg_color(bgcolor_t *color, ea_t ea) { return 0; }

    ///< Is the function a trivial "jump" function?.
    ///< \param pfn           (::func_t *)
    ///< \param jump_target   (::ea_t *)
    ///< \param func_pointer  (::ea_t *)
    ///< \retval <0  no
    ///< \retval 0  don't know
    ///< \retval 1  yes, see 'jump_target' and 'func_pointer'
    virtual int is_jump_func(func_t &pfn, ea_t *jump_target, ea_t *func_pointer) { return 0; }

    ///< find_func_bounds() finished its work.
    ///< The module may fine tune the function bounds
    ///< \param possible_return_code  (int *), in/out
    ///< \param pfn                   (::func_t *)
    ///< \param max_func_end_ea       (::ea_t) (from the kernel's point of view)
    ///< \return void
    virtual void func_bounds(int *possible_return_code, func_t &pfn, ea_t max_func_end_ea) { }

    ///< All function instructions have been analyzed.
    ///< Now the processor module can analyze the stack pointer
    ///< for the whole function
    ///< \param pfn  (::func_t *)
    ///< \retval 0  ok
    ///< \retval <0 bad stack pointer
    virtual int verify_sp(func_t &pfn) { return 0; }

    ///< The kernel wants to set 'noreturn' flags for a function.
    ///< \param pfn  (::func_t *)            <<< other vars don't have the 'p' prefix
    ///< \return 0: ok. any other value: do not set 'noreturn' flag
    virtual int verify_noreturn(func_t &pfn) { return 0; }

    ///< Create a function frame for a newly created function
    ///< Set up frame size, its attributes etc
    ///< \param pfn      (::func_t *)
    ///< \return  1  ok
    ///< \return  0  not implemented
    virtual int create_func_frame(func_t &pfn) { return 0; }

    ///< Get size of function return address in bytes
    ///< If this eveny is not implemented, the kernel will assume
    ///<  - 8 bytes for 64-bit function
    ///<  - 4 bytes for 32-bit function
    ///<  - 2 bytes otherwise
    ///< If this eveny is not implemented, the kernel will assume
    ///< \param frsize   (int *) frame size (out)
    ///< \param pfn      (const ::func_t *), can't be NULL
    ///< \return  1  ok
    ///< \return  0  not implemented
    virtual int get_frame_retsize(int *retsize, const func_t &pfn) { return 0; }

    ///< a coefficient before being used in the stack frame?.
    ///< Currently used by TMS320C55 because the references into
    ///< the stack should be multiplied by 2
    ///< \note #PR_SCALE_STKVARS should be set to use this callback
    ///< \return scaling factor, 0-not implemented
    virtual int get_stkvar_scale_factor() { return 0; }

    ///< Demangle a C++ (or another language) name into a user-readable string.
    ///< This event is called by demangle_name()
    ///< \param res     (int32 *) value to return from demangle_name()
    ///< \param out     (::qstring *) output buffer. may be NULL
    ///< \param name    (const char *) mangled name
    ///< \param disable_mask  (uint32) flags to inhibit parts of output or compiler info/other (see MNG_)
    ///< \param demreq  (demreq_type_t) operation to perform      <<< in name.hpp
    ///< \return: 1 if success, 0-not implemented
    ///< \note if you call demangle_name() from the handler, protect against recursion!
    virtual int demangle_name(int32 *res, qstring *out, const char *name, uint32 disable_mask, demreq_type_t demreq) { return 0; }

        // the following 5 events are very low level
        // take care of possible recursion

    ///< A code reference is being created.
    ///< \param from  (::ea_t)
    ///< \param to    (::ea_t)
    ///< \param type  (::cref_t)
    ///< \return < 0 - cancel cref creation
    ///< \return 0 - not implemented or continue
    virtual int add_cref(ea_t from, ea_t to, cref_t type) { return 0; }

    ///< A data reference is being created.
    ///< \param from  (::ea_t)
    ///< \param to    (::ea_t)
    ///< \param type  (::dref_t)
    ///< \return < 0 - cancel dref creation
    ///< \return 0 - not implemented or continue
    virtual int add_dref(ea_t from, ea_t to, dref_t type) { return 0; }

    ///< A code reference is being deleted.
    ///< \param from    (::ea_t)
    ///< \param to      (::ea_t)
    ///< \param expand  (bool)
    ///< \return < 0 - cancel cref deletion
    ///< \return 0 - not implemented or continue
    virtual int del_cref(ea_t from, ea_t to, bool expand) { return 0; }

    ///< A data reference is being deleted.
    ///< \param from    (::ea_t)
    ///< \param to      (::ea_t)
    ///< \return < 0 - cancel dref deletion
    ///< \return 0 - not implemented or continue
    virtual int del_dref(ea_t from, ea_t to) { return 0; }

    ///< Data reference is being analyzed.
    ///< plugin may correct 'code_ea' (e.g. for thumb mode refs, we clear the last bit)
    ///< \param from        (::ea_t)
    ///< \param to          (::ea_t)
    ///< \param may_define  (bool)
    ///< \param code_ea     (::ea_t *)
    ///< \return < 0 - cancel dref analysis
    ///< \return 0 - not implemented or continue
    virtual int coagulate_dref(ea_t from, ea_t to, bool may_define, ea_t *code_ea) { return 0; }

    ///< The kernel wants to display the segment registers
    ///< in the messages window.
    ///< \param current_ea  (::ea_t)
    ///< \return <0 if the kernel should not show the segment registers.
    ///< (assuming that the module has done it)
    ///< \return 0 - not implemented
    virtual int may_show_sreg(ea_t current_ea) { return 0; }

    ///< ELF loader machine type checkpoint.
    ///< A plugin check of the 'machine_type'. If it is the desired one,
    ///< the the plugin fills 'p_procname' with the processor name
    ///< (one of the names present in \ph{psnames}).
    ///< 'p_pd' is used to handle relocations, otherwise can be left untouched.
    ///< This event occurs for each newly loaded ELF file
    ///< \param li            (linput_t *)
    ///< \param machine_type  (int)
    ///< \param p_procname    (const char **)
    ///< \param p_pd          (proc_def_t **) (see ldr\elf.h)
    ///< \return  e_machine value (if it is different from the
    ///<          original e_machine value, procname and 'p_pd' will be ignored
    ///<          and the new value will be used)
    virtual int loader_elf_machine(linput_t &li, int machine_type, const char **p_procname, proc_def_t **p_pd) { return machine_type; }

    ///< One analysis queue is empty.
    ///< \param type  (::atype_t)              <<< from auto.hpp
    ///< \retval >=0  yes, keep the queue empty (default)
    ///< \retval <0   no, the queue is not empty anymore
    ///< see also \ref idb_event::auto_empty_finally
    virtual int auto_queue_empty(atype_t type) { return 0; }

    ///< Flirt has recognized a library function.
    ///< This callback can be used by a plugin or proc module
    ///< to intercept it and validate such a function.
    ///< \param start_ea  (::ea_t)
    ///< \param funcname  (const char *)
    ///< \retval -1  do not create a function,
    ///< \retval  0  function is validated
    virtual int validate_flirt_func(ea_t start_ea, const char *funcname) { return 0; }

    ///< Called when a signature module has been matched against
    ///< bytes in the database. This is used to compute the
    ///< offset at which a particular module's libfunc should
    ///< be applied.
    ///< \param sig     (const idasgn_t *)
    ///< \param libfun  (const libfunc_t *)
    ///< \param ea      (::ea_t *) \note 'ea' initially contains the ea_t of the
    ///<                                 start of the pattern match
    ///< \retval 1   the ea_t pointed to by the third argument was modified.
    ///< \retval <=0 not modified. use default algorithm.
    virtual int adjust_libfunc_ea(const idasgn_t &sig, const libfunc_t &libfun, ea_t *ea) { return 0; }

    ///< Assemble an instruction.
    ///< (display a warning if an error is found).
    ///< \param bin    (::uchar *) pointer to output opcode buffer
    ///< \param ea     (::ea_t) linear address of instruction
    ///< \param cs     (::ea_t) cs of instruction
    ///< \param ip     (::ea_t) ip of instruction
    ///< \param use32  (bool) is 32bit segment?
    ///< \param line   (const char *) line to assemble
    ///< \return size of the instruction in bytes
    virtual int assemble(uchar *_bin, ea_t ea, ea_t cs, ea_t ip, bool _use32, const char *line) { return 0; }

    ///< Extract address from a string.
    ///< \param  out_ea    (ea_t *), out
    ///< \param  screen_ea (ea_t)
    ///< \param  string    (const char *)
    ///< \param  position  (size_t)
    ///< \retval  1 ok
    ///< \retval  0 kernel should use the standard algorithm
    ///< \retval -1 error
    virtual int extract_address(ea_t *out_ea, ea_t screen_ea, const char *string, size_t x) { return 0; }

    ///< Floating point -> IEEE conversion
    ///< \param m    (void *)   pointer to data
    ///< \param e    (uint16 *) internal IEEE format data
    ///< \param swt  (uint16)   operation (see realcvt() in ieee.h)
    ///< \return  0  not implemented
    ///< \return  1  ok
    ///< \return  \ref REAL_ERROR_ on error
    virtual int realcvt(void *m, unsigned short *e, unsigned short swt) { return 0; }

    ///< Callback: generating asm or lst file.
    ///< The kernel calls this callback twice, at the beginning
    ///< and at the end of listing generation. The processor
    ///< module can intercept this event and adjust its output
    ///< \param starting  (bool) beginning listing generation
    ///< \param fp        (FILE *) output file
    ///< \param is_asm    (bool) true:assembler, false:listing
    ///< \param flags     (int) flags passed to gen_file()
    ///< \param outline   (gen_outline_t **) ptr to ptr to outline callback.
    ///<                  if this callback is defined for this code, it will be
    ///<                  used by the kernel to output the generated lines
    ///< \return void
    virtual void gen_asm_or_lst(bool starting, FILE *fp, bool is_asm, int flags, /*gen_outline_t ** */ void *outline) { }

    ///<  Generate map file. If not implemented
    ///< the kernel itself will create the map file.
    ///< \param nlines (int *) number of lines in map file (-1 means write error)
    ///< \param fp     (FILE *) output file
    ///< \return  0  not implemented
    ///< \return  1  ok
    ///< \retval -1  write error
    virtual int gen_map_file(int *nlines, FILE *fp) { return 0; }

    ///< Create special segment representing the flat group.
    ///< \param image_base  (::ea_t)
    ///< \param bitness     (int)
    ///< \param dataseg_sel (::sel_t)
    ///< return value is ignored
    virtual void create_flat_group(ea_t image_base, int bitness, sel_t dataseg_sel) { }

    ///< IBM PC only internal request,
    ///< should never be used for other purpose
    ///< Get register value by internal index
    ///< \param regval   (uval_t *), out
    ///< \param regnum   (int)
    ///< \return  1 ok
    ///< \return  0 not implemented
    ///< \return -1 failed (undefined value or bad regnum)
    virtual int getreg(uval_t *rv, int regnum) { return 0; }

    /* ======= START OF DEBUGGER CALLBACKS ======= */

    ///< Get next address to be executed
    ///< This function must return the next address to be executed.
    ///< If the instruction following the current one is executed, then it must return #BADADDR
    ///< Usually the instructions to consider are: jumps, branches, calls, returns.
    ///< This function is essential if the 'single step' is not supported in hardware.
    ///< \param target     (::ea_t *), out: pointer to the answer
    ///< \param ea         (::ea_t) instruction address
    ///< \param tid        (int) current therad id
    ///< \param getreg     (::processor_t::regval_getter_t *) function to get register values
    ///< \param regvalues  (const ::regval_t *) register values array
    ///< \retval 0 unimplemented
    ///< \retval 1 implemented
    virtual int next_exec_insn(ea_t *target, ea_t ea, int tid, ::processor_t::regval_getter_t *_getreg, const regval_t *regvalues) { return 0; }

    ///< Calculate the address of the instruction which will be
    ///< executed after "step over". The kernel will put a breakpoint there.
    ///< If the step over is equal to step into or we can not calculate
    ///< the address, return #BADADDR.
    ///< \param target  (::ea_t *) pointer to the answer
    ///< \param ip      (::ea_t) instruction address
    ///< \retval 0 unimplemented
    ///< \retval 1 implemented
    virtual int calc_step_over(ea_t *target, ea_t ip) { return 0; }

    ///< Calculate list of addresses the instruction in 'insn'
    ///< may pass control to.
    ///< This callback is required for source level debugging.
    ///< \param res       (::eavec_t *), out: array for the results.
    ///< \param insn      (const ::insn_t*) the instruction
    ///< \param over      (bool) calculate for step over (ignore call targets)
    ///< \retval  <0 incalculable (indirect jumps, for example)
    ///< \retval >=0 number of addresses of called functions in the array.
    ///<             They must be put at the beginning of the array (0 if over=true)
    virtual int calc_next_eas(eavec_t &res, const insn_t &insn, bool over) { return 0; }

    ///< Calculate the start of a macro instruction.
    ///< This notification is called if IP points to the middle of an instruction
    ///< \param head  (::ea_t *), out: answer, #BADADDR means normal instruction
    ///< \param ip    (::ea_t) instruction address
    ///< \retval 0 unimplemented
    ///< \retval 1 implemented
    virtual int get_macro_insn_head(ea_t *head, ea_t ip) { return 0; }

    ///< Get the number of the operand to be displayed in the
    ///< debugger reference view (text mode).
    ///< \param opnum  (int *) operand number (out, -1 means no such operand)
    ///< \param insn   (const ::insn_t*) the instruction
    ///< \retval 0 unimplemented
    ///< \retval 1 implemented
    virtual int get_dbr_opnum(int *opnum, const insn_t &insn) { return 0; }

    ///< Check if insn will read the TF bit.
    ///< \param insn       (const ::insn_t*) the instruction
    ///< \param getreg     (::processor_t::regval_getter_t *) function to get register values
    ///< \param regvalues  (const ::regval_t *) register values array
    ///< \retval 2  yes, will generate 'step' exception
    ///< \retval 1  yes, will store the TF bit in memory
    ///< \retval 0  no
    virtual int insn_reads_tbit(const insn_t &insn, ::processor_t::regval_getter_t *_getreg, const regval_t *regvalues) { return 0; }

    ///< Clear the TF bit after an insn like pushf stored it in memory.
    ///< \param ea  (::ea_t) instruction address
    ///< \param getreg     (::processor_t::regval_getter_t *) function to get register values
    ///< \param regvalues  (const ::regval_t *) register values array
    ///< \retval 1  ok
    ///< \retval 0  failed
    virtual int clean_tbit(ea_t ea, ::processor_t::regval_getter_t *_getreg, const regval_t *regvalues) { return 0; }

    ///< Get operand information.
    ///< This callback is used to calculate the operand
    ///< value for double clicking on it, hints, etc.
    ///< \param opinf      (::idd_opinfo_t *) the output buffer
    ///< \param ea         (::ea_t) instruction address
    ///< \param n          (int) operand number
    ///< \param thread_id  (int) current thread id
    ///< \param getreg     (::processor_t::regval_getter_t *) function to get register values
    ///< \param regvalues  (const ::regval_t *) register values array
    ///< \return 1-ok, 0-failed
    virtual int get_idd_opinfo(idd_opinfo_t &opinf, ea_t ea, int n, int thread_id, ::processor_t::regval_getter_t *_getreg, const regval_t *regvalues) { return 0; }

    ///< Get register information by its name.
    ///< example: "ah" returns:
    ///<   - main_regname="eax"
    ///<   - bitrange_t = { offset==8, nbits==8 }
    ///<
    ///< This callback may be unimplemented if the register
    ///< names are all present in \ph{reg_names} and they all have
    ///< the same size
    ///< \param main_regname  (const char **), out
    ///< \param bitrange      (::bitrange_t *), out: position and size of the value within 'main_regname' (empty bitrange == whole register)
    ///< \param regname       (const char *)
    ///< \retval  1  ok
    ///< \retval -1  failed (not found)
    ///< \retval  0  unimplemented
    virtual int get_reg_info(const char **main_regname, bitrange_t &bitrange, const char *regname) { return 0; }

        /* ======== START OF TYPEINFO CALLBACKS ========= */
        // The codes below will be called only if #PR_TYPEINFO is set.
        // The codes ev_max_ptr_size, ev_get_default_enum_size MUST be implemented.
        // (other codes are optional but still require for normal
        // operation of the type system. without calc_arglocs,
        // for example, ida will not know about the argument
        // locations for function calls.

    ///< Setup default type libraries. (called after loading
    ///< a new file into the database).
    ///< The processor module may load tils, setup memory
    ///< model and perform other actions required to set up
    ///< the type system.
    ///< This is an optional callback.
    ///< \param none
    ///< \return void
    virtual void setup_til() { }

    ///< Get all possible ABI names and optional extensions for given compiler
    ///< abiname/option is a string entirely consisting of letters, digits and underscore
    ///< \param abi_names (qstrvec_t *) - all possible ABis each in form abiname-opt1-opt2-...
    ///< \param abi_opts  (qstrvec_t *) - array of all possible options in form "opt:description" or opt:hint-line#description
    ///< \param comp      (comp_t) - compiler ID
    ///< \retval 0 not implemented
    ///< \retval 1 ok
    virtual int get_abi_info(qstrvec_t &abi_names, qstrvec_t &abi_opts, comp_t comp) { return 0; }

    ///< Get maximal size of a pointer in bytes.
    ///< \param none
    ///< \return max possible size of a pointer
    virtual int max_ptr_size() { return inf.cc.size_l; }

    ///< Get default enum size.
    ///< \param cm  (::cm_t)
    ///< \returns sizeof(enum)
    virtual int get_default_enum_size(cm_t cm) { return inf.cc.size_e; }

    ///< Get register allocation convention for given calling convention
    ///< \param regs  (::callregs_t *), out
    ///< \param cc    (::cm_t)
    ///< \return 1
    ///< \return 0 - not implemented
    virtual int get_cc_regs(callregs_t &regs, cm_t cc) { return 0; }

    ///< Get offset from SP to the first stack argument.
    ///< For example: pc: 0, hppa: -0x34, ppc: 0x38
    ///< \param none
    ///< \returns the offset
    virtual int get_stkarg_offset() { return 0; }

    ///< Get size of shadow args in bytes.
    ///< \param[out] shadow_args_size  (int *)
    ///< \param pfn                    (::func_t *) (may be NULL)
    ///< \return 1 if filled *shadow_args_size
    ///< \return 0 - not implemented
    virtual int shadow_args_size(int *shadow_size, func_t *pfn) { return 0; }

    ///< Get SIMD-related types according to given attributes ant/or argument location
    ///< \param out (::simd_info_vec_t *)
    ///< \param simd_attrs (const ::simd_info_t *), may be NULL
    ///< \param argloc (const ::argloc_t *), may be NULL
    ///< \param create_tifs (bool) return valid tinfo_t objects, create if neccessary
    ///< \return number of found types, -1-error
    ///< If name==NULL, initialize all SIMD types
    virtual int get_simd_types(simd_info_vec_t &out, const simd_info_t *simd_attrs, const argloc_t *argloc, bool create_tifs) { return 0; }

    ///< Calculate number of purged bytes after call.
    ///< \param ea  (::ea_t) address of the call instruction
    ///< \returns number of purged bytes (usually add sp, N)
    virtual int calc_cdecl_purged_bytes(ea_t ea) { return 0; }

    ///< Calculate number of purged bytes by the given function type.
    ///< \param[out] p_purged_bytes  (int *) ptr to output
    ///< \param fti                  (const ::func_type_data_t *) func type details
    ///< \return 1
    ///< \return 0 - not implemented
    virtual int calc_purged_bytes(int *p_purged_bytes, const func_type_data_t &fti) { return 0; }

    ///< Calculate return value location.
    ///< \param[out] retloc  (::argloc_t *)
    ///< \param rettype      (const tinfo_t *)
    ///< \param cc           (::cm_t)
    ///< \return  0  not implemented
    ///< \return  1  ok,
    ///< \return -1  error
    virtual int calc_retloc(argloc_t &retloc, const tinfo_t &rettype, cm_t cc) { return 0; }

    ///< Calculate function argument locations.
    ///< This callback should fill retloc, all arglocs, and stkargs.
    ///< This callback supersedes calc_argloc2.
    ///< This callback is never called for ::CM_CC_SPECIAL functions.
    ///< \param fti  (::func_type_data_t *) points to the func type info
    ///< \retval  0  not implemented
    ///< \retval  1  ok
    ///< \retval -1  error
    virtual int calc_arglocs(func_type_data_t &fti) { return 0; }

    ///< Calculate locations of the arguments that correspond to '...'.
    ///< \param ftd      (::func_type_data_t *), inout: info about all arguments (including varargs)
    ///< \param regs     (::regobjs_t *) buffer for register values
    ///< \param stkargs  (::relobj_t *) stack arguments
    ///< \param nfixed   (int) number of fixed arguments
    ///< \retval  0  not implemented
    ///< \retval  1  ok
    ///< \retval -1  error
    virtual int calc_varglocs(func_type_data_t &ftd, regobjs_t &regs, relobj_t &stkargs, int nfixed) { return 0; }

    ///< Adjust argloc according to its type/size
    ///< and platform endianess
    ///< \param argloc  (argloc_t *), inout
    ///< \param type    (const tinfo_t *), may be NULL
    ///<   NULL means primitive type of given size
    ///< \param size    (int)
    ///<   'size' makes no sense if type != NULL
    ///<   (type->get_size() should be used instead)
    ///< \retval  0  not implemented
    ///< \retval  1  ok
    ///< \retval -1  error
    virtual int adjust_argloc(argloc_t &argloc, const tinfo_t &type, int size) { return 0; }

    ///< Get function arguments which should be converted to pointers when lowering function prototype.
    ///<  Processor module can also modify 'fti' in
    ///< order to make a non-standard convertion for some of the arguments.
    ///< \param argnums (intvec_t *), out - numbers of arguments to be converted to pointers in acsending order
    ///< \param fti     (::func_type_data_t *), inout func type details
    ///< (special values -1/-2 for return value - position of hidden 'retstr' argument: -1 - at the beginning, -2 - at the end)
    ///< \retval 0 not implemented
    ///< \retval 1 argnums was filled
    ///< \retval 2 argnums was filled and made substantial changes to fti
    virtual int lower_func_type(intvec_t &argnums, func_type_data_t &fti) { return 0; }

    ///< Are 2 register arglocs the same?.
    ///< We need this callback for the pc module.
    ///< \param a1  (::argloc_t *)
    ///< \param a2  (::argloc_t *)
    ///< \retval  1  yes
    ///< \retval -1  no
    ///< \retval  0  not implemented
    virtual int equal_reglocs(const argloc_t &a1, const argloc_t &a2) { return 1; }

    ///< Use information about a stack argument.
    ///< \param ea  (::ea_t) address of the push instruction which
    ///<                     pushes the function argument into the stack
    ///< \param arg  (const ::funcarg_t *) argument info
    ///< \retval 1   ok
    ///< \retval <=0 failed, the kernel will create a comment with the
    ///<             argument name or type for the instruction
    virtual int use_stkarg_type(ea_t ea, const funcarg_t &arg) { return 0; }

    ///< Use information about register argument.
    ///< \param[out] idx (int *) pointer to the returned value, may contain:
    ///<                         - idx of the used argument, if the argument is defined
    ///<                           in the current instruction, a comment will be applied by the kernel
    ///<                         - idx | #REG_SPOIL - argument is spoiled by the instruction
    ///<                         - -1 if the instruction doesn't change any registers
    ///<                         - -2 if the instruction spoils all registers
    ///< \param ea       (::ea_t) address of the instruction
    ///< \param rargs    (const ::funcargvec_t *) vector of register arguments
    ///<                               (including regs extracted from scattered arguments)
    ///< \return 1
    ///< \return 0  not implemented
    virtual int use_regarg_type(int *idx, ea_t ea, const funcargvec_t &rargs) { return 0; }

    ///< Use information about callee arguments.
    ///< \param ea     (::ea_t) address of the call instruction
    ///< \param fti    (::func_type_data_t *) info about function type
    ///< \param rargs  (::funcargvec_t *) array of register arguments
    ///< \return 1 (and removes handled arguments from fti and rargs)
    ///< \return 0  not implemented
    virtual int use_arg_types(ea_t ea, func_type_data_t &fti, funcargvec_t &rargs) { return 0; }

    ///< Argument address info is ready.
    ///< \param caller  (::ea_t)
    ///< \param n       (int) number of formal arguments
    ///< \param tif     (tinfo_t *) call prototype
    ///< \param addrs   (::ea_t *) argument intilization addresses
    ///< \return <0: do not save into idb; other values mean "ok to save"
    virtual int arg_addrs_ready(ea_t caller, int n, const tinfo_t &tif, ea_t *addrs) { return 0; }

    ///< Decorate/undecorate a C symbol name.
    ///< \param outbuf  (::qstring *) output buffer
    ///< \param name    (const char *) name of symbol
    ///< \param mangle  (bool) true-mangle, false-unmangle
    ///< \param cc      (::cm_t) calling convention
    ///< \param type    (const ::tinfo_t *) name type (NULL-unknown)
    ///< \return 1 if success
    ///< \return 0 not implemented or failed
    virtual int decorate_name(qstring *outbuf, const char *name, bool mangle, cm_t cc, const tinfo_t &type) { return 0; }

};
