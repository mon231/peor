/* seh_linux64.c — Windows x64 SEH emulator for peor Linux shellcode.
 *
 * Compiled with -DPEOR_LINUX_SEH and linked into x64 Linux PE builds only.
 * Provides the 5 kernel32 IAT slots that libgcc_eh.a(unwind-seh.o) references,
 * plus the vterminate stdio stubs that libsupc++.a(vterminate.o) references.
 *
 * The shellcode preserves .pdata / .xdata sections verbatim, so we can
 * implement real PE-based function-table lookup and unwind.
 *
 * NOT used for Windows or EFI targets — those use the real kernel32 / freestanding.c. */

typedef __SIZE_TYPE__  size_t;
typedef unsigned int   DWORD;
typedef unsigned long long ULONG64;
typedef void          *PVOID;
typedef unsigned char  BYTE;
typedef unsigned short WORD;

#ifdef __cplusplus
extern "C" {
#endif

/* ── vterminate / cp-demangle stubs ────────────────────────────────────────── */
/* __verbose_terminate_handler in vterminate.o needs stdio and __acrt_iob_func.
 * We never actually call terminate() successfully in our test, but the linker
 * demands the symbols exist. */

typedef void _SEH_FILE;
static _SEH_FILE *_seh_null_iob(unsigned int n) { (void)n; return (_SEH_FILE *)0; }
_SEH_FILE *(*__imp___acrt_iob_func)(unsigned int) = _seh_null_iob;

size_t fwrite(const void *p, size_t sz, size_t n, _SEH_FILE *f)
    { (void)p; (void)sz; (void)n; (void)f; return 0; }
int fputs(const char *s, _SEH_FILE *f)  { (void)s; (void)f; return -1; }
int fputc(int c, _SEH_FILE *f)          { (void)c; (void)f; return -1; }

int __mingw_vsprintf(char *buf, const char *fmt, void *ap)
    { (void)fmt; (void)ap; if (buf) buf[0] = 0; return 0; }

/* ── PEOR_CONTEXT — mirrors Windows x64 CONTEXT exactly ────────────────────── */
/* Total size: 0x4D0 (1232 bytes).  Only fields we touch are laid out; the rest
 * are padding. Offsets verified against winnt.h. */

#define PEOR_CONTEXT_SIZE  0x4D0u

#define PEOR_CTX_OFF_P1Home  0x08u   /* P1Home (home area) */
#define PEOR_CTX_OFF_Rax     0x78u
#define PEOR_CTX_OFF_Rcx     0x80u
#define PEOR_CTX_OFF_Rdx     0x88u
#define PEOR_CTX_OFF_Rbx     0x90u
#define PEOR_CTX_OFF_Rsp     0x98u
#define PEOR_CTX_OFF_Rbp     0xA0u
#define PEOR_CTX_OFF_Rsi     0xA8u
#define PEOR_CTX_OFF_Rdi     0xB0u
#define PEOR_CTX_OFF_R8      0xB8u
#define PEOR_CTX_OFF_R9      0xC0u
#define PEOR_CTX_OFF_R10     0xC8u
#define PEOR_CTX_OFF_R11     0xD0u
#define PEOR_CTX_OFF_R12     0xD8u
#define PEOR_CTX_OFF_R13     0xE0u
#define PEOR_CTX_OFF_R14     0xE8u
#define PEOR_CTX_OFF_R15     0xF0u
#define PEOR_CTX_OFF_Rip     0xF8u

typedef struct {
    BYTE _raw[PEOR_CONTEXT_SIZE];
} PEOR_CONTEXT;

static inline ULONG64 _ctx_rax(PEOR_CONTEXT *c) { ULONG64 v; __builtin_memcpy(&v, c->_raw + PEOR_CTX_OFF_Rax, 8); return v; }
static inline ULONG64 _ctx_rsp(PEOR_CONTEXT *c) { ULONG64 v; __builtin_memcpy(&v, c->_raw + PEOR_CTX_OFF_Rsp, 8); return v; }
static inline ULONG64 _ctx_rip(PEOR_CONTEXT *c) { ULONG64 v; __builtin_memcpy(&v, c->_raw + PEOR_CTX_OFF_Rip, 8); return v; }
static inline void _ctx_set_rax(PEOR_CONTEXT *c, ULONG64 v) { __builtin_memcpy(c->_raw + PEOR_CTX_OFF_Rax, &v, 8); }
static inline void _ctx_set_rip(PEOR_CONTEXT *c, ULONG64 v) { __builtin_memcpy(c->_raw + PEOR_CTX_OFF_Rip, &v, 8); }

/* ── PE header constants ────────────────────────────────────────────────────── */
#define PE_SIGNATURE              0x00004550u
#define PE_OPTIONAL_MAGIC_PE64    0x020Bu
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION  3u

/* ── RUNTIME_FUNCTION (.pdata entry) ────────────────────────────────────────── */
typedef struct {
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD UnwindInfoAddress;
} PEOR_RUNTIME_FUNCTION;

/* ── UNWIND_INFO header ─────────────────────────────────────────────────────── */
/* Version/Flags byte: bits[0..2]=version, bits[3..7]=flags */
#define UNW_FLAG_EHANDLER  0x01u
#define UNW_FLAG_UHANDLER  0x02u
#define UNW_FLAG_CHAININFO 0x04u

typedef struct {
    BYTE  VersionFlags;    /* version in low 3 bits, flags in high 5 */
    BYTE  SizeOfProlog;
    BYTE  CountOfUnwindCodes;
    BYTE  FrameRegisterOffset; /* frame reg in low 4 bits, offset in high 4 (×16) */
} PEOR_UNWIND_INFO_HDR;

/* Unwind operation codes */
#define UWOP_PUSH_NONVOL      0u
#define UWOP_ALLOC_LARGE      1u
#define UWOP_ALLOC_SMALL      2u
#define UWOP_SET_FPREG        3u
#define UWOP_SAVE_NONVOL      4u
#define UWOP_SAVE_NONVOL_FAR  5u
#define UWOP_SAVE_XMM128      8u
#define UWOP_SAVE_XMM128_FAR  9u
#define UWOP_PUSH_MACHFRAME  10u

/* ── DISPATCHER_CONTEXT (subset of fields we read) ──────────────────────────── */
typedef struct {
    ULONG64              ControlPc;         /* 0  */
    ULONG64              ImageBase;         /* 8  */
    PEOR_RUNTIME_FUNCTION *FunctionEntry;  /* 16 */
    ULONG64              EstablisherFrame;  /* 24 */
    ULONG64              TargetIp;          /* 32 */
    PEOR_CONTEXT        *ContextRecord;     /* 40 */
    void                *LanguageHandler;   /* 48 */
    void                *HandlerData;       /* 56 */
    void                *HistoryTable;      /* 64 */
} PEOR_DISPATCHER_CONTEXT;

/* ── EXCEPTION_RECORD (partial) ─────────────────────────────────────────────── */
#define EXCEPTION_NONCONTINUABLE    0x01u
#define EXCEPTION_GCC_SEARCH        0x20474343u  /* '  GCC' */
#define EXCEPTION_GCC_UNWIND        0x21474343u  /* '! GCC' */

typedef struct {
    DWORD   ExceptionCode;        /* 0  */
    DWORD   ExceptionFlags;       /* 4  */
    void   *ExceptionRecord;      /* 8  */
    PVOID   ExceptionAddress;     /* 16 */
    DWORD   NumberParameters;     /* 24 */
    DWORD   _pad;                 /* 28 */
    ULONG64 ExceptionInformation[15]; /* 32 */
} PEOR_EXCEPTION_RECORD;

/* ExceptionInformation indices used by GCC's unwind-seh.o */
#define EI_UNW_EXCEPTION  0u   /* _Unwind_Exception * */
#define EI_TARGET_FRAME   1u   /* establisher frame of catch handler */
#define EI_LANDING_PAD    2u   /* IP of landing pad */

/* ── __ImageBase: linker-provided base address ───────────────────────────────── */
extern char __ImageBase;

/* ── PE parsing helpers ──────────────────────────────────────────────────────── */
static ULONG64 _peor_image_base(void) {
    return (ULONG64)&__ImageBase;
}

static PEOR_RUNTIME_FUNCTION *_peor_pdata(ULONG64 base, DWORD *count_out) {
    /* Locate .pdata via DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].
     * PE64 layout:
     *   base+0x00: DOS header (e_magic='MZ', e_lfanew at +0x3C)
     *   base+e_lfanew: PE signature (4 bytes)
     *   +4: COFF FileHeader (20 bytes)
     *   +24: Optional header: Magic(2)+... DataDirectory starts at offset 112
     *   DataDirectory[3] = EXCEPTION_TABLE: at optional_header+112+3*8 */
    DWORD e_lfanew;
    __builtin_memcpy(&e_lfanew, (char *)base + 0x3C, 4);
    ULONG64 nt = base + e_lfanew;

    /* Verify PE signature */
    DWORD sig;
    __builtin_memcpy(&sig, (char *)nt, 4);
    if (sig != PE_SIGNATURE) { *count_out = 0; return (PEOR_RUNTIME_FUNCTION *)0; }

    /* Optional header magic at nt+24 */
    WORD magic;
    __builtin_memcpy(&magic, (char *)nt + 24, 2);
    if (magic != PE_OPTIONAL_MAGIC_PE64) { *count_out = 0; return (PEOR_RUNTIME_FUNCTION *)0; }

    /* DataDirectory[EXCEPTION] at nt+24+112+IMAGE_DIRECTORY_ENTRY_EXCEPTION*8 */
    ULONG64 dd_off = nt + 24u + 112u + IMAGE_DIRECTORY_ENTRY_EXCEPTION * 8u;
    DWORD rva, size;
    __builtin_memcpy(&rva,  (char *)dd_off,     4);
    __builtin_memcpy(&size, (char *)dd_off + 4, 4);

    *count_out = size / 12u; /* each RUNTIME_FUNCTION = 12 bytes */
    return (PEOR_RUNTIME_FUNCTION *)(base + rva);
}

/* Binary search .pdata for the RUNTIME_FUNCTION enclosing rip_rva. */
static PEOR_RUNTIME_FUNCTION *_peor_lookup_func(
        PEOR_RUNTIME_FUNCTION *pdata, DWORD count, DWORD rip_rva)
{
    DWORD lo = 0, hi = count;
    while (lo < hi) {
        DWORD mid = (lo + hi) / 2u;
        if (rip_rva < pdata[mid].BeginAddress)      hi = mid;
        else if (rip_rva >= pdata[mid].EndAddress)  lo = mid + 1u;
        else                                         return &pdata[mid];
    }
    return (PEOR_RUNTIME_FUNCTION *)0;
}

/* ── RtlCaptureContext emulator ──────────────────────────────────────────────── */
/* Writes all GPRs + RIP into *ctx.  Called by _Unwind_Resume / _Unwind_Backtrace. */
static void _peor_CaptureContext(PEOR_CONTEXT *ctx) {
    __builtin_memset(ctx, 0, PEOR_CONTEXT_SIZE);
    ULONG64 rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi;
    ULONG64 r8, r9, r10, r11, r12, r13, r14, r15, rip;
    __asm__ volatile (
        "mov %%rax, %0\n\t"
        "mov %%rcx, %1\n\t"
        "mov %%rdx, %2\n\t"
        "mov %%rbx, %3\n\t"
        "mov %%rsp, %4\n\t"
        "mov %%rbp, %5\n\t"
        "mov %%rsi, %6\n\t"
        "mov %%rdi, %7\n\t"
        : "=m"(rax),"=m"(rcx),"=m"(rdx),"=m"(rbx),
          "=m"(rsp),"=m"(rbp),"=m"(rsi),"=m"(rdi)
    );
    __asm__ volatile (
        "mov %%r8,  %0\n\t"
        "mov %%r9,  %1\n\t"
        "mov %%r10, %2\n\t"
        "mov %%r11, %3\n\t"
        "mov %%r12, %4\n\t"
        "mov %%r13, %5\n\t"
        "mov %%r14, %6\n\t"
        "mov %%r15, %7\n\t"
        : "=m"(r8),"=m"(r9),"=m"(r10),"=m"(r11),
          "=m"(r12),"=m"(r13),"=m"(r14),"=m"(r15)
    );
    /* Capture the return address of this call as RIP */
    __asm__ volatile ("lea (%%rip), %0" : "=r"(rip));
    __builtin_memcpy(ctx->_raw + PEOR_CTX_OFF_Rax, &rax, 8);
    __builtin_memcpy(ctx->_raw + PEOR_CTX_OFF_Rcx, &rcx, 8);
    __builtin_memcpy(ctx->_raw + PEOR_CTX_OFF_Rdx, &rdx, 8);
    __builtin_memcpy(ctx->_raw + PEOR_CTX_OFF_Rbx, &rbx, 8);
    __builtin_memcpy(ctx->_raw + PEOR_CTX_OFF_Rsp, &rsp, 8);
    __builtin_memcpy(ctx->_raw + PEOR_CTX_OFF_Rbp, &rbp, 8);
    __builtin_memcpy(ctx->_raw + PEOR_CTX_OFF_Rsi, &rsi, 8);
    __builtin_memcpy(ctx->_raw + PEOR_CTX_OFF_Rdi, &rdi, 8);
    __builtin_memcpy(ctx->_raw + PEOR_CTX_OFF_R8,  &r8,  8);
    __builtin_memcpy(ctx->_raw + PEOR_CTX_OFF_R9,  &r9,  8);
    __builtin_memcpy(ctx->_raw + PEOR_CTX_OFF_R10, &r10, 8);
    __builtin_memcpy(ctx->_raw + PEOR_CTX_OFF_R11, &r11, 8);
    __builtin_memcpy(ctx->_raw + PEOR_CTX_OFF_R12, &r12, 8);
    __builtin_memcpy(ctx->_raw + PEOR_CTX_OFF_R13, &r13, 8);
    __builtin_memcpy(ctx->_raw + PEOR_CTX_OFF_R14, &r14, 8);
    __builtin_memcpy(ctx->_raw + PEOR_CTX_OFF_R15, &r15, 8);
    __builtin_memcpy(ctx->_raw + PEOR_CTX_OFF_Rip, &rip, 8);
}

/* ── UNWIND_INFO decoder: apply prolog unwind codes to recover caller RSP ─── */
/* Returns the establisher frame (caller RSP after unwinding the prolog). */
static ULONG64 _peor_decode_unwind(
        ULONG64 base, PEOR_RUNTIME_FUNCTION *rf, ULONG64 rsp)
{
    PEOR_UNWIND_INFO_HDR *ui =
        (PEOR_UNWIND_INFO_HDR *)(base + (rf->UnwindInfoAddress & ~1u));
    BYTE flags   = (ui->VersionFlags >> 3) & 0x1Fu;
    BYTE nwords  = ui->CountOfUnwindCodes;
    WORD *codes  = (WORD *)(ui + 1); /* array of 2-byte unwind codes */

    /* Walk codes to compute stack adjustments */
    for (BYTE i = 0; i < nwords; ) {
        BYTE op  = (BYTE)(codes[i] & 0xF);    /* OpInfo bits [3:0] */
        BYTE info = (BYTE)((codes[i] >> 4) & 0xF); /* OpInfo bits [7:4] */
        (void)info;
        switch (op) {
        case UWOP_PUSH_NONVOL:
            rsp += 8u;
            i += 1;
            break;
        case UWOP_ALLOC_LARGE:
            if (((codes[i] >> 8) & 0xF) == 0) {
                /* next slot is size/8 */
                rsp += (ULONG64)codes[i + 1] * 8u;
                i += 2;
            } else {
                /* next two slots are size */
                DWORD sz; __builtin_memcpy(&sz, &codes[i + 1], 4);
                rsp += sz;
                i += 3;
            }
            break;
        case UWOP_ALLOC_SMALL:
            rsp += (ULONG64)(((codes[i] >> 8) & 0xF) * 8u + 8u);
            i += 1;
            break;
        case UWOP_SET_FPREG:
            /* RSP was set to frame_reg - offset; restore from frame register.
             * We don't track frame registers here, so best-effort: skip. */
            i += 1;
            break;
        case UWOP_SAVE_NONVOL:
        case UWOP_SAVE_XMM128:
            i += 2;
            break;
        case UWOP_SAVE_NONVOL_FAR:
        case UWOP_SAVE_XMM128_FAR:
            i += 3;
            break;
        case UWOP_PUSH_MACHFRAME:
            /* Error code present if info==1 */
            rsp += (ULONG64)(info ? 88u : 80u);
            i += 1;
            break;
        default:
            i += 1;
            break;
        }
    }

    /* Handle chained UNWIND_INFO */
    if (flags & UNW_FLAG_CHAININFO) {
        BYTE align = (nwords & 1u) ? 1u : 0u; /* codes array is padded to DWORD */
        PEOR_RUNTIME_FUNCTION *chain =
            (PEOR_RUNTIME_FUNCTION *)(codes + nwords + align);
        rsp = _peor_decode_unwind(base, chain, rsp);
    }
    return rsp;
}

/* personality function type (Windows x64 calling convention) */
typedef DWORD (*_peor_personality_fn)(
    PVOID ExceptionRecord,
    ULONG64 EstablisherFrame,
    PEOR_CONTEXT *ContextRecord,
    PEOR_DISPATCHER_CONTEXT *DispatcherContext);

/* ── RtlLookupFunctionEntry emulator ────────────────────────────────────────── */
static PEOR_RUNTIME_FUNCTION *_peor_LookupFunctionEntry(
        ULONG64 ControlPc, ULONG64 *ImageBase, void *HistoryTable)
{
    (void)HistoryTable;
    ULONG64 base = _peor_image_base();
    DWORD count;
    PEOR_RUNTIME_FUNCTION *pdata = _peor_pdata(base, &count);
    if (!pdata) return (PEOR_RUNTIME_FUNCTION *)0;
    DWORD rip_rva = (DWORD)(ControlPc - base);
    if (ImageBase) *ImageBase = base;
    return _peor_lookup_func(pdata, count, rip_rva);
}

/* ── RtlVirtualUnwind emulator ───────────────────────────────────────────────── */
/* Invokes the language-specific handler for a frame and returns it. */
static PEOR_RUNTIME_FUNCTION *_peor_VirtualUnwind(
        DWORD HandlerType,
        ULONG64 ImageBase,
        ULONG64 ControlPc,
        PEOR_RUNTIME_FUNCTION *FunctionEntry,
        PEOR_CONTEXT *ContextRecord,
        PVOID *HandlerData,
        ULONG64 *EstablisherFrame,
        PVOID KnonwnFrameReg)
{
    (void)HandlerType; (void)KnonwnFrameReg;

    /* Recover establisher frame by decoding the prolog */
    ULONG64 rsp = _ctx_rsp(ContextRecord);
    ULONG64 frame = _peor_decode_unwind(ImageBase, FunctionEntry, rsp);
    if (EstablisherFrame) *EstablisherFrame = frame;

    /* Update RSP to caller's RSP and RIP to return address on stack */
    ULONG64 ret_addr;
    __builtin_memcpy(&ret_addr, (void *)frame, 8);
    _ctx_set_rip(ContextRecord, ret_addr);
    ULONG64 new_rsp = frame + 8u;
    __builtin_memcpy(ContextRecord->_raw + PEOR_CTX_OFF_Rsp, &new_rsp, 8);

    /* Check for language-specific handler */
    PEOR_UNWIND_INFO_HDR *ui =
        (PEOR_UNWIND_INFO_HDR *)(ImageBase + (FunctionEntry->UnwindInfoAddress & ~1u));
    BYTE flags = (ui->VersionFlags >> 3) & 0x1Fu;
    BYTE nwords = ui->CountOfUnwindCodes;
    BYTE align  = (nwords & 1u) ? 1u : 0u;
    WORD *codes = (WORD *)(ui + 1);

    if ((flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) && HandlerData) {
        DWORD *handler_rva_ptr = (DWORD *)(codes + nwords + align);
        DWORD  handler_rva;
        __builtin_memcpy(&handler_rva, handler_rva_ptr, 4);
        *HandlerData = (void *)(handler_rva_ptr + 1); /* LSDA follows handler RVA */
        return (PEOR_RUNTIME_FUNCTION *)(ImageBase + handler_rva);
    }
    if (HandlerData) *HandlerData = (void *)0;
    return (PEOR_RUNTIME_FUNCTION *)0;
}

/* ── RaiseException emulator ────────────────────────────────────────────────── */
/* Implements the two-phase GCC SEH dispatch:
 *   Phase 1 (ExceptionCode == 0x20474343): walk frames, find handler.
 *   Phase 2 (ExceptionCode == 0x21474343): walk frames up to target, unwind. */
static void _peor_RaiseException(
        DWORD ExceptionCode,
        DWORD ExceptionFlags,
        DWORD NumberParameters,
        const ULONG64 *ExceptionInformation)
{
    ULONG64 base = _peor_image_base();
    DWORD count;
    PEOR_RUNTIME_FUNCTION *pdata = _peor_pdata(base, &count);

    /* Capture current context (caller of RaiseException) */
    PEOR_CONTEXT ctx;
    _peor_CaptureContext(&ctx);
    /* Step one frame up: our caller called _Unwind_RaiseException which called us */
    ULONG64 cur_rsp = _ctx_rsp(&ctx);
    ULONG64 ret1;
    __builtin_memcpy(&ret1, (void *)cur_rsp, 8);
    _ctx_set_rip(&ctx, ret1);
    ULONG64 rsp1 = cur_rsp + 8u;
    __builtin_memcpy(ctx._raw + PEOR_CTX_OFF_Rsp, &rsp1, 8);

    PEOR_EXCEPTION_RECORD exc;
    __builtin_memset(&exc, 0, sizeof(exc));
    exc.ExceptionCode    = ExceptionCode;
    exc.ExceptionFlags   = ExceptionFlags;
    exc.NumberParameters = NumberParameters;
    if (NumberParameters && ExceptionInformation) {
        DWORD n = NumberParameters < 15u ? NumberParameters : 15u;
        __builtin_memcpy(exc.ExceptionInformation, ExceptionInformation, n * 8u);
    }

    ULONG64 target_frame  = (ExceptionCode == EXCEPTION_GCC_UNWIND && NumberParameters >= 2u)
                            ? ExceptionInformation[EI_TARGET_FRAME] : 0u;

    /* Walk the call stack frame-by-frame */
    for (;;) {
        ULONG64 rip = _ctx_rip(&ctx);
        if (!rip) break;
        DWORD rip_rva = (DWORD)(rip - base);
        PEOR_RUNTIME_FUNCTION *rf = _peor_lookup_func(pdata, count, rip_rva);
        if (!rf) {
            /* Leaf function or out of range — step up manually */
            ULONG64 rsp = _ctx_rsp(&ctx);
            ULONG64 ret;
            __builtin_memcpy(&ret, (void *)rsp, 8);
            _ctx_set_rip(&ctx, ret);
            ULONG64 ns = rsp + 8u;
            __builtin_memcpy(ctx._raw + PEOR_CTX_OFF_Rsp, &ns, 8);
            continue;
        }

        /* Compute establisher frame for this function */
        ULONG64 frame = _peor_decode_unwind(base, rf, _ctx_rsp(&ctx));

        /* Dispatch the language handler if present */
        PEOR_UNWIND_INFO_HDR *ui =
            (PEOR_UNWIND_INFO_HDR *)(base + (rf->UnwindInfoAddress & ~1u));
        BYTE flags  = (ui->VersionFlags >> 3) & 0x1Fu;
        BYTE nwords = ui->CountOfUnwindCodes;
        BYTE align  = (nwords & 1u) ? 1u : 0u;
        WORD *codes = (WORD *)(ui + 1);

        if (flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) {
            DWORD *hrva_ptr = (DWORD *)(codes + nwords + align);
            DWORD hrva; __builtin_memcpy(&hrva, hrva_ptr, 4);
            _peor_personality_fn personality =
                (_peor_personality_fn)(base + hrva);
            void *lsda = (void *)(hrva_ptr + 1);

            PEOR_DISPATCHER_CONTEXT dc;
            __builtin_memset(&dc, 0, sizeof(dc));
            dc.ControlPc        = rip;
            dc.ImageBase        = base;
            dc.FunctionEntry    = rf;
            dc.EstablisherFrame = frame;
            dc.ContextRecord    = &ctx;
            dc.HandlerData      = lsda;

            DWORD res = personality(&exc, frame, &ctx, &dc);
            /* res==0: continue search; res==1: handler found (only in search phase) */
            (void)res; /* In phase2 (unwind), personality calls RtlUnwindEx itself */
        }

        /* In unwind phase, stop at target frame */
        if (ExceptionCode == EXCEPTION_GCC_UNWIND && frame == target_frame)
            break;

        /* Advance to next frame */
        ULONG64 rsp = _ctx_rsp(&ctx);
        ULONG64 ret;
        __builtin_memcpy(&ret, (void *)(frame), 8);
        _ctx_set_rip(&ctx, ret);
        ULONG64 ns = frame + 8u;
        __builtin_memcpy(ctx._raw + PEOR_CTX_OFF_Rsp, &ns, 8);
    }

    /* If we reach here in phase 2, abort */
    while (1) {}
}

/* ── RtlUnwindEx emulator ───────────────────────────────────────────────────── */
/* Called by _GCC_specific_handler when the handler frame is reached.
 * Sets RSP = EstablisherFrame, RAX = ReturnValue, then jumps to TargetIp.
 * Never returns. */
static void _peor_RtlUnwindEx(
        PVOID TargetFrame,
        PVOID TargetIp,
        PEOR_EXCEPTION_RECORD *ExceptionRecord,
        PVOID ReturnValue,
        PEOR_CONTEXT *OriginalContext,
        PVOID HistoryTable)
{
    (void)ExceptionRecord; (void)OriginalContext; (void)HistoryTable;
    ULONG64 target_rsp = (ULONG64)TargetFrame;
    ULONG64 target_rip = (ULONG64)TargetIp;
    ULONG64 rax_val    = (ULONG64)ReturnValue;
    /* Restore RSP to target_frame, set RAX = ReturnValue, jump to TargetIp */
    __asm__ volatile (
        "mov %0, %%rsp\n\t"
        "mov %1, %%rax\n\t"
        "jmp *%2\n\t"
        :
        : "r"(target_rsp), "r"(rax_val), "r"(target_rip)
        : "memory"
    );
    __builtin_unreachable();
}

/* ── IAT function pointer slots (x64: C name == COFF name, no underscore) ─── */
void (*__imp_RtlCaptureContext)(PEOR_CONTEXT *)                                             = _peor_CaptureContext;
PEOR_RUNTIME_FUNCTION *(*__imp_RtlLookupFunctionEntry)(ULONG64, ULONG64 *, void *)         = _peor_LookupFunctionEntry;
PEOR_RUNTIME_FUNCTION *(*__imp_RtlVirtualUnwind)(DWORD, ULONG64, ULONG64, PEOR_RUNTIME_FUNCTION *, PEOR_CONTEXT *, PVOID *, ULONG64 *, PVOID) = _peor_VirtualUnwind;
void (*__imp_RaiseException)(DWORD, DWORD, DWORD, const ULONG64 *)                         = _peor_RaiseException;
void (*__imp_RtlUnwindEx)(PVOID, PVOID, PEOR_EXCEPTION_RECORD *, PVOID, PEOR_CONTEXT *, PVOID) = _peor_RtlUnwindEx;

#ifdef __cplusplus
} /* extern "C" */
#endif
