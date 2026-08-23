/* seh_linux64.c — Windows x64 SEH emulator for peor freestanding shellcode.
 *
 * Two compile-time modes:
 *   -DPEOR_LINUX_SEH: Linux shellcode — heap via mmap syscall; abort via exit.
 *   -DPEOR_EFI_SEH:   EFI  shellcode — heap via static array; abort loops.
 *
 * Both modes provide:
 *   - 5 kernel32 IAT slots (libgcc_eh.a/unwind-seh.o): RtlCaptureContext,
 *     RtlLookupFunctionEntry, RtlVirtualUnwind, RaiseException, RtlUnwindEx.
 *   - Freestanding Windows-ABI implementations of all libc.so.6 /
 *     libpthread.so.0 symbols that libsupc++/libgcc_eh need.
 *
 * For Linux: libsupc++/libgcc_eh use Windows x64 ABI (RCX/RDX/R8/R9); glibc
 * uses SysV ABI (RDI/RSI/RDX/RCX).  The __imp_* overrides here bypass glibc.
 *
 * NOT used for Windows targets or EFI x86 (DWARF exceptions, no SEH needed). */

typedef __SIZE_TYPE__      size_t;
typedef unsigned int       DWORD;
typedef unsigned long long ULONG64;
typedef void              *PVOID;
typedef unsigned char      BYTE;
typedef unsigned short     WORD;

#ifdef __cplusplus
extern "C" {
#endif

/* ── Raw Linux syscall helpers (Linux mode only) ──────────────────────────── */
#ifdef PEOR_LINUX_SEH

#define SYS_MMAP         0x09ULL
#define SYS_EXIT         0x3CULL

#define PROT_RW          0x03ULL
#define MAP_PRIV_ANON    0x22ULL
#define MAP_FAILED_ADDR  (~0ULL)

/* mmap syscall: sys_mmap(addr=0, len, prot, flags, fd=-1, off=0) */
static ULONG64 _peor_mmap(ULONG64 len, ULONG64 prot, ULONG64 flags) {
    register ULONG64 _nr  __asm__("rax") = SYS_MMAP;
    register ULONG64 _a1  __asm__("rdi") = 0ULL;
    register ULONG64 _a2  __asm__("rsi") = len;
    register ULONG64 _a3  __asm__("rdx") = prot;
    register ULONG64 _a4  __asm__("r10") = flags;
    register ULONG64 _a5  __asm__("r8")  = MAP_FAILED_ADDR;
    register ULONG64 _a6  __asm__("r9")  = 0ULL;
    ULONG64 r;
    __asm__ volatile("syscall" : "=a"(r)
        : "0"(_nr),"r"(_a1),"r"(_a2),"r"(_a3),"r"(_a4),"r"(_a5),"r"(_a6)
        : "rcx","r11","memory");
    return r;
}

static void __attribute__((noreturn)) _peor_sys_exit(int code) {
    register ULONG64 _nr __asm__("rax") = SYS_EXIT;
    register ULONG64 _a1 __asm__("rdi") = (ULONG64)(unsigned int)code;
    __asm__ volatile("syscall" :: "r"(_nr),"r"(_a1) : "rcx","r11","memory");
    __builtin_unreachable();
}

#endif /* PEOR_LINUX_SEH */


/* ── vterminate stubs (libsupc++ vterminate.o) ────────────────────────────── */
typedef void _SEH_FILE;
static _SEH_FILE *_seh_null_iob(unsigned int n) { (void)n; return (_SEH_FILE *)0; }
_SEH_FILE *(*__imp___acrt_iob_func)(unsigned int) = _seh_null_iob;
size_t fwrite(const void *p, size_t sz, size_t n, _SEH_FILE *f)
    { (void)p;(void)sz;(void)n;(void)f; return 0; }
int fputs(const char *s, _SEH_FILE *f)  { (void)s;(void)f; return -1; }
int fputc(int c,         _SEH_FILE *f)  { (void)c;(void)f; return -1; }
int __mingw_vsprintf(char *b, const char *f, void *a)
    { (void)f;(void)a; if(b) b[0]=0; return 0; }

/* ── Freestanding allocator ───────────────────────────────────────────────── */
#define PEOR_HEAP_SIZE  0x20000u  /* 128 KB */

static BYTE *_heap_base;
static BYTE *_heap_ptr;
static BYTE *_heap_end;

#ifdef PEOR_EFI_SEH
static BYTE _static_heap[PEOR_HEAP_SIZE];
static void _heap_init(void) {
    if (_heap_base) return;
    _heap_base = _static_heap;
    _heap_ptr  = _static_heap;
    _heap_end  = _static_heap + PEOR_HEAP_SIZE;
}
#else  /* PEOR_LINUX_SEH: mmap-backed */
static void _heap_init(void) {
    if (_heap_base) return;
    ULONG64 p = _peor_mmap(PEOR_HEAP_SIZE, PROT_RW, MAP_PRIV_ANON);
    if (p == MAP_FAILED_ADDR || (long long)p < 0) return;
    _heap_base = (BYTE *)p;
    _heap_ptr  = _heap_base;
    _heap_end  = _heap_base + PEOR_HEAP_SIZE;
}
#endif

/* Each allocation: 8-byte header storing actual allocated size, then payload. */
static void *_peor_malloc(size_t n) {
    _heap_init();
    if (!_heap_base || !n) return (void *)0;
    size_t aligned = (n + 7u) & ~7u;
    if (_heap_ptr + 8u + aligned > _heap_end) return (void *)0;
    BYTE *blk = _heap_ptr;
    *(size_t *)blk = aligned;
    _heap_ptr += 8u + aligned;
    return blk + 8u;
}
static void _peor_free(void *p) { (void)p; }
static void *_peor_calloc(size_t nmemb, size_t sz) {
    size_t total = nmemb * sz;
    void *p = _peor_malloc(total);
    if (p) __builtin_memset(p, 0, total);
    return p;
}
static void *_peor_realloc(void *old, size_t newsz) {
    void *n = _peor_malloc(newsz);
    if (n && old) {
        size_t oldsz = ((size_t *)old)[-1];
        size_t cp = newsz < oldsz ? newsz : oldsz;
        __builtin_memcpy(n, old, cp);
    }
    return n;
}

/* ── String / memory functions ────────────────────────────────────────────── */

static void *_peor_memcpy(void *dst, const void *src, size_t n) {
    BYTE *d = (BYTE *)dst; const BYTE *s = (const BYTE *)src;
    while (n--) *d++ = *s++;
    return dst;
}
static void *_peor_memset(void *dst, int c, size_t n) {
    BYTE *d = (BYTE *)dst;
    while (n--) *d++ = (BYTE)c;
    return dst;
}
static int _peor_memcmp(const void *a, const void *b, size_t n) {
    const BYTE *p = (const BYTE *)a, *q = (const BYTE *)b;
    while (n--) { if (*p != *q) return (int)*p - (int)*q; p++; q++; }
    return 0;
}
static size_t _peor_strlen(const char *s) {
    const char *p = s; while (*p) p++; return (size_t)(p - s);
}
static char *_peor_strchr(const char *s, int c) {
    while (*s) { if (*s == (char)c) return (char *)s; s++; }
    return (char)c ? (char *)0 : (char *)s;
}
static int _peor_strcmp(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}
static int _peor_strncmp(const char *a, const char *b, size_t n) {
    while (n && *a && *a == *b) { a++; b++; n--; }
    return n ? (unsigned char)*a - (unsigned char)*b : 0;
}
static unsigned long _peor_strtoul(const char *s, char **end, int base) {
    while (*s == ' ' || *s == '\t') s++;
    int neg = (*s == '-') ? (s++, 1) : (*s == '+' ? (s++, 0) : 0);
    if (base == 0) {
        if (s[0]=='0' && (s[1]=='x'||s[1]=='X')) { base=16; s+=2; }
        else if (*s=='0') { base=8; s++; }
        else base=10;
    }
    unsigned long v = 0;
    for (;;) {
        int d;
        if (*s>='0'&&*s<='9') d=*s-'0';
        else if (*s>='a'&&*s<='z') d=*s-'a'+10;
        else if (*s>='A'&&*s<='Z') d=*s-'A'+10;
        else break;
        if (d>=base) break;
        v = v*(unsigned long)base + (unsigned long)d;
        s++;
    }
    if (end) *end=(char *)s;
    return neg ? (unsigned long)(-(long)v) : v;
}

/* ── Other libc stubs ─────────────────────────────────────────────────────── */

static char *_peor_getenv(const char *n) { (void)n; return (char *)0; }
static int   _peor_atexit(void (*f)(void)) { (void)f; return 0; }
#ifdef PEOR_LINUX_SEH
static void __attribute__((noreturn)) _peor_abort(void) { _peor_sys_exit(1); }
#else
static void __attribute__((noreturn)) _peor_abort(void) { while (1) {} }
#endif

/* ── Pthread stubs (single-threaded; no Windows/glibc pthreads needed) ───── */
#define PEOR_MAX_KEYS  32u

static void *_tls[PEOR_MAX_KEYS];
static unsigned int _key_count;

typedef unsigned int  _peor_key_t;
typedef void         *_peor_mutex_t;
typedef unsigned int  _peor_once_t;

static int _peor_key_create(_peor_key_t *key, void (*d)(void *)) {
    (void)d;
    if (_key_count >= PEOR_MAX_KEYS) return 1;
    *key = _key_count++;
    return 0;
}
static void *_peor_getspecific(_peor_key_t k) {
    return k < PEOR_MAX_KEYS ? _tls[k] : (void *)0;
}
static int _peor_setspecific(_peor_key_t k, const void *v) {
    if (k >= PEOR_MAX_KEYS) return 1;
    _tls[k] = (void *)v;
    return 0;
}
static int _peor_once(_peor_once_t *ctl, void (*fn)(void)) {
    if (!*ctl) { fn(); *ctl = 1u; }
    return 0;
}
static int _peor_mutex_init(_peor_mutex_t *m, const void *a)    { (void)m;(void)a; return 0; }
static int _peor_mutex_lock(_peor_mutex_t *m)                   { (void)m; return 0; }
static int _peor_mutex_unlock(_peor_mutex_t *m)                 { (void)m; return 0; }
static int _peor_mutex_destroy(_peor_mutex_t *m)                { (void)m; return 0; }

/* ── Public direct-name exports ───────────────────────────────────────────── *
 * libsupc++/libgcc_eh can reference malloc, free, etc. either:               *
 *   (a) directly (call malloc) — satisfied by these public names              *
 *   (b) through IAT (call [__imp_malloc]) — satisfied by __imp_* below       */
void *malloc(size_t n)                              { return _peor_malloc(n); }
void  free(void *p)                                 { _peor_free(p); }
void *calloc(size_t nm, size_t sz)                  { return _peor_calloc(nm, sz); }
void *realloc(void *p, size_t n)                    { return _peor_realloc(p, n); }
void *memcpy(void *d, const void *s, size_t n)      { return _peor_memcpy(d, s, n); }
void *memset(void *d, int c, size_t n)              { return _peor_memset(d, c, n); }
int   memcmp(const void *a, const void *b, size_t n){ return _peor_memcmp(a, b, n); }
size_t strlen(const char *s)                        { return _peor_strlen(s); }
char *strchr(const char *s, int c)                  { return _peor_strchr(s, c); }
int   strcmp(const char *a, const char *b)          { return _peor_strcmp(a, b); }
int   strncmp(const char *a, const char *b, size_t n){ return _peor_strncmp(a, b, n); }
unsigned long strtoul(const char *s, char **e, int b){ return _peor_strtoul(s, e, b); }
char *getenv(const char *n)                         { return _peor_getenv(n); }
int   atexit(void (*f)(void))                       { return _peor_atexit(f); }
void  abort(void)                                   { _peor_abort(); }
int   pthread_key_create(_peor_key_t *k, void (*d)(void *)) { return _peor_key_create(k, d); }
void *pthread_getspecific(_peor_key_t k)            { return _peor_getspecific(k); }
int   pthread_setspecific(_peor_key_t k, const void *v) { return _peor_setspecific(k, v); }
int   pthread_once(_peor_once_t *c, void (*fn)(void))   { return _peor_once(c, fn); }
int   pthread_mutex_init(_peor_mutex_t *m, const void *a){ return _peor_mutex_init(m, a); }
int   pthread_mutex_lock(_peor_mutex_t *m)          { return _peor_mutex_lock(m); }
int   pthread_mutex_unlock(_peor_mutex_t *m)        { return _peor_mutex_unlock(m); }
int   pthread_mutex_destroy(_peor_mutex_t *m)       { return _peor_mutex_destroy(m); }

/* ── IAT overrides (for __declspec(dllimport) references via [__imp_*]) ───── */
void *(*__imp_malloc)(size_t)                             = malloc;
void  (*__imp_free)(void *)                               = free;
void *(*__imp_calloc)(size_t, size_t)                     = calloc;
void *(*__imp_realloc)(void *, size_t)                    = realloc;
void *(*__imp_memcpy)(void *, const void *, size_t)       = memcpy;
void *(*__imp_memset)(void *, int, size_t)                = memset;
int   (*__imp_memcmp)(const void *, const void *, size_t) = memcmp;
size_t(*__imp_strlen)(const char *)                       = strlen;
char *(*__imp_strchr)(const char *, int)                  = strchr;
int   (*__imp_strcmp)(const char *, const char *)         = strcmp;
int   (*__imp_strncmp)(const char *, const char *, size_t)= strncmp;
unsigned long (*__imp_strtoul)(const char *, char **, int)= strtoul;
char *(*__imp_getenv)(const char *)                       = getenv;
int   (*__imp_atexit)(void (*)(void))                     = atexit;
void  (*__imp_abort)(void)                                = abort;
int   (*__imp_pthread_key_create)(_peor_key_t *, void (*)(void *)) = pthread_key_create;
void *(*__imp_pthread_getspecific)(_peor_key_t)                    = pthread_getspecific;
int   (*__imp_pthread_setspecific)(_peor_key_t, const void *)      = pthread_setspecific;
int   (*__imp_pthread_once)(_peor_once_t *, void (*)(void))        = pthread_once;
int   (*__imp_pthread_mutex_init)(_peor_mutex_t *, const void *)   = pthread_mutex_init;
int   (*__imp_pthread_mutex_lock)(_peor_mutex_t *)                 = pthread_mutex_lock;
int   (*__imp_pthread_mutex_unlock)(_peor_mutex_t *)               = pthread_mutex_unlock;
int   (*__imp_pthread_mutex_destroy)(_peor_mutex_t *)              = pthread_mutex_destroy;

/* ── EFI-only symbols ─────────────────────────────────────────────────────── */
#ifdef PEOR_EFI_SEH
void *__dso_handle = (void *)0;
void  _pei386_runtime_relocator(void) {}
#endif

/* ── PEOR_CONTEXT — exact Windows x64 CONTEXT layout ─────────────────────── */
#define PEOR_CONTEXT_SIZE  0x4D0u
#define PEOR_CTX_Rax  0x78u
#define PEOR_CTX_Rcx  0x80u
#define PEOR_CTX_Rdx  0x88u
#define PEOR_CTX_Rbx  0x90u
#define PEOR_CTX_Rsp  0x98u
#define PEOR_CTX_Rbp  0xA0u
#define PEOR_CTX_Rsi  0xA8u
#define PEOR_CTX_Rdi  0xB0u
#define PEOR_CTX_R8   0xB8u
#define PEOR_CTX_R9   0xC0u
#define PEOR_CTX_R10  0xC8u
#define PEOR_CTX_R11  0xD0u
#define PEOR_CTX_R12  0xD8u
#define PEOR_CTX_R13  0xE0u
#define PEOR_CTX_R14  0xE8u
#define PEOR_CTX_R15  0xF0u
#define PEOR_CTX_Rip  0xF8u

typedef struct { BYTE _raw[PEOR_CONTEXT_SIZE]; } PEOR_CONTEXT;

static inline ULONG64 _ctx_rsp(const PEOR_CONTEXT *c)
    { ULONG64 v; __builtin_memcpy(&v, c->_raw+PEOR_CTX_Rsp, 8); return v; }
static inline ULONG64 _ctx_rip(const PEOR_CONTEXT *c)
    { ULONG64 v; __builtin_memcpy(&v, c->_raw+PEOR_CTX_Rip, 8); return v; }
static inline void _ctx_set_rsp(PEOR_CONTEXT *c, ULONG64 v)
    { __builtin_memcpy(c->_raw+PEOR_CTX_Rsp, &v, 8); }
static inline void _ctx_set_rip(PEOR_CONTEXT *c, ULONG64 v)
    { __builtin_memcpy(c->_raw+PEOR_CTX_Rip, &v, 8); }

/* ── PE constants ─────────────────────────────────────────────────────────── */
#define PE_SIGNATURE                   0x00004550u
#define PE_OPT_MAGIC_PE64              0x020Bu
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION 3u

/* ── .pdata / .xdata structures ───────────────────────────────────────────── */
typedef struct { DWORD BeginAddress, EndAddress, UnwindInfoAddress; } PEOR_RF;

/* UNWIND_INFO first 4 bytes */
#define UNW_VER_MASK    0x07u
#define UNW_FLAG_SHIFT  3
#define UNW_FLAG_EH     0x01u
#define UNW_FLAG_UH     0x02u
#define UNW_FLAG_CHAIN  0x04u

/* UNWIND_CODE opcodes (in high nibble of slot byte 1) */
#define UWOP_PUSH_NONVOL      0u
#define UWOP_ALLOC_LARGE      1u
#define UWOP_ALLOC_SMALL      2u
#define UWOP_SET_FPREG        3u
#define UWOP_SAVE_NONVOL      4u
#define UWOP_SAVE_NONVOL_FAR  5u
#define UWOP_SAVE_XMM128      8u
#define UWOP_SAVE_XMM128_FAR  9u
#define UWOP_PUSH_MACHFRAME  10u

typedef struct {
    BYTE VersionFlags;
    BYTE SizeOfProlog;
    BYTE CountOfCodes;
    BYTE FrameRegOff;
} PEOR_UI_HDR;

/* ── DISPATCHER_CONTEXT (matches Windows x64 layout) ─────────────────────── */
typedef struct {
    ULONG64  ControlPc;        /* 0  */
    ULONG64  ImageBase;        /* 8  */
    PEOR_RF *FunctionEntry;    /* 16 */
    ULONG64  EstablisherFrame; /* 24 */
    ULONG64  TargetIp;         /* 32 */
    PEOR_CONTEXT *ContextRecord; /* 40 */
    void    *LanguageHandler;  /* 48 */
    void    *HandlerData;      /* 56 */
    void    *HistoryTable;     /* 64 */
} PEOR_DC;

/* ── EXCEPTION_RECORD (partial) ───────────────────────────────────────────── */
#define EXC_GCC_SEARCH  0x20474343u
#define EXC_GCC_UNWIND  0x21474343u
#define EXC_NONCONTINUABLE 0x01u
#define EI_EXC_OBJ   0u  /* _Unwind_Exception * */
#define EI_TGT_FRAME 1u  /* establisher frame of handler */
#define EI_LANDING   2u  /* landing pad IP */

typedef struct {
    DWORD   Code, Flags;
    PVOID   ChainedRecord;
    PVOID   Address;
    DWORD   NumParams, _pad;
    ULONG64 Info[15];
} PEOR_EXC;

/* personality function type */
typedef DWORD (*_peor_pf)(PEOR_EXC *, ULONG64, PEOR_CONTEXT *, PEOR_DC *);

/* ── __ImageBase: linker symbol giving load address ──────────────────────── */
extern char __ImageBase;
static inline ULONG64 _base(void) { return (ULONG64)&__ImageBase; }

/* ── PE header parsing: find .pdata ──────────────────────────────────────── */
static PEOR_RF *_find_pdata(ULONG64 base, DWORD *cnt) {
    DWORD e_lfanew;
    __builtin_memcpy(&e_lfanew, (char *)base + 0x3C, 4);
    ULONG64 nt = base + e_lfanew;
    DWORD sig; __builtin_memcpy(&sig, (char *)nt, 4);
    if (sig != PE_SIGNATURE) { *cnt=0; return 0; }
    WORD magic; __builtin_memcpy(&magic, (char *)nt + 24, 2);
    if (magic != PE_OPT_MAGIC_PE64) { *cnt=0; return 0; }
    /* DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION] is at NT+24+112+3*8 */
    ULONG64 dd = nt + 24u + 112u + IMAGE_DIRECTORY_ENTRY_EXCEPTION * 8u;
    DWORD rva, sz;
    __builtin_memcpy(&rva, (char *)dd,   4);
    __builtin_memcpy(&sz,  (char *)dd+4, 4);
    *cnt = sz / 12u;
    return (PEOR_RF *)(base + rva);
}

static PEOR_RF *_lookup_rf(PEOR_RF *pd, DWORD cnt, DWORD rva) {
    DWORD lo=0, hi=cnt;
    while (lo<hi) {
        DWORD mid=(lo+hi)/2u;
        if (rva < pd[mid].BeginAddress)     hi=mid;
        else if (rva >= pd[mid].EndAddress) lo=mid+1u;
        else                                 return &pd[mid];
    }
    return 0;
}

/* ── UNWIND_INFO decoder: reverse prolog to compute establisher frame ─────── */
static ULONG64 _decode_unwind(ULONG64 base, PEOR_RF *rf, ULONG64 rsp,
                               PEOR_CONTEXT *ctx_out) {
    PEOR_UI_HDR *ui = (PEOR_UI_HDR *)(base + (rf->UnwindInfoAddress & ~1u));
    BYTE flags = (ui->VersionFlags >> UNW_FLAG_SHIFT) & 0x1Fu;
    BYTE count = ui->CountOfCodes;
    BYTE *slots = (BYTE *)(ui + 1);

    for (BYTE i = 0; i < count; ) {
        BYTE b   = slots[i*2 + 1];
        BYTE op  = b & 0x0Fu;
        BYTE inf = (b >> 4) & 0x0Fu;
        switch (op) {
        case UWOP_PUSH_NONVOL:
            rsp += 8u; i++; break;
        case UWOP_ALLOC_SMALL:
            rsp += (ULONG64)(inf * 8u + 8u); i++; break;
        case UWOP_ALLOC_LARGE:
            if (inf == 0) {
                WORD w; __builtin_memcpy(&w, &slots[(i+1)*2], 2);
                rsp += (ULONG64)w * 8u; i += 2;
            } else {
                DWORD d; __builtin_memcpy(&d, &slots[(i+1)*2], 4);
                rsp += (ULONG64)d; i += 3;
            }
            break;
        case UWOP_SET_FPREG:
            if (ctx_out) {
                BYTE fr  = ui->FrameRegOff & 0x0Fu;
                BYTE fof = (ui->FrameRegOff >> 4) & 0x0Fu;
                ULONG64 fp_val = rsp + (ULONG64)fof * 16u;
                if (fr <= 15u)
                    __builtin_memcpy(ctx_out->_raw + 0x78u + (ULONG64)fr * 8u, &fp_val, 8);
            }
            i++; break;
        case UWOP_SAVE_NONVOL:
        case UWOP_SAVE_XMM128:   i += 2; break;
        case UWOP_SAVE_NONVOL_FAR:
        case UWOP_SAVE_XMM128_FAR: i += 3; break;
        case UWOP_PUSH_MACHFRAME:
            rsp += (ULONG64)(inf ? 88u : 80u); i++; break;
        default: i++; break;
        }
    }

    if (flags & UNW_FLAG_CHAIN) {
        BYTE aligned = (count + 1u) & ~1u;
        PEOR_RF *chain = (PEOR_RF *)(slots + aligned * 2u);
        rsp = _decode_unwind(base, chain, rsp, (PEOR_CONTEXT *)0);
    }
    return rsp;
}

/* Extract personality handler pointer and LSDA from UNWIND_INFO. */
static _peor_pf _get_handler(ULONG64 base, PEOR_RF *rf, void **lsda_out) {
    PEOR_UI_HDR *ui = (PEOR_UI_HDR *)(base + (rf->UnwindInfoAddress & ~1u));
    BYTE flags = (ui->VersionFlags >> UNW_FLAG_SHIFT) & 0x1Fu;
    if (!(flags & (UNW_FLAG_EH | UNW_FLAG_UH))) return (_peor_pf)0;
    BYTE count   = ui->CountOfCodes;
    BYTE aligned = (count + 1u) & ~1u;
    BYTE *slots  = (BYTE *)(ui + 1);
    DWORD *hrva_ptr = (DWORD *)(slots + aligned * 2u);
    DWORD hrva; __builtin_memcpy(&hrva, hrva_ptr, 4);
    if (lsda_out) *lsda_out = (void *)(hrva_ptr + 1);
    return (_peor_pf)(base + hrva);
}

/* ── RtlCaptureContext: capture GPRs + return-address as RIP ─────────────── */
static void __attribute__((noinline)) _peor_CaptureContext(PEOR_CONTEXT *ctx) {
    __builtin_memset(ctx, 0, PEOR_CONTEXT_SIZE);
    ULONG64 rax,rcx,rdx,rbx,rbp_,rsi,rdi,r8,r9,r10,r11,r12,r13,r14,r15;
    __asm__ volatile(
        "mov %%rax,%0\n\t" "mov %%rcx,%1\n\t" "mov %%rdx,%2\n\t" "mov %%rbx,%3\n\t"
        "mov %%rbp,%4\n\t" "mov %%rsi,%5\n\t" "mov %%rdi,%6\n\t"
        :"=m"(rax),"=m"(rcx),"=m"(rdx),"=m"(rbx),"=m"(rbp_),"=m"(rsi),"=m"(rdi));
    __asm__ volatile(
        "mov %%r8,%0\n\t"  "mov %%r9,%1\n\t"  "mov %%r10,%2\n\t" "mov %%r11,%3\n\t"
        "mov %%r12,%4\n\t" "mov %%r13,%5\n\t" "mov %%r14,%6\n\t" "mov %%r15,%7\n\t"
        :"=m"(r8),"=m"(r9),"=m"(r10),"=m"(r11),"=m"(r12),"=m"(r13),"=m"(r14),"=m"(r15));
    ULONG64 rip = (ULONG64)__builtin_return_address(0);
    ULONG64 cap_rsp_now;
    __asm__ volatile("mov %%rsp,%0":"=r"(cap_rsp_now));
    ULONG64 rsp = cap_rsp_now + 8u;
    {
        ULONG64 b = _base(); DWORD nc; PEOR_RF *pd = _find_pdata(b, &nc);
        if (pd) {
            ULONG64 self_rip; __asm__ volatile("lea (%%rip),%0":"=r"(self_rip));
            PEOR_RF *srf = _lookup_rf(pd, nc, (DWORD)(self_rip - b));
            if (srf) rsp = _decode_unwind(b, srf, cap_rsp_now, (PEOR_CONTEXT *)0) + 8u;
        }
    }
    __builtin_memcpy(ctx->_raw+PEOR_CTX_Rax, &rax, 8);
    __builtin_memcpy(ctx->_raw+PEOR_CTX_Rcx, &rcx, 8);
    __builtin_memcpy(ctx->_raw+PEOR_CTX_Rdx, &rdx, 8);
    __builtin_memcpy(ctx->_raw+PEOR_CTX_Rbx, &rbx, 8);
    __builtin_memcpy(ctx->_raw+PEOR_CTX_Rsp, &rsp, 8);
    __builtin_memcpy(ctx->_raw+PEOR_CTX_Rbp, &rbp_, 8);
    __builtin_memcpy(ctx->_raw+PEOR_CTX_Rsi, &rsi, 8);
    __builtin_memcpy(ctx->_raw+PEOR_CTX_Rdi, &rdi, 8);
    __builtin_memcpy(ctx->_raw+PEOR_CTX_R8,  &r8,  8);
    __builtin_memcpy(ctx->_raw+PEOR_CTX_R9,  &r9,  8);
    __builtin_memcpy(ctx->_raw+PEOR_CTX_R10, &r10, 8);
    __builtin_memcpy(ctx->_raw+PEOR_CTX_R11, &r11, 8);
    __builtin_memcpy(ctx->_raw+PEOR_CTX_R12, &r12, 8);
    __builtin_memcpy(ctx->_raw+PEOR_CTX_R13, &r13, 8);
    __builtin_memcpy(ctx->_raw+PEOR_CTX_R14, &r14, 8);
    __builtin_memcpy(ctx->_raw+PEOR_CTX_R15, &r15, 8);
    __builtin_memcpy(ctx->_raw+PEOR_CTX_Rip, &rip, 8);
}

/* ── RtlLookupFunctionEntry ───────────────────────────────────────────────── */
static PEOR_RF *_peor_LookupFunctionEntry(
        ULONG64 ControlPc, ULONG64 *ImageBase, void *HistoryTable) {
    (void)HistoryTable;
    ULONG64 base = _base();
    DWORD cnt; PEOR_RF *pd = _find_pdata(base, &cnt);
    if (!pd) return 0;
    if (ImageBase) *ImageBase = base;
    return _lookup_rf(pd, cnt, (DWORD)(ControlPc - base));
}

/* ── RtlVirtualUnwind ─────────────────────────────────────────────────────── */
static void *_peor_VirtualUnwind(
        DWORD HandlerType, ULONG64 ImageBase, ULONG64 ControlPc,
        PEOR_RF *FunctionEntry, PEOR_CONTEXT *ContextRecord,
        PVOID *HandlerData, ULONG64 *EstablisherFrame, PVOID KNFReg) {
    (void)HandlerType;(void)KNFReg;
    ULONG64 rsp = _ctx_rsp(ContextRecord);
    ULONG64 frame = _decode_unwind(ImageBase, FunctionEntry, rsp, (PEOR_CONTEXT *)0);
    if (EstablisherFrame) *EstablisherFrame = frame;
    ULONG64 ret; __builtin_memcpy(&ret, (void *)frame, 8);
    _ctx_set_rip(ContextRecord, ret);
    _ctx_set_rsp(ContextRecord, frame + 8u);
    void *lsda;
    void *handler = (void *)_get_handler(ImageBase, FunctionEntry, &lsda);
    if (HandlerData) *HandlerData = handler ? lsda : (void *)0;
    return handler;
    (void)ControlPc;
}

/* ── RaiseException: two-phase SEH dispatcher ─────────────────────────────── */
static void __attribute__((noinline)) _peor_RaiseException(
        DWORD Code, DWORD Flags, DWORD NumParams, const ULONG64 *Info) {
    ULONG64 cur_rsp;
    __asm__ volatile("mov %%rsp,%0":"=r"(cur_rsp));

    ULONG64 walk_rip = (ULONG64)__builtin_return_address(0);

    ULONG64 base = _base();
    DWORD cnt; PEOR_RF *pdata_init = _find_pdata(base, &cnt);
    ULONG64 walk_rsp;
    if (pdata_init) {
        ULONG64 our_rip;
        __asm__ volatile("lea (%%rip),%0":"=r"(our_rip));
        PEOR_RF *our_rf = _lookup_rf(pdata_init, cnt, (DWORD)(our_rip - base));
        if (our_rf) {
            ULONG64 our_frame = _decode_unwind(base, our_rf, cur_rsp, (PEOR_CONTEXT *)0);
            walk_rsp = our_frame + 8u;
        } else {
            walk_rsp = cur_rsp + 8u;
        }
    } else {
        walk_rsp = cur_rsp + 8u;
    }

    PEOR_RF *pdata = pdata_init;
    if (!pdata) { while(1){} }

    PEOR_EXC exc;
    __builtin_memset(&exc, 0, sizeof(exc));
    exc.Code      = Code;
    exc.Flags     = Flags;
    exc.NumParams = NumParams;
    if (NumParams && Info) {
        DWORD n = NumParams < 15u ? NumParams : 15u;
        __builtin_memcpy(exc.Info, Info, n * 8u);
    }

    PEOR_CONTEXT ctx;
    __builtin_memset(&ctx, 0, PEOR_CONTEXT_SIZE);
    _ctx_set_rip(&ctx, walk_rip);
    _ctx_set_rsp(&ctx, walk_rsp);

    for (;;) {
        ULONG64 rip = _ctx_rip(&ctx);
        if (!rip) break;
        DWORD rip_rva = (DWORD)(rip - base);
        PEOR_RF *rf = _lookup_rf(pdata, cnt, rip_rva);
        if (!rf) {
            ULONG64 rsp = _ctx_rsp(&ctx);
            ULONG64 ret; __builtin_memcpy(&ret, (void *)rsp, 8);
            _ctx_set_rip(&ctx, ret);
            _ctx_set_rsp(&ctx, rsp + 8u);
            continue;
        }

        ULONG64 rsp   = _ctx_rsp(&ctx);
        ULONG64 frame = _decode_unwind(base, rf, rsp, &ctx);

        void *lsda = 0;
        _peor_pf pf = _get_handler(base, rf, &lsda);
        if (pf) {
            PEOR_DC dc;
            __builtin_memset(&dc, 0, sizeof(dc));
            dc.ControlPc        = rip;
            dc.ImageBase        = base;
            dc.FunctionEntry    = rf;
            dc.EstablisherFrame = frame;
            dc.ContextRecord    = &ctx;
            dc.HandlerData      = lsda;

            pf(&exc, frame, &ctx, &dc);
        }

        ULONG64 ret; __builtin_memcpy(&ret, (void *)frame, 8);
        _ctx_set_rip(&ctx, ret);
        _ctx_set_rsp(&ctx, frame + 8u);
    }

    while(1){}
}

/* ── Windows exception flags used during unwind ──────────────────────────── */
#define EXC_UNWINDING       0x02u
#define EXC_TARGET_UNWIND   0x20u

/* ── RtlUnwindEx: call personality for phase-2 then jump to landing pad ──── *
 * Windows SEH phase-2: the personality function (_GCC_specific_handler) is   *
 * called with EXCEPTION_TARGET_UNWIND | EXCEPTION_UNWINDING to let it set   *
 * OrigCtx->{Rip, Rax, Rdx} — Rdx is the handler selector (non-zero for a   *
 * typed catch like catch(PeorLinuxException&), zero for catch(...)).         */
static void __attribute__((noinline)) _peor_RtlUnwindEx(
        PVOID TargetFrame, PVOID TargetIp,
        PEOR_EXC *ExcRecord, PVOID ReturnValue,
        PEOR_CONTEXT *OrigCtx, PVOID HistoryTable) {
    (void)HistoryTable;
    ULONG64 base = _base();
    DWORD cnt; PEOR_RF *pdata = _find_pdata(base, &cnt);

    /* Phase 2: call the personality function for the target frame so it sets  *
     * OrigCtx->Rdx (handler selector) and OrigCtx->Rax (_Unwind_Exception*). *
     * IMPORTANT: ControlPc must be the THROW-SITE IP (OrigCtx->Rip), not the *
     * landing pad.  The LSDA maps try-ranges [begin,end) → landing pad; the  *
     * throw site is INSIDE the try range, while the landing pad is not.       */
    if (pdata && ExcRecord && OrigCtx) {
        ULONG64 throw_pc;
        __builtin_memcpy(&throw_pc, OrigCtx->_raw + PEOR_CTX_Rip, 8);
        PEOR_RF *rf = _lookup_rf(pdata, cnt, (DWORD)(throw_pc - base));
        if (rf) {
            void *lsda = 0;
            _peor_pf pf = _get_handler(base, rf, &lsda);
            if (pf) {
                PEOR_DC dc;
                __builtin_memset(&dc, 0, sizeof(dc));
                dc.ControlPc        = throw_pc;
                dc.ImageBase        = base;
                dc.FunctionEntry    = rf;
                dc.EstablisherFrame = (ULONG64)TargetFrame;
                dc.TargetIp         = (ULONG64)TargetIp;
                dc.ContextRecord    = OrigCtx;
                dc.HandlerData      = lsda;
                ExcRecord->Flags |= EXC_TARGET_UNWIND | EXC_UNWINDING;
                pf(ExcRecord, (ULONG64)TargetFrame, OrigCtx, &dc);
            }
        }
    }

    /* TargetIp is always the correct landing pad (passed directly by personality).  *
     * OrigCtx->Rip is not guaranteed to be updated; use TargetIp for the jump.    *
     * OrigCtx->Rdx (handler selector) and OrigCtx->Rax (_Unwind_Exception*) are  *
     * set by the personality's phase-2 call above.                                */
    ULONG64 tgt_rip = (ULONG64)TargetIp;
    ULONG64 rax_val = (ULONG64)ReturnValue;
    ULONG64 rdx_val = 0, rbp_val = 0, tgt_rsp = (ULONG64)TargetFrame;
    if (OrigCtx) {
        __builtin_memcpy(&tgt_rsp, OrigCtx->_raw + PEOR_CTX_Rsp, 8);
        __builtin_memcpy(&rbp_val, OrigCtx->_raw + PEOR_CTX_Rbp, 8);
        __builtin_memcpy(&rax_val, OrigCtx->_raw + PEOR_CTX_Rax, 8);
        __builtin_memcpy(&rdx_val, OrigCtx->_raw + PEOR_CTX_Rdx, 8);
        if (!rax_val) rax_val = (ULONG64)ReturnValue;
    }
    __asm__ volatile(
        "mov %0, %%r11\n\t"
        "mov %1, %%r12\n\t"
        "mov %2, %%r13\n\t"
        "mov %3, %%r14\n\t"
        "mov %4, %%r15\n\t"
        "mov %%r11, %%rsp\n\t"
        "mov %%r12, %%rax\n\t"
        "mov %%r13, %%rdx\n\t"
        "mov %%r14, %%rbp\n\t"
        "jmp *%%r15\n\t"
        :: "m"(tgt_rsp), "m"(rax_val), "m"(rdx_val), "m"(rbp_val), "m"(tgt_rip)
        : "r11","r12","r13","r14","r15","rax","rdx","memory");
    __builtin_unreachable();
}

/* ── IAT slots for kernel32.dll emulation ────────────────────────────────── */
void (*__imp_RtlCaptureContext)(PEOR_CONTEXT *)                                    = _peor_CaptureContext;
PEOR_RF *(*__imp_RtlLookupFunctionEntry)(ULONG64, ULONG64 *, void *)              = _peor_LookupFunctionEntry;
void *(*__imp_RtlVirtualUnwind)(DWORD,ULONG64,ULONG64,PEOR_RF*,PEOR_CONTEXT*,PVOID*,ULONG64*,PVOID) = _peor_VirtualUnwind;
void (*__imp_RaiseException)(DWORD,DWORD,DWORD,const ULONG64 *)                   = _peor_RaiseException;
void (*__imp_RtlUnwindEx)(PVOID,PVOID,PEOR_EXC*,PVOID,PEOR_CONTEXT*,PVOID)       = _peor_RtlUnwindEx;

#ifdef __cplusplus
} /* extern "C" */
#endif
