/* Freestanding CRT stubs for libsupc++ / libgcc_eh.
 *
 * Two compile-time modes:
 *
 *   Default (Windows, no flag): provide ONLY pthread stubs + __dso_handle.
 *     msvcrt.dll (linked via -lmsvcrt) supplies all other C runtime symbols
 *     (malloc/free/abort/memcpy/string functions, stdio, etc.).
 *
 *   -DPEOR_EFI (EFI / freestanding builds): ALSO provide all stdlib stubs so
 *     no OS library is needed.  Includes stdio no-ops and kernel32 IAT no-ops
 *     for x64.  Used for EFI targets and x86 Linux C++ builds where
 *     libsupc++.a(vterminate.o) pulls in Windows CRT symbols. */

typedef __SIZE_TYPE__ size_t;

/* ─── C linkage guard ─────────────────────────────────────────────────────── */
/* g++ treats .c files as C++ (equivalent to -x c++). All symbols in this file
 * must have C linkage so that libgcc_eh.a / libsupc++.a references resolve. */
#ifdef __cplusplus
extern "C" {
#endif

/* ─── __dso_handle ────────────────────────────────────────────────────────── */
void *__dso_handle = (void *)0;

/* ─── pthreads stubs ──────────────────────────────────────────────────────── */
/* libgcc_eh.a (unwind-dw2-fde.o, emutls.o) and libsupc++.a (eh_alloc.o)
 * reference pthreads.  Stubs suffice in single-threaded freestanding code.
 * For Windows we don't link -lwinpthread (-nodefaultlibs), so these stubs
 * are always needed. */
typedef struct { volatile int _v; char _pad[36]; } _peor_mutex_t;
typedef struct { char _[4]; }                       _peor_mutexattr_t;
typedef volatile int                                _peor_once_t;
typedef unsigned int                                _peor_key_t;

int pthread_mutex_init(_peor_mutex_t *m, const _peor_mutexattr_t *a) {
    (void)a; m->_v = 0; return 0;
}
int pthread_mutex_destroy(_peor_mutex_t *m) { (void)m; return 0; }
int pthread_mutex_lock(_peor_mutex_t *m)    { (void)m; return 0; }
int pthread_mutex_unlock(_peor_mutex_t *m)  { (void)m; return 0; }

int pthread_once(_peor_once_t *once, void (*fn)(void)) {
    if (!*once) { *once = 1; fn(); }
    return 0;
}

/* emutls.o uses TLS keys for emulated thread-local storage */
static unsigned int _peor_next_key = 1;
static void *_peor_tls_slots[64];  /* 64-slot TLS for single-threaded use */

int pthread_key_create(_peor_key_t *key, void (*destructor)(void *)) {
    (void)destructor;
    *key = _peor_next_key++;
    return 0;
}
int pthread_key_delete(_peor_key_t key) { (void)key; return 0; }
void *pthread_getspecific(_peor_key_t key) {
    return (key < 64u) ? _peor_tls_slots[key] : (void *)0;
}
int pthread_setspecific(_peor_key_t key, const void *value) {
    if (key < 64u) _peor_tls_slots[key] = (void *)value;
    return 0;
}

/* ─── _pei386_runtime_relocator stub ─────────────────────────────────────── */
/* MinGW's linker auto-generates ertr stub objects that reference this symbol.
 * peor applies PE relocations via its own asm stub, so a no-op is correct. */
void _pei386_runtime_relocator(void) {}

/* ─── __mingw_vsprintf stub ───────────────────────────────────────────────── */
/* cp-demangle.o (libsupc++.a) needs __mingw_vsprintf for the verbose terminate
 * handler (vterminate.o).  A no-op is sufficient since terminate() in our
 * single-threaded embedded context is already the last resort. */
int __mingw_vsprintf(char *buf, const char *fmt, void *ap) {
    (void)fmt; (void)ap; if (buf) buf[0] = 0; return 0;
}

/* =========================================================================
 * EFI-only section: full CRT stubs (stdlib, string, stdio) + kernel32 IAT
 * no-ops for x64.  Enabled with -DPEOR_EFI.
 * ========================================================================= */
#ifdef PEOR_EFI

/* ─── Bump allocator (malloc / free / calloc / realloc) ──────────────────── */
/* Each allocation is preceded by a header storing the usable size so that
 * realloc() can copy exactly min(old_size, new_size) bytes. */
#define _EH_HEAP_SIZE    65536u
#define _EH_ALLOC_ALIGN  16u
typedef struct { size_t size; } _peor_alloc_hdr;

static char   _eh_heap[_EH_HEAP_SIZE];
static size_t _eh_heap_pos = 0;

void *malloc(size_t n) {
    n = (n + (_EH_ALLOC_ALIGN - 1u)) & ~(size_t)(_EH_ALLOC_ALIGN - 1u);
    size_t need = sizeof(_peor_alloc_hdr) + n;
    if (_eh_heap_pos + need > _EH_HEAP_SIZE) return (void *)0;
    _peor_alloc_hdr *hdr = (_peor_alloc_hdr *)(_eh_heap + _eh_heap_pos);
    hdr->size = n;
    _eh_heap_pos += need;
    return (void *)(hdr + 1);
}

void free(void *p) { (void)p; }

void *calloc(size_t n, size_t size) {
    size_t total = n * size;
    void *p = malloc(total);
    if (p) {
        char *c = (char *)p;
        for (size_t i = 0; i < total; i++) c[i] = 0;
    }
    return p;
}

void *realloc(void *p, size_t n) {
    void *np = malloc(n);
    if (np && p) {
        _peor_alloc_hdr *hdr = ((_peor_alloc_hdr *)p) - 1;
        size_t copy = hdr->size < n ? hdr->size : n;
        char *dst = (char *)np, *src = (char *)p;
        for (size_t i = 0; i < copy; i++) dst[i] = src[i];
    }
    return np;
}

/* ─── Memory ──────────────────────────────────────────────────────────────── */
void *memcpy(void *d, const void *s, size_t n) {
    char *dd = (char *)d; const char *ss = (const char *)s;
    while (n--) *dd++ = *ss++;
    return d;
}

void *memset(void *d, int c, size_t n) {
    unsigned char *p = (unsigned char *)d;
    while (n--) *p++ = (unsigned char)c;
    return d;
}

int memcmp(const void *a, const void *b, size_t n) {
    const unsigned char *aa = (const unsigned char *)a;
    const unsigned char *bb = (const unsigned char *)b;
    while (n--) {
        if (*aa != *bb) return (int)*aa - (int)*bb;
        aa++; bb++;
    }
    return 0;
}

/* ─── String ──────────────────────────────────────────────────────────────── */
size_t strlen(const char *s) {
    const char *p = s; while (*p) p++;
    return (size_t)(p - s);
}

int strcmp(const char *a, const char *b) {
    while (*a && ((unsigned char)*a == (unsigned char)*b)) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

int strncmp(const char *a, const char *b, size_t n) {
    while (n--) {
        if ((unsigned char)*a != (unsigned char)*b)
            return (unsigned char)*a - (unsigned char)*b;
        if (!*a) return 0;
        a++; b++;
    }
    return 0;
}

char *strchr(const char *s, int c) {
    for (; *s; s++) if ((unsigned char)*s == (unsigned char)c) return (char *)s;
    return (c == 0) ? (char *)s : (char *)0;
}

unsigned long strtoul(const char *s, char **end, int base) {
    while (*s == ' ' || *s == '\t') s++;
    if (*s == '+') s++;
    if ((base == 0 || base == 16) && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s += 2; if (!base) base = 16;
    } else if (base == 0) {
        base = (s[0] == '0') ? 8 : 10;
    }
    unsigned long r = 0;
    while (*s) {
        int d;
        if (*s >= '0' && *s <= '9') d = *s - '0';
        else if (*s >= 'a' && *s <= 'z') d = *s - 'a' + 10;
        else if (*s >= 'A' && *s <= 'Z') d = *s - 'A' + 10;
        else break;
        if (d >= base) break;
        r = r * (unsigned long)base + (unsigned long)d;
        s++;
    }
    if (end) *end = (char *)s;
    return r;
}

/* ─── Environment / Process ───────────────────────────────────────────────── */
char *getenv(const char *name) { (void)name; return (char *)0; }
int atexit(void (*fn)(void)) { (void)fn; return 0; }
void abort(void) { while (1) {} }

/* ─── Minimal stdio stubs ─────────────────────────────────────────────────── */
typedef void _PEOR_FILE;

static _PEOR_FILE *_peor_null_iob_fn(unsigned int n) { (void)n; return (_PEOR_FILE *)0; }

/* IAT slot name for __acrt_iob_func differs by arch (COFF underscore rules):
 *   x64: COFF name == C name (no prefix)  → C: __imp___acrt_iob_func
 *   x86: COFF name = "_" + C name         → C: _imp____acrt_iob_func → COFF: __imp____acrt_iob_func */
#ifdef __i386__
_PEOR_FILE *(*_imp____acrt_iob_func)(unsigned int) = _peor_null_iob_fn;
#else
_PEOR_FILE *(*__imp___acrt_iob_func)(unsigned int) = _peor_null_iob_fn;
#endif

size_t fwrite(const void *p, size_t sz, size_t n, _PEOR_FILE *f) { (void)p; (void)sz; (void)n; (void)f; return 0; }
int    fputs(const char *s, _PEOR_FILE *f) { (void)s; (void)f; return -1; }
int    fputc(int c, _PEOR_FILE *f)         { (void)c; (void)f; return -1; }

/* ─── kernel32 IAT no-ops for x64 EFI (unwind-seh.o) ────────────────────── */
#ifdef __x86_64__

typedef unsigned long       DWORD;
typedef unsigned long long  ULONG64;
typedef void               *PVOID;
typedef struct { char _[1232]; } _PEOR_CONTEXT;
typedef struct { DWORD code, flags, nparams; PVOID addr; ULONG64 info[15]; } _PEOR_EXC_RECORD;
typedef struct { char _[56]; } _PEOR_RUNTIME_FUNCTION;
typedef struct { char _[32]; } _PEOR_UH_TABLE;

static void _peor_RaiseException(DWORD c, DWORD f, DWORD n, const ULONG64 *a) {
    (void)c; (void)f; (void)n; (void)a; while (1) {}
}
static _PEOR_RUNTIME_FUNCTION *_peor_RtlLookupFunctionEntry(ULONG64 ip, ULONG64 *base, _PEOR_UH_TABLE *ht) {
    (void)ip; (void)base; (void)ht; return (_PEOR_RUNTIME_FUNCTION *)0;
}
static void _peor_RtlUnwindEx(PVOID tf, PVOID tip, _PEOR_EXC_RECORD *er, PVOID rv, _PEOR_CONTEXT *ctx, _PEOR_UH_TABLE *ht) {
    (void)tf; (void)tip; (void)er; (void)rv; (void)ctx; (void)ht;
}
static void _peor_RtlCaptureContext(_PEOR_CONTEXT *ctx) { (void)ctx; }
static void _peor_RtlVirtualUnwind(DWORD type, ULONG64 base, ULONG64 ip, _PEOR_RUNTIME_FUNCTION *fn, _PEOR_CONTEXT *ctx, PVOID *hd, ULONG64 *fr, PVOID kd) {
    (void)type; (void)base; (void)ip; (void)fn; (void)ctx; (void)hd; (void)fr; (void)kd;
}

/* On x64, C name == COFF name (no leading underscore for PE64) */
void (*__imp_RaiseException)(DWORD, DWORD, DWORD, const ULONG64 *)                                                        = _peor_RaiseException;
_PEOR_RUNTIME_FUNCTION *(*__imp_RtlLookupFunctionEntry)(ULONG64, ULONG64 *, _PEOR_UH_TABLE *)                             = _peor_RtlLookupFunctionEntry;
void (*__imp_RtlUnwindEx)(PVOID, PVOID, _PEOR_EXC_RECORD *, PVOID, _PEOR_CONTEXT *, _PEOR_UH_TABLE *)                    = _peor_RtlUnwindEx;
void (*__imp_RtlCaptureContext)(_PEOR_CONTEXT *)                                                                           = _peor_RtlCaptureContext;
void (*__imp_RtlVirtualUnwind)(DWORD, ULONG64, ULONG64, _PEOR_RUNTIME_FUNCTION *, _PEOR_CONTEXT *, PVOID *, ULONG64 *, PVOID) = _peor_RtlVirtualUnwind;

#endif /* __x86_64__ */
#endif /* PEOR_EFI */

#ifdef __cplusplus
} /* extern "C" */
#endif
