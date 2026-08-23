/* Minimal SJLJ C++ EH runtime for ARM32 EFI (clang armv7-w64-mingw32 -fsjlj-exceptions).
 *
 * Verified against clang 17 compiler output for armv7-w64-mingw32.
 *
 * UFC layout (sp+8 in efi_main, matches clang output):
 *   [+0]  prev              struct UFC*
 *   [+4]  resumption_index  1=in-try, ~0u=inactive, 0=set-by-throw
 *   [+8]  jbuf_exc_ptr      exception object ptr (read at landing pad as r0)
 *   [+12] jbuf_selector     catch selector (read at landing pad as r4)
 *   [+16] jbuf_2            (unused)
 *   [+20] jbuf_3            (unused)
 *   [+24] personality       __gxx_personality_sj0 pointer
 *   [+28] lsda              language-specific data area
 *   [+32] frame_ptr         saved r11
 *   [+36] handler_addr      landing-pad address | Thumb bit
 *   [+40] stack_ptr         saved sp
 *
 * LSDA format (SJLJ, ttype_enc=absptr):
 *   ff  LPStart encoding = omit
 *   00  TType encoding = absptr (4-byte absolute pointers)
 *   uleb128  ttype_base_offset (from .Lttbaseref to .Lttbase)
 *   03  call site encoding (marker; entries use uleb128 pairs)
 *   uleb128  call-site table byte length
 *   [ uleb128 sjlj_index  uleb128 action+1 ] ...
 *   action table: sleb128 type_filter, sleb128 next ...
 *   type table (before .Lttbase): 4-byte absptr per entry, index 1 at base-4, etc.
 */

typedef __UINTPTR_TYPE__ uintptr_t;
typedef __INTPTR_TYPE__  intptr_t;
typedef __SIZE_TYPE__    size_t;

#ifdef __cplusplus
extern "C" {
#endif

/* ─── UFC ─────────────────────────────────────────────────────────────────── */
struct _UFC {
    struct _UFC    *prev;
    unsigned        resumption_index;
    void           *jbuf_exc_ptr;
    unsigned        jbuf_selector;
    unsigned        jbuf_2;
    unsigned        jbuf_3;
    void          (*personality)(void);
    const void     *lsda;
    void           *frame_ptr;
    void           *handler_addr;
    void           *stack_ptr;
};

static struct _UFC *_sjlj_top;

void _Unwind_SjLj_Register(struct _UFC *ctx) {
    ctx->prev = _sjlj_top;
    _sjlj_top = ctx;
}

void _Unwind_SjLj_Unregister(struct _UFC *ctx) {
    _sjlj_top = ctx->prev;
}

/* ─── Exception storage (single active exception, EFI is single-threaded) ── */
#define _EH_OBJ_MAX 64u
static unsigned char _eh_obj[_EH_OBJ_MAX];
static const void   *_g_thrown_type;

void *__cxa_allocate_exception(size_t size) {
    (void)size;
    return (void *)_eh_obj;
}

/* ─── LSDA decode helpers ────────────────────────────────────────────────── */
static const unsigned char *_uleb128(const unsigned char *p, uintptr_t *v) {
    uintptr_t r = 0, s = 0;
    unsigned char b;
    do { b = *p++; r |= (uintptr_t)(b & 0x7fu) << s; s += 7u; } while (b & 0x80u);
    *v = r;
    return p;
}

static const unsigned char *_sleb128(const unsigned char *p, intptr_t *v) {
    uintptr_t r = 0;
    unsigned  s = 0;
    unsigned char b;
    do { b = *p++; r |= (uintptr_t)(b & 0x7fu) << s; s += 7u; } while (b & 0x80u);
    if (s < 8u * sizeof(uintptr_t) && (b & 0x40u))
        r |= ~(uintptr_t)0u << s;
    *v = (intptr_t)r;
    return p;
}

/* ─── Longjmp to landing pad ─────────────────────────────────────────────── */
/* Restores sp and r11 to efi_main's saved values, then branches to the
 * compiler-generated dispatch block (.LBB0_2) with Thumb bit set. */
__attribute__((naked, noreturn))
static void _peor_longjmp(void *new_sp, void *new_r11, void *handler_addr) {
    __asm__(
        "mov sp,  r0\n\t"
        "mov r11, r1\n\t"
        "bx  r2\n\t"
    );
}

/* ─── LSDA walk + install ────────────────────────────────────────────────── */
/* Returns 1 if a handler is found (and jumps there), 0 if not found. */
static int _sjlj_install(struct _UFC *ufc, const void *thrown_ti) {
    /* Mask off Thumb bit: ARM COFF marks data labels in .text as Thumb (bit 0
     * set), including GCC_except_table0.  The LSDA is data, not code. */
    const unsigned char *p =
        (const unsigned char *)((uintptr_t)ufc->lsda & ~(uintptr_t)1u);
    if (!p) return 0;

    /* LPStart encoding: skip (must be 0xff = omit) */
    p++;

    /* TType encoding + base offset */
    unsigned char ttype_enc = *p++;
    uintptr_t ttype_off = 0;
    if (ttype_enc != 0xffu)
        p = _uleb128(p, &ttype_off);
    const unsigned char *ttype_base = p + ttype_off;  /* .Lttbase */

    /* Call site encoding (skip): entries are always (uleb128, uleb128) pairs */
    p++;

    /* Call site table */
    uintptr_t cs_len = 0;
    p = _uleb128(p, &cs_len);
    const unsigned char *cs_end     = p + cs_len;
    const unsigned char *action_base = cs_end;

    /* SJLJ index at throw site = resumption_index - 1 (clang 1-indexed convention) */
    uintptr_t target = (uintptr_t)(ufc->resumption_index - 1u);

    while (p < cs_end) {
        uintptr_t cs_idx = 0, cs_act = 0;
        p = _uleb128(p, &cs_idx);
        p = _uleb128(p, &cs_act);
        if (cs_idx != target) continue;
        if (cs_act == 0u) return 0;  /* cleanup only, no catch */

        /* Walk action chain starting at action_base + (cs_act - 1) */
        const unsigned char *ap = action_base + (cs_act - 1u);
        while (1) {
            intptr_t tf = 0, nx = 0;
            const unsigned char *nxp;
            ap  = _sleb128(ap, &tf);
            nxp = ap;                 /* address of 'next' field */
            ap  = _sleb128(ap, &nx);

            if (tf == 0) {
                /* catch (...): always matches, selector = 1 */
                ufc->jbuf_exc_ptr      = (void *)_eh_obj;
                ufc->jbuf_selector     = 1u;
                ufc->resumption_index  = 0u;
                _peor_longjmp(ufc->stack_ptr, ufc->frame_ptr, ufc->handler_addr);
            } else if (tf > 0) {
                /* Type-specific catch: look up in type table */
                const unsigned char *tte = ttype_base - (uintptr_t)tf * 4u;
                uintptr_t ti_addr = (uintptr_t)tte[0]
                                  | ((uintptr_t)tte[1] << 8u)
                                  | ((uintptr_t)tte[2] << 16u)
                                  | ((uintptr_t)tte[3] << 24u);
                if (ti_addr == 0u || thrown_ti == (const void *)ti_addr) {
                    ufc->jbuf_exc_ptr      = (void *)_eh_obj;
                    ufc->jbuf_selector     = (unsigned)tf;
                    ufc->resumption_index  = 0u;
                    _peor_longjmp(ufc->stack_ptr, ufc->frame_ptr, ufc->handler_addr);
                }
            }

            if (nx == 0) break;
            ap = nxp + nx;  /* jump to next action record */
        }
        break; /* found the right call site; stop */
    }
    return 0;
}

/* ─── __cxa_throw ────────────────────────────────────────────────────────── */
__attribute__((noreturn))
void __cxa_throw(void *thrown_obj, const void *type_info, void (*dtor)(void *)) {
    (void)thrown_obj; (void)dtor;
    _g_thrown_type = type_info;

    struct _UFC *ufc = _sjlj_top;
    while (ufc) {
        /* Skip frames that have no active try block */
        if (ufc->resumption_index != ~0u)
            _sjlj_install(ufc, type_info);
        ufc = ufc->prev;
    }
    while (1) {}  /* no handler found: terminate (no std::terminate available) */
}

/* ─── __cxa_begin_catch / __cxa_end_catch ────────────────────────────────── */
/* At the landing pad, r0 = ufc->jbuf_exc_ptr = _eh_obj = exception object.
 * __cxa_begin_catch returns the same pointer; the code then reads e.code from it. */
void *__cxa_begin_catch(void *exc) {
    return exc;
}

void __cxa_end_catch(void) {
    /* no-op: single-exception bump allocator, nothing to clean up */
}

/* ─── __gxx_personality_sj0 ─────────────────────────────────────────────── */
/* Stub: our __cxa_throw drives unwinding directly via _sjlj_install.
 * This symbol must exist (stored in UFC->personality) but is never called
 * by our runtime. */
int __gxx_personality_sj0(
    int version, int actions, unsigned long long exc_class,
    void *ue_header, struct _UFC *context)
{
    (void)version; (void)actions; (void)exc_class;
    (void)ue_header; (void)context;
    return 8; /* _URC_CONTINUE_UNWIND */
}

/* ─── __class_type_info vtable stub ─────────────────────────────────────── */
/* _ZTI16PeorEfiException points to _ZTVN10__cxxabiv117__class_type_infoE+8.
 * The vtable only needs to exist as a non-null symbol; virtual functions
 * are never called by our type-comparison implementation. */
void *_ZTVN10__cxxabiv117__class_type_infoE[4] = {
    (void *)0, (void *)0, (void *)0, (void *)0
};

#ifdef __cplusplus
} /* extern "C" */
#endif
