/* Minimal CRT stubs for libsupc++ and libgcc in a freestanding context (EFI: no OS).
 * Provides the minimal set of symbols referenced by libsupc++.a / libgcc_eh.a
 * when linked without -lmsvcrt or any OS CRT.
 *
 * NOTE: Only the EFI compilation uses these stubs.
 * The Linux compilation imports these symbols from libc.so.6 at runtime instead. */
typedef __SIZE_TYPE__ size_t;

size_t strlen(const char *s) {
    const char *p = s;
    while (*p) p++;
    return (size_t)(p - s);
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

void *memcpy(void *d, const void *s, size_t n) {
    char *dd = (char *)d;
    const char *ss = (const char *)s;
    while (n--) *dd++ = *ss++;
    return d;
}

void free(void *p) { (void)p; }

void *malloc(size_t n) { (void)n; return (void *)0; }

int atexit(void (*fn)(void)) { (void)fn; return 0; }

void *__dso_handle = (void *)0;

/* pthread stubs — eh_alloc.o uses these for thread-safe exception allocation */
typedef struct { char _opaque[40]; } _peor_mutex_t;
typedef struct { char _opaque[4]; }  _peor_mutexattr_t;
int pthread_mutex_init(_peor_mutex_t *m, const _peor_mutexattr_t *a) { (void)m; (void)a; return 0; }
int pthread_mutex_destroy(_peor_mutex_t *m) { (void)m; return 0; }
int pthread_mutex_lock(_peor_mutex_t *m) { (void)m; return 0; }
int pthread_mutex_unlock(_peor_mutex_t *m) { (void)m; return 0; }
