/*
 * mayhem/mspack_mem.h — an in-memory implementation of libmspack's mspack_system.
 *
 * libmspack drives all I/O through a struct mspack_system (open/read/write/seek/...),
 * so a harness can feed the fuzzer's bytes straight into a decompressor WITHOUT touching
 * the filesystem: we treat the "filename" passed to open() as a pointer to a msp_membuf.
 *
 *  - READ  opens wrap the fuzz input buffer (read-only, seekable).
 *  - WRITE opens are a growable, size-capped sink: decompressed output is accepted (so the
 *    full decode path runs) but discarded once it exceeds MSP_MAX_OUT, which caps a
 *    decompression-bomb before it OOMs the fuzzer.
 *
 * Modelled on libmspack's own examples/cabd_memory.c mem-system.
 */
#ifndef MAYHEM_MSPACK_MEM_H
#define MAYHEM_MSPACK_MEM_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <mspack.h>

/* A "filename": a pointer to one of these is what we hand to open(). */
struct msp_membuf {
    const void *data;   /* input bytes (READ opens); NULL for output */
    size_t      length; /* input length (READ); set to produced size on close (WRITE) */
};

struct msp_memfile {
    /* read view */
    const unsigned char *rdata;
    size_t rlen;
    /* write view (growable) */
    unsigned char *wdata;
    size_t wlen, wcap;
    size_t posn;
    int writable;
    struct msp_membuf *spec;
};

/* Cap total decompressed output per open file (guard against decompression bombs). */
#define MSP_MAX_OUT ((size_t)(64u * 1024u * 1024u))

static void *msp_alloc(struct mspack_system *self, size_t bytes) {
    (void)self; return malloc(bytes);
}
static void msp_free(void *buffer) { free(buffer); }
static void msp_copy(void *src, void *dest, size_t bytes) { memcpy(dest, src, bytes); }
static void msp_msg(struct mspack_file *file, const char *fmt, ...) { (void)file; (void)fmt; }

static struct mspack_file *msp_open(struct mspack_system *self,
                                    const char *filename, int mode) {
    struct msp_membuf *spec = (struct msp_membuf *)filename;
    struct msp_memfile *fh;
    if (mode == MSPACK_SYS_OPEN_READ) {
        if (!spec || !spec->data || !spec->length) return NULL;
        fh = (struct msp_memfile *)msp_alloc(self, sizeof(*fh));
        if (!fh) return NULL;
        memset(fh, 0, sizeof(*fh));
        fh->rdata = (const unsigned char *)spec->data;
        fh->rlen  = spec->length;
        fh->spec  = spec;
        return (struct mspack_file *)fh;
    }
    /* WRITE / UPDATE / APPEND: growable sink */
    fh = (struct msp_memfile *)msp_alloc(self, sizeof(*fh));
    if (!fh) return NULL;
    memset(fh, 0, sizeof(*fh));
    fh->writable = 1;
    fh->spec = spec;
    return (struct mspack_file *)fh;
}

static void msp_close(struct mspack_file *file) {
    struct msp_memfile *fh = (struct msp_memfile *)file;
    if (!fh) return;
    if (fh->spec && fh->writable) fh->spec->length = fh->wlen;
    free(fh->wdata);
    free(fh);
}

static int msp_read(struct mspack_file *file, void *buffer, int bytes) {
    struct msp_memfile *fh = (struct msp_memfile *)file;
    const unsigned char *base;
    size_t len, todo;
    if (!fh || !buffer || bytes < 0) return -1;
    base = fh->writable ? fh->wdata : fh->rdata;
    len  = fh->writable ? fh->wlen  : fh->rlen;
    if (fh->posn >= len) return 0;
    todo = len - fh->posn;
    if (todo > (size_t)bytes) todo = (size_t)bytes;
    if (todo && base) memcpy(buffer, base + fh->posn, todo);
    fh->posn += todo;
    return (int)todo;
}

static int msp_write(struct mspack_file *file, void *buffer, int bytes) {
    struct msp_memfile *fh = (struct msp_memfile *)file;
    size_t need, want;
    if (!fh || !fh->writable || !buffer || bytes < 0) return -1;
    want = (size_t)bytes;
    if (fh->posn > MSP_MAX_OUT) return -1;
    if (fh->posn + want > MSP_MAX_OUT) want = MSP_MAX_OUT - fh->posn; /* short write -> WRITE err */
    need = fh->posn + want;
    if (need > fh->wcap) {
        size_t ncap = fh->wcap ? fh->wcap * 2 : 4096;
        unsigned char *nd;
        while (ncap < need) ncap *= 2;
        if (ncap > MSP_MAX_OUT) ncap = MSP_MAX_OUT;
        nd = (unsigned char *)realloc(fh->wdata, ncap);
        if (!nd) return -1;
        fh->wdata = nd; fh->wcap = ncap;
    }
    if (want) memcpy(fh->wdata + fh->posn, buffer, want);
    fh->posn += want;
    if (fh->posn > fh->wlen) fh->wlen = fh->posn;
    return (int)want;
}

static int msp_seek(struct mspack_file *file, off_t offset, int mode) {
    struct msp_memfile *fh = (struct msp_memfile *)file;
    off_t len;
    if (!fh) return 1;
    len = (off_t)(fh->writable ? fh->wlen : fh->rlen);
    switch (mode) {
    case MSPACK_SYS_SEEK_START: break;
    case MSPACK_SYS_SEEK_CUR:   offset += (off_t)fh->posn; break;
    case MSPACK_SYS_SEEK_END:   offset += len; break;
    default: return 1;
    }
    if (offset < 0 || offset > len) return 1;
    fh->posn = (size_t)offset;
    return 0;
}

static off_t msp_tell(struct mspack_file *file) {
    struct msp_memfile *fh = (struct msp_memfile *)file;
    return fh ? (off_t)fh->posn : -1;
}

static struct mspack_system msp_mem_system = {
    &msp_open,
    &msp_close,
    &msp_read,
    &msp_write,
    &msp_seek,
    &msp_tell,
    &msp_msg,
    &msp_alloc,
    &msp_free,
    &msp_copy,
    NULL
};

#endif /* MAYHEM_MSPACK_MEM_H */
