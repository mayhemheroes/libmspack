/*
 * mayhem/fuzz_msexpand.c — in-process libFuzzer harness for libmspack's SZDD + KWAJ
 * decompressors (the msszdd_decompressor / mskwaj_decompressor code paths that the
 * original `msexpand` example CLI target exercised — see examples/msexpand.c).
 *
 * The original mayhemheroes integration ran the `msexpand` CLI over a raw file
 * (`msexpand @@ out`). That reads/writes actual files, and its output arg wrote a
 * relative path — which fails under Mayhem's read-only image mount (0 edges). This
 * harness drives the SAME decode paths (SZDD then, on a signature mismatch, KWAJ,
 * exactly like msexpand.c) entirely in memory via an mspack_system backed by the
 * fuzz input, so ASan/UBSan can find memory-safety / UB bugs in the decompressors.
 * The Mayhem target name `msexpand` is preserved for run-history continuity.
 */
#include <stdint.h>
#include <stddef.h>
#include "mspack_mem.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct msp_membuf in  = { data, size };
    struct msp_membuf out = { NULL, 0 };
    struct msszdd_decompressor *szddd;
    struct mskwaj_decompressor *kwajd;

    /* SZDD path (mirrors msexpand.c's first attempt). */
    szddd = mspack_create_szdd_decompressor(&msp_mem_system);
    if (szddd) {
        int err = szddd->decompress(szddd, (const char *)&in, (const char *)&out);
        /* also exercise the header-only open() path */
        if (err == MSPACK_ERR_SIGNATURE) {
            struct msszddd_header *hdr = szddd->open(szddd, (const char *)&in);
            if (hdr) szddd->close(szddd, hdr);
        }
        mspack_destroy_szdd_decompressor(szddd);
    }

    /* KWAJ path (mirrors msexpand.c's fallback). */
    out.data = NULL; out.length = 0;
    kwajd = mspack_create_kwaj_decompressor(&msp_mem_system);
    if (kwajd) {
        struct mskwajd_header *hdr = kwajd->open(kwajd, (const char *)&in);
        if (hdr) {
            struct msp_membuf kout = { NULL, 0 };
            kwajd->extract(kwajd, hdr, (const char *)&kout);
            kwajd->close(kwajd, hdr);
        } else {
            /* still drive the one-shot file->file decompress entry point */
            kwajd->decompress(kwajd, (const char *)&in, (const char *)&out);
        }
        mspack_destroy_kwaj_decompressor(kwajd);
    }

    return 0;
}
