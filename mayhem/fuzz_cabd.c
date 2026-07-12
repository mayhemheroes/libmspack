/*
 * mayhem/fuzz_cabd.c — in-process libFuzzer harness for libmspack's CAB decompressor
 * (mscab_decompressor: the MSCF cabinet parser + MSZIP/LZX/Quantum decoders).
 *
 * This is the richest libmspack format. We open the fuzz input as a cabinet straight
 * from memory (via the mspack_system in mspack_mem.h) and, if it parses, extract every
 * file to an in-memory sink — driving the header parser AND the decompression backends
 * under ASan/UBSan. Modelled on examples/cabd_memory.c.
 */
#include <stdint.h>
#include <stddef.h>
#include "mspack_mem.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct msp_membuf source = { data, size };
    struct mscab_decompressor *cabd;
    struct mscabd_cabinet *cab;
    struct mscabd_file *file;
    unsigned n = 0;

    cabd = mspack_create_cab_decompressor(&msp_mem_system);
    if (!cabd) return 0;

    cab = cabd->open(cabd, (const char *)&source);
    if (cab) {
        for (file = cab->files; file; file = file->next) {
            struct msp_membuf out = { NULL, 0 };
            cabd->extract(cabd, file, (const char *)&out);
            if (++n >= 256) break; /* bound work per input */
        }
        cabd->close(cabd, cab);
    }

    mspack_destroy_cab_decompressor(cabd);
    return 0;
}
