/*
 * cache.h - Cache-specific definitions for lsadump_cache BOF
 * by shashinma
 */

#ifndef LSADUMP_CACHE_H
#define LSADUMP_CACHE_H

#include "lsadump.h"

// ============================================================================
// MSCACHE Structures
// ============================================================================

#pragma pack(push, 1)
// MSCACHE_DATA - hash data at the beginning of decrypted enc_data
// Size must be 56 bytes (16+16+24) for correct username offset
typedef struct _MSCACHE_DATA {
    BYTE mshashdata[LM_NTLM_HASH_LENGTH];  // 16: DCC2 hash
    BYTE unkhash[LM_NTLM_HASH_LENGTH];     // 16: unknown hash
    DWORD unk0;                             // 4
    DWORD szSC;                             // 4
    DWORD unkLength;                        // 4
    DWORD unk2;                             // 4
    DWORD unk3;                             // 4
    DWORD unk4;                             // 4
} MSCACHE_DATA, *PMSCACHE_DATA;  // Total: 56 bytes

typedef struct _MSCACHE_ENTRY {
    WORD szUserName;
    WORD szDomainName;
    WORD szEffectiveName;
    WORD szFullName;
    WORD szlogonScript;
    WORD szprofilePath;
    WORD szhomeDirectory;
    WORD szhomeDirectoryDrive;
    DWORD userId;
    DWORD primaryGroupId;
    DWORD groupCount;
    WORD szlogonDomainName;
    WORD unk0;
    FILETIME lastWrite;
    DWORD revision;
    DWORD sidCount;
    DWORD flags;
    DWORD unk1;
    DWORD logonPackage;
    WORD szDnsDomainName;
    WORD szupn;
    BYTE iv[LAZY_NT6_IV_SIZE];
    BYTE cksum[16];
    BYTE enc_data[1];
} MSCACHE_ENTRY, *PMSCACHE_ENTRY;
#pragma pack(pop)

#define FIELD_OFFSET_ENC_DATA (sizeof(MSCACHE_ENTRY) - 1)

#endif // LSADUMP_CACHE_H
