/*
 * sam.h - SAM-specific definitions for lsadump_sam BOF
 * by shashinma
 */

#ifndef LSADUMP_SAM_H
#define LSADUMP_SAM_H

#include "lsadump.h"

// ============================================================================
// DES Parity Table
// ============================================================================

static const BYTE ODD_PARITY[] = {
    1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14,
    16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
    32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
    49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
    64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
    81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
    97, 97, 98, 98, 100, 100, 103, 103, 104, 104, 107, 107, 109, 109, 110, 110,
    112, 112, 115, 115, 117, 117, 118, 118, 121, 121, 122, 122, 124, 124, 127, 127,
    128, 128, 131, 131, 133, 133, 134, 134, 137, 137, 138, 138, 140, 140, 143, 143,
    145, 145, 146, 146, 148, 148, 151, 151, 152, 152, 155, 155, 157, 157, 158, 158,
    161, 161, 162, 162, 164, 164, 167, 167, 168, 168, 171, 171, 173, 173, 174, 174,
    176, 176, 179, 179, 181, 181, 182, 182, 185, 185, 186, 186, 188, 188, 191, 191,
    193, 193, 194, 194, 196, 196, 199, 199, 200, 200, 203, 203, 205, 205, 206, 206,
    208, 208, 211, 211, 213, 213, 214, 214, 217, 217, 218, 218, 220, 220, 223, 223,
    224, 224, 227, 227, 229, 229, 230, 230, 233, 233, 234, 234, 236, 236, 239, 239,
    241, 241, 242, 242, 244, 244, 247, 247, 248, 248, 251, 251, 253, 253, 254, 254
};

// ============================================================================
// SAM Structures
// ============================================================================

#pragma pack(push, 1)
typedef struct _DES_KEY_BLOB {
    BLOBHEADER header;
    DWORD keySize;
    BYTE key[8];
} DES_KEY_BLOB;

typedef struct _OLD_LARGE_INTEGER {
    DWORD LowPart;
    LONG HighPart;
} OLD_LARGE_INTEGER;

typedef struct _SAM_KEY_DATA {
    DWORD Revision;
    DWORD Length;
    BYTE Salt[16];
    BYTE Key[16];
    BYTE CheckSum[16];
    DWORD unk0;
    DWORD unk1;
} SAM_KEY_DATA;

typedef struct _SAM_KEY_DATA_AES {
    DWORD Revision;
    DWORD Length;
    DWORD CheckLen;
    DWORD DataLen;
    BYTE Salt[16];
    BYTE data[32];
} SAM_KEY_DATA_AES;

typedef struct _DOMAIN_ACCOUNT_F {
    WORD Revision;
    WORD unk0;
    DWORD unk1;
    OLD_LARGE_INTEGER CreationTime;
    OLD_LARGE_INTEGER DomainModifiedCount;
    OLD_LARGE_INTEGER MaxPasswordAge;
    OLD_LARGE_INTEGER MinPasswordAge;
    OLD_LARGE_INTEGER ForceLogoff;
    OLD_LARGE_INTEGER LockoutDuration;
    OLD_LARGE_INTEGER LockoutObservationWindow;
    OLD_LARGE_INTEGER ModifiedCountAtLastPromotion;
    DWORD NextRid;
    DWORD PasswordProperties;
    WORD MinPasswordLength;
    WORD PasswordHistoryLength;
    WORD LockoutThreshold;
    WORD unk2;
    DWORD ServerState;
    DWORD ServerRole;
    DWORD UasCompatibilityRequired;
    DWORD unk3;
    SAM_KEY_DATA keys1;
    SAM_KEY_DATA keys2;
    DWORD unk4;
    DWORD unk5;
} DOMAIN_ACCOUNT_F;
#pragma pack(pop)

#endif // LSADUMP_SAM_H
