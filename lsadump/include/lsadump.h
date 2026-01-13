/*
 * lsadump.h - Common definitions for lsadump BOFs
 * by shashinma
 */

#ifndef LSADUMP_H
#define LSADUMP_H

#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"

// ============================================================================
// Common Constants
// ============================================================================

#define SYSKEY_LENGTH           16
#define AES_128_KEY_SIZE        16
#define AES_256_KEY_SIZE        32
#define LAZY_NT6_IV_SIZE        32
#define SHA_DIGEST_LENGTH       20
#define MD4_DIGEST_LENGTH       16
#define LM_NTLM_HASH_LENGTH     16

#define PROV_RSA_AES            24
#define CRYPT_VERIFYCONTEXT     0xF0000000

#define CALG_SHA_256            0x0000800c
#define CALG_SHA1               0x00008004
#define CALG_MD4                0x00008002
#define CALG_AES_256            0x00006610
#define CALG_AES_128            0x0000660e
#define CALG_DES                0x00006601

#define HP_HASHVAL              0x0002
#define KP_MODE                 4
#define KP_IV                   1
#define CRYPT_MODE_ECB          2
#define CRYPT_MODE_CBC          1

#define SIZE_ALIGN(size, alignment) (((size) + (alignment - 1)) & ~(alignment - 1))

// ============================================================================
// Syskey Permutation Table
// ============================================================================

static const BYTE SYSKEY_PERMUT[] = {
    0x0b, 0x06, 0x07, 0x01, 0x08, 0x0a, 0x0e, 0x00,
    0x03, 0x05, 0x02, 0x0f, 0x0d, 0x09, 0x0c, 0x04
};

// ============================================================================
// Common Structures
// ============================================================================

#pragma pack(push, 1)
typedef struct _AES_KEY_BLOB {
    BLOBHEADER header;
    DWORD keySize;
    BYTE key[32];
} AES_KEY_BLOB;

typedef struct _AES128_KEY_BLOB {
    BLOBHEADER header;
    DWORD keySize;
    BYTE key[16];
} AES128_KEY_BLOB;
#pragma pack(pop)

#endif // LSADUMP_H
