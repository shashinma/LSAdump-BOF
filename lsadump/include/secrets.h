/*
 * secrets.h - LSA Secrets-specific definitions for lsadump_secrets BOF
 * by shashinma
 */

#ifndef LSADUMP_SECRETS_H
#define LSADUMP_SECRETS_H

#include "lsadump.h"

// ============================================================================
// LSA Structure Offsets (packed)
// ============================================================================

// PolEKList offsets
#define OFF_VERSION             0
#define OFF_KEYID               4
#define OFF_ALGORITHM           20
#define OFF_FLAG                24
#define OFF_LAZYIV              28
#define OFF_ENCRYPTED           60

// NT6_CLEAR_SECRET offsets
#define OFF_SECRET_SIZE         0
#define OFF_SECRET_DATA         16

// NT6_SYSTEM_KEYS offsets  
#define OFF_KEYS_UNKTYPE0       0
#define OFF_KEYS_CURRENTKEYID   4
#define OFF_KEYS_UNKTYPE1       20
#define OFF_KEYS_NBKEYS         24
#define OFF_KEYS_KEYS           28

// NT6_SYSTEM_KEY offsets
#define OFF_KEY_KEYID           0
#define OFF_KEY_KEYTYPE         16
#define OFF_KEY_KEYSIZE         20
#define OFF_KEY_KEY             24

// ============================================================================
// LSA Keys Info Structure
// ============================================================================

typedef struct _LSA_KEYS_INFO {
    PBYTE keys;
    DWORD nbKeys;
    BYTE currentKeyId[16];
    BYTE currentKey[64];
    DWORD currentKeySize;
} LSA_KEYS_INFO;

#endif // LSADUMP_SECRETS_H
