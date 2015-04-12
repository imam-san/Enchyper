//
//  desmfc.c
//  pin_param
//
//  Created by Imam on 12/30/12.
//  Copyright (c) 2012 Imam. All rights reserved.
//

#include <stdio.h>
#include <string.h>
#include "desmfc.h"

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n,b,i)                    \
{                                               \
(n) = ( (ulong) (b)[(i)    ] << 24 )        \
| ( (ulong) (b)[(i) + 1] << 16 )        \
| ( (ulong) (b)[(i) + 2] <<  8 )        \
| ( (ulong) (b)[(i) + 3]       );       \
}
#endif
#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n,b,i)                    \
{                                               \
(b)[(i)    ] = (byte) ( (n) >> 24 );       \
(b)[(i) + 1] = (byte) ( (n) >> 16 );       \
(b)[(i) + 2] = (byte) ( (n) >>  8 );       \
(b)[(i) + 3] = (byte) ( (n)       );       \
}
#endif

//#define _SELF_TEST_		1

/*
 * Expanded DES S-boxes
 */
ulong SB1[64] =
{
    0x01010400, 0x00000000, 0x00010000, 0x01010404,
    0x01010004, 0x00010404, 0x00000004, 0x00010000,
    0x00000400, 0x01010400, 0x01010404, 0x00000400,
    0x01000404, 0x01010004, 0x01000000, 0x00000004,
    0x00000404, 0x01000400, 0x01000400, 0x00010400,
    0x00010400, 0x01010000, 0x01010000, 0x01000404,
    0x00010004, 0x01000004, 0x01000004, 0x00010004,
    0x00000000, 0x00000404, 0x00010404, 0x01000000,
    0x00010000, 0x01010404, 0x00000004, 0x01010000,
    0x01010400, 0x01000000, 0x01000000, 0x00000400,
    0x01010004, 0x00010000, 0x00010400, 0x01000004,
    0x00000400, 0x00000004, 0x01000404, 0x00010404,
    0x01010404, 0x00010004, 0x01010000, 0x01000404,
    0x01000004, 0x00000404, 0x00010404, 0x01010400,
    0x00000404, 0x01000400, 0x01000400, 0x00000000,
    0x00010004, 0x00010400, 0x00000000, 0x01010004
};

static ulong SB2[64] =
{
    0x80108020, 0x80008000, 0x00008000, 0x00108020,
    0x00100000, 0x00000020, 0x80100020, 0x80008020,
    0x80000020, 0x80108020, 0x80108000, 0x80000000,
    0x80008000, 0x00100000, 0x00000020, 0x80100020,
    0x00108000, 0x00100020, 0x80008020, 0x00000000,
    0x80000000, 0x00008000, 0x00108020, 0x80100000,
    0x00100020, 0x80000020, 0x00000000, 0x00108000,
    0x00008020, 0x80108000, 0x80100000, 0x00008020,
    0x00000000, 0x00108020, 0x80100020, 0x00100000,
    0x80008020, 0x80100000, 0x80108000, 0x00008000,
    0x80100000, 0x80008000, 0x00000020, 0x80108020,
    0x00108020, 0x00000020, 0x00008000, 0x80000000,
    0x00008020, 0x80108000, 0x00100000, 0x80000020,
    0x00100020, 0x80008020, 0x80000020, 0x00100020,
    0x00108000, 0x00000000, 0x80008000, 0x00008020,
    0x80000000, 0x80100020, 0x80108020, 0x00108000
};

static ulong SB3[64] =
{
    0x00000208, 0x08020200, 0x00000000, 0x08020008,
    0x08000200, 0x00000000, 0x00020208, 0x08000200,
    0x00020008, 0x08000008, 0x08000008, 0x00020000,
    0x08020208, 0x00020008, 0x08020000, 0x00000208,
    0x08000000, 0x00000008, 0x08020200, 0x00000200,
    0x00020200, 0x08020000, 0x08020008, 0x00020208,
    0x08000208, 0x00020200, 0x00020000, 0x08000208,
    0x00000008, 0x08020208, 0x00000200, 0x08000000,
    0x08020200, 0x08000000, 0x00020008, 0x00000208,
    0x00020000, 0x08020200, 0x08000200, 0x00000000,
    0x00000200, 0x00020008, 0x08020208, 0x08000200,
    0x08000008, 0x00000200, 0x00000000, 0x08020008,
    0x08000208, 0x00020000, 0x08000000, 0x08020208,
    0x00000008, 0x00020208, 0x00020200, 0x08000008,
    0x08020000, 0x08000208, 0x00000208, 0x08020000,
    0x00020208, 0x00000008, 0x08020008, 0x00020200
};

static ulong SB4[64] =
{
    0x00802001, 0x00002081, 0x00002081, 0x00000080,
    0x00802080, 0x00800081, 0x00800001, 0x00002001,
    0x00000000, 0x00802000, 0x00802000, 0x00802081,
    0x00000081, 0x00000000, 0x00800080, 0x00800001,
    0x00000001, 0x00002000, 0x00800000, 0x00802001,
    0x00000080, 0x00800000, 0x00002001, 0x00002080,
    0x00800081, 0x00000001, 0x00002080, 0x00800080,
    0x00002000, 0x00802080, 0x00802081, 0x00000081,
    0x00800080, 0x00800001, 0x00802000, 0x00802081,
    0x00000081, 0x00000000, 0x00000000, 0x00802000,
    0x00002080, 0x00800080, 0x00800081, 0x00000001,
    0x00802001, 0x00002081, 0x00002081, 0x00000080,
    0x00802081, 0x00000081, 0x00000001, 0x00002000,
    0x00800001, 0x00002001, 0x00802080, 0x00800081,
    0x00002001, 0x00002080, 0x00800000, 0x00802001,
    0x00000080, 0x00800000, 0x00002000, 0x00802080
};

static ulong SB5[64] =
{
    0x00000100, 0x02080100, 0x02080000, 0x42000100,
    0x00080000, 0x00000100, 0x40000000, 0x02080000,
    0x40080100, 0x00080000, 0x02000100, 0x40080100,
    0x42000100, 0x42080000, 0x00080100, 0x40000000,
    0x02000000, 0x40080000, 0x40080000, 0x00000000,
    0x40000100, 0x42080100, 0x42080100, 0x02000100,
    0x42080000, 0x40000100, 0x00000000, 0x42000000,
    0x02080100, 0x02000000, 0x42000000, 0x00080100,
    0x00080000, 0x42000100, 0x00000100, 0x02000000,
    0x40000000, 0x02080000, 0x42000100, 0x40080100,
    0x02000100, 0x40000000, 0x42080000, 0x02080100,
    0x40080100, 0x00000100, 0x02000000, 0x42080000,
    0x42080100, 0x00080100, 0x42000000, 0x42080100,
    0x02080000, 0x00000000, 0x40080000, 0x42000000,
    0x00080100, 0x02000100, 0x40000100, 0x00080000,
    0x00000000, 0x40080000, 0x02080100, 0x40000100
};

static ulong SB6[64] =
{
    0x20000010, 0x20400000, 0x00004000, 0x20404010,
    0x20400000, 0x00000010, 0x20404010, 0x00400000,
    0x20004000, 0x00404010, 0x00400000, 0x20000010,
    0x00400010, 0x20004000, 0x20000000, 0x00004010,
    0x00000000, 0x00400010, 0x20004010, 0x00004000,
    0x00404000, 0x20004010, 0x00000010, 0x20400010,
    0x20400010, 0x00000000, 0x00404010, 0x20404000,
    0x00004010, 0x00404000, 0x20404000, 0x20000000,
    0x20004000, 0x00000010, 0x20400010, 0x00404000,
    0x20404010, 0x00400000, 0x00004010, 0x20000010,
    0x00400000, 0x20004000, 0x20000000, 0x00004010,
    0x20000010, 0x20404010, 0x00404000, 0x20400000,
    0x00404010, 0x20404000, 0x00000000, 0x20400010,
    0x00000010, 0x00004000, 0x20400000, 0x00404010,
    0x00004000, 0x00400010, 0x20004010, 0x00000000,
    0x20404000, 0x20000000, 0x00400010, 0x20004010
};

static ulong SB7[64] =
{
    0x00200000, 0x04200002, 0x04000802, 0x00000000,
    0x00000800, 0x04000802, 0x00200802, 0x04200800,
    0x04200802, 0x00200000, 0x00000000, 0x04000002,
    0x00000002, 0x04000000, 0x04200002, 0x00000802,
    0x04000800, 0x00200802, 0x00200002, 0x04000800,
    0x04000002, 0x04200000, 0x04200800, 0x00200002,
    0x04200000, 0x00000800, 0x00000802, 0x04200802,
    0x00200800, 0x00000002, 0x04000000, 0x00200800,
    0x04000000, 0x00200800, 0x00200000, 0x04000802,
    0x04000802, 0x04200002, 0x04200002, 0x00000002,
    0x00200002, 0x04000000, 0x04000800, 0x00200000,
    0x04200800, 0x00000802, 0x00200802, 0x04200800,
    0x00000802, 0x04000002, 0x04200802, 0x04200000,
    0x00200800, 0x00000000, 0x00000002, 0x04200802,
    0x00000000, 0x00200802, 0x04200000, 0x00000800,
    0x04000002, 0x04000800, 0x00000800, 0x00200002
};

static ulong SB8[64] =
{
    0x10001040, 0x00001000, 0x00040000, 0x10041040,
    0x10000000, 0x10001040, 0x00000040, 0x10000000,
    0x00040040, 0x10040000, 0x10041040, 0x00041000,
    0x10041000, 0x00041040, 0x00001000, 0x00000040,
    0x10040000, 0x10000040, 0x10001000, 0x00001040,
    0x00041000, 0x00040040, 0x10040040, 0x10041000,
    0x00001040, 0x00000000, 0x00000000, 0x10040040,
    0x10000040, 0x10001000, 0x00041040, 0x00040000,
    0x00041040, 0x00040000, 0x10041000, 0x00001000,
    0x00000040, 0x10040040, 0x00001000, 0x00041040,
    0x10001000, 0x00000040, 0x10000040, 0x10040000,
    0x10040040, 0x10000000, 0x00040000, 0x10001040,
    0x00000000, 0x10041040, 0x00040040, 0x10000040,
    0x10040000, 0x10001000, 0x10001040, 0x00000000,
    0x10041040, 0x00041000, 0x00041000, 0x00001040,
    0x00001040, 0x00040040, 0x10000000, 0x10041000
};

/*
 * PC1: left and right halves bit-swap
 */
static ulong LHs[16] =
{
    0x00000000, 0x00000001, 0x00000100, 0x00000101,
    0x00010000, 0x00010001, 0x00010100, 0x00010101,
    0x01000000, 0x01000001, 0x01000100, 0x01000101,
    0x01010000, 0x01010001, 0x01010100, 0x01010101
};

static ulong RHs[16] =
{
    0x00000000, 0x01000000, 0x00010000, 0x01010000,
    0x00000100, 0x01000100, 0x00010100, 0x01010100,
    0x00000001, 0x01000001, 0x00010001, 0x01010001,
    0x00000101, 0x01000101, 0x00010101, 0x01010101,
};

/*
 * Initial Permutation macro
 */
#define DES_IP(X,Y)                                             \
{                                                               \
T = ((X >>  4) ^ Y) & 0x0F0F0F0F; Y ^= T; X ^= (T <<  4);   \
T = ((X >> 16) ^ Y) & 0x0000FFFF; Y ^= T; X ^= (T << 16);   \
T = ((Y >>  2) ^ X) & 0x33333333; X ^= T; Y ^= (T <<  2);   \
T = ((Y >>  8) ^ X) & 0x00FF00FF; X ^= T; Y ^= (T <<  8);   \
Y = ((Y << 1) | (Y >> 31)) & 0xFFFFFFFF;                    \
T = (X ^ Y) & 0xAAAAAAAA; Y ^= T; X ^= T;                   \
X = ((X << 1) | (X >> 31)) & 0xFFFFFFFF;                    \
}

/*
 * Final Permutation macro
 */
#define DES_FP(X,Y)                                             \
{                                                               \
X = ((X << 31) | (X >> 1)) & 0xFFFFFFFF;                    \
T = (X ^ Y) & 0xAAAAAAAA; X ^= T; Y ^= T;                   \
Y = ((Y << 31) | (Y >> 1)) & 0xFFFFFFFF;                    \
T = ((Y >>  8) ^ X) & 0x00FF00FF; X ^= T; Y ^= (T <<  8);   \
T = ((Y >>  2) ^ X) & 0x33333333; X ^= T; Y ^= (T <<  2);   \
T = ((X >> 16) ^ Y) & 0x0000FFFF; Y ^= T; X ^= (T << 16);   \
T = ((X >>  4) ^ Y) & 0x0F0F0F0F; Y ^= T; X ^= (T <<  4);   \
}

/*
 * DES round macro
 */
#define DES_ROUND(X,Y)                          \
{                                               \
T = *SK++ ^ X;                              \
Y ^= SB8[ (T      ) & 0x3F ] ^              \
SB6[ (T >>  8) & 0x3F ] ^              \
SB4[ (T >> 16) & 0x3F ] ^              \
SB2[ (T >> 24) & 0x3F ];               \
\
T = *SK++ ^ ((X << 28) | (X >> 4));         \
Y ^= SB7[ (T      ) & 0x3F ] ^              \
SB5[ (T >>  8) & 0x3F ] ^              \
SB3[ (T >> 16) & 0x3F ] ^              \
SB1[ (T >> 24) & 0x3F ];               \
}

void des_main_ks( ulong SK[32], uchar key[8] )
{
    int i;
    ulong X, Y, T;
    
    GET_UINT32_BE( X, key, 0 );
    GET_UINT32_BE( Y, key, 4 );
    
    /*
     * Permuted Choice 1
     */
    T =  ((Y >>  4) ^ X) & 0x0F0F0F0F;  X ^= T; Y ^= (T <<  4);
    T =  ((Y      ) ^ X) & 0x10101010;  X ^= T; Y ^= (T      );
    
    X =   (LHs[ (X      ) & 0xF] << 3) | (LHs[ (X >>  8) & 0xF ] << 2)
    | (LHs[ (X >> 16) & 0xF] << 1) | (LHs[ (X >> 24) & 0xF ]     )
    | (LHs[ (X >>  5) & 0xF] << 7) | (LHs[ (X >> 13) & 0xF ] << 6)
    | (LHs[ (X >> 21) & 0xF] << 5) | (LHs[ (X >> 29) & 0xF ] << 4);
    
    Y =   (RHs[ (Y >>  1) & 0xF] << 3) | (RHs[ (Y >>  9) & 0xF ] << 2)
    | (RHs[ (Y >> 17) & 0xF] << 1) | (RHs[ (Y >> 25) & 0xF ]     )
    | (RHs[ (Y >>  4) & 0xF] << 7) | (RHs[ (Y >> 12) & 0xF ] << 6)
    | (RHs[ (Y >> 20) & 0xF] << 5) | (RHs[ (Y >> 28) & 0xF ] << 4);
    
    X &= 0x0FFFFFFF;
    Y &= 0x0FFFFFFF;
    
    /*
     * calculate subkeys
     */
    for( i = 0; i < 16; i++ )
    {
        if( i < 2 || i == 8 || i == 15 )
        {
            X = ((X <<  1) | (X >> 27)) & 0x0FFFFFFF;
            Y = ((Y <<  1) | (Y >> 27)) & 0x0FFFFFFF;
        }
        else
        {
            X = ((X <<  2) | (X >> 26)) & 0x0FFFFFFF;
            Y = ((Y <<  2) | (Y >> 26)) & 0x0FFFFFFF;
        }
        
        *SK++ =   ((X <<  4) & 0x24000000) | ((X << 28) & 0x10000000)
        | ((X << 14) & 0x08000000) | ((X << 18) & 0x02080000)
        | ((X <<  6) & 0x01000000) | ((X <<  9) & 0x00200000)
        | ((X >>  1) & 0x00100000) | ((X << 10) & 0x00040000)
        | ((X <<  2) & 0x00020000) | ((X >> 10) & 0x00010000)
        | ((Y >> 13) & 0x00002000) | ((Y >>  4) & 0x00001000)
        | ((Y <<  6) & 0x00000800) | ((Y >>  1) & 0x00000400)
        | ((Y >> 14) & 0x00000200) | ((Y      ) & 0x00000100)
        | ((Y >>  5) & 0x00000020) | ((Y >> 10) & 0x00000010)
        | ((Y >>  3) & 0x00000008) | ((Y >> 18) & 0x00000004)
        | ((Y >> 26) & 0x00000002) | ((Y >> 24) & 0x00000001);
        
        *SK++ =   ((X << 15) & 0x20000000) | ((X << 17) & 0x10000000)
        | ((X << 10) & 0x08000000) | ((X << 22) & 0x04000000)
        | ((X >>  2) & 0x02000000) | ((X <<  1) & 0x01000000)
        | ((X << 16) & 0x00200000) | ((X << 11) & 0x00100000)
        | ((X <<  3) & 0x00080000) | ((X >>  6) & 0x00040000)
        | ((X << 15) & 0x00020000) | ((X >>  4) & 0x00010000)
        | ((Y >>  2) & 0x00002000) | ((Y <<  8) & 0x00001000)
        | ((Y >> 14) & 0x00000808) | ((Y >>  9) & 0x00000400)
        | ((Y      ) & 0x00000200) | ((Y <<  7) & 0x00000100)
        | ((Y >>  7) & 0x00000020) | ((Y >>  3) & 0x00000011)
        | ((Y <<  2) & 0x00000004) | ((Y >> 21) & 0x00000002);
    }
}

void Encrypt_DES(int mode, byte *key, byte *data)
{
	des3_context ctx3;
	des_context ctx;
	byte temp[10];
	
	memset(&ctx, 0x00, sizeof(des_context));
	memset(&ctx3, 0x00, sizeof (des3_context));
	memset(temp, 0x00, sizeof temp);
    
	memcpy(temp, data, 8);
	switch(mode)
	{
		case 0:
			des_set_key(&ctx, key);
			des_encrypt(&ctx, temp, data);
			return;
		case 1:
			des3_set_2keys(&ctx3, key);
		case 2:
			des3_set_3keys(&ctx3, key);
			break;
	}
	des3_encrypt(&ctx3, temp, data);
	return;
}

void Decrypt_DES(int mode, byte *key, byte *data)
{
	des3_context ctx3;
	des_context ctx;
	byte temp[10];
	
	memset(&ctx, 0x00, sizeof(des_context));
	memset(&ctx3, 0x00, sizeof (des3_context));
	memset(temp, 0x00, sizeof temp);
    
	memcpy(temp, data, 8);
	switch(mode)
	{
		case 0:
			des_set_key(&ctx, key);
			des_decrypt(&ctx, temp, data);
			return;
		case 1:
			des3_set_2keys(&ctx3, key);
			break;
		case 2:
			des3_set_3keys(&ctx3, key);
			break;
	}
	des3_decrypt(&ctx3, temp, data);
	return;
}
/*
 * DES key schedule
 */
void des_set_key( des_context *ctx, uchar key[8] )
{
    int i;
    
    des_main_ks( ctx->esk, key );
    
    for( i = 0; i < 32; i += 2 )
    {
        ctx->dsk[i    ] = ctx->esk[30 - i];
        ctx->dsk[i + 1] = ctx->esk[31 - i];
    }
}

void des_crypt( ulong SK[32], uchar input[8], uchar output[8] )
{
    ulong X, Y, T;
    
    GET_UINT32_BE( X, input, 0 );
    GET_UINT32_BE( Y, input, 4 );
    
    DES_IP( X, Y );
    
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    
    DES_FP( Y, X );
    
    PUT_UINT32_BE( Y, output, 0 );
    PUT_UINT32_BE( X, output, 4 );
}

/*
 * DES 64-bit block encryption (ECB)
 */
void des_encrypt( des_context *ctx, uchar input[8], uchar output[8] )
{
    des_crypt( ctx->esk, input, output );
}

/*
 * DES 64-bit block decryption (ECB)
 */
void des_decrypt( des_context *ctx, uchar input[8], uchar output[8] )
{
    des_crypt( ctx->dsk, input, output );
}

/*
 * DES-CBC encryption
 */
void des_cbc_encrypt( des_context *ctx, uchar iv[8],
                     uchar *input, uchar *output, unsigned int len )
{
    int i, n = len;
    
    while( n > 0 )
    {
        for( i = 0; i < 8; i++ )
            output[i] = input[i] ^ iv[i];
        
        des_crypt( ctx->esk, output, output );
        memcpy( iv, output, 8 );
        
        input  += 8;
        output += 8;
        len    -= 8;
    }
}

/*
 * DES-CBC decryption
 */
void des_cbc_decrypt( des_context *ctx, uchar iv[8],
                     uchar *input, uchar *output, unsigned int len )
{
    int i, n = len;
    uchar temp[8];
    
    while( n > 0 )
    {
        memcpy( temp, input, 8 );
        des_crypt( ctx->dsk, input, output );
        
        for( i = 0; i < 8; i++ )
            output[i] = output[i] ^ iv[i];
        
        memcpy( iv, temp, 8 );
        
        input  += 8;
        output += 8;
        len    -= 8;
    }
}

/*
 * Triple-DES key schedule (112-bit)
 */
void des3_set_2keys( des3_context *ctx, uchar key[16] )
{
    int i;
    
    des_main_ks( ctx->esk     , key     );
    des_main_ks( ctx->dsk + 32, key + 8 );
    
    for( i = 0; i < 32; i += 2 )
    {
        ctx->dsk[i     ] = ctx->esk[30 - i];
        ctx->dsk[i +  1] = ctx->esk[31 - i];
        
        ctx->esk[i + 32] = ctx->dsk[62 - i];
        ctx->esk[i + 33] = ctx->dsk[63 - i];
        
        ctx->esk[i + 64] = ctx->esk[     i];
        ctx->esk[i + 65] = ctx->esk[ 1 + i];
        
        ctx->dsk[i + 64] = ctx->dsk[     i];
        ctx->dsk[i + 65] = ctx->dsk[ 1 + i];
    }
}

/*
 * Triple-DES key schedule (168-bit)
 */
void des3_set_3keys( des3_context *ctx, uchar key[24] )
{
    int i;
    
    des_main_ks( ctx->esk     , key      );
    des_main_ks( ctx->dsk + 32, key +  8 );
    des_main_ks( ctx->esk + 64, key + 16 );
    
    for( i = 0; i < 32; i += 2 )
    {
        ctx->dsk[i     ] = ctx->esk[94 - i];
        ctx->dsk[i +  1] = ctx->esk[95 - i];
        
        ctx->esk[i + 32] = ctx->dsk[62 - i];
        ctx->esk[i + 33] = ctx->dsk[63 - i];
        
        ctx->dsk[i + 64] = ctx->esk[30 - i];
        ctx->dsk[i + 65] = ctx->esk[31 - i];
    }
}

void des3_crypt( ulong SK[96], uchar input[8], uchar output[8] )
{
    ulong X, Y, T;
    
    GET_UINT32_BE( X, input, 0 );
    GET_UINT32_BE( Y, input, 4 );
    
    DES_IP( X, Y );
    
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    
    DES_ROUND( X, Y );  DES_ROUND( Y, X );
    DES_ROUND( X, Y );  DES_ROUND( Y, X );
    DES_ROUND( X, Y );  DES_ROUND( Y, X );
    DES_ROUND( X, Y );  DES_ROUND( Y, X );
    DES_ROUND( X, Y );  DES_ROUND( Y, X );
    DES_ROUND( X, Y );  DES_ROUND( Y, X );
    DES_ROUND( X, Y );  DES_ROUND( Y, X );
    DES_ROUND( X, Y );  DES_ROUND( Y, X );
    
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    DES_ROUND( Y, X );  DES_ROUND( X, Y );
    
    DES_FP( Y, X );
    
    PUT_UINT32_BE( Y, output, 0 );
    PUT_UINT32_BE( X, output, 4 );
}


void des3_encrypt( des3_context *ctx, uchar input[8], uchar output[8] )
{
	des3_crypt( ctx->esk, input, output );
}

/*
 * Triple-DES 64-bit block decryption (ECB)
 */
void des3_decrypt( des3_context *ctx, uchar input[8], uchar output[8] )
{
	des3_crypt( ctx->dsk, input, output );
}

/*
 * 3DES-CBC encryption
 */
void des3_cbc_encrypt( des3_context *ctx, uchar iv[8],
                      uchar *input, uchar *output, unsigned int len )
{
    int i, n = len;
    while( n > 0 )
    {
        for( i = 0; i < 8; i++ )
            output[i] = input[i] ^ iv[i];
        
        des3_crypt( ctx->esk, output, output );
        memcpy( iv, output, 8 );
        
        input  += 8;
        output += 8;
        n -= 8;
    }
}

/*
 * 3DES-CBC decryption
 */
void des3_cbc_decrypt( des3_context *ctx, uchar iv[8],
                      uchar *input, uchar *output, unsigned int len )
{
    uchar temp[8];
    int i, n = len;
    while( n > 0 )
    {
        memcpy( temp, input, 8 );
        des3_crypt( ctx->dsk, input, output );
        
        for( i = 0; i < 8; i++ )
            output[i] = output[i] ^ iv[i];
        
        memcpy( iv, temp, 8 );
        
        input  += 8;
        output += 8;
        n -= 8;
    }
}


#if 1
//def TLE_MANDIRI
/*
 * 3DES-MAC encryption
 */

void setkey(unsigned long k[][2], unsigned char *key, int decrypt)
{
	unsigned char pc1[] = {
		57, 49, 41, 33, 25, 17,  9, 1,  58, 50, 42, 34, 26, 18,
		10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
		63, 55, 47, 39, 31, 23, 15, 7,  62, 54, 46, 38, 30, 22,
		14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4
	};
	unsigned char totrot[] = {
		1,2,4,6,8,10,12,14,15,17,19,21,23,25,27,28
	};
	unsigned char pc2[] = {
		14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
		23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
		41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
		44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
	};
	int bytebit[] = {
		0200,0100,040,020,010,04,02,01
	};
    
	unsigned char pc1m[56];
	unsigned char pcr[56];
	register int i,j,l;
	int m;
	unsigned char ks[8];
    
	for (j=0; j<56; j++)
	{
		l=pc1[j]-1;
		m = l & 07;
		pc1m[j]=(key[l>>3] & bytebit[m]) ? 1 : 0;
	}
	for (i=0; i<16; i++)
	{
		memset(ks,0,sizeof(ks));
		for (j=0; j<56; j++)
			pcr[j] = pc1m[(l=j+totrot[decrypt? 15-i : i])<(j<28? 28 : 56) ? l: l-28];
		for (j=0; j<48; j++){
			if (pcr[pc2[j]-1]){
				l= j % 6;
				ks[j/6] |= bytebit[l] >> 2;
			}
		}
		k[i][0] = ((long)ks[0] << 24)
        | ((long)ks[2] << 16)
        | ((long)ks[4] << 8)
        | ((long)ks[6]);
		k[i][1] = ((long)ks[1] << 24)
        | ((long)ks[3] << 16)
        | ((long)ks[5] << 8)
        | ((long)ks[7]);
	}
}

#define	F(l,r,key1,key2){\
work = ((r >> 4) | (r << 28)) ^ key1;	\
l ^= Spbox[6][work & 0x3f];		\
l ^= Spbox[4][(work >> 8) & 0x3f];	\
l ^= Spbox[2][(work >> 16) & 0x3f];	\
l ^= Spbox[0][(work >> 24) & 0x3f];	\
work = r ^ key2;			\
l ^= Spbox[7][work & 0x3f];		\
l ^= Spbox[5][(work >> 8) & 0x3f];	\
l ^= Spbox[3][(work >> 16) & 0x3f];	\
l ^= Spbox[1][(work >> 24) & 0x3f];	\
}


void encrypt(unsigned long ks[16][2], unsigned char block[8])
{
	unsigned long left, right, work;
    
	unsigned long Spbox[8][64] = {
        0x01010400,0x00000000,0x00010000,0x01010404, 0x01010004,0x00010404,0x00000004,0x00010000,
        0x00000400,0x01010400,0x01010404,0x00000400, 0x01000404,0x01010004,0x01000000,0x00000004,
        0x00000404,0x01000400,0x01000400,0x00010400, 0x00010400,0x01010000,0x01010000,0x01000404,
        0x00010004,0x01000004,0x01000004,0x00010004, 0x00000000,0x00000404,0x00010404,0x01000000,
        0x00010000,0x01010404,0x00000004,0x01010000, 0x01010400,0x01000000,0x01000000,0x00000400,
        0x01010004,0x00010000,0x00010400,0x01000004, 0x00000400,0x00000004,0x01000404,0x00010404,
        0x01010404,0x00010004,0x01010000,0x01000404, 0x01000004,0x00000404,0x00010404,0x01010400,
        0x00000404,0x01000400,0x01000400,0x00000000, 0x00010004,0x00010400,0x00000000,0x01010004,
        0x80108020,0x80008000,0x00008000,0x00108020, 0x00100000,0x00000020,0x80100020,0x80008020,
        0x80000020,0x80108020,0x80108000,0x80000000, 0x80008000,0x00100000,0x00000020,0x80100020,
        0x00108000,0x00100020,0x80008020,0x00000000, 0x80000000,0x00008000,0x00108020,0x80100000,
        0x00100020,0x80000020,0x00000000,0x00108000, 0x00008020,0x80108000,0x80100000,0x00008020,
        0x00000000,0x00108020,0x80100020,0x00100000, 0x80008020,0x80100000,0x80108000,0x00008000,
        0x80100000,0x80008000,0x00000020,0x80108020, 0x00108020,0x00000020,0x00008000,0x80000000,
        0x00008020,0x80108000,0x00100000,0x80000020, 0x00100020,0x80008020,0x80000020,0x00100020,
        0x00108000,0x00000000,0x80008000,0x00008020, 0x80000000,0x80100020,0x80108020,0x00108000,
        0x00000208,0x08020200,0x00000000,0x08020008, 0x08000200,0x00000000,0x00020208,0x08000200,
        0x00020008,0x08000008,0x08000008,0x00020000, 0x08020208,0x00020008,0x08020000,0x00000208,
        0x08000000,0x00000008,0x08020200,0x00000200, 0x00020200,0x08020000,0x08020008,0x00020208,
        0x08000208,0x00020200,0x00020000,0x08000208, 0x00000008,0x08020208,0x00000200,0x08000000,
        0x08020200,0x08000000,0x00020008,0x00000208, 0x00020000,0x08020200,0x08000200,0x00000000,
        0x00000200,0x00020008,0x08020208,0x08000200, 0x08000008,0x00000200,0x00000000,0x08020008,
        0x08000208,0x00020000,0x08000000,0x08020208, 0x00000008,0x00020208,0x00020200,0x08000008,
        0x08020000,0x08000208,0x00000208,0x08020000, 0x00020208,0x00000008,0x08020008,0x00020200,
        0x00802001,0x00002081,0x00002081,0x00000080, 0x00802080,0x00800081,0x00800001,0x00002001,
        0x00000000,0x00802000,0x00802000,0x00802081, 0x00000081,0x00000000,0x00800080,0x00800001,
        0x00000001,0x00002000,0x00800000,0x00802001, 0x00000080,0x00800000,0x00002001,0x00002080,
        0x00800081,0x00000001,0x00002080,0x00800080, 0x00002000,0x00802080,0x00802081,0x00000081,
        0x00800080,0x00800001,0x00802000,0x00802081, 0x00000081,0x00000000,0x00000000,0x00802000,
        0x00002080,0x00800080,0x00800081,0x00000001, 0x00802001,0x00002081,0x00002081,0x00000080,
        0x00802081,0x00000081,0x00000001,0x00002000, 0x00800001,0x00002001,0x00802080,0x00800081,
        0x00002001,0x00002080,0x00800000,0x00802001, 0x00000080,0x00800000,0x00002000,0x00802080,
        0x00000100,0x02080100,0x02080000,0x42000100, 0x00080000,0x00000100,0x40000000,0x02080000,
        0x40080100,0x00080000,0x02000100,0x40080100, 0x42000100,0x42080000,0x00080100,0x40000000,
        0x02000000,0x40080000,0x40080000,0x00000000, 0x40000100,0x42080100,0x42080100,0x02000100,
        0x42080000,0x40000100,0x00000000,0x42000000, 0x02080100,0x02000000,0x42000000,0x00080100,
        0x00080000,0x42000100,0x00000100,0x02000000, 0x40000000,0x02080000,0x42000100,0x40080100,
        0x02000100,0x40000000,0x42080000,0x02080100, 0x40080100,0x00000100,0x02000000,0x42080000,
        0x42080100,0x00080100,0x42000000,0x42080100, 0x02080000,0x00000000,0x40080000,0x42000000,
        0x00080100,0x02000100,0x40000100,0x00080000, 0x00000000,0x40080000,0x02080100,0x40000100,
        0x20000010,0x20400000,0x00004000,0x20404010, 0x20400000,0x00000010,0x20404010,0x00400000,
        0x20004000,0x00404010,0x00400000,0x20000010, 0x00400010,0x20004000,0x20000000,0x00004010,
        0x00000000,0x00400010,0x20004010,0x00004000, 0x00404000,0x20004010,0x00000010,0x20400010,
        0x20400010,0x00000000,0x00404010,0x20404000, 0x00004010,0x00404000,0x20404000,0x20000000,
        0x20004000,0x00000010,0x20400010,0x00404000, 0x20404010,0x00400000,0x00004010,0x20000010,
        0x00400000,0x20004000,0x20000000,0x00004010, 0x20000010,0x20404010,0x00404000,0x20400000,
        0x00404010,0x20404000,0x00000000,0x20400010, 0x00000010,0x00004000,0x20400000,0x00404010,
        0x00004000,0x00400010,0x20004010,0x00000000, 0x20404000,0x20000000,0x00400010,0x20004010,
        0x00200000,0x04200002,0x04000802,0x00000000, 0x00000800,0x04000802,0x00200802,0x04200800,
        0x04200802,0x00200000,0x00000000,0x04000002, 0x00000002,0x04000000,0x04200002,0x00000802,
        0x04000800,0x00200802,0x00200002,0x04000800, 0x04000002,0x04200000,0x04200800,0x00200002,
        0x04200000,0x00000800,0x00000802,0x04200802, 0x00200800,0x00000002,0x04000000,0x00200800,
        0x04000000,0x00200800,0x00200000,0x04000802, 0x04000802,0x04200002,0x04200002,0x00000002,
        0x00200002,0x04000000,0x04000800,0x00200000, 0x04200800,0x00000802,0x00200802,0x04200800,
        0x00000802,0x04000002,0x04200802,0x04200000, 0x00200800,0x00000000,0x00000002,0x04200802,
        0x00000000,0x00200802,0x04200000,0x00000800, 0x04000002,0x04000800,0x00000800,0x00200002,
        0x10001040,0x00001000,0x00040000,0x10041040, 0x10000000,0x10001040,0x00000040,0x10000000,
        0x00040040,0x10040000,0x10041040,0x00041000, 0x10041000,0x00041040,0x00001000,0x00000040,
        0x10040000,0x10000040,0x10001000,0x00001040, 0x00041000,0x00040040,0x10040040,0x10041000,
        0x00001040,0x00000000,0x00000000,0x10040040, 0x10000040,0x10001000,0x00041040,0x00040000,
        0x00041040,0x00040000,0x10041000,0x00001000, 0x00000040,0x10040040,0x00001000,0x00041040,
        0x10001000,0x00000040,0x10000040,0x10040000, 0x10040040,0x10000000,0x00040000,0x10001040,
        0x00000000,0x10041040,0x00040040,0x10000040, 0x10040000,0x10001000,0x10001040,0x00000000,
        0x10041040,0x00041000,0x00041000,0x00001040, 0x00001040,0x00040040,0x10000000,0x10041000,
    };
    
	left = ((unsigned long)block[0] << 24)
    | ((unsigned long)block[1] << 16)
    | ((unsigned long)block[2] << 8)
    | (unsigned long)block[3];
	right = ((unsigned long)block[4] << 24)
    | ((unsigned long)block[5] << 16)
    | ((unsigned long)block[6] << 8)
    | (unsigned long)block[7];
    
	work = ((left >> 4) ^ right) & 0x0f0f0f0f;
	right ^= work;
	left ^= work << 4;
	work = ((left >> 16) ^ right) & 0xffff;
	right ^= work;
	left ^= work << 16;
	work = ((right >> 2) ^ left) & 0x33333333;
	left ^= work;
	right ^= (work << 2);
	work = ((right >> 8) ^ left) & 0xff00ff;
	left ^= work;
	right ^= (work << 8);
	right = (right << 1) | (right >> 31);
	work = (left ^ right) & 0xaaaaaaaa;
	left ^= work;
	right ^= work;
	left = (left << 1) | (left >> 31);
    
	F(left,right,ks[0][0],ks[0][1]);
	F(right,left,ks[1][0],ks[1][1]);
	F(left,right,ks[2][0],ks[2][1]);
	F(right,left,ks[3][0],ks[3][1]);
	F(left,right,ks[4][0],ks[4][1]);
	F(right,left,ks[5][0],ks[5][1]);
	F(left,right,ks[6][0],ks[6][1]);
	F(right,left,ks[7][0],ks[7][1]);
	F(left,right,ks[8][0],ks[8][1]);
	F(right,left,ks[9][0],ks[9][1]);
	F(left,right,ks[10][0],ks[10][1]);
	F(right,left,ks[11][0],ks[11][1]);
	F(left,right,ks[12][0],ks[12][1]);
	F(right,left,ks[13][0],ks[13][1]);
	F(left,right,ks[14][0],ks[14][1]);
	F(right,left,ks[15][0],ks[15][1]);
    
	right = (right << 31) | (right >> 1);
	work = (left ^ right) & 0xaaaaaaaa;
	left ^= work;
	right ^= work;
	left = (left >> 1) | (left  << 31);
	work = ((left >> 8) ^ right) & 0xff00ff;
	right ^= work;
	left ^= work << 8;
	work = ((left >> 2) ^ right) & 0x33333333;
	right ^= work;
	left ^= work << 2;
	work = ((right >> 16) ^ left) & 0xffff;
	left ^= work;
	right ^= work << 16;
	work = ((right >> 4) ^ left) & 0x0f0f0f0f;
	left ^= work;
	right ^= work << 4;
	block[0] = (unsigned char)(right >> 24);
	block[1] = (unsigned char)(right >> 16);
	block[2] = (unsigned char)(right >> 8);
	block[3] = (unsigned char)(right);
	block[4] = (unsigned char)(left >> 24);
	block[5] = (unsigned char)(left >> 16);
	block[6] = (unsigned char)(left >> 8);
	block[7] = (unsigned char)(left);
}

void des3_mac_encrypt( des3_context *ctx, uchar iv[8], uchar *input, uchar *output, unsigned int len )
{
    int i;
    
    while( len >= 8 )
    {
        for( i = 0; i < 8; i++ ) {
            output[i] = input[i] ^ iv[i];
		}
        
        des3_crypt( ctx->esk, output, output );
        
        memcpy( iv, output, 8 );
        
        input  += 8;
        len    -= 8;
    }
}

//yd: created
int inDES_CBC_Encrypt(unsigned char *cInputBuffer,int inSize,
                      unsigned char *sessionKEY, unsigned char * uchOut3DESe )
{
	des_context ctx;
	uchar iv[8];
    
	memset(iv,0,8);
    
	des_set_key( &ctx, sessionKEY );
	des_cbc_encrypt( &ctx, iv, cInputBuffer, uchOut3DESe, inSize);
    
	return(0);
}

//yd: created
int inDES_CBC_Decrypt(unsigned char *cInputBuffer,int inSize,
                      unsigned char *sessionKEY, unsigned char * uchOut3DESd )
{
	des_context ctx;
	uchar iv[8];
    
	memset(iv,0x00,8);
	des_set_key( &ctx, sessionKEY );
	des_cbc_decrypt( &ctx, iv, cInputBuffer, uchOut3DESd, inSize );
    
	return(0);
}

int in3DES_CBC_Encrypt(unsigned char *cInputBuffer,int inSize, unsigned char *sessionKEY, unsigned char * uchOut3DESe )
{
	des3_context ctx3;
	uchar iv[8];
    
	memset(iv,0,8);
	des3_set_2keys( &ctx3, sessionKEY );
	des3_cbc_encrypt(&ctx3, iv, cInputBuffer, uchOut3DESe, inSize);
    
	return(0);
}

int in3DES_CBC_Decrypt(unsigned char *cInputBuffer,int inSize, unsigned char *sessionKEY, unsigned char * uchOut3DESd )
{
	des3_context ctx3;
	uchar iv[8];
    
	memset(iv,0x00,8);
	des3_set_2keys( &ctx3, sessionKEY );
	des3_cbc_decrypt(&ctx3,iv,cInputBuffer,uchOut3DESd,inSize);
    
	return(0);
}

int in3DES_Encrypt(unsigned char *cInputBuffer, unsigned char *sessionKEY, unsigned char * uchOut3DESe )
{
	/* uchar DES3_init[8] =
     {
     0x4E, 0x6F, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74
     };
     
	 uchar DES3_keys[16] =
     {
     0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
     0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01,
	 };*/
	des3_context ctx3;
    
	des3_set_2keys( &ctx3, sessionKEY );
	des3_encrypt( &ctx3, cInputBuffer, uchOut3DESe );
    
	return(1);
}

int inImamDES_DE (unsigned char *szKey, unsigned char *szClearData, unsigned char *szResult)
{
	unsigned long k[16][2];
	setkey(k, szKey, 0);
	encrypt(k, szClearData);
	setkey(k, &szKey[8], 1);
	encrypt(k, szClearData);
	setkey(k, szKey, 0);
	encrypt(k, szClearData);
	memcpy(szResult, szClearData, 8);
	return 1;
}

int inImamDES_TD (unsigned char *szKey, unsigned char *szEncData, unsigned char *szResult)
{
	unsigned long k[16][2];
	setkey(k, &szKey[16], 1);
	encrypt(k, szEncData);
	setkey(k, &szKey[8], 0);
	encrypt(k, szEncData);
	setkey(k, szKey, 1);
	encrypt(k, szEncData);
	memcpy(szResult, szEncData, 8);
	return 1;
}

int inImamDES_TE (unsigned char *szKey, unsigned char *szClearData, unsigned char *szResult)
{
	unsigned long k[16][2];
	setkey(k, szKey, 0);
	encrypt(k, szClearData);
	setkey(k, &szKey[8], 1);
	encrypt(k, szClearData);
	setkey(k, &szKey[16], 0);
	encrypt(k, szClearData);
	memcpy(szResult, szClearData, 8);
	return 1;
}
#endif