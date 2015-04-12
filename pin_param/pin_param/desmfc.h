//
//  desmfc.h
//  pin_param
//
//  Created by Imam on 12/30/12.
//  Copyright (c) 2012 Imam. All rights reserved.
//

#ifndef pin_param_desmfc_h
#define pin_param_desmfc_h
typedef unsigned long ulong;

typedef unsigned char  uchar;
typedef unsigned char  byte;

typedef struct
{
    ulong esk[32];     /* DES encryption subkeys */
    ulong dsk[32];     /* DES decryption subkeys */
}
des_context;

typedef struct
{
    ulong esk[96];     /* Triple-DES encryption subkeys */
    ulong dsk[96];     /* Triple-DES decryption subkeys */
}
des3_context;

void Encrypt_DES(int mode, byte *key, byte *data);
void Decrypt_DES(int mode, byte *key, byte *data);


/*
 * DES key schedule
 */
void des_set_key( des_context *ctx, uchar key[8] );

/*
 * DES 64-bit block encryption (ECB)
 */
void des_encrypt( des_context *ctx, uchar input[8], uchar output[8] );

/*
 * DES 64-bit block decryption (ECB)
 */
void des_decrypt( des_context *ctx, uchar input[8], uchar output[8] );

/*
 * DES-CBC encryption
 */
void des_cbc_encrypt( des_context *ctx, uchar iv[8],
                     uchar *input, uchar *output, unsigned int len );

/*
 * DES-CBC decryption
 */
void des_cbc_decrypt( des_context *ctx, uchar iv[8],
                     uchar *input, uchar *output, unsigned int len );

/*
 * Triple-DES key schedule (112-bit)
 */
void des3_set_2keys( des3_context *ctx, uchar key[16] );

/*
 * Triple-DES key schedule (168-bit)
 */
void des3_set_3keys( des3_context *ctx, uchar key[24] );

/*
 * Triple-DES 64-bit block encryption (ECB)
 */
void des3_encrypt( des3_context *ctx, uchar input[8], uchar output[8] );

/*
 * Triple-DES 64-bit block decryption (ECB)
 */
void des3_decrypt( des3_context *ctx, uchar input[8], uchar output[8] );

/*
 * 3DES-CBC encryption
 */
void des3_cbc_encrypt( des3_context *ctx, uchar iv[8],
                      uchar *input, uchar *output, unsigned int len );

/*
 * 3DES-CBC decryption
 */
void des3_cbc_decrypt( des3_context *ctx, uchar iv[8],
                      uchar *input, uchar *output, unsigned int len );

//L: added
#if 1 //def TLE_MANDIRI
/*
 * 3DES-MAC encryption
 */
void des3_mac_encrypt( des3_context *ctx, uchar iv[8],
                      uchar *input, uchar *output, unsigned int len );

int inDES_CBC_Encrypt(unsigned char *cInputBuffer,int inSize,
                      unsigned char *sessionKEY, unsigned char * uchOut3DESe ); //L: created
int inDES_CBC_Decrypt(unsigned char *cInputBuffer,int inSize,
                      unsigned char *sessionKEY, unsigned char * uchOut3DESd ); //L: created

int in3DES_CBC_Encrypt(unsigned char *cInputBuffer,int inSize,
                       unsigned char *sessionKEY, unsigned char *uchOut3DESe);
int in3DES_CBC_Decrypt(unsigned char *cInputBuffer,int inSize,
                       unsigned char *sessionKEY, unsigned char *uchOut3DESd);

int in3DES_Encrypt(unsigned char *cInputBuffer, unsigned char *sessionKEY,
                   unsigned char *uchOut3DESe);
int inImamDES_DE (unsigned char *szKey, unsigned char *szClearData, unsigned char *szResult);
int inImamDES_TD (unsigned char *szKey, unsigned char *szEncData, unsigned char *szResult);
int inImamDES_TE (unsigned char *szKey, unsigned char *szClearData, unsigned char *szResult);
#endif



#endif
