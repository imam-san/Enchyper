//
//  pinfunc.h
//  pin_param
//
//  Created by Imam on 12/30/12.
//  Copyright (c) 2012 Imam. All rights reserved.
//

#ifndef pin_param_pinfunc_h
#define pin_param_pinfunc_h


int checkmode(int i,unsigned char *buff, int len );
unsigned char aasc_to_bcd2(unsigned char asc);
/*
 ** private function:  set_star // fill the star buffer for secure display
 ** input:             i_l_len  // how many stars need to be filled
 ** output:            o_pc_buf // output buffer
 */


void asc_to_bcd2(unsigned char *bcd_buf, unsigned char *asc_buf, int n);
void SVC_DSP_2_HEX (unsigned char  * src, unsigned char * dest, unsigned long num_digit);
void SVC_HEX_2_DSP(unsigned char  * src, unsigned char * dest,int num_digit);

int inHexascii(unsigned char *ucDest, unsigned char *ucSrc, int inSize);
int traceme(unsigned char * buff2, int len);


unsigned char * pinfunction(unsigned char * pin,unsigned  char * pout);
void Algorithmpin(unsigned char *Pin,unsigned char *terminal, unsigned char *Outme);


#endif
