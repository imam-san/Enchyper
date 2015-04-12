//
//  pinfunc.c
//  pin_param
//
//  Created by Imam on 12/30/12.
//  Copyright (c) 2012 Imam. All rights reserved.
//

#include <stdio.h>
#include <string.h>
#include "desmfc.h"

int checkmode(int i,unsigned char *buff, int len )

{int j=0;
    switch (i)
    {
        case 1:
            for(j=0;j<len;j++)
            {
                if ( ( buff[j]!='0') || ( buff[j]!='1') ||( buff[j]!='2')||( buff[j]!='3')||( buff[j]!='4')||( buff[j]!='5')
                    ||( buff[j]!='6') || ( buff[j]!='7') ||( buff[j]!='8')||( buff[j]!='9')) //||( buff[j]!='')||( buff[j]!='5')
                    
                    return 1;
            }
            break;
        case 2:
            if ( ( buff[j]!='0') || ( buff[j]!='1') ||( buff[j]!='2')||( buff[j]!='3')||( buff[j]!='4')||( buff[j]!='5')
                ||( buff[j]!='6') || ( buff[j]!='7') ||( buff[j]!='8')||( buff[j]!='9')||( buff[j]!='a')||( buff[j]!='b')
                ||( buff[j]!='c') || ( buff[j]!='d') ||( buff[j]!='e')||( buff[j]!='f')||( buff[j]!='A')||( buff[j]!='B')
                ||( buff[j]!='C') || ( buff[j]!='D') ||( buff[j]!='E')||( buff[j]!='F'))
                
                return 1;
            break;
    }
    return 0;
}


unsigned char aasc_to_bcd2(unsigned char asc)
{
    unsigned char bcd;
    
    if ((asc >= '0') && (asc <= '9'))
        bcd = asc - '0';
    else if ((asc >= 'A') && (asc <= 'F'))
        bcd = asc - 'A' + 10;
    else if ((asc >= 'a') && (asc <= 'f'))
        bcd = asc - 'a' + 10;
    else if (asc >= 0x30 && asc <= 0x3f)
        bcd = asc - '0';
    else
    {
       
        bcd = 0x0f;
    }
    return bcd;
}



void asc_to_bcd2(unsigned char *bcd_buf, unsigned char *asc_buf, int n)
{
    int i, j;
    
    j = 0;
    for (i = 0; i < (n + 1) / 2; i++)
    {
        bcd_buf[i] = aasc_to_bcd2(asc_buf[j++]);
        bcd_buf[i] = ((j >= n) ? 0x00 : aasc_to_bcd2(asc_buf[j++])) +
        (bcd_buf[i] << 4);
    }
}
void SVC_DSP_2_HEX (unsigned char  * src, unsigned char * dest, unsigned long num_digit)
{
    asc_to_bcd2(dest, src,num_digit*2 );
    
}
void SVC_HEX_2_DSP(unsigned char  * src, unsigned char * dest,int num_digit)
{

    char s_out[32];
    int i = 0;
    memset(s_out,0x00,sizeof s_out);
 
    
    for ( i=0; i < num_digit; i++ )
    {
       
        sprintf ( &s_out[i*2], "%02X", src[i] );
        
    }
    memcpy(dest,s_out,num_digit*2);
}


int inHexascii(unsigned char *ucDest, unsigned char *ucSrc, int inSize)
{
    int i, iRet;
    iRet=1;
    
    if (inSize > 0)
    {
        for (i = 0; i < (inSize / 2); i++)
        {
            *(ucDest + (2 *i)) = ((*(ucSrc + i) &0xF0) >> 4) + 0x30;
            if (*(ucDest + (2 *i)) > 0x39)
                *(ucDest + (2 *i)) += 0x07;
            *(ucDest + (2 *i) + 1) = (*(ucSrc + i) &0x0F) + 0x30;
            if (*(ucDest + (2 *i) + 1) > 0x39)
                *(ucDest + (2 *i) + 1) += 0x07;
        }
        if (inSize % 2 != 0)
        {
            /* traitement size impaire */
            *(ucDest + (2 *i)) = ((*(ucSrc + i) &0xF0) >> 4) + 0x30;
            if (*(ucDest + (2 *i)) > 0x39)
                *(ucDest + (2 *i)) += 0x07;
        }
        iRet=0;
        //        return (0);
    }
    else
    	iRet=1;
    //        return (1);
    return iRet;
}

int traceme(unsigned char * buff2, int len)
{
    unsigned char buff[30];
    memset(buff,0x00,sizeof(buff));
    SVC_HEX_2_DSP(buff2,buff,len);
   // NSLOG(@"_trace %s\n",buff);
    return 0;
    
}


unsigned char * pinfunction(unsigned char * pin,unsigned  char * pout)
{
#define KEY1 (unsigned char*)"1111111111111111"
	
	
    
	unsigned char buftmp2[16];
	unsigned char tmpout[16];
	int i;
  
	memset(tmpout, 0x00, sizeof(tmpout));
	memcpy(buftmp2, pin,8);
    
    Decrypt_DES(1, KEY1, buftmp2);
    
    traceme(buftmp2, 8);
    
    SVC_HEX_2_DSP(buftmp2,tmpout,8);
    traceme(tmpout, 8);
    
	for ( i=0;i<8;i++)
	{
        
		if (tmpout[i]>'9')
			tmpout[i]=tmpout[i]-0x11;
        
        
	}
    traceme(tmpout, 8);
    
    
 
	
    memcpy(pout,tmpout,8);
	return pout;
}


void Algorithmpin(unsigned char *Pin,unsigned char *terminal, unsigned char *Outme)
{
    
    unsigned char  pinpar[8];

    char PINpar[8];
	char SerNo[10];
    int k;
    unsigned char xorret[8];
    
    memset(pinpar,0x00,sizeof pinpar);
    
    
    {
        memset(PINpar, 0x30, sizeof(PINpar));
        memcpy(PINpar, Pin, 4);
        memcpy(&PINpar[4], Pin, 4);
        
        memset(SerNo, 0x30, sizeof(SerNo));
        memcpy(SerNo, terminal, 8);
        
        memset(xorret,0x00, sizeof xorret);
        for (k=0;k<8;k++)
        {xorret[k]=SerNo[k]^PINpar[k];
           
        }
        
        pinfunction(xorret,Outme);
    }
}
