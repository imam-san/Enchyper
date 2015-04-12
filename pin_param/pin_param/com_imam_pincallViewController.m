//
//  com_imam_pincallViewController.m
//  pin_param
//
//  Created by Imam on 12/28/12.
//  Copyright (c) 2012 Imam. All rights reserved.
//
#include <CommonCrypto/CommonCryptor.h>
#import "com_imam_pincallViewController.h"
#include "pinfunc.h"
//#import "<CommonCrypto/CommonCryptor.h>"


@interface com_imam_pincallViewController ()

@end

@implementation com_imam_pincallViewController
@synthesize outme;
@synthesize outlabel;
@synthesize pinpar,terminal;

- (void)viewDidLoad
{
    [super viewDidLoad];
	// Do any additional setup after loading the view, typically from a nib.
    self.pinpar.delegate = self;
    self.terminal.delegate=self;
}

- (BOOL)textFieldShouldReturn:(UITextField *)textField {
    [textField resignFirstResponder];
    return NO;
}
- (BOOL)textView:(UITextView *)textView shouldChangeTextInRange:(NSRange)range
 replacementText:(NSString *)text {
    
    if([text isEqualToString:@"\n"]) {
        [textView resignFirstResponder];
        return NO;
    }
    return YES;
}
- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (IBAction)clear:(id)sender {
    outme.text=@"";
    pinpar.text=@"";
    terminal.text=@"";
    outlabel.text=@"****";
    
    
    
}

- (IBAction)gome:(id)sender {
   // outme.text=@"Hello";
    
    NSString *OutmeString;
    unsigned char terminal2[16];
    unsigned char outme2[8];
    unsigned char keyme[16];
     char buff[10];
    memset(buff,0x00,sizeof buff);
  //  size_t movedBytes=0;
    memcpy(terminal2,"\x05\x02\x0C\x05\x06\x03\x00\x06\x05\x02\x0C\x05\x06\x03\x00\x06",16);
    memcpy(keyme,"1111111111111111" , 16);
    
 
    Algorithmpin((unsigned char *)"1234", (unsigned char *)"70514192", outme2);
  
    sprintf(buff,"%c%c%c%c%c%c%c%c",outme2[0],outme2[1],outme2[2],outme2[3],outme2[4],outme2[5],outme2[6],outme2[7]);
    NSLog(@" %s",buff);
    
    OutmeString = [NSString stringWithCString:buff encoding:NSASCIIStringEncoding];


    self.outlabel.text=[NSString stringWithFormat:@"%s", buff];

}
@end
