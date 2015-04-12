//
//  com_imam_pincallViewController.h
//  pin_param
//
//  Created by Imam on 12/28/12.
//  Copyright (c) 2012 Imam. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface com_imam_pincallViewController : UIViewController
@property (weak, nonatomic) IBOutlet UITextField *pinpar;
@property (weak, nonatomic) IBOutlet UITextField *terminal;
- (IBAction)clear:(id)sender;
- (IBAction)gome:(id)sender;
@property (weak, nonatomic) IBOutlet UILabel *outme;
@property (strong, nonatomic) IBOutlet UILabel *outlabel;

@end
