//
//  AppDelegate.m
//  VPCCMCrypt
//
//  Created by Bill Panagiotopoulos on 3/20/14.
//  Copyright (c) 2014. All rights reserved.
//

#import "AppDelegate.h"

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
    
    NSData *key = [NSData dataWithBytes:(char[]){0xa2,0xd0,0x13,0x6b,0x2f,0x2b,0xd7,0xef,0xb4,0xd9,0xbc,0x91,0xc0,0xcd,0x7c,0x02} length:16];
    NSData *iv = [NSData dataWithBytes:(char[]){0x63,0x32,0x38,0x35,0x34,0x30,0x33,0x66} length:8];
    NSData *adata = [@"authentication data" dataUsingEncoding:NSUTF8StringEncoding];
    
    NSData *message = [@"Hello from CCM Mode!" dataUsingEncoding:NSUTF8StringEncoding];
    
    VPCCMCrypt *ccm = [[VPCCMCrypt alloc] initWithKey:key
                                                   iv:iv
                                                adata:adata
                                            tagLength:16];
    
    [ccm encryptDataWithData:message finishedBlock:^(NSData *data) {
        
        NSLog(@"Encrypted Data: %@", data);
        
        [ccm decryptDataWithData:data finishedBlock:^(NSData *data) {
            NSLog(@"Decrypted message: %@", [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]);
        } errorBlock:^(NSError *error) {
            NSLog(@"Decryption Error: %@", error);
        }];
        
    } errorBlock:^(NSError *error) {
        NSLog(@"Encryption Error: %@", error);
    }];

    // Override point for customization after application launch.
    return YES;
}


- (void)applicationWillResignActive:(UIApplication *)application
{
    // Sent when the application is about to move from active to inactive state. This can occur for certain types of temporary interruptions (such as an incoming phone call or SMS message) or when the user quits the application and it begins the transition to the background state.
    // Use this method to pause ongoing tasks, disable timers, and throttle down OpenGL ES frame rates. Games should use this method to pause the game.
}

- (void)applicationDidEnterBackground:(UIApplication *)application
{
    // Use this method to release shared resources, save user data, invalidate timers, and store enough application state information to restore your application to its current state in case it is terminated later. 
    // If your application supports background execution, this method is called instead of applicationWillTerminate: when the user quits.
}

- (void)applicationWillEnterForeground:(UIApplication *)application
{
    // Called as part of the transition from the background to the inactive state; here you can undo many of the changes made on entering the background.
}

- (void)applicationDidBecomeActive:(UIApplication *)application
{
    // Restart any tasks that were paused (or not yet started) while the application was inactive. If the application was previously in the background, optionally refresh the user interface.
}

- (void)applicationWillTerminate:(UIApplication *)application
{
    // Called when the application is about to terminate. Save data if appropriate. See also applicationDidEnterBackground:.
}

@end
