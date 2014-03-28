//
//  VPCCMCrypt.h
// 
//  Created by Bill Panagiotopoulos on 3/19/14.
//  Copyright (c) 2014. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface VPCCM : NSObject<NSStreamDelegate> {
    
    NSInteger _tagLength, _blockSize, _blocksCount, _exitNext, _keySize, _ivSize, _adataSize;
    
    long long _bytesLeft, _fileSize;
    
    unsigned char *_char_key, *_char_iv, *_char_ctr, *_char_adata, *_Y, *_S0, *_char_ctr_cipher, *_CC;
}

@property (nonatomic, retain) NSString *errorMessage;
@property (nonatomic) NSInteger errorNumber;

- (instancetype)initWithKey:(NSData *)key
                         iv:(NSData *)iv
                      adata:(NSData *)adata
                  tagLength:(NSInteger)tagLength
                   fileSize:(long long)fileSize;

- (unsigned char *)encryptBlock:(unsigned char *)bytes
                         length:(NSInteger)length;

- (unsigned char *)decryptBlock:(unsigned char *)buffer
                         length:(NSUInteger)length
                       exitNext:(NSInteger *)exitNext;

- (NSData *)getTag;

- (BOOL)verifyTagWithFileURL:(NSURL *)inputFile;
- (BOOL)verifyTagWithData:(NSData *)data;

- (void)freemem;
- (void)initialize;

@end
