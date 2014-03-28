 //
//  VPCCMCrypt.m
//  VPCCMCrypt
//
//  Created by Bill Panagiotopoulos on 3/23/14.
//  Copyright (c) 2014 Arx.net. All rights reserved.
//

#import "VPCCMCrypt.h"
#import "VPCCM.h"
#import <CommonCrypto/CommonCryptor.h>

#define _blocksCount 1024

NSString *const ANPushServiceError  = @"com.vpccmcrypt.CryptError";

@implementation VPCCMCrypt

- (instancetype)initWithKey:(NSData *)key
                         iv:(NSData *)iv
                      adata:(NSData *)adata
                  tagLength:(NSInteger)tagLength {

    if (self = [super init]) {
        _key = key;
        _iv = iv;
        _adata = adata;
        _tagLength = tagLength;
        _blockSize = kCCBlockSizeAES128;
        _bufferSize = _blocksCount * _blockSize;

    }
    
    return self;
    
}

- (void)encryptStreamWithUrl:(NSURL *)url
                   dataBlock:(crypted_data_callback)dataBlock
                  errorBlock:(error_callback)errorBlock {
    
    dispatch_queue_t backgroundQueue = dispatch_queue_create("com.vpccm.bgqueue", NULL);
    
    dispatch_async(backgroundQueue, ^(void) {

        NSDictionary *fileAttributes = [[NSFileManager defaultManager] attributesOfItemAtPath:url.path error:nil];
        NSNumber *fileSizeNumber = [fileAttributes objectForKey:NSFileSize];
        
        long long fileSize = [fileSizeNumber longLongValue];
        _bytesLeft = fileSize;
        
    
        VPCCM *ccmIstance = [[VPCCM alloc] initWithKey:_key
                                                    iv:_iv
                                                 adata:_adata
                                             tagLength:_tagLength
                                              fileSize:fileSize];
    
        NSInputStream *inputStream = [[NSInputStream alloc] initWithURL:url];
        unsigned char buffer[_bufferSize];
    
        [inputStream open];
    
        
        
        while ([inputStream hasBytesAvailable])
        {
            long bytesRead = [inputStream read:buffer maxLength:_bufferSize];
            
            if (bytesRead > 0) {
                
                NSData *encrypted = [[NSData alloc] initWithBytesNoCopy:
                                     [ccmIstance encryptBlock:buffer
                                                       length:bytesRead]
                                                       length:bytesRead
                                                 freeWhenDone:NO];
                
                if (ccmIstance.errorMessage != nil) {
                    NSError *error = [self createErrorObject:ccmIstance.errorMessage errorNumber:3];
                    errorBlock(error);
                    return;
                }
                
                dataBlock(encrypted, NO);
            }
        }
    
        //The last block is the tag
        NSData *tag = [ccmIstance getTag];
        dataBlock(tag, YES);
    
        [inputStream close];
    });
}

- (void)encryptFileToFileWithSourceURL:(NSURL *)sourceURL
                               destUrl:(NSURL *)destURL
                         finishedBlock:(crypted_file_callback)finishBlock
                            errorBlock:(error_callback)errorBlock {

    NSOutputStream *outputStream = [[NSOutputStream alloc] initWithURL:destURL append:NO];
    [outputStream open];
    
    [self encryptStreamWithUrl:sourceURL dataBlock:^(NSData *data, BOOL isLastBlock) {

        
        
        if ([outputStream hasSpaceAvailable]) {
            [outputStream write:[data bytes] maxLength:data.length];
        }

        if (isLastBlock) {
            if (finishBlock) {
                finishBlock();
            }

            [outputStream close];
        }
       // NSLog(@"data:%@", data);
    } errorBlock:^(NSError *error) {
        errorBlock(error);
    }];
}

- (void)encryptDataWithData:(NSData *)data
              finishedBlock:(crypted_alldata_callback)dataBlock
                 errorBlock:(error_callback)errorBlock {
    
    dispatch_queue_t backgroundQueue = dispatch_queue_create("com.vpccm.bgqueue", NULL);
    
    dispatch_async(backgroundQueue, ^(void) {
    
    
        NSInteger loopCount = ceil(data.length/(float)_bufferSize);
        
        VPCCM *ccmIstance = [[VPCCM alloc] initWithKey:_key
                                                    iv:_iv
                                                 adata:_adata
                                             tagLength:_tagLength
                                              fileSize:data.length];
        
        NSMutableData *cipher = [[NSMutableData alloc] init];
        
        unsigned char *bytes = (unsigned char *)[data bytes];
        
        for (NSInteger i = 0; i < loopCount; i++) {
            NSData *encrypted = nil;
            
            if (i != loopCount-1) {
                
                encrypted = [[NSData alloc] initWithBytes:[ccmIstance encryptBlock:bytes + i*_bufferSize
                                                                            length:_bufferSize]
                                                                            length:_bufferSize];
            } else {
                NSInteger len = data.length%_bufferSize;
                
                encrypted = [[NSData alloc] initWithBytes:[ccmIstance encryptBlock:bytes + i*_bufferSize
                                                                            length:len]
                                                                            length:len];
            }
            
            if (ccmIstance.errorMessage != nil) {
                NSError *error = [self createErrorObject:ccmIstance.errorMessage
                                             errorNumber:ccmIstance.errorNumber];
                errorBlock(error);
                return;
            }
            
            [cipher appendData:encrypted];
        }
        
        //Append tag
        NSData *tag = [ccmIstance getTag];
        
        [cipher appendData:tag];
    
        dataBlock(cipher);
    });
}

- (void)decryptStreamWithUrl:(NSURL *)url
                   dataBlock:(crypted_data_callback)dataBlock
                  errorBlock:(error_callback)errorBlock {

    dispatch_queue_t backgroundQueue = dispatch_queue_create("com.vpccm.bgqueue", NULL);
    
    dispatch_async(backgroundQueue, ^(void) {
        
        NSDictionary *fileAttributes = [[NSFileManager defaultManager] attributesOfItemAtPath:url.path error:nil];
        NSNumber *fileSizeNumber = [fileAttributes objectForKey:NSFileSize];
        
        long long fileSize = [fileSizeNumber longLongValue];
        _bytesLeft = fileSize;
        
        
        VPCCM *ccmIstance = [[VPCCM alloc] initWithKey:_key
                                                    iv:_iv
                                                 adata:_adata
                                             tagLength:_tagLength
                                              fileSize:fileSize];
        
        if ([ccmIstance verifyTagWithFileURL:url]) {
            [ccmIstance initialize];
            
            NSInputStream *inputStream = [[NSInputStream alloc] initWithURL:url];
            unsigned char buffer[_bufferSize];
            
            [inputStream open];
            
            while ([inputStream hasBytesAvailable])
            {
                long bytesRead = [inputStream read:buffer maxLength:_bufferSize];
                
                if (_bytesLeft-bytesRead <= _blockSize) {
                    bytesRead -= _tagLength-(_bytesLeft-bytesRead);
                    if (bytesRead == 0) {
                        break;
                    }
                }
                
                NSInteger exitNext = 0;
                
                NSData *decrypted = [[NSData alloc] initWithBytesNoCopy:
                                                    [ccmIstance decryptBlock:buffer
                                                                      length:bytesRead
                                                                    exitNext:&exitNext]
                                                                        length:bytesRead
                                                            freeWhenDone:NO];
                
                if (ccmIstance.errorMessage != nil) {
                    NSError *error = [self createErrorObject:ccmIstance.errorMessage
                                                 errorNumber:ccmIstance.errorNumber];
                    errorBlock(error);
                    return;
                }
                
                _bytesLeft -= bytesRead;
                BOOL isLastBlock = (exitNext == 1);
                
                dataBlock(decrypted, isLastBlock);
                
                if (isLastBlock) {
                    break;
                }
            }
        } else {
            NSError *error = [self createErrorObject:@"Invalid TAG" errorNumber:1];
            errorBlock(error);
        }
    });
    
}

- (void)decryptFileToFileWithSourceURL:(NSURL *)sourceURL
                               destUrl:(NSURL *)destURL
                         finishedBlock:(crypted_file_callback)finishBlock
                            errorBlock:(error_callback)errorBlock {
    
    NSOutputStream *outputStream = [[NSOutputStream alloc] initWithURL:destURL append:NO];
    [outputStream open];
    
    [self decryptStreamWithUrl:sourceURL dataBlock:^(NSData *data, BOOL isLastBlock) {
        
        if ([outputStream hasSpaceAvailable]) {
            [outputStream write:[data bytes] maxLength:data.length];
        }
        
        if (isLastBlock) {
            if (finishBlock) {
                finishBlock();
            }
            
            [outputStream close];
        }
        // NSLog(@"data:%@", data);
    } errorBlock:^(NSError *error) {
        errorBlock(error);
    }];
}


- (void)decryptDataWithData:(NSData *)data
              finishedBlock:(crypted_alldata_callback)dataBlock
                 errorBlock:(error_callback)errorBlock {
    
    dispatch_queue_t backgroundQueue = dispatch_queue_create("com.vpccm.bgqueue", NULL);
    
    dispatch_async(backgroundQueue, ^(void) {
        
        if (data.length <= _tagLength) {
            NSError *error = [self createErrorObject:@"Cipher text is too short" errorNumber:2];
            errorBlock(error);
            return;
        }
        
        NSData *dataPart = [data subdataWithRange:NSMakeRange(0, data.length-_tagLength)];
        
        _bytesLeft = dataPart.length;
        
        VPCCM *ccmIstance = [[VPCCM alloc] initWithKey:_key
                                                    iv:_iv
                                                 adata:_adata
                                             tagLength:_tagLength
                                              fileSize:data.length];
        
        if ([ccmIstance verifyTagWithData:data]) {
            [ccmIstance initialize];
            
            NSInteger loopCount = ceil(dataPart.length/(float)_bufferSize);
            
            NSMutableData *plain = [[NSMutableData alloc] init];
            
            unsigned char *bytes = (unsigned char *)[data bytes];
            
            for (NSInteger i = 0; i < loopCount; i++) {
                NSData *decrypted = nil;
                
                if (i != loopCount-1) {
                    
                    decrypted = [[NSData alloc] initWithBytes:[ccmIstance decryptBlock:bytes + i*_bufferSize
                                                                                length:_bufferSize
                                                                              exitNext:NULL]
                                                                                length:_bufferSize];
                    
                } else {
                    NSInteger len = dataPart.length%_bufferSize;
                    
                    decrypted = [[NSData alloc] initWithBytes:[ccmIstance decryptBlock:bytes + i*   _bufferSize
                                                                                length:len
                                                                              exitNext:NULL]
                                                                                length:len];
                }
                
                if (ccmIstance.errorMessage != nil) {
                    NSError *error = [self createErrorObject:ccmIstance.errorMessage
                                                 errorNumber:ccmIstance.errorNumber];
                    errorBlock(error);
                    return;
                }
                
                [plain appendData:decrypted];
            }
            
            dataBlock(plain);
            
        } else {
            NSError *error = [self createErrorObject:@"Invalid TAG" errorNumber:1];
            errorBlock(error);
        }
        [ccmIstance freemem];
    });
}

#pragma mark - 
#pragma mark private methods

- (NSError *)createErrorObject:(NSString *)message
                   errorNumber:(NSInteger)number {
    NSDictionary *errorDict = @{NSLocalizedDescriptionKey : message};
    
    return [[NSError alloc] initWithDomain:ANPushServiceError
                                      code:number
                                  userInfo:errorDict];
}

@end
