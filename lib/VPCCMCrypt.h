//
//  VPCCMCrypt.h
//  VPCCMCrypt
//
//  Created by Bill Panagiotopoulos on 3/23/14.
//  Copyright (c) 2014. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "VPCCM.h"

@interface VPCCMCrypt : NSObject {
    NSInteger _tagLength, _bufferSize, _blockSize;
    
    long long _bytesLeft;
    NSData *_key, *_iv, *_adata;
}

typedef void (^crypted_data_callback)(NSData *data, BOOL isLastBlock);
typedef void (^crypted_alldata_callback)(NSData *data);
typedef void (^crypted_file_callback)(void);

typedef void (^error_callback)(NSError *error);

- (instancetype)initWithKey:(NSData *)key
                         iv:(NSData *)iv
                      adata:(NSData *)adata
                  tagLength:(NSInteger)tagLength;

- (void)encryptStreamWithUrl:(NSURL *)url
                   dataBlock:(crypted_data_callback)dataBlock
                  errorBlock:(error_callback)errorBlock;

- (void)encryptFileToFileWithSourceURL:(NSURL *)sourceURL
                               destUrl:(NSURL *)destURL
                         finishedBlock:(crypted_file_callback)finishBlock
                            errorBlock:(error_callback)errorBlock;

- (void)encryptDataWithData:(NSData *)data
              finishedBlock:(crypted_alldata_callback)dataBlock
                 errorBlock:(error_callback)errorBlock;

- (void)decryptStreamWithUrl:(NSURL *)url
                   dataBlock:(crypted_data_callback)dataBlock
                  errorBlock:(error_callback)errorBlock;

- (void)decryptFileToFileWithSourceURL:(NSURL *)sourceURL
                               destUrl:(NSURL *)destURL
                         finishedBlock:(crypted_file_callback)finishBlock
                            errorBlock:(error_callback)errorBlock;

- (void)decryptDataWithData:(NSData *)data
              finishedBlock:(crypted_alldata_callback)dataBlock
                 errorBlock:(error_callback)errorBlock;

@end
