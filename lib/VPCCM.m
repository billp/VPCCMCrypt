//
//  VPCCMCrypt.m
// 
//  Created by Bill Panagiotopoulos on 3/19/14.
//  Copyright (c) 2014. All rights reserved.
//

#import "VPCCM.h"
#import <CommonCrypto/CommonCryptor.h>

#define _blocksCount 1024

@implementation VPCCM

@synthesize errorMessage = _errorMessage;
@synthesize errorNumber = _errorNumber;

- (instancetype)initWithKey:(NSData *)key
                         iv:(NSData *)iv
                      adata:(NSData *)adata
                  tagLength:(NSInteger)tagLength
                   fileSize:(long long)fileSize {
    
    if (self = [super init]) {
        _tagLength = tagLength;
        _blockSize = kCCBlockSizeAES128;
        
        _char_key = (unsigned char *)[key bytes];
        _char_iv = (unsigned char *)[iv bytes];
        _char_adata = (unsigned char *)[adata bytes];
        
        _keySize = key.length;
        _ivSize = iv.length;
        _adataSize = adata.length;
        
        [self initialize];
        
        _fileSize = fileSize;
        _bytesLeft = fileSize;
    }
    
    return self;
}


- (unsigned char *)encryptBlock:(unsigned char *)bytes
                         length:(NSInteger)length {
    
    /* Encrypt block
     */
    _bytesLeft -= length;
    
    NSInteger subBlockCount = ceil(length/(float)_blockSize);
    NSInteger paddingCount = length % _blockSize;
    
    for (NSInteger i = 0; i < subBlockCount; i++) {
        unsigned char *subBlockBytes = bytes + i*_blockSize;
        
        NSInteger subBlockLength = (i == subBlockCount-1 && paddingCount > 0) ? paddingCount : _blockSize;
        NSInteger naplBytesLength = (ceil((_adataSize)/(float)_blockSize) * _blockSize) + 3 * _blockSize;
    
        unsigned char *xorBytes = malloc(subBlockLength);
        unsigned char *naplBytes = malloc(naplBytesLength);
        unsigned char *yBytes = malloc(_blockSize);
        unsigned char *yCipher = malloc(_blockSize);
        
        naplBytesLength = [self _formatting_NAP:(unsigned char *)subBlockBytes
                                         buffer:naplBytes
                                         length:subBlockLength];
        
        
        if (_exitNext == -1) {
            _exitNext = 0;
        
            for (NSInteger i = 0; i < naplBytesLength; i+= _blockSize) {
                [self _bytesXorWithBytes:naplBytes+i
                                andBytes:_Y
                                 outBuff:yBytes
                                  length:_blockSize];
                
                [self _aesEncrypt:yBytes cipher:yCipher length:_blockSize];
                
                /* Copy cipher bytes to _Y
                 */
                [self _arrayCopyToDestination:_Y source:yCipher length:_blockSize];
            }
        } else {
            [self _bytesXorWithBytes:naplBytes
                            andBytes:_Y outBuff:yBytes
                              length:_blockSize];

            [self _aesEncrypt:yBytes cipher:yCipher length:_blockSize];
            
            /* Copy cipher bytes to _Y
             */
            [self _arrayCopyToDestination:_Y source:yCipher length:_blockSize];

        }

        int n = 0;
        
        for (NSInteger j = 15; j > 0; j--) {
            n = *(_char_ctr+j);
            *(_char_ctr+j) = (n + 1) & 255 ;
            
            if (*(_char_ctr+j) != '\0') {
                break;
            }
        }
        
        [self _aesEncrypt:_char_ctr
                   cipher:_char_ctr_cipher
                   length:_blockSize];

        [self _bytesXorWithBytes:(unsigned char *)subBlockBytes
                        andBytes:_char_ctr_cipher
                         outBuff:xorBytes
                          length:subBlockLength];
        
        for (NSInteger j = 0; j < subBlockLength; j++) {
            *(_CC+i*_blockSize+j) = *(xorBytes+j);
        }
        
        if (subBlockLength < _blockSize || (_bytesLeft == 0 && subBlockLength == _blockSize)) {
            _exitNext = 1;
        }

        free(xorBytes);
        free(naplBytes);
        free(yBytes);
        free(yCipher);
        
    }

    return _CC;
}

- (unsigned char *)decryptBlock:(unsigned char *)buffer
                         length:(NSUInteger)length
                       exitNext:(NSInteger *)exitNext {
    _bytesLeft -= length;

    NSInteger subBlockCount = ceil(length/(float)_blockSize);
    NSInteger paddingCount = length % _blockSize;
    
    for (NSInteger i = 0; i < subBlockCount; i++) {
        unsigned char *subBlockBytes = buffer + i*_blockSize;
        
        NSInteger subBlockLength = (i == subBlockCount-1 && paddingCount > 0) ? paddingCount : _blockSize;
        unsigned char *xorBytes = malloc(subBlockLength);
        
        int n = 0;
        
        for (NSInteger j = 15; j > 0; j--) {
            n = *(_char_ctr+j);
            *(_char_ctr+j) = (n + 1) & 255 ;
            
            if (*(_char_ctr+j) != '\0') {
                break;
            }
        }
        
        [self _aesEncrypt:_char_ctr
                   cipher:_char_ctr_cipher
                   length:_blockSize];
        
        [self _bytesXorWithBytes:(unsigned char *)subBlockBytes
                        andBytes:_char_ctr_cipher
                         outBuff:xorBytes
                          length:subBlockLength];
        
        for (NSInteger j = 0; j < subBlockLength; j++) {
            *(_CC+i*_blockSize+j) = *(xorBytes+j);
        }
        
        free(xorBytes);
        
        if (subBlockLength < _blockSize || (_bytesLeft == 0 && subBlockLength == _blockSize)) {
            _exitNext = 1;
        }
        
    }
    
    if (exitNext) {
        *exitNext = _exitNext;
    }
    
    return _CC;
}


- (NSData *)getTag {
    
    /* Returns the tag of the cipher
     */
    unsigned char *tagBuffer = malloc(_blockSize);
    
    [self _bytesXorWithBytes:_Y
                    andBytes:_S0
                     outBuff:tagBuffer
                      length:_blockSize];

    
    NSData *tag = [[NSData alloc] initWithBytes:tagBuffer length:_tagLength];
    
    free(tagBuffer);
    [self freemem];
    
    return tag;
}

- (void)freemem {
    free(_Y);
    free(_S0);
    free(_char_ctr);
    free(_char_ctr_cipher);
    free(_CC);
    
    _Y = NULL;
    _S0 = NULL;
    _char_ctr = NULL;
    _char_ctr_cipher = NULL;
    _CC = NULL;
}

- (void)initialize {
    _exitNext = -1;
    _errorMessage = nil;
    
    _CC = malloc(_blocksCount * _blockSize);
    _Y = malloc(_blockSize);
    _S0 = malloc(_blockSize);
    _char_ctr = malloc(_blockSize);
    _char_ctr_cipher = malloc(_blockSize);
    
    [self _generateCounterBlock:_char_ctr];
    [self _aesEncrypt:_char_ctr cipher:_S0 length:_blockSize];
    
    for (NSInteger i = 0; i < _blockSize; i++) {
        *(_Y+i) = 0x0;
    }
}

- (BOOL)verifyTagWithFileURL:(NSURL *)inputFile {
    
    [self _generateCounterBlock:_char_ctr];
    [self _aesEncrypt:_char_ctr cipher:_S0 length:_blockSize];
    
    unsigned char *T = malloc(_tagLength);
    NSFileHandle *fileHandle = [NSFileHandle fileHandleForReadingFromURL:inputFile error:nil];

    [fileHandle seekToFileOffset:_fileSize-_tagLength];
    
    NSData *tag = [fileHandle readDataToEndOfFile];
    
    [self _bytesXorWithBytes:(unsigned char *)[tag bytes] andBytes:_S0 outBuff:T length:_tagLength];
    
    for (NSInteger i = 0; i < _blockSize; i++) {
        *(_Y+i) = 0x0;
    }
    _exitNext = -1;
    
    NSUInteger _bufferSize = _blocksCount * kCCBlockSizeAES128;
    
    unsigned char buffer[_bufferSize];
    
    NSInputStream *inputStream = [[NSInputStream alloc] initWithURL:inputFile];
    
    [inputStream open];
    
    _fileSize -= _tagLength;
    
    while ([inputStream hasBytesAvailable]) {
        long bytesRead = [inputStream read:buffer maxLength:_bufferSize];
        
        if (_bytesLeft-bytesRead <= _blockSize) {
            bytesRead -= _tagLength-(_bytesLeft-bytesRead);
            if (bytesRead == 0) {
                break;
            }
        }
        
        [self _verifyTagWithBlock:buffer length:bytesRead];
        
        if (_exitNext == 1) {
            break;
        }
    }
    
    NSData *fileTag = [NSData dataWithBytes:T length:_tagLength];
    NSData *calculatedTag = [NSData dataWithBytes:_Y length:_tagLength];
    
    free(T);
    
    [self freemem];
    
    if ([fileTag isEqualToData:calculatedTag]) {
        return YES;
    }
    
    return NO;
}

- (BOOL)verifyTagWithData:(NSData *)data {
    
    [self _generateCounterBlock:_char_ctr];
    [self _aesEncrypt:_char_ctr cipher:_S0 length:_blockSize];
    
    unsigned char *T = malloc(_tagLength);

    NSData *tag = [data subdataWithRange:NSMakeRange(data.length-_tagLength, _tagLength)];
    
    [self _bytesXorWithBytes:(unsigned char *)[tag bytes] andBytes:_S0 outBuff:T length:_tagLength];

    NSData *dataPart = [data subdataWithRange:NSMakeRange(0, data.length-_tagLength)];
    
    
    for (NSInteger i = 0; i < _blockSize; i++) {
        *(_Y+i) = 0x0;
    }
    _exitNext = -1;
    
    NSUInteger _bufferSize = _blocksCount * kCCBlockSizeAES128;;
    
    _fileSize -= _tagLength;
    
    NSInteger loopCount = ceil(dataPart.length/(float)_bufferSize);
    
    unsigned char *bytes = (unsigned char *)[dataPart bytes];
    
    for (NSInteger i = 0; i < loopCount; i++) {
    
        if (i != loopCount-1) {
            [self _verifyTagWithBlock:bytes+i*_bufferSize length:_bufferSize];
        } else {
            NSInteger len = dataPart.length%_bufferSize;
            [self _verifyTagWithBlock:bytes + i*_bufferSize length:len];
        }
    }
    
    NSData *dataTag = [NSData dataWithBytes:T length:_tagLength];
    NSData *calculatedTag = [NSData dataWithBytes:_Y length:_tagLength];
    
    [self freemem];
    free(T);
    
    if ([dataTag isEqualToData:calculatedTag]) {
        return YES;
    }
    
    return NO;
}


#pragma mark -
#pragma mark private methods

- (void)_verifyTagWithBlock:(unsigned char *)buffer
                     length:(NSUInteger)length {
    
    _bytesLeft -= length;
    NSInteger subBlockCount = ceil(length/(float)_blockSize);
    NSInteger paddingCount = length % _blockSize;
    
    for (NSInteger i = 0; i < subBlockCount; i++) {
        unsigned char *subBlockBytes = buffer + i*_blockSize;
        
        NSInteger subBlockLength = (i == subBlockCount-1 && paddingCount > 0) ? paddingCount : _blockSize;
        NSInteger naplBytesLength = (ceil((_adataSize)/(float)_blockSize) * _blockSize) + 3 * _blockSize;
        
        unsigned char *xorBytes = malloc(subBlockLength);
        unsigned char *naplBytes = malloc(naplBytesLength);
        unsigned char *yBytes = malloc(_blockSize);
        unsigned char *yCipher = malloc(_blockSize);
        
        int n = 0;
        
        for (NSInteger j = 15; j > 0; j--) {
            n = *(_char_ctr+j);
            *(_char_ctr+j) = (n + 1) & 255 ;
            
            if (*(_char_ctr+j) != '\0') {
                break;
            }
        }
        
        [self _aesEncrypt:_char_ctr
                   cipher:_char_ctr_cipher
                   length:_blockSize];
        
        
        [self _bytesXorWithBytes:(unsigned char *)subBlockBytes
                        andBytes:_char_ctr_cipher
                         outBuff:xorBytes
                          length:subBlockLength];
        
        
        naplBytesLength = [self _formatting_NAP:(unsigned char *)xorBytes
                                         buffer:naplBytes
                                         length:subBlockLength];

        if (_exitNext == -1) {
            _exitNext = 0;
            
            for (NSInteger i = 0; i < naplBytesLength; i+= _blockSize) {
                
                [self _bytesXorWithBytes:naplBytes+i
                                andBytes:_Y
                                 outBuff:yBytes
                                  length:_blockSize];
                
                [self _aesEncrypt:yBytes cipher:yCipher length:_blockSize];
                
                /* Copy cipher bytes to _Y
                 */
                [self _arrayCopyToDestination:_Y source:yCipher length:_blockSize];
            }
        } else {
            
            [self _bytesXorWithBytes:naplBytes
                            andBytes:_Y
                             outBuff:yBytes
                              length:_blockSize];
            
            [self _aesEncrypt:yBytes cipher:yCipher length:_blockSize];
            
            /* Copy cipher bytes to _Y
             */
            [self _arrayCopyToDestination:_Y source:yCipher length:_blockSize];
        }
        
        if (subBlockLength < _blockSize || (_bytesLeft == 0 && subBlockLength == _blockSize)) {
            _exitNext = 1;
        }
        
        free(xorBytes);
        free(naplBytes);
        free(yBytes);
        free(yCipher);
    }
}

- (long)_formatAssociatedData:(unsigned char *)buffer {

    NSInteger payloadLength = 1;
    
    NSInteger value = _adataSize;
    
    if (_adataSize == 0) {
        *(buffer) = 0x0;
    }
    else if (_adataSize <= 0xFEFF) {
        for (NSInteger i = 1; i >= 0; i--) {
            *(buffer+i) = value & 0xFF;
            value = value >> 8;
        }
        payloadLength = 2;
    } else {
        _errorMessage = @"Invalid adata length. Should be <= 65279";
        _errorNumber = 3;
    }
    
    NSInteger paddingLength = (_blockSize - _adataSize % _blockSize) - payloadLength;
    
    for (NSInteger i = 0; i < _adataSize; i++) {
        *(buffer+i+payloadLength) = *(_char_adata+i);
    }
    
    for (NSInteger i = 0; i < paddingLength; i++) {
        *(buffer+payloadLength+_adataSize+i) = 0x0;
    }
    
    if (paddingLength < 0) {
        paddingLength = 0;
    }
    
    return payloadLength+_adataSize + paddingLength;
}

- (long)_formatting_NAP:(unsigned char *)plainDataBlock
                 buffer:(unsigned char *)buffer
                 length:(NSInteger)payloadLength {
    if (_exitNext == -1) {
        [self _formatHeaderWithPayloadLength:_fileSize buffer:buffer];
        
        long adata_len = _blockSize;
        
        if (_adataSize > 0) {
            adata_len += [self _formatAssociatedData:buffer+_blockSize];
        }
        
        [self _formatPayload:plainDataBlock buffer:buffer+adata_len length:payloadLength];
        
        return adata_len + _blockSize;
        
    } else {
        [self _formatPayload:plainDataBlock
                      buffer:buffer
                      length:payloadLength];
    }
    
    return -1;
}


- (void)_formatHeaderWithPayloadLength:(long long)payloadLength
                                buffer:(unsigned char *)buffer
{
    NSInteger qLen = 15 - _ivSize;
    
    int fl = 0x0;
    
    fl |= (_adataSize > 0) ? 0x40 : 0x00;
    fl |= ((((_tagLength - 2) / 2) & 0x07) << 3);
    fl |= ((qLen - 1) & 0x07);
    
    *(buffer) = fl;
    
    for (NSInteger i = 0; i < qLen; i++) {
        *(buffer+_blockSize-i-1) = payloadLength & 255;
        payloadLength >>= 8;
    }
    
    for (NSInteger i = 0; i < _ivSize; i++) {
        *(buffer+1+i) = *(_char_iv+i);
    }
}

- (void)_formatPayload:(unsigned char *)plainDataBlock
                buffer:(unsigned char *)buffer
                length:(NSInteger)length {
    
    NSInteger pad = length % _blockSize;
    
    for (NSInteger i = 0; i < length; i++) {
        *(buffer+i) = *(plainDataBlock+i);
    }
    
    if (pad > 0) {
        for (NSInteger i = 0; i < _blockSize - pad; i++) {
            *(buffer+length+i) = 0x0;
        }
    }
}

- (void)_generateCounterBlock:(unsigned char *)buffer {
    
    NSInteger qLen = 15 - _ivSize;
    
    int fl = 0x0;
    fl |= (qLen - 1) & 0x07;
   
    *(buffer) = fl;
    
    for (NSInteger i = 0; i < _ivSize; i++) {
        *(buffer+i+1) = *(_char_iv+i);
    }
    
    for (NSInteger i = _ivSize+1; i < _blockSize; i++) {
        *(buffer+i) = 0x0;
    }
}

- (void)_bytesXorWithBytes:(unsigned char *)bytesLeft
                  andBytes:(unsigned char *)bytesRight
                   outBuff:(unsigned char *)outbuff
                    length:(NSInteger)length {
    
    for (NSInteger i = 0; i < length; i++) {
        *(outbuff+i) = *(bytesLeft+i) ^ *(bytesRight+i);
    }

}

-(void)_aesEncrypt:(unsigned char *)bytes
            cipher:(unsigned char *)cipherBytes
            length:(NSInteger)length {
    
    size_t outLength;
    
    CCCryptorStatus result = CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionECBMode,
                                     _char_key, _keySize, _char_iv,
                                     bytes, length, cipherBytes,
                                     length, &outLength);
    
    if (result != kCCSuccess) {
        //Catch the error here
        _errorMessage = @"AES128 Encryption Error";
        _errorNumber = 4;
    }
}

-(void)_arrayCopyToDestination:(unsigned char *)destination
                        source:(unsigned char *)source
                        length:(NSInteger)length {
    
    for (NSInteger i = 0; i < length; i++) {
        *(destination+i) = *(source+i);
    }
}

- (void)PrintHex:(unsigned char *)bytes
          length:(NSInteger)length {
    NSLog(@"%@", [[NSData alloc] initWithBytes:bytes length:length]);
}

@end
