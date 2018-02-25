VPCCMCrypt
==========

AES/CCM library in Objective-C with Streaming Support

# Features

- AES/128 - ECB Mode
- Stream Encryption/Decryption methods which allows you to upload each chunk of data to server
- Data to Data Encryption/Decryption methods
- File to File Encryption/Decryption methods
- It uses only 16kb of memory (for stream operations)

#Installation

Add these lines to your Podfile
```objective-c
platform :ios, '6.0'
pod 'VPCCMCrypt', '~> 0.0.1'
```

# Initialization

```objective-c
NSData *key = ...
NSData *iv = ...
NSData *adata = ...
NSInteger tagLength = ...

VPCCMCrypt *ccm = [[VPCCMCrypt alloc] initWithKey:key
                                               iv:iv
                                            adata:adata
                                        tagLength:tagLength];
```
# How to use

**Data to Data Encryption**

```objective-c
NSData *plainData = ...

[ccm encryptDataWithData:plainData 
           finishedBlock:^(NSData *data) {
           //Do something with data
} errorBlock:^(NSError *error) {
        NSLog(@"Encryption Error: %@", error);
}];


```
**Data to Data Decryption:**
```objective-c
NSData *encryptedData = ...

[ccm decryptDataWithData:encryptedData 
           finishedBlock:^(NSData *data) {
        //Do something with data
} errorBlock:^(NSError *error) {
        NSLog(@"Decryption Error: %@", error);
}];
```
**File to File Encryption**

```objective-c
NSURL *sourceURL = ...
NSURL *destinationURL = ...

[ccm encryptFileToFileWithSourceURL:sourceURL
                            destUrl:destinationURL
                      finishedBlock:^{
                          //Encryption finished
                      } errorBlock:^(NSError *error) {
                          NSLog(@"Encryption Error: %@", error);
                      }];
```
**File to File Decryption:**

```objective-c
NSURL *sourceURL = ...
NSURL *destinationURL = ...

[ccm decryptFileToFileWithSourceURL:sourceURL
                            destUrl:destinationURL
                      finishedBlock:^{
                          //Decryption finished
                      } errorBlock:^(NSError *error) {
                          NSLog(@"Encryption Error: %@", error);
                      }];
```

**Stream Encryption**

```objective-c
NSURL *fileUrl = ...

[ccm encryptStreamWithUrl:fileUrl
                dataBlock:^(NSData *data, BOOL isLastBlock) {
                    if (isLastBlock) {
                        //data = TAG
                    }
                    //Upload data to server
                    
                } errorBlock:^(NSError *error) {
                    NSLog(@"Encryption Error: %@", error);
                }];
```

**Stream Decryption**

```objective-c
NSURL *fileUrl = ...

[ccm decryptStreamWithUrl:fileUrl
                dataBlock:^(NSData *data, BOOL isLastBlock) {
                    //Do something with the decrypted data
                    
                } errorBlock:^(NSError *error) {
                    NSLog(@"Decryption Error: %@", error);
                }];
```

# Contributors
Special thanks to Thanos Chatziathanasiou (tchatzi@arx.net) for his implementation in Perl
