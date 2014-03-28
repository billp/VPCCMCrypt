VPCCMCrypt
==========


AES/CCM Implementation in Objective-C with Streaming Support

#Features:

- AES/128 - ECB Mode
- Streaming support for large files
- Data to Data Encryption/Decryption
- File to File Encryption/Decryption
- Stream Encryption/Decryption which allows you to upload each chunk of data to server
- It uses only 16kb of memory for all operations

#Initialization

```
NSData *key = ...
NSData *iv = ...
NSData *adata = ...
NSInteger tagLength = ...

VPCCMCrypt *ccm = [[VPCCMCrypt alloc] initWithKey:key
                                               iv:iv
                                            adata:adata
                                        tagLength:tagLength];
```
#How to use

**Data to Data Encryption**

```
NSData *plainData = ...

[ccm encryptDataWithData:plainData finishedBlock:^(NSData *data) {
        //Do something with data
} errorBlock:^(NSError *error) {
        NSLog(@"Encryption Error: %@", error);
}];


```
**Data to Data Decryption:**
```
NSData *encryptedData = ...

[ccm decryptDataWithData:encryptedData finishedBlock:^(NSData *data) {
        //Do something with data
} errorBlock:^(NSError *error) {
        NSLog(@"Decryption Error: %@", error);
}];
```
**File to File Encryption**

```
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

```
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

```
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

```
NSURL *fileUrl = ...
[ccm decryptStreamWithUrl:fileUrl
                dataBlock:^(NSData *data, BOOL isLastBlock) {
                    //Do something with the decrypted data
                    
                } errorBlock:^(NSError *error) {
                    NSLog(@"Decryption Error: %@", error);
                }];
```

#Special thanks
to Thanos Chatziathanasiou (tchatzi@arx.net) for his implementation in Perl
