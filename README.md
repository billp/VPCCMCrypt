VPCCMCrypt
==========


AES/CCM Implementation in Objective-C with Streaming Support

**Features:**

- AES/128 - ECB Mode
- Streaming support for large files
- Data to Data Encryption/Decryption
- File to File Encryption/Decryption
- Stream Encryption/Decryption which allows you to upload each chunk of data to server
- It uses only 16kb of memory for all operations

**Initialization:**

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
**How to use:**

_Data to Data Encryption:_

```
NSData *plainData = ...

[ccm encryptDataWithData:plainData finishedBlock:^(NSData *data) {
        //Do something with data
} errorBlock:^(NSError *error) {
        NSLog(@"Encryption Error: %@", error);
}];


```
_Data to Data Decryption:_
```
NSData *encryptedData = ...

[ccm decryptDataWithData:encryptedData finishedBlock:^(NSData *data) {
        //Do something with data
} errorBlock:^(NSError *error) {
        NSLog(@"Decryption Error: %@", error);
}];
```
_File to File Encryption:_

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
_File to File Decryption:_

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

_Stream Encryption_

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

_Stream Decryption_

```
NSURL *fileUrl = ...
[ccm decryptStreamWithUrl:fileUrl
                dataBlock:^(NSData *data, BOOL isLastBlock) {
                    //Do something with the decrypted data
                    
                } errorBlock:^(NSError *error) {
                    NSLog(@"Decryption Error: %@", error);
                }];
```

_Special thanks to Thanos Chatziathanasiou (tchatzi@arx.net) for his help_
