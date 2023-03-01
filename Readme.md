# OpenSsl 3.0 update [POC]

## Overview
According to https://www.OpenSSL.org/policies/releasestrat.html, OpenSSL Version 1.1.1 will be supported until 2023-09-11 (LTS).  
Need to upgrade OpenSsl to 3.0.X before 1.1.1 support stopping.
Initial build with OpenSSL 3.0.X showed significant size increase versus OpenSSL 1.1.1, details as(Build based on MTL):  
|Driver           |   1.1.1    |    3.0     |   percent  |  
|-----------------|------------|------------|------------|
|CryptoDxeFull    |   1014     |    1578    |     57%    |                
|CryptoPei        |   386      |    794     |    106%    |           
|CryptoPeiPreMem  |   31       |    417     |    1245%   |     
|CryptoDxe        |   804      |    1278    |     59%    |  
|CryptoSmm        |   558      |    986     |     77%    |  

This branch is for investigating how to reduce the size increase.
The branch owner: Li Yi <yi1.li@intel.com>

## Latest update
Will update latest result here(Build based on MTL).  
|Driver           |   1.1.1    |    3.0     |   percent  |
|-----------------|------------|------------|------------|           
|CryptoPei        |   386      |    410     |    6%      |           
|CryptoPeiPreMem  |   31       |    31      |    0%      |     
|CryptoDxe        |   804      |    997     |    24%     |  
|CryptoSmm        |   558      |    712     |    27%     |  

## Why size increased

New module : Provider, Encode, Decode  
More complex API, There will be two code paths supporting 1.1.1 legacy and 3.0 provider at the same time.  

## How to reduce size
### 1.Cut Provider
As CryptoPkg\Library\OpensslLib\OpensslStub\uefiprov.c

### 2.Remove unnecessary module 
SM2, SM3, MD5...
#### Risk:
1. SM3  
Supported in TCG2(MdePkg\Include\Protocol\Tcg2Protocol.h) and TPM20(MdePkg\Include\IndustryStandard\Tpm20.h)  
2. MD5  
Dependency as:
MD5 --> PEM --> CryptoPem(Ec\RsaGetPrivateKeyFromPem): used in Pkcs7Sign and Unit test  
         |----> Pkcs7Sign(the priv key of input is PEM encoded): Just used in Unit test

### 3.Disable algorithm auto init
Add -DOPENSSL_NO_AUTOALGINIT will disable OpenSsl from adding all digests and ciphers at initialization time.  
Can reduce the size by ~20KB.  
#### Risk:
OPENSSL_NO_AUTOALGINIT Will break PKCS7, Authenticode and Ts due to OpenSsl bug:  
https://github.com/openssl/openssl/issues/20221  
Currently only available when compiling PEI.

### 4.Cut Name/NID mapping
There are some unreasonably huge arrays(~110KB) in the obj_dat.h and obj_xref.h, like:  
```static const unsigned char so[8076]```  
```static const ASN1_OBJECT nid_objs[NUM_NID] ```  
Removing unnecessary data can reduce the size by ~50KB.  
#### Risk:
1. DXE and SMM use more functions than PEI, so can only reduce fewer size.  
2. Need a detailed script or readme. The best way is to automatically cut through openssl config, raised issue in community:  
https://github.com/openssl/openssl/issues/20260

### 5.Hash API downgrade (for PeiPreMem)
High level API (EVP) will introduce provider and NID mapping which can increase size extremely.  
This can bring the PeiPreMem size down to 31KB.  
Commit: 9f907088faaa00838915b32d1a184fd0c501303e CryptoPkg: downgrade hash all  

### 6.Remove EN/DECODER provider
Will reduce the size by ~70KB, but needs to ensure that all API works properly in the legacy code path,  
so that we can remove the entire EN/DECODER module.  
This needs to change the openssl code, such as:  
https://github.com/liyi77/openssl/commit/d1b07663c40c5fccfa60fcd2fea9620819e8e5d5
#### Risk:
This will become workaround if openssl doesn't accept such changes.  

### 7.Cut unnecessary API in OpenSsl
https://github.com/liyi77/openssl/commits/openssl-3.0-POC  
Such as:  
remove x509 print function  
remove unused ras ameth  
remove unused x509 extentions  
...  
#### Risk:
This is workaround.

## Timeline
Target for 2023 Q1