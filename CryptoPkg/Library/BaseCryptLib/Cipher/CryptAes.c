/** @file
  AES Wrapper Implementation over OpenSSL.

Copyright (c) 2010 - 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "InternalCryptLib.h"
#include <openssl/evp.h>

/**
  Retrieves the size, in bytes, of the context buffer required for AES operations.

  @return  The size, in bytes, of the context buffer required for AES operations.

**/
UINTN
EFIAPI
AesGetContextSize (
  VOID
  )
{
  //
  // AES uses different key contexts for encryption and decryption, so here memory
  // for 2 copies of AES_KEY is allocated.
  //
  return (UINTN)(4 + 256);
}

/**
  Initializes user-supplied memory as AES context for subsequent use.

  This function initializes user-supplied memory pointed by AesContext as AES context.
  In addition, it sets up all AES key materials for subsequent encryption and decryption
  operations.
  There are 3 options for key length, 128 bits, 192 bits, and 256 bits.

  If AesContext is NULL, then return FALSE.
  If Key is NULL, then return FALSE.
  If KeyLength is not valid, then return FALSE.

  @param[out]  AesContext  Pointer to AES context being initialized.
  @param[in]   Key         Pointer to the user-supplied AES key.
  @param[in]   KeyLength   Length of AES key in bits.

  @retval TRUE   AES context initialization succeeded.
  @retval FALSE  AES context initialization failed.

**/
BOOLEAN
EFIAPI
AesInit (
  OUT  VOID         *AesContext,
  IN   CONST UINT8  *Key,
  IN   UINTN        KeyLength
  )
{
  //
  // Check input parameters.
  //
  if ((AesContext == NULL) || (Key == NULL) || ((KeyLength != 128) && (KeyLength != 192) && (KeyLength != 256))) {
    return FALSE;
  }

  //
  // Initialize AES encryption & decryption key schedule.
  //

  *(UINT8 *)AesContext = (UINT8)KeyLength;
  CopyMem ((UINT8 *)AesContext, (UINT8 *)&KeyLength, 4);
  CopyMem ((UINT8 *)AesContext + 4, Key, KeyLength);

  return TRUE;
}

/**
  Performs AES encryption on a data buffer of the specified size in CBC mode.

  This function performs AES encryption on data buffer pointed by Input, of specified
  size of InputSize, in CBC mode.
  InputSize must be multiple of block size (16 bytes). This function does not perform
  padding. Caller must perform padding, if necessary, to ensure valid input data size.
  Initialization vector should be one block size (16 bytes).
  AesContext should be already correctly initialized by AesInit(). Behavior with
  invalid AES context is undefined.

  If AesContext is NULL, then return FALSE.
  If Input is NULL, then return FALSE.
  If InputSize is not multiple of block size (16 bytes), then return FALSE.
  If Ivec is NULL, then return FALSE.
  If Output is NULL, then return FALSE.

  @param[in]   AesContext  Pointer to the AES context.
  @param[in]   Input       Pointer to the buffer containing the data to be encrypted.
  @param[in]   InputSize   Size of the Input buffer in bytes.
  @param[in]   Ivec        Pointer to initialization vector.
  @param[out]  Output      Pointer to a buffer that receives the AES encryption output.

  @retval TRUE   AES encryption succeeded.
  @retval FALSE  AES encryption failed.

**/
BOOLEAN
EFIAPI
AesCbcEncrypt (
  IN   VOID         *AesContext,
  IN   CONST UINT8  *Input,
  IN   UINTN        InputSize,
  IN   CONST UINT8  *Ivec,
  OUT  UINT8        *Output
  )
{
  EVP_CIPHER_CTX    *Ctx;
  CONST EVP_CIPHER  *Cipher;
  UINTN             TempOutSize;
  BOOLEAN           RetValue;
  UINT8             *Key;
  UINTN             KeySize;

  if (InputSize > INT_MAX) {
    return FALSE;
  }

  KeySize = *(UINT32 *)AesContext;
  switch (KeySize) {
    case 16:
      Cipher = EVP_aes_128_cbc ();
      break;
    case 24:
      Cipher = EVP_aes_192_cbc ();
      break;
    case 32:
      Cipher = EVP_aes_256_cbc ();
      break;
    default:
      return FALSE;
  }

  Key = (UINT8 *)AesContext + 4;
  Ctx = EVP_CIPHER_CTX_new ();
  if (Ctx == NULL) {
    return FALSE;
  }

  RetValue = (BOOLEAN)EVP_EncryptInit_ex (Ctx, Cipher, NULL, NULL, NULL);
  if (!RetValue) {
    goto Done;
  }

  RetValue = (BOOLEAN)EVP_EncryptInit_ex (Ctx, NULL, NULL, Key, Ivec);
  if (!RetValue) {
    goto Done;
  }

  RetValue = (BOOLEAN)EVP_EncryptUpdate (Ctx, Output, (INT32 *)&TempOutSize, Input, (INT32)InputSize);
  if (!RetValue) {
    goto Done;
  }

  RetValue = (BOOLEAN)EVP_EncryptFinal_ex (Ctx, Output, (INT32 *)&TempOutSize);
  if (!RetValue) {
    goto Done;
  }

Done:
  EVP_CIPHER_CTX_free (Ctx);
  return RetValue;
}

/**
  Performs AES decryption on a data buffer of the specified size in CBC mode.

  This function performs AES decryption on data buffer pointed by Input, of specified
  size of InputSize, in CBC mode.
  InputSize must be multiple of block size (16 bytes). This function does not perform
  padding. Caller must perform padding, if necessary, to ensure valid input data size.
  Initialization vector should be one block size (16 bytes).
  AesContext should be already correctly initialized by AesInit(). Behavior with
  invalid AES context is undefined.

  If AesContext is NULL, then return FALSE.
  If Input is NULL, then return FALSE.
  If InputSize is not multiple of block size (16 bytes), then return FALSE.
  If Ivec is NULL, then return FALSE.
  If Output is NULL, then return FALSE.

  @param[in]   AesContext  Pointer to the AES context.
  @param[in]   Input       Pointer to the buffer containing the data to be encrypted.
  @param[in]   InputSize   Size of the Input buffer in bytes.
  @param[in]   Ivec        Pointer to initialization vector.
  @param[out]  Output      Pointer to a buffer that receives the AES encryption output.

  @retval TRUE   AES decryption succeeded.
  @retval FALSE  AES decryption failed.

**/
BOOLEAN
EFIAPI
AesCbcDecrypt (
  IN   VOID         *AesContext,
  IN   CONST UINT8  *Input,
  IN   UINTN        InputSize,
  IN   CONST UINT8  *Ivec,
  OUT  UINT8        *Output
  )
{
  EVP_CIPHER_CTX    *Ctx;
  CONST EVP_CIPHER  *Cipher;
  UINTN             TempOutSize;
  BOOLEAN           RetValue;
  UINT8             *Key;
  UINTN             KeySize;

  if (InputSize > INT_MAX) {
    return FALSE;
  }

  KeySize = *(UINT32 *)AesContext;
  switch (KeySize) {
    case 16:
      Cipher = EVP_aes_128_cbc ();
      break;
    case 24:
      Cipher = EVP_aes_192_cbc ();
      break;
    case 32:
      Cipher = EVP_aes_256_cbc ();
      break;
    default:
      return FALSE;
  }

  Key = (UINT8 *)AesContext + 4;
  Ctx = EVP_CIPHER_CTX_new ();
  if (Ctx == NULL) {
    return FALSE;
  }

  RetValue = (BOOLEAN)EVP_DecryptInit_ex (Ctx, Cipher, NULL, NULL, NULL);
  if (!RetValue) {
    goto Done;
  }

  RetValue = (BOOLEAN)EVP_DecryptInit_ex (Ctx, NULL, NULL, Key, Ivec);
  if (!RetValue) {
    goto Done;
  }

  RetValue = (BOOLEAN)EVP_DecryptUpdate (Ctx, Output, (INT32 *)&TempOutSize, Input, (INT32)InputSize);
  if (!RetValue) {
    goto Done;
  }

  RetValue = (BOOLEAN)EVP_DecryptFinal_ex (Ctx, Output, (INT32 *)&TempOutSize);
  if (!RetValue) {
    goto Done;
  }

Done:
  EVP_CIPHER_CTX_free (Ctx);
  return RetValue;
}
