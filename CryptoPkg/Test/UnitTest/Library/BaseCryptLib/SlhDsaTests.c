/** @file
  Application for SLH DSA Primitives Validation.

Copyright (c) 2025, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "TestBaseCryptLib.h"
#include "SlhDsaTestsSignatures.h"

#define DEBUG_PRINT_SLH_DSA 1

STATIC VOID TestPrintBuffer (UINT8 *Buf, UINTN BufSize) {
#if DEBUG_PRINT_SLH_DSA
  for (UINT32 Index = 0; Index < BufSize; Index++) {
      DEBUG ((DEBUG_INFO, "0x%2x ", Buf[Index]));
      if ((Index + 1) % 16 == 0) {
        DEBUG ((DEBUG_INFO, "\n"));
      }
  }
#endif
}

VOID *mSlhDsa;

UNIT_TEST_STATUS
EFIAPI
TestVerifySlhPreReq (
  UNIT_TEST_CONTEXT  Context
  )
{
  SlhDsaTestSignatures *SlhCtx;

  SlhCtx = (SlhDsaTestSignatures *)Context;
  mSlhDsa = SlhNewByNid (SlhCtx->Nid);
  if (mSlhDsa == NULL) {
    return UNIT_TEST_ERROR_TEST_FAILED;
  }

  return UNIT_TEST_PASSED;
}

VOID
EFIAPI
TestVerifySlhCleanUp (
  UNIT_TEST_CONTEXT  Context
  )
{
  if (mSlhDsa != NULL) {
    SlhFree (mSlhDsa);
    mSlhDsa = NULL;
  }
}

UNIT_TEST_STATUS
EFIAPI
TestVerifySlhDsaVerify (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  BOOLEAN              Status;
  SlhDsaTestSignatures *SlhCtx;
  UINT8                PubKey[256];
  UINTN                PubKeySize;

  SlhCtx = (SlhDsaTestSignatures *)Context;

  Status = SlhSetPubKey (mSlhDsa, (UINT8 *)SlhCtx->PublicKey, &SlhCtx->PublicKeyLen);
  UT_ASSERT_TRUE (Status);
  DEBUG ((DEBUG_INFO, "Expected Public Key:\n"));
  TestPrintBuffer ((UINT8 *)SlhCtx->PublicKey, SlhCtx->PublicKeyLen);
  PubKeySize = sizeof (PubKey);
  Status = SlhGetPubKey (mSlhDsa, PubKey, &PubKeySize);
  UT_ASSERT_TRUE (Status);
  UT_ASSERT_EQUAL (SlhCtx->PublicKeyLen, PubKeySize);
  DEBUG ((DEBUG_INFO, "Retrieved Public Key:\n"));
  TestPrintBuffer (PubKey, PubKeySize);
  UT_ASSERT_MEM_EQUAL (SlhCtx->PublicKey, PubKey, PubKeySize);

  Status = SlhDsaVerify (mSlhDsa,
                        (UINT8 *)SlhCtx->Context, SlhCtx->ContextLen,
                        (UINT8 *)SlhCtx->Msg, SlhCtx->MsgLen,
                        (UINT8 *)SlhCtx->Sig, SlhCtx->SigLen);
  UT_ASSERT_TRUE (Status);

  return UNIT_TEST_PASSED;
}


TEST_DESC  mSlhDsaTest[] = {
  //
  // -----Description--------------------------------------Class----------------------Function---------------------------------Pre---------------------Post---------Context
  //
  { "TestVerifySlhDsaVerify()", "CryptoPkg.BaseCryptLib.Slh", TestVerifySlhDsaVerify, TestVerifySlhPreReq, TestVerifySlhCleanUp, &mSlhDsaSha2128sVerifyCtx },
};

UINTN  mSlhDsaTestNum = ARRAY_SIZE (mSlhDsaTest);
