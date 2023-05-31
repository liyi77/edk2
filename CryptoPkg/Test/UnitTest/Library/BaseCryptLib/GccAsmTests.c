/** @file
  Application for Gcc Asm Primitives Validation.

Copyright (c) 2023, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "TestBaseCryptLib.h"

UINT64  UDivisor = 0x5A5A;  //23130
UINT64  UDividend = 0xA5A5A5A5A5A5; //182130867283365
UINT64  URemainder;
UINT64  UReturn;
INT64   SReturn;
UINT64  RightDivRet = 7874226860;
UINT64  RightModRet = 11565;

UINT64 	__testudivmoddi4 (UINT64 num, UINT64 den, UINT64 *rem_p);
UINT64  __testudivdi3(UINT64 a, UINT64 b);
UINT64  __testumoddi3(UINT64 a, UINT64 b);
INT64   __testdivdi3(INT64 a, INT64 b);

UNIT_TEST_STATUS
EFIAPI
TestVerifyGccAsm (
  UNIT_TEST_CONTEXT  Context
  )
{
    UReturn = UDividend % UDivisor;
    UT_ASSERT_EQUAL (RightModRet, UReturn);
    UReturn = UDividend / UDivisor;
    UT_ASSERT_EQUAL (RightDivRet, UReturn);

    UReturn = __testumoddi3 (UDividend, UDivisor);
    UT_ASSERT_EQUAL (RightModRet, UReturn);

    UReturn = __testudivdi3 (UDividend, UDivisor);
    UT_ASSERT_EQUAL (RightDivRet, UReturn);

    UReturn = __testudivmoddi4 (UDividend, UDivisor, &URemainder);
    UT_ASSERT_EQUAL (RightModRet, URemainder);
    UT_ASSERT_EQUAL (RightDivRet, UReturn);

    SReturn = __testdivdi3 ((INT64) UDividend, (INT64) UDivisor);
    UT_ASSERT_EQUAL (RightDivRet, SReturn);

    return UNIT_TEST_PASSED;
}

TEST_DESC  mGccAsmTest[] = {
  //
  // -----Description----------------Class---------------------Function---------------Pre------------------Post------------Context
  //
  { "TestVerifyGccAsm()", "CryptoPkg.BaseCryptLib.Hash", TestVerifyGccAsm, NULL, NULL, NULL },
};

UINTN  mGccAsmTestNum = ARRAY_SIZE (mGccAsmTest);
