/** @file
  This is defines the tests that will run on TlsLib

  Copyright (c) Microsoft Corporation.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/
#include "TestTlsLib.h"

SUITE_DESC  mSuiteDesc[] = {
  //
  // Title--------------------------Package-------------------Sup--Tdn----TestNum------------TestDesc
  //
  { "Handshake verify tests",     "CryptoPkg.TlsLib",        NULL, NULL, &mHandshakeTestNum,   mHandshakeTest},
};

EFI_STATUS
EFIAPI
CreateUnitTest (
  IN     CHAR8                       *UnitTestName,
  IN     CHAR8                       *UnitTestVersion,
  IN OUT UNIT_TEST_FRAMEWORK_HANDLE  *Framework
  )
{
  EFI_STATUS  Status;
  UINTN       SuiteIndex;
  UINTN       TestIndex;

  if ((Framework == NULL) || (UnitTestVersion == NULL) || (UnitTestName == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  Status = EFI_SUCCESS;
  //
  // Start setting up the test framework for running the tests.
  //
  Status = InitUnitTestFramework (Framework, UnitTestName, gEfiCallerBaseName, UnitTestVersion);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed in InitUnitTestFramework. Status = %r\n", Status));
    goto EXIT;
  }

  for (SuiteIndex = 0; SuiteIndex < ARRAY_SIZE (mSuiteDesc); SuiteIndex++) {
    UNIT_TEST_SUITE_HANDLE  Suite = NULL;
    Status = CreateUnitTestSuite (&Suite, *Framework, mSuiteDesc[SuiteIndex].Title, mSuiteDesc[SuiteIndex].Package, mSuiteDesc[SuiteIndex].Sup, mSuiteDesc[SuiteIndex].Tdn);
    if (EFI_ERROR (Status)) {
      Status = EFI_OUT_OF_RESOURCES;
      goto EXIT;
    }

    for (TestIndex = 0; TestIndex < *mSuiteDesc[SuiteIndex].TestNum; TestIndex++) {
      AddTestCase (Suite, (mSuiteDesc[SuiteIndex].TestDesc + TestIndex)->Description, (mSuiteDesc[SuiteIndex].TestDesc + TestIndex)->ClassName, (mSuiteDesc[SuiteIndex].TestDesc + TestIndex)->Func, (mSuiteDesc[SuiteIndex].TestDesc + TestIndex)->PreReq, (mSuiteDesc[SuiteIndex].TestDesc + TestIndex)->CleanUp, (mSuiteDesc[SuiteIndex].TestDesc + TestIndex)->Context);
    }
  }

EXIT:
  return Status;
}
