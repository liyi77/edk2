/** @file
  Application for Tls Primitives Validation.

Copyright (c) 2022, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __TLS_TEST_H__
#define __TLS_TEST_H__

#include <PiPei.h>
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/UnitTestLib.h>
#include <Library/PrintLib.h>
#include <Library/BaseCryptLib.h>
#include <Protocol/Tls.h>
#include <IndustryStandard/Tls1.h>
#include <Library/TlsLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
// #include <UnitTestTypes.h>
#include <Library/UnitTestLib.h>
#include <TlsTestCert.h>
// #include <Library/UnitTestAssertLib.h>

#define UNIT_TEST_NAME     "TlsLib Unit Test"
#define UNIT_TEST_VERSION  "1.0"

typedef struct {
  CHAR8                     *Description;
  CHAR8                     *ClassName;
  UNIT_TEST_FUNCTION        Func;
  UNIT_TEST_PREREQUISITE    PreReq;
  UNIT_TEST_CLEANUP         CleanUp;
  UNIT_TEST_CONTEXT         Context;
} TEST_DESC;

typedef struct {
  CHAR8                       *Title;
  CHAR8                       *Package;
  UNIT_TEST_SUITE_SETUP       Sup;
  UNIT_TEST_SUITE_TEARDOWN    Tdn;
  UINTN                       *TestNum;
  TEST_DESC                   *TestDesc;
} SUITE_DESC;

extern UINTN      mHandshakeTestNum;
extern TEST_DESC  mHandshakeTest[];

/** Creates a framework you can use */
EFI_STATUS
EFIAPI
CreateUnitTest (
  IN     CHAR8                       *UnitTestName,
  IN     CHAR8                       *UnitTestVersion,
  IN OUT UNIT_TEST_FRAMEWORK_HANDLE  *Framework
  );

/**
  Validate UEFI-OpenSSL DH Interfaces.

  @retval  EFI_SUCCESS  Validation succeeded.
  @retval  EFI_ABORTED  Validation failed.

**/
EFI_STATUS
ValidateCryptDh (
  VOID
  );

/**
  Validate UEFI-OpenSSL pseudorandom number generator interfaces.

  @retval  EFI_SUCCESS  Validation succeeded.
  @retval  EFI_ABORTED  Validation failed.

**/
EFI_STATUS
ValidateCryptPrng (
  VOID
  );

#endif
