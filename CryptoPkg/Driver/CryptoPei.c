/** @file
  Installs the EDK II Crypto PPI.  If this PEIM is dispatched before memory is
  discovered, the RegisterForShadow() feature is used to reload this PEIM into
  memory after memory is discovered.

  Copyright (C) Microsoft Corporation. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiPei.h>
#include <Library/PeiServicesLib.h>
#include <Library/DebugLib.h>
#include <Ppi/Crypto.h>

extern CONST EDKII_CRYPTO_PROTOCOL  mEdkiiCrypto;

CONST EFI_PEI_PPI_DESCRIPTOR  mEdkiiCryptoPpiList = {
  (EFI_PEI_PPI_DESCRIPTOR_PPI | EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST),
  &gEdkiiCryptoPpiGuid,
  (EDKII_CRYPTO_PPI *)&mEdkiiCrypto
};

/**
Entry to CryptoPeiEntry.

@param FileHandle   The image handle.
@param PeiServices  The PEI services table.

@retval Status      From internal routine or boot object, should not fail
**/
EFI_STATUS
EFIAPI
CryptoPeiEntry (
  IN       EFI_PEI_FILE_HANDLE  FileHandle,
  IN CONST EFI_PEI_SERVICES     **PeiServices
  )
{
  EFI_STATUS              Status;
  VOID                    *MemoryDiscoveredPpi;
  EDKII_CRYPTO_PPI        *EdkiiCryptoPpi;
  EFI_PEI_PPI_DESCRIPTOR  *EdkiiCryptoPpiDescriptor;

  //
  // Not all Open SSL services support XIP due to use of global variables.
  // Use gEfiPeiMemoryDiscoveredPpiGuid to detect Pre-Mem and Post-Mem and
  // always shadow this module in memory in Post-Mem.
  //
  Status = PeiServicesLocatePpi (
             &gEfiPeiMemoryDiscoveredPpiGuid,
             0,
             NULL,
             (VOID **)&MemoryDiscoveredPpi
             );
  if (Status == EFI_NOT_FOUND) {
    //
    // CryptoPei is dispatched before gEfiPeiMemoryDiscoveredPpiGuid
    //
    Status = PeiServicesRegisterForShadow (FileHandle);
    ASSERT_EFI_ERROR (Status);
    if (!EFI_ERROR (Status)) {
      //
      // First CryptoPpi installation. CryptoPei could come from memory or flash
      // it will be re-installed after gEfiPeiMemoryDiscoveredPpiGuid
      //
      DEBUG ((DEBUG_INFO, "CryptoPeiEntry: Install Pre-Memory Crypto PPI\n"));
      Status = PeiServicesInstallPpi (&mEdkiiCryptoPpiList);
      ASSERT_EFI_ERROR (Status);
    }
  } else if (Status == EFI_SUCCESS) {
    //
    // CryptoPei is dispatched after gEfiPeiMemoryDiscoveredPpiGuid
    //
    Status = PeiServicesLocatePpi (
               &gEdkiiCryptoPpiGuid,
               0,
               &EdkiiCryptoPpiDescriptor,
               (VOID **)&EdkiiCryptoPpi
               );
    if (!EFI_ERROR (Status)) {
      //
      // CryptoPei was also dispatched before gEfiPeiMemoryDiscoveredPpiGuid
      //
      DEBUG ((DEBUG_INFO, "CryptoPeiEntry: ReInstall Post-Memmory Crypto PPI\n"));
      Status = PeiServicesReInstallPpi (
                 EdkiiCryptoPpiDescriptor,
                 &mEdkiiCryptoPpiList
                 );
      ASSERT_EFI_ERROR (Status);
    } else {
      DEBUG ((DEBUG_INFO, "CryptoPeiEntry: Install Post-Memmory Crypto PPI\n"));
      Status = PeiServicesInstallPpi (&mEdkiiCryptoPpiList);
    }
  } else {
    ASSERT_EFI_ERROR (Status);
  }

  // TEST GCC ASM HERE!
  DEBUG ((DEBUG_INFO, "CryptoPeiEntry: TEST GCC ASM HERE!\n"));
  DEBUG ((DEBUG_INFO, "CryptoPeiEntry: TEST GCC ASM HERE!\n"));

  UINT64  UDivisor = 46887;
  UINT64  UDividend = 2577776;
  if (PeiServices == NULL) {
      UDivisor = 1;
      UDividend = 1;
  }
  UINT64  UReturn;
  INT64   SReturn;
  UINT64  UReturn2;


  DEBUG ((DEBUG_INFO, "TEST BEGIN: UDivisor = 46887  UDividend = 2577776\n"));
  DEBUG ((DEBUG_INFO, "TEST BEGIN: RightDivRet = 54  RightModRet = 45878\n"));

  //undefined reference to `__umoddi3'
  UReturn = UDividend % 46887;
  DEBUG ((DEBUG_INFO, "CASE1: __umoddi3\n"));
  DEBUG ((DEBUG_INFO, "CASE1: UReturn = UDividend Mod UDivisor\n"));
  DEBUG ((DEBUG_INFO, "CASE1: UReturn = %d \n", UReturn));

  //undefined reference to `__udivdi3'
  UReturn = UDividend / 46887;
  DEBUG ((DEBUG_INFO, "CASE2: __udivdi3\n"));
  DEBUG ((DEBUG_INFO, "CASE2: UReturn = UDividend Div UDivisor\n"));
  DEBUG ((DEBUG_INFO, "CASE2: UReturn = %d \n", UReturn));

  //undefined reference to `__udivmoddi4'
  UReturn = UDividend / UDivisor;
  UReturn2 = UDividend % UDivisor;
  DEBUG ((DEBUG_INFO, "CASE3: __udivmoddi4\n"));
  DEBUG ((DEBUG_INFO, "CASE3: UReturn = UDividend Div UDivisor\n"));
  DEBUG ((DEBUG_INFO, "CASE3: UReturn2 = UDividend Mod UDivisor\n"));
  DEBUG ((DEBUG_INFO, "CASE3: UReturn = %d \n", UReturn));
  DEBUG ((DEBUG_INFO, "CASE3: UReturn2 = %d \n", UReturn2));

  //undefined reference to `__divdi3'
  SReturn = (INT64)UDividend / 46887;
  DEBUG ((DEBUG_INFO, "CASE4: __divdi3\n"));
  DEBUG ((DEBUG_INFO, "CASE4: SReturn = SDividend Div UDivisor\n"));
  DEBUG ((DEBUG_INFO, "CASE4: SReturn = %d \n", SReturn));

  DEBUG ((DEBUG_INFO, "TEST STOP\n"));
  CpuDeadLoop ();

  return Status;
}
