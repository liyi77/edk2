/** @file
  Application for Handshake Primitives Validation.

Copyright (c) 2022, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "TestTlsLib.h"

#define DEBUG_PRINT_TLS_HANDSHAKE_MESSAGE 0

VOID TestPrintBuffer (UINT8 *Buf, UINTN BufSize) {
#if DEBUG_PRINT_TLS_HANDSHAKE_MESSAGE
  for (UINT32 Index = 0; Index < BufSize; Index++) {
      DEBUG ((
        DEBUG_INFO,
        "0x%2x ", Buf[Index]));
      if ((Index + 1) % 16 == 0) {
        DEBUG ((
          DEBUG_INFO,
          "\n"));
      }
  }
#endif
}

VOID *TestTlsCtxClient   = NULL;
VOID *TestTlsCtxServer   = NULL;
VOID *TestTlsConnClient  = NULL;
VOID *TestTlsConnServer  = NULL;

UNIT_TEST_STATUS
EFIAPI
TestTlsHandshakePreReq (
  UNIT_TEST_CONTEXT  Context
  )
{
  UINT16 Ciphers[] = {0xC030, 0xC02C, 0xC02B};
  // UINT32 Curve = TlsEcNamedCurveSecp384r1;
  // UINT8  SignAlgoList[] = {2, TlsHashAlgoSha384, TlsSignatureAlgoEcdsa};
  if (!TlsInitialize ()) {
    return UNIT_TEST_ERROR_TEST_FAILED;
  }
  // Use minimal version of TLS 1.2
  TestTlsCtxClient  = TlsCtxNew (0x3, 0x03);
  TestTlsCtxServer  = TlsCtxNew (0x3, 0x03);
  if ((TestTlsCtxClient == NULL) || (TestTlsCtxServer == NULL)) {
    return UNIT_TEST_ERROR_TEST_FAILED;
  }

  TestTlsConnClient = TlsNew (TestTlsCtxClient);
  TestTlsConnServer = TlsNew (TestTlsCtxServer);
  if ((TestTlsConnClient == NULL) || (TestTlsConnServer == NULL)) {
    return UNIT_TEST_ERROR_TEST_FAILED;
  }

  TlsSetConnectionEnd (TestTlsConnClient, FALSE);
  TlsSetConnectionEnd (TestTlsConnServer, TRUE);
  TlsSetVerify (TestTlsConnClient, EFI_TLS_VERIFY_PEER);
  if (TlsSetVersion (TestTlsConnClient, 0x03, 0x03) != EFI_SUCCESS ||
      TlsSetVersion (TestTlsConnServer, 0x03, 0x03) != EFI_SUCCESS ||
      TlsSetCaCertificate (TestTlsConnClient, TestTlsEcCA, sizeof (TestTlsEcCA)) != EFI_SUCCESS ||
      TlsSetCaCertificate (TestTlsConnServer, TestTlsEcCA, sizeof (TestTlsEcCA)) != EFI_SUCCESS ||
      //TlsSetHostPublicCert (TestTlsConnServer, TestTlsEcServer, sizeof (TestTlsEcServer)) != EFI_SUCCESS    ||
      // TlsSetHostPublicCert (TestTlsConnServer, TestTlsEcServerExpired, sizeof (TestTlsEcServerExpired)) != EFI_SUCCESS    ||
      // TlsSetHostPrivateKey (TestTlsConnServer, TestTlsEcServer, sizeof (TestTlsEcServer)) != EFI_SUCCESS ||
      TlsSetCipherList (TestTlsConnClient, Ciphers, 3) != EFI_SUCCESS
      // TlsSetCipherList (TestTlsConnServer, Ciphers, 2) != EFI_SUCCESS ||
      // TlsSetSignatureAlgoList (TestTlsConnClient, SignAlgoList, sizeof (SignAlgoList)) != EFI_SUCCESS ||
      // TlsSetEcCurve (TestTlsConnClient, (UINT8 *) &Curve, sizeof (UINT32)) != EFI_SUCCESS ||
      // TlsSetSignatureAlgoList (TestTlsConnServer, SignAlgoList, sizeof (SignAlgoList)) != EFI_SUCCESS ||
      // TlsSetEcCurve (TestTlsConnServer, (UINT8 *) &Curve, sizeof (UINT32)) != EFI_SUCCESS ||
      // TlsSetHostPrivateKey (TestTlsConnServer, TestTlsEcServerKey, sizeof (TestTlsEcServerKey)) != EFI_SUCCESS
      ) {
    return UNIT_TEST_ERROR_TEST_FAILED;
  }

  return UNIT_TEST_PASSED;
}

VOID
EFIAPI
TestTlsHandshakeCleanUp (
  UNIT_TEST_CONTEXT  Context
  )
{
  TlsConnFree (TestTlsCtxClient);
  TlsConnFree (TestTlsCtxServer);
  TlsCtxFree (TestTlsConnClient);
  TlsCtxFree (TestTlsConnServer);
}

UNIT_TEST_STATUS
EFIAPI
TestTlsHandshake (
  UNIT_TEST_CONTEXT  Context
  )
{
  // BOOLEAN  Status;
  UINT8 ClientM[65535];
  UINTN ClientMSize;
  UINT8 ServerM[65535];
  UINTN ServerMSize;

  //Test Valid Certificate
  DEBUG ((DEBUG_INFO, "### Valid Certificate Test Start...\n"));
  ClientMSize = 65535;
  ServerMSize = 65535;
  //Client Hello
  if (TlsDoHandshake (TestTlsConnClient, NULL, 0, ClientM, &ClientMSize) != EFI_SUCCESS) {
    DEBUG ((DEBUG_INFO, "Error: At Client Hello\n"));
    return UNIT_TEST_ERROR_TEST_FAILED;
  };
  DEBUG ((DEBUG_INFO, "### Client Hello Message:\n"));
  TestPrintBuffer (ClientM, ClientMSize);

  //Set Valid Certificate
  if (TlsSetHostPublicCert (TestTlsConnServer, TestTlsEcServer, sizeof (TestTlsEcServer))
                            != EFI_SUCCESS
      || TlsSetHostPrivateKey (TestTlsConnServer, TestTlsEcServerKey, sizeof (TestTlsEcServerKey))
                            != EFI_SUCCESS) {
     DEBUG ((DEBUG_INFO, "Error: At setting valid certificate\n"));
     return UNIT_TEST_ERROR_TEST_FAILED;
  }
  //Server Hello
  if (TlsDoHandshake (TestTlsConnServer, ClientM, ClientMSize, ServerM, &ServerMSize) != EFI_SUCCESS) {
    DEBUG ((DEBUG_INFO, "Error: At Server Hello\n"));
    return UNIT_TEST_ERROR_TEST_FAILED;
  };
  DEBUG ((DEBUG_INFO, "### Server Hello Message:\n"));
  TestPrintBuffer (ServerM, ServerMSize);

  //Verify Cert
  ClientMSize = 65535;
  if (TlsDoHandshake (TestTlsConnClient, ServerM, ServerMSize, ClientM, &ClientMSize) != EFI_SUCCESS) {
    DEBUG ((DEBUG_INFO, "### Check Error Log:\n"));
    DEBUG ((DEBUG_INFO, "### F : SSL_F_TLS_PROCESS_SERVER_CERTIFICATE := 367 := 0x16f\n"));
    DEBUG ((DEBUG_INFO, "### R : SSL_R_CERTIFICATE_VERIFY_FAILED := 134 := 0x86\n"));
    DEBUG ((DEBUG_INFO, "### If Error Code Matched, Then:\n"));
    DEBUG ((DEBUG_INFO, "Error: At Client Key Exchange, Valid Certificate Should Pass This Test\n"));
    return UNIT_TEST_ERROR_TEST_FAILED;
  };
  DEBUG ((DEBUG_INFO, "### Client Verify Message:\n"));
  TestPrintBuffer (ClientM, ClientMSize);
  DEBUG ((DEBUG_INFO, "### Valid Certificate Test Passed\n"));

  if (TlsShutdown (TestTlsConnClient) != EFI_SUCCESS
      || TlsShutdown (TestTlsConnServer) != EFI_SUCCESS) {
    DEBUG ((DEBUG_INFO, "Error: At Conn Shutdown\n"));
    return UNIT_TEST_ERROR_TEST_FAILED;        
  }

  //Test Expired Certificate
  DEBUG ((DEBUG_INFO, "### Expired Certificate Test Start...\n"));
  ClientMSize = 65535;
  ServerMSize = 65535;
  //Client Hello
  if (TlsDoHandshake (TestTlsConnClient, NULL, 0, ClientM, &ClientMSize) != EFI_SUCCESS) {
    DEBUG ((DEBUG_INFO, "Error: At Client Hello\n"));
    return UNIT_TEST_ERROR_TEST_FAILED;
  };
  DEBUG ((DEBUG_INFO, "### Client Hello Message:\n"));
  TestPrintBuffer (ClientM, ClientMSize);

  //Test Expired Certificate
  if (TlsSetHostPublicCert (TestTlsConnServer, TestTlsEcServerExpired, sizeof (TestTlsEcServerExpired))
                          != EFI_SUCCESS
      || TlsSetHostPrivateKey (TestTlsConnServer, TestTlsEcServerKey, sizeof (TestTlsEcServerKey))
                          != EFI_SUCCESS) {
     DEBUG ((DEBUG_INFO, "Error: At Setting Expired Certificate\n"));
     return UNIT_TEST_ERROR_TEST_FAILED;
  }
  //Server Hello
  if (TlsDoHandshake (TestTlsConnServer, ClientM, ClientMSize, ServerM, &ServerMSize) != EFI_SUCCESS) {
    DEBUG ((DEBUG_INFO, "Error: At Server Hello\n"));
    return UNIT_TEST_ERROR_TEST_FAILED;
  };
  DEBUG ((DEBUG_INFO, "### Server Hello Message:\n"));
  TestPrintBuffer (ServerM, ServerMSize);

  //Verify Cert
  ClientMSize = 65535;
  if (TlsDoHandshake (TestTlsConnClient, ServerM, ServerMSize, ClientM, &ClientMSize) != EFI_ABORTED) {
    DEBUG ((DEBUG_INFO, "Error: At Client Key Exchange, Expired Certificate Should Not Pass This Test\n"));
    return UNIT_TEST_ERROR_TEST_FAILED;
  };

  DEBUG ((DEBUG_INFO, "### Check Error Log:\n"));
  DEBUG ((DEBUG_INFO, "### F : SSL_F_TLS_PROCESS_SERVER_CERTIFICATE := 367 := 0x16f\n"));
  DEBUG ((DEBUG_INFO, "### R : SSL_R_CERTIFICATE_VERIFY_FAILED := 134 := 0x86\n"));
  DEBUG ((DEBUG_INFO, "### If Error Code Matched, Then:\n"));
  DEBUG ((DEBUG_INFO, "### Expired Certificate Test Passed\n"));

  // UT_ASSERT_TRUE (Status);

  // F : SSL_F_TLS_PROCESS_SERVER_CERTIFICATE := 367 := 0x16f
  // R : SSL_R_CERTIFICATE_VERIFY_FAILED := 134 := 0x86
  return UNIT_TEST_PASSED;
}

TEST_DESC  mHandshakeTest[] = {
  //
  // -----Description-----------------Class------------------Function----Pre----Post----Context
  //
  { "TestVerifyHandshake()", "CryptoPkg.TlsLib", TestTlsHandshake, TestTlsHandshakePreReq, TestTlsHandshakeCleanUp, NULL },
};

UINTN  mHandshakeTestNum = ARRAY_SIZE (mHandshakeTest);
