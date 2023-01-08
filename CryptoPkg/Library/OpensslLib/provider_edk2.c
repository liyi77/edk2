/** @file
  UEFI Openssl provider implementation.

  Copyright (c) 2022, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <openssl/core.h>
#include "provider_local.h"

OSSL_provider_init_fn ossl_uefi_provider_init;
OSSL_provider_init_fn ossl_base_provider_init;
OSSL_provider_init_fn ossl_null_provider_init;
OSSL_provider_init_fn ossl_default_provider_init;
const OSSL_PROVIDER_INFO ossl_predefined_providers[] = {
    // { "default", NULL, ossl_uefi_provider_init, NULL, 1 },
    { "default", NULL, ossl_default_provider_init, NULL, 1 },
    { "base", NULL, ossl_base_provider_init, NULL, 0 },
    { "null", NULL, ossl_null_provider_init, NULL, 0 },
    { NULL, NULL, NULL, NULL, 0 }
};
