/** @file
  Elliptic Curve and ECDH API implementation based on OpenSSL

  Copyright (c) 2022, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Base.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseCryptLib.h>
#include <Library/DebugLib.h>
#include <Library/PcdLib.h>

#include <openssl/opensslv.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/ec.h>

// =====================================================================================
//    Basic Elliptic Curve Primitives
// =====================================================================================

/**
  Return the Nid of certain ECC group.

  @param[in]  Group  Identifying number for the ECC group (IANA "Group
                     Description" attribute registry for RFC 2409).

  @retval !=-1    On success.
  @retval -1      ECC group not supported.
**/
STATIC
INT32
CryptoNidToOpensslNid (
  IN UINTN CryptoNid
)
{
  INT32  Nid;

  switch (CryptoNid) {
    case CRYPTO_NID_SECP256R1:
      Nid = NID_X9_62_prime256v1;
      break;
    case CRYPTO_NID_SECP384R1:
      Nid = NID_secp384r1;
      break;
    case CRYPTO_NID_SECP521R1:
      Nid = NID_secp521r1;
      break;
    default:
      return -1;
  }

  return Nid;
}

/**
  Initialize new opaque EcGroup object. This object represents an EC curve and
  and is used for calculation within this group. This object should be freed
  using EcGroupFree() function.

  @param[in]  Group  Identifying number for the ECC group (IANA "Group
                     Description" attribute registry for RFC 2409).

  @retval EcGroup object  On success.
  @retval NULL            On failure.
**/
VOID *
EFIAPI
EcGroupInit (
  IN UINTN  CryptoNid
  )
{
  INT32  Nid;

  Nid = CryptoNidToOpensslNid (CryptoNid);

  if (Nid < 0) {
    return NULL;
  }

  return EC_GROUP_new_by_curve_name (Nid);
}

STATIC
INT32
EFIAPI
EcGroupGetPrimeBytes (
  IN VOID *EcGroup
  )
{
  // EC_GROUP_get_degree() will return the bits number of prime in EcGroup.
  return (EC_GROUP_get_degree (EcGroup) + 7) / 8;
}

/**
  Get EC curve parameters. While elliptic curve equation is Y^2 mod P = (X^3 + AX + B) Mod P.
  This function will set the provided Big Number objects  to the corresponding
  values. The caller needs to make sure all the "out" BigNumber parameters
  are properly initialized.

  @param[in]  EcGroup    EC group object.
  @param[out] BnPrime    Group prime number.
  @param[out] BnA        A coefficient.
  @param[out] BnB        B coefficient..
  @param[in]  BnCtx      BN context.

  @retval EFI_SUCCESS        On success.
  @retval EFI_PROTOCOL_ERROR On failure.
**/
EFI_STATUS
EFIAPI
EcGroupGetCurve (
  IN CONST VOID  *EcGroup,
  OUT VOID       *BnPrime,
  OUT VOID       *BnA,
  OUT VOID       *BnB,
  IN VOID        *BnCtx
  )
{
  return EC_GROUP_get_curve (EcGroup, BnPrime, BnA, BnB, BnCtx) ?
         EFI_SUCCESS : EFI_PROTOCOL_ERROR;
}

/**
  Get EC group order.
  This function will set the provided Big Number object to the corresponding
  value. The caller needs to make sure that the "out" BigNumber parameter
  is properly initialized.

  @param[in]  EcGroup   EC group object.
  @param[out] BnOrder   Group prime number.

  @retval EFI_SUCCESS        On success.
  @retval EFI_PROTOCOL_ERROR On failure.
**/
EFI_STATUS
EFIAPI
EcGroupGetOrder (
  IN VOID   *EcGroup,
  OUT VOID  *BnOrder
  )
{
  return EC_GROUP_get_order (EcGroup, BnOrder, NULL) ?
         EFI_SUCCESS : EFI_PROTOCOL_ERROR;
}

/**
  Free previously allocated EC group object using EcGroupInit().

  @param[in]  EcGroup   EC group object to free.
**/
VOID
EFIAPI
EcGroupFree (
  IN VOID  *EcGroup
  )
{
  EC_GROUP_free (EcGroup);
}

/**
  Initialize new opaque EC Point object. This object represents an EC point
  within the given EC group (curve).

  @param[in]  EC Group, properly initialized using EcGroupInit().

  @retval EC Point object  On success.
  @retval NULL             On failure.
**/
VOID *
EFIAPI
EcPointInit (
  IN CONST VOID  *EcGroup
  )
{
  return EC_POINT_new (EcGroup);
}

/**
  Free previously allocated EC Point object using EcPointInit().

  @param[in]  EcPoint   EC Point to free.
  @param[in]  Clear     TRUE iff the memory should be cleared.
**/
VOID
EFIAPI
EcPointDeInit (
  IN VOID     *EcPoint,
  IN BOOLEAN  Clear
  )
{
  if (Clear) {
    EC_POINT_clear_free (EcPoint);
  } else {
    EC_POINT_free (EcPoint);
  }
}

/**
  Get EC point affine (x,y) coordinates.
  This function will set the provided Big Number objects to the corresponding
  values. The caller needs to make sure all the "out" BigNumber parameters
  are properly initialized.

  @param[in]  EcGroup    EC group object.
  @param[in]  EcPoint    EC point object.
  @param[out] BnX        X coordinate.
  @param[out] BnY        Y coordinate.
  @param[in]  BnCtx      BN context, created with BigNumNewContext().

  @retval EFI_SUCCESS        On success.
  @retval EFI_PROTOCOL_ERROR On failure.
**/
EFI_STATUS
EFIAPI
EcPointGetAffineCoordinates (
  IN CONST VOID  *EcGroup,
  IN CONST VOID  *EcPoint,
  OUT VOID       *BnX,
  OUT VOID       *BnY,
  IN VOID        *BnCtx
  )
{
  return EC_POINT_get_affine_coordinates (EcGroup, EcPoint, BnX, BnY, BnCtx) ?
         EFI_SUCCESS : EFI_INVALID_PARAMETER;
}

/**
  Set EC point affine (x,y) coordinates.

  @param[in]  EcGroup    EC group object.
  @param[in]  EcPoint    EC point object.
  @param[in]  BnX        X coordinate.
  @param[in]  BnY        Y coordinate.
  @param[in]  BnCtx      BN context, created with BigNumNewContext().

  @retval EFI_SUCCESS        On success.
  @retval EFI_PROTOCOL_ERROR On failure.
**/
EFI_STATUS
EFIAPI
EcPointSetAffineCoordinates (
  IN CONST VOID  *EcGroup,
  IN VOID        *EcPoint,
  IN CONST VOID  *BnX,
  IN CONST VOID  *BnY,
  IN VOID        *BnCtx
  )
{
  return EC_POINT_set_affine_coordinates (EcGroup, EcPoint, BnX, BnY, BnCtx) ?
         EFI_SUCCESS : EFI_INVALID_PARAMETER;
}

/**
  EC Point addition. EcPointResult = EcPointA + EcPointB.

  @param[in]  EcGroup          EC group object.
  @param[out] EcPointResult    EC point to hold the result. The point should
                               be properly initialized.
  @param[in]  EcPointA         EC Point.
  @param[in]  EcPointB         EC Point.
  @param[in]  BnCtx            BN context, created with BigNumNewContext().

  @retval EFI_SUCCESS        On success
  @retval EFI_PROTOCOL_ERROR On failure
**/
EFI_STATUS
EFIAPI
EcPointAdd (
  IN CONST VOID  *EcGroup,
  OUT VOID       *EcPointResult,
  IN CONST VOID  *EcPointA,
  IN CONST VOID  *EcPointB,
  IN VOID        *BnCtx
  )
{
  return EC_POINT_add (EcGroup, EcPointResult, EcPointA, EcPointB, BnCtx) ?
         EFI_SUCCESS : EFI_INVALID_PARAMETER;
}

/**
  Variable EC point multiplication. EcPointResult = EcPoint * BnPScalar.

  @param[in]  EcGroup          EC group object.
  @param[out] EcPointResult    EC point to hold the result. The point should
                               be properly initialized.
  @param[in]  EcPoint          EC Point.
  @param[in]  BnPScalar        P Scalar.
  @param[in]  BnCtx            BN context, created with BigNumNewContext().

  @retval EFI_SUCCESS        On success.
  @retval EFI_PROTOCOL_ERROR On failure.
**/
EFI_STATUS
EFIAPI
EcPointMul (
  IN CONST VOID  *EcGroup,
  OUT VOID       *EcPointResult,
  IN CONST VOID  *EcPoint,
  IN CONST VOID  *BnPScalar,
  IN VOID        *BnCtx
  )
{
  return EC_POINT_mul (EcGroup, EcPointResult, NULL, EcPoint, BnPScalar, BnCtx) ?
         EFI_SUCCESS : EFI_INVALID_PARAMETER;
}

/**
  Calculate the inverse of the supplied EC point.

  @param[in]     EcGroup   EC group object.
  @param[in,out] EcPoint   EC point to invert.
  @param[in]     BnCtx     BN context, created with BigNumNewContext().

  @retval EFI_SUCCESS        On success.
  @retval EFI_PROTOCOL_ERROR On failure.
**/
EFI_STATUS
EFIAPI
EcPointInvert (
  IN CONST VOID  *EcGroup,
  IN OUT VOID    *EcPoint,
  IN VOID        *BnCtx
  )
{
  return EC_POINT_invert (EcGroup, EcPoint, BnCtx) ?
         EFI_SUCCESS : EFI_INVALID_PARAMETER;
}

/**
  Check if the supplied point is on EC curve.

  @param[in]  EcGroup   EC group object.
  @param[in]  EcPoint   EC point to check.
  @param[in]  BnCtx     BN context, created with BigNumNewContext().

  @retval TRUE          On curve.
  @retval FALSE         Otherwise.
**/
BOOLEAN
EFIAPI
EcPointIsOnCurve (
  IN CONST VOID  *EcGroup,
  IN CONST VOID  *EcPoint,
  IN VOID        *BnCtx
  )
{
  return EC_POINT_is_on_curve (EcGroup, EcPoint, BnCtx) == 1;
}

/**
  Check if the supplied point is at infinity.

  @param[in]  EcGroup   EC group object.
  @param[in]  EcPoint   EC point to check.

  @retval TRUE          At infinity.
  @retval FALSE         Otherwise.
**/
BOOLEAN
EFIAPI
EcPointIsAtInfinity (
  IN CONST VOID  *EcGroup,
  IN CONST VOID  *EcPoint
  )
{
  return EC_POINT_is_at_infinity (EcGroup, EcPoint) == 1;
}

/**
  Check if EC points are equal.

  @param[in]  EcGroup   EC group object.
  @param[in]  EcPointA  EC point A.
  @param[in]  EcPointB  EC point B.
  @param[in]  BnCtx     BN context, created with BigNumNewContext().

  @retval TRUE          A == B.
  @retval FALSE         Otherwise.
**/
BOOLEAN
EFIAPI
EcPointEqual (
  IN CONST VOID  *EcGroup,
  IN CONST VOID  *EcPointA,
  IN CONST VOID  *EcPointB,
  IN VOID        *BnCtx
  )
{
  return EC_POINT_cmp (EcGroup, EcPointA, EcPointB, BnCtx) == 0;
}

/**
  Set EC point compressed coordinates. Points can be described in terms of
  their compressed coordinates. For a point (x, y), for any given value for x
  such that the point is on the curve there will only ever be two possible
  values for y. Therefore, a point can be set using this function where BnX is
  the x coordinate and YBit is a value 0 or 1 to identify which of the two
  possible values for y should be used.

  @param[in]  EcGroup    EC group object.
  @param[in]  EcPoint    EC Point.
  @param[in]  BnX        X coordinate.
  @param[in]  YBit       0 or 1 to identify which Y value is used.
  @param[in]  BnCtx      BN context, created with BigNumNewContext().

  @retval EFI_SUCCESS        On success.
  @retval EFI_PROTOCOL_ERROR On failure.
**/
EFI_STATUS
EFIAPI
EcPointSetCompressedCoordinates (
  IN CONST VOID  *EcGroup,
  IN VOID        *EcPoint,
  IN CONST VOID  *BnX,
  IN UINT8       YBit,
  IN VOID        *BnCtx
  )
{
  return EC_POINT_set_compressed_coordinates (EcGroup, EcPoint, BnX, YBit, BnCtx) ?
         EFI_SUCCESS : EFI_INVALID_PARAMETER;
}

// =====================================================================================
//    Elliptic Curve Diffie Hellman Primitives
// =====================================================================================

/**
  Generate a key using ECDH algorithm. Please note, this function uses
  pseudo random number generator. The caller must make sure RandomSeed()
  function was properly called before.

  @param[in]  EcGroup  EC group object.
  @param[out] PKey     Pointer to an object that will hold the ECDH key.

  @retval EFI_SUCCESS        On success.
  @retval EFI_UNSUPPORTED    ECC group not supported.
  @retval EFI_PROTOCOL_ERROR On failure.
**/
EFI_STATUS
EFIAPI
EcDhGenKey (
  IN  VOID  *EcGroup,
  OUT VOID  **PKey
  )
{
  EFI_STATUS    Status;
  INT32         Nid;
  EVP_PKEY_CTX  *Ctx;

  if (PKey == NULL || EcGroup == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Status = EFI_PROTOCOL_ERROR;
  Nid    = EC_GROUP_get_curve_name (EcGroup);
  Ctx    = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);

  if (Ctx == NULL) {
      goto fail;
  }
  if (EVP_PKEY_keygen_init (Ctx) != 1) {
    goto fail;
  }
  if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid (Ctx, Nid) != 1) {
    goto fail;
  }
  // Assume RAND_seed was called
  if (EVP_PKEY_keygen (Ctx, (EVP_PKEY **)PKey) != 1) {
    goto fail;
  }
  Status = EFI_SUCCESS;

fail:
  EVP_PKEY_CTX_free (Ctx);
  return Status;
}

/**
  Free ECDH Key object previously created by EcDhGenKey().

  @param[in] PKey  ECDH Key.
**/
VOID
EFIAPI
EcDhKeyFree (
  IN VOID  *PKey
  )
{
  EVP_PKEY_free (PKey);
}

/**
  Set the public key.

  @param[in, out]   PKey           ECDH Key object.
  @param[in]        EcGroup        EC group object.
  @param[in]        Public         Pointer to the buffer to receive generated public X,Y.
  @param[in]        PublicSize     The size of Public buffer in bytes.
  @param[in]        IncY           Flag to compressed coordinates.

  @retval EFI_SUCCESS        On success.
  @retval EFI_PROTOCOL_ERROR On failure.
**/
EFI_STATUS
EFIAPI
EcDhSetPubKey (
  IN OUT  VOID     *PKey,
  IN      VOID     *EcGroup,
  IN      UINT8    *PublicKey,
  IN      UINTN    PublicKeySize,
  IN      UINT32   *IncY
  )
{
  EC_KEY         *EcKey;
  BIGNUM         *BnX;
  BIGNUM         *BnY;
  EC_POINT       *EcPoint;
  INT32          HalfSize;
  EFI_STATUS     Status;

  if (PublicKey == NULL || EcGroup == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  HalfSize = EcGroupGetPrimeBytes (EcGroup);
  if ((IncY == NULL) && (PublicKeySize != (UINT32) HalfSize * 2)) {
    return EFI_INVALID_PARAMETER;
  }
  //Compressed coordinates
  if ((IncY != NULL) && (PublicKeySize != (UINT32) HalfSize)) {
    return EFI_INVALID_PARAMETER;
  }

  EcKey   = NULL;
  BnX     = NULL;
  BnY     = NULL;
  EcPoint = NULL;
  Status  = EFI_PROTOCOL_ERROR;

  BnX = BN_bin2bn (PublicKey, (UINT32) HalfSize, NULL);
  EcPoint = EC_POINT_new(EcGroup);
  if ((BnX == NULL) || (EcPoint == NULL)) {
    goto Done;
  }

	if (IncY == NULL) {
		BnY = BN_bin2bn(PublicKey + HalfSize, (UINT32) HalfSize, NULL);
		if (BnY == NULL) {
			goto Done;
    }
    if (EC_POINT_set_affine_coordinates (EcGroup, EcPoint, BnX, BnY, NULL) != 1) {
			goto Done;
		}
	} else {
    //Compressed coordinates
    if (EC_POINT_set_compressed_coordinates(EcGroup, EcPoint, BnX, *IncY, NULL) != 1) {
			goto Done;
		}
	}

  //EC_KEY* function will be deprecated in openssl 3.0, need update here when OpensslLib updating.
  EcKey = EC_KEY_new_by_curve_name (EC_GROUP_get_curve_name(EcGroup));
  if ((EcKey == NULL) || (EC_KEY_set_public_key (EcKey, EcPoint) != 1)) {
    goto Done;
  }

  if (PKey == NULL) {
    PKey = EVP_PKEY_new ();
    if ((PKey == NULL) || (EVP_PKEY_set1_EC_KEY (PKey, EcKey) != 1)) {
      EVP_PKEY_free (PKey);
      goto Done;
    }
  } else {
    if (EVP_PKEY_set1_EC_KEY (PKey, EcKey) != 1) {
      goto Done;
    }
  }

  Status = EFI_SUCCESS;

Done:
  BN_free (BnX);
  BN_free (BnY);
  EC_POINT_free(EcPoint);
  EC_KEY_free (EcKey);
  return Status;
}

/**
  Get the public key EC point. The provided EC point's coordinates will
  be set accordingly.

  @param[in]  PKey           ECDH Key object.
  @param[in]  EcGroup        EC group object.
  @param[in]  Public         Pointer to the buffer to receive generated public X,Y.
  @param[in]  PublicSize     The size of Public buffer in bytes.

  @retval EFI_SUCCESS        On success.
  @retval EFI_INVALID_PARAMETER EcPoint should be initialized properly.
  @retval EFI_PROTOCOL_ERROR On failure.
**/
EFI_STATUS
EFIAPI
EcDhGetPubKey (
  IN      VOID   *PKey,
  IN      VOID   *EcGroup,
  OUT     UINT8  *PublicKey,
  IN OUT  UINTN  *PublicKeySize
  )
{
  EC_KEY          *EcKey;
  CONST EC_POINT  *EcPoint;
  EFI_STATUS      Status;
  BIGNUM          *BnX;
  BIGNUM          *BnY;
  INTN            XSize;
  INTN            YSize;
  UINTN           HalfSize;

  if (PKey == NULL || EcGroup == NULL || PublicKeySize == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (PublicKey == NULL && *PublicKeySize != 0) {
    return EFI_INVALID_PARAMETER;
  }

  HalfSize = EcGroupGetPrimeBytes (EcGroup);
  if (*PublicKeySize < HalfSize * 2) {
    *PublicKeySize = HalfSize * 2;
    return EFI_INVALID_PARAMETER;
  }
  *PublicKeySize = HalfSize * 2;

  EcKey  = NULL;
  BnX    = NULL;
  BnY    = NULL;
  Status = EFI_PROTOCOL_ERROR;

  //EC_KEY* function will be deprecated in openssl 3.0, need update here when OpensslLib updating.
  EcKey = EVP_PKEY_get1_EC_KEY (PKey);
  if (EcKey == NULL) {
    goto out;
  }

  EcPoint = EC_KEY_get0_public_key (EcKey);
  if (EcPoint == NULL) {
    goto out;
  }

  BnX = BN_new();
  BnY = BN_new();
  if (BnX == NULL || BnY == NULL) {
    goto out;
  }
  if (EC_POINT_get_affine_coordinates(EcGroup, EcPoint, BnX, BnY, NULL) != 1) {
    goto out;
  }
  XSize = BN_num_bytes (BnX);
  YSize = BN_num_bytes (BnY);
  if (XSize <= 0 || YSize <= 0) {
    goto out;
  }
  ASSERT ((UINTN)XSize <= HalfSize && (UINTN)YSize <= HalfSize);

  ZeroMem (PublicKey, *PublicKeySize);
  BN_bn2bin (BnX, &PublicKey[0 + HalfSize - XSize]);
  BN_bn2bin (BnY, &PublicKey[HalfSize + HalfSize - YSize]);

  Status = EFI_SUCCESS;
out:
  BN_free (BnX);
  BN_free (BnY);
  EC_KEY_free (EcKey);
  return Status;
}

/**
  Derive ECDH secret.

  @param[in]  PKey           ECDH Key object.
  @param[in]  EcGroup        EC group object.
  @param[in]  PeerPKey       Peer public key object. Certain sanity checks on the key
                             will be performed to confirm that it is valid.
  @param[out] SecretSize     On success, holds secret size.
  @param[out] Secret         On success, holds the derived secret.
                             Should be freed by caller using FreePool()
                             function.

  @retval EFI_SUCCESS           On success.
  @retval EFI_UNSUPPORTED       ECC group not supported.
  @retval EFI_INVALID_PARAMETER Secret and SecretSize should be initialized properly.
  @retval EFI_INVALID_PARAMETER Public key should be checked against NIST.SP.800-56Ar2.
  @retval EFI_PROTOCOL_ERROR    On failure.
**/
EFI_STATUS
EFIAPI
EcDhDeriveSecret (
  IN VOID    *PKey,
  IN VOID    *EcGroup,
  IN VOID    *PeerPKey,
  OUT UINTN  *SecretSize,
  OUT UINT8  *Secret
  )
{
  EVP_PKEY_CTX  *Ctx;
  EFI_STATUS    Status;
  UINTN         HalfSize;

  if (PKey == NULL || EcGroup == NULL || PeerPKey == NULL || SecretSize == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if ((Secret == NULL) && (*SecretSize != 0)) {
    return EFI_INVALID_PARAMETER;
  }

  HalfSize = EcGroupGetPrimeBytes (EcGroup);
  if (*SecretSize < HalfSize) {
    *SecretSize = HalfSize;
    return EFI_INVALID_PARAMETER;
  }
  *SecretSize = HalfSize;

  if (!EVP_PKEY_public_check (PeerPKey)) {
    return EFI_INVALID_PARAMETER;
  }

  Ctx     = NULL;
  Status  = EFI_PROTOCOL_ERROR;

  Ctx = EVP_PKEY_CTX_new (PKey, NULL);
  if (Ctx == NULL) {
    goto fail;
  }

  if ((EVP_PKEY_derive_init (Ctx) != 1) ||
      (EVP_PKEY_derive_set_peer (Ctx, PeerPKey) != 1) ||
      (EVP_PKEY_derive (Ctx, Secret, SecretSize) != 1))
  {
    goto fail;
  }

fail:
  EVP_PKEY_CTX_free (Ctx);
  return Status;
}
