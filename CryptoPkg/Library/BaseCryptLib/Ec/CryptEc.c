/** @file
  Elliptic Curve and ECDH API implementation based on OpenSSL

  Copyright (c) 2022, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "InternalCryptLib.h"
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
  Allocates and Initializes one Elliptic Curve Context for subsequent use
  with the NID.
  
  @param[in]  Nid cipher NID
  @return     Pointer to the Elliptic Curve Context that has been initialized.
              If the allocations fails, EcNewByNid() returns NULL.
**/
VOID *
EFIAPI
EcDhNewByNid (
  IN UINTN  Nid
  )
{
  EC_KEY   *EcKey;
  EC_GROUP *Group;
  INT32    OpenSslNid;

  OpenSslNid = CryptoNidToOpensslNid (Nid);
  if (OpenSslNid < 0) {
    return FALSE;
  }

  EcKey = EC_KEY_new();
  Group = EC_GROUP_new_by_curve_name(OpenSslNid);
  if (EcKey == NULL || Group == NULL) {
    goto fail;
  }

  if (EC_KEY_set_group(EcKey, Group) != 1) {
    goto fail;
  }

  EC_GROUP_free(Group);
  return (VOID *)EcKey;

fail:
  EC_GROUP_free(Group);
  EC_KEY_free (EcKey);
  return NULL;
}

/**
  Release the specified EC context.

  @param[in]  EcContext  Pointer to the EC context to be released.
**/
VOID
EFIAPI
EcDhFree (
  IN  VOID  *EcContext
  )
{
  EC_KEY_free ((EC_KEY *) EcContext);
}

/**
  Generates EC key and returns EC public key (X, Y), Please note, this function uses
  pseudo random number generator. The caller must make sure RandomSeed()
  function was properly called before.
  The Ec context should be correctly initialized by EcNewByNid.
  This function generates random secret, and computes the public key (X, Y), which is
  returned via parameter Public, PublicSize.
  X is the first half of Public with size being PublicSize / 2,
  Y is the second half of Public with size being PublicSize / 2.
  EC context is updated accordingly.
  If the Public buffer is too small to hold the public X, Y, FALSE is returned and
  PublicSize is set to the required buffer size to obtain the public X, Y.
  For P-256, the PublicSize is 64. First 32-byte is X, Second 32-byte is Y.
  For P-384, the PublicSize is 96. First 48-byte is X, Second 48-byte is Y.
  For P-521, the PublicSize is 132. First 66-byte is X, Second 66-byte is Y.
  If EcContext is NULL, then return FALSE.
  If PublicSize is NULL, then return FALSE.
  If PublicSize is large enough but Public is NULL, then return FALSE.
  @param[in, out]  EcContext      Pointer to the EC context.
  @param[out]      Public         Pointer to the buffer to receive generated public X,Y.
  @param[in, out]  PublicSize     On input, the size of Public buffer in bytes.
                                  On output, the size of data returned in Public buffer in bytes.
  @retval TRUE   EC public X,Y generation succeeded.
  @retval FALSE  EC public X,Y generation failed.
  @retval FALSE  PublicSize is not large enough.
**/
BOOLEAN
EFIAPI
EcDhGenerateKey (
  IN OUT  VOID   *EcContext,
  OUT     UINT8  *PublicKey,
  IN OUT  UINTN  *PublicKeySize
  )
{
  EC_KEY         *EcKey;
  CONST EC_GROUP *Group;
  CONST EC_POINT *EcPoint;
  BOOLEAN        RetVal;
  BIGNUM         *BnX;
  BIGNUM         *BnY;
  UINTN          HalfSize;
  INTN           XSize;
  INTN           YSize;

  if (EcContext == NULL || PublicKeySize == NULL) {
    return FALSE;
  }

  if (PublicKey == NULL && *PublicKeySize != 0) {
    return FALSE;
  }

  EcKey = (EC_KEY *)EcContext;
  Group = EC_KEY_get0_group (EcKey);
  HalfSize = (EC_GROUP_get_degree (Group) + 7) / 8;

  // Assume RAND_seed was called
  if (EC_KEY_generate_key (EcKey) != 1) {
    return FALSE;
  }

  if (*PublicKeySize != HalfSize * 2) {
    *PublicKeySize = HalfSize * 2;
    return FALSE;
  }
  *PublicKeySize = HalfSize * 2;

  EcPoint = EC_KEY_get0_public_key (EcKey);
  if (EcPoint == NULL) {
    return FALSE;
  }

  RetVal = FALSE;
  BnX = BN_new();
  BnY = BN_new();
  if (BnX == NULL || BnY == NULL) {
    goto fail;
  }

  if (EC_POINT_get_affine_coordinates (Group, EcPoint, BnX, BnY, NULL) != 1) {
    goto fail;
  }

  XSize = BN_num_bytes (BnX);
  YSize = BN_num_bytes (BnY);
  if (XSize <= 0 || YSize <= 0) {
    goto fail;
  }
  ASSERT ((UINTN)XSize <= HalfSize && (UINTN)YSize <= HalfSize);

  ZeroMem (PublicKey, *PublicKeySize);
  BN_bn2bin (BnX, &PublicKey[0 + HalfSize - XSize]);
  BN_bn2bin (BnY, &PublicKey[HalfSize + HalfSize - YSize]);

  RetVal = TRUE;

fail:
  BN_free (BnX);
  BN_free (BnY);
  return RetVal;
}

/**
  Gets the public key component from the established EC context.
  The Ec context should be correctly initialized by EcNewByNid, and successfully 
  generate key pair from EcGenerateKey().
  For P-256, the PublicSize is 64. First 32-byte is X, Second 32-byte is Y.
  For P-384, the PublicSize is 96. First 48-byte is X, Second 48-byte is Y.
  For P-521, the PublicSize is 132. First 66-byte is X, Second 66-byte is Y.
  @param[in, out]  EcContext      Pointer to EC context being set.
  @param[out]      Public         Pointer to the buffer to receive generated public X,Y.
  @param[in, out]  PublicSize     On input, the size of Public buffer in bytes.
                                  On output, the size of data returned in Public buffer in bytes.
  @retval  TRUE   EC key component was retrieved successfully.
  @retval  FALSE  Invalid EC key component.
**/
BOOLEAN
EFIAPI
EcDhGetPubKey (
  IN OUT  VOID   *EcContext,
  OUT     UINT8  *PublicKey,
  IN OUT  UINTN  *PublicKeySize
  )
{
  EC_KEY         *EcKey;
  CONST EC_GROUP *Group;
  CONST EC_POINT *EcPoint;
  BIGNUM         *BnX;
  BIGNUM         *BnY;
  UINTN          HalfSize;
  INTN           XSize;
  INTN           YSize;
  BOOLEAN        RetVal;

  if (EcContext == NULL || PublicKeySize == NULL) {
    return FALSE;
  }

  if (PublicKey == NULL && *PublicKeySize != 0) {
    return FALSE;
  }

  EcKey = (EC_KEY *)EcContext;
  Group = EC_KEY_get0_group (EcKey);
  HalfSize = (EC_GROUP_get_degree (Group) + 7) / 8;
  if (*PublicKeySize != HalfSize * 2) {
    *PublicKeySize = HalfSize * 2;
    return FALSE;
  }
  *PublicKeySize = HalfSize * 2;

  EcPoint = EC_KEY_get0_public_key (EcKey);
  if (EcPoint == NULL) {
    return FALSE;
  }

  RetVal = FALSE;
  BnX = BN_new();
  BnY = BN_new();
  if (BnX == NULL || BnY == NULL) {
    goto fail;
  }

  if (EC_POINT_get_affine_coordinates (Group, EcPoint, BnX, BnY, NULL) != 1) {
    goto fail;
  }

  XSize = BN_num_bytes (BnX);
  YSize = BN_num_bytes (BnY);
  if (XSize <= 0 || YSize <= 0) {
    goto fail;
  }
  ASSERT ((UINTN)XSize <= HalfSize && (UINTN)YSize <= HalfSize);

  if (PublicKey != NULL) {
    ZeroMem (PublicKey, *PublicKeySize);
    BN_bn2bin (BnX, &PublicKey[0 + HalfSize - XSize]);
    BN_bn2bin (BnY, &PublicKey[HalfSize + HalfSize - YSize]);
  }

  RetVal = TRUE;

fail:
  BN_free (BnX);
  BN_free (BnY);
  return RetVal;
}

/**
  Computes exchanged common key.
  Given peer's public key (X, Y), this function computes the exchanged common key,
  based on its own context including value of curve parameter and random secret.
  X is the first half of PeerPublic with size being PeerPublicSize / 2,
  Y is the second half of PeerPublic with size being PeerPublicSize / 2.
  If public key is compressed, the PeerPublic will only contain half key (X).
  If EcContext is NULL, then return FALSE.
  If PeerPublic is NULL, then return FALSE.
  If PeerPublicSize is 0, then return FALSE.
  If Key is NULL, then return FALSE.
  If KeySize is not large enough, then return FALSE.
  For P-256, the PeerPublicSize is 64. First 32-byte is X, Second 32-byte is Y.
  For P-384, the PeerPublicSize is 96. First 48-byte is X, Second 48-byte is Y.
  For P-521, the PeerPublicSize is 132. First 66-byte is X, Second 66-byte is Y.
  @param[in, out]  EcContext          Pointer to the EC context.
  @param[in]       PeerPublic         Pointer to the peer's public X,Y.
  @param[in]       PeerPublicSize     Size of peer's public X,Y in bytes.
  @param[in]       CompressFlag       Flag of key is compressed or not.
  @param[out]      Key                Pointer to the buffer to receive generated key.
  @param[in, out]  KeySize            On input, the size of Key buffer in bytes.
                                      On output, the size of data returned in Key buffer in bytes.
  @retval TRUE   EC exchanged key generation succeeded.
  @retval FALSE  EC exchanged key generation failed.
  @retval FALSE  KeySize is not large enough.
**/
BOOLEAN
EFIAPI
EcDhComputeKey (
  IN OUT  VOID         *EcContext,
  IN      CONST UINT8  *PeerPublic,
  IN      UINTN        PeerPublicSize,
  IN      CONST INT32  *CompressFlag,
  OUT     UINT8        *Key,
  IN OUT  UINTN        *KeySize
  )
{
  EC_KEY         *EcKey;
  EC_KEY         *PeerEcKey;
  CONST EC_GROUP *Group;
  BOOLEAN        RetVal;
  BIGNUM         *BnX;
  BIGNUM         *BnY;
  EC_POINT       *Point;
  INT32          OpenSslNid;
  UINTN          HalfSize;

  if (EcContext == NULL || PeerPublic == NULL || KeySize == NULL) {
    return FALSE;
  }

  if (Key == NULL && *KeySize != 0) {
    return FALSE;
  }

  if (PeerPublicSize > INT_MAX) {
    return FALSE;
  }

  EcKey = (EC_KEY *) EcContext;
  Group = EC_KEY_get0_group (EcKey);
  HalfSize = (EC_GROUP_get_degree (Group) + 7) / 8;
  if (CompressFlag == NULL && PeerPublicSize != HalfSize * 2) {
    return FALSE;
  }
  if (CompressFlag != NULL && PeerPublicSize != HalfSize) {
    return FALSE;
  }
  if (*KeySize < HalfSize) {
    *KeySize = HalfSize;
    return FALSE;
  }
  *KeySize = HalfSize;

  RetVal = FALSE;
  Point = NULL;
  BnX = BN_bin2bn (PeerPublic, (INT32) HalfSize, NULL);
  BnY = NULL;
  Point = EC_POINT_new (Group);
  if (BnX == NULL || Point == NULL) {
    goto fail;
  }

  if (CompressFlag == NULL) {
    BnY = BN_bin2bn (PeerPublic + HalfSize, (INT32) HalfSize, NULL);
    if (BnY == NULL) {
      goto fail;
    }
    if (EC_POINT_set_affine_coordinates (Group, Point, BnX, BnY, NULL) != 1) {
      goto fail;
    }
  } else {
    if (EC_POINT_set_compressed_coordinates (Group, Point, BnX, *CompressFlag, NULL) != 1) {
      goto fail;
    }    
  }

  // Validate NIST ECDH public key
  OpenSslNid = EC_GROUP_get_curve_name (Group);
  PeerEcKey = EC_KEY_new_by_curve_name (OpenSslNid);
  if (PeerEcKey == NULL) {
    goto fail;
  }
  if (EC_KEY_set_public_key (PeerEcKey, Point) != 1) {
    goto fail;
  }
  if (EC_KEY_check_key (PeerEcKey) != 1) {
    goto fail;
  }

  if (ECDH_compute_key (Key, *KeySize, Point, EcKey, NULL) <= 0) {
    goto fail;
  }

  RetVal = TRUE;

fail:
  BN_free (BnX);
  BN_free (BnY);
  EC_POINT_free(Point);
  EC_KEY_free (PeerEcKey);
  return RetVal;
}