// Copyright (C) 2023 Consibio ApS. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found
// in the LICENSE file.

/**
A library to sign and verify JWTs using Toit.

Supports HMAC (HS256, HS384, HS512) with a shared secret, and ECDSA with P-256 and SHA-256
  (ES256) with an $ec.EcKey.

$verify checks the signature, that the token's header names the expected algorithm, that the
  token has an "exp" that hasn't passed, and that its "nbf", if it has one, has. It doesn't check
  other claims, such as "aud", "iss" or "sub".
*/

import encoding.base64 as base64
import encoding.json as json
import crypto.hmac as hmac
import crypto.ec as ec

HMAC_ALGORITHMS ::= ["HS256", "HS384", "HS512"]
EC_ALGORITHMS ::= ["ES256"]
SUPPORTED_ALGORITHMS ::= HMAC_ALGORITHMS + EC_ALGORITHMS

/**
The size in bytes of each of the two integers (r and s) of an ES256 signature.
*/
ES256_INTEGER_SIZE ::= 32

// The start of the SubjectPublicKeyInfo DER of every P-256 public key (uncompressed point):
// the id-ecPublicKey and prime256v1 object identifiers, and the bit string header.
P256_SPKI_PREFIX_ ::= #[
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
  0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
]
P256_SPKI_SIZE_ ::= 91

/**
Signs a JWT with the given payload and secret, using the given algorithm.
Default algorithm is HS256.

The $header can hold extra header fields, eg. "kid". It can't set "alg" or "typ".
*/
sign --payload/Map --secret/string --algorithm/string="HS256" --header/Map={:} -> string:
  if not HMAC_ALGORITHMS.contains algorithm: throw "JWTSignError: Unsupported algorithm: $algorithm"

  content := encode_content_ --payload=payload --algorithm=algorithm --header=header
  signature_b64 := compute_signature_ --jwt_content=content --algorithm=algorithm --secret=secret
  return "$content.$signature_b64"

/**
Signs a JWT with the given payload and EC private key, using the given algorithm.
Default (and only) algorithm is ES256, which needs a P-256 key.

The signature is the raw 64-byte r||s form of RFC 7518, section 3.4. The $header can hold
  extra header fields, eg. "kid". It can't set "alg" or "typ".
*/
sign --payload/Map --key/ec.EcKey --algorithm/string="ES256" --header/Map={:} -> string:
  if not EC_ALGORITHMS.contains algorithm: throw "JWTSignError: Unsupported algorithm: $algorithm"
  if not key.is_private: throw "JWTSignError: Signing needs a private key"
  if not is_p256_ key: throw "JWTSignError: $algorithm needs a P-256 key"

  content := encode_content_ --payload=payload --algorithm=algorithm --header=header
  der_signature := key.sign content --hash=ec.EcKey.SHA_256
  signature := der_to_jose_signature_ der_signature --integer_size=ES256_INTEGER_SIZE
  return "$content.$(base64.encode signature --url_mode)"

/**
Verifies a JWT with the given secret and algorithm.

The token's header must name the same $algorithm. The token must have an "exp" that hasn't
  passed, and its "nbf", if it has one, must have passed.

Throws if the token isn't valid, unless $throwing is false. Then it returns false instead.
*/
verify --token/string --secret/string --algorithm/string="HS256" --throwing/bool=true -> bool:
  if not HMAC_ALGORITHMS.contains algorithm: throw "JWTVerifyError: Unsupported algorithm: $algorithm"

  parts := split_ token
  if not parts: return fail_ throwing "JWTVerifyError: Malformed token"
  if (header_algorithm_ parts[0]) != algorithm: return fail_ throwing "JWTVerifyError: Token algorithm is not $algorithm"
  if claims_error := claims_error_ parts[1]: return fail_ throwing claims_error

  computed_signature := compute_signature_ --jwt_content="$parts[0].$parts[1]" --secret=secret --algorithm=algorithm
  if not constant_time_equals_ parts[2] computed_signature: return fail_ throwing "JWTVerifyError: Token signature mismatch"
  return true

/**
Verifies a JWT with the given EC public key and algorithm.

The $key must be a P-256 key. A private key is used through its public key.

The token's header must name the same $algorithm. The token must have an "exp" that hasn't
  passed, and its "nbf", if it has one, must have passed.

Throws if the token isn't valid, unless $throwing is false. Then it returns false instead.
*/
verify --token/string --key/ec.EcKey --algorithm/string="ES256" --throwing/bool=true -> bool:
  if not EC_ALGORITHMS.contains algorithm: throw "JWTVerifyError: Unsupported algorithm: $algorithm"
  if not is_p256_ key: throw "JWTVerifyError: $algorithm needs a P-256 key"
  public_key := key.is_private ? (ec.EcKey.parse_public key.der) : key

  parts := split_ token
  if not parts: return fail_ throwing "JWTVerifyError: Malformed token"
  if (header_algorithm_ parts[0]) != algorithm: return fail_ throwing "JWTVerifyError: Token algorithm is not $algorithm"
  if claims_error := claims_error_ parts[1]: return fail_ throwing claims_error

  match := false
  catch:
    signature := base64.decode parts[2] --url_mode
    der := jose_to_der_signature_ signature --integer_size=ES256_INTEGER_SIZE
    match = public_key.verify "$parts[0].$parts[1]" der --hash=ec.EcKey.SHA_256
  if not match: return fail_ throwing "JWTVerifyError: Token signature mismatch"
  return true

/**
Returns when the token expires.
Throws an error if the token has no expiration (ie. the "exp" field is empty).
*/
expires --token/string -> Time:
  payload_b64 := (token.split ".")[1]
  payload_json := (base64.decode payload_b64 --url_mode).to_string
  payload := json.parse payload_json
  exp := payload.get "exp"
  if exp == null: throw "JWTExpiryError: Token has no expiration"
  return Time.epoch --s=(payload.get "exp")

/**
Whether the token expires within the given time.
Defaults to 5 minutes, if nothing is set.
*/
expires_soon --token/string --h/int=0 --m/int=0 --s/int=0 -> bool:
  // Default to 5 minutes, if nothing is set
  if h==0 and m==0 and s==0: m=5

  expire_time := expires --token=token
  return (Time.now.to expire_time) < (Duration --h=h --m=m --s=s)

/**
Whether the token is expired. A token without an expiration counts as expired.
*/
is_expired --token/string -> bool:
  catch:
    expire_time := expires --token=token
    return (expire_time < Time.now)
  return true

/**
Converts a DER-encoded ECDSA signature, as returned by $ec.EcKey.sign, to the
  fixed-size r||s form that JWTs use (RFC 7518, section 3.4).

Each integer is left-padded with zeros to $integer_size bytes (32 for ES256).
Throws if $der isn't a DER ECDSA signature, or an integer doesn't fit. It doesn't reject every
  non-canonical DER encoding (eg. extra leading zeros), as it is only given signatures from
  $ec.EcKey.sign.
*/
der_to_jose_signature_ der/ByteArray --integer_size/int -> ByteArray:
  if integer_size < 1: throw "JWTSignatureError: Integer size must be positive"
  // SEQUENCE { INTEGER r, INTEGER s }
  if der.size < 2 or der[0] != 0x30: throw "JWTSignatureError: Signature is not a DER sequence"
  offset := 1
  sequence_size := der[offset++]
  if sequence_size == 0x81:
    if der.size < 3: throw "JWTSignatureError: Truncated DER signature"
    sequence_size = der[offset++]
  else if sequence_size > 0x7f:
    throw "JWTSignatureError: Unsupported DER length"
  if offset + sequence_size != der.size: throw "JWTSignatureError: Wrong DER sequence length"

  result := ByteArray integer_size * 2
  2.repeat: | index/int |
    if offset + 2 > der.size or der[offset] != 0x02: throw "JWTSignatureError: Expected a DER integer"
    integer_size_in_der := der[offset + 1]
    offset += 2
    if integer_size_in_der == 0 or integer_size_in_der > 0x7f or offset + integer_size_in_der > der.size:
      throw "JWTSignatureError: Wrong DER integer length"
    integer := der[offset..offset + integer_size_in_der]
    offset += integer_size_in_der
    // DER integers are signed, so a positive integer with its top bit set has a leading zero.
    start := 0
    while start < integer.size - 1 and integer[start] == 0: start++
    integer = integer[start..]
    if integer.size > integer_size: throw "JWTSignatureError: Signature integer too large"
    result.replace (index * integer_size + integer_size - integer.size) integer
  if offset != der.size: throw "JWTSignatureError: Trailing bytes in DER signature"
  return result

/**
Converts a fixed-size r||s ECDSA signature (RFC 7518, section 3.4) to DER, as
  $ec.EcKey.verify takes it.

Throws if $signature isn't 2 * $integer_size bytes.
*/
jose_to_der_signature_ signature/ByteArray --integer_size/int -> ByteArray:
  if integer_size < 1: throw "JWTSignatureError: Integer size must be positive"
  if signature.size != integer_size * 2: throw "JWTSignatureError: Signature must be $(integer_size * 2) bytes"
  integers := [signature[..integer_size], signature[integer_size..]].map: | integer/ByteArray |
    start := 0
    while start < integer.size - 1 and integer[start] == 0: start++
    integer = integer[start..]
    // Keep the integer positive.
    (integer[0] & 0x80) != 0 ? #[0x02, integer.size + 1, 0x00] + integer : #[0x02, integer.size] + integer
  body := integers[0] + integers[1]
  if body.size > 0x7f: return #[0x30, 0x81, body.size] + body
  return #[0x30, body.size] + body

encode_content_ --payload/Map --algorithm/string --header/Map -> string:
  if header.contains "alg" or header.contains "typ": throw "JWTSignError: The header can't set 'alg' or 'typ'"
  full_header := {"alg": algorithm, "typ": "JWT"}
  header.do: | name value | full_header[name] = value
  header_b64 := base64.encode (json.stringify full_header) --url_mode
  payload_b64 := base64.encode (json.stringify payload) --url_mode
  return "$header_b64.$payload_b64"

/** Returns the three parts of the $token, or null if it doesn't have three. */
split_ token/string -> List?:
  parts := token.split "."
  return parts.size == 3 ? parts : null

/** Returns the "alg" of the base64url-encoded $header_b64, or null if it has none. */
header_algorithm_ header_b64/string -> string?:
  catch:
    header := json.parse (base64.decode header_b64 --url_mode).to_string
    if header is Map: return header.get "alg"
  return null

/**
Returns why the claims of the base64url-encoded $payload_b64 make the token invalid now, or null
  if they don't: the token must have an "exp" that hasn't passed, and its "nbf", if it has one,
  must have passed.
*/
claims_error_ payload_b64/string -> string?:
  payload := null
  catch: payload = json.parse (base64.decode payload_b64 --url_mode).to_string
  if payload is not Map: return "JWTVerifyError: Malformed token"
  now := Time.now.s_since_epoch
  exp := payload.get "exp"
  if exp == null: return "JWTVerifyError: Token has no expiration"
  if exp is not num: return "JWTVerifyError: Malformed token"
  if exp < now: return "JWTVerifyError: Token expired"
  nbf := payload.get "nbf"
  if nbf != null:
    if nbf is not num: return "JWTVerifyError: Malformed token"
    if nbf > now: return "JWTVerifyError: Token not yet valid"
  return null

/** Whether $a and $b are equal, in a time that doesn't depend on where they differ. */
constant_time_equals_ a/string b/string -> bool:
  if a.size != b.size: return false
  difference := 0
  a.size.repeat: difference |= (a.at --raw it) ^ (b.at --raw it)
  return difference == 0

/** Whether the $key is a P-256 key. */
is_p256_ key/ec.EcKey -> bool:
  public_key := key.is_private ? (ec.EcKey.parse_public key.der) : key
  der := public_key.der
  return der.size == P256_SPKI_SIZE_ and der[..P256_SPKI_PREFIX_.size] == P256_SPKI_PREFIX_

fail_ throwing/bool message/string -> bool:
  if throwing: throw message
  return false

/**
Computes the signature of the given JWT content with the given secret and algorithm.
*/
compute_signature_ --jwt_content/string --secret/string --algorithm/string="HS256" -> string:
  signature := null
  if algorithm == "HS256":      signature = hmac.hmac_sha256 --key=secret jwt_content
  else if algorithm == "HS384": signature = hmac.hmac_sha384 --key=secret jwt_content
  else if algorithm == "HS512": signature = hmac.hmac_sha512 --key=secret jwt_content

  if signature==null: throw "JWTSignatureError: Unsupported algorithm: $algorithm"

  signature_b64 := base64.encode signature --url_mode
  return signature_b64
