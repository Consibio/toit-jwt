
// Copyright (C) 2023 Consibio ApS. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found
// in the LICENSE file.

/**
A library to sign and verify JWTs using Toit.

Supports HMAC (HS256, HS384, HS512) with a shared secret, and ECDSA with P-256 and SHA-256
  (ES256) with an $ec.EcKey.
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

/**
Sign a JWT using the given payload and secret with the given algorithm.
Default algorithm is HS256.

The $header can hold extra header fields, eg. "kid". It can't set "alg" or "typ".
*/
sign --payload/Map --secret/string --algorithm/string="HS256" --header/Map={:} -> string:
  if not HMAC_ALGORITHMS.contains algorithm: throw "JWTSignError: Unsupported algorithm: $algorithm"

  content := encode_content_ --payload=payload --algorithm=algorithm --header=header
  signature_b64 := compute_signature_ --jwt_content=content --algorithm=algorithm --secret=secret
  return "$content.$signature_b64"

/**
Sign a JWT using the given payload and EC private key with the given algorithm.
Default (and only) algorithm is ES256, which needs a P-256 key.

The signature is the raw 64-byte r||s form of RFC 7518, section 3.4. The $header can hold
  extra header fields, eg. "kid". It can't set "alg" or "typ".
*/
sign --payload/Map --key/ec.EcKey --algorithm/string="ES256" --header/Map={:} -> string:
  if not EC_ALGORITHMS.contains algorithm: throw "JWTSignError: Unsupported algorithm: $algorithm"
  if not key.is_private: throw "JWTSignError: Signing needs a private key"

  content := encode_content_ --payload=payload --algorithm=algorithm --header=header
  der_signature := key.sign content --hash=ec.EcKey.SHA_256
  signature := der_to_jose_signature der_signature --integer_size=ES256_INTEGER_SIZE
  return "$content.$(base64.encode signature --url_mode)"


/**
Verify a JWT using the given secret and algorithm.

The token's header must name the same $algorithm.

By default, the verify methods throws an error if the token is expired or the signature does not match.
If you want to handle these cases yourself, you can set throwing to false, and the method will false, if verification fails.
*/
verify --token/string --secret/string --algorithm/string="HS256" --throwing/bool=true -> bool:
  if not HMAC_ALGORITHMS.contains algorithm: throw "JWTVerifyError: Unsupported algorithm: $algorithm"

  parts := split_ token
  if not parts: return fail_ throwing "JWTVerifyError: Malformed token"
  if (header_algorithm_ parts[0]) != algorithm: return fail_ throwing "JWTVerifyError: Token algorithm is not $algorithm"

  // Check if the token is expired
  if (is_expired --token=token) and throwing: throw "JWTVerifyError: Token expired"

  // Compute signature and check if the signatures matches
  computed_signature := compute_signature_ --jwt_content="$parts[0].$parts[1]" --secret=secret --algorithm=algorithm
  match := parts[2] == computed_signature

  if throwing and not match: throw "JWTVerifyError: Token signature mismatch"
  return match

/**
Verify a JWT using the given EC public key and algorithm.

The token's header must name the same $algorithm.

Throws if the token is expired or the signature does not match, unless $throwing is false.
  Then it returns false instead.
*/
verify --token/string --key/ec.EcKey --algorithm/string="ES256" --throwing/bool=true -> bool:
  if not EC_ALGORITHMS.contains algorithm: throw "JWTVerifyError: Unsupported algorithm: $algorithm"

  parts := split_ token
  if not parts: return fail_ throwing "JWTVerifyError: Malformed token"
  if (header_algorithm_ parts[0]) != algorithm: return fail_ throwing "JWTVerifyError: Token algorithm is not $algorithm"

  if (is_expired --token=token) and throwing: throw "JWTVerifyError: Token expired"

  match := false
  catch:
    signature := base64.decode parts[2] --url_mode
    der := jose_to_der_signature signature --integer_size=ES256_INTEGER_SIZE
    match = key.verify "$parts[0].$parts[1]" der --hash=ec.EcKey.SHA_256

  if throwing and not match: throw "JWTVerifyError: Token signature mismatch"
  return match

/**
Get a $Time representing when the token expires.
Throws an error if the token has no expiration (ie. the "exp" field is empty)
*/
expires --token/string -> Time:
  payload_b64 := (token.split ".")[1]
  payload_json := (base64.decode payload_b64 --url_mode).to_string
  payload := json.parse payload_json
  exp := payload.get "exp"
  if exp == null: throw "JWTExpiryError: Token has no expiration"
  return Time.epoch --s=(payload.get "exp")


/**
Check if the token expires within the given time.
Defaults to 5min, if nothing is set.
*/
expires_soon --token/string --h/int=0 --m/int=0 --s/int=0 -> bool:
  // Default to 5 minutes, if nothing is set
  if h==0 and m==0 and s==0: m=5

  expire_time := expires --token=token
  return (Time.now.to expire_time) < (Duration --h=h --m=m --s=s)

/**
Check if the token is expired.
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
Throws if $der isn't a valid DER ECDSA signature, or an integer doesn't fit.
*/
der_to_jose_signature der/ByteArray --integer_size/int -> ByteArray:
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
    // DER integers are signed, so a positive integer with its top bit set has a leading zero
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
jose_to_der_signature signature/ByteArray --integer_size/int -> ByteArray:
  if signature.size != integer_size * 2: throw "JWTSignatureError: Signature must be $(integer_size * 2) bytes"
  integers := [signature[..integer_size], signature[integer_size..]].map: | integer/ByteArray |
    start := 0
    while start < integer.size - 1 and integer[start] == 0: start++
    integer = integer[start..]
    // Keep the integer positive
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

fail_ throwing/bool message/string -> bool:
  if throwing: throw message
  return false

/**
Compute the signature of the given JWT content using the given secret and algorithm.
*/
compute_signature_ --jwt_content/string --secret/string --algorithm/string="HS256" -> string:

  signature := null
  if algorithm == "HS256":      signature = hmac.hmac_sha256 --key=secret jwt_content
  else if algorithm == "HS384": signature = hmac.hmac_sha384 --key=secret jwt_content
  else if algorithm == "HS512": signature = hmac.hmac_sha512 --key=secret jwt_content

  if signature==null: throw "JWTSignatureError: Unsupported algorithm: $algorithm"

  signature_b64 := base64.encode signature --url_mode
  return signature_b64
