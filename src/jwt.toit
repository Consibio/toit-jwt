// Copyright (C) 2023 Consibio ApS. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found
// in the LICENSE file.

/**
A library to sign and verify JWTs using Toit.
*/

import encoding.base64 as base64
import encoding.json as json
import crypto.hmac as hmac

SUPPORTED_ALGORITHMS ::= ["HS256", "HS384", "HS512"]

/**
Sign a JWT using the given payload and secret with the given algorithm. 
Default algorithm is HS256.
*/
sign --payload/Map --secret/string --algorithm/string="HS256":
  if not SUPPORTED_ALGORITHMS.contains algorithm: throw "JWTSignError: Unsupported algorithm: $algorithm"

  header := {"alg": algorithm, "typ": "JWT"}
  header_b64 := base64.encode (json.stringify header) --url_mode
  payload_b64 := base64.encode (json.stringify payload) --url_mode
  signature_b64 := compute_signature_  --jwt_content="$header_b64.$payload_b64" --algorithm=algorithm --secret=secret
  
  return "$header_b64.$payload_b64.$(signature_b64)"


/**
Verify a JWT using the given secret and algorithm.

By default, the verify methods throws an error if the token is expired or the signature does not match.
If you want to handle these cases yourself, you can set throwing to false, and the method will false, if verification fails.
*/
verify --token/string --secret/string --algorithm/string="HS256" --throwing/bool=true -> bool:
  if not SUPPORTED_ALGORITHMS.contains algorithm: throw "JWTVerifyError: Unsupported algorithm: $algorithm"

  // Check if the token is expired
  if (is_expired --token=token) and throwing: throw "JWTVerifyError: Token expired"
  
  header_b64 := (token.split ".")[0]
  payload_b64 := (token.split ".")[1]
  signature_b64 := (token.split ".")[2]

  // Compute signature and check if the signatures matches
  computed_signature := compute_signature_ --jwt_content="$header_b64.$payload_b64" --secret=secret --algorithm=algorithm
  match := signature_b64 == computed_signature

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