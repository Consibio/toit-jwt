// Copyright (C) 2023 Consibio ApS. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found
// in the LICENSE file.

/**
A library to sign and verify JWTs using Toit.
*/

import encoding.base64 as base64
import encoding.json as json
import crypto.hmac as hmac

sign --payload/Map --secret/string --algorithm/string="HS256":
  if not ["HS256", "HS384", "HS512"].contains algorithm: throw "JWTError: Unsupported algorithm: $algorithm"

  header := {"alg": algorithm, "typ": "JWT"}
  header_b64 := base64.encode (json.stringify header) --url_mode
  payload_b64 := base64.encode (json.stringify payload) --url_mode
  
  signature := null
  if algorithm == "HS256":      signature = hmac.hmac_sha256 --key=secret "$header_b64.$payload_b64"
  else if algorithm == "HS384": signature = hmac.hmac_sha384 --key=secret "$header_b64.$payload_b64"
  else if algorithm == "HS512": signature = hmac.hmac_sha512 --key=secret "$header_b64.$payload_b64"

  signature_b64 := base64.encode signature --url_mode
  return "$header_b64.$payload_b64.$(signature_b64)"

verify --token/string --secret/string --algorithm/string="HS256":