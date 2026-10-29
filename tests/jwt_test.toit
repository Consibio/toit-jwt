/**
  To execute, run: 
  jag run -d host jwt_test.toit
*/

import jwt
import crypto.ec as ec
import expect show *

main:
    test_hmac
    test_es256
    test_signature_conversion

test_hmac:
    /**
    Test JWT signing and verification using pre-defined payload and secret and compare it against output of https://jwt.io/
    */
    payload := {
        "aud": "audience",
        "sub": "1234567890",
        "iat": 1516239022,
        "exp": 1516242622
    }
    secret := "super-secret-key"

    /**
    Test JWT generation using HS265
    */
    // https://jwt.io/#debugger-io?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhdWRpZW5jZSIsInN1YiI6IjEyMzQ1Njc4OTAiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MTUxNjI0MjYyMn0.8paFWuHoJM2SBa9zcxoltlb54XEb60ME2AuauExlBPM
    target_jwt_hs256 := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhdWRpZW5jZSIsInN1YiI6IjEyMzQ1Njc4OTAiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MTUxNjI0MjYyMn0.8paFWuHoJM2SBa9zcxoltlb54XEb60ME2AuauExlBPM"
    result_hs256 := jwt.sign --payload=payload --secret=secret --algorithm="HS256"
    expect ((result_hs256.split ".")[0] == (target_jwt_hs256.split ".")[0]) --message="Headers should match using HS256"
    expect ((result_hs256.split ".")[1] == (target_jwt_hs256.split ".")[1]) --message="Payloads should match using HS256"
    expect ((result_hs256.split ".")[2] == (target_jwt_hs256.split ".")[2]) --message="Signatures should match using HS256"
    expect (result_hs256 == target_jwt_hs256) --message="JWTs should match using HS256"

    /**
    Test JWT generation using HS384
    */
    // https://jwt.io/#debugger-io?token=eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhdWRpZW5jZSIsInN1YiI6IjEyMzQ1Njc4OTAiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MTUxNjI0MjYyMn0.RnlOud71NtkYoEoxJwPcTNjEyqg4958g4BZwxqgKstqGxnP1Y0hmjqIRkhfOC_xl
    target_jwt_hs384 := "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhdWRpZW5jZSIsInN1YiI6IjEyMzQ1Njc4OTAiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MTUxNjI0MjYyMn0.RnlOud71NtkYoEoxJwPcTNjEyqg4958g4BZwxqgKstqGxnP1Y0hmjqIRkhfOC_xl"
    result_hs384 := jwt.sign --payload=payload --secret=secret --algorithm="HS384"
    expect (result_hs384 == target_jwt_hs384) --message="JWTs should match using HS384"

    /**
    Test JWT generation using HS512
    */
    // https://jwt.io/#debugger-io?token=eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhdWRpZW5jZSIsInN1YiI6IjEyMzQ1Njc4OTAiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MTUxNjI0MjYyMn0.RnlOud71NtkYoEoxJwPcTNjEyqg4958g4BZwxqgKstqGxnP1Y0hmjqIRkhfOC_xl
    target_jwt_hs512 := "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhdWRpZW5jZSIsInN1YiI6IjEyMzQ1Njc4OTAiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MTUxNjI0MjYyMn0.G0493IJf3RuQpbtoidaLzHT0GSqUwuExoXizQ5GunfDB0LOCmLBjfeVH6i_hl-HkhFbCAIeRSIn2pqlIw5tAAg"
    result_hs512 := jwt.sign --payload=payload --secret=secret --algorithm="HS512"
    expect (result_hs512 == target_jwt_hs512) --message="JWTs should match using HS512"

    /**
    Test JWT verification using HS265, HS384 and HS512
    */

    // Updated "exp" field of payload to be in the future, instead of the predefined value, which is in the past and will cause a verification error
    payload["exp"] = ((Time.now).plus --h=1).s_since_epoch
    up_to_date_token_hs256 := jwt.sign --payload=payload --secret=secret --algorithm="HS256"
    up_to_date_token_hs384 := jwt.sign --payload=payload --secret=secret --algorithm="HS384"
    up_to_date_token_hs512 := jwt.sign --payload=payload --secret=secret --algorithm="HS512"

    expect_no_throw: (jwt.verify --token=up_to_date_token_hs256 --secret=secret --algorithm="HS256")
    expect_no_throw: (jwt.verify --token=up_to_date_token_hs384 --secret=secret --algorithm="HS384")
    expect_no_throw: (jwt.verify --token=up_to_date_token_hs512 --secret=secret --algorithm="HS512")

    // Test with predefined target token, which should have expired
    expect_throw "JWTVerifyError: Token expired": jwt.verify --token=target_jwt_hs256 --secret=secret --algorithm="HS256"

    /**
    Test that is_expired convenience method works
    */
    expect      (jwt.is_expired --token=target_jwt_hs256) --message="Token should be expired"
    expect_not  (jwt.is_expired --token=up_to_date_token_hs512) --message="Token should not be expired"

    /**
    Test that expires and expires_soon convenience methods works
    */
    expect      ((jwt.expires --token=up_to_date_token_hs256) == (Time.epoch --s=payload["exp"])) --message="expires should return the same value as the payload's exp field but as a Time object"
    expect      ((jwt.expires_soon --token=up_to_date_token_hs256 --h=1 --s=10)) --message="expires_soon should be true, as the token expires in 1 hour and the within-cutoff is set to 1h + 10s"
    expect_not  ((jwt.expires_soon --token=up_to_date_token_hs256 --m=59 --s=59)) --message="expires_soon should not be true, as the token expires in 1 hour and the within-cutoff is set to 1h minus 1s"
// A P-256 key and a token signed with it by Node's jsonwebtoken 9.0.3, to check that
// both sides agree on the ES256 format. The key is only used by this test.
TEST_EC_PRIVATE_KEY ::= """
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEII1zRV6MHq5bDDw8Xi7icb1yeQCgSff7e6XLsBs9ZtvcoAoGCCqGSM49
AwEHoUQDQgAEdHPKXQ2hTtlAPJVaktZSDl/ThECmr/VaFZHEabppwlKK3LRp36pI
Xqxw51BSg2+Bup3fKIoL8aVaOnL7BJ3BMg==
-----END EC PRIVATE KEY-----
"""

TEST_EC_PUBLIC_KEY ::= """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdHPKXQ2hTtlAPJVaktZSDl/ThECm
r/VaFZHEabppwlKK3LRp36pIXqxw51BSg2+Bup3fKIoL8aVaOnL7BJ3BMg==
-----END PUBLIC KEY-----
"""

NODE_ES256_TOKEN ::= "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3QifQ.eyJhdWQiOiJhdWRpZW5jZSIsInN1YiI6IjEyMzQ1Njc4OTAiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6NDEwMjQ0NDgwMH0.UJ7d5FQoiMEh24tDHpKpIltq721F-w9Be9_ySz8Vwyzb2C7v9ACaCG554P7ni-KqlNdZmA-sKpvIsxXrlwQ5Qw"

test_es256:
    private_key := ec.EcKey.parse_private TEST_EC_PRIVATE_KEY
    public_key := ec.EcKey.parse_public TEST_EC_PUBLIC_KEY
    payload := {
        "aud": "audience",
        "sub": "1234567890",
        "iat": 1516239022,
        "exp": 4102444800,
    }

    // A token signed by jsonwebtoken verifies here
    expect (jwt.verify --token=NODE_ES256_TOKEN --key=public_key) --message="Node's ES256 token should verify"

    // ECDSA signatures are randomized, so compare the header and payload, and verify the signature
    token := jwt.sign --payload=payload --key=private_key --header={"kid": "test"}
    parts := token.split "."
    node_parts := NODE_ES256_TOKEN.split "."
    expect_equals node_parts[0] parts[0]
    expect_equals node_parts[1] parts[1]
    expect_equals 86 parts[2].size  // 64 bytes, base64url without padding
    expect (jwt.verify --token=token --key=public_key) --message="ES256 token should verify"

    // Many signatures, so that some have integers with leading zero bytes or the top bit set
    100.repeat:
        t := jwt.sign --payload=payload --key=private_key
        expect (jwt.verify --token=t --key=public_key) --message="ES256 token should verify"

    // A generated key works too
    pair := ec.EcKeyPair.generate
    generated := jwt.sign --payload=payload --key=pair.private_key
    expect (jwt.verify --token=generated --key=pair.public_key)
    expect_not (jwt.verify --token=generated --key=public_key --no-throwing) --message="Wrong key should not verify"
    expect_throw "JWTVerifyError: Token signature mismatch": jwt.verify --token=generated --key=public_key

    // A tampered payload doesn't verify
    tampered_payload := payload.copy
    tampered_payload["sub"] = "someone-else"
    tampered := (jwt.sign --payload=tampered_payload --key=private_key).split "."
    forged := "$parts[0].$tampered[1].$parts[2]"
    expect_not (jwt.verify --token=forged --key=public_key --no-throwing)

    // The algorithm in the token's header must match: an HS256 token isn't accepted as ES256,
    // and an ES256 token isn't accepted as HS256
    hs256 := jwt.sign --payload=payload --secret="secret"
    expect_not (jwt.verify --token=hs256 --key=public_key --no-throwing)
    expect_throw "JWTVerifyError: Token algorithm is not ES256": jwt.verify --token=hs256 --key=public_key
    expect_not (jwt.verify --token=token --secret="secret" --no-throwing)

    // Unsupported algorithms, public keys and reserved header fields
    expect_throw "JWTSignError: Unsupported algorithm: HS256": jwt.sign --payload=payload --key=private_key --algorithm="HS256"
    expect_throw "JWTSignError: Unsupported algorithm: ES256": jwt.sign --payload=payload --secret="secret" --algorithm="ES256"
    expect_throw "JWTSignError: Signing needs a private key": jwt.sign --payload=payload --key=public_key
    expect_throw "JWTSignError: The header can't set 'alg' or 'typ'": jwt.sign --payload=payload --key=private_key --header={"alg": "none"}

    // Expired tokens throw
    expired_payload := payload.copy
    expired_payload["exp"] = 1516242622
    expired := jwt.sign --payload=expired_payload --key=private_key
    expect_throw "JWTVerifyError: Token expired": jwt.verify --token=expired --key=public_key

test_signature_conversion:
    r := ByteArray 32: it + 1
    s := ByteArray 32: 0xff - it

    // r has no leading zero, s has its top bit set and needs one in DER
    der := #[0x30, 0x45, 0x02, 0x20] + r + #[0x02, 0x21, 0x00] + s
    expect_equals (r + s) (jwt.der_to_jose_signature der --integer_size=32)
    expect_equals der (jwt.jose_to_der_signature r + s --integer_size=32)

    // Short integers are left-padded
    short_r := #[0x00, 0x00] + r[2..]
    short_der := #[0x30, 0x43, 0x02, 0x1e] + r[2..] + #[0x02, 0x21, 0x00] + s
    expect_equals (short_r + s) (jwt.der_to_jose_signature short_der --integer_size=32)
    expect_equals short_der (jwt.jose_to_der_signature short_r + s --integer_size=32)

    // A zero integer
    zero := ByteArray 32
    zero_der := #[0x30, 0x26, 0x02, 0x01, 0x00, 0x02, 0x21, 0x00] + s
    expect_equals (zero + s) (jwt.der_to_jose_signature zero_der --integer_size=32)
    expect_equals zero_der (jwt.jose_to_der_signature zero + s --integer_size=32)

    // Malformed input throws
    expect_throw "JWTSignatureError: Signature is not a DER sequence": jwt.der_to_jose_signature #[0x31, 0x00] --integer_size=32
    expect_throw "JWTSignatureError: Wrong DER sequence length": jwt.der_to_jose_signature der[..der.size - 1] --integer_size=32
    expect_throw "JWTSignatureError: Expected a DER integer": jwt.der_to_jose_signature #[0x30, 0x02, 0x03, 0x00] --integer_size=32
    too_large := #[0x30, 0x46, 0x02, 0x21, 0x01] + r + #[0x02, 0x21, 0x00] + s
    expect_throw "JWTSignatureError: Signature integer too large": jwt.der_to_jose_signature too_large --integer_size=32
    expect_throw "JWTSignatureError: Signature must be 64 bytes": jwt.jose_to_der_signature r --integer_size=32
