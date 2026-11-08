/**
  To execute, run: 
  jag run -d host jwt_test.toit
*/

import jwt
import crypto.ec as ec
import encoding.base64 as base64
import encoding.json as json
import expect show *

main:
    test_hmac
    test_es256
    test_rfc7515_es256
    test_claims
    test_curves
    test_malformed_tokens
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

    // A signature of the right size with one character changed doesn't verify
    parts := up_to_date_token_hs256.split "."
    last := parts[2][parts[2].size - 1] == 'A' ? "B" : "A"
    changed := "$parts[0].$parts[1].$parts[2][..parts[2].size - 1]$last"
    expect_not (jwt.verify --token=changed --secret=secret --no-throwing)
    expect_throw "JWTVerifyError: Token signature mismatch": jwt.verify --token=changed --secret=secret
    expect_not (jwt.verify --token=up_to_date_token_hs256 --secret="another-secret" --no-throwing)

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

    // A private key verifies through its public key
    expect (jwt.verify --token=token --key=private_key) --message="A private key should verify"
    expect_not (jwt.verify --token=generated --key=private_key --no-throwing) --message="Wrong private key should not verify"

/**
The ES256 example of RFC 7515, Appendix A.3, which other implementations use as well.

Its token expired in 2011, so the signature is checked directly.
*/
test_rfc7515_es256:
    // The JWK of the example, as a SubjectPublicKeyInfo: the P-256 prefix and the uncompressed point
    x := base64.decode "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU" --url_mode
    y := base64.decode "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0" --url_mode
    spki := #[
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
    ] + x + y
    public_key := ec.EcKey.parse_public spki

    signing_input := "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    signature := base64.decode "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q" --url_mode
    expect_equals 64 signature.size
    der := jwt.jose_to_der_signature_ signature --integer_size=jwt.ES256_INTEGER_SIZE
    expect (public_key.verify signing_input der --hash=ec.EcKey.SHA_256) --message="RFC 7515 A.3 should verify"
    expect_equals signature (jwt.der_to_jose_signature_ der --integer_size=jwt.ES256_INTEGER_SIZE)

    flipped := signature.copy
    flipped[10] ^= 0x01
    flipped_der := jwt.jose_to_der_signature_ flipped --integer_size=jwt.ES256_INTEGER_SIZE
    expect_not (public_key.verify signing_input flipped_der --hash=ec.EcKey.SHA_256)

    // As a token, it is rejected: it expired in 2011
    token := "$signing_input.$(base64.encode signature --url_mode)"
    expect_not (jwt.verify --token=token --key=public_key --no-throwing)
    expect_throw "JWTVerifyError: Token expired": jwt.verify --token=token --key=public_key

/**
The "exp" and "nbf" claims are checked with and without throwing.
*/
test_claims:
    private_key := ec.EcKey.parse_private TEST_EC_PRIVATE_KEY
    public_key := ec.EcKey.parse_public TEST_EC_PUBLIC_KEY
    secret := "super-secret-key"
    now := Time.now.s_since_epoch

    check := : | payload/Map expected_error/string? |
        es256 := jwt.sign --payload=payload --key=private_key
        hs256 := jwt.sign --payload=payload --secret=secret
        if expected_error:
            expect_not (jwt.verify --token=es256 --key=public_key --no-throwing) --message="ES256 should fail: $expected_error"
            expect_not (jwt.verify --token=hs256 --secret=secret --no-throwing) --message="HS256 should fail: $expected_error"
            expect_throw expected_error: jwt.verify --token=es256 --key=public_key
            expect_throw expected_error: jwt.verify --token=hs256 --secret=secret
        else:
            expect (jwt.verify --token=es256 --key=public_key --no-throwing)
            expect (jwt.verify --token=hs256 --secret=secret --no-throwing)

    check.call {"exp": now + 60} null
    check.call {"exp": now - 60} "JWTVerifyError: Token expired"
    check.call {"exp": 1} "JWTVerifyError: Token expired"
    check.call {"sub": "no expiry"} "JWTVerifyError: Token has no expiration"
    check.call {"exp": "tomorrow"} "JWTVerifyError: Malformed token"
    check.call {"exp": now + 60, "nbf": now - 60} null
    check.call {"exp": now + 60, "nbf": now + 3600} "JWTVerifyError: Token not yet valid"
    check.call {"exp": now + 60, "nbf": "later"} "JWTVerifyError: Malformed token"

    // A payload that isn't a JSON object
    header := base64.encode (json.stringify {"alg": "HS256", "typ": "JWT"}) --url_mode
    [base64.encode "[1, 2]" --url_mode, base64.encode "not json" --url_mode, "%%%"].do: | payload_b64 |
        content := "$header.$payload_b64"
        token := "$content.$(base64.encode (jwt.compute_signature_ --jwt_content=content --secret=secret) --url_mode)"
        expect_not (jwt.verify --token=token --secret=secret --no-throwing)
        expect_throw "JWTVerifyError: Malformed token": jwt.verify --token=token --secret=secret

// A secp256k1 key, which isn't P-256 although its integers have the same size.
TEST_SECP256K1_PRIVATE_KEY ::= """
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIDqYsat3S/16UCsi0510jZnk2mct7XuvCaDvy8Mzi7rZoAcGBSuBBAAK
oUQDQgAEWizuvjnnupkugeDl7OhIJ4QeSYMxhxWCLQhIh5ViWwrDrYfgT/gFuUfb
YKUHcVVFAiKl5oDOIPIskHn1QtY4Gg==
-----END EC PRIVATE KEY-----
"""

/**
ES256 needs a P-256 key, both to sign and to verify.
*/
test_curves:
    payload := {"exp": Time.now.s_since_epoch + 60}
    p256 := ec.EcKey.parse_private TEST_EC_PRIVATE_KEY
    token := jwt.sign --payload=payload --key=p256

    k1 := ec.EcKey.parse_private TEST_SECP256K1_PRIVATE_KEY
    p384 := (ec.EcKeyPair.generate --curve=ec.EcKey.CURVE_SECP384R1).private_key
    p521 := (ec.EcKeyPair.generate --curve=ec.EcKey.CURVE_SECP521R1).private_key
    [k1, p384, p521].do: | key/ec.EcKey |
        expect_throw "JWTSignError: ES256 needs a P-256 key": jwt.sign --payload=payload --key=key
        expect_throw "JWTVerifyError: ES256 needs a P-256 key": jwt.verify --token=token --key=key
        public_key := ec.EcKey.parse_public key.der
        expect_throw "JWTVerifyError: ES256 needs a P-256 key": jwt.verify --token=token --key=public_key --no-throwing

/**
Malformed tokens and signatures make verify fail, without other errors.
*/
test_malformed_tokens:
    private_key := ec.EcKey.parse_private TEST_EC_PRIVATE_KEY
    public_key := ec.EcKey.parse_public TEST_EC_PUBLIC_KEY
    token := jwt.sign --payload={"exp": Time.now.s_since_epoch + 60} --key=private_key
    parts := token.split "."
    content := "$parts[0].$parts[1]"
    raw := base64.decode parts[2] --url_mode
    der := jwt.jose_to_der_signature_ raw --integer_size=jwt.ES256_INTEGER_SIZE

    none_header := base64.encode (json.stringify {"alg": "none", "typ": "JWT"}) --url_mode
    bad_signatures := [
        "",
        "$(parts[2])=",  // Padding
        base64.encode raw,  // Not base64url
        base64.encode der --url_mode,  // DER instead of raw
        base64.encode raw[..63] --url_mode,  // Truncated
        base64.encode (ByteArray 64) --url_mode,  // All zeros
        base64.encode (ByteArray 64: 0xff) --url_mode,
    ]
    bad_tokens := bad_signatures.map: "$content.$it"
    bad_tokens += [
        content,
        "$content.$(parts[2]).extra",
        "$none_header.$parts[1].",
        "not a token",
    ]
    bad_tokens.do: | bad/string |
        expect_not (jwt.verify --token=bad --key=public_key --no-throwing) --message="Should not verify: $bad"
        expect_throw_any: jwt.verify --token=bad --key=public_key
        expect_not (jwt.verify --token=bad --secret="secret" --no-throwing) --message="Should not verify as HS256: $bad"

expect_throw_any [block]:
    error := catch: block.call
    expect_not_null error

test_signature_conversion:
    r := ByteArray 32: it + 1
    s := ByteArray 32: 0xff - it

    // r has no leading zero, s has its top bit set and needs one in DER
    der := #[0x30, 0x45, 0x02, 0x20] + r + #[0x02, 0x21, 0x00] + s
    expect_equals (r + s) (jwt.der_to_jose_signature_ der --integer_size=32)
    expect_equals der (jwt.jose_to_der_signature_ r + s --integer_size=32)

    // Short integers are left-padded
    short_r := #[0x00, 0x00] + r[2..]
    short_der := #[0x30, 0x43, 0x02, 0x1e] + r[2..] + #[0x02, 0x21, 0x00] + s
    expect_equals (short_r + s) (jwt.der_to_jose_signature_ short_der --integer_size=32)
    expect_equals short_der (jwt.jose_to_der_signature_ short_r + s --integer_size=32)

    // A zero integer
    zero := ByteArray 32
    zero_der := #[0x30, 0x26, 0x02, 0x01, 0x00, 0x02, 0x21, 0x00] + s
    expect_equals (zero + s) (jwt.der_to_jose_signature_ zero_der --integer_size=32)
    expect_equals zero_der (jwt.jose_to_der_signature_ zero + s --integer_size=32)

    // Malformed input throws
    expect_throw "JWTSignatureError: Signature is not a DER sequence": jwt.der_to_jose_signature_ #[0x31, 0x00] --integer_size=32
    expect_throw "JWTSignatureError: Wrong DER sequence length": jwt.der_to_jose_signature_ der[..der.size - 1] --integer_size=32
    expect_throw "JWTSignatureError: Expected a DER integer": jwt.der_to_jose_signature_ #[0x30, 0x02, 0x03, 0x00] --integer_size=32
    too_large := #[0x30, 0x46, 0x02, 0x21, 0x01] + r + #[0x02, 0x21, 0x00] + s
    expect_throw "JWTSignatureError: Signature integer too large": jwt.der_to_jose_signature_ too_large --integer_size=32
    expect_throw "JWTSignatureError: Signature must be 64 bytes": jwt.jose_to_der_signature_ r --integer_size=32
    expect_throw "JWTSignatureError: Integer size must be positive": jwt.jose_to_der_signature_ #[] --integer_size=0
    expect_throw "JWTSignatureError: Integer size must be positive": jwt.der_to_jose_signature_ der --integer_size=0
