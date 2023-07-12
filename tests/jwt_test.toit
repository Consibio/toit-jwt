/**
  To execute, run: 
  jag run -d host jwt_test.toit
*/

import jwt
import expect show *

main:
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