/**
  To execute, run: 
  jag run -d host jwt_test.toit
*/

import jwt
import expect show *

main:
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
    Test JWT verification using HS265
    */
    expect (jwt.verify --token=target_jwt_hs256 --secret=secret --algorithm="HS256") --message="JWT should be verified using HS256"
    expect (jwt.verify --token=target_jwt_hs384 --secret=secret --algorithm="HS384") --message="JWT should be verified using HS384"
    expect (jwt.verify --token=target_jwt_hs512 --secret=secret --algorithm="HS512") --message="JWT should be verified using HS512"

    // Induce error and assert, that verification fails
    faulty_target_jwt_hs256 := target_jwt_hs256.replace "e" "E"
    expect_not (jwt.verify --token=faulty_target_jwt_hs256 --secret=secret --algorithm="HS256") --message="Faulty JWT should not be verified using HS256"
