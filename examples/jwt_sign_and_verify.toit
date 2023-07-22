import jwt

main:

  payload := {
    "aud": "audience",
    "sub": "1234567890",
    "iat": Time.now.s_since_epoch,
    "exp": (Time.now.plus --h=1).s_since_epoch
  }
  secret := "super-secret-key"
  algorithm := "HS256"  // Supported algorithms: "HS256", "HS384", "HS512"

  /**
  Signing
  */
  token := jwt.sign --payload=payload --secret=secret --algorithm=algorithm

  /**
  Verifying
  */
  is_valid := jwt.verify --token=token --secret=secret --algorithm=algorithm

  /**
  Is expired?
  */
  is_expired := jwt.is_expired --token=token

  /**
  Get a Time object, indicating when the token expires
  */
  expires := jwt.expires --token=token
  print "Token expires at: $expires.stringify"

  /**
  Test wether the token expires soon (default is within 5mins)
  */
  expires_soon := jwt.expires_soon --token=token
  if expires_soon: print "Token expires soon"
  else: print "Token does not expire soon"

  expires_within_1h := jwt.expires_soon --token=token --h=1
  if expires_within_1h: print "Token expires within 1h"  

  /**
  Verify non-throwing

  Be default, jwt.verify will throw an error, if verification fails.
  You can force the function to return a boolean instead by passing --throwing=false
  */
  is_valid_non_throwing := jwt.verify --token=token --secret=secret --algorithm=algorithm --throwing=false
