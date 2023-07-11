import jwt

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
Verify non-throwing

Be default, jwt.verify will throw an error, if verification fails.
You can force the function to return a boolean instead by passing --throwing=false
*/
is_valid_non_throwing := jwt.verify --token=token --secret=secret --algorithm=algorithm --throwing=false
