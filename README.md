# toit-jwt
Toit package for signing and verifying JWTs.
This library is a work in progress. Please feel free to open issues or open pull requests, if features are missing.

## Example
```
import jwt

payload := {
  "aud": "audience",
  "sub": "1234567890",
  "iat": Time.now.s_since_epoch,
  "exp": (Time.now.plus --h=1).s_since_epoch
}
secret := "super-secret-key"

token := jwt.sign --payload=payload --secret=secret --algorithm="HS256"
is_valid := jwt.verify --token=token --secret=secret --algorithm="HS256"

is_expired := jwt.is_expired --token=token
```

### ES256

ES256 signs with an EC P-256 private key from `crypto.ec`. The signature is the raw 64-byte
`r||s` form that JWTs use (RFC 7518, section 3.4), not the DER form that `EcKey.sign` returns.

```
import crypto.ec as ec
import jwt

payload := {
  "sub": "1234567890",
  "exp": (Time.now.plus --h=1).s_since_epoch
}
key_pair := ec.EcKeyPair.generate  // P-256 by default
token := jwt.sign --payload=payload --key=key_pair.private_key --header={"kid": "my-key"}
is_valid := jwt.verify --token=token --key=key_pair.public_key
```

ES256 needs a P-256 key; `sign` and `verify` throw for keys on other curves. Keys come from
`crypto.ec`, which parses PEM or DER: SEC1 or PKCS#8 private keys, and SubjectPublicKeyInfo
public keys. A raw 65-byte point isn't accepted. `verify` also takes a private key, and then
uses its public key.

The library needs Toit SDK v2.0.0-alpha.195 or newer, the first with `crypto.ec`.

## What `verify` checks

- The signature.
- That the token's header names the expected algorithm, so a token can't choose how it is
  verified.
- That the token has an `exp` that hasn't passed. A token without `exp` is rejected.
- That its `nbf`, if it has one, has passed.

It doesn't check other claims, such as `aud`, `iss`, `sub` or `iat`. Check those yourself.

`verify` throws if the token isn't valid. With `--no-throwing`, it returns false instead.

ECDSA signatures can be changed into another valid signature for the same token, so don't use
the token string as a unique key, eg. to detect replays.

## Algorithms

### Supported algorithms

| Algorithm           | Signing algorithm      |
|---------------------|------------------------|
| HS256               | HMAC using SHA-256     |
| HS384               | HMAC using SHA-384     |
| HS512               | HMAC using SHA-512     |
| ES256               | ECDSA using P-256 and SHA-256 |


### Algorithms not yet supported
The following algorithms are not yet supported (but are planned to be included in the future):

| Algorithm           | Signing algorithm                  |
|---------------------|------------------------------------|
| RS256               | RSASSA-PKCS1-v1_5 using SHA-256    |
| RS384               | RSASSA-PKCS1-v1_5 using SHA-384    |
| RS512               | RSASSA-PKCS1-v1_5 using SHA-512    |

### Unsupported algorithms
The following algorithms are not supported and there are no plans to implemented them. 
If you need this anyways, please open an issue.

| Algorithm           | Signing algorithm                    |
|---------------------|--------------------------------------|
| PS256               | RSASSA-PSS using SHA-256             |
| PS384               | RSASSA-PSS using SHA-384             |
| PS512               | RSASSA-PSS using SHA-512             |
| ES384               | ECDSA using P-384 curve and SHA-384  |
| ES512               | ECDSA using P-521 curve and SHA-512  |
