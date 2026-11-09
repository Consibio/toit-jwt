# Changelog

## v1.3.0

### Added
- ES256 (ECDSA with P-256 and SHA-256): `sign --key` and `verify --key`, with an `EcKey` from
  `crypto.ec`. Signatures are the raw 64-byte `r||s` form of RFC 7518.
- `sign` takes a `--header` with extra header fields, eg. `kid`.
- `HMAC_ALGORITHMS`, `EC_ALGORITHMS` and `ES256_INTEGER_SIZE`.

### Behaviour changes
- `verify` rejects a token whose header doesn't name the expected `--algorithm`, including a
  token without `alg`. Before, the header was ignored.
- `verify --no-throwing` now returns false for an expired token. Before, it only checked the
  signature, so it accepted expired tokens.
- `verify` rejects a token whose `nbf` hasn't passed.
- `verify` rejects a token without `exp` with "JWTVerifyError: Token has no expiration" (it was
  "Token expired"), and a token whose payload isn't a JSON object with "JWTVerifyError:
  Malformed token" (it was "Token expired").
- `verify` rejects tokens with more than three parts. With `--no-throwing`, a token with fewer
  than three parts returns false instead of throwing an out-of-bounds error.
- HS256, HS384 and HS512 signatures are compared in constant time.
- `SUPPORTED_ALGORITHMS` includes `"ES256"`, which `sign --secret` doesn't take: use
  `HMAC_ALGORITHMS` for the algorithms that take a secret.

### Requirements
- Toit SDK v2.0.0-alpha.195 or newer, the first with `crypto.ec`.
