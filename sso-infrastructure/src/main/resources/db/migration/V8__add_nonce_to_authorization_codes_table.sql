ALTER TABLE authorization_codes
    ADD COLUMN nonce VARCHAR(255);

COMMENT ON COLUMN authorization_codes.nonce IS
    'Optional OIDC nonce (RFC OpenID Connect Core 1.0, section 3.1.2.1) captured from GET /authorize and echoed back unchanged as the id_token nonce claim by POST /token (Phase 3.4). Nullable because nonce is RECOMMENDED, not REQUIRED, for the Authorization Code flow - a client that omits it still gets a valid code, just with no nonce to echo back.';
