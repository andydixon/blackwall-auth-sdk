# BlackWall Provider Security Model (SDK View)

Last reviewed: 2026-02-26

This document summarises provider-side security guarantees that SDK integrators should design around.

## Threat Assumptions

- Provider is internet-exposed.
- Attackers can register and attempt tenant-boundary abuse.
- OAuth/WebAuthn endpoints are abuse targets and may rate limit.

## Invariants Integrators Should Assume

1. Tenant/project/user/client scope is enforced server-side and can change between request steps.
2. OAuth authorize can fail with `invalid_scope` if requested scopes are not currently allowed for the client.
3. Token/refresh exchange can fail with `invalid_grant` when subject/client state or scope policy changes.
4. UserInfo can fail for revoked/invalid/inactive subjects even before nominal token expiry.
5. Admin and portal workflows are distinct scope domains; do not mix them in client UX flows.

## Integration Guidance

- Keep requested scopes minimal and aligned to the provider client configuration.
- Treat `access_denied`, `invalid_scope`, and `invalid_grant` as expected security outcomes, not transport errors.
- Build retries only for transient failures; do not blindly retry authz/authn denials.
- Keep enrolment URLs/tokens and OAuth tokens out of URLs, logs, and analytics tags.
- Use strict HTTPS and secure session-cookie handling in the relying party app.
