# Authenticator lifecycle and navigation — 0.18

The header sidebar button hides or reopens navigation in both the security console and AI Workspace. Hidden navigation is inert for keyboard/screen-reader focus; the header toggle remains available. The preference is local/cross-tab and stores only a boolean. Settings remains anchored to its trigger; narrow displays retain an in-viewport layout. Sign-in has responsive account, verification and recovery stages, shared appearance, password visibility and an allowlisted return section. No account/factor value is saved as a UI preference.

## User Management

Settings → Users → User Management displays authenticator enrollment and remaining recovery-code counts. Administrators have `accounts.reset_mfa`; an Administrator may explicitly delegate it on an Analyst role alongside `accounts.read`. Existing delegated roles do not automatically gain this permission. Delegated operators cannot modify themselves, Administrators or other privileged/delegated operators. The server rechecks the operator's current role and authentication version inside the update transaction.

- **Add MFA** retires pending challenges/sessions and requires the owner to enroll at next sign-in. Operators do not choose, receive or register the owner's secret.
- **Change MFA** retires a registered factor for verified device replacement/recovery, revokes old recovery codes and requires new owner enrollment.
- **Remove MFA** deletes the existing authenticator registration and recovery codes; it does not turn off mandatory MFA. Old sessions and pending challenges become invalid immediately on their next request. The account stays active/disabled as before.

Every operator mutation requires the operator's current password and an unused authenticator/recovery code. Inputs are not logged. Actions use an explicit target revision, bounded reason choices and CSRF; concurrent target changes require directory refresh. Metadata audit events record actor, target, action and reason. Before using a recovery control, an organization must perform its own identity verification; this prototype does not independently prove a caller's identity outside the configured factors. Independent machine credentials are not implicitly revoked.

## Own authenticator

The current account uses Profile & account → Change my MFA. Password plus the existing authenticator/recovery code authorizes a five-minute replacement setup. The current factor stays active while the new QR is pending. A valid code from the new authenticator atomically replaces the seed, issues ten new one-use recovery codes and advances the account authentication version. Other sessions and all prior recovery codes are revoked; the completing session is rotated. Failed/expired setup leaves the prior factor in place. The pending secret is excluded from ordinary state responses and audit metadata. Codes/setup are cleared when the Settings panel is closed.

Self-removal through User Management is denied to avoid locking out the last Administrator. If the last Administrator loses both its authenticator and recovery codes, web recovery is intentionally unavailable; restoring access requires an independently authorized offline procedure. The implementation does not provide automated identity proofing, multiple simultaneous authenticators or WebAuthn. Local accounts and organization OIDC remain separate modes; IdP factors are managed at the IdP.

Tests use fictional accounts in temporary loopback stores and verify reauthentication, CSRF, authority revocation, self-reset denial, factor/recovery/session retirement, stale target versions, replacement expiry and concurrent authentication-version changes. Real configured factors are preserved during deployment.
