# Settings and local account RBAC

Settings opens as a same-page native modal from the lower-left button. Audit Logs and Appearance moved inside Settings; Profile & account shows the authenticated username, role, access profile and UEBA binding. Manage users is Administrator-only, with separate Users and Roles tabs. On mobile the settings navigation wraps without opening browser tabs.

The first administrator is initialized explicitly through the local Profile form, requiring a 12–256 character password and a declared administrator role. No default credential is embedded. Bootstrap atomically refuses a second initialization, invalidates all existing demo sessions and permanently closes demo identity switching while any account exists. Subsequent visits require local sign-in. Account records/roles survive restart and activity reset; cookies/sessions are process-local and expire after eight hours. The UI never receives password hashes/salts. Passwords use independent random 128-bit salts and PBKDF2-HMAC-SHA256 (600,000 iterations). Login errors are generic; five attempts per username and thirty total per rolling minute are enforced using persisted metadata. CSRF, same-origin and loopback checks apply to account operations.

| Access profile | Capabilities |
| --- | --- |
| Administrator | Security review, audit access, integrations and user/role management |
| Analyst | Existing security review, audit, governed labels, endpoint controls and integrations; no account management |
| User | Governed AI/transfer actions and own bound UEBA subject; no audit/account administration |

Custom roles inherit one of these fixed profiles. This is not a per-action permission editor. Accounts with a User profile require an existing UEBA subject binding; multiple accounts may share a binding and therefore share its behavior context. Administrative accounts have no employee transfer identity. Machine keys remain separately scoped service identities; disabling an account does not implicitly revoke independent integration credentials.

Administrators can create accounts/roles, update role/binding and disable/re-enable accounts. Account activity and role permissions are re-read on every HTTP request, so disabled accounts lose session access immediately on the next request. A transaction prevents disabling/demoting the last active Administrator. Built-in profiles and existing role definitions are immutable through the exposed API; new role names must be unique. No account hard-delete, self-service password change, password recovery, MFA or multi-tenant account store is claimed. Current local account mode and the existing optional OIDC mode are mutually exclusive at startup; do not enable both. For external organizational exposure, TLS ingress and reviewed identity provisioning are required; this server continues to bind to loopback only.

Routes: GET `/api/account/context` provides the current session's setup/sign-in context and CSRF value; POST `/api/account/bootstrap`, POST `/api/account/login`; GET `/api/accounts`, POST `/api/accounts/users`, POST `/api/accounts/roles` are protected by the current server-derived account profile. Supplying role or actor fields to ordinary transfer/session requests cannot grant management access.

Tests use isolated temporary stores and fictional passwords. Runtime accounts databases, credential files and their backups must remain outside Git. Account changes record metadata-only audit events. Stored hashes protect passwords from direct disclosure, but SQLite and local files are not immutable against an OS administrator.
