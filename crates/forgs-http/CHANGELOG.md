# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/kaspar030/forgs/compare/forgs-http-v0.1.1...forgs-http-v0.2.0) - 2026-10-18

### Other

- SSH public keys as a user credential: parsing/fingerprints (forgs::ssh), SshKeyStore seam + authenticate_ssh_key, forgs_ssh_key table (migration 9), /auth/keys/ssh routes, client calls, logout --all ssh_keys_added_after
- Keys/members API: live-key caps per namespace and user, paginated listings, hash-prefix-only and role-gated key detail, audit refused mints and non-member writes (audit HTTP-13)
- Name/subject canonicalisation: refuse id-shaped root names, case-insensitive child names (migration 7), canonical SubjectKey::parse (audit AN-5/6/8/9)
- check allowed kinds before DB lookup, fail-closed SystemClock, cookie_api_prefix must end with /
- Workload JWT single use: record (issuer, jti) until exp+leeway, refuse replay (audit IDP-5)
- Last-admin guard: transactional re-check, count only active users, pin personal owner
- Workload claim constraints: ref/environment/job_workflow_ref/event allow-lists, event deny-list (pull_request_target by default), ref_protected; record extra claims (audit IDP-3)
- Rate-limit root-name releases, attribute tombstones, operator release API, optional tombstone cool-down (audit HTTP-07)
- Device flow abuse hardening: per-kind + per-source start caps with ClientIp hook, enforced slow_down, uniform 404 + lockout for user-code guessing, typed code + review step, cancellable approvals (audit HTTP-06, HTTP-11, HTTP-08/TC-5, HB-3, HTTP-13)
- Don't persist unauthenticated audit noise; add audit retention to the sweep (HTTP-05)
- Identity linking: step-up re-auth (cookie only), list/unlink routes, logout --all can unlink late identities (audit HB-2)
- Cookie hardening: __Host- prefix, Origin required for cookie-ticket signup, login revokes previous session, logout clears flow cookies, nosniff on JSON errors, default-port public_url (audit HB-1, HB-4, HB-5)
- API keys die with their creator's standing; derived workload tokens die with key/creator (audit HTTP-03/AN-7, HTTP-10, TC-4)
- zeroize secrets, credfile helper, document GHA behaviour under a pin (CL-7, CL-8, CL-9)
- Session refresh: atomic consume and absolute chain lifetime (auth_time, Ttls::session_max_life)
- Key GHA workload subjects on immutable repo/owner ids and namespace them per issuer
- Named workload identities require the highest role; check_payload gets caller context (KeyMint); unnamed key subject uses ApiKeyId
