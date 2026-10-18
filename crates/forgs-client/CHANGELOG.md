# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/kaspar030/forgs/compare/forgs-client-v0.1.1...forgs-client-v0.2.0) - 2026-10-18

### Other

- SSH public keys as a user credential: parsing/fingerprints (forgs::ssh), SshKeyStore seam + authenticate_ssh_key, forgs_ssh_key table (migration 9), /auth/keys/ssh routes, client calls, logout --all ssh_keys_added_after
- Keys/members API: live-key caps per namespace and user, paginated listings, hash-prefix-only and role-gated key detail, audit refused mints and non-member writes (audit HTTP-13)
- Workload JWT single use: record (issuer, jti) until exp+leeway, refuse replay (audit IDP-5)
- Last-admin guard: transactional re-check, count only active users, pin personal owner
- Rate-limit root-name releases, attribute tombstones, operator release API, optional tombstone cool-down (audit HTTP-07)
- Don't persist unauthenticated audit noise; add audit retention to the sweep (HTTP-05)
- Identity linking: step-up re-auth (cookie only), list/unlink routes, logout --all can unlink late identities (audit HB-2)
- zeroize secrets, credfile helper, document GHA behaviour under a pin (CL-7, CL-8, CL-9)
- harden browser launch, http/pin policy, device-flow inputs (audit CL-1..CL-6)
- Key GHA workload subjects on immutable repo/owner ids and namespace them per issuer
