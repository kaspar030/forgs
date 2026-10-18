# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/kaspar030/forgs/compare/forgs-idp-v0.1.1...forgs-idp-v0.2.0) - 2026-10-18

### Other

- Workload JWT single use: record (issuer, jti) until exp+leeway, refuse replay (audit IDP-5)
- per-provider trust_email_verified knob; untrusted providers never claim user emails (audit IDP-4)
- Workload claim constraints: ref/environment/job_workflow_ref/event allow-lists, event deny-list (pull_request_target by default), ref_protected; record extra claims (audit IDP-3)
- Don't persist unauthenticated audit noise; add audit retention to the sweep (HTTP-05)
- zeroize secrets, credfile helper, document GHA behaviour under a pin (CL-7, CL-8, CL-9)
- cold JWKS callers under the floor wait for the in-flight fetch
- OIDC/JWKS hardening (IDP-6..9)
- Key GHA workload subjects on immutable repo/owner ids and namespace them per issuer
