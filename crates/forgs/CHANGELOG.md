# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/kaspar030/forgs/releases/tag/forgs-v0.1.0) - 2026-10-14

### Other

- Add Cargo metadata and license files for publishing
- describe forgs as it is now, not how it got here
- create_namespace / delete_namespace (atomic create + admin, owned-count cap)
- Seams for apps: AppTokenLookup in forgs-http, API-key payloads via ApiKeyPurposes::check_payload, public ForgsClient::post/post_json with route guard, members/rename client calls
- axum auth routes, signup, device authorization server, cookies/CSRF
- device login, refresh, logout, API keys and workload exchange over hyper+rustls/ring
- identity providers (GitHub, generic OIDC + Codeberg/Forgejo/GitLab presets) and GitHub Actions workload OIDC
- workspace scaffold and pure core crate
