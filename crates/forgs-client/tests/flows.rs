//! End-to-end flows against a loopback stub server.

mod common;

use std::time::Duration;

use common::{Reply, StubServer};
use forgs_client::api::{DevicePollResponse, TokenResponse};
use forgs_client::{
    gha, refresh, ApiKeySpec, ClientError, DeviceLogin, DeviceLoginError, ForgsClient, PollPolicy,
    Secret,
};
use serde_json::json;

/// Every secret the stub issues or the tests send contains this marker, so
/// one substring check proves nothing leaked into `Debug` output.
const MARK: &str = "SEKRIT";

fn assert_redacted(v: &impl std::fmt::Debug) {
    let s = format!("{v:?}");
    assert!(!s.contains(MARK), "secret leaked into Debug: {s}");
}

async fn setup() -> (StubServer, ForgsClient) {
    let stub = StubServer::start().await;
    let client = ForgsClient::new(&stub.base(), None)
        .unwrap()
        .with_timeout(Duration::from_secs(5));
    (stub, client)
}

fn token_json(with_refresh: bool) -> serde_json::Value {
    let mut v = json!({"token": format!("{MARK}-session"), "expires": 1000,
                       "username": "alice", "user_id": "01JUSER"});
    if with_refresh {
        v["refresh_token"] = json!(format!("{MARK}-refresh"));
    }
    v
}

fn fast() -> PollPolicy {
    PollPolicy {
        min_interval: Duration::from_millis(5),
        slow_down_step: Duration::from_millis(40),
        default_expires_in: Duration::from_mins(15),
        max_transport_retries: 2,
    }
}

fn device_start_json(expires_in: u64) -> serde_json::Value {
    json!({"device_secret": format!("{MARK}-device"), "user_code": "ABCD-1234",
           "verification_uri": "https://auth.example/device", "interval": 0,
           "expires_in": expires_in})
}

#[tokio::test]
async fn token_grants_send_the_right_json() {
    let (stub, c) = setup().await;
    stub.script("/auth/token", vec![Reply::json(&token_json(false))]);

    let cases: Vec<(TokenResponse, serde_json::Value)> = vec![
        (
            c.refresh_session("SEKRIT-s").await.unwrap(),
            json!({"grant_type": "refresh", "session_token": "SEKRIT-s"}),
        ),
        (
            c.redeem_refresh_token("SEKRIT-r").await.unwrap(),
            json!({"grant_type": "refresh_token", "refresh_token": "SEKRIT-r"}),
        ),
        (
            c.exchange_github_oidc("SEKRIT-jwt").await.unwrap(),
            json!({"grant_type": "github_oidc", "oidc_token": "SEKRIT-jwt"}),
        ),
        (
            c.exchange_api_key("SEKRIT-key").await.unwrap(),
            json!({"grant_type": "api_key", "api_key": "SEKRIT-key"}),
        ),
    ];
    let reqs = stub.requests();
    assert_eq!(reqs.len(), cases.len());
    for (req, (resp, expected)) in reqs.iter().zip(&cases) {
        assert_eq!(req.method, "POST");
        assert_eq!(req.path(), "/auth/token");
        assert_eq!(req.header("content-type"), Some("application/json"));
        assert_eq!(req.header("authorization"), None);
        assert_eq!(&req.json(), expected);
        assert_eq!(resp.token, "SEKRIT-session");
        assert_eq!(resp.username.as_deref(), Some("alice"));
        assert_redacted(resp);
    }
}

#[tokio::test]
async fn a_base_path_prefix_is_kept() {
    let stub = StubServer::start().await;
    let c = ForgsClient::new(&format!("{}/forgs/", stub.base()), None).unwrap();
    stub.script("/forgs/auth/token", vec![Reply::json(&token_json(false))]);
    c.refresh_session("SEKRIT").await.unwrap();
    assert_eq!(stub.last().path(), "/forgs/auth/token");
}

#[tokio::test]
async fn rejections_carry_status_and_code_only() {
    let (stub, c) = setup().await;
    stub.script("/auth/token", vec![Reply::error(401, "invalid_grant")]);
    let e = c.redeem_refresh_token("SEKRIT").await.unwrap_err();
    assert_eq!(
        e,
        ClientError::Rejected {
            status: 401,
            code: "invalid_grant".into()
        }
    );

    stub.script(
        "/auth/token",
        vec![Reply::status(502, "<html>SEKRIT bad gateway</html>")],
    );
    let e = c.redeem_refresh_token("SEKRIT").await.unwrap_err();
    assert_eq!(e.code(), Some("unknown"));
    assert_eq!(e.status(), Some(502));
    assert!(!format!("{e} {e:?}").contains(MARK));
}

#[tokio::test]
async fn a_bad_success_body_is_malformed_without_quoting_it() {
    let (stub, c) = setup().await;
    stub.script(
        "/auth/token",
        vec![Reply::json(&json!({"token": format!("{MARK}-x")}))],
    );
    let e = c.refresh_session("s").await.unwrap_err();
    assert!(matches!(e, ClientError::Malformed(_)), "{e:?}");
    assert!(!format!("{e} {e:?}").contains(MARK), "{e}");

    stub.script("/auth/token", vec![Reply::status(200, "not json")]);
    assert!(matches!(
        c.refresh_session("s").await,
        Err(ClientError::Malformed(_))
    ));
}

#[tokio::test]
async fn transport_failures_are_transport() {
    let (stub, c) = setup().await;
    stub.script("/auth/token", vec![Reply::Drop]);
    let e = c.refresh_session("s").await.unwrap_err();
    assert!(matches!(e, ClientError::Transport(_)), "{e:?}");

    // Nothing listening.
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let c = ForgsClient::new(&format!("http://127.0.0.1:{dead}"), None).unwrap();
    assert!(matches!(
        c.refresh_session("s").await,
        Err(ClientError::Transport(_))
    ));
}

#[tokio::test]
async fn logout_sends_bearer_and_body_and_accepts_204() {
    let (stub, c) = setup().await;
    stub.script("/auth/logout", vec![Reply::no_content()]);
    c.logout("SEKRIT-s", Some("SEKRIT-r"), false).await.unwrap();
    let r = stub.last();
    assert_eq!(r.path(), "/auth/logout");
    assert_eq!(r.header("authorization"), Some("Bearer SEKRIT-s"));
    assert_eq!(r.json(), json!({"refresh_token": "SEKRIT-r", "all": false}));

    c.logout("SEKRIT-s", None, true).await.unwrap();
    assert_eq!(stub.last().json(), json!({"all": true}));

    stub.script("/auth/logout", vec![Reply::error(401, "unauthorized")]);
    assert_eq!(
        c.logout("x", None, false).await.unwrap_err().code(),
        Some("unauthorized")
    );
}

#[tokio::test]
async fn api_keys_create_list_revoke() {
    let (stub, c) = setup().await;
    stub.script(
        "/auth/keys",
        vec![
            Reply::json(
                &json!({"key": format!("{MARK}-apikey"), "key_hash": "abcdef0123",
                "id": "01JKEY", "namespace": "01JNS", "single_use": true, "purpose": "ci",
                "subject_name": "builder", "expires": 99}),
            ),
            Reply::json(&json!({"namespace": "01JNS", "keys": [{"id": "01JKEY",
                "key_hash": "abcdef0123", "single_use": true, "purpose": "ci",
                "created_at": 1}]})),
            Reply::json(&json!({"namespace": "01JNS", "revoked": ["abcdef0123"]})),
        ],
    );
    let created = c
        .create_api_key(
            "SEKRIT-s",
            &ApiKeySpec {
                namespace: "acme".into(),
                ttl_secs: 3600,
                multi_use: false,
                purpose: "ci".into(),
                subject_name: Some("builder".into()),
                payload: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(created.key, "SEKRIT-apikey");
    assert_eq!(created.subject_name.as_deref(), Some("builder"));
    assert_redacted(&created);

    let list = c.list_api_keys("SEKRIT-s", "acme").await.unwrap();
    assert_eq!(list.keys.len(), 1);
    let revoked = c
        .revoke_api_key("SEKRIT-s", "acme", "abcdef01")
        .await
        .unwrap();
    assert_eq!(revoked.revoked, vec!["abcdef0123".to_owned()]);

    let reqs = stub.requests();
    assert!(reqs
        .iter()
        .all(|r| r.header("authorization") == Some("Bearer SEKRIT-s")));
    assert_eq!(
        reqs[0].json(),
        json!({"action": "create", "namespace": "acme", "ttl_secs": 3600,
               "multi_use": false, "purpose": "ci", "subject_name": "builder"})
    );
    assert_eq!(
        reqs[1].json(),
        json!({"action": "list", "namespace": "acme"})
    );
    assert_eq!(
        reqs[2].json(),
        json!({"action": "revoke", "namespace": "acme", "prefix": "abcdef01"})
    );

    stub.script("/auth/keys", vec![Reply::error(409, "ambiguous_prefix")]);
    let e = c.revoke_api_key("s", "acme", "ab").await.unwrap_err();
    assert!(forgs_client::cli::describe(&e, "revoking").contains("longer prefix"));
}

#[tokio::test]
async fn device_login_pending_slow_down_granted() {
    let (stub, c) = setup().await;
    stub.script(
        "/auth/device/start",
        vec![Reply::json(&device_start_json(900))],
    );
    stub.script(
        "/auth/device/poll",
        vec![
            Reply::json(&json!({"status": "pending"})),
            Reply::json(&json!({"status": "slow_down"})),
            Reply::json(&json!({"status": "pending"})),
            Reply::json(&{
                let mut v = token_json(true);
                v["status"] = json!("granted");
                v
            }),
        ],
    );
    let login = DeviceLogin::start(&c).await.unwrap();
    assert_eq!(login.user_code(), "ABCD-1234");
    assert_eq!(login.verification_uri(), "https://auth.example/device");
    assert_redacted(&login);

    let started = std::time::Instant::now();
    let session = login.wait_with(&c, fast()).await.unwrap();
    // Two polls after the slow_down run at >= the bumped interval.
    assert!(started.elapsed() >= Duration::from_millis(2 * 40));
    assert_eq!(session.session_token.expose(), "SEKRIT-session");
    assert_eq!(
        session.refresh_token.as_ref().map(Secret::expose),
        Some("SEKRIT-refresh")
    );
    assert_eq!(session.username.as_deref(), Some("alice"));
    assert_redacted(&session);

    assert_eq!(stub.count("/auth/device/poll"), 4);
    for r in stub
        .requests()
        .iter()
        .filter(|r| r.path() == "/auth/device/poll")
    {
        assert_eq!(r.json(), json!({"device_secret": "SEKRIT-device"}));
        assert_eq!(r.header("authorization"), None);
    }
}

#[tokio::test]
async fn device_login_denied_and_expired() {
    let (stub, c) = setup().await;
    stub.script(
        "/auth/device/start",
        vec![Reply::json(&device_start_json(900))],
    );
    for (status, want) in [("denied", "Denied"), ("expired", "Expired")] {
        stub.script(
            "/auth/device/poll",
            vec![
                Reply::json(&json!({"status": "pending"})),
                Reply::json(&json!({"status": status})),
            ],
        );
        let login = DeviceLogin::start(&c).await.unwrap();
        let e = login.wait_with(&c, fast()).await.unwrap_err();
        assert_eq!(format!("{e:?}"), want);
    }
}

#[tokio::test]
async fn device_login_stops_at_the_deadline() {
    let (stub, c) = setup().await;
    // Expires in 1s; the server keeps saying pending.
    stub.script(
        "/auth/device/start",
        vec![Reply::json(&device_start_json(1))],
    );
    stub.script(
        "/auth/device/poll",
        vec![Reply::json(&json!({"status": "pending"}))],
    );
    let login = DeviceLogin::start(&c).await.unwrap();
    let policy = PollPolicy {
        min_interval: Duration::from_millis(100),
        ..fast()
    };
    let e = login.wait_with(&c, policy).await.unwrap_err();
    assert!(matches!(e, DeviceLoginError::Expired), "{e:?}");
    assert!(stub.count("/auth/device/poll") <= 11);
}

#[tokio::test]
async fn device_login_retries_transport_blips() {
    let (stub, c) = setup().await;
    stub.script(
        "/auth/device/start",
        vec![Reply::json(&device_start_json(900))],
    );
    stub.script(
        "/auth/device/poll",
        vec![
            Reply::Drop,
            Reply::Drop,
            Reply::json(&json!({"status": "pending"})),
            Reply::Drop,
            Reply::json(&{
                let mut v = token_json(false);
                v["status"] = json!("granted");
                v
            }),
        ],
    );
    let session = DeviceLogin::start(&c)
        .await
        .unwrap()
        .wait_with(&c, fast())
        .await
        .unwrap();
    assert!(session.refresh_token.is_none());

    // A sustained run gives up.
    stub.script("/auth/device/poll", vec![Reply::Drop]);
    let e = DeviceLogin::start(&c)
        .await
        .unwrap()
        .wait_with(&c, fast())
        .await
        .unwrap_err();
    assert!(matches!(e, DeviceLoginError::Unreachable(_)), "{e:?}");

    // A rejection is final.
    stub.script(
        "/auth/device/poll",
        vec![Reply::error(400, "invalid_grant")],
    );
    let e = DeviceLogin::start(&c)
        .await
        .unwrap()
        .wait_with(&c, fast())
        .await
        .unwrap_err();
    assert!(matches!(e, DeviceLoginError::Rejected(_)), "{e:?}");
    assert_redacted(&e);
}

#[tokio::test]
async fn device_poll_outcomes_decode() {
    let (stub, c) = setup().await;
    stub.script(
        "/auth/device/poll",
        vec![Reply::json(&json!({"status": "slow_down"}))],
    );
    assert_eq!(
        c.device_poll("SEKRIT").await.unwrap(),
        DevicePollResponse::SlowDown
    );
}

#[tokio::test]
async fn renew_prefers_the_refresh_token_and_falls_back() {
    let (stub, c) = setup().await;
    stub.script("/auth/token", vec![Reply::json(&token_json(false))]);
    refresh::renew(&c, Some("SEKRIT-s"), Some("SEKRIT-r"))
        .await
        .unwrap();
    assert_eq!(stub.last().json()["grant_type"], "refresh_token");
    refresh::renew(&c, Some("SEKRIT-s"), None).await.unwrap();
    assert_eq!(stub.last().json()["grant_type"], "refresh");
    assert!(refresh::renew(&c, None, None).await.is_err());

    // Rejected redemption falls back to the live session.
    stub.script(
        "/auth/token",
        vec![
            Reply::error(400, "invalid_request"),
            Reply::json(&token_json(false)),
        ],
    );
    refresh::renew(&c, Some("SEKRIT-s"), Some("SEKRIT-r"))
        .await
        .unwrap();
    assert_eq!(stub.count("/auth/token"), 4);
    assert_eq!(stub.last().json()["grant_type"], "refresh");

    // With no session, the redemption's error stands.
    stub.script("/auth/token", vec![Reply::error(401, "invalid_grant")]);
    let e = refresh::renew(&c, None, Some("SEKRIT-r"))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Some("invalid_grant"));
}

#[tokio::test]
async fn gha_id_token_fetch() {
    let (stub, c) = setup().await;
    stub.script(
        "/idtoken",
        vec![Reply::json(
            &json!({"count": 1, "value": format!("{MARK}.jwt")}),
        )],
    );
    let url = format!("{}/idtoken?api-version=2.0", stub.base());
    let jwt = gha::fetch_id_token(
        &c,
        &url,
        &Secret::from("SEKRIT-req"),
        "https://forgs.example",
    )
    .await
    .unwrap();
    assert_eq!(jwt.expose(), "SEKRIT.jwt");
    assert_redacted(&jwt);
    let r = stub.last();
    assert_eq!(r.method, "GET");
    assert_eq!(r.header("authorization"), Some("Bearer SEKRIT-req"));
    assert_eq!(
        r.query(),
        "api-version=2.0&audience=https%3A%2F%2Fforgs.example"
    );

    for aud in ["", " ", "a&b", "a#b"] {
        assert!(matches!(
            gha::fetch_id_token(&c, &url, &Secret::from("t"), aud).await,
            Err(ClientError::Url(_))
        ));
    }
    stub.script("/idtoken", vec![Reply::json(&json!({"value": ""}))]);
    assert!(matches!(
        gha::fetch_id_token(&c, &url, &Secret::from("t"), "aud").await,
        Err(ClientError::Malformed(_))
    ));
    stub.script("/idtoken", vec![Reply::status(403, "{}")]);
    assert_eq!(
        gha::fetch_id_token(&c, &url, &Secret::from("t"), "aud")
            .await
            .unwrap_err()
            .status(),
        Some(403)
    );
}

#[tokio::test]
async fn https_fails_closed_against_a_non_tls_peer() {
    use tokio::io::AsyncWriteExt as _;
    // A peer that answers a ClientHello with plaintext HTTP: the handshake
    // must fail as a transport error, never fall back to cleartext.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}")
                .await;
        }
    });
    for pin in [None, Some([0; 32])] {
        let c = ForgsClient::new(&format!("https://127.0.0.1:{port}"), pin)
            .unwrap()
            .with_timeout(Duration::from_secs(5));
        assert!(matches!(
            c.refresh_session("s").await,
            Err(ClientError::Transport(_))
        ));
    }
}

#[tokio::test]
async fn api_key_payload_is_sent_and_echoed() {
    let (stub, c) = setup().await;
    stub.script(
        "/auth/keys",
        vec![Reply::json(
            &json!({"key": format!("{MARK}-apikey"), "key_hash": "abcdef0123",
            "id": "01JKEY", "namespace": "01JNS", "single_use": false, "purpose": "node",
            "payload": {"tags": ["a", "b"]}, "expires": 99}),
        )],
    );
    let created = c
        .create_api_key(
            "SEKRIT-s",
            &ApiKeySpec {
                namespace: "acme".into(),
                ttl_secs: 60,
                multi_use: true,
                purpose: "node".into(),
                payload: Some(json!({"tags": ["b", "a"]})),
                ..ApiKeySpec::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(created.payload, Some(json!({"tags": ["a", "b"]})));
    assert_redacted(&created);
    assert_eq!(
        stub.last().json(),
        json!({"action": "create", "namespace": "acme", "ttl_secs": 60, "multi_use": true,
               "purpose": "node", "payload": {"tags": ["b", "a"]}})
    );
}

#[tokio::test]
async fn app_routes_share_the_trust_path() {
    let (stub, c) = setup().await;
    stub.script(
        "/api/nodes/enroll",
        vec![Reply::json(&json!({"node": "n1"}))],
    );
    let r: serde_json::Value = c
        .post_json(
            "/api/nodes/enroll",
            Some(&Secret::from("SEKRIT-n")),
            &json!({"name": "box"}),
        )
        .await
        .unwrap();
    assert_eq!(r, json!({"node": "n1"}));
    let req = stub.last();
    assert_eq!(req.method, "POST");
    assert_eq!(req.path(), "/api/nodes/enroll");
    assert_eq!(req.header("authorization"), Some("Bearer SEKRIT-n"));
    assert!(!req.target.contains(MARK));
    assert!(!req.body.contains(MARK));
    assert_eq!(req.json(), json!({"name": "box"}));

    // 204 through `post`, no bearer.
    stub.script("/api/nodes/approve", vec![Reply::no_content()]);
    let body = c
        .post("/api/nodes/approve", None, &json!({"code": "X"}))
        .await
        .unwrap();
    assert!(body.is_empty());
    assert_eq!(stub.last().header("authorization"), None);

    // Rejections map as for /auth routes.
    stub.script("/api/nodes/enroll", vec![Reply::error(403, "forbidden")]);
    let e = c
        .post_json::<_, serde_json::Value>("/api/nodes/enroll", None, &json!({}))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Some("forbidden"));

    // A route that is not an absolute path never leaves the process.
    let before = stub.requests().len();
    for bad in ["api/x", "@evil.example/x", "https://evil.example/x"] {
        let e = c
            .post(bad, Some(&Secret::from("SEKRIT-n")), &json!({}))
            .await
            .unwrap_err();
        assert!(matches!(e, ClientError::Url(_)), "{bad}: {e:?}");
    }
    assert_eq!(stub.requests().len(), before);
}

#[tokio::test]
async fn app_get_routes_share_the_trust_path() {
    let (stub, c) = setup().await;
    let nodes = json!({"nodes": ["n1"]});
    stub.script("/api/nodes", vec![Reply::json(&nodes), Reply::json(&nodes)]);
    let r: serde_json::Value = c
        .get_json("/api/nodes?x=1", Some(&Secret::from("SEKRIT-g")))
        .await
        .unwrap();
    assert_eq!(r, nodes);
    let req = stub.last();
    assert_eq!(req.method, "GET");
    assert_eq!(req.path(), "/api/nodes");
    assert_eq!(req.query(), "x=1");
    assert_eq!(req.header("authorization"), Some("Bearer SEKRIT-g"));
    assert!(!req.target.contains(MARK));
    assert_eq!(req.body, "");

    // Raw bytes through `get`, no bearer.
    let body = c.get("/api/nodes", None).await.unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
        nodes
    );
    assert_eq!(stub.last().header("authorization"), None);

    // Non-2xx maps to Rejected.
    stub.script("/api/nodes", vec![Reply::error(403, "forbidden")]);
    let e = c
        .get_json::<serde_json::Value>("/api/nodes", None)
        .await
        .unwrap_err();
    assert!(
        matches!(e, ClientError::Rejected { status: 403, .. }),
        "{e:?}"
    );
    assert_eq!(e.code(), Some("forbidden"));

    // A 2xx that is not JSON is Malformed.
    stub.script("/api/nodes", vec![Reply::status(200, "nope")]);
    let e = c
        .get_json::<serde_json::Value>("/api/nodes", None)
        .await
        .unwrap_err();
    assert!(matches!(e, ClientError::Malformed(_)), "{e:?}");

    // A route that is not an absolute path never leaves the process.
    let before = stub.requests().len();
    for bad in ["api/x", "@evil.example/x", "https://evil.example/x"] {
        let e = c
            .get(bad, Some(&Secret::from("SEKRIT-g")))
            .await
            .unwrap_err();
        assert!(matches!(e, ClientError::Url(_)), "{bad}: {e:?}");
    }
    assert_eq!(stub.requests().len(), before);
}

#[tokio::test]
async fn members_and_rename() {
    let (stub, c) = setup().await;
    stub.script(
        "/auth/members",
        vec![
            Reply::json(&json!({"namespace": "01JNS", "members": [
                {"subject": "user:01JU", "user_id": "01JU", "username": "alice", "role": "admin"}]})),
            Reply::no_content(),
            Reply::no_content(),
            Reply::error(403, "forbidden"),
        ],
    );
    let list = c.list_members("SEKRIT-s", "acme").await.unwrap();
    assert_eq!(list.members[0].username.as_deref(), Some("alice"));
    c.set_member("SEKRIT-s", "acme", "bob", "member")
        .await
        .unwrap();
    c.remove_member("SEKRIT-s", "acme", "bob").await.unwrap();
    let e = c
        .remove_member("SEKRIT-s", "acme", "bob")
        .await
        .unwrap_err();
    assert!(
        matches!(e, ClientError::Rejected { status: 403, .. }),
        "{e:?}"
    );
    assert_eq!(e.code(), Some("forbidden"));

    stub.script("/auth/rename", vec![Reply::no_content()]);
    c.rename(
        "SEKRIT-s",
        &forgs_client::api::RenameRequest::User {
            new_username: "alice2".into(),
        },
    )
    .await
    .unwrap();

    let reqs = stub.requests();
    assert!(reqs
        .iter()
        .all(|r| r.header("authorization") == Some("Bearer SEKRIT-s")));
    let bodies: Vec<_> = reqs
        .iter()
        .map(|r| (r.path().to_owned(), r.json()))
        .collect();
    assert_eq!(
        bodies,
        vec![
            (
                "/auth/members".to_owned(),
                json!({"action": "list", "namespace": "acme"})
            ),
            (
                "/auth/members".to_owned(),
                json!({"action": "set", "namespace": "acme",
                "username": "bob", "role": "member"})
            ),
            (
                "/auth/members".to_owned(),
                json!({"action": "remove", "namespace": "acme",
                "username": "bob"})
            ),
            (
                "/auth/members".to_owned(),
                json!({"action": "remove", "namespace": "acme",
                "username": "bob"})
            ),
            (
                "/auth/rename".to_owned(),
                json!({"action": "user", "new_username": "alice2"})
            ),
        ]
    );
}
