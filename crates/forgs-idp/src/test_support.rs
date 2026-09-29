//! Test-only helpers: a tiny loopback HTTP/1.1 stub server and committed RSA
//! test keys. No network beyond 127.0.0.1.

#![allow(dead_code, clippy::missing_panics_doc)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

/// A canned response.
#[derive(Clone, Debug)]
pub struct Reply {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn ok(content_type: &str, body: impl Into<Vec<u8>>) -> Self {
        Self::status(200, content_type, body)
    }

    pub fn json(body: &serde_json::Value) -> Self {
        Self::ok("application/json", body.to_string())
    }

    pub fn status(status: u16, content_type: &str, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            content_type: content_type.to_owned(),
            body: body.into(),
        }
    }
}

/// One request the stub received.
#[derive(Clone, Debug)]
pub struct Recorded {
    pub method: String,
    /// Path including the query string.
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Recorded {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or("")
    }

    /// Decoded form (or query) fields.
    pub fn form(&self) -> HashMap<String, String> {
        parse_form(&self.body)
    }

    pub fn query(&self) -> HashMap<String, String> {
        parse_form(self.target.split_once('?').map_or("", |(_, q)| q))
    }
}

pub fn parse_form(s: &str) -> HashMap<String, String> {
    s.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (decode(k), decode(v))
        })
        .collect()
}

fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                let hex = std::str::from_utf8(&b[i + 1..i + 3]).unwrap();
                out.push(u8::from_str_radix(hex, 16).unwrap());
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).unwrap()
}

#[derive(Default)]
struct State {
    routes: HashMap<String, Reply>,
    requests: Vec<Recorded>,
}

/// A loopback HTTP/1.1 server answering canned replies by path (query
/// ignored for routing), recording every request. Unknown paths get 404.
pub struct StubServer {
    addr: SocketAddr,
    state: Arc<Mutex<State>>,
}

impl StubServer {
    pub async fn start(routes: Vec<(String, Reply)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(State {
            routes: routes.into_iter().collect(),
            requests: Vec::new(),
        }));
        let st = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    return;
                };
                let st = Arc::clone(&st);
                tokio::spawn(async move {
                    let _ = serve(sock, st).await;
                });
            }
        });
        Self { addr, state }
    }

    pub fn base(&self) -> String {
        format!("http://127.0.0.1:{}", self.addr.port())
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base())
    }

    pub fn set(&self, path: &str, reply: Reply) {
        self.state
            .lock()
            .unwrap()
            .routes
            .insert(path.to_owned(), reply);
    }

    pub fn requests(&self) -> Vec<Recorded> {
        self.state.lock().unwrap().requests.clone()
    }

    pub fn count(&self, path: &str) -> usize {
        self.requests().iter().filter(|r| r.path() == path).count()
    }
}

async fn serve(mut sock: tokio::net::TcpStream, st: Arc<Mutex<State>>) -> std::io::Result<()> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        let n = sock.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or("").split(' ');
    let method = first.next().unwrap_or("").to_owned();
    let target = first.next().unwrap_or("").to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect();
    let len: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    while buf.len() < head_end + len {
        let n = sock.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let body = String::from_utf8_lossy(&buf[head_end..]).into_owned();
    let rec = Recorded {
        method,
        target,
        headers,
        body,
    };
    let reply = {
        let mut s = st.lock().unwrap();
        let reply = s
            .routes
            .get(rec.path())
            .cloned()
            .unwrap_or_else(|| Reply::status(404, "text/plain", "not found"));
        s.requests.push(rec);
        reply
    };
    let head = format!(
        "HTTP/1.1 {} X\r\ncontent-type: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        reply.status,
        reply.content_type,
        reply.body.len()
    );
    sock.write_all(head.as_bytes()).await?;
    sock.write_all(&reply.body).await?;
    sock.shutdown().await
}

#[cfg(feature = "oidc")]
pub use keys::*;

#[cfg(feature = "oidc")]
mod keys {
    use base64::Engine as _;
    use jsonwebtoken::jwk::JwkSet;
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use serde_json::json;

    /// A committed RSA-2048 private key, PKCS#1 DER, base64. Committed rather
    /// than generated at test time: RSA keygen in a debug build is slow and
    /// its timing variable. Signs only fixtures.
    pub const KEY_A_DER_B64: &str = concat!(
        "MIIEpAIBAAKCAQEArsL3i977OYrPnKq6SjRYRIYuzkEAd+rd3hvupoNtMt/w7kG6qX2apWgw",
        "tqbMvX06fmswpnBqQuF99lOvBZYQ1AfsV6igmRp9WET0X+kO0ptI0bYs1UGWYc2LMHQWEUJA",
        "tFjH5YzOteoEsw1RwceJ9kDn1WMkotIq/uvx+LlptN98PtnpL3vjIvo+QyYD8ulcEmIygjnE",
        "Vf/Dpx76agi4gRTG9miu7NkU3VgZXnMfQdjh7Exz04Qg3ItN/kTkoxx6Yjn1wuo77fZxj7Sp",
        "AiZbSRix3sRxij/Wt4VfMT2MBwWNb1KjOVxQygPfl9KsxTxD6njiXWtQez89r5RVfoUH0QID",
        "AQABAoIBAAv/eqXxqGcU7pf06KvmLWvW7SkKhru04N06JweWMk2x2NqioewM9tcFm4KOr7O6",
        "qzoOpd0SDq7fcu8RuQxgdxtMx/RksVHm4wAdC8yh4CX5XzshOga8uqmlm463XuR5xfNxEkLi",
        "MzbYsCXoHjAi64fVK5VszxEWmLkTqHMeV5wr4SMQA4JmmMO8Yr/TcmkIQxCwzTlOy+Mm9XBq",
        "3WnKKhiAeDX1V2S+DzXucbiXRNpyHx2o/FDtDpsWe2ZGiiZTrUBM9HgU3lS3FXGwNkhAHKAn",
        "VxVMpiAk0xFoJQ1+ZevTy+SJHf9SeTalhxZENjPmX6FY5095UFNSdHWb2nZKVSECgYEA7OFb",
        "CaoIB3ELnlnwbu3CUiASd8JpxDhViBiKpykwAnO/shrc/meeuzbqn+LGOHW/WicuVJBQwdF8",
        "3LOGHWxqmOnBZbRgdw0His27xQ3BSKm0p90qb3kKqoLTg0gY/sZ9lWsSci4f+OxdqamzNHDV",
        "vof2KiQjCcrZ9CIS8VSB550CgYEAvN4OVeuFM9Q7j2YRnAxSPMIvE0Z35LG9UQYVmwU9/rDm",
        "IQwV6TkrGrjhytz9Ra4neeZDmY8PvgP6KMyzwPtEF8ozop9I4fU40iel+UioAo/+FacctwgM",
        "0geGcG7rsA92udPxwbpNCmJA8tdKRJ9lcp/kNEbAHQEIGhjFs7LJPMUCgYEA5SYj0TeAyOIc",
        "oTTUGBs8jgGkm+GgO0dbxmonRwna/aRHXt4JxrkqnmTDl6PiqR+O2oFomjl5ReWHamDobnJA",
        "tGf8xIw3fTNHhoj7CecCgW5Z6sFSmb94B/bC8g6+z0fomLCZiYcBOuY8vTICv8ofm08fXSjU",
        "FFb9fOOxe2+KsykCgYEAkirIrXY5AIOgFLrJphtjCeK+zAwdfcCQ48PxtKe58wK1F55i1ryH",
        "v4aWOIoO+X5uzsiGSLGPXV92m1zRQOk1KbQzgggEP9uovfwxV1wDqvgFjHxonL5+LY3lXd56",
        "SSeumuKMl4G3XfHskgRMVg+GU8+qrUqUI95IhunlF82mMIECgYAxvXnRxgjI/p/5ERXYvvaL",
        "QfnJ0jFfcGr6hlx3INsMq9JcpI1C2FiWkPuU/folOSKYHQ7bNNxtMh6lkBW2+m4Zm1CAzlRB",
        "DM8oAR00QMf12agzXuXXBqpaDIeq011IJmtUIPwSJAxSBOnrT1lZvff7EIqg8CRj5uUPNLfx",
        "hKhlIA==",
    );

    /// Base64url modulus of [`KEY_A_DER_B64`].
    pub const KEY_A_N: &str = concat!(
        "rsL3i977OYrPnKq6SjRYRIYuzkEAd-rd3hvupoNtMt_w7kG6qX2apWgwtqbMvX06fmswpnBq",
        "QuF99lOvBZYQ1AfsV6igmRp9WET0X-kO0ptI0bYs1UGWYc2LMHQWEUJAtFjH5YzOteoEsw1R",
        "wceJ9kDn1WMkotIq_uvx-LlptN98PtnpL3vjIvo-QyYD8ulcEmIygjnEVf_Dpx76agi4gRTG",
        "9miu7NkU3VgZXnMfQdjh7Exz04Qg3ItN_kTkoxx6Yjn1wuo77fZxj7SpAiZbSRix3sRxij_W",
        "t4VfMT2MBwWNb1KjOVxQygPfl9KsxTxD6njiXWtQez89r5RVfoUH0Q",
    );

    /// A second key, for the rotation and wrong-key tests.
    pub const KEY_B_DER_B64: &str = concat!(
        "MIIEowIBAAKCAQEApesnGL/IibSnxbbALzq9yErXD9Hklbk6gpMTvfEOnPmNDw7w/MiHgTSb",
        "3JC9zyZ5Qb9zS8HK3SCMDd/VysZIe2rQ1MvETvkL3ryX3g6qHTtXy8yqLvOIDMrS7abrglWr",
        "EHrYziVHxaB6nxO6X8gVMThi+yAuUoZjm4pirkwohD8Gf/tpYgIP7A/zGOSluQj8vodb1M9q",
        "kfWllxMSTjg0Y2hgxz3/PKTKRoeRmJY1vVQC75VuA716KRGlepi7u0bex49jB3R1gvJRper0",
        "rN+Oidt/bOn3+oIolxCHUmulJrWASpwkwVMnew1AcI9VT8HF4R99TB6LdRUVfjbA1JgJjwID",
        "AQABAoIBAE99V5/N0h/XQ0HAClcWR3I8GMjlgCQTN+ry19R6NswR6vi56c7Rq8nFEJ8dYTJr",
        "dlB/jpdO4wgJ3c+P23dog7VNOXuZnBVRz9QIeqHSWMHkem2TQj14Q0gNq/xbqh0pOemNUW2C",
        "At61wcmQxAu7ahvIrfMuOcMjy3jrVde3ePnSChWoj+bSWKV+XH3cRnPhez6NispbpTb0y35E",
        "z93bixH5bb5CzzH+59DtPF8+9tQ9q3jUQRtsGKm+jgcXNYbr2ENCC5I2LzyfAtzHP6wzUSxv",
        "FeeiOroZ/ChNTOptm3ECH8BJGfBw6LnlGxBcUFIC69ixmLMECSlgWhHYRUmr+uECgYEA3oo/",
        "KYsSsO66bZW5xJTCdsu2vAA21ATRKJptLAghQ1FImLMQYoM9rfW4OWD+Uf4SJ2OqN45B1GtC",
        "Ff8wa1w3dG17gRio1PBw0ctALxm0vbOFiGT2qGBfOJ3IAS0uUw4mSesdiUKpEzzSz+e5Hq3O",
        "Z72UidgmBuarmVLacOupAUcCgYEAvt1/ivhL8u0JDyfw8F72znsRYkXw3DFRq65KoSCrnoek",
        "mj42Z+7B+TVjwhwB9u4q8u0ohtZu6UC2LDWWjg8MSotvjW3TwKQhpwZV8LX1NEcpBU9XI1fD",
        "GbNQu5GT1ESTL1/Dy5Ik4DfJ2Y3yJC/f6jeWnYLm2yqWAc1AXpH1mXkCgYAP/XT+YizMo8qn",
        "dxurAVlbudV+erF12IbC2R3BDTB+qseBmVQzD+UNq9s53DtJ3uylAedIKKOYRMCx3e03uZ+O",
        "cRNvujrfWgtxN558A+fVvaF5pG+It6v/4G5vjzSF6T1dEFTF+RE2/abUI31MtAZhs+CJawuI",
        "cWihEq/5byVsnwKBgGsbT1yEE9LB88h+iHXLRMMASvQT/aMDRiqKhzS+abBvvA4WhV9zm4Sm",
        "0lF2eB/C7XUfYxOvt9PLTa+nbtJPXX1jm/kIvcCoGn5pTsbixTRODpX9PRAHSuPcPZzUh9mh",
        "ldsK6YwOegUdKXedcVmfSA9enHXNpJEu57khHlMzo1g5AoGBANQcvcBfnMDuGPYKSqGsrCn9",
        "G3UZDtJ+mCvXyTdnTif/tP8Xvsi9+h4CYQl/zG8CHNo9aNqdnIoIVS9ZfTVmSF1n9IQTVByr",
        "Y4o97s7rIAqpEVzY0H2fHA5MgO4hmSAAOdWiG0d5ScstfWofmcj/8tYWHv8VZthbkqxtJtW/",
        "bqP0",
    );

    /// Base64url modulus of [`KEY_B_DER_B64`].
    pub const KEY_B_N: &str = concat!(
        "pesnGL_IibSnxbbALzq9yErXD9Hklbk6gpMTvfEOnPmNDw7w_MiHgTSb3JC9zyZ5Qb9zS8HK",
        "3SCMDd_VysZIe2rQ1MvETvkL3ryX3g6qHTtXy8yqLvOIDMrS7abrglWrEHrYziVHxaB6nxO6",
        "X8gVMThi-yAuUoZjm4pirkwohD8Gf_tpYgIP7A_zGOSluQj8vodb1M9qkfWllxMSTjg0Y2hg",
        "xz3_PKTKRoeRmJY1vVQC75VuA716KRGlepi7u0bex49jB3R1gvJRper0rN-Oidt_bOn3-oIo",
        "lxCHUmulJrWASpwkwVMnew1AcI9VT8HF4R99TB6LdRUVfjbA1JgJjw",
    );

    fn der(b64: &str) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap()
    }

    /// A JWKS document holding the named `(kid, modulus)` keys.
    pub fn jwks_json(entries: &[(&str, &str)]) -> serde_json::Value {
        let keys: Vec<serde_json::Value> = entries
            .iter()
            .map(|(kid, n)| {
                json!({ "kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid, "n": n, "e": "AQAB" })
            })
            .collect();
        json!({ "keys": keys })
    }

    pub fn jwks(entries: &[(&str, &str)]) -> JwkSet {
        serde_json::from_value(jwks_json(entries)).unwrap()
    }

    /// Sign `claims` RS256 under `kid` with the given committed key.
    pub fn sign(kid: &str, key_der_b64: &str, claims: &serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_owned());
        jsonwebtoken::encode(
            &header,
            claims,
            &EncodingKey::from_rsa_der(&der(key_der_b64)),
        )
        .unwrap()
    }

    /// Sign with no `kid` header.
    pub fn sign_without_kid(key_der_b64: &str, claims: &serde_json::Value) -> String {
        jsonwebtoken::encode(
            &Header::new(Algorithm::RS256),
            claims,
            &EncodingKey::from_rsa_der(&der(key_der_b64)),
        )
        .unwrap()
    }
}
