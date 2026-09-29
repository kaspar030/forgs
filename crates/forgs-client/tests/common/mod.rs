//! A loopback HTTP/1.1 stub server: scripted replies per path, every request
//! recorded. No server framework — `tokio::net` and a hand-parsed request.

#![allow(dead_code, clippy::missing_panics_doc)]

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

/// A canned response, or a dropped connection.
#[derive(Clone, Debug)]
pub enum Reply {
    Http {
        status: u16,
        content_type: String,
        body: Vec<u8>,
    },
    /// Close the socket without answering (a transport failure).
    Drop,
}

impl Reply {
    pub fn json(body: &serde_json::Value) -> Self {
        Self::status(200, body.to_string())
    }

    pub fn status(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self::Http {
            status,
            content_type: "application/json".to_owned(),
            body: body.into(),
        }
    }

    pub fn error(status: u16, code: &str) -> Self {
        Self::status(status, format!(r#"{{"error":"{code}"}}"#))
    }

    pub fn no_content() -> Self {
        Self::status(204, Vec::new())
    }
}

/// One request the stub received.
#[derive(Clone, Debug)]
pub struct Recorded {
    pub method: String,
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

    pub fn query(&self) -> &str {
        self.target.split_once('?').map_or("", |(_, q)| q)
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap()
    }
}

#[derive(Default)]
struct State {
    /// Per path: replies served in order; the last one repeats.
    routes: HashMap<String, VecDeque<Reply>>,
    requests: Vec<Recorded>,
}

pub struct StubServer {
    addr: SocketAddr,
    state: Arc<Mutex<State>>,
}

impl StubServer {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(State::default()));
        let st = Arc::clone(&state);
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
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

    /// Script `path`: replies in order, the last repeating.
    pub fn script(&self, path: &str, replies: Vec<Reply>) {
        self.state
            .lock()
            .unwrap()
            .routes
            .insert(path.to_owned(), replies.into());
    }

    pub fn requests(&self) -> Vec<Recorded> {
        self.state.lock().unwrap().requests.clone()
    }

    pub fn last(&self) -> Recorded {
        self.requests().pop().expect("no request recorded")
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
    let rec = Recorded {
        method,
        target,
        headers,
        body: String::from_utf8_lossy(&buf[head_end..]).into_owned(),
    };
    let reply = {
        let mut s = st.lock().unwrap();
        let reply = match s.routes.get_mut(rec.path()) {
            Some(q) if q.len() > 1 => q.pop_front().unwrap(),
            Some(q) if !q.is_empty() => q[0].clone(),
            _ => Reply::status(404, "not found"),
        };
        s.requests.push(rec);
        reply
    };
    let Reply::Http {
        status,
        content_type,
        body,
    } = reply
    else {
        // Dropping the socket unanswered is the transport failure.
        return Ok(());
    };
    let head = format!(
        "HTTP/1.1 {status} X\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\n\
         connection: close\r\n\r\n",
        body.len()
    );
    sock.write_all(head.as_bytes()).await?;
    sock.write_all(&body).await?;
    sock.shutdown().await
}
