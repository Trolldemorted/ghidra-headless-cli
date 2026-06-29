//! TCP ndjson transport to the RPC server.
//!
//! Each call opens a fresh connection, writes one JSON line, reads exactly one
//! JSON response line, and closes. The server keeps connections long-lived, but
//! a one-shot CLI invocation has no reason to reuse them.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;

use crate::json::Json;

/// Holds the resolved server endpoint and write-gate secret for the duration
/// of one CLI run. `write_password` mirrors the `GHIDRA_RPC_WRITE_PASSWORD`
/// environment variable: when `Some`, every outgoing request gets the secret
/// injected as a top-level `password` field so the server can authenticate the
/// mutation; when `None`, the field is omitted and the server (if its own env
/// var is unset) accepts the request anyway.
pub struct Client {
    pub host: String,
    pub write_password: Option<String>,
}

impl Client {
    /// Build a request with the write-gate password injected when configured.
    /// Returns the original request unchanged when `write_password` is None or
    /// the request isn't a JSON object (the wire protocol only sends objects,
    /// so the no-op is defensive rather than expected).
    fn stamp_password(&self, mut request: Json) -> Json {
        if let Some(pw) = &self.write_password
            && !pw.is_empty()
        {
            request.set("password", Json::Str(pw.clone()));
        }
        request
    }

    /// Send a request and return the parsed response, or a transport/parse error.
    fn call(&self, request: &Json) -> Result<Json, String> {
        let line = request.to_string();
        log::trace!("-> {}", line);

        let stream = TcpStream::connect(&self.host)
            .map_err(|e| format!("connect to {}: {}", self.host, e))?;
        let mut writer = &stream;
        writer
            .write_all(line.as_bytes())
            .and_then(|_| writer.write_all(b"\n"))
            .and_then(|_| writer.flush())
            .map_err(|e| format!("write to {}: {}", self.host, e))?;

        let mut reader = BufReader::new(&stream);
        let mut response = String::new();
        let read = reader
            .read_line(&mut response)
            .map_err(|e| format!("read from {}: {}", self.host, e))?;
        if read == 0 {
            return Err(format!(
                "connection closed by {} before a response",
                self.host
            ));
        }
        let trimmed = response.trim_end_matches(['\r', '\n']);
        log::trace!("<- {}", trimmed);

        Json::parse(trimmed).map_err(|e| format!("malformed response: {}", e))
    }

    /// Send a request, log transport and server-side errors at the error level,
    /// and return the response only when `success` is true. Stamps the
    /// configured write-gate password onto the request before sending.
    pub fn invoke(&self, request: Json) -> Result<Json, ()> {
        let stamped = self.stamp_password(request);
        match self.call(&stamped) {
            Err(transport) => {
                log::error!("{}", transport);
                Err(())
            }
            Ok(response) => {
                let success = response
                    .get("success")
                    .and_then(Json::as_bool)
                    .unwrap_or(false);
                if success {
                    log::debug!("server reported success");
                    Ok(response)
                } else {
                    // Emit the server's error verbatim, no post-processing.
                    let message = response
                        .get("error")
                        .and_then(Json::as_str)
                        .unwrap_or("server reported failure without an 'error' field");
                    log::error!("{}", message);
                    Err(())
                }
            }
        }
    }

    /// Invoke a request whose only meaningful result is success, logging a
    /// confirmation line for the procedure on success. Stamps the
    /// configured write-gate password onto the request before sending.
    pub fn run_simple(&self, request: Json) -> Result<(), ()> {
        let name = request
            .get("procedure")
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_string();
        self.invoke(request)?;
        log::info!("{}: success", name);
        Ok(())
    }
}
