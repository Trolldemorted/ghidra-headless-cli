//! TCP ndjson transport to the RPC server.
//!
//! Each call opens a fresh connection, writes one JSON line, reads exactly one
//! JSON response line, and closes. The server keeps connections long-lived, but
//! a one-shot CLI invocation has no reason to reuse them.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;

use crate::json::Json;

/// Holds the resolved server endpoint for the duration of one CLI run.
pub struct Client {
    pub host: String,
}

impl Client {
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
    /// and return the response only when `success` is true.
    pub fn invoke(&self, request: Json) -> Result<Json, ()> {
        match self.call(&request) {
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
    /// confirmation line for the procedure on success.
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
