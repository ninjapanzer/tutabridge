mod search;
mod session;
mod utf7;

use log::{debug, error, info};
use std::io::ErrorKind;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;

use crate::store::LocalStore;
use crate::sync::MailStore;
use crate::tuta::MailBackend;
use session::ImapSession;

/// Numbers IMAP connections in acceptance order so log lines from concurrent
/// or overlapping sessions (auth, commands, the eventual disconnect) can be
/// told apart. Purely a log-correlation id — never persisted, never sent to
/// a client.
static SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);

pub async fn serve(
    port: u16,
    store: Arc<MailStore>,
    backend: Arc<dyn MailBackend>,
    local_store: Arc<LocalStore>,
    tls: TlsAcceptor,
    password_hash: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await?;
    info!("IMAP server listening on 127.0.0.1:{} (TLS)", port);

    crate::net::accept_loop(
        listener,
        "IMAP",
        crate::net::MAX_CONNECTIONS,
        move |stream, addr| {
            let store = store.clone();
            let backend = backend.clone();
            let local_store = local_store.clone();
            let tls = tls.clone();
            let pw_hash = password_hash.clone();
            async move {
                let session_id = SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
                match tokio::time::timeout(crate::net::HANDSHAKE_TIMEOUT, tls.accept(stream)).await
                {
                    Ok(Ok(tls_stream)) => {
                        info!("IMAP session {session_id}: opened ({addr})");
                        if let Err(e) = handle_connection(
                            tls_stream,
                            session_id,
                            store,
                            backend,
                            local_store,
                            pw_hash,
                        )
                        .await
                        {
                            error!("IMAP session {session_id}: connection error: {e}");
                        }
                    }
                    Ok(Err(e)) => error!("IMAP session {session_id}: TLS handshake failed ({addr}): {e}"),
                    Err(_) => debug!("IMAP session {session_id}: TLS handshake timed out ({addr})"),
                }
            }
        },
    )
    .await;

    Ok(())
}

/// True for the io::Error rustls reports when a peer closes the TCP
/// connection without sending a TLS close_notify alert first. Under TLS 1.3's
/// AEAD framing this can't hide a truncated response the way it could
/// pre-1.3, and short-lived clients that open a connection, run one command
/// and exit (as most non-interactive IMAP CLI tools do) routinely skip the
/// clean shutdown. Treating it as an ordinary EOF keeps that common,
/// harmless case out of the error log.
fn is_close_notify_eof(e: &std::io::Error) -> bool {
    e.kind() == ErrorKind::UnexpectedEof
}

async fn handle_connection(
    stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    session_id: u64,
    store: Arc<MailStore>,
    backend: Arc<dyn MailBackend>,
    local_store: Arc<LocalStore>,
    password_hash: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let mut store_watch: watch::Receiver<u64> = store.subscribe();
    let mut session = ImapSession::new(store, backend, password_hash, Some(local_store))
        .with_session_id(session_id);

    writer
        .write_all(b"* OK TutaBridge IMAP4rev1 ready\r\n")
        .await?;
    writer.flush().await?;

    let mut line = String::new();
    loop {
        if session.is_idle() {
            line.clear();
            tokio::select! {
                result = reader.read_line(&mut line) => {
                    let n = match result {
                        Ok(n) => n,
                        Err(e) if is_close_notify_eof(&e) => {
                            debug!(
                                "IMAP session {session_id}: connection terminated client-side without a TLS close_notify (while idle): {e}"
                            );
                            break;
                        }
                        Err(e) => return Err(e.into()),
                    };
                    if n == 0 {
                        debug!("IMAP session {session_id}: connection closed (EOF while idle)");
                        break;
                    }
                    let trimmed = line.trim_end();
                    debug!("IMAP C (idle): {}", trimmed);
                    if trimmed.eq_ignore_ascii_case("DONE") {
                        let responses = session.end_idle();
                        for resp in &responses {
                            debug!("IMAP S: {}", resp.trim_end());
                            writer.write_all(resp.as_bytes()).await?;
                        }
                        writer.flush().await?;
                    }
                }
                _ = store_watch.changed() => {
                    let updates = session.check_new_mail().await;
                    for resp in &updates {
                        debug!("IMAP S (store update): {}", resp.trim_end());
                        writer.write_all(resp.as_bytes()).await?;
                    }
                    writer.flush().await?;
                }
            }
            continue;
        }

        line.clear();
        let n = match reader.read_line(&mut line).await {
            Ok(n) => n,
            Err(e) if is_close_notify_eof(&e) => {
                debug!(
                    "IMAP session {session_id}: connection terminated client-side without a TLS close_notify: {e}"
                );
                break;
            }
            Err(e) => return Err(e.into()),
        };
        if n == 0 {
            debug!("IMAP session {session_id}: connection closed (EOF)");
            break;
        }

        let trimmed = line.trim_end();
        debug!("IMAP C: {}", trimmed);

        // APPEND carries a message literal the line-based session layer cannot
        // read, so it is handled here at the socket level.
        if !session.is_awaiting_auth() {
            if let Some(req) = session::parse_append(trimmed) {
                handle_append(&mut reader, &mut writer, &session, req).await?;
                continue;
            }
        }

        let responses = if session.is_awaiting_auth() {
            session.handle_auth_response(trimmed)
        } else {
            session.handle_command(trimmed).await
        };
        for resp in &responses {
            debug!("IMAP S: {}", resp.trim_end());
            writer.write_all(resp.as_bytes()).await?;
        }
        writer.flush().await?;

        if session.is_logout() {
            debug!("IMAP session {session_id}: closed after LOGOUT");
            break;
        }
    }

    Ok(())
}

/// Largest APPEND message literal we will read into memory.
const MAX_APPEND_BYTES: usize = 26_214_400;

/// Handle an `APPEND`. Tuta saves sent mail server-side, so an APPEND to the
/// Sent folder is accepted as a no-op: read and discard the literal, reply OK.
/// That lets a mail client's "save a copy to Sent" succeed without creating a
/// duplicate (the real copy arrives via the syncer). Other folders are not
/// supported yet and are rejected before the literal is sent, so the client
/// aborts the synchronizing literal and the stream stays in sync.
async fn handle_append<R, W>(
    reader: &mut R,
    writer: &mut W,
    session: &ImapSession,
    req: session::AppendRequest,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWriteExt + Unpin,
{
    if !session.append_targets_sent(&req.mailbox).await {
        let resp = format!(
            "{} NO [CANNOT] APPEND is only supported for the Sent folder; Tuta saves sent mail automatically\r\n",
            req.tag
        );
        writer.write_all(resp.as_bytes()).await?;
        writer.flush().await?;
        return Ok(());
    }
    if req.literal_size > MAX_APPEND_BYTES {
        let resp = format!("{} NO message too large\r\n", req.tag);
        writer.write_all(resp.as_bytes()).await?;
        writer.flush().await?;
        return Ok(());
    }

    // Synchronizing literal: tell the client to send the message, then read and
    // discard it plus the trailing CRLF (the real Sent copy comes from sync).
    writer.write_all(b"+ OK\r\n").await?;
    writer.flush().await?;
    let mut buf = vec![0u8; req.literal_size];
    reader.read_exact(&mut buf).await?;
    let mut tail = String::new();
    reader.read_line(&mut tail).await?;

    let resp = format!("{} OK APPEND completed\r\n", req.tag);
    writer.write_all(resp.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mail::parser::ParsedMessage;
    use crate::tuta::FolderInfo;
    use tokio::io::AsyncReadExt;
    use tutasdk::entities::generated::tutanota::{Mail, MailDetails, MailSetEntry, TutanotaFile};
    use tutasdk::folder_system::MailSetKind;
    use tutasdk::IdTupleGenerated;

    struct NoopBackend;
    #[async_trait::async_trait]
    impl MailBackend for NoopBackend {
        async fn load_mail_ids_for_folder(
            &self,
            _f: &FolderInfo,
            _l: usize,
        ) -> Result<Vec<Mail>, String> {
            unimplemented!()
        }
        async fn load_mail(&self, _l: &str, _e: &str) -> Result<Option<Mail>, String> {
            unimplemented!()
        }
        async fn decrypt_inline_mail(&self, _j: &str) -> Result<Option<Mail>, String> {
            unimplemented!()
        }
        async fn decrypt_inline_mail_set_entry(
            &self,
            _j: &str,
        ) -> Result<Option<MailSetEntry>, String> {
            unimplemented!()
        }
        async fn decrypt_inline_mail_details_blob(
            &self,
            _j: &str,
        ) -> Result<Option<MailDetails>, String> {
            unimplemented!()
        }
        async fn load_mail_details(&self, _m: &Mail) -> Result<Option<MailDetails>, String> {
            unimplemented!()
        }
        async fn load_attachments(
            &self,
            _m: &Mail,
        ) -> Result<Vec<(TutanotaFile, Vec<u8>)>, String> {
            unimplemented!()
        }
        async fn list_folders(&self) -> Result<Vec<FolderInfo>, String> {
            unimplemented!()
        }
        async fn set_unread_status(
            &self,
            _ids: Vec<IdTupleGenerated>,
            _u: bool,
        ) -> Result<(), String> {
            unimplemented!()
        }
        async fn trash_mails(&self, _ids: Vec<IdTupleGenerated>) -> Result<(), String> {
            unimplemented!()
        }
        async fn move_mails(
            &self,
            _ids: Vec<IdTupleGenerated>,
            _t: &FolderInfo,
        ) -> Result<(), String> {
            unimplemented!()
        }
        async fn send_mail(&self, _m: &ParsedMessage) -> Result<(), String> {
            unimplemented!()
        }
    }

    async fn session_with_sent() -> ImapSession {
        let store = MailStore::new();
        let sent = FolderInfo {
            id: "sent".into(),
            list_id: "folders".into(),
            entries_list_id: "se".into(),
            kind: MailSetKind::Sent,
            imap_path: "Sent".into(),
            special_use: Some("\\Sent".into()),
        };
        store.set_folder_list(vec![sent]).await;
        ImapSession::new(store, Arc::new(NoopBackend), None, None)
    }

    #[test]
    fn close_notify_eof_is_recognized() {
        let e = std::io::Error::new(
            ErrorKind::UnexpectedEof,
            "peer closed connection without sending TLS close_notify",
        );
        assert!(is_close_notify_eof(&e));
    }

    #[test]
    fn other_io_errors_are_not_treated_as_close_notify() {
        let e = std::io::Error::new(ErrorKind::ConnectionReset, "connection reset by peer");
        assert!(!is_close_notify_eof(&e));
    }

    #[tokio::test]
    async fn append_to_sent_reads_literal_and_returns_ok() {
        let session = session_with_sent().await;
        let (mut client, server) = tokio::io::duplex(4096);
        let (sr, mut sw) = tokio::io::split(server);
        let mut reader = BufReader::new(sr);
        let req = session::AppendRequest {
            tag: "a1".into(),
            mailbox: "Sent".into(),
            literal_size: 5,
        };

        let server_fut = handle_append(&mut reader, &mut sw, &session, req);
        let client_fut = async {
            let mut buf = [0u8; 32];
            let n = client.read(&mut buf).await.unwrap();
            assert!(
                String::from_utf8_lossy(&buf[..n]).starts_with('+'),
                "expected a continuation request"
            );
            client.write_all(b"hello\r\n").await.unwrap();
            let mut resp = vec![0u8; 128];
            let n = client.read(&mut resp).await.unwrap();
            String::from_utf8_lossy(&resp[..n]).into_owned()
        };
        let (res, resp) = tokio::join!(server_fut, client_fut);
        res.unwrap();
        assert!(resp.contains("a1 OK APPEND completed"), "got {resp:?}");
    }

    #[tokio::test]
    async fn append_to_non_sent_is_rejected_without_continuation() {
        let session = session_with_sent().await;
        let (mut client, server) = tokio::io::duplex(4096);
        let (sr, mut sw) = tokio::io::split(server);
        let mut reader = BufReader::new(sr);
        let req = session::AppendRequest {
            tag: "b2".into(),
            mailbox: "Drafts".into(),
            literal_size: 5,
        };

        let server_fut = handle_append(&mut reader, &mut sw, &session, req);
        let client_fut = async {
            let mut resp = vec![0u8; 128];
            let n = client.read(&mut resp).await.unwrap();
            String::from_utf8_lossy(&resp[..n]).into_owned()
        };
        let (res, resp) = tokio::join!(server_fut, client_fut);
        res.unwrap();
        assert!(resp.contains("b2 NO"), "got {resp:?}");
        assert!(
            !resp.contains('+'),
            "a rejected folder must not get a continuation"
        );
    }
}
