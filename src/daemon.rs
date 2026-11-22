//! The listener every machine runs. It binds only to the Tailscale address,
//! refuses anything from outside the tailnet, and serves peers that prove
//! they hold the fleet key.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::Result;
use tracing::{info, warn};

use crate::config::{Config, PAIRING_MAX_ATTEMPTS, Paths, Peer, VERSION, hex_decode, hex_encode, now_secs};
use crate::exec::{self, EnvCache};
use crate::privacy;
use crate::proto::{
    CHUNK, Challenge, Conn, HANDSHAKE_TIMEOUT, Hello, HelloMode, Kind, LABEL_CLIENT, LABEL_SERVER, LABEL_WRAP,
    ListEntry, Listing, MAGIC, NodeInfo, PROTO_VERSION, Proof, ProtoError, Request, Welcome, Written, mac,
    mac_verify, pair_key, xor32,
};
use crate::transfer::{self, Partial, WalkOpts, resolve_path};

/// How often the daemon checks that it is still on the right address.
const WATCH_INTERVAL: Duration = Duration::from_secs(15);
const LOG_ROTATE_BYTES: u64 = 5 * 1024 * 1024;
/// How often a confined daemon checks whether access has been granted.
const ACCESS_POLL: Duration = Duration::from_secs(30);

struct Daemon {
    paths: Paths,
    env: EnvCache,
    /// Serialises read-modify-write of the config file.
    config_lock: Mutex<()>,
    tailnet_only: bool,
    /// Confined because this Mac hasn't granted Full Disk Access.
    limited: bool,
    /// Set when confinement itself failed: serve nothing that touches files.
    refuse: Option<String>,
    active: AtomicUsize,
}

/// Counts a connection for as long as it is being served.
struct Active<'a>(&'a AtomicUsize);

impl<'a> Active<'a> {
    fn new(counter: &'a AtomicUsize) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        Self(counter)
    }
}

impl Drop for Active<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

pub fn is_tailnet(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && octets[1] & 0xC0 == 64
}

/// This machine's Tailscale IPv4 address, if Tailscale is up.
pub fn tailscale_ip() -> Option<Ipv4Addr> {
    if_addrs::get_if_addrs().ok()?.into_iter().find_map(|iface| match iface.ip() {
        IpAddr::V4(ip) if is_tailnet(ip) => Some(ip),
        _ => None,
    })
}

pub fn node_info(config: &Config, paths: &Paths) -> NodeInfo {
    NodeInfo {
        name: config.name.clone(),
        port: config.port,
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        version: VERSION.to_string(),
        home: paths.home.display().to_string(),
        limited: false,
    }
}

fn init_logging(paths: &Paths) -> Result<()> {
    fs::create_dir_all(&paths.dir)?;
    let path = paths.log();
    if fs::metadata(&path).map(|m| m.len() > LOG_ROTATE_BYTES).unwrap_or(false) {
        fs::rename(&path, path.with_extension("log.1"))?;
    }
    let file = fs::OpenOptions::new().create(true).append(true).open(&path)?;
    tracing_subscriber::fmt().with_ansi(false).with_writer(Mutex::new(file)).init();
    Ok(())
}

pub fn run(paths: Paths) -> Result<()> {
    init_logging(&paths)?;
    let config = paths.load_or_init()?;
    let (limited, refuse) = if privacy::has_full_disk_access() {
        (false, None)
    } else {
        match privacy::confine(&paths.home) {
            Ok(()) => {
                warn!("no Full Disk Access: Desktop, Documents and Downloads are blocked. Grant it in {}", privacy::GRANT_HELP);
                (true, None)
            }
            Err(err) => {
                warn!(%err, "could not confine the daemon; refusing file and command requests");
                (true, Some(format!("{} needs Full Disk Access for ferry: {}", config.name, privacy::GRANT_HELP)))
            }
        }
    };
    let daemon = Arc::new(Daemon {
        paths,
        env: EnvCache::new(),
        config_lock: Mutex::new(()),
        tailnet_only: config.bind.is_none(),
        limited,
        refuse,
        active: AtomicUsize::new(0),
    });
    info!(name = %config.name, port = config.port, version = VERSION, limited, "ferry daemon starting");
    if limited {
        let daemon = daemon.clone();
        thread::spawn(move || watch_for_access(&daemon));
    }

    // Warm the shell environment so the first command doesn't pay for it.
    {
        let daemon = daemon.clone();
        thread::spawn(move || drop(daemon.env.get(&daemon.paths)));
    }

    let mut bound: Option<IpAddr> = None;
    loop {
        let wanted = config.bind.or_else(|| tailscale_ip().map(IpAddr::V4));
        match wanted {
            Some(ip) if bound != Some(ip) => match TcpListener::bind(SocketAddr::new(ip, config.port)) {
                Ok(listener) => {
                    info!(%ip, port = config.port, "listening");
                    bound = Some(ip);
                    let daemon = daemon.clone();
                    thread::spawn(move || accept_loop(listener, daemon));
                }
                Err(err) => warn!(%ip, port = config.port, %err, "could not listen, will retry"),
            },
            Some(_) => {}
            None if bound.is_none() => warn!("no Tailscale address yet, waiting"),
            None => {}
        }
        thread::sleep(if bound.is_some() { WATCH_INTERVAL } else { Duration::from_secs(3) });
    }
}

/// Once Full Disk Access is granted, restart (the service manager brings the
/// daemon straight back) so it runs unconfined. A fresh process is asked,
/// because a running one may not see the new grant.
fn watch_for_access(daemon: &Daemon) {
    let Ok(exe) = std::env::current_exe() else { return };
    loop {
        thread::sleep(ACCESS_POLL);
        let granted = std::process::Command::new(&exe)
            .arg("__fda-check")
            .stdin(std::process::Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        if granted && daemon.active.load(Ordering::SeqCst) == 0 {
            info!("Full Disk Access granted; restarting to run unconfined");
            std::process::exit(0);
        }
    }
}

fn accept_loop(listener: TcpListener, daemon: Arc<Daemon>) {
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
            Err(err) => {
                warn!(%err, "accept failed");
                thread::sleep(Duration::from_millis(200));
                continue;
            }
        };
        let daemon = daemon.clone();
        thread::spawn(move || {
            let _active = Active::new(&daemon.active);
            let from = stream.peer_addr().ok();
            match handle(stream, &daemon) {
                Ok(()) | Err(ProtoError::Closed) => {}
                Err(err) => warn!(?from, %err, "connection ended with an error"),
            }
        });
    }
}

fn handle(mut stream: TcpStream, daemon: &Daemon) -> Result<(), ProtoError> {
    let from = match stream.peer_addr()?.ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            Some(ip) => ip,
            None => return Err(ProtoError::Auth("IPv6 peers are not supported".into())),
        },
    };
    if daemon.tailnet_only && !is_tailnet(from) {
        return Err(ProtoError::Auth(format!("{from} is not a tailnet address")));
    }
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    let mut magic = [0u8; 6];
    match stream.read_exact(&mut magic) {
        Ok(()) => {}
        // `ferry status` and port checks connect and hang up; not an error.
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Err(ProtoError::Closed),
        Err(err) => return Err(err.into()),
    }
    if &magic != MAGIC {
        return Err(ProtoError::Auth("not a ferry client".into()));
    }
    let mut conn = Conn::new(stream)?;
    let hello: Hello = conn.recv_json()?;
    if hello.v != PROTO_VERSION {
        return conn.send_err(format!(
            "protocol mismatch: this machine speaks v{PROTO_VERSION}, {} speaks v{}. Update ferry on both.",
            hello.info.name, hello.v
        ));
    }

    let config = daemon.paths.require().map_err(|err| ProtoError::Failed(err.to_string()))?;
    let key: [u8; 32] = match hello.mode {
        HelloMode::Fleet => *config.key.as_bytes(),
        HelloMode::Pair => match pending_secret(daemon) {
            Some(secret) => pair_key(&secret),
            None => return conn.send_err("no pairing code is active on this machine: run `ferry pair` there first"),
        },
    };

    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|err| ProtoError::Failed(err.to_string()))?;
    let nonce_s = hex_encode(&nonce);
    conn.send_ok(Challenge { nonce: nonce_s.clone(), name: config.name.clone() })?;
    let proof: Proof = conn.recv_json()?;
    let parts: [&[u8]; 4] =
        [hello.nonce.as_bytes(), nonce_s.as_bytes(), hello.info.name.as_bytes(), config.name.as_bytes()];
    if !mac_verify(&key, LABEL_CLIENT, &parts, &proof.mac) {
        warn!(%from, name = %hello.info.name, mode = ?hello.mode, "rejected: wrong key");
        return conn.send_err(match hello.mode {
            HelloMode::Fleet => format!(
                "{} is not paired with {}. Run `ferry pair` on one and `ferry pair <code>` on the other.",
                hello.info.name, config.name
            ),
            HelloMode::Pair => {
                count_failed_pairing(daemon);
                "wrong pairing code".to_string()
            }
        });
    }

    let client = Peer {
        name: hello.info.name.clone(),
        ip: from,
        port: hello.info.port,
        os: hello.info.os.clone(),
        arch: hello.info.arch.clone(),
        version: hello.info.version.clone(),
        home: hello.info.home.clone(),
    };
    if hello.mode == HelloMode::Pair {
        let taken = client.name == config.name || config.peer(&client.name).is_some_and(|p| p.ip != from);
        if taken {
            return conn.send_err(format!(
                "the name {:?} is already used in this fleet. Rename this machine with `ferry install --name <new>`.",
                client.name
            ));
        }
    }
    let config = remember(daemon, client)?;

    let grant = (hello.mode == HelloMode::Pair).then(|| {
        let pad = mac(&key, LABEL_WRAP, &parts[..2]);
        hex_encode(&xor32(config.key.as_bytes(), &pad))
    });
    conn.send_ok(Welcome {
        mac: hex_encode(&mac(&key, LABEL_SERVER, &parts)),
        info: NodeInfo { limited: daemon.limited, ..node_info(&config, &daemon.paths) },
        peers: config.peers.iter().filter(|p| p.name != hello.info.name).cloned().collect(),
        grant,
    })?;
    if hello.mode == HelloMode::Pair {
        daemon.paths.clear_pairing();
        info!(%from, name = %hello.info.name, "paired a new machine");
        return Ok(());
    }

    conn.set_read_timeout(None)?;
    let request: Request = match conn.recv_json() {
        Ok(request) => request,
        Err(ProtoError::Closed) => return Ok(()),
        Err(err) => return Err(err),
    };
    let op = request.name();
    let peer = hello.info.name.as_str();
    let started = std::time::Instant::now();
    let result = serve(conn, request, daemon, peer);
    let ms = started.elapsed().as_millis() as u64;
    match &result {
        Ok(detail) => info!(peer, op, ms, "{detail}"),
        Err(err) => warn!(peer, op, ms, %err, "request failed"),
    }
    result.map(|_| ())
}

fn pending_secret(daemon: &Daemon) -> Option<Vec<u8>> {
    let pairing = daemon.paths.load_pairing()?;
    if pairing.expires < now_secs() || pairing.attempts >= PAIRING_MAX_ATTEMPTS {
        daemon.paths.clear_pairing();
        return None;
    }
    hex_decode(&pairing.secret)
}

fn count_failed_pairing(daemon: &Daemon) {
    let _guard = daemon.config_lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(mut pairing) = daemon.paths.load_pairing() else { return };
    pairing.attempts += 1;
    if pairing.attempts >= PAIRING_MAX_ATTEMPTS {
        warn!("too many wrong pairing codes, the code is now void");
        daemon.paths.clear_pairing();
    } else if let Err(err) = daemon.paths.save_pairing(&pairing) {
        warn!(%err, "could not record a failed pairing attempt");
    }
}

/// Records where a peer was last seen and returns the current config.
fn remember(daemon: &Daemon, peer: Peer) -> Result<Config, ProtoError> {
    let _guard = daemon.config_lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut config = daemon.paths.require().map_err(|err| ProtoError::Failed(err.to_string()))?;
    if config.upsert_peer(peer)
        && let Err(err) = daemon.paths.save(&config)
    {
        warn!(%err, "could not save the peer list");
    }
    Ok(config)
}

/// Handles one authenticated request. The returned text goes in the log.
fn serve(mut conn: Conn, request: Request, daemon: &Daemon, peer: &str) -> Result<String, ProtoError> {
    let home = &daemon.paths.home;
    if let Some(reason) = &daemon.refuse
        && !matches!(request, Request::Ping)
    {
        conn.send_err(reason.clone())?;
        return Err(ProtoError::Failed(reason.clone()));
    }
    match request {
        Request::Ping => {
            conn.send_ok(())?;
            Ok("pong".into())
        }
        Request::Push { dest, force } => {
            let summary = transfer::recv_tree(&mut conn, &dest, home, home, force)?;
            Ok(format!("received {} files, {} bytes into {}", summary.files, summary.bytes, summary.root))
        }
        Request::Pull { sources, excludes, gitignore } => {
            match transfer::plan(&sources, home, home, &WalkOpts { excludes, gitignore }) {
                Ok(plan) => {
                    let summary = transfer::send_tree(&mut conn, plan)?;
                    Ok(format!("sent {} files, {} bytes from {sources:?}", summary.files, summary.bytes))
                }
                Err(message) => {
                    conn.send_err(message.clone())?;
                    Err(ProtoError::Failed(message))
                }
            }
        }
        Request::List { path } => {
            let resolved = resolve_path(&path, home, home);
            match list(&resolved) {
                Ok(entries) => {
                    let count = entries.len();
                    conn.send_ok(Listing { path: resolved.display().to_string(), entries })?;
                    Ok(format!("listed {count} entries in {}", resolved.display()))
                }
                Err(err) => {
                    let message = format!("{}: {err}", resolved.display());
                    conn.send_err(message.clone())?;
                    Err(ProtoError::Failed(message))
                }
            }
        }
        Request::Read { path } => {
            let resolved = resolve_path(&path, home, home);
            let mut file = match File::open(&resolved).and_then(|f| f.metadata().map(|m| (f, m))) {
                Ok((file, meta)) if meta.is_file() => file,
                Ok(_) => {
                    let message = format!("{}: not a file", resolved.display());
                    conn.send_err(message.clone())?;
                    return Err(ProtoError::Failed(message));
                }
                Err(err) => {
                    let message = format!("{}: {err}", resolved.display());
                    conn.send_err(message.clone())?;
                    return Err(ProtoError::Failed(message));
                }
            };
            conn.send_ok(())?;
            let mut buf = vec![0u8; CHUNK];
            let mut total = 0u64;
            loop {
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                total += n as u64;
                conn.send(Kind::Data, &buf[..n])?;
            }
            conn.send(Kind::FileEnd, &[])?;
            conn.flush()?;
            Ok(format!("read {total} bytes from {}", resolved.display()))
        }
        Request::Write { path } => {
            let resolved = resolve_path(&path, home, home);
            let opened = transfer::follow_links(&resolved).and_then(|target| {
                target.parent().map_or(Ok(()), fs::create_dir_all)?;
                let mode = fs::metadata(&target).ok().map(|meta| transfer::mode_bits(&meta));
                Partial::create(&target, mode).map(|(tmp, file)| (target, tmp, file))
            });
            let (target, tmp, mut file) = match opened {
                Ok(opened) => opened,
                Err(err) => {
                    let message = format!("{}: {err}", resolved.display());
                    conn.send_err(message.clone())?;
                    return Err(ProtoError::Failed(message));
                }
            };
            conn.send_ok(())?;
            let mut total = 0u64;
            let outcome = loop {
                match conn.recv() {
                    Ok((Kind::Data, bytes)) => {
                        if let Err(err) = file.write_all(bytes) {
                            break Err(format!("{}: {err}", resolved.display()));
                        }
                        total += bytes.len() as u64;
                    }
                    Ok((Kind::FileEnd, _)) => break Ok(()),
                    Ok((got, _)) => break Err(format!("unexpected {got:?} frame")),
                    Err(err) => break Err(err.to_string()),
                }
            };
            drop(file);
            let outcome = outcome.and_then(|()| tmp.finish(&target).map_err(|err| format!("{}: {err}", resolved.display())));
            match outcome {
                Ok(()) => {
                    conn.send_ok(Written { path: resolved.display().to_string(), bytes: total })?;
                    Ok(format!("wrote {total} bytes to {}", resolved.display()))
                }
                Err(message) => {
                    conn.send_err(message.clone())?;
                    Err(ProtoError::Failed(message))
                }
            }
        }
        Request::Exec(spec) => {
            let what = match (&spec.script, spec.argv.first()) {
                (Some(_), _) => "script".to_string(),
                (None, Some(program)) => program.clone(),
                (None, None) => "nothing".to_string(),
            };
            exec::serve(conn, spec, &daemon.paths, &daemon.env, peer)?;
            Ok(format!("ran {what}"))
        }
    }
}

fn list(path: &std::path::Path) -> std::io::Result<Vec<ListEntry>> {
    let describe = |name: String, meta: &fs::Metadata| ListEntry {
        name,
        kind: if meta.file_type().is_symlink() {
            "l"
        } else if meta.is_dir() {
            "d"
        } else {
            "f"
        }
        .to_string(),
        size: if meta.is_file() { meta.len() } else { 0 },
        mtime: transfer::mtime_secs(meta),
    };
    let meta = fs::metadata(path)?;
    if !meta.is_dir() {
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        return Ok(vec![describe(name, &meta)]);
    }
    let mut entries = Vec::new();
    for dent in fs::read_dir(path)? {
        let dent = dent?;
        // An entry that vanished mid-listing is simply left out.
        if let Ok(meta) = dent.metadata() {
            entries.push(describe(dent.file_name().to_string_lossy().into_owned(), &meta));
        }
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::thread::JoinHandle;

    use super::*;
    use crate::transfer::{Entry, EntryKind, ManifestChunk, Summary};

    /// A daemon whose home is a temporary directory, removed on drop.
    struct Fixture {
        daemon: Arc<Daemon>,
        home: PathBuf,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            if fs::remove_dir_all(&self.home).is_err() {}
        }
    }

    type Served = JoinHandle<Result<String, ProtoError>>;

    impl Fixture {
        fn new() -> Self {
            let mut id = [0u8; 8];
            getrandom::fill(&mut id).unwrap();
            let home = std::env::temp_dir().join(format!("ferry-test-{}", hex_encode(&id)));
            fs::create_dir(&home).unwrap();
            let daemon = Arc::new(Daemon {
                paths: Paths { dir: home.join(".ferry"), home: home.clone() },
                env: EnvCache::new(),
                config_lock: Mutex::new(()),
                tailnet_only: false,
                limited: false,
                refuse: None,
                active: AtomicUsize::new(0),
            });
            Self { daemon, home }
        }

        /// Serves one request and returns the client's end of it.
        fn request(&self, request: Request) -> (Conn, Served) {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (server, _) = listener.accept().unwrap();
            let daemon = self.daemon.clone();
            let served = thread::spawn(move || serve(Conn::new(server).unwrap(), request, &daemon, "test"));
            let conn = Conn::new(client).unwrap();
            conn.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            (conn, served)
        }

        /// Starts a write. The daemon has opened its file when this returns.
        fn start_write(&self, path: &str) -> (Conn, Served) {
            let (mut conn, served) = self.request(Request::Write { path: path.into() });
            conn.recv_reply::<()>().unwrap();
            (conn, served)
        }

        #[cfg(unix)]
        fn write(&self, path: &str, text: &str) {
            finish_write(self.start_write(path), text);
        }

        /// Starts copying a file to `a.txt` and sends its contents, but not
        /// the end. The daemon has written them when this returns.
        fn start_copy(&self, text: &str, mode: u32) -> (Conn, Served) {
            let (mut conn, served) = self.request(Request::Push { dest: "a.txt".into(), force: true });
            let entry = Entry { p: "a.txt".into(), k: EntryKind::File, s: text.len() as u64, m: 1, x: mode, l: None };
            conn.send_ok(ManifestChunk { entries: vec![entry], last: true, single_file: true }).unwrap();
            assert!(matches!(conn.recv().unwrap(), (Kind::Need, [0, 0, 0, 0])));
            conn.send(Kind::FileBegin, &0u32.to_le_bytes()).unwrap();
            conn.send(Kind::Data, text.as_bytes()).unwrap();
            conn.flush().unwrap();
            for _ in 0..1000 {
                if self.files().iter().any(|path| fs::metadata(path).is_ok_and(|meta| meta.len() == text.len() as u64)) {
                    return (conn, served);
                }
                thread::sleep(Duration::from_millis(10));
            }
            panic!("the daemon never wrote {text:?}");
        }

        fn files(&self) -> Vec<PathBuf> {
            fs::read_dir(&self.home).unwrap().map(|dent| dent.unwrap().path()).collect()
        }

        fn names(&self) -> Vec<String> {
            let mut names: Vec<String> =
                self.files().iter().map(|path| path.file_name().unwrap().to_string_lossy().into_owned()).collect();
            names.sort();
            names
        }

        fn read(&self, name: &str) -> String {
            fs::read_to_string(self.home.join(name)).unwrap()
        }
    }

    fn finish_write((mut conn, served): (Conn, Served), text: &str) {
        conn.send(Kind::Data, text.as_bytes()).unwrap();
        conn.send(Kind::FileEnd, &[]).unwrap();
        conn.flush().unwrap();
        assert_eq!(conn.recv_reply::<Written>().unwrap().bytes, text.len() as u64);
        served.join().unwrap().unwrap();
    }

    fn finish_copy((mut conn, served): (Conn, Served)) {
        conn.send(Kind::FileEnd, &[]).unwrap();
        conn.send_json(&serde_json::json!({ "errors": [] })).unwrap();
        assert_eq!(conn.recv_reply::<Summary>().unwrap().errors, Vec::<String>::new());
        served.join().unwrap().unwrap();
    }

    #[test]
    fn writes_at_once_to_names_that_differ_by_extension() {
        let fixture = Fixture::new();
        let json = fixture.start_write("c.json");
        let yaml = fixture.start_write("c.yaml");
        finish_write(json, "json");
        finish_write(yaml, "yaml");
        assert_eq!(fixture.read("c.json"), "json");
        assert_eq!(fixture.read("c.yaml"), "yaml");
        assert_eq!(fixture.names(), ["c.json", "c.yaml"]);
    }

    #[test]
    fn writes_at_once_to_one_file() {
        let fixture = Fixture::new();
        let first = fixture.start_write("a.txt");
        let second = fixture.start_write("a.txt");
        finish_write(first, "the first");
        finish_write(second, "second");
        assert_eq!(fixture.read("a.txt"), "second");
        assert_eq!(fixture.names(), ["a.txt"]);
    }

    #[test]
    fn copies_at_once_to_one_file() {
        let fixture = Fixture::new();
        let first = fixture.start_copy("first", 0o644);
        let second = fixture.start_copy("the second", 0o644);
        finish_copy(first);
        finish_copy(second);
        assert_eq!(fixture.read("a.txt"), "the second");
        assert_eq!(fixture.names(), ["a.txt"]);
    }

    #[cfg(unix)]
    mod unix {
        use std::os::unix::fs::{PermissionsExt, symlink};
        use std::path::Path;

        use super::*;

        fn mode(path: &Path) -> u32 {
            fs::metadata(path).unwrap().permissions().mode() & 0o7777
        }

        fn set_mode(path: &Path, mode: u32) {
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        }

        #[test]
        fn write_keeps_permissions() {
            let fixture = Fixture::new();
            let path = fixture.home.join("a.sh");
            fs::write(&path, "old").unwrap();
            for bits in [0o600, 0o755, 0o664, 0o400, 0o000] {
                set_mode(&path, bits);
                fixture.write("a.sh", "new");
                assert_eq!(mode(&path), bits, "expected {bits:o}");
            }
            set_mode(&path, 0o600);
            assert_eq!(fixture.read("a.sh"), "new");
        }

        #[test]
        fn new_files_get_default_permissions() {
            let fixture = Fixture::new();
            fs::write(fixture.home.join("usual"), "").unwrap();
            fixture.write("new", "text");
            assert_eq!(mode(&fixture.home.join("new")), mode(&fixture.home.join("usual")));
        }

        #[test]
        fn private_files_stay_private_while_being_written() {
            let fixture = Fixture::new();
            let path = fixture.home.join("secret");
            fs::write(&path, "old").unwrap();
            set_mode(&path, 0o600);
            let write = fixture.start_write("secret");
            assert_eq!(fixture.files().iter().map(|path| mode(path)).collect::<Vec<_>>(), [0o600, 0o600]);
            finish_write(write, "new");
            fs::remove_file(&path).unwrap();

            let copy = fixture.start_copy("copied", 0o600);
            assert_eq!(fixture.files().iter().map(|path| mode(path)).collect::<Vec<_>>(), [0o600]);
            finish_copy(copy);
        }

        #[test]
        fn write_goes_through_symlinks() {
            let fixture = Fixture::new();
            let target = fixture.home.join("dir").join("target");
            fs::create_dir(fixture.home.join("dir")).unwrap();
            fs::write(&target, "old").unwrap();
            set_mode(&target, 0o600);
            // A chain: link -> dir/inner -> target, both relative.
            symlink("dir/inner", fixture.home.join("link")).unwrap();
            symlink("target", fixture.home.join("dir").join("inner")).unwrap();

            let write = fixture.start_write("link");
            assert_eq!(fixture.names(), ["dir", "link"], "the temporary file belongs beside the target");
            finish_write(write, "new");
            assert_eq!(fs::read_link(fixture.home.join("link")).unwrap(), Path::new("dir/inner"));
            assert_eq!(fs::read_link(fixture.home.join("dir").join("inner")).unwrap(), Path::new("target"));
            assert_eq!(fs::read_to_string(&target).unwrap(), "new");
            assert_eq!(mode(&target), 0o600);
        }

        #[test]
        fn write_creates_the_target_of_a_dangling_symlink() {
            let fixture = Fixture::new();
            symlink("missing", fixture.home.join("link")).unwrap();
            fixture.write("link", "new");
            assert_eq!(fs::read_link(fixture.home.join("link")).unwrap(), Path::new("missing"));
            assert_eq!(fixture.read("missing"), "new");
        }

        #[test]
        fn write_refuses_a_symlink_loop() {
            let fixture = Fixture::new();
            symlink("b", fixture.home.join("a")).unwrap();
            symlink("a", fixture.home.join("b")).unwrap();
            let (mut conn, served) = fixture.request(Request::Write { path: "a".into() });
            assert!(conn.recv_reply::<()>().is_err());
            assert!(served.join().unwrap().is_err());
            assert_eq!(fixture.names(), ["a", "b"]);
        }
    }
}
