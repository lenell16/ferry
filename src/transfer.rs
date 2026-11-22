//! Copying trees: the sender lists what it has, the receiver answers with the
//! files it lacks, and only those travel. Both directions use the same two
//! functions with the roles swapped.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use ignore::WalkBuilder;
use ignore::overrides::OverrideBuilder;
use serde::{Deserialize, Serialize};

use crate::config::{hex_encode, random};
use crate::proto::{CHUNK, Conn, Kind, ProtoError, Reply};

const MANIFEST_BATCH: usize = 4096;
/// How many symlinks in a row to follow before calling it a loop.
const MAX_LINKS: usize = 40;
/// Never worth copying, and `._*` files have broken loaders on Windows.
const DEFAULT_EXCLUDES: &[&str] = &[".DS_Store", "._*"];
/// A chunk must shrink by this much to be sent compressed.
const MIN_SAVING: f64 = 0.9;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    #[serde(rename = "f")]
    File,
    #[serde(rename = "d")]
    Dir,
    #[serde(rename = "l")]
    Symlink,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Entry {
    /// Path relative to the destination root, `/`-separated.
    pub p: String,
    pub k: EntryKind,
    #[serde(default)]
    pub s: u64,
    /// Modification time, seconds since the epoch.
    #[serde(default)]
    pub m: i64,
    /// Unix permission bits, 0 when the sender has none (Windows).
    #[serde(default)]
    pub x: u32,
    /// Symlink target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub l: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ManifestChunk {
    pub entries: Vec<Entry>,
    pub last: bool,
    /// True when the whole transfer is one file named on the command line,
    /// which lets the destination name the file instead of a directory.
    pub single_file: bool,
}

#[derive(Serialize, Deserialize)]
struct SenderDone {
    errors: Vec<String>,
}

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct Summary {
    /// Where the files landed, as an absolute path on the receiver.
    pub root: String,
    pub files: u64,
    pub bytes: u64,
    pub unchanged: u64,
    pub entries: u64,
    pub errors: Vec<String>,
}

#[derive(Default)]
pub struct WalkOpts {
    pub excludes: Vec<String>,
    pub gitignore: bool,
}

/// Everything the sender is about to offer.
pub struct Plan {
    pub entries: Vec<Entry>,
    paths: Vec<PathBuf>,
    pub single_file: bool,
    pub errors: Vec<String>,
}

/// Turns `~`, relative and absolute spellings into a real path.
pub fn resolve_path(spec: &str, base: &Path, home: &Path) -> PathBuf {
    if spec.is_empty() || spec == "~" {
        return home.to_path_buf();
    }
    if let Some(rest) = spec.strip_prefix("~/").or_else(|| spec.strip_prefix("~\\")) {
        return home.join(rest);
    }
    let path = Path::new(spec);
    if path.is_absolute() { path.to_path_buf() } else { base.join(path) }
}

/// Follows a symlink to the file it names in the end, which may not exist yet.
pub fn follow_links(path: &Path) -> io::Result<PathBuf> {
    let mut path = path.to_path_buf();
    for _ in 0..MAX_LINKS {
        // Relative links start from the folder that holds them.
        match (fs::read_link(&path), path.parent()) {
            (Ok(link), Some(parent)) => path = parent.join(link),
            _ => return Ok(path),
        }
    }
    Err(io::Error::other("too many levels of symbolic links"))
}

pub fn ends_with_separator(spec: &str) -> bool {
    spec.ends_with('/') || (cfg!(windows) && spec.ends_with('\\'))
}

pub fn mtime_secs(meta: &fs::Metadata) -> i64 {
    match meta.modified().map(|time| time.duration_since(UNIX_EPOCH)) {
        Ok(Ok(after)) => after.as_secs() as i64,
        Ok(Err(before)) => -(before.duration().as_secs() as i64),
        Err(_) => 0,
    }
}

#[cfg(unix)]
pub fn mode_bits(meta: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
pub fn mode_bits(_meta: &fs::Metadata) -> u32 {
    0
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o7777))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> io::Result<()> {
    Ok(())
}

fn file_entry(rel: String, meta: &fs::Metadata) -> Entry {
    Entry { p: rel, k: EntryKind::File, s: meta.len(), m: mtime_secs(meta), x: mode_bits(meta), l: None }
}

/// Lists the files behind each source. A directory named without a trailing
/// slash is copied as itself; with one, its contents are copied.
pub fn plan(sources: &[String], base: &Path, home: &Path, opts: &WalkOpts) -> Result<Plan, String> {
    let mut plan = Plan { entries: Vec::new(), paths: Vec::new(), single_file: false, errors: Vec::new() };
    for spec in sources {
        let path = resolve_path(spec, base, home);
        let meta = fs::metadata(&path).map_err(|err| format!("{}: {err}", path.display()))?;
        if !meta.is_dir() {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| format!("{}: not a usable file name", path.display()))?;
            plan.entries.push(file_entry(name.to_string(), &meta));
            plan.paths.push(path);
            plan.single_file = sources.len() == 1;
            continue;
        }
        let contents_only = ends_with_separator(spec) || spec == "." || spec.ends_with("/.");
        let prefix = if contents_only {
            None
        } else {
            // `..` and friends have no file name until canonicalised.
            let named = path.file_name().map(|n| n.to_os_string()).or_else(|| {
                fs::canonicalize(&path).ok().and_then(|p| p.file_name().map(|n| n.to_os_string()))
            });
            named.and_then(|n| n.to_str().map(str::to_string))
        };
        walk(&path, prefix.as_deref(), opts, &mut plan)?;
    }
    Ok(plan)
}

fn walk(root: &Path, prefix: Option<&str>, opts: &WalkOpts, plan: &mut Plan) -> Result<(), String> {
    let mut overrides = OverrideBuilder::new(root);
    for pattern in DEFAULT_EXCLUDES.iter().copied().chain(opts.excludes.iter().map(String::as_str)) {
        overrides.add(&format!("!{pattern}")).map_err(|err| format!("bad --exclude {pattern:?}: {err}"))?;
    }
    let overrides = overrides.build().map_err(|err| format!("bad --exclude: {err}"))?;

    let mut builder = WalkBuilder::new(root);
    builder.standard_filters(false).follow_links(false).overrides(overrides);
    builder.sort_by_file_name(|a, b| a.cmp(b));
    if opts.gitignore {
        builder.git_ignore(true).git_exclude(true).git_global(true).parents(true).require_git(false);
    }

    for dent in builder.build() {
        let dent = match dent {
            Ok(dent) => dent,
            Err(err) => {
                plan.errors.push(err.to_string());
                continue;
            }
        };
        let path = dent.path();
        let below = path.strip_prefix(root).unwrap_or(path);
        let mut parts: Vec<&str> = prefix.into_iter().collect();
        let mut usable = true;
        for component in below.components() {
            match component.as_os_str().to_str() {
                Some(part) => parts.push(part),
                None => usable = false,
            }
        }
        if !usable {
            plan.errors.push(format!("{}: name is not valid UTF-8, skipped", path.display()));
            continue;
        }
        if parts.is_empty() {
            continue; // the root itself, when only its contents are wanted
        }
        let rel = parts.join("/");
        let Some(file_type) = dent.file_type() else { continue };
        if file_type.is_dir() {
            plan.entries.push(Entry { p: rel, k: EntryKind::Dir, s: 0, m: 0, x: 0, l: None });
        } else if file_type.is_symlink() {
            match fs::read_link(path) {
                Ok(target) => plan.entries.push(Entry {
                    p: rel,
                    k: EntryKind::Symlink,
                    s: 0,
                    m: 0,
                    x: 0,
                    l: Some(target.to_string_lossy().into_owned()),
                }),
                Err(err) => {
                    plan.errors.push(format!("{}: {err}", path.display()));
                    continue;
                }
            }
        } else if file_type.is_file() {
            match dent.metadata() {
                Ok(meta) => plan.entries.push(file_entry(rel, &meta)),
                Err(err) => {
                    plan.errors.push(format!("{}: {err}", path.display()));
                    continue;
                }
            }
        } else {
            continue; // sockets, pipes and devices don't copy
        }
        plan.paths.push(path.to_path_buf());
    }
    Ok(())
}

/// Offers the plan, then streams whatever the receiver asks for.
pub fn send_tree(conn: &mut Conn, mut plan: Plan) -> Result<Summary, ProtoError> {
    let mut batches = plan.entries.chunks(MANIFEST_BATCH).peekable();
    if batches.peek().is_none() {
        conn.send_ok(ManifestChunk { entries: Vec::new(), last: true, single_file: false })?;
    }
    while let Some(batch) = batches.next() {
        conn.send_ok(ManifestChunk {
            entries: batch.to_vec(),
            last: batches.peek().is_none(),
            single_file: plan.single_file,
        })?;
    }

    let wanted: Vec<u32> = match conn.recv()? {
        (Kind::Need, bytes) => bytes.chunks_exact(4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])).collect(),
        (Kind::Json, bytes) => match serde_json::from_slice::<Reply<()>>(bytes)? {
            Reply::Err(message) => return Err(ProtoError::Failed(message)),
            Reply::Ok(()) => return Err(ProtoError::Unexpected { got: Kind::Json, want: "the list of needed files" }),
        },
        (got, _) => return Err(ProtoError::Unexpected { got, want: "the list of needed files" }),
    };

    let mut buf = vec![0u8; CHUNK];
    for index in wanted {
        let Some(path) = plan.paths.get(index as usize) else { continue };
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(err) => {
                plan.errors.push(format!("{}: {err}", path.display()));
                continue;
            }
        };
        conn.send(Kind::FileBegin, &index.to_le_bytes())?;
        let mut compress = true;
        loop {
            let filled = match fill(&mut file, &mut buf) {
                Ok(filled) => filled,
                Err(err) => {
                    plan.errors.push(format!("{}: {err}", path.display()));
                    conn.send(Kind::FileAbort, &[])?;
                    break;
                }
            };
            if filled == 0 {
                conn.send(Kind::FileEnd, &[])?;
                break;
            }
            let chunk = &buf[..filled];
            if compress && filled >= 64 {
                let packed = lz4_flex::compress_prepend_size(chunk);
                if (packed.len() as f64) < filled as f64 * MIN_SAVING {
                    conn.send(Kind::DataLz4, &packed)?;
                } else {
                    // Already-compressed data: stop paying for the attempt.
                    compress = false;
                    conn.send(Kind::Data, chunk)?;
                }
            } else {
                conn.send(Kind::Data, chunk)?;
            }
            if filled < buf.len() {
                conn.send(Kind::FileEnd, &[])?;
                break;
            }
        }
    }
    conn.send_json(&SenderDone { errors: std::mem::take(&mut plan.errors) })?;
    conn.recv_reply()
}

/// Reads until the buffer is full or the file ends.
fn fill(file: &mut File, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    Ok(filled)
}

/// The temporary file a destination is written to first. Removed on drop
/// unless it was moved into place.
pub struct Partial {
    tmp: PathBuf,
    mode: Option<u32>,
}

impl Partial {
    /// Creates one in the same folder as `path`, under a name of its own so
    /// that writes running at the same time never share it. Given the mode the
    /// file will end up with, only its owner can open it until then.
    pub fn create(path: &Path, mode: Option<u32>) -> io::Result<(Self, File)> {
        let mut id = [0u8; 8];
        random(&mut id).map_err(io::Error::other)?;
        let tmp = path.with_file_name(format!(".ferry-{}", hex_encode(&id)));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        if mode.is_some() {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&tmp)?;
        Ok((Self { tmp, mode }, file))
    }

    /// Sets the final mode and moves the file to `path`.
    pub fn finish(self, path: &Path) -> io::Result<()> {
        if let Some(mode) = self.mode {
            set_mode(&self.tmp, mode)?;
        }
        fs::rename(&self.tmp, path)
    }
}

impl Drop for Partial {
    fn drop(&mut self) {
        if let Err(err) = fs::remove_file(&self.tmp)
            && err.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!(tmp = %self.tmp.display(), %err, "left a partial file behind");
        }
    }
}

/// A file being received. `file` comes before `tmp` so it is closed first.
struct Incoming {
    index: usize,
    file: Option<File>,
    tmp: Option<Partial>,
    bytes: u64,
    error: Option<String>,
}

/// Joins a manifest path onto the root, refusing anything that would escape.
fn target(root: &Path, rel: &str) -> Result<PathBuf, String> {
    let mut out = root.to_path_buf();
    for part in rel.split('/') {
        let mut components = Path::new(part).components();
        match (components.next(), components.next()) {
            (Some(Component::Normal(name)), None) => out.push(name),
            _ => return Err(format!("{rel}: unsafe path, skipped")),
        }
    }
    Ok(out)
}

fn unchanged(path: &Path, entry: &Entry) -> bool {
    match fs::symlink_metadata(path) {
        Ok(meta) => meta.is_file() && meta.len() == entry.s && (mtime_secs(&meta) - entry.m).abs() <= 1,
        Err(_) => false,
    }
}

#[cfg(unix)]
fn make_symlink(path: &Path, link: &str) -> Result<bool, String> {
    if let Ok(existing) = fs::read_link(path) {
        if existing == Path::new(link) {
            return Ok(false);
        }
        fs::remove_file(path).map_err(|err| format!("{}: {err}", path.display()))?;
    } else if fs::symlink_metadata(path).is_ok() {
        return Err(format!("{}: exists and is not a symlink", path.display()));
    }
    std::os::unix::fs::symlink(link, path).map_err(|err| format!("{}: {err}", path.display()))?;
    Ok(true)
}

#[cfg(not(unix))]
fn make_symlink(path: &Path, _link: &str) -> Result<bool, String> {
    Err(format!("{}: symlink skipped (not supported on this machine)", path.display()))
}

/// Receives a tree into `dest`. Returns what was written.
pub fn recv_tree(conn: &mut Conn, dest: &str, base: &Path, home: &Path, force: bool) -> Result<Summary, ProtoError> {
    let mut entries: Vec<Entry> = Vec::new();
    let single_file = loop {
        let chunk: ManifestChunk = conn.recv_reply()?;
        entries.extend(chunk.entries);
        if chunk.last {
            break chunk.single_file;
        }
    };

    let dest_path = resolve_path(dest, base, home);
    let as_directory = dest.is_empty() || ends_with_separator(dest) || dest_path.is_dir();
    let rename = (single_file && entries.len() == 1 && entries[0].k == EntryKind::File && !as_directory)
        .then(|| dest_path.file_name().and_then(|n| n.to_str()).map(str::to_string))
        .flatten();
    let root = match &rename {
        Some(_) => dest_path.parent().map(Path::to_path_buf).unwrap_or_else(|| dest_path.clone()),
        None => dest_path.clone(),
    };
    if let Err(err) = fs::create_dir_all(&root) {
        let message = format!("{}: {err}", root.display());
        conn.send_err(message.clone())?;
        return Err(ProtoError::Failed(message));
    }

    let mut summary = Summary {
        root: match &rename {
            Some(_) => dest_path.display().to_string(),
            None => root.display().to_string(),
        },
        entries: entries.len() as u64,
        ..Summary::default()
    };
    let mut targets: Vec<Option<PathBuf>> = Vec::with_capacity(entries.len());
    let mut need: Vec<u8> = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let rel = rename.as_deref().unwrap_or(&entry.p);
        let path = match target(&root, rel) {
            Ok(path) => path,
            Err(message) => {
                summary.errors.push(message);
                targets.push(None);
                continue;
            }
        };
        match entry.k {
            EntryKind::Dir => {
                if let Err(err) = fs::create_dir_all(&path) {
                    summary.errors.push(format!("{}: {err}", path.display()));
                }
            }
            EntryKind::Symlink => match make_symlink(&path, entry.l.as_deref().unwrap_or("")) {
                Ok(true) => summary.files += 1,
                Ok(false) => summary.unchanged += 1,
                Err(message) => summary.errors.push(message),
            },
            EntryKind::File => {
                if !force && unchanged(&path, entry) {
                    summary.unchanged += 1;
                } else {
                    need.extend_from_slice(&(index as u32).to_le_bytes());
                }
            }
        }
        targets.push(Some(path));
    }
    conn.send(Kind::Need, &need)?;
    conn.flush()?;

    let mut current: Option<Incoming> = None;
    loop {
        let (kind, payload) = conn.recv()?;
        match kind {
            Kind::FileBegin => {
                let index = payload
                    .try_into()
                    .map(u32::from_le_bytes)
                    .map_err(|_| ProtoError::Failed("malformed file header".into()))? as usize;
                let Some(Some(path)) = targets.get(index) else {
                    return Err(ProtoError::Failed("sender offered a file that was not requested".into()));
                };
                current = Some(open_incoming(index, path, &entries[index]));
            }
            Kind::Data | Kind::DataLz4 => {
                let Some(incoming) = current.as_mut() else {
                    return Err(ProtoError::Unexpected { got: kind, want: "a file header" });
                };
                if incoming.error.is_some() {
                    continue;
                }
                let unpacked;
                let bytes: &[u8] = if kind == Kind::DataLz4 {
                    let claimed = payload.get(..4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize);
                    if claimed.is_none_or(|len| len > CHUNK) {
                        return Err(ProtoError::Failed("compressed chunk is larger than allowed".into()));
                    }
                    unpacked = lz4_flex::decompress_size_prepended(payload)
                        .map_err(|err| ProtoError::Failed(format!("corrupt compressed chunk: {err}")))?;
                    &unpacked
                } else {
                    payload
                };
                if let Some(file) = incoming.file.as_mut() {
                    match file.write_all(bytes) {
                        Ok(()) => incoming.bytes += bytes.len() as u64,
                        Err(err) => incoming.error = Some(err.to_string()),
                    }
                }
            }
            Kind::FileEnd => {
                let Some(incoming) = current.take() else {
                    return Err(ProtoError::Unexpected { got: kind, want: "a file header" });
                };
                let entry = &entries[incoming.index];
                match finish_incoming(incoming, entry, &targets) {
                    Ok(bytes) => {
                        summary.files += 1;
                        summary.bytes += bytes;
                    }
                    Err(message) => summary.errors.push(message),
                }
            }
            Kind::FileAbort => current = None,
            Kind::Json => {
                let done: SenderDone = serde_json::from_slice(payload)?;
                summary.errors.extend(done.errors);
                break;
            }
            got => return Err(ProtoError::Unexpected { got, want: "file data" }),
        }
    }
    conn.send_ok(summary.clone())?;
    Ok(summary)
}

fn open_incoming(index: usize, path: &Path, entry: &Entry) -> Incoming {
    let mode = (entry.x != 0).then_some(entry.x);
    let opened = Partial::create(path, mode).or_else(|err| {
        // The manifest lists parents first, but an excluded parent can be missing.
        match (err.kind(), path.parent()) {
            (io::ErrorKind::NotFound, Some(parent)) => fs::create_dir_all(parent).and_then(|()| Partial::create(path, mode)),
            _ => Err(err),
        }
    });
    match opened {
        Ok((tmp, file)) => Incoming { index, file: Some(file), tmp: Some(tmp), bytes: 0, error: None },
        Err(err) => Incoming { index, file: None, tmp: None, bytes: 0, error: Some(err.to_string()) },
    }
}

/// Stamps the finished file with the sender's time and mode, then moves it
/// into place.
fn finish_incoming(mut incoming: Incoming, entry: &Entry, targets: &[Option<PathBuf>]) -> Result<u64, String> {
    let Some(Some(path)) = targets.get(incoming.index) else {
        return Err("internal: file without a destination".into());
    };
    let describe = |err: &dyn std::fmt::Display| format!("{}: {err}", path.display());
    if let Some(error) = incoming.error.take() {
        return Err(describe(&error));
    }
    let (Some(file), Some(tmp)) = (incoming.file.take(), incoming.tmp.take()) else {
        return Err(describe(&"file was never opened"));
    };
    let mtime = if entry.m >= 0 {
        UNIX_EPOCH + Duration::from_secs(entry.m as u64)
    } else {
        UNIX_EPOCH - Duration::from_secs(entry.m.unsigned_abs())
    };
    file.set_modified(mtime).map_err(|err| describe(&err))?;
    drop(file);
    tmp.finish(path).map_err(|err| describe(&err))?;
    Ok(incoming.bytes)
}
