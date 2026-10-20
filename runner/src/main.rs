//! Toolbay runner: one small program that opens a project as its own desktop window.
//!
//! Toolbay's build pipeline copies this program next to a `toolbay/` folder holding
//! `app.json` and the project's files, renames it after the project, and zips it up.
//! `app.json` picks one of three modes:
//!
//! - "static": a built web app (Vite, Next export, plain HTML) served from `toolbay/<root>`
//!   over a private `tb://` protocol, so routing, fetch() of local files and storage work
//!   as on a website, with no server and no open port.
//! - "server": a web app that needs its own server (Next.js SSR, Express). The runner starts
//!   the bundled command on a free local port and opens the window once it answers.
//! - "process": a program that opens its own window (a Python Tk/Qt app). The runner starts it
//!   with the bundled runtime and quits when it quits.
//! - "cli": a command-line tool. The runner shows a simple launcher page (fields for options,
//!   a Run button, the output) so people never need a terminal.
//!
//! Each app keeps its own browser storage in %LOCALAPPDATA%\Toolbay\AppData\<id>.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tauri::http::{Response, StatusCode};
use tauri::{AppHandle, Emitter, Manager, RunEvent, State, WebviewUrl, WebviewWindowBuilder};

#[derive(Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase", default)]
struct AppConfig {
    id: String,
    name: String,
    description: String,
    mode: String,
    width: Option<f64>,
    height: Option<f64>,
    /// static: folder inside toolbay/ with index.html.
    root: Option<String>,
    /// static: serve index.html for unknown paths (single-page apps).
    spa: Option<bool>,
    /// server / cli: program and fixed arguments; paths are relative to toolbay/.
    command: Vec<String>,
    cwd: Option<String>,
    env: HashMap<String, String>,
    /// server: page to open; {port} is replaced.
    url: Option<String>,
    /// cli: example options shown in the launcher.
    args_hint: Option<String>,
    /// cli: ask for a folder or file to pass.
    examples: Vec<String>,
}

struct Ctx {
    base: PathBuf,
    cfg: AppConfig,
    child: Mutex<Option<Child>>,
    stdin: Mutex<Option<std::process::ChildStdin>>,
}

/// toolbay/ next to the program (Windows, zip) or in the .app's Resources (macOS).
fn payload_dir() -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_default();
    let dir = exe.parent().map(Path::to_path_buf).unwrap_or_default();
    let candidates = [dir.join("toolbay"), dir.join("..").join("Resources").join("toolbay")];
    candidates.iter().find(|p| p.join("app.json").exists()).cloned().unwrap_or_else(|| dir.join("toolbay"))
}

fn resolve(base: &Path, p: &str) -> PathBuf {
    let path = Path::new(p);
    if path.is_absolute() || !p.contains(['/', '\\']) && !base.join(p).exists() {
        // Bare program names ("node") come from PATH; absolute paths are used as is.
        return path.to_path_buf();
    }
    base.join(path)
}

fn safe_join(root: &Path, url_path: &str) -> Option<PathBuf> {
    let decoded = percent_decode(url_path);
    let mut out = root.to_path_buf();
    for c in Path::new(decoded.trim_start_matches('/')).components() {
        match c {
            Component::Normal(s) => out.push(s),
            Component::CurDir => {}
            _ => return None,
        }
    }
    Some(out)
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or(""), 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn serve(root: &Path, spa: bool, path: &str) -> Response<Vec<u8>> {
    let path = path.split(['?', '#']).next().unwrap_or("/");
    let mut file = match safe_join(root, path) {
        Some(f) => f,
        None => return Response::builder().status(StatusCode::FORBIDDEN).body(vec![]).unwrap(),
    };
    if file.is_dir() {
        file = file.join("index.html");
    }
    if !file.exists() {
        // Next/Gatsby style exports: /about -> about.html
        let html = file.with_extension("html");
        if html.exists() {
            file = html;
        } else if spa && Path::new(path).extension().is_none() {
            file = root.join("index.html");
        }
    }
    match std::fs::read(&file) {
        Ok(bytes) => {
            let mime = mime_guess::from_path(&file).first_or_octet_stream();
            Response::builder()
                .header("Content-Type", mime.essence_str())
                .header("Cache-Control", "no-cache")
                .body(bytes)
                .unwrap()
        }
        Err(_) => Response::builder().status(StatusCode::NOT_FOUND).body(b"Not found".to_vec()).unwrap(),
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").and_then(|l| l.local_addr()).map(|a| a.port()).unwrap_or(38917)
}

fn fill(s: &str, port: u16) -> String {
    s.replace("{port}", &port.to_string())
}

fn command_for(ctx: &Ctx, extra: &[String], port: u16) -> Result<Command, String> {
    let (prog, fixed) = ctx.cfg.command.split_first().ok_or("This app has nothing to run.")?;
    let mut cmd = Command::new(resolve(&ctx.base, prog));
    cmd.args(fixed.iter().map(|a| fill(a, port))).args(extra);
    cmd.current_dir(ctx.cfg.cwd.as_deref().map(|c| ctx.base.join(c)).unwrap_or_else(|| ctx.base.clone()));
    for (k, v) in &ctx.cfg.env {
        cmd.env(k, fill(v, port));
    }
    // Bundled runtimes (node/, python/) come first on PATH.
    let mut path = vec![ctx.base.join("node"), ctx.base.join("python"), ctx.base.join("python").join("Scripts")];
    path.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()));
    if let Ok(p) = std::env::join_paths(path) {
        cmd.env("PATH", p);
    }
    cmd.env("PYTHONUNBUFFERED", "1").env("PYTHONIOENCODING", "utf-8").env("FORCE_COLOR", "0");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // no console window
    }
    Ok(cmd)
}

fn stop_child(ctx: &Ctx) {
    ctx.stdin.lock().unwrap().take();
    if let Some(mut c) = ctx.child.lock().unwrap().take() {
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            let _ = Command::new("taskkill")
                .args(["/PID", &c.id().to_string(), "/T", "/F"])
                .creation_flags(0x0800_0000)
                .status();
        }
        let _ = c.kill();
        let _ = c.wait();
    }
}

// ------------------------------------------------------------------ cli launcher commands

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Info {
    name: String,
    description: String,
    args_hint: String,
    examples: Vec<String>,
}

#[tauri::command]
fn cli_info(ctx: State<Ctx>) -> Result<Info, String> {
    if ctx.cfg.mode != "cli" {
        return Err("not available".into());
    }
    Ok(Info {
        name: ctx.cfg.name.clone(),
        description: ctx.cfg.description.clone(),
        args_hint: ctx.cfg.args_hint.clone().unwrap_or_default(),
        examples: ctx.cfg.examples.clone(),
    })
}

/// Split options the way a shell would for simple cases: spaces, and "quoted parts".
fn split_args(s: &str) -> Vec<String> {
    let (mut out, mut cur, mut quote, mut any) = (vec![], String::new(), None::<char>, false);
    for ch in s.chars() {
        match (quote, ch) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => cur.push(c),
            (None, '"' | '\'') => {
                quote = Some(ch);
                any = true
            }
            (None, c) if c.is_whitespace() => {
                if any || !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                    any = false;
                }
            }
            (None, c) => cur.push(c),
        }
    }
    if any || !cur.is_empty() {
        out.push(cur);
    }
    out
}

#[tauri::command]
fn cli_run(app: AppHandle, ctx: State<Ctx>, args: String) -> Result<(), String> {
    if ctx.cfg.mode != "cli" {
        return Err("not available".into());
    }
    stop_child(&ctx);
    let mut cmd = command_for(&ctx, &split_args(&args), 0)?;
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|_| "The tool didn't start. Try reinstalling it from Toolbay.".to_string())?;
    let out = child.stdout.take();
    let err = child.stderr.take();
    *ctx.stdin.lock().unwrap() = child.stdin.take();
    *ctx.child.lock().unwrap() = Some(child);
    for (stream, kind) in [(out.map(|o| Box::new(o) as Box<dyn std::io::Read + Send>), "out"), (err.map(|e| Box::new(e) as Box<dyn std::io::Read + Send>), "err")] {
        if let Some(s) = stream {
            let app = app.clone();
            std::thread::spawn(move || {
                for line in BufReader::new(s).lines().map_while(Result::ok) {
                    app.emit("cli-output", serde_json::json!({ "kind": kind, "line": line })).ok();
                }
            });
        }
    }
    let app2 = app.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis(200));
        let ctx = app2.state::<Ctx>();
        let mut guard = ctx.child.lock().unwrap();
        match guard.as_mut().map(|c| c.try_wait()) {
            Some(Ok(Some(status))) => {
                guard.take();
                app2.emit("cli-exit", status.code()).ok();
                break;
            }
            Some(Ok(None)) => continue,
            _ => {
                app2.emit("cli-exit", serde_json::Value::Null).ok();
                break;
            }
        }
    });
    Ok(())
}

#[tauri::command]
fn cli_input(ctx: State<Ctx>, line: String) -> Result<(), String> {
    let mut guard = ctx.stdin.lock().unwrap();
    let w = guard.as_mut().ok_or("The tool isn't running.")?;
    writeln!(w, "{line}").and_then(|_| w.flush()).map_err(|_| "The tool isn't listening.".to_string())
}

#[tauri::command]
fn cli_stop(ctx: State<Ctx>) {
    stop_child(&ctx);
}

// ------------------------------------------------------------------ main

fn fatal(msg: &str) -> ! {
    eprintln!("{msg}");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let _ = Command::new("mshta")
            .arg(format!("javascript:alert({});close()", serde_json::to_string(msg).unwrap()))
            .creation_flags(0x0800_0000)
            .status();
    }
    std::process::exit(1)
}

fn data_dir(id: &str) -> Option<PathBuf> {
    let id: String = id.chars().filter(|c| c.is_ascii_alphanumeric() || "-_.".contains(*c)).collect();
    #[cfg(windows)]
    let root = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    #[cfg(not(windows))]
    let root = std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Library").join("Application Support"));
    root.map(|r| r.join("Toolbay").join("AppData").join(if id.is_empty() { "app".into() } else { id }))
}

fn main() {
    let base = payload_dir();
    let cfg: AppConfig = std::fs::read_to_string(base.join("app.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| fatal("This app is missing its files. Reinstall it from Toolbay."));
    let ctx = Ctx { base: base.clone(), cfg: cfg.clone(), child: Mutex::new(None), stdin: Mutex::new(None) };
    let static_root = base.join(cfg.root.clone().unwrap_or_else(|| "www".into()));
    let spa = cfg.spa.unwrap_or(true);

    let app = tauri::Builder::default()
        .manage(ctx)
        .register_uri_scheme_protocol("tb", move |_ctx, req| serve(&static_root, spa, req.uri().path()))
        .invoke_handler(tauri::generate_handler![cli_info, cli_run, cli_input, cli_stop])
        .setup(move |app| {
            if cfg.mode == "process" {
                // A program with its own window (a Python Tk/Qt app, say): start it, stay
                // in the background, and quit when it quits, so the hub sees it as running.
                let ctx = app.state::<Ctx>();
                let mut cmd = command_for(&ctx, &[], 0).map_err(|e| e.to_string())?;
                cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
                let child = cmd.spawn().map_err(|_| "The app didn't start.".to_string())?;
                *ctx.child.lock().unwrap() = Some(child);
                let handle = app.handle().clone();
                std::thread::spawn(move || loop {
                    std::thread::sleep(Duration::from_millis(300));
                    let ctx = handle.state::<Ctx>();
                    let done = match ctx.child.lock().unwrap().as_mut().map(|c| c.try_wait()) {
                        Some(Ok(None)) => None,
                        Some(Ok(Some(s))) => Some(s.code().unwrap_or(0)),
                        _ => Some(1),
                    };
                    if let Some(code) = done {
                        handle.exit(code);
                        break;
                    }
                });
                return Ok(());
            }
            let title = if cfg.name.is_empty() { "Toolbay App".to_string() } else { cfg.name.clone() };
            let (w, h) = (cfg.width.unwrap_or(1200.0), cfg.height.unwrap_or(800.0));
            let tb = |p: &str| -> tauri::Url {
                let s = if cfg!(windows) { format!("http://tb.localhost{p}") } else { format!("tb://localhost{p}") };
                s.parse().unwrap()
            };
            let url = match cfg.mode.as_str() {
                "server" => WebviewUrl::App("loading.html".into()),
                "cli" => WebviewUrl::App("cli.html".into()),
                _ => WebviewUrl::CustomProtocol(tb("/")),
            };
            // Hidden until the first page has loaded, so there's no blank white flash.
            let mut b = WebviewWindowBuilder::new(app, "main", url)
                .title(&title)
                .inner_size(w, h)
                .min_inner_size(420.0, 320.0)
                .center()
                .visible(false)
                .on_page_load(|win, payload| {
                    if matches!(payload.event(), tauri::webview::PageLoadEvent::Finished) {
                        let _ = win.show();
                        let _ = win.set_focus();
                    }
                });
            if let Some(d) = data_dir(&cfg.id) {
                b = b.data_directory(d);
            }
            let win = b.build()?;
            // Show it anyway if the page is slow, so the app never seems not to open.
            let fallback = win.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_secs(4));
                if !fallback.is_visible().unwrap_or(true) {
                    let _ = fallback.show();
                }
            });

            if cfg.mode == "server" {
                let port = free_port();
                let ctx = app.state::<Ctx>();
                let mut cmd = command_for(&ctx, &[], port).map_err(|e| e.to_string())?;
                cmd.env("PORT", port.to_string()).env("HOSTNAME", "127.0.0.1").env("HOST", "127.0.0.1");
                cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
                let child = cmd.spawn().map_err(|_| "The app's server didn't start.".to_string())?;
                *ctx.child.lock().unwrap() = Some(child);
                let target = fill(cfg.url.as_deref().unwrap_or("http://127.0.0.1:{port}/"), port);
                std::thread::spawn(move || {
                    let start = Instant::now();
                    while start.elapsed() < Duration::from_secs(90) {
                        if TcpStream::connect_timeout(&([127, 0, 0, 1], port).into(), Duration::from_millis(300)).is_ok() {
                            std::thread::sleep(Duration::from_millis(400));
                            if let Ok(u) = target.parse() {
                                win.navigate(u).ok();
                            }
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(300));
                    }
                    win.eval("document.body.innerHTML='<p style=\"font:16px system-ui;color:#ededed;padding:32px\">This app didn\\'t start. Close it and try again; if it keeps happening, reinstall it from Toolbay.</p>'").ok();
                });
            }
            Ok(())
        })
        .build(tauri::generate_context!())
        .unwrap_or_else(|_| fatal("This app couldn't open. Make sure Microsoft Edge WebView2 is installed, then try again."));

    app.run(|handle, event| match event {
        // "process" mode has no window; don't quit just because none is open.
        RunEvent::ExitRequested { code: None, api, .. } if handle.state::<Ctx>().cfg.mode == "process" => {
            api.prevent_exit();
        }
        RunEvent::Exit => {
            stop_child(&handle.state::<Ctx>());
        }
        _ => {}
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_args() {
        assert_eq!(split_args(r#"-o "my file.txt" --fast"#), vec!["-o", "my file.txt", "--fast"]);
        assert_eq!(split_args(""), Vec::<String>::new());
        assert_eq!(split_args(r#"a '' b"#), vec!["a", "", "b"]);
    }

    #[test]
    fn blocks_traversal() {
        let root = Path::new("/r");
        assert!(safe_join(root, "/../etc/passwd").is_none());
        assert!(safe_join(root, "/%2e%2e/x").is_none());
        assert_eq!(safe_join(root, "/a/b.js").unwrap(), Path::new("/r/a/b.js"));
    }
}
