use axum::{
    extract::{DefaultBodyLimit, Multipart, Path, State},
    http::{HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::HashSet, sync::{Arc, Mutex}};

const APP_HTML: &str = include_str!("../static/app.html");
const PORT: u16 = 3100;

// ───────────────────────── data model ─────────────────────────

#[derive(Serialize, Deserialize, Clone, Default)]
struct Doc {
    name: String,
    text: String,
    html: String,
    updated: String,
    #[serde(default)]
    photo: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
struct Settings {
    api_key: Option<String>,
    model: String,
    default_query: String,
    daily_goal: u32,
    auto_prepare: bool,
    auto_threshold: u32,
}
impl Default for Settings {
    fn default() -> Self {
        Settings {
            api_key: None,
            model: "deepseek/deepseek-v4-flash".into(),
            default_query: String::new(),
            daily_goal: 10,
            auto_prepare: true,
            auto_threshold: 75,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Default)]
struct Job {
    id: String,
    title: String,
    company: String,
    url: String,
    location: String,
    source: String,
    jd: String,
    status: String, // new | saved | ready | applied | interview | offer | rejected
    score: Option<u32>,
    analysis: Option<Value>,
    cv_html: Option<String>,
    cover_html: Option<String>,
    warnings: Vec<String>,
    notes: String,
    created: String,
    applied_at: Option<String>,
    #[serde(default)]
    auto: bool,
    #[serde(default)]
    busy: bool,
    error: Option<String>,
}

#[derive(Serialize, Deserialize, Default)]
struct Db {
    settings: Settings,
    cv: Option<Doc>,
    cover: Option<Doc>,
    jobs: Vec<Job>,
}

struct St {
    db: Mutex<Db>,
    http: reqwest::Client,
    path: std::path::PathBuf,
}

type S = Arc<St>;

struct AppErr(StatusCode, String);
impl IntoResponse for AppErr {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}
fn bad<T: ToString>(m: T) -> AppErr { AppErr(StatusCode::BAD_REQUEST, m.to_string()) }
fn ise<T: ToString>(m: T) -> AppErr { AppErr(StatusCode::INTERNAL_SERVER_ERROR, m.to_string()) }
type R<T> = Result<T, AppErr>;

impl St {
    fn save(&self, db: &Db) {
        if let Ok(s) = serde_json::to_string_pretty(db) {
            let tmp = self.path.with_extension("tmp");
            if std::fs::write(&tmp, s).is_ok() {
                let _ = std::fs::rename(&tmp, &self.path);
            }
        }
    }
    /// mutate DB and persist
    fn with<T>(&self, f: impl FnOnce(&mut Db) -> T) -> T {
        let mut g = self.db.lock().unwrap();
        let r = f(&mut g);
        self.save(&g);
        r
    }
}

fn now() -> String { chrono::Utc::now().to_rfc3339() }

// ───────────────────────── text helpers ─────────────────────────

fn decode(s: &str) -> String {
    s.replace("&nbsp;", " ").replace("&lt;", "<").replace("&gt;", ">")
        .replace("&quot;", "\"").replace("&#39;", "'").replace("&amp;", "&")
}
fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}
fn strip_tags(h: &str) -> String {
    let mut o = String::with_capacity(h.len());
    let mut intag = false;
    for c in h.chars() {
        match c {
            '<' => { intag = true; o.push(' ') }
            '>' => intag = false,
            _ if !intag => o.push(c),
            _ => {}
        }
    }
    decode(&o).split_whitespace().collect::<Vec<_>>().join(" ")
}
fn digit_runs(s: &str) -> HashSet<String> {
    let mut set = HashSet::new();
    let mut cur = String::new();
    for c in s.chars() {
        if c.is_ascii_digit() { cur.push(c) } else if !cur.is_empty() { set.insert(std::mem::take(&mut cur)); }
    }
    if !cur.is_empty() { set.insert(cur); }
    set
}
/// remove dangerous markup the model (or a malicious JD) might have produced
fn sanitize_html(h: &str) -> String {
    let mut s = h.trim().to_string();
    if s.starts_with("```") {
        s = s.trim_start_matches("```html").trim_start_matches("```").trim_end_matches("```").trim().to_string();
    }
    for tag in ["script", "style", "iframe", "object", "embed", "form", "link", "meta"] {
        loop {
            let low = s.to_ascii_lowercase();
            let Some(a) = low.find(&format!("<{tag}")) else { break };
            let close = format!("</{tag}>");
            let end = low[a..].find(&close).map(|e| a + e + close.len())
                .or_else(|| low[a..].find('>').map(|e| a + e + 1)).unwrap_or(s.len());
            s.replace_range(a..end, "");
        }
    }
    // drop inline event handlers & javascript: urls
    let mut out = String::new();
    let mut rest = s.as_str();
    while let Some(i) = rest.to_ascii_lowercase().find(" on") {
        let (head, tail) = rest.split_at(i);
        let t = &tail[1..];
        let name_len = t.chars().take_while(|c| c.is_ascii_alphabetic()).count();
        let after = &t[name_len..];
        if name_len > 2 && after.trim_start().starts_with('=') {
            out.push_str(head);
            let a = after.trim_start()[1..].trim_start();
            let skip = if let Some(q) = a.chars().next().filter(|c| *c == '"' || *c == '\'') {
                a[1..].find(q).map(|e| e + 2).unwrap_or(a.len())
            } else { a.find(|c: char| c.is_whitespace() || c == '>').unwrap_or(a.len()) };
            rest = &a[skip..];
        } else {
            out.push_str(head);
            out.push(' ');
            rest = &tail[1..];
        }
    }
    out.push_str(rest);
    out.replace("javascript:", "")
}
fn extract_json(s: &str) -> Option<Value> {
    let a = s.find('{')?;
    let b = s.rfind('}')?;
    serde_json::from_str(&s[a..=b]).ok()
}
/// the exact string in `html` that corresponds to `needle` (raw or entity-escaped)
fn find_in_html(html: &str, needle: &str) -> Option<String> {
    let n = needle.trim();
    if n.len() < 8 || n.contains('<') || n.contains('>') { return None; }
    if html.contains(n) { return Some(n.to_string()); }
    let e = esc(n);
    if html.contains(&e) { return Some(e); }
    None
}

// ───────────────────────── LLM ─────────────────────────

async fn llm(st: &S, system: &str, user: &str) -> R<String> {
    let (key, model) = {
        let d = st.db.lock().unwrap();
        (
            d.settings.api_key.clone().filter(|k| !k.is_empty()).or_else(|| std::env::var("OPENROUTER_API_KEY").ok()),
            d.settings.model.clone(),
        )
    };
    let key = key.ok_or_else(|| bad("No OpenRouter API key. Add it in Settings."))?;
    let body = json!({
        "model": model,
        "temperature": 0.2,
        "messages": [{"role":"system","content":system},{"role":"user","content":user}]
    });
    let mut last = String::new();
    for attempt in 0..3 {
        let resp = st.http.post("https://openrouter.ai/api/v1/chat/completions")
            .bearer_auth(&key)
            .header("HTTP-Referer", "http://localhost:3100")
            .header("X-Title", "JobPilot")
            .json(&body).send().await;
        match resp {
            Ok(r) => {
                let status = r.status();
                let v: Value = r.json().await.unwrap_or(Value::Null);
                if let Some(c) = v["choices"][0]["message"]["content"].as_str() {
                    if !c.trim().is_empty() { return Ok(c.to_string()); }
                }
                last = v["error"]["message"].as_str().map(String::from).unwrap_or(format!("OpenRouter returned HTTP {status} with no content"));
                if status.as_u16() == 401 || status.as_u16() == 402 { break; }
            }
            Err(e) => last = e.to_string(),
        }
        tokio::time::sleep(std::time::Duration::from_secs(1 + attempt)).await;
    }
    Err(ise(format!("LLM error: {last}")))
}

const NO_INVENT: &str = "ABSOLUTE RULE: you may only use facts, employers, titles, dates, numbers, skills, tools and achievements that already appear in the candidate's CV text. Never invent, infer, exaggerate or add anything new. You may only reword, reorder, condense or emphasise what is already there.";

// ───────────────────────── documents ─────────────────────────

async fn upload_doc(State(st): State<S>, Path(kind): Path<String>, mut mp: Multipart) -> R<Json<Value>> {
    if kind != "cv" && kind != "cover" { return Err(bad("kind must be cv or cover")); }
    let mut name = String::new();
    let mut bytes = Vec::new();
    while let Some(f) = mp.next_field().await.map_err(bad)? {
        if f.name() == Some("file") {
            name = f.file_name().unwrap_or("document.pdf").to_string();
            bytes = f.bytes().await.map_err(bad)?.to_vec();
        }
    }
    if bytes.is_empty() { return Err(bad("No file received")); }
    let bytes2 = bytes.clone();
    let text = tokio::task::spawn_blocking(move || pdf_extract::extract_text_from_mem(&bytes))
        .await.map_err(|_| bad("Could not read this PDF"))?
        .map_err(|e| bad(format!("Could not read PDF: {e}")))?;
    let text = text.lines().map(|l| l.trim_end()).collect::<Vec<_>>().join("\n");
    if text.trim().len() < 50 {
        return Err(bad("No selectable text found in the PDF (is it a scan?). Export a text-based PDF."));
    }
    let sys = if kind == "cv" {
        "You convert text extracted from a PDF CV/resume into a clean HTML fragment (no <html>/<head>/<body>, no CSS, no scripts). The app's stylesheet depends on this exact structure:\n- <h1> = full name.\n- <ul class=\"contact\"> directly after it: one <li> per contact item (location, phone, email, each profile link as <a href>), original order.\n- <p class=\"summary\"> = the profile/intro paragraph(s), if the CV has one(one <p>, no <br>).\n- Then every section: <h2> section heading (keep the original language), followed by its entries.\n- Each entry (job, project, degree, course...): <h3> with the entry title (links as <a href>). If the entry has a date range, put it as <time>11.2024 - Present</time> as the FIRST child inside that <h3>. A sub-line (role, company, location) is a <p>. Bullet points are <ul><li>. Skills/languages/certificates: <p> or <ul><li> exactly as grouped in the original.\nPreserve EVERY word, number, link and the original order exactly; fix only line-break artefacts, broken hyphenation and text the extractor duplicated (it sometimes repeats a title or link text, e.g. 'Title (Title (Click hereClick here))' must become 'Title (<a>Click here</a>)'). Do not add, remove, summarise or rephrase anything. Output only the HTML."
    } else {
        "You convert text extracted from a PDF cover letter into a clean HTML fragment (no <html>/<head>/<body>, no CSS, no scripts). Layout of the original: sender block (name on the first line in <strong>, then address/phone/email lines separated by <br>) as one <p>; then the date <p> if present; then the subject line as <p><strong>...</strong></p>; salutation <p>; body paragraphs as <p>; closing and signature as <p> with <br>. Preserve EVERY word, number and the original order exactly; fix only line-break artefacts and broken hyphenation. Do not add, remove, summarise or rephrase anything. Output only the HTML."
    };
    let html = sanitize_html(&llm(&st, sys, &text).await?);
    let photo = if kind == "cv" { tokio::task::spawn_blocking(move || extract_photo(&bytes2)).await.ok().flatten() } else { None };
    let doc = Doc { name, text, html, updated: now(), photo };
    st.with(|d| if kind == "cv" { d.cv = Some(doc.clone()) } else { d.cover = Some(doc.clone()) });
    Ok(Json(json!({"name": doc.name, "updated": doc.updated})))
}

#[derive(Deserialize)]
struct HtmlBody { html: String }
async fn put_doc_html(State(st): State<S>, Path(kind): Path<String>, Json(b): Json<HtmlBody>) -> R<Json<Value>> {
    let html = sanitize_html(&b.html);
    st.with(|d| {
        let slot = if kind == "cv" { &mut d.cv } else { &mut d.cover };
        if let Some(doc) = slot { doc.html = html; doc.text = strip_tags(&doc.html); doc.updated = now(); }
    });
    Ok(Json(json!({"ok": true})))
}

const CV_CSS: &str = "<style>
html{background:#777}
body.cv{width:210mm;min-height:297mm;margin:0 auto;padding:10mm 0 10mm;position:relative;box-sizing:border-box;font:10.5pt/1.4 'Minion Pro','Palatino Linotype',Georgia,serif;color:#111;background:linear-gradient(90deg,#d4d4d4 0,#d4d4d4 52mm,#fff 52mm)}
body.cv a{color:#1f3a93}
body.cv>img.photo{position:absolute;left:12mm;top:12mm;width:40mm;height:52mm;object-fit:cover}
body.cv>h1{margin:6mm 12mm 4mm 62mm;font-size:25pt;font-weight:400;line-height:1.15;text-align:center}
body.cv>ul.contact{list-style:none;margin:0 12mm 0 90mm;padding:0;border:0;min-height:34mm;font-size:9.5pt}
body.cv>ul.contact li{margin:0 0 1.6mm;padding-left:7mm;position:relative;word-break:break-all}
body.cv>ul.contact li::before{position:absolute;left:0;top:0;font-size:9pt;content:'\\2022'}
body.cv>ul.contact li:nth-child(1)::before{content:'\\2316'}
body.cv>ul.contact li:nth-child(2)::before{content:'\\260E'}
body.cv>ul.contact li:nth-child(3)::before{content:'\\2709'}
body.cv>ul.contact li:nth-child(4)::before{content:'in';font:700 8pt Arial,sans-serif;top:.3mm}
body.cv>ul.contact li:nth-child(5)::before{content:'gh';font:700 7pt Arial,sans-serif;top:.4mm}
body.cv>ul.contact li:nth-child(6)::before{content:'\\25CE'}
body.cv>p.summary{margin:0 12mm;padding:8mm 0 6mm;border:0}
body.cv>h2{float:left;clear:left;width:38mm;margin:4mm 0 0 12mm;font-size:12.5pt;font-weight:700;line-height:1.2;border:0;padding:0;text-transform:none;letter-spacing:0}
body.cv>h3,body.cv>p,body.cv>ul{margin-left:56mm;margin-right:12mm;margin-top:0;margin-bottom:0;border-left:.35mm solid #222}
body.cv>h3{position:relative;padding:5mm 0 1mm 6mm;font-size:10.5pt;font-weight:700;line-height:1.3}
body.cv>h3::before{content:'';position:absolute;left:-1.4mm;top:6.6mm;width:2.4mm;height:2.4mm;border-radius:50%;background:#111}
body.cv>h3 time{position:absolute;left:-44mm;top:5.3mm;width:36mm;font-weight:400;font-size:9.5pt;color:#333}
body.cv>h2+h3 time{top:13mm}
body.cv>p{padding:0 0 1mm 6mm}
body.cv>ul{padding:1mm 0 2mm 12mm;list-style:disc}
body.cv>ul li{margin:0 0 .8mm;text-align:justify}
body.cv>p.summary{border:0}
@media print{html{background:linear-gradient(90deg,#d4d4d4 0,#d4d4d4 52mm,#fff 52mm)}body.cv{background:none;margin:0;padding:10mm 0;min-height:0;-webkit-box-decoration-break:clone;box-decoration-break:clone}body.cv>img.photo{top:12mm}@page{size:A4;margin:0}}
@media print{*{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
</style>";

const CL_CSS: &str = "<style>
body.cl{font:11pt/1.3 'Times New Roman',Times,serif;color:#000;max-width:170mm;margin:12mm auto;padding:0 6mm}
body.cl h1,body.cl h2,body.cl h3{font-size:11pt;font-weight:700;margin:0 0 9pt;padding:0;border:0;text-transform:none;letter-spacing:0}
body.cl p{margin:0 0 9pt}
body.cl a{color:#0563c1}
@media print{body.cl{margin:0;padding:0;max-width:none}@page{size:A4;margin:25mm}}
</style>";

fn page_html(html: &str, title: &str, kind: &str, photo: Option<&str>) -> String {
    let (css, cls) = if kind == "cv" { (CV_CSS, "cv") } else { (CL_CSS, "cl") };
    let img = match (kind == "cv", photo) { (true, Some(p)) => format!("<img class=\"photo\" src=\"{p}\">"), _ => String::new() };
    format!("<!doctype html><html><head><meta charset=utf-8><title>{}</title>{css}</head><body class=\"{cls}\">{img}{html}</body></html>", esc(title))
}

fn doc_page(html: &str, title: &str, kind: &str, photo: Option<&str>) -> Response {
    let mut r = Html(page_html(html, title, kind, photo)).into_response();
    r.headers_mut().insert("content-security-policy", HeaderValue::from_static("default-src 'none'; style-src 'unsafe-inline'; img-src data:"));
    r
}

fn cv_photo(d: &Db) -> Option<String> { d.cv.as_ref().and_then(|c| c.photo.clone()) }

async fn view_base(State(st): State<S>, Path(kind): Path<String>) -> Response {
    let r = { let d = st.db.lock().unwrap(); (if kind == "cv" { &d.cv } else { &d.cover }).as_ref().map(|x| (x.html.clone(), cv_photo(&d))) };
    match r { Some((h, p)) => doc_page(&h, &kind, &kind, p.as_deref()), None => (StatusCode::NOT_FOUND, "not uploaded").into_response() }
}
async fn view_job(State(st): State<S>, Path((id, kind)): Path<(String, String)>) -> Response {
    let r = { let d = st.db.lock().unwrap(); d.jobs.iter().find(|j| j.id == id).map(|j| (if kind == "cv" { j.cv_html.clone() } else { j.cover_html.clone() }, format!("{} - {} - {}", kind, j.company, j.title), cv_photo(&d))) };
    match r { Some((Some(h), t, p)) => doc_page(&h, &t, &kind, p.as_deref()), _ => (StatusCode::NOT_FOUND, "not generated yet").into_response() }
}

// ───────────────────────── PDF export (headless Edge/Chrome) ─────────────────────────

fn find_browser() -> Option<String> {
    [r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
     r"C:\Program Files\Google\Chrome\Application\chrome.exe", r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"]
        .iter().find(|p| std::path::Path::new(p).exists()).map(|s| s.to_string())
}

async fn html_to_pdf(page: String) -> R<Vec<u8>> {
    let exe = find_browser().ok_or_else(|| ise("Microsoft Edge or Google Chrome is needed to create PDFs but was not found."))?;
    let dir = std::env::temp_dir().join(format!("jp_pdf_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).map_err(ise)?;
    let src = dir.join("page.html");
    let out = dir.join("out.pdf");
    std::fs::write(&src, page).map_err(ise)?;
    let url = format!("file:///{}", src.to_string_lossy().replace('\\', "/").replace(' ', "%20"));
    let mut cmd = tokio::process::Command::new(exe);
    cmd.args(["--headless=new", "--disable-gpu", "--no-pdf-header-footer", "--no-first-run"])
        .arg(format!("--user-data-dir={}", dir.join("profile").display()))
        .arg(format!("--print-to-pdf={}", out.display()))
        .arg(url).kill_on_drop(true);
    #[cfg(windows)] cmd.creation_flags(0x08000000);
    let run = tokio::time::timeout(std::time::Duration::from_secs(60), cmd.output()).await;
    let bytes = std::fs::read(&out);
    let _ = std::fs::remove_dir_all(&dir);
    match (run, bytes) {
        (_, Ok(b)) if b.len() > 500 => Ok(b),
        _ => Err(ise("Could not create the PDF (browser did not produce a file).")),
    }
}

fn safe_name(s: &str) -> String {
    let t: String = s.chars().map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect();
    t.trim_matches('_').chars().take(80).collect()
}

async fn finish_export(kind: &str, html: &str, photo: Option<String>, stem: &str) -> R<Json<Value>> {
    let bytes = html_to_pdf(page_html(html, stem, kind, photo.as_deref())).await?;
    let home = std::env::var("USERPROFILE").unwrap_or_else(|_| ".".into());
    let dir = std::path::PathBuf::from(home).join("Downloads");
    std::fs::create_dir_all(&dir).ok();
    let path = dir.join(format!("{}.pdf", safe_name(stem)));
    std::fs::write(&path, bytes).map_err(ise)?;
    let _ = std::process::Command::new("explorer.exe").arg(format!("/select,{}", path.display())).spawn();
    Ok(Json(json!({"path": path.to_string_lossy()})))
}

async fn export_base(State(st): State<S>, Path(kind): Path<String>) -> R<Json<Value>> {
    let (h, name, photo) = {
        let d = st.db.lock().unwrap();
        let doc = (if kind == "cv" { &d.cv } else { &d.cover }).as_ref().ok_or_else(|| bad("not uploaded"))?;
        (doc.html.clone(), doc.name.clone(), cv_photo(&d))
    };
    let stem = name.trim_end_matches(".pdf").trim_end_matches(".PDF").to_string();
    finish_export(&kind, &h, photo, &format!("{stem}_{kind}")).await
}
async fn export_job(State(st): State<S>, Path((id, kind)): Path<(String, String)>) -> R<Json<Value>> {
    let (h, stem, photo) = {
        let d = st.db.lock().unwrap();
        let j = d.jobs.iter().find(|j| j.id == id).ok_or_else(|| bad("no such job"))?;
        let h = (if kind == "cv" { j.cv_html.clone() } else { j.cover_html.clone() }).ok_or_else(|| bad("not generated yet"))?;
        let who = d.cv.as_ref().map(|c| c.name.trim_end_matches(".pdf").to_string()).unwrap_or_default();
        let who = if kind == "cv" { who } else { "Cover_Letter".to_string() };
        (h, format!("{}_{}", who, if j.company.is_empty() { j.title.clone() } else { j.company.clone() }), cv_photo(&d))
    };
    finish_export(&kind, &h, photo, &stem).await
}

// ───────────────────────── photo extraction (best effort, needs poppler's pdfimages) ─────────────────────────

fn find_pdfimages() -> String {
    if let Ok(rd) = std::fs::read_dir(r"C:\poppler") {
        for e in rd.flatten() {
            let p = e.path().join("Library").join("bin").join("pdfimages.exe");
            if p.exists() { return p.to_string_lossy().to_string(); }
        }
    }
    "pdfimages".into()
}

fn extract_photo(pdf: &[u8]) -> Option<String> {
    use base64::Engine;
    let dir = std::env::temp_dir().join(format!("jp_img_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).ok()?;
    std::fs::write(dir.join("in.pdf"), pdf).ok()?;
    let mut cmd = std::process::Command::new(find_pdfimages());
    cmd.args(["-all", "-f", "1", "-l", "1"]).arg(dir.join("in.pdf")).arg(dir.join("img"));
    #[cfg(windows)] { use std::os::windows::process::CommandExt; cmd.creation_flags(0x08000000); }
    let _ = cmd.output();
    let mut best: Option<(u64, std::path::PathBuf, &str)> = None;
    for e in std::fs::read_dir(&dir).ok()?.flatten() {
        let p = e.path();
        let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("").to_lowercase();
        let mime = match ext.as_str() { "jpg" | "jpeg" => "image/jpeg", "png" => "image/png", _ => continue };
        let len = e.metadata().map(|m| m.len()).unwrap_or(0);
        if len < 8_000 || len > 4_000_000 { continue; }
        // prefer JPEGs (photos); PNG output of soft masks is usually tiny/flat
        let rank = len + if mime == "image/jpeg" { 100_000_000 } else { 0 };
        if best.as_ref().map_or(true, |b| rank > b.0) { best = Some((rank, p, mime)); }
    }
    let r = best.and_then(|(_, p, mime)| std::fs::read(p).ok().map(|b| format!("data:{mime};base64,{}", base64::engine::general_purpose::STANDARD.encode(b))));
    let _ = std::fs::remove_dir_all(&dir);
    r
}

async fn health() -> Response {
    let mut r = Json(json!({"ok": true})).into_response();
    r.headers_mut().insert("access-control-allow-origin", HeaderValue::from_static("*"));
    r
}

fn job_summary(j: &Job) -> Value {
    json!({
        "id": j.id, "title": j.title, "company": j.company, "url": j.url, "location": j.location,
        "source": j.source, "status": j.status, "score": j.score, "notes": j.notes, "created": j.created,
        "applied_at": j.applied_at, "auto": j.auto, "busy": j.busy, "error": j.error,
        "has_docs": j.cv_html.is_some(), "has_analysis": j.analysis.is_some(), "warnings": j.warnings.len(),
    })
}

async fn get_state(State(st): State<S>) -> Json<Value> {
    let d = st.db.lock().unwrap();
    let key_set = d.settings.api_key.as_deref().map_or(false, |k| !k.is_empty()) || std::env::var("OPENROUTER_API_KEY").is_ok();
    Json(json!({
        "settings": {"has_key": key_set, "model": d.settings.model, "default_query": d.settings.default_query,
            "daily_goal": d.settings.daily_goal, "auto_prepare": d.settings.auto_prepare, "auto_threshold": d.settings.auto_threshold},
        "cv": d.cv.as_ref().map(|x| json!({"name": x.name, "updated": x.updated})),
        "cover": d.cover.as_ref().map(|x| json!({"name": x.name, "updated": x.updated})),
        "jobs": d.jobs.iter().map(job_summary).collect::<Vec<_>>(),
    }))
}

#[derive(Deserialize)]
struct SettingsBody {
    api_key: Option<String>, model: Option<String>, default_query: Option<String>,
    daily_goal: Option<u32>, auto_prepare: Option<bool>, auto_threshold: Option<u32>,
}
async fn put_settings(State(st): State<S>, Json(b): Json<SettingsBody>) -> Json<Value> {
    st.with(|d| {
        let s = &mut d.settings;
        if let Some(k) = b.api_key { if !k.trim().is_empty() { s.api_key = Some(k.trim().to_string()); } }
        if let Some(m) = b.model { if !m.trim().is_empty() { s.model = m.trim().to_string(); } }
        if let Some(q) = b.default_query { s.default_query = q; }
        if let Some(g) = b.daily_goal { s.daily_goal = g; }
        if let Some(a) = b.auto_prepare { s.auto_prepare = a; }
        if let Some(t) = b.auto_threshold { s.auto_threshold = t.min(100); }
    });
    Json(json!({"ok": true}))
}

// ───────────────────────── jobs ─────────────────────────

fn new_job(title: &str, company: &str, url: &str, location: &str, source: &str, jd: &str) -> Job {
    Job {
        id: uuid::Uuid::new_v4().to_string()[..8].to_string(),
        title: title.into(), company: company.into(), url: url.into(), location: location.into(), source: source.into(),
        jd: jd.chars().take(14000).collect(), status: "new".into(), created: now(), ..Default::default()
    }
}

#[derive(Deserialize)]
struct NewJob { title: Option<String>, company: Option<String>, url: Option<String>, jd: String, #[serde(default)] analyze: bool }
async fn create_job(State(st): State<S>, Json(b): Json<NewJob>) -> R<Json<Value>> {
    if b.jd.trim().len() < 40 { return Err(bad("Paste the full job description.")); }
    let j = new_job(b.title.as_deref().unwrap_or(""), b.company.as_deref().unwrap_or(""), b.url.as_deref().unwrap_or(""), "", "pasted", &b.jd);
    let id = j.id.clone();
    st.with(|d| d.jobs.insert(0, j));
    if b.analyze { analyze_job(&st, &id).await?; }
    Ok(Json(json!({"id": id})))
}

async fn get_job(State(st): State<S>, Path(id): Path<String>) -> R<Json<Value>> {
    let d = st.db.lock().unwrap();
    let j = d.jobs.iter().find(|j| j.id == id).ok_or_else(|| AppErr(StatusCode::NOT_FOUND, "no such job".into()))?;
    let mut v = job_summary(j);
    v["jd"] = json!(j.jd); v["analysis"] = json!(j.analysis); v["warnings_list"] = json!(j.warnings);
    Ok(Json(v))
}

#[derive(Deserialize)]
struct PatchJob { status: Option<String>, notes: Option<String>, title: Option<String>, company: Option<String>, url: Option<String> }
async fn patch_job(State(st): State<S>, Path(id): Path<String>, Json(b): Json<PatchJob>) -> Json<Value> {
    st.with(|d| if let Some(j) = d.jobs.iter_mut().find(|j| j.id == id) {
        if let Some(s) = b.status {
            if s == "applied" && j.applied_at.is_none() { j.applied_at = Some(now()); }
            if s != "applied" && s != "interview" && s != "offer" && s != "rejected" { j.applied_at = None; }
            j.status = s;
        }
        if let Some(n) = b.notes { j.notes = n; }
        if let Some(n) = b.title { j.title = n; }
        if let Some(n) = b.company { j.company = n; }
        if let Some(n) = b.url { j.url = n; }
    });
    Json(json!({"ok": true}))
}
async fn delete_job(State(st): State<S>, Path(id): Path<String>) -> Json<Value> {
    st.with(|d| d.jobs.retain(|j| j.id != id));
    Json(json!({"ok": true}))
}

// ───────────────────────── analysis ─────────────────────────

fn set_busy(st: &S, id: &str, busy: bool, err: Option<String>) {
    st.with(|d| if let Some(j) = d.jobs.iter_mut().find(|j| j.id == id) { j.busy = busy; if !busy || err.is_some() { j.error = err; } });
}

async fn analyze_job(st: &S, id: &str) -> R<()> {
    set_busy(st, id, true, None);
    let r = analyze_inner(st, id).await;
    set_busy(st, id, false, r.as_ref().err().map(|e| e.1.clone()));
    r
}

async fn analyze_inner(st: &S, id: &str) -> R<()> {
    let (cv, jd, cv_html) = {
        let d = st.db.lock().unwrap();
        let cv = d.cv.clone().ok_or_else(|| bad("Upload your CV first (Documents tab)."))?;
        let j = d.jobs.iter().find(|j| j.id == id).ok_or_else(|| bad("no such job"))?;
        (cv.text.clone(), j.jd.clone(), cv.html.clone())
    };
    let sys = format!("You are a meticulous technical recruiter and resume editor. Compare the candidate's CV with the job description and answer with ONE JSON object only (no markdown).\n{NO_INVENT}\nMATCHING IS BASED ON SKILLS ONLY. From the JD list the concrete skills it asks for: technologies, programming languages, frameworks, tools, platforms, methods and explicit technical/professional competencies (max 30, de-duplicated, short names like \"FastAPI\" or \"RAG\"). IGNORE years of experience, degrees, seniority, location, language level, salary, soft traits, benefits and company description. For each skill decide if the CV evidences it: in_cv=true only if the CV text explicitly contains that skill or an obvious exact equivalent (e.g. \"LLMs\" = \"Large Language Models\"); then put in evidence a short EXACT quote from the CV (max 120 chars). Otherwise in_cv=false, evidence=\"\". required=true if the JD marks it required/must-have/core, false if nice-to-have/preferred.\nSchema:\n{{\"title\":str (job title from JD),\"company\":str (or \"\"),\"verdict\":str (1-2 sentences about the SKILL fit only),\"skills\":[{{\"skill\":str,\"required\":bool,\"in_cv\":bool,\"evidence\":str}}],\"suggestions\":[{{\"section\":str,\"original\":str,\"proposed\":str,\"reason\":str}}]}}\nSuggestion rules: 'original' MUST be copied character-for-character from ONE text passage of the CV HTML (plain text only, no tags, 12-300 chars). 'proposed' is plain text that rewords/reorders/emphasises that same passage using JD skill terminology ONLY where the CV genuinely supports it. No new numbers, tools, employers or claims. Give at most 8 high-impact suggestions (skill keywords, ordering of strengths, summary tailoring).");
    let user = format!("=== CV (HTML) ===\n{cv_html}\n\n=== JOB DESCRIPTION ===\n{jd}");
    let out = llm(st, &sys, &user).await?;
    let mut v = extract_json(&out).ok_or_else(|| ise("The model returned an unreadable answer. Try again."))?;
    let cv_digits = digit_runs(&cv);
    let mut kept = vec![];
    let mut dropped = 0;
    for s in v["suggestions"].as_array().cloned().unwrap_or_default() {
        let orig = s["original"].as_str().unwrap_or("");
        let prop = s["proposed"].as_str().unwrap_or("").trim();
        let ok_nums = digit_runs(prop).is_subset(&cv_digits);
        match (find_in_html(&cv_html, orig), ok_nums && !prop.is_empty() && prop != orig) {
            (Some(m), true) => kept.push(json!({
                "id": kept.len(), "section": s["section"], "original": m, "proposed": prop, "reason": s["reason"]
            })),
            _ => dropped += 1,
        }
    }
    v["suggestions"] = json!(kept);
    v["dropped_unsafe"] = json!(dropped);
    // score is computed here from verified skills (required = weight 2, nice-to-have = weight 1)
    let norm = |x: &str| x.to_lowercase().split_whitespace().collect::<Vec<_>>().join(" ");
    let cv_norm = norm(&cv);
    let (mut got, mut tot) = (0.0f64, 0.0f64);
    let (mut matched, mut missing, mut rows) = (vec![], vec![], vec![]);
    for sk in v["skills"].as_array().cloned().unwrap_or_default() {
        let name = sk["skill"].as_str().unwrap_or("").trim().to_string();
        if name.is_empty() { continue; }
        let w = if sk["required"].as_bool().unwrap_or(true) { 2.0 } else { 1.0 };
        let ev = sk["evidence"].as_str().unwrap_or("");
        let nn = norm(&name);
        let claimed = sk["in_cv"].as_bool().unwrap_or(false);
        let found = (claimed && (cv_norm.contains(&nn) || (ev.len() >= 3 && cv_norm.contains(&norm(ev)))))
            || (nn.len() >= 4 && cv_norm.contains(&nn));
        tot += w;
        if found { got += w; matched.push(name.clone()); } else { missing.push(name.clone()); }
        rows.push(json!({"skill": name, "required": w > 1.5, "in_cv": found, "evidence": ev}));
    }
    let score = if tot > 0.0 { (100.0 * got / tot).round() as u32 } else { 0 };
    v["skills"] = json!(rows);
    v["matched"] = json!(matched);
    v["missing"] = json!(missing);
    v["score"] = json!(score);
    let (t, c) = (v["title"].as_str().unwrap_or("").to_string(), v["company"].as_str().unwrap_or("").to_string());
    st.with(|d| if let Some(j) = d.jobs.iter_mut().find(|j| j.id == id) {
        j.score = Some(score); j.analysis = Some(v);
        if j.title.is_empty() { j.title = t; }
        if j.company.is_empty() { j.company = c; }
        if j.status == "new" && score >= 1 { j.status = "new".into(); }
    });
    Ok(())
}

async fn analyze_route(State(st): State<S>, Path(id): Path<String>) -> R<Json<Value>> {
    analyze_job(&st, &id).await?;
    Ok(Json(json!({"ok": true})))
}

// ───────────────────────── generation (approved edits → CV + cover letter) ─────────────────────────

#[derive(Deserialize)]
struct GenBody { accepted: Vec<usize> }
async fn generate_route(State(st): State<S>, Path(id): Path<String>, Json(b): Json<GenBody>) -> R<Json<Value>> {
    set_busy(&st, &id, true, None);
    let r = generate_job(&st, &id, &b.accepted, false).await;
    set_busy(&st, &id, false, r.as_ref().err().map(|e| e.1.clone()));
    r?;
    Ok(Json(json!({"ok": true})))
}

async fn generate_job(st: &S, id: &str, accepted: &[usize], auto: bool) -> R<()> {
    let (cv, cover, job) = {
        let d = st.db.lock().unwrap();
        let cv = d.cv.clone().ok_or_else(|| bad("Upload your CV first."))?;
        let cover = d.cover.clone().ok_or_else(|| bad("Upload your old cover letter first (it is the style template)."))?;
        let j = d.jobs.iter().find(|j| j.id == id).cloned().ok_or_else(|| bad("no such job"))?;
        (cv, cover, j)
    };
    let analysis = job.analysis.clone().ok_or_else(|| bad("Analyze the job first."))?;
    // 1) CV: apply approved edits deterministically - nothing outside the approved passages can change
    let mut cv_html = cv.html.clone();
    let mut applied_notes = vec![];
    for s in analysis["suggestions"].as_array().cloned().unwrap_or_default() {
        let sid = s["id"].as_u64().unwrap_or(u64::MAX) as usize;
        if !accepted.contains(&sid) { continue; }
        if let (Some(o), Some(p)) = (s["original"].as_str(), s["proposed"].as_str()) {
            if cv_html.contains(o) {
                cv_html = cv_html.replacen(o, &esc(p), 1);
                applied_notes.push(format!("- \"{}\" -> \"{}\"", strip_tags(o), p));
            }
        }
    }
    // 2) cover letter in the voice/format of the old one
    let sys = format!("You write cover letters. Produce a NEW cover letter for the target job that follows the format, structure, paragraph count, tone, signature, phrasing habits and sentence rhythm of the candidate's PREVIOUS cover letter as closely as possible, adapting only what must change (company, role, date/address lines, and the emphasis of which strengths are highlighted for this job).\n{NO_INVENT}\nEvery achievement or skill mentioned must be traceable to the CV or the previous letter. If the JD asks for something the CV does not show, simply do not mention it. Output only an HTML fragment (p, strong, br) with no scripts or CSS.");
    let user = format!("=== PREVIOUS COVER LETTER (style template) ===\n{}\n\n=== CANDIDATE CV (the only source of facts) ===\n{}\n\n=== TARGET JOB ===\nTitle: {}\nCompany: {}\n\n{}\n\n=== Approved CV emphasis changes (for consistency) ===\n{}",
        cover.html, cv_html, job.title, job.company, job.jd, applied_notes.join("\n"));
    let cover_html = sanitize_html(&llm(st, &sys, &user).await?);
    // 3) fact guard
    let allowed: HashSet<String> = digit_runs(&format!("{} {} {}", cv.text, cover.text, job.company));
    let mut warnings = vec![];
    let extra: Vec<String> = digit_runs(&strip_tags(&cover_html)).difference(&allowed).cloned().collect();
    if !extra.is_empty() {
        warnings.push(format!("Cover letter contains numbers not found in your CV/old letter: {} - verify or remove.", extra.join(", ")));
    }
    st.with(|d| if let Some(j) = d.jobs.iter_mut().find(|j| j.id == id) {
        j.cv_html = Some(cv_html); j.cover_html = Some(cover_html); j.warnings = warnings; j.auto = auto;
        if j.status == "new" || j.status == "saved" { j.status = "ready".into(); }
    });
    Ok(())
}

// ───────────────────────── discovery + autopilot ─────────────────────────

struct Found { title: String, company: String, url: String, location: String, source: &'static str, desc: String }

async fn fetch_remotive(st: &S, q: &str) -> Vec<Found> {
    let url = format!("https://remotive.com/api/remote-jobs?limit=60&search={}", urlenc(q));
    let Ok(r) = st.http.get(url).send().await else { return vec![] };
    let v: Value = r.json().await.unwrap_or(Value::Null);
    v["jobs"].as_array().cloned().unwrap_or_default().iter().map(|j| Found {
        title: j["title"].as_str().unwrap_or("").into(), company: j["company_name"].as_str().unwrap_or("").into(),
        url: j["url"].as_str().unwrap_or("").into(), location: format!("Remote - {}", j["candidate_required_location"].as_str().unwrap_or("")),
        source: "remotive", desc: strip_tags(j["description"].as_str().unwrap_or("")),
    }).collect()
}
async fn fetch_arbeitnow(st: &S, q: &str) -> Vec<Found> {
    let Ok(r) = st.http.get("https://www.arbeitnow.com/api/job-board-api").send().await else { return vec![] };
    let v: Value = r.json().await.unwrap_or(Value::Null);
    let words: Vec<String> = q.to_lowercase().split_whitespace().map(String::from).collect();
    v["data"].as_array().cloned().unwrap_or_default().iter().filter_map(|j| {
        let title = j["title"].as_str().unwrap_or("");
        let desc = strip_tags(j["description"].as_str().unwrap_or(""));
        let hay = format!("{} {}", title, desc).to_lowercase();
        if !words.is_empty() && !words.iter().any(|w| hay.contains(w)) { return None; }
        Some(Found { title: title.into(), company: j["company_name"].as_str().unwrap_or("").into(),
            url: j["url"].as_str().unwrap_or("").into(), location: j["location"].as_str().unwrap_or("").into(),
            source: "arbeitnow", desc })
    }).collect()
}
fn urlenc(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() { (b as char).to_string() } else { format!("%{:02X}", b) }).collect()
}

async fn discover(st: &S, q: &str) -> usize {
    let (a, b) = tokio::join!(fetch_remotive(st, q), fetch_arbeitnow(st, q));
    let mut added = 0;
    st.with(|d| {
        for f in a.into_iter().chain(b) {
            if f.url.is_empty() || d.jobs.iter().any(|j| j.url == f.url) || f.desc.len() < 80 { continue; }
            d.jobs.push(new_job(&f.title, &f.company, &f.url, &f.location, f.source, &f.desc));
            added += 1;
        }
    });
    added
}

async fn score_pending(st: &S) {
    let (ids, auto, thr) = {
        let d = st.db.lock().unwrap();
        (d.jobs.iter().filter(|j| j.analysis.is_none() && !j.busy && j.status == "new").map(|j| j.id.clone()).collect::<Vec<_>>(),
         d.settings.auto_prepare, d.settings.auto_threshold)
    };
    let sem = Arc::new(tokio::sync::Semaphore::new(4));
    let mut hs = vec![];
    for id in ids {
        let (st, sem) = (st.clone(), sem.clone());
        hs.push(tokio::spawn(async move {
            let _p = sem.acquire().await;
            if analyze_job(&st, &id).await.is_ok() && auto {
                let (score, n) = { let d = st.db.lock().unwrap(); d.jobs.iter().find(|j| j.id == id).map(|j| (j.score.unwrap_or(0), j.analysis.as_ref().map(|a| a["suggestions"].as_array().map_or(0, |x| x.len())).unwrap_or(0))).unwrap_or((0, 0)) };
                if score >= thr {
                    set_busy(&st, &id, true, None);
                    let all: Vec<usize> = (0..n).collect();
                    let r = generate_job(&st, &id, &all, true).await;
                    set_busy(&st, &id, false, r.err().map(|e| e.1));
                }
            }
        }));
    }
    for h in hs { let _ = h.await; }
}

#[derive(Deserialize)]
struct AutoBody { query: Option<String> }
async fn autopilot(State(st): State<S>, Json(b): Json<AutoBody>) -> R<Json<Value>> {
    {
        let d = st.db.lock().unwrap();
        if d.cv.is_none() { return Err(bad("Upload your CV first.")); }
    }
    let q = b.query.unwrap_or_default();
    if !q.is_empty() { st.with(|d| d.settings.default_query = q.clone()); }
    let st2 = st.clone();
    tokio::spawn(async move { discover(&st2, &q).await; score_pending(&st2).await; });
    Ok(Json(json!({"started": true})))
}
async fn score_all_route(State(st): State<S>) -> Json<Value> {
    let st2 = st.clone();
    tokio::spawn(async move { score_pending(&st2).await });
    Json(json!({"started": true}))
}

// ───────────────────────── main ─────────────────────────

async fn index() -> Html<&'static str> { Html(APP_HTML) }

#[tokio::main]
async fn main() {
    let dir = std::path::PathBuf::from(std::env::var("JOBPILOT_DATA").unwrap_or_else(|_| "data".into()));
    std::fs::create_dir_all(&dir).ok();
    let path = dir.join("db.json");
    let mut db: Db = std::fs::read_to_string(&path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
    for j in &mut db.jobs { j.busy = false; }
    let st: S = Arc::new(St {
        db: Mutex::new(db),
        http: reqwest::Client::builder().timeout(std::time::Duration::from_secs(180)).user_agent("JobPilot/0.1").build().unwrap(),
        path,
    });
    let app = Router::new()
        .route("/", get(index))
        .route("/api/health", get(health))
        .route("/api/state", get(get_state))
        .route("/api/settings", put(put_settings))
        .route("/api/docs/:kind", post(upload_doc))
        .route("/api/docs/:kind/html", put(put_doc_html))
        .route("/doc/base/:kind", get(view_base))
        .route("/doc/job/:id/:kind", get(view_job))
        .route("/api/export/base/:kind", post(export_base))
        .route("/api/export/job/:id/:kind", post(export_job))
        .route("/api/jobs", post(create_job))
        .route("/api/jobs/:id", get(get_job).patch(patch_job).delete(delete_job))
        .route("/api/jobs/:id/analyze", post(analyze_route))
        .route("/api/jobs/:id/generate", post(generate_route))
        .route("/api/autopilot", post(autopilot))
        .route("/api/score-all", post(score_all_route))
        .layer(DefaultBodyLimit::max(25 * 1024 * 1024))
        .with_state(st);
    let l = tokio::net::TcpListener::bind(("127.0.0.1", PORT)).await.expect("port 3100 busy?");
    println!("JobPilot running at http://localhost:{PORT}");
    axum::serve(l, app).await.unwrap();
}
