use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Read};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result};
use tantivy::collector::{Count, TopDocs};
use tantivy::query::{BooleanQuery, QueryParser, TermQuery};
use tantivy::schema::{self, IndexRecordOption, Schema, Value, STORED, STRING, TEXT};
use tantivy::query::Occur;
use tantivy::{doc, Index, SnippetGenerator, TantivyDocument, Term};
use tokio::sync::Mutex;

#[derive(Clone)]
struct DocEntry {
    source: String,
    title: String,
    breadcrumb: String,
    body: String,
    url: String,
}

pub struct SearchResult {
    pub source: String,
    pub title: String,
    pub breadcrumb: String,
    pub url: String,
    pub snippet: String,
}

pub struct DocDetail {
    pub source: String,
    pub title: String,
    pub breadcrumb: String,
    pub url: String,
    pub body: String,
}

pub struct ChildEntry {
    pub name: String,
    pub source: String,
    pub summary: String,
    pub child_count: usize,
}

const VOLATILE_CACHE_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

struct VersionIndex {
    tantivy: Index,
    entries: Vec<DocEntry>,
    sources: HashMap<String, String>,
    built_at: Instant,
}

pub struct DocIndex {
    cache_dir: PathBuf,
    indexes: Mutex<HashMap<String, VersionIndex>>,
    schema: Schema,
    title_field: schema::Field,
    body_field: schema::Field,
    source_field: schema::Field,
    url_field: schema::Field,
    breadcrumb_field: schema::Field,
}

impl DocIndex {
    pub fn new() -> Self {
        let cache_dir = std::env::var("HOME")
            .map(|h| PathBuf::from(h).join(".cache").join("zig-docs-mcp"))
            .unwrap_or_else(|_| PathBuf::from("/tmp/zig-docs-mcp"));

        let mut builder = Schema::builder();
        let title_field = builder.add_text_field("title", TEXT | STORED);
        let body_field = builder.add_text_field("body", TEXT | STORED);
        let source_field = builder.add_text_field("source", STRING | STORED);
        let url_field = builder.add_text_field("url", STRING | STORED);
        let breadcrumb_field = builder.add_text_field("breadcrumb", STRING | STORED);
        let schema = builder.build();

        DocIndex {
            cache_dir,
            indexes: Mutex::new(HashMap::new()),
            schema,
            title_field,
            body_field,
            source_field,
            url_field,
            breadcrumb_field,
        }
    }

    pub async fn search(
        &self,
        query: &str,
        version: &str,
        source_filter: Option<&str>,
    ) -> Result<(Vec<SearchResult>, usize)> {
        self.ensure_index(version).await?;

        let indexes = self.indexes.lock().await;
        let vi = indexes.get(version).context("Index not found")?;

        let reader = vi.tantivy.reader()?;
        let searcher = reader.searcher();

        let mut query_parser =
            QueryParser::for_index(&vi.tantivy, vec![self.title_field, self.body_field]);
        query_parser.set_field_boost(self.title_field, 2.0);

        let text_query = query_parser.parse_query(query)?;

        let search_query: Box<dyn tantivy::query::Query> = if let Some(source) = source_filter {
            Box::new(BooleanQuery::new(vec![
                (Occur::Must, text_query),
                (
                    Occur::Must,
                    Box::new(TermQuery::new(
                        Term::from_field_text(self.source_field, source),
                        IndexRecordOption::Basic,
                    )),
                ),
            ]))
        } else {
            text_query
        };

        let (top_docs, total) =
            searcher.search(&search_query, &(TopDocs::with_limit(10), Count))?;

        let snippet_gen =
            SnippetGenerator::create(&searcher, search_query.as_ref(), self.body_field)?;

        let mut results = Vec::new();
        for (_score, doc_address) in top_docs {
            let retrieved: TantivyDocument = searcher.doc(doc_address)?;

            let title = field_text(&retrieved, self.title_field);
            let source = field_text(&retrieved, self.source_field);
            let url = field_text(&retrieved, self.url_field);
            let breadcrumb = field_text(&retrieved, self.breadcrumb_field);

            let snippet = snippet_gen.snippet_from_doc(&retrieved);
            let snippet_html = snippet.to_html();
            let snippet_text = snippet_html.replace("<b>", "**").replace("</b>", "**");

            results.push(SearchResult {
                source,
                title,
                breadcrumb,
                url,
                snippet: snippet_text,
            });
        }

        Ok((results, total))
    }

    pub async fn get_doc(&self, path: &str, version: &str) -> Result<Vec<DocDetail>> {
        self.ensure_index(version).await?;

        let indexes = self.indexes.lock().await;
        let vi = indexes.get(version).context("Index not found")?;

        let mut results: Vec<DocDetail> = vi
            .entries
            .iter()
            .filter(|e| e.title == path)
            .map(|e| DocDetail {
                source: e.source.clone(),
                title: e.title.clone(),
                breadcrumb: e.breadcrumb.clone(),
                url: e.url.clone(),
                body: e.body.clone(),
            })
            .collect();

        // Case-insensitive fallback — Zig paths are case-sensitive but LLMs
        // may get the casing wrong after reading search results.
        if results.is_empty() {
            let path_lower = path.to_lowercase();
            results = vi
                .entries
                .iter()
                .filter(|e| e.title.to_lowercase() == path_lower)
                .map(|e| DocDetail {
                    source: e.source.clone(),
                    title: e.title.clone(),
                    breadcrumb: e.breadcrumb.clone(),
                    url: e.url.clone(),
                    body: e.body.clone(),
                })
                .collect();
        }

        Ok(results)
    }

    pub async fn list_children(&self, parent: &str, version: &str) -> Result<Vec<ChildEntry>> {
        self.ensure_index(version).await?;

        let indexes = self.indexes.lock().await;
        let vi = indexes.get(version).context("Index not found")?;

        let prefix = format!("{}.", parent);
        let mut children = Vec::new();
        let mut seen = HashSet::new();

        // Strategy 1: dotted path prefix (stdlib)
        for entry in &vi.entries {
            if let Some(rest) = entry.title.strip_prefix(&prefix) {
                let direct_name = rest.split('.').next().unwrap_or(rest);
                if direct_name.is_empty() {
                    continue;
                }
                let child_path = format!("{}.{}", parent, direct_name);

                if seen.insert(child_path.clone()) {
                    let sub_prefix = format!("{}.", child_path);
                    let child_count = vi
                        .entries
                        .iter()
                        .filter(|e| e.title.starts_with(&sub_prefix))
                        .count();

                    let doc = vi.entries.iter().find(|e| e.title == child_path);

                    children.push(ChildEntry {
                        name: direct_name.to_string(),
                        source: doc
                            .map(|d| d.source.clone())
                            .unwrap_or_else(|| entry.source.clone()),
                        summary: doc.map(|d| summary_line(&d.body)).unwrap_or_default(),
                        child_count,
                    });
                }
            }
        }

        // Strategy 2: breadcrumb hierarchy (langref/guides)
        if children.is_empty() {
            let bc_prefix = format!("{} > ", parent);
            for entry in &vi.entries {
                if let Some(rest) = entry.breadcrumb.strip_prefix(&bc_prefix) {
                    if !rest.contains(" > ") {
                        if seen.insert(entry.title.clone()) {
                            let child_bc_prefix = format!("{} > ", entry.breadcrumb);
                            let child_count = vi
                                .entries
                                .iter()
                                .filter(|e| e.breadcrumb.starts_with(&child_bc_prefix))
                                .count();

                            children.push(ChildEntry {
                                name: entry.title.clone(),
                                source: entry.source.clone(),
                                summary: summary_line(&entry.body),
                                child_count,
                            });
                        }
                    }
                }
            }
        }

        children.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(children)
    }

    pub async fn get_source(&self, path: &str, version: &str) -> Result<Option<(String, String)>> {
        self.ensure_index(version).await?;

        let indexes = self.indexes.lock().await;
        let vi = indexes.get(version).context("Index not found")?;

        // Exact file match — return whole module
        if let Some(source) = vi.sources.get(path) {
            return Ok(Some((path.to_string(), source.clone())));
        }

        // Strip components to find the containing module file, then try
        // to extract just the requested declaration from it.
        let mut module_path = path.to_string();
        loop {
            match module_path.rsplit_once('.') {
                Some((parent, _)) if parent.contains('.') => {
                    module_path = parent.to_string();
                    if let Some(source) = vi.sources.get(&module_path) {
                        let remainder = &path[module_path.len() + 1..];
                        if let Some(decl_source) = extract_declaration(source, remainder) {
                            return Ok(Some((path.to_string(), decl_source)));
                        }
                        // Couldn't isolate the declaration — return whole file
                        return Ok(Some((module_path, source.clone())));
                    }
                }
                _ => return Ok(None),
            }
        }
    }

    async fn ensure_index(&self, version: &str) -> Result<()> {
        {
            let indexes = self.indexes.lock().await;
            if let Some(vi) = indexes.get(version) {
                if is_release_version(version) || vi.built_at.elapsed() < VOLATILE_CACHE_TTL {
                    return Ok(());
                }
                tracing::info!("In-memory index expired for version {}", version);
            }
        }

        let vi = self.build_index(version).await?;

        let mut indexes = self.indexes.lock().await;
        indexes.insert(version.to_string(), vi);
        Ok(())
    }

    async fn build_index(&self, version: &str) -> Result<VersionIndex> {
        let client = reqwest::Client::builder()
            .user_agent("zig-docs-mcp/0.1.0")
            .build()?;

        let mut all_entries = Vec::new();
        let mut stdlib_sources = HashMap::new();

        let (langref, stdlib, guides) = tokio::join!(
            self.fetch_and_parse_langref(&client, version),
            self.fetch_and_parse_stdlib(&client, version),
            self.fetch_and_parse_guides(&client),
        );

        match langref {
            Ok(entries) => {
                tracing::info!(count = entries.len(), "Parsed langref entries");
                all_entries.extend(entries);
            }
            Err(e) => tracing::warn!("Failed to fetch langref: {}", e),
        }
        match stdlib {
            Ok((entries, sources)) => {
                tracing::info!(count = entries.len(), "Parsed stdlib entries");
                all_entries.extend(entries);
                stdlib_sources = sources;
            }
            Err(e) => tracing::warn!("Failed to fetch stdlib: {}", e),
        }
        match guides {
            Ok(entries) => {
                tracing::info!(count = entries.len(), "Parsed guide entries");
                all_entries.extend(entries);
            }
            Err(e) => tracing::warn!("Failed to fetch guides: {}", e),
        }

        tracing::info!(
            total = all_entries.len(),
            "Building tantivy index for version {}",
            version
        );

        let index = Index::create_in_ram(self.schema.clone());
        let mut writer = index.writer(50_000_000)?;

        for entry in &all_entries {
            writer.add_document(doc!(
                self.title_field => entry.title.as_str(),
                self.body_field => entry.body.as_str(),
                self.source_field => entry.source.as_str(),
                self.url_field => entry.url.as_str(),
                self.breadcrumb_field => entry.breadcrumb.as_str(),
            ))?;
        }

        writer.commit()?;
        Ok(VersionIndex {
            tantivy: index,
            entries: all_entries,
            sources: stdlib_sources,
            built_at: Instant::now(),
        })
    }

    async fn fetch_and_parse_langref(
        &self,
        client: &reqwest::Client,
        version: &str,
    ) -> Result<Vec<DocEntry>> {
        let url = format!("https://ziglang.org/documentation/{}/", version);
        let html = self.fetch_cached(client, version, "langref.html", &url).await?;
        Ok(parse_langref_html(&html, version))
    }

    async fn fetch_and_parse_stdlib(
        &self,
        client: &reqwest::Client,
        version: &str,
    ) -> Result<(Vec<DocEntry>, HashMap<String, String>)> {
        let tar_path = self.cache_dir.join(version).join("sources.tar");
        let tar_bytes = if tar_path.exists() && (is_release_version(version) || is_cache_fresh(&tar_path)) {
            tokio::fs::read(&tar_path).await?
        } else {
            let url = format!(
                "https://ziglang.org/documentation/{}/std/sources.tar",
                version
            );
            tracing::info!("Downloading stdlib sources from {}", url);
            let bytes = client.get(&url).send().await?.error_for_status()?.bytes().await?;

            if let Some(parent) = tar_path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            tokio::fs::write(&tar_path, &bytes).await?;
            bytes.to_vec()
        };

        let version = version.to_string();
        tokio::task::spawn_blocking(move || parse_stdlib_tar(&tar_bytes, &version))
            .await
            .context("stdlib parse task panicked")?
    }

    async fn fetch_and_parse_guides(&self, client: &reqwest::Client) -> Result<Vec<DocEntry>> {
        const GUIDE_PAGES: &[&str] =
            &["overview", "getting-started", "build-system", "tools", "samples"];

        let mut entries = Vec::new();
        for page in GUIDE_PAGES {
            let url = format!("https://ziglang.org/learn/{}/", page);
            match client.get(&url).send().await {
                Ok(resp) => match resp.text().await {
                    Ok(html) => entries.extend(parse_guide_html(&html, page)),
                    Err(e) => tracing::warn!("Failed to read guide {}: {}", page, e),
                },
                Err(e) => tracing::warn!("Failed to fetch guide {}: {}", page, e),
            }
        }
        Ok(entries)
    }

    async fn fetch_cached(
        &self,
        client: &reqwest::Client,
        version: &str,
        filename: &str,
        url: &str,
    ) -> Result<String> {
        let path = self.cache_dir.join(version).join(filename);

        if path.exists() && (is_release_version(version) || is_cache_fresh(&path)) {
            tracing::info!("Using cached {}", path.display());
            return Ok(tokio::fs::read_to_string(&path).await?);
        }

        tracing::info!("Downloading {}", url);
        let text = client.get(url).send().await?.error_for_status()?.text().await?;

        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(&path, &text).await?;
        Ok(text)
    }
}

fn field_text(doc: &TantivyDocument, field: schema::Field) -> String {
    doc.get_first(field)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn summary_line(text: &str) -> String {
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed == "Fields:" {
            continue;
        }
        if trimmed.len() > 150 {
            return format!("{}...", &trimmed[..147]);
        }
        return trimmed.to_string();
    }
    String::new()
}

fn is_release_version(version: &str) -> bool {
    version.chars().next().map_or(false, |c| c.is_ascii_digit())
}

fn is_cache_fresh(path: &std::path::Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else { return false };
    let Ok(modified) = meta.modified() else { return false };
    SystemTime::now()
        .duration_since(modified)
        .map_or(false, |age| age < VOLATILE_CACHE_TTL)
}

// --- Langref parsing ---

fn parse_langref_html(html: &str, version: &str) -> Vec<DocEntry> {
    let open_re =
        regex::Regex::new(r#"<(h[2-5])\s[^>]*?id=["']([^"']*)["'][^>]*>"#).unwrap();

    struct HeadingMatch {
        level: u8,
        id: String,
        title: String,
        full_start: usize,
        heading_end: usize,
    }

    let mut headings = Vec::new();
    for cap in open_re.captures_iter(html) {
        let open_match = cap.get(0).unwrap();
        let tag = &cap[1];
        let id = cap[2].to_string();
        let level = tag.as_bytes()[1] - b'0';

        let close_tag = format!("</{}>", tag);
        let after_open = open_match.end();
        let (title, heading_end) = if let Some(close_pos) = html[after_open..].find(&close_tag) {
            let title_html = &html[after_open..after_open + close_pos];
            let doc = scraper::Html::parse_fragment(title_html);
            let title = doc.root_element().text().collect::<String>().trim().to_string();
            (title, after_open + close_pos + close_tag.len())
        } else {
            (String::new(), after_open)
        };

        headings.push(HeadingMatch {
            level,
            id,
            title,
            full_start: open_match.start(),
            heading_end,
        });
    }

    let mut entries = Vec::new();
    let mut heading_stack: Vec<(u8, String)> = Vec::new();

    for (i, h) in headings.iter().enumerate() {
        let body_end = if i + 1 < headings.len() {
            headings[i + 1].full_start
        } else {
            html.len()
        };

        let body_html = &html[h.heading_end..body_end];
        let body_doc = scraper::Html::parse_fragment(body_html);
        let body_text = normalize_whitespace(&body_doc.root_element().text().collect::<String>());

        while heading_stack.last().map_or(false, |(l, _)| *l >= h.level) {
            heading_stack.pop();
        }
        heading_stack.push((h.level, h.title.clone()));

        let breadcrumb = heading_stack
            .iter()
            .map(|(_, t)| t.as_str())
            .collect::<Vec<_>>()
            .join(" > ");

        if h.title.is_empty() && body_text.is_empty() {
            continue;
        }

        entries.push(DocEntry {
            source: "langref".to_string(),
            title: h.title.clone(),
            breadcrumb,
            body: body_text,
            url: format!("https://ziglang.org/documentation/{}/#{}", version, h.id),
        });
    }

    entries
}

// --- Stdlib parsing ---

fn parse_stdlib_tar(tar_bytes: &[u8], version: &str) -> Result<(Vec<DocEntry>, HashMap<String, String>)> {
    let mut archive = tar::Archive::new(Cursor::new(tar_bytes));
    let mut entries = Vec::new();
    let mut sources = HashMap::new();

    for tar_entry in archive.entries()? {
        let mut tar_entry = tar_entry?;
        let path = tar_entry.path()?.to_path_buf();

        if path.extension().map_or(true, |ext| ext != "zig") {
            continue;
        }

        let mut content = String::new();
        if tar_entry.read_to_string(&mut content).is_err() {
            continue;
        }

        // "std/mem.zig" -> "std.mem", "std/std.zig" -> "std"
        let raw = path.with_extension("").to_string_lossy().replace(['/', '\\'], ".");
        let parts: Vec<&str> = raw.split('.').collect();
        let module_path = if parts.len() >= 2 && parts.last() == parts.get(parts.len() - 2) {
            parts[..parts.len() - 1].join(".")
        } else {
            raw
        };

        sources.insert(module_path.clone(), content.clone());
        entries.extend(parse_zig_doc_comments(&content, &module_path, version));
    }

    Ok((entries, sources))
}

fn parse_zig_doc_comments(source: &str, module_path: &str, version: &str) -> Vec<DocEntry> {
    let mut entries = Vec::new();
    let lines: Vec<&str> = source.lines().collect();

    // --- Module-level documentation ---

    // Collect //! doc comments from the top of the file (before any declarations)
    let mut module_doc_lines: Vec<&str> = Vec::new();
    for line in &lines {
        let trimmed = line.trim();
        if trimmed.starts_with("//!") {
            let comment = trimmed.strip_prefix("//!").unwrap_or("");
            let comment = comment.strip_prefix(' ').unwrap_or(comment);
            module_doc_lines.push(comment);
        } else if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        } else {
            break;
        }
    }

    // Detect @This() struct module pattern (e.g., `const Writer = @This();`)
    let is_struct_module = lines.iter().take(10).any(|line| {
        let trimmed = line.trim();
        trimmed.starts_with("const ") && trimmed.contains("= @This()")
    });

    if !module_doc_lines.is_empty() || is_struct_module {
        let mut body_parts = Vec::new();

        if !module_doc_lines.is_empty() {
            body_parts.push(module_doc_lines.join("\n"));
        }

        if is_struct_module {
            let fields = collect_struct_fields(&lines);
            if !fields.is_empty() {
                body_parts.push(format!("Fields:\n{}", fields.join("\n")));
            }
        }

        let body = body_parts.join("\n\n");
        let parent = module_path.rsplit_once('.').map_or(module_path, |(p, _)| p);

        entries.push(DocEntry {
            source: "stdlib".to_string(),
            title: module_path.to_string(),
            breadcrumb: parent.to_string(),
            body,
            url: format!(
                "https://ziglang.org/documentation/{}/std/#{}",
                version, module_path
            ),
        });
    }

    // --- Per-declaration documentation ---
    let mut i = 0;

    while i < lines.len() {
        if !lines[i].trim().starts_with("///") {
            i += 1;
            continue;
        }

        let mut doc_lines = Vec::new();
        while i < lines.len() && lines[i].trim().starts_with("///") {
            let comment = lines[i].trim().strip_prefix("///").unwrap_or("");
            let comment = comment.strip_prefix(' ').unwrap_or(comment);
            doc_lines.push(comment);
            i += 1;
        }

        while i < lines.len() && lines[i].trim().is_empty() {
            i += 1;
        }

        if i < lines.len() {
            let line = lines[i].trim();
            if line.starts_with("pub ") {
                let name = extract_decl_name(line);
                if !name.is_empty() {
                    let doc_text = doc_lines.join("\n");
                    let title = format!("{}.{}", module_path, name);
                    let declaration = collect_declaration(&lines, i);
                    let body = if doc_text.is_empty() {
                        declaration
                    } else {
                        format!("{}\n\n{}", doc_text, declaration)
                    };

                    entries.push(DocEntry {
                        source: "stdlib".to_string(),
                        title: title.clone(),
                        breadcrumb: module_path.to_string(),
                        body,
                        url: format!(
                            "https://ziglang.org/documentation/{}/std/#{}",
                            version, title
                        ),
                    });
                }
            }
        }

        i += 1;
    }

    entries
}

fn extract_decl_name(line: &str) -> String {
    let rest = line.strip_prefix("pub ").unwrap_or(line);

    let rest = if let Some(r) = rest.strip_prefix("fn ") {
        r
    } else if let Some(r) = rest.strip_prefix("const ") {
        r
    } else if let Some(r) = rest.strip_prefix("var ") {
        r
    } else if rest.starts_with("usingnamespace ") {
        return "usingnamespace".to_string();
    } else {
        rest
    };

    rest.chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '@')
        .collect()
}

/// Extract struct field declarations from a @This() module.
/// Looks for top-level (unindented) lines matching `identifier: Type`.
fn collect_struct_fields(lines: &[&str]) -> Vec<String> {
    let mut fields = Vec::new();
    for line in lines {
        // Only top-level lines (struct fields have no indentation)
        if line.starts_with(' ') || line.starts_with('\t') {
            continue;
        }
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with("//")
            || trimmed.starts_with("pub ")
            || trimmed.starts_with("const ")
            || trimmed.starts_with("var ")
            || trimmed.starts_with("fn ")
            || trimmed.starts_with('}')
            || trimmed.starts_with('{')
            || trimmed.starts_with("test ")
            || trimmed.starts_with("comptime ")
            || trimmed.starts_with("usingnamespace ")
            || trimmed.starts_with("@")
        {
            continue;
        }
        let first_char = trimmed.chars().next().unwrap_or(' ');
        if (first_char.is_alphabetic() || first_char == '_') && trimmed.contains(": ") {
            fields.push(trimmed.trim_end_matches(',').to_string());
        }
    }
    fields
}

/// Collect the full declaration starting at `start`, potentially spanning multiple lines.
fn collect_declaration(lines: &[&str], start: usize) -> String {
    let line = lines[start].trim();
    let rest = line.strip_prefix("pub ").unwrap_or(line);

    // Multi-line function signature: collect until '{' or ';'
    let is_fn = rest.starts_with("fn ")
        || rest.starts_with("inline fn ")
        || rest.starts_with("noinline fn ")
        || rest.starts_with("export fn ")
        || (rest.starts_with("extern ") && rest.contains(" fn "));

    if is_fn && !line.contains('{') && !line.contains(';') {
        let mut parts = vec![line.to_string()];
        for j in (start + 1)..lines.len() {
            let next = lines[j].trim();
            if next.is_empty() {
                break;
            }
            if let Some(pos) = next.find('{') {
                let before = next[..pos].trim();
                if !before.is_empty() {
                    parts.push(before.to_string());
                }
                break;
            }
            if next.ends_with(';') {
                parts.push(next.to_string());
                break;
            }
            parts.push(next.to_string());
        }
        return parts.join(" ");
    }

    // Inline struct/enum/union: summarize fields and pub declarations
    if line.contains("= struct {")
        || line.contains("= enum {")
        || line.contains("= enum(")
        || line.contains("= union(")
        || line.contains("= union {")
    {
        let mut depth: i32 = line.chars().filter(|&c| c == '{').count() as i32
            - line.chars().filter(|&c| c == '}').count() as i32;

        if depth <= 0 {
            return line.to_string();
        }

        let mut fields = Vec::new();
        let mut decls = Vec::new();
        let cap = 30;
        let mut j = start + 1;

        while j < lines.len() && depth > 0 {
            let next = lines[j].trim();
            let prev_depth = depth;

            depth += next.chars().filter(|&c| c == '{').count() as i32;
            depth -= next.chars().filter(|&c| c == '}').count() as i32;

            if depth <= 0 {
                break;
            }

            if prev_depth == 1 && fields.len() + decls.len() < cap {
                if next.starts_with("pub ") {
                    let name = extract_decl_name(next);
                    if !name.is_empty() {
                        let kind = if next.contains(" fn ") {
                            "fn"
                        } else if next.contains(" const ") {
                            "const"
                        } else if next.contains(" var ") {
                            "var"
                        } else {
                            ""
                        };
                        if kind.is_empty() {
                            decls.push(format!("    pub {}", name));
                        } else {
                            decls.push(format!("    pub {} {}", kind, name));
                        }
                    }
                } else if !next.is_empty()
                    && !next.starts_with("//")
                    && !next.starts_with('}')
                    && !next.starts_with('{')
                    && !next.starts_with("comptime")
                {
                    let first_char = next.chars().next().unwrap_or(' ');
                    if (first_char.is_alphabetic() || first_char == '_') && next.contains(": ") {
                        fields.push(format!("    {}", next.trim_end_matches(',')));
                    }
                }
            }

            j += 1;
        }

        if fields.is_empty() && decls.is_empty() {
            return line.to_string();
        }

        let mut result = vec![line.to_string()];
        result.extend(fields);
        result.extend(decls);
        result.push("}".to_string());
        return result.join("\n");
    }

    line.to_string()
}

/// Extract a specific declaration from source code by dotted name path.
/// E.g., "init" extracts `pub fn init`, "InitOptions.timeout" drills into
/// the InitOptions struct and extracts the timeout field.
fn extract_declaration(source: &str, path: &str) -> Option<String> {
    let parts: Vec<&str> = path.split('.').collect();
    let lines: Vec<&str> = source.lines().collect();
    extract_decl_from_lines(&lines, &parts)
}

fn extract_decl_from_lines(lines: &[&str], path: &[&str]) -> Option<String> {
    if path.is_empty() {
        return None;
    }
    let name = path[0];
    let mut brace_depth: i32 = 0;
    let mut i = 0;

    while i < lines.len() {
        let trimmed = lines[i].trim();
        let depth_before = brace_depth;

        // Track brace depth so we only match declarations at the current scope
        for ch in trimmed.chars() {
            match ch {
                '{' => brace_depth += 1,
                '}' => brace_depth -= 1,
                _ => {}
            }
        }

        if depth_before == 0 && decl_matches(trimmed, name) {
            // Include preceding /// doc comments
            let mut doc_start = i;
            while doc_start > 0 && lines[doc_start - 1].trim().starts_with("///") {
                doc_start -= 1;
            }

            let decl_end = find_decl_end(lines, i);

            if path.len() == 1 {
                return Some(dedent(&lines[doc_start..=decl_end].join("\n")));
            } else {
                // For nested lookup, extract the body between braces and recurse
                let brace_line = (i..=decl_end).find(|&j| lines[j].contains('{'))?;
                let body = &lines[brace_line + 1..decl_end];
                return extract_decl_from_lines(body, &path[1..]);
            }
        }

        i += 1;
    }

    None
}

/// Check if a source line declares the given name.
fn decl_matches(line: &str, name: &str) -> bool {
    let rest = line.strip_prefix("pub ").unwrap_or(line);

    // Look for fn/const/var keyword and check the identifier after it
    for kw in ["fn ", "const ", "var "] {
        if let Some(pos) = rest.find(kw) {
            let before = rest[..pos].trim();
            if before.is_empty()
                || before == "inline"
                || before == "noinline"
                || before == "export"
                || before.starts_with("extern")
            {
                let after_kw = &rest[pos + kw.len()..];
                let ident: String = after_kw
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '@')
                    .collect();
                if ident == name {
                    return true;
                }
            }
        }
    }

    // Field declarations: `name: Type` or `name: Type,`
    let first_char = name.chars().next().unwrap_or(' ');
    if (first_char.is_alphabetic() || first_char == '_')
        && rest.starts_with(name)
        && rest[name.len()..].starts_with(':')
    {
        return true;
    }

    false
}

/// Find the end line of a declaration starting at `start`, tracking delimiter depth.
fn find_decl_end(lines: &[&str], start: usize) -> usize {
    let mut brace_depth: i32 = 0;
    let mut paren_depth: i32 = 0;
    let mut has_braces = false;

    for j in start..lines.len() {
        for ch in lines[j].chars() {
            match ch {
                '{' => {
                    brace_depth += 1;
                    has_braces = true;
                }
                '}' => brace_depth -= 1,
                '(' => paren_depth += 1,
                ')' => paren_depth -= 1,
                _ => {}
            }
        }

        if has_braces && brace_depth <= 0 {
            return j;
        }

        if !has_braces && paren_depth <= 0 {
            let trimmed = lines[j].trim();
            if trimmed.ends_with(';') || trimmed.ends_with(',') {
                return j;
            }
        }
    }

    lines.len().saturating_sub(1)
}

/// Remove common leading indentation from a block of text.
fn dedent(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let min_indent = lines
        .iter()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.len() - l.trim_start().len())
        .min()
        .unwrap_or(0);

    if min_indent == 0 {
        return text.to_string();
    }

    lines
        .iter()
        .map(|l| {
            if l.len() >= min_indent {
                &l[min_indent..]
            } else {
                l.trim()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// --- Guide parsing ---

fn parse_guide_html(html: &str, page: &str) -> Vec<DocEntry> {
    let open_re =
        regex::Regex::new(r#"<(h[1-5])\s[^>]*?id=["']([^"']*)["'][^>]*>"#).unwrap();

    struct HeadingMatch {
        id: String,
        title: String,
        full_start: usize,
        heading_end: usize,
    }

    let mut headings = Vec::new();
    for cap in open_re.captures_iter(html) {
        let open_match = cap.get(0).unwrap();
        let tag = &cap[1];
        let id = cap[2].to_string();

        let close_tag = format!("</{}>", tag);
        let after_open = open_match.end();
        let (title, heading_end) = if let Some(close_pos) = html[after_open..].find(&close_tag) {
            let title_html = &html[after_open..after_open + close_pos];
            let doc = scraper::Html::parse_fragment(title_html);
            let title = doc.root_element().text().collect::<String>().trim().to_string();
            (title, after_open + close_pos + close_tag.len())
        } else {
            (String::new(), after_open)
        };

        headings.push(HeadingMatch {
            id,
            title,
            full_start: open_match.start(),
            heading_end,
        });
    }

    if headings.is_empty() {
        let doc = scraper::Html::parse_document(html);
        let sel = scraper::Selector::parse("main, article, .content, body").unwrap();
        if let Some(el) = doc.select(&sel).next() {
            let text = normalize_whitespace(&el.text().collect::<String>());
            if !text.is_empty() {
                return vec![DocEntry {
                    source: "guide".to_string(),
                    title: page.to_string(),
                    breadcrumb: format!("Learn > {}", page),
                    body: text,
                    url: format!("https://ziglang.org/learn/{}/", page),
                }];
            }
        }
        return Vec::new();
    }

    let mut entries = Vec::new();

    for (i, h) in headings.iter().enumerate() {
        let body_end = if i + 1 < headings.len() {
            headings[i + 1].full_start
        } else {
            html.len()
        };

        let body_html = &html[h.heading_end..body_end];
        let body_doc = scraper::Html::parse_fragment(body_html);
        let body_text = normalize_whitespace(&body_doc.root_element().text().collect::<String>());

        if h.title.is_empty() && body_text.is_empty() {
            continue;
        }

        entries.push(DocEntry {
            source: "guide".to_string(),
            title: h.title.clone(),
            breadcrumb: format!("Learn > {} > {}", page, h.title),
            body: body_text,
            url: format!("https://ziglang.org/learn/{}/#{}", page, h.id),
        });
    }

    entries
}

fn normalize_whitespace(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}
