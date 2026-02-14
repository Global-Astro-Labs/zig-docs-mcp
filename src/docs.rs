use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Read};
use std::path::PathBuf;

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

struct VersionIndex {
    tantivy: Index,
    entries: Vec<DocEntry>,
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
                        summary: doc.map(|d| first_line(&d.body)).unwrap_or_default(),
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
                                summary: first_line(&entry.body),
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

    async fn ensure_index(&self, version: &str) -> Result<()> {
        {
            let indexes = self.indexes.lock().await;
            if indexes.contains_key(version) {
                return Ok(());
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
            Ok(entries) => {
                tracing::info!(count = entries.len(), "Parsed stdlib entries");
                all_entries.extend(entries);
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
    ) -> Result<Vec<DocEntry>> {
        let tar_path = self.cache_dir.join(version).join("sources.tar");
        let tar_bytes = if tar_path.exists() {
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

        if path.exists() {
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

fn first_line(text: &str) -> String {
    let line = text.lines().next().unwrap_or("");
    if line.len() > 150 {
        format!("{}...", &line[..147])
    } else {
        line.to_string()
    }
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

fn parse_stdlib_tar(tar_bytes: &[u8], version: &str) -> Result<Vec<DocEntry>> {
    let mut archive = tar::Archive::new(Cursor::new(tar_bytes));
    let mut entries = Vec::new();

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

        entries.extend(parse_zig_doc_comments(&content, &module_path, version));
    }

    Ok(entries)
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
                    let body = if doc_text.is_empty() {
                        line.to_string()
                    } else {
                        format!("{}\n\n{}", doc_text, line)
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
