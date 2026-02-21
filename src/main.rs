mod docs;

use std::sync::Arc;

use rmcp::{
    ErrorData as McpError, ServerHandler, ServiceExt,
    handler::server::{tool::ToolRouter, wrapper::Parameters},
    model::*,
    schemars, tool, tool_handler, tool_router,
    transport::stdio,
};

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct SearchParams {
    /// Search terms
    query: String,
    /// Zig version (default: "master"). Applies to langref and stdlib; guides are unversioned.
    #[schemars(rename = "version")]
    version: Option<String>,
    /// Filter results by source: "langref", "stdlib", or "guide". Omit to search all sources.
    source: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct GetDocParams {
    /// Full path to the symbol (e.g., "std.Io.Writer" or "std.mem.Allocator")
    path: String,
    /// Zig version (default: "master")
    version: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct ListChildrenParams {
    /// Parent path to list children of (e.g., "std.Io" or "std.mem")
    parent: String,
    /// Zig version (default: "master")
    version: Option<String>,
}

#[derive(Clone)]
struct ZigDocsServer {
    doc_index: Arc<docs::DocIndex>,
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl ZigDocsServer {
    fn new() -> Self {
        Self {
            doc_index: Arc::new(docs::DocIndex::new()),
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        description = "Search Zig programming language documentation. Covers the language reference, standard library API docs, and learning guides. Returns the top 10 results ranked by relevance."
    )]
    async fn search_zig_docs(
        &self,
        Parameters(params): Parameters<SearchParams>,
    ) -> Result<CallToolResult, McpError> {
        let version = params.version.as_deref().unwrap_or("master");

        if let Some(ref source) = params.source {
            if !["langref", "stdlib", "guide"].contains(&source.as_str()) {
                return Ok(CallToolResult::success(vec![Content::text(
                    "Invalid source filter. Use \"langref\", \"stdlib\", or \"guide\".",
                )]));
            }
        }

        match self
            .doc_index
            .search(&params.query, version, params.source.as_deref())
            .await
        {
            Ok((results, total)) => {
                if results.is_empty() {
                    return Ok(CallToolResult::success(vec![Content::text(
                        "No results found.",
                    )]));
                }

                let header = format!("Showing {} of {} results\n\n", results.len(), total);

                let formatted = results
                    .iter()
                    .enumerate()
                    .map(|(i, r)| {
                        format!(
                            "### {}. [{}] {}\n_{}_\n{}\n\n{}",
                            i + 1,
                            r.source,
                            r.title,
                            r.breadcrumb,
                            r.url,
                            r.snippet,
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n\n---\n\n");

                Ok(CallToolResult::success(vec![Content::text(format!(
                    "{}{}",
                    header, formatted
                ))]))
            }
            Err(e) => {
                tracing::error!("Search failed: {}", e);
                Err(McpError::internal_error(
                    format!("Search failed: {}", e),
                    None,
                ))
            }
        }
    }

    #[tool(
        description = "Get the full documentation for a specific Zig symbol by its path. Use after finding a symbol via search to read its complete documentation including doc comments and declaration."
    )]
    async fn get_doc(
        &self,
        Parameters(params): Parameters<GetDocParams>,
    ) -> Result<CallToolResult, McpError> {
        let version = params.version.as_deref().unwrap_or("master");

        match self.doc_index.get_doc(&params.path, version).await {
            Ok(results) => {
                if results.is_empty() {
                    return Ok(CallToolResult::success(vec![Content::text(format!(
                        "No documentation found for \"{}\".\n\n\
                         Tip: paths are case-sensitive (e.g., \"std.Io.Writer\" not \"std.io.writer\"). \
                         Use search_zig_docs to find the correct path.",
                        params.path
                    ))]));
                }

                let formatted = results
                    .iter()
                    .map(|r| {
                        format!(
                            "## {}\n_{} | {}_\n{}\n\n{}",
                            r.title, r.source, r.breadcrumb, r.url, r.body,
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n\n---\n\n");

                Ok(CallToolResult::success(vec![Content::text(formatted)]))
            }
            Err(e) => {
                tracing::error!("get_doc failed: {}", e);
                Err(McpError::internal_error(
                    format!("get_doc failed: {}", e),
                    None,
                ))
            }
        }
    }

    #[tool(
        description = "List the direct children (members, methods, types) of a Zig module or type. Shows each child with a summary and how many sub-children it has, so you know where to drill deeper. Use get_doc on a child for full details."
    )]
    async fn list_children(
        &self,
        Parameters(params): Parameters<ListChildrenParams>,
    ) -> Result<CallToolResult, McpError> {
        let version = params.version.as_deref().unwrap_or("master");

        match self.doc_index.list_children(&params.parent, version).await {
            Ok(children) => {
                if children.is_empty() {
                    return Ok(CallToolResult::success(vec![Content::text(format!(
                        "No children found for \"{}\".\n\n\
                         Tip: use search_zig_docs to find the correct parent path.",
                        params.parent
                    ))]));
                }

                let header = format!(
                    "## Children of {} ({} members)\n\n",
                    params.parent,
                    children.len()
                );

                let items: Vec<String> = children
                    .iter()
                    .map(|c| {
                        let children_note = if c.child_count > 0 {
                            format!(" _({} children)_", c.child_count)
                        } else {
                            String::new()
                        };
                        let summary = if c.summary.is_empty() {
                            String::new()
                        } else {
                            format!(" — {}", c.summary)
                        };
                        format!(
                            "- **{}** [{}]{}{}",
                            c.name, c.source, children_note, summary
                        )
                    })
                    .collect();

                Ok(CallToolResult::success(vec![Content::text(format!(
                    "{}{}",
                    header,
                    items.join("\n")
                ))]))
            }
            Err(e) => {
                tracing::error!("list_children failed: {}", e);
                Err(McpError::internal_error(
                    format!("list_children failed: {}", e),
                    None,
                ))
            }
        }
    }
}

#[tool_handler]
impl ServerHandler for ZigDocsServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                format!(
                    "{}\n\n{}\n{}",
                    "Search and browse Zig documentation: language reference, standard library, and learning guides.",
                    "Use search_zig_docs to find symbols by keyword. \
                     Use get_doc to read the full documentation for a specific symbol. \
                     Use list_children to browse what's inside a module or type.",
                    include_str!("zig.md"),
                )
                    .into(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("zig_docs_mcp=info".parse()?),
        )
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    tracing::info!("Starting Zig Docs MCP server");

    let service = ZigDocsServer::new().serve(stdio()).await.inspect_err(|e| {
        tracing::error!("Failed to start server: {}", e);
    })?;

    service.waiting().await?;
    Ok(())
}
