# zig-docs-mcp

An MCP server that gives LLMs searchable access to Zig documentation — the
language reference, standard library API (parsed from source), and learning
guides.

On first use for a given Zig version, the server fetches documentation from
ziglang.org and builds an in-memory full-text index (Tantivy). Fetched sources
are cached to `~/.cache/zig-docs-mcp/`. A bundled migration guide covering Zig
0.13→0.15 changes is included in the server's instructions, so the LLM has
up-to-date language knowledge before it makes any tool calls.

## Tools

- **search_zig_docs** — Full-text search across all doc sources. Returns the
  top 10 results ranked by relevance. Filterable by source (`langref`,
  `stdlib`, `guide`) and Zig version.
- **get_doc** — Retrieve complete documentation for a symbol by its dotted path
  (e.g. `std.mem.Allocator`). Case-insensitive fallback for when LLMs get
  casing wrong.
- **list_children** — Browse the direct children of a module or type. Shows
  member counts so you know where to drill deeper.

## Build

```
cargo build --release
```

## Usage

Configure as an MCP server in your client. For Claude Code (`~/.claude/settings.json`):

```json
{
  "mcpServers": {
    "zig-docs": {
      "command": "/path/to/zig-docs-mcp"
    }
  }
}
```

The server communicates over stdio.

## License

ISC
