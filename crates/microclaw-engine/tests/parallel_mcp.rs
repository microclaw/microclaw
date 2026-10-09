use microclaw_engine::mcp::{collect_config_paths, McpConfig, McpManager, McpTrust};
use microclaw_engine::tools::{mcp::McpTool, Tool};
use serde_json::json;

#[test]
fn parallel_fragment_is_optional_and_anonymous() {
    let config: McpConfig =
        serde_json::from_str(include_str!("../../../mcp.parallel.example.json")).unwrap();
    assert!(config.default_protocol_version.is_none());
    assert_eq!(config.mcp_servers.len(), 1);
    let server = &config.mcp_servers["parallel"];
    assert_eq!(server.transport, "streamable_http");
    assert_eq!(server.endpoint, "https://search.parallel.ai/mcp");
    assert_eq!(server.headers.len(), 1);
    assert_eq!(server.headers["User-Agent"], "microclaw");
    assert_eq!(server.trust, McpTrust::Limited);
    assert!(server.env.is_empty());
}

/// Opt-in network smoke test. No Parallel key or LLM credentials are needed.
#[tokio::test]
#[ignore = "calls the public Parallel endpoint; subject to anonymous rate limits"]
async fn parallel_fragment_search_and_fetch() {
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(data.path().join("mcp.d")).unwrap();
    std::fs::write(
        data.path().join("mcp.d/parallel.json"),
        include_str!("../../../mcp.parallel.example.json"),
    )
    .unwrap();
    let manager = McpManager::from_config_paths(&collect_config_paths(data.path()), 60).await;
    let tools: Vec<_> = manager
        .all_tools()
        .into_iter()
        .map(|(server, info)| McpTool::new(server, info))
        .collect();
    let search = tools
        .iter()
        .find(|tool| tool.name() == "mcp_parallel_web_search")
        .expect("Parallel search registered from the fragment");
    let fetch = tools
        .iter()
        .find(|tool| tool.name() == "mcp_parallel_web_fetch")
        .expect("Parallel fetch registered from the fragment");
    let result = search
        .execute(json!({
            "objective": "Find the official Rust programming language website",
            "search_queries": ["Rust programming language official website"]
        }))
        .await;
    assert!(!result.is_error, "{}", result.content);
    println!("Search output: {}", result.content);
    assert!(
        result.content.contains("rust-lang.org"),
        "{}",
        result.content
    );
    let result = fetch
        .execute(json!({
            "urls": ["https://www.rust-lang.org/"],
            "objective": "What is Rust?"
        }))
        .await;
    assert!(!result.is_error, "{}", result.content);
    println!("Fetch output: {}", result.content);
    assert!(result.content.contains("Rust"), "{}", result.content);
}

#[tokio::test]
async fn parallel_fragment_sends_headers_through_native_transport() {
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/mcp", listener.local_addr().unwrap());
    let observed = Arc::new(Mutex::new(Vec::new()));
    let requests = observed.clone();
    let task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let (headers, body) = loop {
                let mut chunk = [0; 4096];
                let count = socket.read(&mut chunk).await.unwrap();
                assert!(count > 0);
                bytes.extend_from_slice(&chunk[..count]);
                if let Some(boundary) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                    let headers = String::from_utf8(bytes[..boundary].to_vec()).unwrap();
                    let length: usize = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse().unwrap())
                        })
                        .unwrap_or(0);
                    if bytes.len() >= boundary + 4 + length {
                        break (
                            headers,
                            serde_json::from_slice::<serde_json::Value>(
                                &bytes[boundary + 4..boundary + 4 + length],
                            )
                            .unwrap(),
                        );
                    }
                }
            };
            requests.lock().unwrap().push((headers, body.clone()));
            let result = match body["method"].as_str().unwrap() {
                "initialize" => {
                    json!({"protocolVersion":"2025-11-05", "capabilities":{"tools":{}}, "serverInfo":{"name":"fixture", "version":"1"}})
                }
                "tools/list" => {
                    json!({"tools":[{"name":"web_search", "inputSchema":{"type":"object"}}, {"name":"web_fetch", "inputSchema":{"type":"object"}}]})
                }
                "tools/call" => {
                    json!({"content":[{"type":"text", "text":"Rust https://www.rust-lang.org/"}], "isError":false})
                }
                "notifications/initialized" => {
                    socket.write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
                    continue;
                }
                other => panic!("Unexpected MCP method: {other}"),
            };
            let payload = json!({"jsonrpc":"2.0", "id":body["id"], "result":result}).to_string();
            let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}", payload.len());
            socket.write_all(response.as_bytes()).await.unwrap();
        }
    });
    let mut config: serde_json::Value =
        serde_json::from_str(include_str!("../../../mcp.parallel.example.json")).unwrap();
    config["mcpServers"]["parallel"]["endpoint"] = json!(endpoint);
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir(data.path().join("mcp.d")).unwrap();
    std::fs::write(data.path().join("mcp.d/parallel.json"), config.to_string()).unwrap();
    let manager = McpManager::from_config_paths(&collect_config_paths(data.path()), 60).await;
    assert_eq!(manager.servers().len(), 1);
    for (server, info) in manager.all_tools() {
        let tool = McpTool::new(server, info);
        let result = tool.execute(json!({"objective":"Rust", "search_queries":["Rust"], "urls":["https://www.rust-lang.org/"]})).await;
        assert!(!result.is_error, "{}", result.content);
        assert!(result.content.contains("rust-lang.org"));
    }
    let observed = observed.lock().unwrap();
    for (headers, _) in observed.iter() {
        assert!(headers.starts_with("POST /mcp HTTP/1.1\r\n"), "{headers}");
        assert!(
            headers
                .lines()
                .any(|line| line.eq_ignore_ascii_case("user-agent: microclaw")),
            "{headers}"
        );
        assert!(!headers.to_ascii_lowercase().contains("authorization:"));
    }
    for method in ["initialize", "tools/list", "tools/call"] {
        assert!(observed.iter().any(|(_, body)| body["method"] == method));
    }
    for name in ["web_search", "web_fetch"] {
        assert!(observed
            .iter()
            .any(|(_, body)| body["params"]["name"] == name));
    }
    task.abort();
}
