//! Entity graph: correlated attack-surface view of one scan.
//!
//! Nodes are deduplicated by (kind, label), so shared infrastructure (one
//! IP behind many hostnames, one technology on many hosts) collapses
//! naturally. Queries answer "all hosts running X" and "all endpoints
//! with parameter `id`". Exports: JSON, DOT, Mermaid.

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use swiftrecon_core::{StoredEndpoint, StoredParam, StoredPort, StoredTech};

/// One graph node. Labels are display strings, escaped on export.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Node {
    pub kind: String,
    pub label: String,
}

/// Scan rows assembled for graph building (store reads, no DB here).
#[derive(Debug, Default)]
pub struct ScanData {
    pub subdomains: Vec<String>,
    pub ports: Vec<StoredPort>,
    pub endpoints: Vec<StoredEndpoint>,
    pub params: Vec<StoredParam>,
    pub techs: Vec<(String, StoredTech)>,
}

/// Directed entity graph with labeled edges.
pub struct Graph {
    inner: DiGraph<Node, String>,
    index: HashMap<(String, String), NodeIndex>,
}

impl Graph {
    pub fn new() -> Self {
        Self {
            inner: DiGraph::new(),
            index: HashMap::new(),
        }
    }

    fn node(&mut self, kind: &str, label: &str) -> NodeIndex {
        let key = (kind.to_string(), label.to_string());
        if let Some(index) = self.index.get(&key) {
            return *index;
        }
        let index = self.inner.add_node(Node {
            kind: key.0.clone(),
            label: key.1.clone(),
        });
        self.index.insert(key, index);
        index
    }

    fn link(&mut self, from: NodeIndex, to: NodeIndex, relation: &str) {
        if self.inner.find_edge(from, to).is_none() {
            self.inner.add_edge(from, to, relation.to_string());
        }
    }

    pub fn node_count(&self) -> usize {
        self.inner.node_count()
    }

    pub fn edge_count(&self) -> usize {
        self.inner.edge_count()
    }

    /// Hosts running a technology (host -runs-> tech edges).
    pub fn hosts_running(&self, tech: &str) -> Vec<String> {
        let mut hosts = Vec::new();
        for edge in self.inner.edge_references() {
            let source = &self.inner[edge.source()];
            let target = &self.inner[edge.target()];
            if edge.weight() == "runs"
                && target.kind == "technology"
                && target.label == tech
                && (source.kind == "host" || source.kind == "subdomain")
            {
                hosts.push(source.label.clone());
            }
        }
        hosts.sort();
        hosts.dedup();
        hosts
    }

    /// Endpoint templates having a parameter with this name.
    pub fn endpoints_with_param(&self, name: &str) -> Vec<String> {
        let mut endpoints = Vec::new();
        for edge in self.inner.edge_references() {
            let source = &self.inner[edge.source()];
            let target = &self.inner[edge.target()];
            if edge.weight() == "has_param"
                && source.kind == "endpoint"
                && target.kind == "parameter"
                && target.label == name
            {
                endpoints.push(source.label.clone());
            }
        }
        endpoints.sort();
        endpoints.dedup();
        endpoints
    }

    /// Host groups sharing one IP (shared infrastructure).
    pub fn shared_infrastructure(&self) -> Vec<Vec<String>> {
        let mut groups: HashMap<String, Vec<String>> = HashMap::new();
        for edge in self.inner.edge_references() {
            let source = &self.inner[edge.source()];
            let target = &self.inner[edge.target()];
            if edge.weight() == "resolves_to"
                && (source.kind == "host" || source.kind == "subdomain")
                && target.kind == "ip"
            {
                groups
                    .entry(target.label.clone())
                    .or_default()
                    .push(source.label.clone());
            }
        }
        let mut out: Vec<Vec<String>> = groups
            .into_iter()
            .filter(|(_, hosts)| hosts.len() > 1)
            .map(|(_, mut hosts)| {
                hosts.sort();
                hosts
            })
            .collect();
        out.sort();
        out
    }

    /// JSON node-link export.
    pub fn to_json(&self) -> serde_json::Value {
        let nodes: Vec<&Node> = self.inner.node_weights().collect();
        let edges: Vec<serde_json::Value> = self
            .inner
            .edge_references()
            .map(|edge| {
                serde_json::json!({
                    "from": self.inner[edge.source()],
                    "to": self.inner[edge.target()],
                    "relation": edge.weight(),
                })
            })
            .collect();
        serde_json::json!({ "nodes": nodes, "edges": edges })
    }

    /// DOT export (labels quoted and escaped).
    pub fn to_dot(&self) -> String {
        let mut out = String::from("digraph swiftrecon {\n");
        for index in self.inner.node_indices() {
            let node = &self.inner[index];
            out.push_str(&format!(
                "  n{} [label=\"[{}] {}\"];\n",
                index.index(),
                node.kind,
                dot_escape(&node.label)
            ));
        }
        for edge in self.inner.edge_references() {
            out.push_str(&format!(
                "  n{} -> n{} [label=\"{}\"];\n",
                edge.source().index(),
                edge.target().index(),
                edge.weight()
            ));
        }
        out.push('}');
        out.push('\n');
        out
    }

    /// Mermaid flowchart export (labels sanitized: quotes stripped).
    pub fn to_mermaid(&self) -> String {
        let mut out = String::from("flowchart TD\n");
        for index in self.inner.node_indices() {
            let node = &self.inner[index];
            let label = node
                .label
                .replace('"', "")
                .replace(['[', ']', '{', '}'], "");
            out.push_str(&format!(
                "  n{}[\"[{}] {}\"]\n",
                index.index(),
                node.kind,
                label
            ));
        }
        for edge in self.inner.edge_references() {
            out.push_str(&format!(
                "  n{} -->|{}| n{}\n",
                edge.source().index(),
                edge.weight(),
                edge.target().index()
            ));
        }
        out
    }
}

impl Default for Graph {
    fn default() -> Self {
        Self::new()
    }
}

fn dot_escape(label: &str) -> String {
    label.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Build the entity graph from one scan's stored rows.
pub fn build(data: &ScanData) -> Graph {
    let mut graph = Graph::new();
    for host in &data.subdomains {
        graph.node("subdomain", host);
    }
    for port in &data.ports {
        let host = graph.node("host", &port.host);
        let ip = graph.node("ip", &port.ip);
        let node = graph.node("port", &format!("{}:{}", port.ip, port.port));
        graph.link(host, ip, "resolves_to");
        graph.link(ip, node, "listens");
    }
    for (host, tech) in &data.techs {
        let host_node = graph.node("host", host);
        let tech_node = graph.node("technology", &tech.name);
        graph.link(host_node, tech_node, "runs");
    }
    for endpoint in &data.endpoints {
        let endpoint_node = graph.node("endpoint", &endpoint.template);
        if let Some(host) = endpoint_host(&endpoint.template) {
            let host_node = graph.node("host", &host);
            graph.link(host_node, endpoint_node, "exposes");
        }
    }
    for param in &data.params {
        let endpoint_node = graph.node("endpoint", &param.endpoint);
        let param_node = graph.node("parameter", &param.name);
        graph.link(endpoint_node, param_node, "has_param");
    }
    graph
}

fn endpoint_host(template: &str) -> Option<String> {
    url::Url::parse(template)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ScanData {
        ScanData {
            subdomains: vec!["a.test".to_string(), "b.test".to_string()],
            ports: vec![
                StoredPort {
                    host: "a.test".to_string(),
                    ip: "1.2.3.4".to_string(),
                    port: 80,
                    state: "open".to_string(),
                    reason: "handshake".to_string(),
                },
                StoredPort {
                    host: "b.test".to_string(),
                    ip: "1.2.3.4".to_string(),
                    port: 443,
                    state: "open".to_string(),
                    reason: "handshake".to_string(),
                },
            ],
            endpoints: vec![StoredEndpoint {
                template: "http://a.test/users/{id}".to_string(),
                methods: vec!["GET".to_string()],
                sources: vec!["crawler".to_string()],
            }],
            params: vec![StoredParam {
                endpoint: "http://a.test/users/{id}".to_string(),
                name: "verbose".to_string(),
                location: "query".to_string(),
                method: "GET".to_string(),
            }],
            techs: vec![(
                "a.test".to_string(),
                StoredTech {
                    host: "a.test".to_string(),
                    name: "nginx".to_string(),
                    version: String::new(),
                    confidence: 0.7,
                },
            )],
        }
    }

    #[test]
    fn shared_ip_collapses_to_one_node() {
        let graph = build(&sample());
        let ips: Vec<_> = graph
            .inner
            .node_weights()
            .filter(|n| n.kind == "ip")
            .collect();
        assert_eq!(ips.len(), 1);
        let groups = graph.shared_infrastructure();
        assert_eq!(
            groups,
            vec![vec!["a.test".to_string(), "b.test".to_string()]]
        );
    }

    #[test]
    fn queries_answer() {
        let graph = build(&sample());
        assert_eq!(graph.hosts_running("nginx"), vec!["a.test".to_string()]);
        assert!(graph.hosts_running("apache").is_empty());
        assert_eq!(
            graph.endpoints_with_param("verbose"),
            vec!["http://a.test/users/{id}".to_string()]
        );
        assert!(graph.endpoints_with_param("missing").is_empty());
    }

    #[test]
    fn exports_render() {
        let graph = build(&sample());
        let dot = graph.to_dot();
        assert!(dot.starts_with("digraph swiftrecon"));
        assert!(dot.contains("resolves_to"));
        let mermaid = graph.to_mermaid();
        assert!(mermaid.starts_with("flowchart TD"));
        assert!(mermaid.contains("-->|runs|"));
        let json = graph.to_json();
        assert!(json.get("nodes").is_some());
        assert!(json.get("edges").is_some());
    }

    #[test]
    fn hostile_labels_escaped_in_dot() {
        let mut graph = Graph::new();
        graph.node("subdomain", "evil\\\".test");
        let dot = graph.to_dot();
        assert!(!dot.contains("evil\\\".test"));
    }
}
