//! Crawl, JS analysis, endpoint and parameter extraction (Phase 4).

pub mod crawl;
pub mod js;
pub mod openapi;
pub mod url;

pub use crawl::{crawl, extract_features, parse_robots, parse_sitemap, CrawlConfig, Form, Page};
pub use url::{
    canonicalize, query_params, resolve_against, template_path, ParamLocation, Parameter,
};
