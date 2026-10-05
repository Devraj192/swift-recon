//! Phase 5 benchmarks: local, deterministic, CPU-only. Network baselines
//! against third-party tools are out of scope for this sandbox; rerun on a
//! real network with `cargo bench` and compare there.

use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

fn bench_canonicalize(c: &mut Criterion) {
    let urls: Vec<String> = (0..200)
        .map(|i| format!("HTTP://Example.COM:80/a//b{i}/?b=2&a=1&utm_source=x#frag"))
        .collect();
    c.bench_function("canonicalize_200", |b| {
        b.iter(|| {
            for url in &urls {
                black_box(swiftrecon_web::canonicalize(url));
            }
        })
    });
}

fn bench_merge(c: &mut Criterion) {
    let lists = vec![
        (
            "crtsh".to_string(),
            (0..500).map(|i| format!("h{i}.test")).collect(),
        ),
        (
            "bruteforce".to_string(),
            (250..750).map(|i| format!("h{i}.test")).collect(),
        ),
    ];
    c.bench_function("merge_1000_hosts", |b| {
        b.iter(|| black_box(swiftrecon_discover::merge_sources(lists.clone())))
    });
}

fn bench_js(c: &mut Criterion) {
    let source = include_str!("../../../lab/spa/app.js");
    let big = source.repeat(20);
    c.bench_function("js_analyze", |b| {
        b.iter(|| black_box(swiftrecon_web::js::analyze(&big)))
    });
}

fn bench_fingerprint(c: &mut Criterion) {
    let rules = swiftrecon_fingerprint::load_rules(include_str!("../../../rules/fingerprint.toml"))
        .unwrap();
    let observed = swiftrecon_fingerprint::Observed {
        server: Some("nginx/1.24".to_string()),
        powered_by: None,
        cookie_names: vec!["sess".to_string()],
        meta_generator: Some("WordPress 6.4".to_string()),
        html_excerpt: include_str!("../../../lab/spa/index.html").to_string(),
    };
    c.bench_function("fingerprint", |b| {
        b.iter(|| black_box(swiftrecon_fingerprint::fingerprint(&rules, &observed)))
    });
}

criterion_group!(
    benches,
    bench_canonicalize,
    bench_merge,
    bench_js,
    bench_fingerprint
);
criterion_main!(benches);
