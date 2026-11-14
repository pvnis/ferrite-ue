# Rust Agent Guidelines

## Verification Workflow
Before completing any task, you MUST run and pass:
1. `cargo fmt --check`
2. `cargo clippy --all-targets -- -D warnings`
3. `cargo test`

## Coding Standards
- **Error Handling**: Never use `.unwrap()`, `.expect()`, or `panic!()` in non-test code. Propagate errors using `?` with `thiserror` (libraries) or `anyhow` (binaries).
- **Safety**: Do not introduce `unsafe` blocks.
- **Dependencies**: Do not run `cargo add` or modify `Cargo.toml` dependencies without asking first.
- **Idioms**: Prefer iterators over manual index loops. Keep functions small and pass slices (`&[T]`, `&str`) rather than owned types (`&Vec<T>`, `&String`) in function arguments.

