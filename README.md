<div align="center">
 <p><h1>ntex-remove-trailing-slash</h1> </p>
  <p><strong>Removing trailing slash on ntex Framework</strong> </p>
</div>

## Usage

As in the description, this crate provides a middleware for the ntex framework that removes trailing slashes from incoming requests. So it will be possible to access the same resource with or without a trailing slash.
This is useful for creating a consistent API where the presence or absence of a trailing slash does not affect the resource being accessed.
So, ``GET /api/resource/`` and ``GET /api/resource`` will both return the same resource.
Inspired by actix's.

```toml
[dependencies]
ntex-remove-trailing-slash = { version = "0.1.0" }
```

## Example

```rust
use ntex_remove_trailing_slash::RemoveTrailingSlash;
use ntex::{server::Server, web::{error::ErrorInternalServerError, route, scope, types::JsonConfig, App, HttpServer}};

pub fn create_new_www()->std::io::Result<Server>
{
    let app=HttpServer::new(|| {
        let ts=RemoveTrailingSlash::default();
        App::new()
        .wrap(ts)
    });
    app.bind(("0.0.0.0",80)?;
    Ok(app.run())
}
```
