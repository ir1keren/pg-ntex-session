<div align="center">
 <p><h1>pg-ntex-session</h1> </p>
  <p><strong>PostgreSQL backend for ntex session</strong> </p>
</div>

## Overview

By default, only cookie session backend is implemented. This crate provides PostgreSQL back end with Diesel's engine

In general, you insert a *session* middleware and initialize it, such as a `PgNtexSession`.
To access session data, [*Session*](https://docs.rs/ntex-session/latest/ntex_session/struct.Session.html) extractor must be used. Session extractor allows us to get or set session data.

```toml
[dependencies]
pg-ntex-session = { version = "0.1.0" }
```

## Example

```rust
use ntex::web::{self, App, HttpResponse, Error};
use pg_ntex_session::{encryption::Simple, PgNtexSession};
use diesel::{r2d2::{ConnectionManager, Pool}, PgConnection};
use std::sync::Arc;

fn index(session: Session) -> Result<&'static str, Error> {
    // access session data
    if let Some(count) = session.get::<i32>("counter")? {
        println!("SESSION value: {}", count);
        session.set("counter", count+1)?;
    } else {
        session.set("counter", 1)?;
    }
!
    Ok("Welcome!")
}
!
//DB connection sting
const DATABASE_URL:&'static str="postgres://postgres:password@localhost/my_db";
//32 characters
const ENC_KEY:&'static str="29dba93e4ce64609bb5d592dab92ec00";
//Pool of connection manager
const :Arc<Pool<ConnectionManager<PgConnection>>>=Arc::new(
    Pool::builder().max_size(16)
       .build(ConnectionManager::<PgConnection>::new(DATABASE_URL))
       .unwrap()
);

#[ntex::main]
async fn main() -> std::io::Result<()> {
    web::server(
        || App::new().wrap(
              <PgNtexSession<Simple>>::new(ENC_KEY.as_bytes(), Some(Simple::new(ENC_KEY.as_str())), CONNECTION.clone()))
             )
            .service(web::resource("/").to(|| async { HttpResponse::Ok() })))
        .bind("127.0.0.1:59880")?
        .run()
        .await
}
```
