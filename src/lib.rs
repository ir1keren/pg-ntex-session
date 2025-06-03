use cookie::{CookieJar, Key, SameSite};
use ntex::{http::HttpMessage, web::WebRequest};
use uuid::Uuid;
use std::fmt::Display;
use once_cell::sync::OnceCell;
use diesel::pg::PgConnection;

struct PgSessionInner {
    db_url: String,
    session_id:Uuid,
    key: Key,
    name: String,
    path: String,
    domain: Option<String>,
    secure: bool,
    http_only: bool,
    max_age: Option<Duration>,
    expires_in: Option<Duration>,
    same_site: Option<SameSite>,
}

impl PgSessionInner
{
    fn new(key: &[u8], db_url:impl Display) -> Self {
        CookieSessionInner {
            db_url: db_url.to_string(),
            session_id: Uuid::new_v4(),
            key: Key::derive_from(key),
            name: "nx-sess".to_owned(),
            path: "/".to_owned(),
            domain: None,
            secure: true,
            http_only: true,
            max_age: None,
            expires_in: None,
            same_site: None,
        }
    }

    fn get_connection(&self)
    {

    }

    fn create_session(&self)
    {

    }

    fn load<Err>(&self, req: &WebRequest<Err>) -> (bool, HashMap<String, String>)
    {
        if let Ok(cookies) = req.cookies() {
            for cookie in cookies.iter() {
                if cookie.name() == self.name {
                    let mut jar = CookieJar::new();
                    jar.add_original(cookie.clone());

                    let cookie_opt = jar.signed(&self.key).get(&self.name);
                    if let Some(cookie) = cookie_opt {
                        if let Ok(val) = serde_json::from_str::<HashMap<String, String>>(cookie.value()) {
                            return (false, val);
                        }
                    }
                }
            }
        }

        self.create_session();
        (true, HashMap::new())
    }
}

static PG_CONNECTION: OnceCell<PgConnection>= OnceCell::new();
