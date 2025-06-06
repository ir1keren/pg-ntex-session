//! User sessions.
//!
//!
//! By default, only cookie session backend is implemented. This crate
//! provides PostgreSQL back end with Diesel's engine
//!
//! In general, you insert a *session* middleware and initialize it
//! , such as a `PgNtexSession`. To access session data,
//! [*Session*](https://docs.rs/ntex-session/latest/ntex_session/struct.Session.html) extractor must be used. Session
//! extractor allows us to get or set session data.
//!
//! ```rust,no_run
//! use ntex::web::{self, App, HttpResponse, Error};
//! use pg_ntex_session::{encryption::Simple, PgNtexSession};
//! use diesel::{r2d2::{ConnectionManager, Pool}, PgConnection};
//! use std::sync::Arc;
//!
//! fn index(session: Session) -> Result<&'static str, Error> {
//!     // access session data
//!     if let Some(count) = session.get::<i32>("counter")? {
//!         println!("SESSION value: {}", count);
//!         session.set("counter", count+1)?;
//!     } else {
//!         session.set("counter", 1)?;
//!     }
//!
//!     Ok("Welcome!")
//! }
//!
//! //DB connection sting
//! const DATABASE_URL:&'static str="postgres://postgres:password@localhost/my_db";
//! //32 characters
//! const ENC_KEY:&'static str="29dba93e4ce64609bb5d592dab92ec00";
//! //Pool of connection manager
//! const :Arc<Pool<ConnectionManager<PgConnection>>>=Arc::new(
//!     Pool::builder().max_size(16)
//!        .build(ConnectionManager::<PgConnection>::new(DATABASE_URL))
//!        .unwrap()
//! );
//! 
//! #[ntex::main]
//! async fn main() -> std::io::Result<()> {
//!     web::server(
//!         || App::new().wrap(
//!               <PgNtexSession<Simple>>::new(ENC_KEY.as_bytes(), Some(Simple::new(ENC_KEY.as_str())), CONNECTION.clone()))
//!              )
//!             .service(web::resource("/").to(|| async { HttpResponse::Ok() })))
//!         .bind("127.0.0.1:59880")?
//!         .run()
//!         .await
//! }
//! ```
pub mod encryption;

use chrono::Local;
use cookie::{Cookie, CookieJar, Key, time::{OffsetDateTime, Duration as TimeDuration}, SameSite};
use ntex::{http::{header::{HeaderValue, COOKIE, SET_COOKIE, USER_AGENT}, HttpMessage}, web::{DefaultError, ErrorRenderer, HttpRequest, WebRequest, WebResponse, WebResponseError}};
use ntex_session::{Session, SessionStatus};
use uuid::Uuid;
use std::{collections::HashMap, fmt::Display, rc::Rc, sync::Arc, time::Duration};
use once_cell::sync::OnceCell;
use diesel::{prelude::*, r2d2::{ConnectionManager, Pool}, sql_query, PgConnection, RunQueryDsl};
use ntex::service::{Middleware, Service, ServiceCtx};
use encryption::*;
use base64::prelude::*;

#[derive(Debug)]
pub struct PgSessError(anyhow::Error);

impl PgSessError {
    pub fn new(error:anyhow::Error) -> Self
    {
        Self(error)
    }
}

impl Display for PgSessError
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f,"{}",self.0)
    }
}

impl std::error::Error for PgSessError {}

impl WebResponseError<DefaultError> for PgSessError {}

// impl ResponseError for PgSessError
// {
//     fn error_response(&self) -> ntex::http::Response {
//         ErrorInternalServerError(&self.0).error_response()
//     }
// }

impl From<anyhow::Error> for PgSessError {
    fn from(value: anyhow::Error) -> Self {
        Self(value)
    }
}

#[derive(Debug, QueryableByName)]
struct PgSessionRow
{
    #[diesel(sql_type = diesel::sql_types::Text)]
    sess_state:String
}

#[derive(QueryableByName)]
struct ExistsResult {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    exists: bool,
}

struct PgSessionInner<SE:StateEncryption + Clone> {
    encryption_engine:Option<Box<SE>>,
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

impl <SE:StateEncryption + Clone> PgSessionInner<SE>
{
    fn new(key: &[u8],ee:Option<SE>) -> Self {
        Self {
            encryption_engine:ee.clone().map(|v| Box::new(v)),
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

    fn check_table(&self)->anyhow::Result<()>
    {
        if let Some(pg)=PG_CONNECTION.get()
        {
            if let Ok(mut conn)=pg.get() {
                if let Ok(res,)=sql_query("SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'web_sessions')").get_result::<ExistsResult>(&mut conn)
                {
                    if !res.exists {
                        let query=sql_query("CREATE TABLE web_sessions(id VARCHAR(32) NOT NULL, sess_state TEXT DEFAULT NULL, user_agent TEXT NOT NULL, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, expired_at TIMESTAMP NOT NULL, CONSTRAINT pk_web_sessions PRIMARY KEY(id))");
                        query.execute(&mut conn)?;
                        let query=sql_query("CREATE INDEX IF NOT EXISTS idx_web_sessions_exp ON web_sessions(expired_at)");
                        query.execute(&mut conn)?;
                    }
                }
            }
        }

        Ok(())
    }

    fn fetch_session(&self,session_id:impl AsRef<str>) -> anyhow::Result<Option<PgSessionRow>>
    {
        let session_id=session_id.as_ref();

        if let Some(pg)=PG_CONNECTION.get()
        {
            let mut conn=pg.get()?;
            Ok(sql_query(format!("SELECT sess_state FROM web_sessions WHERE id='{}'",session_id)).get_result::<PgSessionRow>(&mut conn).optional()?)
        } else {
            Err(anyhow::Error::msg("OnceCell not initialized"))
        }
    }

    fn load<Err>(&self, req: &WebRequest<Err>) -> anyhow::Result<(bool, String, HashMap<String, String>)>
    {
        self.check_table()?;
        let mut session_id=Uuid::new_v4().simple().to_string();
        
        if let Ok(cookies) = req.cookies() {
            for cookie in cookies.iter() {
                if cookie.name() == self.name {
                    let mut jar = CookieJar::new();
                    jar.add_original(cookie.clone());

                    let cookie_opt = jar.signed(&self.key).get(&self.name);
                    if let Some(cookie) = cookie_opt {
                        if let Ok(val) = serde_json::from_str::<HashMap<String, String>>(cookie.value()) {
                            if let Some(sid)=val.get("sid") {
                                session_id=sid.clone();

                                if let Some(row)=self.fetch_session(&session_id).expect("Unable to fetch session row") {
                                    let mut s=row.sess_state.clone();
                                    
                                    if let Some(en)=self.encryption_engine.as_ref() {
                                        s=en.decrypt(BASE64_STANDARD.decode(&s)?)?;
                                    }

                                    let val=serde_json::from_str::<HashMap<String,String>>(&s)?;
                                    return Ok((false, session_id,val));
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok((true, session_id, HashMap::new()))
    }

    fn remove(&self, res: &mut WebResponse, session_id:impl AsRef<str>)->Result<(),PgSessError>
    {
        let session_id=session_id.as_ref();

        if let Some(db)=PG_CONNECTION.get() {
            let mut conn=db.get().map_err(|err|PgSessError::new(anyhow::Error::new(err)))?;
            sql_query(format!("DELETE FROM web_sessions WHERE id='{}'",session_id)).execute(&mut conn).map_err(|err|PgSessError::new(anyhow::Error::new(err)))?;
        }

        let mut cookie = Cookie::from(self.name.clone());
        cookie.set_value("");
        cookie.set_max_age(TimeDuration::ZERO);
        cookie.set_expires(OffsetDateTime::now_utc() - TimeDuration::days(365));

        let val = HeaderValue::from_str(&cookie.to_string()).unwrap();
        res.headers_mut().append(SET_COOKIE, val);

        Ok(())
    }

    fn save(&self,session_id:impl Display,wres:&mut WebResponse,states:impl Iterator<Item = (String,String)>)->Result<(),PgSessError>
    {
        let session_id=session_id.to_string();
        let states=<HashMap<String,String>>::from_iter(states);
        let mut state=serde_json::to_string(&states).map_err(|err|PgSessError::new(anyhow::Error::new(err)))?;

        if let Some(en)=self.encryption_engine.as_ref() {
            let val=en.encrypt(&state)?;
            state=BASE64_STANDARD.encode(&val);
        }

        let mut cookie = Cookie::new(self.name.clone(), format!(r#"{{"sid":"{}"}}"#,&session_id));
        cookie.set_path(self.path.clone());
        cookie.set_secure(self.secure);
        cookie.set_http_only(self.http_only);

        if let Some(ref domain) = self.domain {
            cookie.set_domain(domain.clone());
        }

        let expired_at=if let Some(expires_in) = self.expires_in {
            cookie.set_expires(OffsetDateTime::now_utc() + expires_in);
            Local::now() + expires_in
        } else {
            Local::now() + Duration::from_secs(3600)
        }.naive_local();
        
        if let Some(db)=PG_CONNECTION.get() {
            let now=Local::now();
            let dt_format="%Y-%m-%d %H:%M:%S%.9f";
            let query=sql_query(format!("INSERT INTO web_sessions (id, sess_state, user_agent, created_at, expired_at) VALUES('{}', '{}', '{}', '{}', '{}') ON CONFLICT(id) DO UPDATE SET sess_state=EXCLUDED.sess_state, expired_at=EXCLUDED.expired_at",&session_id,&state,wres.headers().get(USER_AGENT).and_then(|v|v.to_str().ok().map(|s|s.to_string())).unwrap_or("ntex::web".to_string()),now.format(dt_format).to_string(),expired_at.format(dt_format).to_string()));
            let mut conn=db.get().map_err(|err|PgSessError::new(anyhow::Error::new(err)))?;
            query.execute(&mut conn).map_err(|err|PgSessError::new(anyhow::Error::new(err)))?;
        }

        let mut jar = CookieJar::new();
        jar.signed_mut(&self.key).add(cookie);

        for cookie in jar.delta() {
            let val = HeaderValue::from_str(&cookie.encoded().to_string()).unwrap();
            wres.headers_mut().append(SET_COOKIE, val);
        }

        Ok(())
    }
}

pub struct PgNtexSession<SE:StateEncryption + Clone>(Rc<PgSessionInner<SE>>);

impl <SE:StateEncryption + Clone> PgNtexSession<SE>
{
/// Construct new *signed* `PgNtexSession` instance.
///
/// You can use UUID v4 as encryption key.
/// Panics if key length is less than 32 bytes.
/// ```pooled_connection``` is a Pool of Postgres Connection Manager. Check [*r2d2 Pool sample*](https://docs.rs/r2d2/latest/r2d2/) and [*ConnectionManager sample*](https://docs.rs/diesel/latest/diesel/r2d2/struct.ConnectionManager.html#method.new)
    pub fn new(key:impl AsRef<[u8]>,encryption_engine:Option<SE>,pooled_connection:Arc<Pool<ConnectionManager<PgConnection>>>)->Self
    {
        let key=key.as_ref();
        PG_CONNECTION.get_or_init(||pooled_connection);
        COOKIE_ENC_KEY.get_or_init(||key.to_vec());
        Self(Rc::new(PgSessionInner::new(key,encryption_engine)))
    }

    /// Sets the `path` field in the session cookie being built.
    pub fn path<S: Into<String>>(mut self, value: S) -> Self {
        Rc::get_mut(&mut self.0).unwrap().path = value.into();
        self
    }

    /// Sets the `name` field in the session cookie being built.
    pub fn name<S: Into<String>>(mut self, value: S) -> Self {
        Rc::get_mut(&mut self.0).unwrap().name = value.into();
        self
    }

    /// Sets the `domain` field in the session cookie being built.
    pub fn domain<S: Into<String>>(mut self, value: S) -> Self {
        Rc::get_mut(&mut self.0).unwrap().domain = Some(value.into());
        self
    }

    /// Sets the `secure` field in the session cookie being built.
    ///
    /// If the `secure` field is set, a cookie will only be transmitted when the
    /// connection is secure - i.e. `https`
    pub fn secure(mut self, value: bool) -> Self {
        Rc::get_mut(&mut self.0).unwrap().secure = value;
        self
    }

    /// Sets the `http_only` field in the session cookie being built.
    pub fn http_only(mut self, value: bool) -> Self {
        Rc::get_mut(&mut self.0).unwrap().http_only = value;
        self
    }

    /// Sets the `same_site` field in the session cookie being built.
    pub fn same_site(mut self, value: SameSite) -> Self {
        Rc::get_mut(&mut self.0).unwrap().same_site = Some(value);
        self
    }

    /// Sets the `max-age` field in the session cookie being built.
    pub fn max_age(self, seconds: u64) -> Self {
        self.max_age_time(Duration::from_secs(seconds))
    }

    /// Sets the `max-age` field in the session cookie being built.
    pub fn max_age_time(mut self, value: Duration) -> Self {
        Rc::get_mut(&mut self.0).unwrap().max_age = Some(value);
        self
    }

    /// Sets the `expires` field in the session cookie being built.
    pub fn expires_in(self, seconds: u64) -> Self {
        self.expires_in_time(Duration::from_secs(seconds))
    }

    /// Sets the `expires` field in the session cookie being built.
    pub fn expires_in_time(mut self, value: Duration) -> Self {
        Rc::get_mut(&mut self.0).unwrap().expires_in = Some(value);
        self
    }
}

impl<S,SE:StateEncryption + Clone> Middleware<S> for PgNtexSession<SE> {
    type Service = PgNtexSessionMiddleware<S,SE>;

    fn create(&self, service: S) -> Self::Service {
        PgNtexSessionMiddleware { service, inner: self.0.clone() }
    }
}

/// Session middleware with Postgres backend for Ntex web framework
pub struct PgNtexSessionMiddleware<S,SE: StateEncryption + Clone> {
    service: S,
    inner: Rc<PgSessionInner<SE>>,
}

impl<S, Err,SE:StateEncryption + Clone> Service<WebRequest<Err>> for PgNtexSessionMiddleware<S,SE>
where
    S: Service<WebRequest<Err>, Response = WebResponse>,
    S::Error: 'static,
    Err: ErrorRenderer,
    Err::Container: From<PgSessError>,
{
    type Response = WebResponse;
    type Error = S::Error;

    ntex::forward_poll!(service);
    ntex::forward_ready!(service);
    ntex::forward_shutdown!(service);

    /// On first request, a new session cookie is returned in response, regardless
    /// of whether any session state is set.  This cookie only stores one field:
    /// ```sid``` which is a session ID, that points to primary key to PostgreSQL
    /// table. With subsequent requests, if the session state changes, then
    /// set-cookie is returned in response.  As a user logs out, call
    /// session.purge() to set SessionStatus accordingly and this will trigger
    /// removal of the session cookie in the response.
    async fn call(&self,req: WebRequest<Err>, ctx: ServiceCtx<'_, Self>) -> Result<Self::Response, Self::Error>
    {
        let inner = self.inner.clone();
        let (is_new, session_id, state) = self.inner.load(&req).expect("Error loading session");

        let prolong_expiration = self.inner.expires_in.is_some();
        Session::set_session(state.into_iter(), &req);
        clean_expired_session();
        
        ctx.call(&self.service, req).await.map(|mut res| {
            match Session::get_changes(&mut res) {
                (SessionStatus::Changed, Some(state))
                |(SessionStatus::Renewed, Some(state))=>res.checked_expr::<Err, _, _>(|res| {
                    inner.save(&session_id, res, state)
                }),
                (SessionStatus::Unchanged, Some(state)) if prolong_expiration =>  {
                    res.checked_expr::<Err, _, _>(|res| {
                        inner.save(&session_id, res, state)
                    })
                },
                (SessionStatus::Unchanged, _) => if is_new  {
                    let state: HashMap<String, String> = HashMap::new();
                    res.checked_expr::<Err, _, _>(|res| {
                        inner.save(&session_id, res, state.iter().map(|(k,v)|(k.clone(),v.clone())))
                    })
                } else {
                    res
                },
                (SessionStatus::Purged, _) => {
                    let _ = inner.remove(&mut res, &session_id);
                    res
                },
                _ => res
            }
        })
    }
}

/// Returns saved session ID, in form of 32 hex characters, or returns
/// ```None``` instead, if you haven't saved your states in this 
/// current session
pub fn get_session_id<'a>(http_req:&'a HttpRequest)->Option<String>
{
    if let Some(cookie_header)=http_req.headers().get(COOKIE)
    {
        if let Ok(cookie_str) = cookie_header.to_str().map(|v|v.to_string()) {
            for cookie in cookie_str.split(';').map(|s|s.trim().to_string()) {
                if let Ok(parsed_cookie) = Cookie::parse(cookie) {
                    if parsed_cookie.name() == "nx-sess" {
                        let mut jar = CookieJar::new();
                        jar.add_original(parsed_cookie.clone());
                        
                        if let Some(key)=COOKIE_ENC_KEY.get() {
                            let cookie_key=Key::derive_from(key.as_slice());
                            if let Some(cookie)=jar.signed(&cookie_key).get("nx-sess") {
                                if let Ok(val) = serde_json::from_str::<HashMap<String, String>>(cookie.value()) {
                                    return val.get("sid").cloned();
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    None
}

/// Clean expired sessions in database, which tolerates +3 minutes
/// from actual ```expired_at``` value.
/// You can use it with timer to clean it periodically.
pub fn clean_expired_session()
{
    let now_minus=Local::now() - Duration::from_secs(180);
    
    if let Some(pool)=PG_CONNECTION.get() {
        if let Ok(mut conn)=pool.get() {
            let _=sql_query(format!("DELETE FROM web_sessions WHERE expiired_at <= '{}'",now_minus.format("%Y-%m-%d %H:%M:%S%.9f").to_string())).execute(&mut conn);
        }
    }
}

static PG_CONNECTION: OnceCell<Arc<Pool<ConnectionManager<PgConnection>>>>= OnceCell::new();
static COOKIE_ENC_KEY:OnceCell<Vec<u8>>=OnceCell::new();
