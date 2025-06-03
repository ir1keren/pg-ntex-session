pub mod encryption;

use chrono::Local;
use cookie::{Cookie, CookieJar, Key, time::{OffsetDateTime, Duration as TimeDuration}, SameSite};
use ntex::{http::{header::{HeaderValue, SET_COOKIE}, HttpMessage}, web::{DefaultError, ErrorRenderer, WebRequest, WebResponse, WebResponseError}};
use ntex_session::{Session, SessionStatus};
use uuid::Uuid;
use std::{collections::HashMap, fmt::Display, rc::Rc, sync::Arc, time::Duration};
use once_cell::sync::OnceCell;
use diesel::{prelude::*, r2d2::{ConnectionManager, Pool}, sql_query, sql_types::{Text, Timestamp}, PgConnection, RunQueryDsl};
use ntex::service::{Middleware, Service, ServiceCtx};
use encryption::*;

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
    session_id:Uuid,
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
            session_id: Uuid::new_v4(),
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

    fn check_table(&self)
    {
        if let Some(pg)=PG_CONNECTION.get()
        {
            if let Ok(mut conn)=pg.get() {
                if let Ok(res,)=sql_query("SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'web_sessions')").get_result::<ExistsResult>(&mut conn)
                {
                    if !res.exists {
                        sql_query("CREATE TABLE web_sessions(id VARCHAR(32) NOT NULL, sess_state TEXT DEFAULT NULL, user_agent TEXT NOT NULL, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, expired_at NOT NULL CONSTRAINT pk_web_sessions PRIMARY KEY(id))").execute(&mut conn).expect("Failed to create table");
                        sql_query("CREATE INDEX IF NOT EXISTS idx_web_sessions_exp ON web_sessions(expired_at)").execute(&mut conn).expect("Failed to create indexes");
                    }
                }
            }
        }
    }

    fn fetch_session(&self) -> anyhow::Result<Option<PgSessionRow>>
    {
        if let Some(pg)=PG_CONNECTION.get()
        {
            let mut conn=pg.get()?;
            Ok(sql_query(format!("SELECT sess_state FROM web_sessions WHERE id='{}'",self.session_id.simple().to_string())).get_result::<PgSessionRow>(&mut conn).optional()?)
        } else {
            Err(anyhow::Error::msg("OnceCell not initialized"))
        }
        
    }

    fn load<Err>(&self, req: &WebRequest<Err>) -> anyhow::Result<(bool, HashMap<String, String>)>
    {
        if let Ok(cookies) = req.cookies() {
            for cookie in cookies.iter() {
                if cookie.name() == self.name {
                    self.check_table();

                    let mut jar = CookieJar::new();
                    jar.add_original(cookie.clone());

                    let cookie_opt = jar.signed(&self.key).get(&self.name);
                    if let Some(cookie) = cookie_opt {
                        if let Ok(val) = serde_json::from_str::<HashMap<String, String>>(cookie.value()) {
                            if let Some(sid)=val.get("sid") {
                                if let Ok(uid)=Uuid::parse_str(sid) {
                                    if self.session_id == uid {
                                        if let Some(row)=self.fetch_session().expect("Unable to fetch session row") {
                                            let mut s=row.sess_state.clone();
                                            
                                            if let Some(en)=self.encryption_engine.as_ref() {
                                                s=en.decrypt(s.as_bytes())?;
                                            }

                                            let val=serde_json::from_str::<HashMap<String,String>>(&s)?;
                                            return Ok((false,val));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok((true, HashMap::new()))
    }

    fn remove(&self, res: &mut WebResponse)->Result<(),PgSessError>
    {
        if let Some(db)=PG_CONNECTION.get() {
            let mut conn=db.get().map_err(|err|PgSessError::new(anyhow::Error::new(err)))?;
            sql_query(format!("DELETE FROM web_sessions WHERE id='{}'",self.session_id.simple().to_owned())).execute(&mut conn).map_err(|err|PgSessError::new(anyhow::Error::new(err)))?;
        }

        let mut cookie = Cookie::from(self.name.clone());
        cookie.set_value("");
        cookie.set_max_age(TimeDuration::ZERO);
        cookie.set_expires(OffsetDateTime::now_utc() - TimeDuration::days(365));

        let val = HeaderValue::from_str(&cookie.to_string()).unwrap();
        res.headers_mut().append(SET_COOKIE, val);

        Ok(())
    }

    fn save(&self,wres:&mut WebResponse,states:impl Iterator<Item = (String,String)>)->Result<(),PgSessError>
    {
        let states=<HashMap<String,String>>::from_iter(states);
        let mut state=serde_json::to_string(&states).map_err(|err|PgSessError::new(anyhow::Error::new(err)))?;

        if let Some(en)=self.encryption_engine.as_ref() {
            let val=en.encrypt(&state)?;
            state=String::from_utf8(val).map_err(|err|PgSessError::new(anyhow::Error::new(err)))?;
        }

        let sid=self.session_id.simple().to_string();
        let mut cookie = Cookie::new(self.name.clone(), format!(r#"{{"sid":"{}"}}"#,&sid));
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
            let query=sql_query("INSERT INTO web_sessions(id, sess_state, user_agent, created_at, expired_at) VALUES(?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET sess_state=?, expired_at=?")
            .bind::<Text,_>(sid.clone())
            .bind::<Text,_>(state.clone())
            .bind::<Text,_>(wres.headers().get("user-agent").and_then(|v|v.to_str().ok().map(|s|s.to_string())).unwrap_or("ntex::web".to_string()))
            .bind::<Timestamp,_>(Local::now().naive_local())
            .bind::<Timestamp,_>(expired_at.clone())
            .bind::<Text,_>(state.clone())
            .bind::<Timestamp,_>(expired_at.clone());
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
    pub fn new(key:impl AsRef<[u8]>,encryption_engine:Option<SE>,pooled_connection:Arc<Pool<ConnectionManager<PgConnection>>>)->Self
    {
        let key=key.as_ref();
        PG_CONNECTION.get_or_init(||pooled_connection);
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
        let (is_new, state) = self.inner.load(&req).expect("Error loading session");

        let prolong_expiration = self.inner.expires_in.is_some();
        Session::set_session(state.into_iter(), &req);
        
        ctx.call(&self.service, req).await.map(|mut res| {
            match Session::get_changes(&mut res) {
                (SessionStatus::Changed, Some(state))
                |(SessionStatus::Renewed, Some(state))=>res.checked_expr::<Err, _, _>(|res| {
                    inner.save(res, state)
                }),
                (SessionStatus::Unchanged, Some(state)) if prolong_expiration =>  {
                    res.checked_expr::<Err, _, _>(|res| {
                        inner.save(res, state)
                    })
                },
                (SessionStatus::Unchanged, _) => if is_new  {
                    let state: HashMap<String, String> = HashMap::new();
                    res.checked_expr::<Err, _, _>(|res| {
                        inner.save(res, state.iter().map(|(k,v)|(k.clone(),v.clone())))
                    })
                } else {
                    res
                },
                (SessionStatus::Purged, _) => {
                    let _ = inner.remove(&mut res);
                    res
                },
                _ => res
            }
        })
    }
}

static PG_CONNECTION: OnceCell<Arc<Pool<ConnectionManager<PgConnection>>>>= OnceCell::new();
