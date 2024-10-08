use core::time;
//#![deny(clippy::all)]
use std::collections::{HashMap, HashSet};
use std::vec;

use ldap3::result::Result as LdapResult;
use ldap3::{ldap_escape, LdapConn, LdapConnSettings, Scope, SearchEntry};
use napi::bindgen_prelude::AsyncTask;
use napi::Result as NapiResult;
use napi::{Env, Task};
use napi::{Error as NapiError, JsString};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Serialize;

#[macro_use]
extern crate napi_derive;

#[napi(object)]
//#[derive(Copy, Clone)]
pub struct TlsOptions {
  pub reject_unauthorized: bool,
}
#[napi(object)]
pub struct LdapOpts {
  pub url: String,
  pub connect_timeout: Option<i32>,
  pub tls_options: Option<TlsOptions>,
}
#[napi(object)]
pub struct AuthOpts {
  pub ldap_opts: LdapOpts,
  pub user_search_base: String,
  pub username_attribute: String,
  pub username: String,
  pub admin_dn: Option<String>,
  pub admin_password: Option<String>,
  pub user_dn: Option<String>,
  pub user_password: Option<String>,
  pub verify_user_exists: Option<bool>,
  pub attributes: Option<Vec<String>>,
  pub starttls: Option<bool>,
  pub groups_search_base: Option<String>,
  pub group_class: Option<String>,
  pub group_member_attribute: Option<String>,
  pub group_member_user_attribute: Option<String>,
}

struct SearchUser {
  auth_opts: AuthOpts,
}

#[derive(Serialize)]
struct MySearchEntry {
  pub dn: String,
  pub attrs: HashMap<String, Vec<String>>,
  pub bin_attrs: HashMap<String, Vec<String>>,
}
impl From<&SearchEntry> for MySearchEntry {
  fn from(entry: &SearchEntry) -> Self {
    let mut ret = MySearchEntry {
      dn: entry.dn.clone(),
      attrs: entry.attrs.clone(),
      bin_attrs: HashMap::new(),
    };

    for (key, attr) in entry.bin_attrs.iter() {
      let mut attr_vec: Vec<String> = vec![];
      for bin_v in attr {
        attr_vec.push(STANDARD.encode(bin_v));
      }
      ret.bin_attrs.insert(key.clone(), attr_vec);
    }
    ret
  }
}

#[napi]
impl Task for SearchUser {
  type Output = SearchEntry;
  type JsValue = JsString;

  fn compute(&mut self) -> NapiResult<Self::Output> {
    _search_user(&self.auth_opts).map_err(|e| NapiError::from_reason(format!("{}", e)))
  }

  fn resolve(&mut self, env: Env, output: SearchEntry) -> NapiResult<Self::JsValue> {
    let my_entries: MySearchEntry = MySearchEntry::from(&output);
    let s =
      serde_json::to_string(&my_entries).map_err(|e| NapiError::from_reason(format!("{}", e)))?;
    env.create_string(&s)
  }

  fn reject(&mut self, env: Env, err: NapiError) -> NapiResult<Self::JsValue> {
    //self.data.unref(env)?;
    _ = env;
    Err(err)
  }
}

#[napi]
#[allow(dead_code)]
fn authenticate(auth_opts: AuthOpts) -> AsyncTask<SearchUser> {
  AsyncTask::new(SearchUser { auth_opts })
}

fn _search_user(auth_opts: &AuthOpts) -> LdapResult<SearchEntry> {
  let connect_timeout_ms: u64 = auth_opts
    .ldap_opts
    .connect_timeout
    .unwrap_or(5000)
    .try_into()
    .unwrap_or(5000);
  let timeout = time::Duration::from_millis(connect_timeout_ms);
  let tls_verify = match &auth_opts.ldap_opts.tls_options {
    Some(v) => v.reject_unauthorized,
    None => true,
  };

  let ldap_settings = LdapConnSettings::new()
    .set_conn_timeout(timeout)
    .set_no_tls_verify(!tls_verify)
    .set_starttls(auth_opts.starttls.unwrap_or(false));

  let mut conn = LdapConn::with_settings(ldap_settings, &auth_opts.ldap_opts.url)?;
  let admin_dn = match &auth_opts.admin_dn {
    Some(s) => s,
    None => "",
  };
  let admin_password = match &auth_opts.admin_password {
    Some(s) => s,
    None => "",
  };
  if admin_dn.is_empty() {
    let user_dn = match &auth_opts.user_dn {
      Some(s) => s,
      None => "",
    };
    let user_password = match &auth_opts.user_password {
      Some(s) => s,
      None => "",
    };
    conn.simple_bind(user_dn, user_password)?.success()?;
  } else {
    conn.simple_bind(admin_dn, admin_password)?.success()?;
    // also needs to bind with username and user_password
    let search_result = conn.search(
      &auth_opts.user_search_base,
      Scope::Subtree,
      &format!(
        "{}={}",
        ldap_escape(&auth_opts.username_attribute),
        ldap_escape(&auth_opts.username)
      ),
      &vec!["-"],
    );
    let rs = match search_result {
      Ok(result) => result,
      Err(e) => {
        conn.unbind()?;
        return Err(e);
      }
    };
    let rs = match rs.success() {
      Ok((result, _)) => result,
      Err(e) => {
        conn.unbind()?;
        return Err(e);
      }
    };
    if rs.is_empty() {
      conn.unbind()?;
      return Err(ldap3::LdapError::LdapResult {
        result: ldap3::LdapResult {
          rc: 1,
          matched: "not found".into(),
          refs: vec![],
          ctrls: vec![],
          text: "user not found".into(),
        },
      });
    }
    let entry = &rs[0];
    let found_user = SearchEntry::construct(entry.clone());
    let user_dn = &found_user.dn;
    // bind with user's dn and password.
    if let Some(v) = auth_opts.verify_user_exists {
      if v {
        return Ok(found_user);
      }
    }
    let user_password = match &auth_opts.user_password {
      Some(password) => password,
      None => {
        conn.unbind()?;
        return Err(ldap3::LdapError::LdapResult {
          result: ldap3::LdapResult {
            rc: 1,
            matched: user_dn.into(),
            refs: vec![],
            ctrls: vec![],
            text: "userPassword is not supplied".into(),
          },
        });
      }
    };
    conn.simple_bind(user_dn, user_password)?.success()?;
  }

  let mut attrs_set: HashSet<String> = match &auth_opts.attributes {
    Some(v) => HashSet::from_iter(v.clone()),
    None => HashSet::new(),
  };
  if let Some(mu) = &auth_opts.group_member_user_attribute {
    attrs_set.insert(mu.clone());
  }
  if attrs_set.is_empty() {
    attrs_set.insert("-".into());
  }
  let filter = &format!(
    "{}={}",
    ldap_escape(&auth_opts.username_attribute),
    ldap_escape(&auth_opts.username)
  );
  let attrs: Vec<String> = Vec::from_iter(attrs_set);
  let search_result = conn.search(&auth_opts.user_search_base, Scope::Subtree, filter, &attrs);
  let rs = match search_result {
    Ok(result) => result,
    Err(e) => {
      conn.unbind()?;
      return Err(e);
    }
  };
  let rs = match rs.success() {
    Ok((result, _)) => result,
    Err(e) => {
      conn.unbind()?;
      return Err(e);
    }
  };
  if rs.is_empty() {
    conn.unbind()?;
    return Err(ldap3::LdapError::LdapResult {
      result: ldap3::LdapResult {
        rc: 1,
        matched: "not found".into(),
        refs: vec![],
        ctrls: vec![],
        text: "user not found".into(),
      },
    });
  }
  let entry = &rs[0];
  let mut result = SearchEntry::construct(entry.clone());
  if let (
    Some(group_class),
    Some(groups_search_base),
    Some(group_member_attribute),
    Some(group_member_user_attribute),
  ) = (
    &auth_opts.group_class,
    &auth_opts.groups_search_base,
    &auth_opts.group_member_attribute,
    &auth_opts.group_member_user_attribute,
  ) {
    if let Some(values) = result.attrs.get(group_member_user_attribute) {
      let group_member = &values[0];
      let filter = &format!(
        "(&(objectclass={})({}={}))",
        ldap_escape(group_class),
        ldap_escape(group_member_attribute),
        ldap_escape(group_member)
      );
      let search_result = conn.search(groups_search_base, Scope::Subtree, filter, &vec!["dn"]);
      let rs = match search_result {
        Ok(result) => result,
        Err(e) => {
          conn.unbind()?;
          return Err(e);
        }
      };
      let rs = match rs.success() {
        Ok((result, _)) => result,
        Err(e) => {
          conn.unbind()?;
          return Err(e);
        }
      };
      let mut groups: Vec<String> = vec![];
      for entry in rs {
        let search_entry = SearchEntry::construct(entry);
        groups.push(search_entry.dn);
      }
      result.attrs.insert(String::from("groups"), groups);
    }
  }
  conn.unbind()?;
  Ok(result)
}
