extern crate serde;
extern crate serde_json;
extern crate libgatekeeper_sys;
extern crate reqwest;

use libgatekeeper_sys::{Nfc, NfcDevice, Realm};
use std::time::Duration;
use std::env;
use std::thread;
use serde_json::{Value};
use std::result::Result;
use reqwest::StatusCode;
use reqwest::header::AUTHORIZATION;

pub struct GateKeeperMemberListener<'a> {
    nfc_device: NfcDevice<'a>,
    http: reqwest::blocking::Client,

    realm: Realm,

    // Passed to GK-MQTT to resolve users
    server_token: String,
    // HTTP Endpoint
    endpoint: String,

    // Safeguard against double-scans
    just_scanned: bool,

    // Route URL
    route: &'static str,
}

pub enum FetchError {
    NotFound,
    ParseError,
    NetworkError,
    Unknown,
}

pub enum RealmInfo {
    Drink,
    MemberProjects,
    Doors,
}

impl RealmInfo {
    fn get_route(&self) -> &'static str {
        match self {
            RealmInfo::Drink => "drink",
            RealmInfo::Doors => "doors",
            RealmInfo::MemberProjects => "projects",
        }
    }
    fn get_name(&self) -> &'static str {
        match self {
            RealmInfo::Doors => "Doors",
            RealmInfo::Drink => "Drink",
            RealmInfo::MemberProjects => "Member Projects",
        }
    }
    fn env_name(&self) -> &'static str {
        match self {
            RealmInfo::Drink => "DRINK",
            RealmInfo::Doors => "DOORS",
            RealmInfo::MemberProjects => "MEMBER_PROJECTS",
        }
    }
    fn get_auth_key(&self) -> String {
        env::var(format!("GK_REALM_{}_AUTH_KEY", self.env_name())).unwrap()
    }
    fn get_read_key(&self) -> String {
        env::var(format!("GK_REALM_{}_READ_KEY", self.env_name())).unwrap()
    }
    fn get_public_key(&self) -> String {
        env::var(format!("GK_REALM_{}_PUBLIC_KEY", self.env_name())).unwrap()
    }
    fn get_id(&self) -> u8 {
        match self {
            RealmInfo::Doors => 0,
            RealmInfo::Drink => 1,
            RealmInfo::MemberProjects => 2,
        }
    }
}

impl <'a> GateKeeperMemberListener<'a> {
    pub fn new_for_realm(nfc: &'a mut Nfc, conn_str: String, realm_detail: RealmInfo) -> Option<Self> {
        let nfc_device = nfc.gatekeeper_device(conn_str)
            .ok_or("failed to get gatekeeper device").unwrap();

        let realm = Realm::new(
            realm_detail.get_id(), realm_detail.get_name(), "",
            &realm_detail.get_auth_key(),
            &realm_detail.get_read_key(),
            // No write key:
            &"a".repeat(32),
            &realm_detail.get_public_key(),
            // No private key:
            &format!("-----BEGIN EC PRIVATE KEY-----\
{}\n-----END EC PRIVATE KEY-----\n", "a".repeat(224))
        ).unwrap();

        return Some(GateKeeperMemberListener {
            nfc_device,
            realm,
            http: reqwest::blocking::Client::new(),

            server_token: env::var("GK_SERVER_TOKEN").unwrap().to_string(),
            just_scanned: false,
            endpoint: env::var("GK_HTTP_ENDPOINT")
                .unwrap_or("http://localhost:3000".to_string()).to_string(),
            route: realm_detail.get_route(),
        });
    }

    pub fn new(nfc: &'a mut Nfc, conn_str: String) -> Option<Self> {
        Self::new_for_realm(nfc, conn_str, RealmInfo::MemberProjects)
    }

    pub fn poll_for_user(&mut self) -> Option<String> {
        let tag = self.nfc_device.first_tag();
        if let Some(mut tag) = tag {
            if self.just_scanned {
                thread::sleep(Duration::from_millis(250));
                return None;
            }
            if let Ok(association) = tag.authenticate(&mut self.realm) {
                self.just_scanned = true;
                return Some(association);
            }
        } else {
            self.just_scanned = false;
        }
        return None;
    }

    
    pub fn wait_for_user(&mut self) -> Option<String> {
        loop {
            if let Some(association) = self.poll_for_user() {
                return Some(association);
            } else {
                thread::sleep(Duration::from_millis(250));
            }
        }
    }

    pub fn fetch_user(&mut self, key: String) -> Result<Value, FetchError> {
        match self.http.get(
            format!("{}/{}/by-key/{}", self.endpoint.clone(), self.route, &key)
        ).header(AUTHORIZATION, self.server_token.clone()).send() {
            Ok(res) => {
                match res.status() {
                    StatusCode::OK => {
                        if let Ok(text) = res.text() {
                            if let Ok(value) = serde_json::from_str(&text) {
                                return Ok(value);
                            } else {
                                return Err(FetchError::ParseError);
                            }
                        } else {
                            return Err(FetchError::ParseError);
                        }
                    },
                    StatusCode::NOT_FOUND => {
                        return Err(FetchError::NotFound);
                    }
                    _ => {
                        return Err(FetchError::Unknown);
                    }
                }
            },
            Err(err) => {
                println!("Error fetching data for key: {:?}", err);
                return Err(FetchError::NetworkError);
            }
        }
    }
}
