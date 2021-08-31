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
    just_scanned: bool
}

pub enum FetchError {
    NotFound,
    ParseError,
    NetworkError,
    Unknown,
}

impl <'a> GateKeeperMemberListener<'a> {
    pub fn new(nfc: &'a mut Nfc, conn_str: String) -> Option<Self> {
        let nfc_device = nfc.gatekeeper_device(conn_str)
            .ok_or("failed to get gatekeeper device").unwrap();

        let realm = Realm::new(
            2, "Member Projects", "",
            &env::var("GK_REALM_MEMBER_PROJECTS_AUTH_KEY").unwrap().to_string(),
            &env::var("GK_REALM_MEMBER_PROJECTS_READ_KEY").unwrap().to_string(),
            &env::var("GK_REALM_MEMBER_PROJECTS_UPDATE_KEY").unwrap().to_string(),
            &env::var("GK_REALM_MEMBER_PROJECTS_PUBLIC_KEY").unwrap().to_string(),
            &env::var("GK_REALM_MEMBER_PROJECTS_PRIVATE_KEY").unwrap().to_string()
        ).unwrap();

        return Some(GateKeeperMemberListener {
            nfc_device,
            realm,
            http: reqwest::blocking::Client::new(),

            server_token: env::var("GK_SERVER_TOKEN").unwrap().to_string(),
            just_scanned: false,
            endpoint: env::var("GK_HTTP_ENDPOINT")
                .unwrap_or("http://localhost:3000".to_string()).to_string()
        });
    }
    
    pub fn wait_for_user(&mut self) -> Option<String> {
        loop {
            let tag = self.nfc_device.first_tag();
            if let Some(mut tag) = tag {
                if self.just_scanned {
                    thread::sleep(Duration::from_millis(250));
                    continue;
                }
                if let Ok(association) = tag.authenticate(&mut self.realm) {
                    self.just_scanned = true;
                    return Some(association);
                }
            } else {
                self.just_scanned = false;
            }
            thread::sleep(Duration::from_millis(250));
        }
    }

    pub fn fetch_user(&mut self, key: String) -> Result<Value, FetchError> {
        match self.http.get(
            self.endpoint.clone() + "/projects/by-key/" + &key
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
