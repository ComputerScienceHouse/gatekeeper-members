pub use gatekeeper_core::RealmType;
use gatekeeper_core::{GatekeeperReader, NfcTag, Realm, UndifferentiatedTag};
use reqwest::header::AUTHORIZATION;
use reqwest::StatusCode;
use serde_json::Value;
use std::env;
use std::result::Result;
use std::thread;
use std::time::Duration;

pub struct GateKeeperMemberListener<'a> {
    nfc_device: GatekeeperReader<'a>,
    http: reqwest::blocking::Client,

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

trait RealmTypeExt {
    fn get_route(&self) -> &'static str;
    fn env_name(&self) -> &'static str;
    fn get_auth_key(&self) -> Vec<u8>;
    fn get_read_key(&self) -> Vec<u8>;
    fn get_desfire_signing_public_key(&self) -> Vec<u8>;
    fn get_mobile_decryption_private_key(&self) -> Vec<u8>;
    fn get_mobile_signing_private_key(&self) -> Vec<u8>;
}

impl RealmTypeExt for RealmType {
    fn get_route(&self) -> &'static str {
        match self {
            Self::Door => "doors",
            Self::Drink => "drink",
            Self::MemberProjects => "projects",
        }
    }
    fn env_name(&self) -> &'static str {
        match self {
            Self::Door => "DOORS",
            Self::Drink => "DRINK",
            Self::MemberProjects => "MEMBER_PROJECTS",
        }
    }
    fn get_auth_key(&self) -> Vec<u8> {
        env::var(format!("GK_REALM_{}_AUTH_KEY", self.env_name()))
            .unwrap()
            .into_bytes()
    }
    fn get_read_key(&self) -> Vec<u8> {
        env::var(format!("GK_REALM_{}_READ_KEY", self.env_name()))
            .unwrap()
            .into_bytes()
    }
    fn get_desfire_signing_public_key(&self) -> Vec<u8> {
        env::var(format!("GK_REALM_{}_PUBLIC_KEY", self.env_name()))
            .unwrap()
            .into_bytes()
    }
    fn get_mobile_decryption_private_key(&self) -> Vec<u8> {
        env::var(format!(
            "GK_REALM_{}_MOBILE_CRYPT_PRIVATE_KEY",
            self.env_name()
        ))
        .unwrap()
        .into_bytes()
    }
    fn get_mobile_signing_private_key(&self) -> Vec<u8> {
        env::var(format!("GK_REALM_{}_MOBILE_PRIVATE_KEY", self.env_name()))
            .unwrap()
            .into_bytes()
    }
}

impl<'a> GateKeeperMemberListener<'a> {
    pub fn new(conn_str: String, realm_type: RealmType) -> Option<Self> {
        let realm = Realm::new(
            realm_type,
            realm_type.get_auth_key(),
            realm_type.get_read_key(),
            &realm_type.get_desfire_signing_public_key(),
            &realm_type.get_mobile_decryption_private_key(),
            &realm_type.get_mobile_signing_private_key(),
            None,
        );

        Some(GateKeeperMemberListener {
            nfc_device: GatekeeperReader::new(conn_str, realm)?,
            http: reqwest::blocking::Client::new(),

            server_token: env::var("GK_SERVER_TOKEN").unwrap(),
            just_scanned: false,
            endpoint: env::var("GK_HTTP_ENDPOINT")
                .unwrap_or_else(|_| "http://localhost:3000".to_string()),
            route: realm_type.get_route(),
        })
    }

    pub fn poll_for_tag(&mut self) -> Option<UndifferentiatedTag> {
        let nearby_tags = self.nfc_device.get_nearby_tags();
        if nearby_tags.is_empty() {
            self.just_scanned = false;
        }
        if self.just_scanned {
            thread::sleep(Duration::from_millis(250));
            return None;
        }
        self.just_scanned = !nearby_tags.is_empty();
        nearby_tags.into_iter().next()
    }

    pub fn poll_for_user(&mut self) -> Option<String> {
        self.poll_for_tag().and_then(|tag| tag.authenticate().ok())
    }

    pub fn wait_for_user(&mut self) -> Option<String> {
        loop {
            if let Some(association) = self.poll_for_user() {
                return Some(association);
            }
        }
    }

    pub fn fetch_user(&self, key: String) -> Result<Value, FetchError> {
        match self
            .http
            .get(format!(
                "{}/{}/by-key/{}",
                self.endpoint.clone(),
                self.route,
                &key
            ))
            .header(AUTHORIZATION, self.server_token.clone())
            .send()
        {
            Ok(res) => match res.status() {
                StatusCode::OK => {
                    if let Ok(text) = res.text() {
                        if let Ok(value) = serde_json::from_str(&text) {
                            Ok(value)
                        } else {
                            Err(FetchError::ParseError)
                        }
                    } else {
                        Err(FetchError::ParseError)
                    }
                }
                StatusCode::NOT_FOUND => Err(FetchError::NotFound),
                _ => Err(FetchError::Unknown),
            },
            Err(err) => {
                println!("Error fetching data for key: {:?}", err);
                Err(FetchError::NetworkError)
            }
        }
    }
}
