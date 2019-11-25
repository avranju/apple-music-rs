use std::ops::Add;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use biscuit::jwa::SignatureAlgorithm;
use biscuit::jws::{Header, RegisteredHeader, Secret};
use biscuit::{ClaimsSet, Empty, RegisteredClaims, JWT};
use pem::Pem;
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde::{Deserialize, Serialize};

use crate::error::Error;

#[derive(Serialize, Deserialize, Debug)]
struct KeyInfo {
    #[serde(rename = "kid")]
    key_id: String,
}

pub struct TokenService {
    key_id: String,
    team_id: String,
    private_key: Pem,
}

impl Clone for TokenService {
    fn clone(&self) -> Self {
        TokenService {
            key_id: self.key_id.clone(),
            team_id: self.team_id.clone(),
            private_key: Pem {
                tag: self.private_key.tag.clone(),
                contents: self.private_key.contents.clone(),
            },
        }
    }
}

impl TokenService {
    pub fn new(key_id: &str, team_id: &str, private_key_pem: &str) -> Result<Self, Error> {
        let token = TokenService {
            key_id: key_id.to_string(),
            team_id: team_id.to_string(),
            private_key: pem::parse(private_key_pem)?,
        };

        Ok(token)
    }

    pub fn gen_token(&self, expiry: Duration) -> Result<String, Error> {
        let claims = ClaimsSet::<Empty> {
            registered: RegisteredClaims {
                issuer: Some(FromStr::from_str(&self.team_id)?),
                expiry: Some(From::from(
                    SystemTime::now()
                        .add(expiry)
                        .duration_since(UNIX_EPOCH)?
                        .as_secs() as i64,
                )),
                issued_at: Some(From::from(
                    SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64,
                )),
                ..Default::default()
            },
            private: Default::default(),
        };

        let token = JWT::new_decoded(
            Header {
                registered: RegisteredHeader {
                    algorithm: SignatureAlgorithm::ES256,
                    ..Default::default()
                },
                private: KeyInfo {
                    key_id: self.key_id.clone(),
                },
            },
            claims,
        );

        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &self.private_key.contents)?;
        let secret = Secret::EcdsaKeyPair(Arc::new(key_pair));
        let signed_token = token.into_encoded(&secret)?;

        Ok(serde_json::to_string(&signed_token)?)
    }
}
