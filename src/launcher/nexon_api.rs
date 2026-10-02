use anyhow::{anyhow, Result};
use reqwest::blocking::{Client, Response};
use serde::{Deserialize, Serialize};

const NEXON_BASE: &str = "https://www.nexon.com";
const PRODUCT_ID: &str = "10200";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NexonSession {
    pub access_token: String,
    pub g_access_token: String,
    pub session_token: String,
    pub hashed_user_id: String,
}

impl NexonSession {
    pub fn cookie_header(&self) -> String {
        format!(
            "AToken={}; g_AToken={}; NxLSession={}; NexonUserID={}",
            self.access_token, self.g_access_token, self.session_token, self.hashed_user_id
        )
    }
}

pub struct NexonApiClient {
    pub session: NexonSession,
    client: Client,
}

impl NexonApiClient {
    pub fn new(session: NexonSession) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("NexonLauncher.nxl-release-18.14.10-220-fc7480c-coreapp-3.3.0")
            .build()?;
        Ok(Self { session, client })
    }

    /// Check if the game is accessible (playable) with the current session.
    pub fn is_playable(&self) -> Result<bool> {
        #[derive(Serialize)]
        struct Req<'a> {
            #[serde(rename = "productId")]
            product_id: &'a str,
        }

        let resp = self.client
            .post(format!("{}/api/game-auth2/v1/playable", NEXON_BASE))
            // 401 AUTH FIX: Only send Cookie header, do NOT send Authorization: Bearer. 
            // Sending Bearer with wrong scope causes 401 and prevents cookie refresh.
            .header("Cookie", self.session.cookie_header())
            .json(&Req { product_id: PRODUCT_ID })
            .send()?;

        Ok(resp.status().is_success())
    }

    /// Get a passport token needed as the `/P:` argument when launching Client.exe.
    pub fn get_passport(&self) -> Result<String> {
        #[derive(Serialize)]
        struct Req<'a> {
            #[serde(rename = "productId")]
            product_id: &'a str,
        }
        #[derive(Deserialize)]
        struct Resp {
            passport: Option<String>,
        }

        let resp = self.client
            .post(format!("{}/api/passport/v2/passport", NEXON_BASE))
            // 401 AUTH FIX applies here as well.
            .header("Cookie", self.session.cookie_header())
            .json(&Req { product_id: PRODUCT_ID })
            .send()?;

        let status = resp.status();
        let body = resp.text().unwrap_or_default();

        if status.as_u16() == 401 {
            return Err(anyhow!("Passport 401 Unauthorized: Session is stale or invalid scope."));
        }

        if !status.is_success() {
            return Err(anyhow!("Passport request failed ({}): {}", status, body));
        }

        let parsed: Resp = serde_json::from_str(&body)
            .map_err(|e| anyhow!("Passport parse error ({}): body={}", e, body))?;

        parsed.passport.ok_or_else(|| anyhow!("Passport response has no passport field"))
    }
}
