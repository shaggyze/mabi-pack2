// Nexon Mabinogi news feed (right-hand launcher panel).
//
// Nexon news feed:
//   GET https://nxl.nxfs.nexon.com/news/regions/1/<product>/en-US/list.json
//   → JSON array of { Id, Category, Title, Summary, LiveDate, ImageThumbnail2 }.
//
// Public endpoint — no auth. Display only; never used for launch/licensing.
// Each item's article URL is built from its id + a slug of the title, the way
// the launcher's "open news" link does.

use anyhow::{anyhow, Result};
use once_cell::sync::Lazy;
use serde::Serialize;

use super::auth;

const NEWS_URL: &str = "https://nxl.nxfs.nexon.com/news/regions/1/{}/en-US/list.json";
const NEWS_UA: &str = "NexonLauncher.nxl-release-18.14.10-220-fc7480c-coreapp-3.3.0";
const NEWS_HUB: &str = "https://www.nexon.com/mabinogi/news";

static CLIENT: Lazy<reqwest::blocking::Client> = Lazy::new(|| {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .user_agent(NEWS_UA)
        .build()
        .expect("failed to build news HTTP client")
});

#[derive(Debug, Clone, Serialize)]
pub struct NewsItem {
    pub id: i64,
    pub category: String,
    pub title: String,
    pub summary: String,
    /// Article URL built from the id + a slug of the title.
    pub url: String,
    /// Raw `LiveDate` (ISO-8601 UTC) as served.
    pub date: String,
    /// Thumbnail image URL (`ImageThumbnail2`), empty if none.
    pub image: String,
    /// True for a maintenance notice.
    pub maintenance: bool,
}

/// Fetch the Nexon news list for the active product (see [`auth::product_id`]).
pub fn fetch_news() -> Result<Vec<NewsItem>> {
    fetch_news_for(auth::product_id())
}

/// Fetch the news list for a specific product id.
pub fn fetch_news_for(product_id: u32) -> Result<Vec<NewsItem>> {
    let url = NEWS_URL.replace("{}", &product_id.to_string());
    let resp = CLIENT.get(&url).send()?;
    let status = resp.status();
    let body = resp.text().unwrap_or_default();
    if !status.is_success() {
        return Err(anyhow!("news feed HTTP {}", status));
    }
    parse_news(&body)
}

/// Parse the news `list.json` body into items (public for testing).
pub fn parse_news(body: &str) -> Result<Vec<NewsItem>> {
    let arr: serde_json::Value = serde_json::from_str(body).map_err(|e| anyhow!("news JSON: {}", e))?;
    let arr = arr.as_array().ok_or_else(|| anyhow!("news feed is not a JSON array"))?;
    let mut out = Vec::with_capacity(arr.len());
    for v in arr {
        let id = v["Id"].as_i64().unwrap_or(0);
        let title = v["Title"].as_str().unwrap_or("").to_string();
        let category = v["Category"].as_str().unwrap_or("").to_string();
        out.push(NewsItem {
            url: build_news_url(id, &title),
            summary: v["Summary"].as_str().unwrap_or("").to_string(),
            date: v["LiveDate"].as_str().unwrap_or("").to_string(),
            image: v["ImageThumbnail2"].as_str().unwrap_or("").to_string(),
            maintenance: category.eq_ignore_ascii_case("maintenance"),
            category,
            title,
            id,
        });
    }
    Ok(out)
}

/// Build the article URL from a feed item's id + title, e.g.
/// `(-44611, "[COMPLETED] Unscheduled Maintenance")`
/// → `https://www.nexon.com/mabinogi/news/44611/unscheduled-maintenance`.
/// Falls back to the news hub when the slug would be empty.
pub fn build_news_url(id: i64, title: &str) -> String {
    let id_abs = id.unsigned_abs();
    // Strip leading "[tag] " markers.
    let mut s = title.to_lowercase();
    while s.starts_with('[') {
        match s.find(']') {
            Some(p) => s = s[p + 1..].trim().to_string(),
            None => break,
        }
    }
    let mut slug = String::new();
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch);
        } else if !slug.is_empty() && !slug.ends_with('-') {
            slug.push('-');
        }
    }
    let slug = slug.trim_end_matches('-');
    if slug.is_empty() {
        NEWS_HUB.to_string()
    } else {
        format!("{}/{}/{}", NEWS_HUB, id_abs, slug)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugifies_and_strips_tags() {
        assert_eq!(
            build_news_url(-44611, "[COMPLETED] Unscheduled Maintenance - August 28th"),
            "https://www.nexon.com/mabinogi/news/44611/unscheduled-maintenance-august-28th"
        );
        assert_eq!(build_news_url(0, "[tag]"), NEWS_HUB);
    }

    #[test]
    fn parses_list_json() {
        let body = r#"[
            {"Id":44611,"Category":"maintenance","Title":"Server Down","Summary":"s","LiveDate":"2026-08-28T15:00:00Z","ImageThumbnail2":"https://img/x.png"},
            {"Id":100,"Category":"events","Title":"Fun Event","Summary":"","LiveDate":"","ImageThumbnail2":""}
        ]"#;
        let items = parse_news(body).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].title, "Server Down");
        assert!(items[0].maintenance);
        assert_eq!(items[0].image, "https://img/x.png");
        assert_eq!(items[0].url, "https://www.nexon.com/mabinogi/news/44611/server-down");
        assert!(!items[1].maintenance);
    }
}
