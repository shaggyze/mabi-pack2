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

// ── Maintenance windows ─────────────────────────────────────────────────────────
//
// Nexon's maintenance API answers 401 without a valid session, and during
// maintenance the account API answers 401/404 too, which looks like an expired
// session. The public news feed is the source that works logged out: a
// maintenance notice's Summary carries the window in Pacific time, e.g.
//   "Maintenance: October 22nd, 6:00 AM to 9:00 AM PDT"
//   "Maintenance: March 13th 10:00 AM ~ March 14th 8:30 AM PDT"
// and its Title gains "[COMPLETED]" once the servers are back.

/// A maintenance window read from a news notice (unix seconds, UTC).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MaintenanceWindow {
    pub title: String,
    pub url: String,
    pub start: i64,
    /// 0 when the notice gives no end time.
    pub end: i64,
}

/// A notice past its end by more than this is stale (Nexon forgot "[COMPLETED]").
const STALE_AFTER_END_SECS: i64 = 12 * 3600;

static TIME_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(
        r"(?i)(?:\b(january|february|march|april|may|june|july|august|september|october|november|december|jan|feb|mar|apr|jun|jul|aug|sept|sep|oct|nov|dec)\.?\s+(\d{1,2})(?:st|nd|rd|th)?,?\s*)?\b(\d{1,2}):(\d{2})\s*([ap])\.?m\b\.?(?:\s*(pdt|pst|pt)\b)?",
    )
    .expect("maintenance time regex")
});

fn month_number(name: &str) -> Option<u32> {
    let n = name.to_ascii_lowercase();
    const MONTHS: [&str; 12] = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
    MONTHS.iter().position(|m| n.starts_with(m)).map(|i| i as u32 + 1)
}

/// US Pacific offset from UTC in hours on `date`: -7 from the second Sunday of
/// March to the first Sunday of November (daylight time), else -8.
fn pacific_offset_hours(date: chrono::NaiveDate) -> i64 {
    use chrono::Datelike;
    let nth_sunday = |month: u32, n: u32| {
        let first = chrono::NaiveDate::from_ymd_opt(date.year(), month, 1).unwrap();
        let to_sunday = (7 - first.weekday().num_days_from_sunday()) % 7;
        first + chrono::Duration::days((to_sunday + 7 * (n - 1)) as i64)
    };
    if date >= nth_sunday(3, 2) && date < nth_sunday(11, 1) { -7 } else { -8 }
}

/// The window in a notice's Summary as unix seconds `(start, end)`; `end` is 0
/// when only a start time is given. `live_date` (the notice's ISO `LiveDate`)
/// supplies the year; `None` when no time is found.
pub fn parse_window(summary: &str, live_date: &str) -> Option<(i64, i64)> {
    use chrono::{Datelike, NaiveDate, NaiveTime};
    let posted = chrono::DateTime::parse_from_rfc3339(live_date).ok().map(|d| d.naive_utc().date());

    struct Part { month: Option<u32>, day: Option<u32>, h: u32, m: u32, tz: Option<i64> }
    let parts: Vec<Part> = TIME_RE
        .captures_iter(summary)
        .filter_map(|c| {
            let h12: u32 = c[3].parse().ok()?;
            let m: u32 = c[4].parse().ok()?;
            if !(1..=12).contains(&h12) || m > 59 {
                return None;
            }
            let h = h12 % 12 + if c[5].eq_ignore_ascii_case("p") { 12 } else { 0 };
            let tz = c.get(6).and_then(|z| match z.as_str().to_ascii_lowercase().as_str() {
                "pdt" => Some(-7),
                "pst" => Some(-8),
                _ => None, // "PT": by date
            });
            Some(Part {
                month: c.get(1).and_then(|x| month_number(x.as_str())),
                day: c.get(2).and_then(|x| x.as_str().parse().ok()),
                h,
                m,
                tz,
            })
        })
        .take(2)
        .collect();
    let first = parts.first()?;
    // "11:15AM PDT ~ 12:15 PM PDT" gives no date: use the day it was posted.
    let (month, day) = match (first.month, first.day) {
        (Some(m), Some(d)) => (m, d),
        _ => posted.map(|p| (p.month(), p.day()))?,
    };
    // The year the notice was posted; a January window posted in December is next year's.
    let mut year = posted.map(|d| d.year()).unwrap_or_else(|| chrono::Utc::now().year());
    if let Some(p) = posted {
        if p.month() >= 11 && month <= 2 {
            year += 1;
        }
    }
    // A part without its own zone takes the last stated one ("6:00 AM - 9:00 AM PDT").
    let stated_tz = parts.iter().rev().find_map(|p| p.tz);
    let to_unix = |date: NaiveDate, p: &Part| -> Option<i64> {
        let local = date.and_time(NaiveTime::from_hms_opt(p.h, p.m, 0)?);
        let off = p.tz.or(stated_tz).unwrap_or_else(|| pacific_offset_hours(date));
        Some(local.and_utc().timestamp() - off * 3600)
    };
    let start_date = NaiveDate::from_ymd_opt(year, month, day)?;
    let start = to_unix(start_date, first)?;
    let end = match parts.get(1) {
        None => 0,
        Some(p) => {
            let end_date = match (p.month, p.day) {
                (Some(m), Some(d)) => NaiveDate::from_ymd_opt(year + i32::from(m < month), m, d)?,
                _ => start_date,
            };
            let mut end = to_unix(end_date, p)?;
            // "11:00 PM ~ 1:30 AM" with no second date runs past midnight.
            if end <= start && p.month.is_none() {
                end += 24 * 3600;
            }
            end
        }
    };
    Some((start, end))
}

/// The maintenance notice in progress at `now`, if any: a maintenance item not
/// marked "[COMPLETED]"/"[RESOLVED]" whose window has started and has not ended
/// more than [`STALE_AFTER_END_SECS`] ago (a late notice usually means overtime).
pub fn active_maintenance_in(items: &[NewsItem], now: i64) -> Option<MaintenanceWindow> {
    items
        .iter()
        .filter(|n| n.maintenance)
        .filter(|n| {
            let t = n.title.to_ascii_uppercase();
            !t.contains("[COMPLETED]") && !t.contains("[RESOLVED]")
        })
        .filter_map(|n| {
            let (start, end) = parse_window(&n.summary, &n.date)?;
            let last = if end > 0 { end } else { start };
            (start <= now && now <= last + STALE_AFTER_END_SECS).then(|| MaintenanceWindow {
                title: n.title.clone(),
                url: n.url.clone(),
                start,
                end,
            })
        })
        .next()
}

/// [`active_maintenance_in`] for the live feed, cached for 60 s. A feed that
/// cannot be read counts as "no maintenance known".
pub fn active_maintenance() -> Option<MaintenanceWindow> {
    use std::sync::Mutex;
    use std::time::{Duration, Instant};
    static CACHE: Lazy<Mutex<Option<(Instant, Option<MaintenanceWindow>)>>> = Lazy::new(|| Mutex::new(None));
    // Unit tests of the auth retry paths must not reach the network.
    if cfg!(test) {
        return None;
    }
    if let Some((at, w)) = CACHE.lock().ok()?.as_ref() {
        if at.elapsed() < Duration::from_secs(60) {
            return w.clone();
        }
    }
    let now = chrono::Utc::now().timestamp();
    let w = match fetch_news() {
        Ok(items) => active_maintenance_in(&items, now),
        Err(e) => {
            log::warn!("[Launcher] Maintenance check: news feed unavailable: {}", e);
            None
        }
    };
    if let Ok(mut c) = CACHE.lock() {
        *c = Some((Instant::now(), w.clone()));
    }
    w
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

    fn utc(s: &str) -> i64 {
        chrono::DateTime::parse_from_rfc3339(s).unwrap().timestamp()
    }

    #[test]
    fn maintenance_windows_from_real_notices() {
        let cases: [(&str, &str, &str, Option<&str>); 9] = [
            ("Maintenance: October 22nd, 6:00 AM to 9:00 AM PDT", "2026-10-21T17:00:00Z",
             "2026-10-22T13:00:00Z", Some("2026-10-22T16:00:00Z")),
            ("Maintenance: October 15th, 7:00 AM - 12:00 PM PDT", "2026-10-14T17:15:00Z",
             "2026-10-15T14:00:00Z", Some("2026-10-15T19:00:00Z")),
            ("Maintenance: March 13th 10:00 AM ~ March 14th 8:30 AM PDT", "2026-03-13T10:00:00Z",
             "2026-03-13T17:00:00Z", Some("2026-03-14T15:30:00Z")),
            ("Maintenance: March 8th, 1:45 AM PST - 4:00 AM PDT", "2026-03-06T17:00:00Z",
             "2026-03-08T09:45:00Z", Some("2026-03-08T11:00:00Z")),
            ("Maintenance: February 26th, 5:00 AM PST - 10:00 AM PST", "2026-02-25T17:00:00Z",
             "2026-02-26T13:00:00Z", Some("2026-02-26T18:00:00Z")),
            // "PT" and no zone: Pacific by date (March 22nd is daylight time).
            ("Maintenance: March 22nd 3:00 PM ~ 6:37 PM PT", "2026-03-22T14:00:00Z",
             "2026-03-22T22:00:00Z", Some("2026-03-23T01:37:00Z")),
            ("Maintenance: January 9th 3:00 PM ~ 5:00 PM PST", "2026-01-09T13:00:00Z",
             "2026-01-09T23:00:00Z", Some("2026-01-10T01:00:00Z")),
            // Posted in December for January: next year.
            ("Maintenance: January 1st, 7:00 AM PST - 10:00 AM PST", "2025-12-23T17:00:00Z",
             "2026-01-01T15:00:00Z", Some("2026-01-01T18:00:00Z")),
            // Start only.
            ("[COMPLETED] Maintenance: May 13th, 12:55 AM PDT", "2026-05-13T00:55:00Z",
             "2026-05-13T07:55:00Z", None),
        ];
        for (summary, live, start, end) in cases {
            let (s, e) = parse_window(summary, live).unwrap_or_else(|| panic!("no window: {}", summary));
            assert_eq!(s, utc(start), "start of {}", summary);
            assert_eq!(e, end.map(utc).unwrap_or(0), "end of {}", summary);
        }
        // No date in the text: the posting day.
        let (s, e) = parse_window("Connection Issues: 11:15AM PDT ~ 12:15 PM PDT", "2026-10-06T11:30:00Z").unwrap();
        assert_eq!((s, e), (utc("2026-10-06T18:15:00Z"), utc("2026-10-06T19:15:00Z")));
        assert_eq!(parse_window("Event Dates: October 15th ~ November 12th", "2026-10-14T17:00:00Z"), None);
    }

    #[test]
    fn active_maintenance_needs_an_open_window() {
        let item = |title: &str, summary: &str| NewsItem {
            id: 1,
            category: "maintenance".into(),
            title: title.into(),
            summary: summary.into(),
            url: String::new(),
            date: "2026-10-21T17:00:00Z".into(),
            image: String::new(),
            maintenance: true,
        };
        let open = [item("Scheduled Maintenance - October 22nd", "Maintenance: October 22nd, 6:00 AM to 9:00 AM PDT")];
        let done = [item("[COMPLETED] Scheduled Maintenance - October 22nd", "Maintenance: October 22nd, 6:00 AM to 9:00 AM PDT")];
        let during = utc("2026-10-22T14:00:00Z");
        let w = active_maintenance_in(&open, during).expect("in progress");
        assert_eq!(w.end, utc("2026-10-22T16:00:00Z"));
        assert!(active_maintenance_in(&done, during).is_none(), "completed");
        assert!(active_maintenance_in(&open, utc("2026-10-22T12:00:00Z")).is_none(), "not started");
        assert!(active_maintenance_in(&open, utc("2026-10-22T18:00:00Z")).is_some(), "overtime, not completed yet");
        assert!(active_maintenance_in(&open, utc("2026-10-23T05:00:00Z")).is_none(), "stale notice");
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
