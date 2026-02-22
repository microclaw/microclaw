use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use matrix_sdk::authentication::matrix::MatrixSession;
use matrix_sdk::config::SyncSettings;
use matrix_sdk::deserialized_responses::EncryptionInfo;
use matrix_sdk::ruma::events::room::message::{
    MessageType, RoomMessageEventContent, SyncRoomMessageEvent,
};
use matrix_sdk::ruma::{OwnedDeviceId, OwnedRoomId, OwnedUserId};
use matrix_sdk::{Client, SessionMeta, SessionTokens};
use serde::Deserialize;
use tokio::sync::mpsc;

#[derive(Deserialize)]
struct MatrixWhoAmIResponse {
    user_id: String,
    #[serde(default)]
    device_id: Option<String>,
}

fn parse_args() -> Result<HashMap<String, String>, String> {
    let mut out = HashMap::new();
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        if !arg.starts_with("--") {
            return Err(format!("unexpected argument: {arg}"));
        }
        let key = arg.trim_start_matches("--").to_string();
        let Some(value) = it.next() else {
            return Err(format!("missing value for argument: --{key}"));
        };
        out.insert(key, value);
    }
    Ok(out)
}

fn required(args: &HashMap<String, String>, key: &str) -> Result<String, String> {
    args.get(key)
        .cloned()
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| format!("missing required argument: --{key}"))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args().map_err(|e| format!("argument error: {e}"))?;
    let homeserver_url = required(&args, "homeserver-url")?;
    let access_token = required(&args, "access-token")?;
    let room_id_raw = required(&args, "room-id")?;
    let bot_user_id_raw = required(&args, "bot-user-id")?;
    let message = required(&args, "message")?;
    let timeout_secs: u64 = args
        .get("timeout-secs")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(60);

    let room_id: OwnedRoomId = room_id_raw
        .parse()
        .map_err(|e| format!("invalid room id '{room_id_raw}': {e}"))?;
    let bot_user_id: OwnedUserId = bot_user_id_raw
        .parse()
        .map_err(|e| format!("invalid bot user id '{bot_user_id_raw}': {e}"))?;

    let client = Client::builder()
        .homeserver_url(homeserver_url.clone())
        .build()
        .await?;

    let whoami_url = format!(
        "{}/_matrix/client/v3/account/whoami",
        homeserver_url.trim_end_matches('/')
    );
    let whoami = reqwest::Client::new()
        .get(whoami_url)
        .bearer_auth(access_token.trim())
        .send()
        .await?
        .error_for_status()?
        .json::<MatrixWhoAmIResponse>()
        .await?;

    let user_id: OwnedUserId = whoami
        .user_id
        .parse()
        .map_err(|e| format!("invalid whoami user_id: {e}"))?;
    let Some(device_id_raw) = whoami.device_id else {
        return Err("whoami missing device_id".into());
    };
    let device_id: OwnedDeviceId = device_id_raw.into();

    let session = MatrixSession {
        meta: SessionMeta { user_id, device_id },
        tokens: SessionTokens {
            access_token,
            refresh_token: None,
        },
    };

    client
        .matrix_auth()
        .restore_session(session, matrix_sdk::store::RoomLoadSettings::default())
        .await?;

    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let watched_room = room_id.clone();
    let watched_bot = bot_user_id.clone();
    let tx = Arc::new(tx);
    client.add_event_handler(
        move |ev: SyncRoomMessageEvent,
              room: matrix_sdk::Room,
              encryption_info: Option<EncryptionInfo>| {
            let tx = tx.clone();
            let watched_room = watched_room.clone();
            let watched_bot = watched_bot.clone();
            async move {
                if encryption_info.is_none() {
                    return;
                }
                let watched_room_ref: &matrix_sdk::ruma::RoomId =
                    <OwnedRoomId as AsRef<matrix_sdk::ruma::RoomId>>::as_ref(&watched_room);
                if room.room_id() != watched_room_ref {
                    return;
                }
                let SyncRoomMessageEvent::Original(ev) = ev else {
                    return;
                };
                if ev.sender != watched_bot {
                    return;
                }
                let body = match &ev.content.msgtype {
                    MessageType::Text(text) => text.body.clone(),
                    _ => return,
                };
                let _ = tx.send(body);
            }
        },
    );

    client
        .sync_once(SyncSettings::default().timeout(Duration::from_millis(500)))
        .await?;

    let room = client
        .get_room(&room_id)
        .ok_or_else(|| format!("room {room_id} not found in client store"))?;
    room.send(RoomMessageEventContent::text_plain(message))
        .await?;

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        if let Ok(body) = rx.try_recv() {
            println!("{body}");
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for encrypted reply from {} in {}",
                bot_user_id, room_id
            )
            .into());
        }
        client
            .sync_once(SyncSettings::default().timeout(Duration::from_millis(2_000)))
            .await?;
    }
}
