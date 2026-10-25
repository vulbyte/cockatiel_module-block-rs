//! block — moderator blocking + user appeals.
//!
//! A mod-gated moderation module. Moderators block/unblock users (the actual
//! block lives in the engine's user DB); blocked users may file an appeal,
//! which is logged locally and can be resolved (approve → unblock, deny) by a
//! moderator of sufficient authority.
//!
//!   `!block <user> [reason]`   block a user (mod-gated)
//!   `!ban <user> [reason]`     alias of `!block`
//!   `!unblock <user>`          unblock a user (mod-gated)
//!   `!unban <user>`            alias of `!unblock`
//!   `!appeal <text>`           file an appeal (banned users only; logged, trigger message deleted)
//!   `!appeals`                 list pending appeals (mod-gated)
//!   `!appeal approve <id>`     approve an appeal → emit an unblock (mod-gated)
//!   `!appeal deny <id>`        deny an appeal (mod-gated)
//!
//! The block/unblock are performed by emitting a `DatabaseQuery` with the ids
//! `"userdb_block"` / `"userdb_unblock"` and a JSON payload the engine's user DB
//! understands (the same shape the reprimand module uses).
//!
//! Appeals are persisted as a JSON array in `<data_dir>/appeals.json`
//! (`module_specific.data_dir`, default `~/.cockatiel/block/`).

use futures_util::{SinkExt, StreamExt};
use prost::Message;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::Mutex as AsyncMutex;
use tokio_tungstenite::tungstenite::protocol::Message as WsMessage;
use tracing::{info, warn};
use tracing_subscriber::FmtSubscriber;

use cockatiel_client::proto::container_for_engine::Payload as EnginePayload;
use cockatiel_client::proto::container_for_module::Payload as ModulePayload;
use cockatiel_client::proto::*;
use cockatiel_client::CockatielClient;

type WsWriteHalf = futures_util::stream::SplitSink<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    WsMessage,
>;

const BLOCK_COMMAND: &str = "block";
const UNBLOCK_COMMAND: &str = "unblock";
/// Aliases for `!block` / `!unblock`; normalized to their canonical command
/// before handling so behaviour (gating, reply, query) is identical.
const BAN_COMMAND: &str = "ban";
const UNBAN_COMMAND: &str = "unban";
const APPEAL_COMMAND: &str = "appeal";
const APPEALS_COMMAND: &str = "appeals";
/// Every command this module owns. Incoming commands outside this set are
/// ignored (the engine routes registered commands; anything else is not ours).
const COMMANDS: [&str; 6] = [
    BLOCK_COMMAND,
    BAN_COMMAND,
    UNBLOCK_COMMAND,
    UNBAN_COMMAND,
    APPEAL_COMMAND,
    APPEALS_COMMAND,
];

const DEFAULT_FLAG: &str = "!";
const DEFAULT_DATA_DIR: &str = "~/.cockatiel/block";
const DEFAULT_BLOCK_AUTHORITY: &str = "mod";
const DEFAULT_APPROVE_AUTHORITY: &str = "mod";
const DEFAULT_RECONNECT_BASE_SECS: u32 = 1;
const DEFAULT_RECONNECT_MAX_SECS: u32 = 30;

// ── config ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Settings {
    command_flag: String,
    data_dir: String,
    /// Minimum role required for `!block` / `!unblock` / `!appeals`.
    block_authority: String,
    /// Minimum role required to approve/deny an appeal.
    approve_authority: String,
    reconnect_base_secs: u32,
    reconnect_max_secs: u32,
}

/// Read `module_specific`, filling any missing keys with defaults and writing
/// them back so every knob is editable in place in the module manager.
fn ensure_defaults() -> Settings {
    let root: Option<serde_json::Value> = std::fs::read_to_string("config.json")
        .ok()
        .and_then(|d| serde_json::from_str(&d).ok());
    let ms = root
        .as_ref()
        .and_then(|r| r.get("module_specific"))
        .and_then(|m| m.as_object())
        .cloned()
        .unwrap_or_default();
    let s = |k: &str, d: &str| ms.get(k).and_then(|v| v.as_str()).unwrap_or(d).to_string();
    let command_flag = s("command_flag", DEFAULT_FLAG);
    let data_dir = s("data_dir", DEFAULT_DATA_DIR);
    let block_authority = s("block_authority", DEFAULT_BLOCK_AUTHORITY);
    let approve_authority = s("approve_authority", DEFAULT_APPROVE_AUTHORITY);
    let reconnect_base_secs = ms
        .get("reconnect_base_secs")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .unwrap_or(DEFAULT_RECONNECT_BASE_SECS);
    let reconnect_max_secs = ms
        .get("reconnect_max_secs")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .unwrap_or(DEFAULT_RECONNECT_MAX_SECS);
    if let Some(mut root) = root {
        if let Some(obj) = root.as_object_mut() {
            if let Some(ms) = obj
                .entry("module_specific".to_string())
                .or_insert_with(|| serde_json::json!({}))
                .as_object_mut()
            {
                ms.entry("command_flag".to_string())
                    .or_insert_with(|| serde_json::json!(command_flag));
                ms.entry("data_dir".to_string())
                    .or_insert_with(|| serde_json::json!(data_dir));
                ms.entry("block_authority".to_string())
                    .or_insert_with(|| serde_json::json!(block_authority));
                ms.entry("approve_authority".to_string())
                    .or_insert_with(|| serde_json::json!(approve_authority));
                ms.entry("reconnect_base_secs".to_string())
                    .or_insert_with(|| serde_json::json!(reconnect_base_secs));
                ms.entry("reconnect_max_secs".to_string())
                    .or_insert_with(|| serde_json::json!(reconnect_max_secs));
            }
            let _ = std::fs::write("config.json", serde_json::to_string_pretty(&root).unwrap());
        }
    }
    Settings {
        command_flag,
        data_dir,
        block_authority,
        approve_authority,
        reconnect_base_secs,
        reconnect_max_secs,
    }
}

/// Expand a leading `~` to `$HOME` (module config paths are written by hand).
fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{home}/{rest}");
        }
    } else if path == "~" {
        if let Ok(home) = std::env::var("HOME") {
            return home;
        }
    }
    path.to_string()
}

// ── pure helpers (unit-tested) ──────────────────────────────────────────────

/// Extract the positional args from a routed command. The engine already parsed
/// the command (it attached `chat.command`), so we only strip the
/// `<flag><command>` prefix and keep everything after verbatim. This module
/// registers NO flags, so a `-word` inside an argument is text, not a flag.
fn strip_command(raw: &str, flag: &str, name: &str) -> String {
    let mut rest = raw.trim().to_string();
    if let Some(idx) = rest.find(flag) {
        rest = rest[idx + flag.len()..].trim_start().to_string();
    }
    if rest.starts_with(name) {
        rest = rest[name.len()..].trim_start().to_string();
    }
    rest
}

/// Split a string into its first whitespace-delimited token and the trimmed
/// remainder (empty string when there is no remainder).
fn split_once_ws(s: &str) -> (&str, &str) {
    let s = s.trim();
    match s.split_once(char::is_whitespace) {
        Some((h, r)) => (h, r.trim()),
        None => (s, ""),
    }
}

/// Whether the actor holds at least the configured authority. `"owner"`
/// requires owner; `"admin"` requires admin or owner; anything else (default
/// `"mod"`) requires moderator, admin, or owner. An absent/missing user is
/// never authorized.
fn has_authority(user_data: Option<&UserData>, authority: &str) -> bool {
    let Some(u) = user_data else { return false };
    match authority.to_ascii_lowercase().as_str() {
        "owner" => u.is_owner,
        "admin" => u.is_owner || u.is_admin,
        _ => u.is_owner || u.is_admin || u.is_moderator,
    }
}

/// Whether the message author currently has at least one active ban, as
/// enriched by the engine into `chat.user_data.bans` (a `Ban` with
/// `unbanned == false`). Only banned users may appeal.
///
/// NOTE: "banned in a specific module" is not surfaced here — a per-module ban
/// would need the engine to populate module-scoped ban entries, which depends
/// on the not-yet-landed per-module bans feature. When it lands, extend this
/// predicate to consider that source too.
fn user_is_banned(chat: &ChatMessage) -> bool {
    chat.user_data
        .as_ref()
        .map(|u| u.bans.iter().any(|b| !b.unbanned))
        .unwrap_or(false)
}

/// The actor block for a DatabaseQuery payload: who triggered the action.
fn actor_json(chat: &ChatMessage) -> serde_json::Value {
    serde_json::json!({
        "uuid7": chat.user_uuid7,
        "platform": chat.platform,
        "handle": chat
            .user_data
            .as_ref()
            .map(|u| u.username.clone())
            .unwrap_or_default(),
    })
}

/// Pull the platform message id out of the adapter's raw message JSON
/// (`raw_data`). The Discord gateway payload carries a top-level `"id"`.
/// Missing/unparseable → empty (so no delete is attempted).
fn platform_message_id(raw_data: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(raw_data)
        .ok()
        .and_then(|v| v.get("id").and_then(|x| x.as_str()).map(|s| s.to_string()))
        .unwrap_or_default()
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ── appeals store (JSON) ────────────────────────────────────────────────────

/// One filed appeal. `text` is never echoed back to chat.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Appeal {
    id: String,
    user_uuid7: String,
    platform: String,
    handle: String,
    channel: String,
    text: String,
    at: i64,
    status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resolved_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resolved_at: Option<i64>,
}

/// The `<data_dir>/appeals.json` array, read-modify-written per operation (the
/// module runs a single loop, so no locking is needed).
struct Appeals {
    dir: String,
}

impl Appeals {
    fn new(dir: String) -> Self {
        Self { dir }
    }

    fn path(&self) -> String {
        format!("{}/appeals.json", expand_tilde(&self.dir).trim_end_matches('/'))
    }

    fn load(&self) -> Vec<Appeal> {
        std::fs::read_to_string(self.path())
            .ok()
            .and_then(|d| serde_json::from_str(&d).ok())
            .unwrap_or_default()
    }

    fn save(&self, appeals: &[Appeal]) -> Result<(), String> {
        let path = self.path();
        if let Some(parent) = std::path::Path::new(&path).parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let body = serde_json::to_string_pretty(appeals).map_err(|e| e.to_string())?;
        std::fs::write(&path, body).map_err(|e| e.to_string())
    }

    fn append(&self, appeal: Appeal) -> Result<(), String> {
        let mut all = self.load();
        all.push(appeal);
        self.save(&all)
    }

    /// Find an appeal by full id or unambiguous id prefix.
    fn find(&self, id: &str) -> Option<Appeal> {
        self.load().into_iter().find(|a| a.id == id || a.id.starts_with(id))
    }

    /// Every appeal still awaiting a decision, in filing order.
    fn pending(&self) -> Vec<Appeal> {
        self.load().into_iter().filter(|a| a.status == "pending").collect()
    }

    /// Resolve a pending appeal by id/prefix, recording who resolved it and
    /// when. Returns whether a pending appeal was matched.
    fn resolve(&self, id: &str, status: &str, resolver: &str) -> Result<bool, String> {
        let mut all = self.load();
        let mut found = false;
        for a in all.iter_mut() {
            if a.status == "pending" && (a.id == id || a.id.starts_with(id)) {
                a.status = status.to_string();
                a.resolved_by = Some(resolver.to_string());
                a.resolved_at = Some(now_ms());
                found = true;
            }
        }
        if found {
            self.save(&all)?;
        }
        Ok(found)
    }
}

// ── engine plumbing ─────────────────────────────────────────────────────────

/// Session identity (auth token + module ids) shared between the read loop and
/// the query sender so a reconnect's fresh credentials are picked up by both.
#[derive(Clone)]
struct EngineIdentity {
    auth: String,
    instance: String,
    module: String,
}

/// A block/unblock command awaiting the engine's answer. The engine's
/// `DatabaseQueryResult` only carries the (shared) `query_id`, so the context
/// needed to report a failure back to the channel is stashed here, FIFO per
/// query id.
struct PendingBlock {
    chat: ChatMessage,
    handle: String,
    is_block: bool,
}

/// Encode and send a ContainerForEngine on the shared write half.
async fn send_container(write: &Arc<AsyncMutex<WsWriteHalf>>, container: ContainerForEngine) {
    let mut buf = Vec::new();
    if container.encode(&mut buf).is_ok() {
        let mut w = write.lock().await;
        let _ = w.send(WsMessage::Binary(buf)).await;
    }
}

/// Register the module's chat commands with the engine. Called on every fresh
/// session (initial connect and each reconnect — the engine forgets a session's
/// commands when the socket drops).
async fn register_commands(
    write: &Arc<AsyncMutex<WsWriteHalf>>,
    identity: &Arc<AsyncMutex<EngineIdentity>>,
    command_flag: &str,
) {
    let id = identity.lock().await.clone();
    let cmd = |name: &str, desc: &str| Command {
        command_name: name.to_string(),
        command_flag: command_flag.to_string(),
        command_description: desc.to_string(),
        command_flags: vec![],
    };
    let commands = ContainerForEngine {
        version: 2,
        auth_token: id.auth,
        module_name: id.module,
        module_instance_uuid7: id.instance,
        payload: Some(EnginePayload::Commands(Commands {
            commands: vec![
                cmd(BLOCK_COMMAND, "block a user (moderator only)"),
                cmd(BAN_COMMAND, "block a user, alias of !block (moderator only)"),
                cmd(UNBLOCK_COMMAND, "unblock a user (moderator only)"),
                cmd(UNBAN_COMMAND, "unblock a user, alias of !unblock (moderator only)"),
                cmd(APPEAL_COMMAND, "file an appeal, or approve/deny one (moderator only)"),
                cmd(APPEALS_COMMAND, "list pending appeals (moderator only)"),
            ],
            alert_on_unknown_command: false,
        })),
    };
    send_container(write, commands).await;
    info!(
        "registered !{} / !{} / !{} / !{} / !{} / !{} commands",
        BLOCK_COMMAND,
        BAN_COMMAND,
        UNBLOCK_COMMAND,
        UNBAN_COMMAND,
        APPEAL_COMMAND,
        APPEALS_COMMAND
    );
}

/// Build a base SendToPlatforms (actor = the chat author).
fn base_send(id: &EngineIdentity, chat: &ChatMessage, msg: String) -> SendToPlatforms {
    let handle = chat
        .user_data
        .as_ref()
        .map(|u| u.username.clone())
        .unwrap_or_default();
    SendToPlatforms {
        msg,
        level: 0,
        module_uuid7: id.instance.clone(),
        pid: String::new(),
        platform: chat.platform.clone(),
        actor_platform: chat.platform.clone(),
        actor_handle: handle,
        actor_uuid7: chat.user_uuid7.clone(),
        channel_id: chat.channel_id.clone(),
        ..Default::default()
    }
}

/// Wrap a SendToPlatforms into an engine container.
fn send_container_for(id: &EngineIdentity, send: SendToPlatforms) -> ContainerForEngine {
    ContainerForEngine {
        version: 2,
        auth_token: id.auth.clone(),
        module_name: id.module.clone(),
        module_instance_uuid7: id.instance.clone(),
        payload: Some(EnginePayload::SendToPlatforms(send)),
    }
}

/// A plain chat reply (command feedback).
fn reply_container(id: &EngineIdentity, chat: &ChatMessage, msg: impl Into<String>) -> ContainerForEngine {
    send_container_for(id, base_send(id, chat, msg.into()))
}

/// A chat reply that ALSO deletes an incoming platform message id (the appeal
/// trigger). The post-send delete path is honored by adapters that support it.
fn deleting_reply_container(
    id: &EngineIdentity,
    chat: &ChatMessage,
    msg: impl Into<String>,
    delete_message_id: String,
) -> ContainerForEngine {
    let mut send = base_send(id, chat, msg.into());
    send.delete_message_id = delete_message_id;
    send_container_for(id, send)
}

/// A DatabaseQuery container carrying a JSON payload in `sql` (the reprimand
/// convention: the engine's user-DB handlers parse `sql` as their arguments).
fn db_container(id: &EngineIdentity, query_id: &str, payload: &serde_json::Value) -> ContainerForEngine {
    ContainerForEngine {
        version: 2,
        auth_token: id.auth.clone(),
        module_name: id.module.clone(),
        module_instance_uuid7: id.instance.clone(),
        payload: Some(EnginePayload::DatabaseQuery(DatabaseQuery {
            query_id: query_id.to_string(),
            sql: payload.to_string(),
            params: vec![],
        })),
    }
}

// ── command handling ────────────────────────────────────────────────────────

/// Handle one of this module's commands, returning the engine messages to send.
/// Pure w.r.t. the engine socket (all outward effects are in the return value),
/// so the whole flow is drivable in a test.
fn handle_command(
    id: &EngineIdentity,
    chat: &ChatMessage,
    appeals: &Appeals,
    settings: &Settings,
    name: &str,
    args: &str,
) -> Vec<ContainerForEngine> {
    match name {
        BLOCK_COMMAND | BAN_COMMAND => handle_block(id, chat, settings, BLOCK_COMMAND, args),
        UNBLOCK_COMMAND | UNBAN_COMMAND => {
            handle_block(id, chat, settings, UNBLOCK_COMMAND, args)
        }
        APPEAL_COMMAND => handle_appeal(id, chat, appeals, settings, args),
        APPEALS_COMMAND => handle_appeals(id, chat, appeals, settings),
        _ => Vec::new(),
    }
}

/// `!block <user> [reason]` / `!unblock <user>` — mod-gated, emits a
/// `userdb_block` / `userdb_unblock` DatabaseQuery. Always replies: an
/// acknowledgement on success, a "not a moderator" refusal on authorization
/// failure, and (from the read loop) a failure reply if the engine query fails.
fn handle_block(
    id: &EngineIdentity,
    chat: &ChatMessage,
    settings: &Settings,
    name: &str,
    args: &str,
) -> Vec<ContainerForEngine> {
    if !has_authority(chat.user_data.as_ref(), &settings.block_authority) {
        return vec![reply_container(id, chat, "You are not a moderator.")];
    }
    let is_block = name == BLOCK_COMMAND;
    let usage = if is_block {
        format!("Usage: `{}{} <user> [reason]`.", settings.command_flag, BLOCK_COMMAND)
    } else {
        format!("Usage: `{}{} <user>`.", settings.command_flag, UNBLOCK_COMMAND)
    };
    let (target, rest) = split_once_ws(args);
    if target.is_empty() {
        return vec![reply_container(id, chat, usage)];
    }
    let handle = target.strip_prefix('@').unwrap_or(target).to_string();
    let reason = if is_block { rest.to_string() } else { String::new() };
    let payload = serde_json::json!({
        "platform": chat.platform,
        "handle": handle,
        "uuid7": "",
        "reason": reason,
        "actor": actor_json(chat),
    });
    // Acknowledge immediately (so the command is never silent) alongside the
    // engine query; a query failure is reported later from the DatabaseQueryResult
    // path (see the read loop).
    let ack = if is_block {
        if reason.is_empty() {
            format!("blocked @{handle}")
        } else {
            format!("blocked @{handle}: {reason}")
        }
    } else {
        format!("unblocked @{handle}")
    };
    vec![
        reply_container(id, chat, ack),
        db_container(
            id,
            if is_block { "userdb_block" } else { "userdb_unblock" },
            &payload,
        ),
    ]
}

/// `!appeal <text>` (file) or `!appeal approve|deny <id>` (resolve).
///
/// Filing only works for a currently-banned user (see [`user_is_banned`]): a
/// non-banned user is told they need not appeal and their message is left alone
/// (not logged, not deleted).
fn handle_appeal(
    id: &EngineIdentity,
    chat: &ChatMessage,
    appeals: &Appeals,
    settings: &Settings,
    args: &str,
) -> Vec<ContainerForEngine> {
    let (head, rest) = split_once_ws(args);
    if head.eq_ignore_ascii_case("approve") || head.eq_ignore_ascii_case("deny") {
        return resolve_appeal(id, chat, appeals, settings, head, rest);
    }
    if args.trim().is_empty() {
        return vec![reply_container(
            id,
            chat,
            format!("Usage: `{}{} <text>`.", settings.command_flag, APPEAL_COMMAND),
        )];
    }
    // Only a user who is actually banned (an active, not-yet-unbanned ban) may
    // appeal. A non-banned user is told so; their message is neither logged nor
    // deleted.
    if !user_is_banned(chat) {
        return vec![reply_container(id, chat, "You have no bans, no need to appeal.")];
    }
    let appeal = Appeal {
        id: uuid::Uuid::now_v7().to_string(),
        user_uuid7: chat.user_uuid7.clone(),
        platform: chat.platform.clone(),
        handle: chat
            .user_data
            .as_ref()
            .map(|u| u.username.clone())
            .unwrap_or_default(),
        channel: chat.channel_id.clone(),
        text: args.trim().to_string(),
        at: now_ms(),
        status: "pending".to_string(),
        resolved_by: None,
        resolved_at: None,
    };
    match appeals.append(appeal) {
        // Acknowledge without echoing the appeal text, and delete the trigger.
        Ok(()) => vec![deleting_reply_container(
            id,
            chat,
            "Your appeal was logged. A moderator will review it.",
            platform_message_id(&chat.raw_data),
        )],
        Err(e) => vec![reply_container(id, chat, format!("Could not log your appeal: {e}"))],
    }
}

/// `!appeal approve <id>` / `!appeal deny <id>` — mod-gated by
/// `approve_authority`. Approve additionally emits a `userdb_unblock`.
fn resolve_appeal(
    id: &EngineIdentity,
    chat: &ChatMessage,
    appeals: &Appeals,
    settings: &Settings,
    action: &str,
    rest: &str,
) -> Vec<ContainerForEngine> {
    if !has_authority(chat.user_data.as_ref(), &settings.approve_authority) {
        return vec![reply_container(id, chat, "Only moderators can resolve appeals.")];
    }
    let Some(appeal_id) = rest.split_whitespace().next() else {
        return vec![reply_container(
            id,
            chat,
            format!("Usage: `{}{} {action} <id>`.", settings.command_flag, APPEAL_COMMAND),
        )];
    };
    let Some(appeal) = appeals.find(appeal_id) else {
        return vec![reply_container(id, chat, format!("No appeal with id `{appeal_id}`."))];
    };
    if appeal.status != "pending" {
        return vec![reply_container(
            id,
            chat,
            format!("Appeal `{appeal_id}` is already {}.", appeal.status),
        )];
    }
    let actor = chat
        .user_data
        .as_ref()
        .map(|u| u.username.clone())
        .unwrap_or_default();
    let approved = action.eq_ignore_ascii_case("approve");
    let status = if approved { "approved" } else { "denied" };
    let mut out = Vec::new();
    if approved {
        let payload = serde_json::json!({
            "platform": appeal.platform,
            "handle": appeal.handle,
            "uuid7": appeal.user_uuid7,
            "reason": "",
            "actor": actor_json(chat),
        });
        out.push(db_container(id, "userdb_unblock", &payload));
    }
    match appeals.resolve(appeal_id, status, &actor) {
        Ok(true) => out.push(reply_container(id, chat, format!("Appeal `{appeal_id}` {status}."))),
        Ok(false) => out.push(reply_container(
            id,
            chat,
            format!("No pending appeal with id `{appeal_id}`."),
        )),
        Err(e) => out.push(reply_container(id, chat, format!("Could not update appeal: {e}"))),
    }
    out
}

/// `!appeals` — list pending appeals (mod-gated) as `id · @handle · reason`.
fn handle_appeals(
    id: &EngineIdentity,
    chat: &ChatMessage,
    appeals: &Appeals,
    settings: &Settings,
) -> Vec<ContainerForEngine> {
    if !has_authority(chat.user_data.as_ref(), &settings.block_authority) {
        return vec![reply_container(id, chat, "Only moderators can view appeals.")];
    }
    let pending = appeals.pending();
    let msg = if pending.is_empty() {
        "No pending appeals.".to_string()
    } else {
        let lines: Vec<String> = pending
            .iter()
            .map(|a| format!("{} · @{} · {}", a.id, a.handle, a.text))
            .collect();
        format!("Pending appeals ({}):\n{}", pending.len(), lines.join("\n"))
    };
    vec![reply_container(id, chat, msg)]
}

// ── main ────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let client = CockatielClient::connect("config.json").await?;
    let (write, read) = client.stream.split();
    let write_shared: Arc<AsyncMutex<WsWriteHalf>> = Arc::new(AsyncMutex::new(write));
    let module_name = client.config.module_name.clone();
    info!("block module connected as '{}'", module_name);
    let identity: Arc<AsyncMutex<EngineIdentity>> = Arc::new(AsyncMutex::new(EngineIdentity {
        auth: client.auth_token.clone(),
        instance: client.instance_uuid7.clone(),
        module: module_name,
    }));

    let settings = ensure_defaults();
    let write_for_task = Arc::clone(&write_shared);
    let identity_for_task = Arc::clone(&identity);

    // Read loop + engine-session supervisor: owns the read half, answers
    // liveness probes, acks every pre/in-process stage, surfaces
    // DatabaseQueryResult failures, and reconnects with backoff — re-registering
    // the commands on each fresh session.
    tokio::spawn(async move {
        let mut read = read;
        let appeals = Appeals::new(settings.data_dir.clone());
        // In-flight block/unblock commands awaiting their engine answer, so a
        // failed query can be reported back to the channel (never silent).
        let mut pending: HashMap<String, VecDeque<PendingBlock>> = HashMap::new();
        loop {
            register_commands(&write_for_task, &identity_for_task, &settings.command_flag).await;
            loop {
                let Some(msg) = read.next().await else { break };
                let data = match msg {
                    Ok(WsMessage::Binary(d)) => d,
                    Ok(WsMessage::Close(_)) => {
                        info!("Engine closed connection");
                        break;
                    }
                    Ok(_) => continue,
                    Err(e) => {
                        warn!("Engine WebSocket error: {}", e);
                        break;
                    }
                };
                let Ok(container) = ContainerForModule::decode(data.as_ref()) else { continue };
                let id = identity_for_task.lock().await.clone();
                match container.payload {
                    Some(ModulePayload::AuthVerify(_)) => {
                        let reply = ContainerForEngine {
                            version: 2,
                            auth_token: id.auth.clone(),
                            module_name: id.module.clone(),
                            module_instance_uuid7: id.instance.clone(),
                            payload: Some(EnginePayload::AuthVerify(AuthVerify {
                                cur_auth: id.auth.clone(),
                            })),
                        };
                        send_container(&write_for_task, reply).await;
                    }
                    Some(ModulePayload::DatabaseQueryResult(res)) => {
                        if !res.success {
                            eprintln!(
                                "[block] query '{}' failed: {}",
                                res.query_id, res.error
                            );
                        }
                        // Report a failed block/unblock back to the channel so
                        // the command is never silent. Successful queries were
                        // already acknowledged when the command was issued.
                        if !res.success
                            && (res.query_id == "userdb_block"
                                || res.query_id == "userdb_unblock")
                        {
                            if let Some(queue) = pending.get_mut(&res.query_id) {
                                if let Some(p) = queue.pop_front() {
                                    let verb = if p.is_block { "block" } else { "unblock" };
                                    let msg =
                                        format!("could not {verb} @{}: {}", p.handle, res.error);
                                    send_container(
                                        &write_for_task,
                                        reply_container(&id, &p.chat, msg),
                                    )
                                    .await;
                                }
                            }
                        }
                    }
                    Some(ModulePayload::MessagePreProcess(pre)) => {
                        let MessagePreProcess { message_uuid7: uuid, raw_message, audio, audio_type } = pre;
                        if !uuid.is_empty() {
                            let receipt = ContainerForEngine {
                                version: 2,
                                auth_token: id.auth.clone(),
                                module_name: id.module.clone(),
                                module_instance_uuid7: id.instance.clone(),
                                payload: Some(EnginePayload::MessageAck(MessageAck {
                                    message_uuid7: uuid.clone(),
                                })),
                            };
                            send_container(&write_for_task, receipt).await;
                        }
                        // Handle our routed command when present.
                        if let Some(chat) = &raw_message {
                            if let Some(cmd) = &chat.command {
                                if COMMANDS.contains(&cmd.command_name.as_str()) {
                                    let args = strip_command(
                                        &chat.raw_message,
                                        &cmd.command_flag,
                                        &cmd.command_name,
                                    );
                                    let out = handle_command(
                                        &id,
                                        chat,
                                        &appeals,
                                        &settings,
                                        &cmd.command_name,
                                        &args,
                                    );
                                    // Track any block/unblock query we just
                                    // emitted so a failed result can be
                                    // reported to the channel.
                                    for c in &out {
                                        if let Some(EnginePayload::DatabaseQuery(q)) = &c.payload {
                                            if q.query_id == "userdb_block"
                                                || q.query_id == "userdb_unblock"
                                            {
                                                if let Ok(p) = serde_json::from_str::<
                                                    serde_json::Value,
                                                >(
                                                    &q.sql
                                                ) {
                                                    let handle = p
                                                        .get("handle")
                                                        .and_then(|v| v.as_str())
                                                        .unwrap_or("")
                                                        .to_string();
                                                    pending
                                                        .entry(q.query_id.clone())
                                                        .or_default()
                                                        .push_back(PendingBlock {
                                                            chat: chat.clone(),
                                                            handle,
                                                            is_block: q
                                                                .query_id
                                                                == "userdb_block",
                                                        });
                                                }
                                            }
                                        }
                                    }
                                    for c in out {
                                        send_container(&write_for_task, c).await;
                                    }
                                }
                            }
                        }
                        // ALWAYS ack the pre-process stage: echo the raw
                        // ChatMessage back with the same message_uuid7 so the
                        // engine advances instead of stalling until the timeout
                        // sweep — on every path, command or not.
                        let ack = ContainerForEngine {
                            version: 2,
                            auth_token: id.auth.clone(),
                            module_name: id.module.clone(),
                            module_instance_uuid7: id.instance.clone(),
                            payload: Some(EnginePayload::MessagePreProcess(MessagePreProcess {
                                message_uuid7: uuid,
                                raw_message,
                                audio,
                                audio_type,
                            })),
                        };
                        send_container(&write_for_task, ack).await;
                    }
                    Some(ModulePayload::MessageInProcess(process)) => {
                        if !process.message_uuid7.is_empty() {
                            let receipt = ContainerForEngine {
                                version: 2,
                                auth_token: id.auth.clone(),
                                module_name: id.module.clone(),
                                module_instance_uuid7: id.instance.clone(),
                                payload: Some(EnginePayload::MessageAck(MessageAck {
                                    message_uuid7: process.message_uuid7.clone(),
                                })),
                            };
                            send_container(&write_for_task, receipt).await;
                        }
                        let ack = ContainerForEngine {
                            version: 2,
                            auth_token: id.auth.clone(),
                            module_name: id.module.clone(),
                            module_instance_uuid7: id.instance.clone(),
                            payload: Some(EnginePayload::MessageInProcess(MessageInProcess {
                                message_uuid7: process.message_uuid7,
                                raw_message: process.raw_message,
                                processed_message: process.processed_message,
                                abandon_message: process.abandon_message,
                                audio: process.audio,
                                audio_type: process.audio_type,
                            })),
                        };
                        send_container(&write_for_task, ack).await;
                    }
                    Some(ModulePayload::Shutdown(_)) => {
                        info!("Engine requested shutdown — exiting");
                        std::process::exit(0);
                    }
                    _ => {}
                }
            }

            // The engine connection dropped — reconnect with backoff instead of
            // leaving the module unresponsive.
            info!("Engine disconnected — reconnecting...");
            let mut backoff = settings.reconnect_base_secs;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(backoff as u64)).await;
                match CockatielClient::connect("config.json").await {
                    Ok(conn) => {
                        info!("Reconnected to engine");
                        let (w, r) = conn.stream.split();
                        *write_for_task.lock().await = w;
                        *identity_for_task.lock().await = EngineIdentity {
                            auth: conn.auth_token,
                            instance: conn.instance_uuid7,
                            module: conn.config.module_name,
                        };
                        read = r;
                        break; // back to outer loop → re-register the commands
                    }
                    Err(e) => {
                        warn!("Engine reconnect failed: {} — retrying in {}s", e, backoff);
                        backoff = (backoff * 2).min(settings.reconnect_max_secs);
                    }
                }
            }
        }
    });

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_identity() -> EngineIdentity {
        EngineIdentity {
            auth: "t".into(),
            instance: "inst".into(),
            module: "block".into(),
        }
    }

    fn settings(dir: &str) -> Settings {
        Settings {
            command_flag: "!".into(),
            data_dir: dir.into(),
            block_authority: "mod".into(),
            approve_authority: "mod".into(),
            reconnect_base_secs: 1,
            reconnect_max_secs: 30,
        }
    }

    /// A `ChatMessage` as the discord-adapter emits it (raw_data carries the id).
    fn chat(user: &str, channel: &str, msg_id: &str, text: &str, ud: UserData) -> ChatMessage {
        let raw = format!(
            r#"{{"id":"{msg_id}","channel_id":"{channel}","content":{}}}"#,
            serde_json::to_string(text).unwrap()
        );
        ChatMessage {
            platform: "discord".into(),
            raw_data: raw.into_bytes(),
            raw_message: text.into(),
            user_uuid7: user.into(),
            command: None,
            user_data: Some(ud),
            channel_id: channel.into(),
        }
    }

    fn member() -> UserData {
        UserData::default()
    }
    fn moderator() -> UserData {
        UserData { username: "mod".into(), is_moderator: true, ..Default::default() }
    }
    fn admin() -> UserData {
        UserData { username: "admin".into(), is_admin: true, ..Default::default() }
    }
    /// A user with one active (not-yet-unbanned) ban in `user_data.bans`.
    fn banned() -> UserData {
        UserData {
            username: "bad".into(),
            bans: vec![Ban { unbanned: false, ..Default::default() }],
            ..Default::default()
        }
    }

    fn db_queries(v: &[ContainerForEngine]) -> Vec<DatabaseQuery> {
        v.iter()
            .filter_map(|c| match &c.payload {
                Some(EnginePayload::DatabaseQuery(q)) => Some(q.clone()),
                _ => None,
            })
            .collect()
    }
    fn sends(v: &[ContainerForEngine]) -> Vec<SendToPlatforms> {
        v.iter()
            .filter_map(|c| match &c.payload {
                Some(EnginePayload::SendToPlatforms(s)) => Some(s.clone()),
                _ => None,
            })
            .collect()
    }

    // ── pure helpers ────────────────────────────────────────────────────────

    #[test]
    fn strips_flag_and_command_keeps_args() {
        assert_eq!(strip_command("!block @user rude", "!", "block"), "@user rude");
        assert_eq!(strip_command("!appeal approve abc", "!", "appeal"), "approve abc");
        assert_eq!(strip_command("!appeals", "!", "appeals"), "");
        assert_eq!(strip_command("!block", "!", "block"), "");
    }

    #[test]
    fn split_once_ws_handles_empty_tails() {
        assert_eq!(split_once_ws("a b c"), ("a", "b c"));
        assert_eq!(split_once_ws("a"), ("a", ""));
        assert_eq!(split_once_ws("  a   "), ("a", ""));
        assert_eq!(split_once_ws(""), ("", ""));
    }

    #[test]
    fn authority_gates_by_level() {
        let member = member();
        let modu = moderator();
        let adminu = admin();
        // "mod" is the default level.
        assert!(has_authority(Some(&modu), "mod"));
        assert!(has_authority(Some(&adminu), "mod"));
        assert!(!has_authority(Some(&member), "mod"));
        // "admin" requires admin+.
        assert!(has_authority(Some(&adminu), "admin"));
        assert!(!has_authority(Some(&modu), "admin"));
        // "owner" requires owner.
        assert!(!has_authority(Some(&adminu), "owner"));
        assert!(!has_authority(Some(&member), "owner"));
        // Unknown authority falls back to the mod gate; a missing user is never
        // authorized.
        assert!(has_authority(Some(&modu), "typo"));
        assert!(!has_authority(None, "mod"));
    }

    #[test]
    fn platform_message_id_reads_top_level_id() {
        assert_eq!(platform_message_id(br#"{"id":"123","content":"x"}"#), "123");
        assert_eq!(platform_message_id(b"{}"), "");
        assert_eq!(platform_message_id(b"not json"), "");
    }

    #[test]
    fn tilde_expands() {
        let home = std::env::var("HOME").unwrap_or_default();
        assert_eq!(expand_tilde("~/.cockatiel/block"), format!("{home}/.cockatiel/block"));
        assert_eq!(expand_tilde("/abs/path"), "/abs/path");
    }

    // ── appeals store ───────────────────────────────────────────────────────

    fn temp_dir() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("cockatiel-block-{}", uuid::Uuid::now_v7()))
    }

    fn sample_appeal(id: &str) -> Appeal {
        Appeal {
            id: id.into(),
            user_uuid7: "u1".into(),
            platform: "discord".into(),
            handle: "bob".into(),
            channel: "chan".into(),
            text: "let me back in".into(),
            at: 42,
            status: "pending".into(),
            resolved_by: None,
            resolved_at: None,
        }
    }

    #[test]
    fn appeals_append_find_pending_and_resolve() {
        let dir = temp_dir();
        let store = Appeals::new(dir.to_string_lossy().to_string());
        // Multiple appeals are all logged.
        store.append(sample_appeal("aaaa1111-0000-0000-0000-000000000000")).unwrap();
        store.append(sample_appeal("bbbb2222-0000-0000-0000-000000000000")).unwrap();
        assert_eq!(store.pending().len(), 2);

        // Prefix lookup.
        assert!(store.find("aaaa").is_some());
        assert!(store.find("zzzz").is_none());

        // Resolve one; only it changes status, and the resolver/time are set.
        assert!(store.resolve("bbbb", "denied", "mod").unwrap());
        let pending = store.pending();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, "aaaa1111-0000-0000-0000-000000000000");
        let denied = store.find("bbbb").unwrap();
        assert_eq!(denied.status, "denied");
        assert_eq!(denied.resolved_by.as_deref(), Some("mod"));
        assert!(denied.resolved_at.is_some());

        // Re-resolving an already-resolved appeal does nothing.
        assert!(!store.resolve("bbbb", "approved", "admin").unwrap());

        // Survives a fresh handle over the same dir.
        let store2 = Appeals::new(dir.to_string_lossy().to_string());
        assert_eq!(store2.pending().len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── end-to-end command handling ─────────────────────────────────────────

    #[test]
    fn block_denied_for_member() {
        let id = test_identity();
        let dir = temp_dir();
        let store = Appeals::new(dir.to_string_lossy().to_string());
        let s = settings(dir.to_string_lossy().as_ref());
        let out = handle_command(&id, &chat("u1", "c", "m1", "!block @bob rude", member()), &store, &s, BLOCK_COMMAND, "@bob rude");
        let sent = sends(&out);
        assert_eq!(sent.len(), 1);
        assert!(sent[0].msg.to_lowercase().contains("moderator"));
        assert!(db_queries(&out).is_empty());
    }

    #[test]
    fn block_emits_userdb_block_for_mod() {
        let id = test_identity();
        let dir = temp_dir();
        let store = Appeals::new(dir.to_string_lossy().to_string());
        let s = settings(dir.to_string_lossy().as_ref());
        let out = handle_command(&id, &chat("u1", "c", "m1", "!block @bob rude", moderator()), &store, &s, BLOCK_COMMAND, "@bob rude");
        let q = db_queries(&out);
        assert_eq!(q.len(), 1);
        assert_eq!(q[0].query_id, "userdb_block");
        let payload: serde_json::Value = serde_json::from_str(&q[0].sql).unwrap();
        assert_eq!(payload["platform"], "discord");
        assert_eq!(payload["handle"], "bob"); // '@' stripped
        assert_eq!(payload["uuid7"], "");
        assert_eq!(payload["reason"], "rude");
        assert_eq!(payload["actor"]["uuid7"], "u1");
        assert_eq!(payload["actor"]["handle"], "mod");
        // A visible acknowledgement accompanies the query.
        let sent = sends(&out);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].msg, "blocked @bob: rude");
    }

    #[test]
    fn unblock_emits_userdb_unblock() {
        let id = test_identity();
        let dir = temp_dir();
        let store = Appeals::new(dir.to_string_lossy().to_string());
        let s = settings(dir.to_string_lossy().as_ref());
        let out = handle_command(&id, &chat("u1", "c", "m1", "!unblock bob", admin()), &store, &s, UNBLOCK_COMMAND, "bob");
        let q = db_queries(&out);
        assert_eq!(q.len(), 1);
        assert_eq!(q[0].query_id, "userdb_unblock");
        let payload: serde_json::Value = serde_json::from_str(&q[0].sql).unwrap();
        assert_eq!(payload["handle"], "bob");
        assert_eq!(payload["reason"], "");
        // A visible acknowledgement accompanies the query.
        assert_eq!(sends(&out)[0].msg, "unblocked @bob");
    }

    #[test]
    fn ban_is_alias_of_block() {
        let id = test_identity();
        let dir = temp_dir();
        let store = Appeals::new(dir.to_string_lossy().to_string());
        let s = settings(dir.to_string_lossy().as_ref());
        let out = handle_command(&id, &chat("u1", "c", "m1", "!ban @bob rude", moderator()), &store, &s, BAN_COMMAND, "@bob rude");
        let q = db_queries(&out);
        assert_eq!(q.len(), 1);
        assert_eq!(q[0].query_id, "userdb_block");
        let payload: serde_json::Value = serde_json::from_str(&q[0].sql).unwrap();
        assert_eq!(payload["handle"], "bob");
        assert_eq!(payload["reason"], "rude");
        assert_eq!(sends(&out)[0].msg, "blocked @bob: rude");
        // Same mod gating: a member is refused and no query is emitted.
        let denied = handle_command(&id, &chat("u2", "c", "m2", "!ban bob", member()), &store, &s, BAN_COMMAND, "bob");
        assert!(db_queries(&denied).is_empty());
        assert!(sends(&denied)[0].msg.to_lowercase().contains("moderator"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unban_is_alias_of_unblock() {
        let id = test_identity();
        let dir = temp_dir();
        let store = Appeals::new(dir.to_string_lossy().to_string());
        let s = settings(dir.to_string_lossy().as_ref());
        let out = handle_command(&id, &chat("u1", "c", "m1", "!unban bob", admin()), &store, &s, UNBAN_COMMAND, "bob");
        let q = db_queries(&out);
        assert_eq!(q.len(), 1);
        assert_eq!(q[0].query_id, "userdb_unblock");
        let payload: serde_json::Value = serde_json::from_str(&q[0].sql).unwrap();
        assert_eq!(payload["handle"], "bob");
        assert_eq!(sends(&out)[0].msg, "unblocked @bob");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn block_usage_when_no_target() {
        let id = test_identity();
        let dir = temp_dir();
        let store = Appeals::new(dir.to_string_lossy().to_string());
        let s = settings(dir.to_string_lossy().as_ref());
        let out = handle_command(&id, &chat("u1", "c", "m1", "!block", moderator()), &store, &s, BLOCK_COMMAND, "");
        assert!(sends(&out)[0].msg.contains("Usage"));
        assert!(db_queries(&out).is_empty());
    }

    #[test]
    fn appeal_logs_deletes_trigger_and_never_echoes_text() {
        let id = test_identity();
        let dir = temp_dir();
        let store = Appeals::new(dir.to_string_lossy().to_string());
        let s = settings(dir.to_string_lossy().as_ref());
        let out = handle_command(
            &id,
            &chat("u1", "c", "m7", "!appeal please unblock me", banned()),
            &store,
            &s,
            APPEAL_COMMAND,
            "please unblock me",
        );
        let sent = sends(&out);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].delete_message_id, "m7");
        assert!(!sent[0].msg.contains("please unblock me"));

        let pending = store.pending();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].text, "please unblock me");
        assert_eq!(pending[0].handle, "bad");
        assert_eq!(pending[0].platform, "discord");
        assert_eq!(pending[0].channel, "c");
        assert_eq!(pending[0].status, "pending");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn appeal_from_unbanned_user_is_neither_logged_nor_deleted() {
        let id = test_identity();
        let dir = temp_dir();
        let store = Appeals::new(dir.to_string_lossy().to_string());
        let s = settings(dir.to_string_lossy().as_ref());

        // No bans at all: refused, nothing logged, message NOT deleted.
        let no_ban = handle_command(
            &id,
            &chat("u1", "c", "m7", "!appeal let me in", member()),
            &store,
            &s,
            APPEAL_COMMAND,
            "let me in",
        );
        let sent = sends(&no_ban);
        assert_eq!(sent.len(), 1);
        assert!(sent[0].msg.contains("no bans"));
        assert!(sent[0].delete_message_id.is_empty());
        assert!(store.pending().is_empty());

        // A *previously* banned (unbanned == true) user is treated as unbanned.
        let mut ud = banned();
        ud.bans[0].unbanned = true;
        let lifted = handle_command(
            &id,
            &chat("u1", "c", "m8", "!appeal let me in", ud),
            &store,
            &s,
            APPEAL_COMMAND,
            "let me in",
        );
        assert!(sends(&lifted)[0].msg.contains("no bans"));
        assert!(store.pending().is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn user_is_banned_checks_active_bans() {
        let c = |ud: UserData| chat("u", "c", "m", "!x", ud);
        assert!(!user_is_banned(&c(member())));
        assert!(user_is_banned(&c(banned())));
        let mut lifted = banned();
        lifted.bans[0].unbanned = true;
        assert!(!user_is_banned(&c(lifted)));
        // Missing user_data → not banned.
        let mut none = c(member());
        none.user_data = None;
        assert!(!user_is_banned(&none));
    }

    #[test]
    fn appeals_listing_is_mod_gated() {
        let id = test_identity();
        let dir = temp_dir();
        let store = Appeals::new(dir.to_string_lossy().to_string());
        let s = settings(dir.to_string_lossy().as_ref());
        store.append(sample_appeal("cccc3333-0000-0000-0000-000000000000")).unwrap();

        // A member sees nothing useful.
        let denied = handle_command(&id, &chat("u9", "c", "m1", "!appeals", member()), &store, &s, APPEALS_COMMAND, "");
        assert!(sends(&denied)[0].msg.to_lowercase().contains("moderator"));

        // A mod sees the pending appeal as `id · @handle · reason`.
        let out = handle_command(&id, &chat("u1", "c", "m1", "!appeals", moderator()), &store, &s, APPEALS_COMMAND, "");
        let msg = &sends(&out)[0].msg;
        assert!(msg.contains("cccc3333-0000-0000-0000-000000000000"));
        assert!(msg.contains("@bob"));
        assert!(msg.contains("let me back in"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn approve_emits_unblock_and_resolves() {
        let id = test_identity();
        let dir = temp_dir();
        let store = Appeals::new(dir.to_string_lossy().to_string());
        let s = settings(dir.to_string_lossy().as_ref());
        store.append(sample_appeal("dddd4444-0000-0000-0000-000000000000")).unwrap();

        let out = handle_command(
            &id,
            &chat("u1", "c", "m1", "!appeal approve dddd", moderator()),
            &store,
            &s,
            APPEAL_COMMAND,
            "approve dddd",
        );
        let q = db_queries(&out);
        assert_eq!(q.len(), 1);
        assert_eq!(q[0].query_id, "userdb_unblock");
        let payload: serde_json::Value = serde_json::from_str(&q[0].sql).unwrap();
        assert_eq!(payload["handle"], "bob");
        assert_eq!(payload["uuid7"], "u1");
        assert!(store.find("dddd").unwrap().status == "approved");
        assert!(store.pending().is_empty());
        assert!(sends(&out)[0].msg.contains("approved"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn deny_resolves_without_unblock() {
        let id = test_identity();
        let dir = temp_dir();
        let store = Appeals::new(dir.to_string_lossy().to_string());
        let s = settings(dir.to_string_lossy().as_ref());
        store.append(sample_appeal("eeee5555-0000-0000-0000-000000000000")).unwrap();

        let out = handle_command(
            &id,
            &chat("u1", "c", "m1", "!appeal deny eeee", admin()),
            &store,
            &s,
            APPEAL_COMMAND,
            "deny eeee",
        );
        assert!(db_queries(&out).is_empty(), "deny must not emit an unblock");
        assert_eq!(store.find("eeee").unwrap().status, "denied");
        assert!(sends(&out)[0].msg.contains("denied"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn approve_requires_configured_authority() {
        let id = test_identity();
        let dir = temp_dir();
        let store = Appeals::new(dir.to_string_lossy().to_string());
        let mut s = settings(dir.to_string_lossy().as_ref());
        s.approve_authority = "admin".into();
        store.append(sample_appeal("ffff6666-0000-0000-0000-000000000000")).unwrap();

        // A moderator is below the admin-only threshold.
        let out = handle_command(
            &id,
            &chat("u1", "c", "m1", "!appeal approve ffff", moderator()),
            &store,
            &s,
            APPEAL_COMMAND,
            "approve ffff",
        );
        assert!(db_queries(&out).is_empty());
        assert!(sends(&out)[0].msg.to_lowercase().contains("moderator"));
        // Still pending, untouched.
        assert!(store.find("ffff").unwrap().status == "pending");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_command_is_ignored() {
        let id = test_identity();
        let dir = temp_dir();
        let store = Appeals::new(dir.to_string_lossy().to_string());
        let s = settings(dir.to_string_lossy().as_ref());
        let out = handle_command(&id, &chat("u1", "c", "m1", "!nope", moderator()), &store, &s, "nope", "");
        assert!(out.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
