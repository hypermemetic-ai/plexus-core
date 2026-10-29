//! Global pending response registry for bidirectional communication
//!
//! This module provides a global registry for pending bidirectional requests,
//! enabling transports like MCP (which are fundamentally request-response) to
//! route responses back to the correct BidirChannel.
//!
//! # Architecture
//!
//! 1. When a BidirChannel sends a request, it registers a callback in this registry
//! 2. The transport (e.g., MCP) sends the request to the client as a notification
//! 3. The client responds via a tool call (e.g., `_plexus_respond`)
//! 4. The transport looks up the request in this registry and forwards the response
//! 5. The registry callback deserializes and sends to the waiting BidirChannel
//!
//! # Who may answer (BIDIR-13)
//!
//! A pending entry carries its **asker**: the connection the `Request` item
//! went out on. The hub's WebSocket pipe binds it ([`bind_asker`]) before the
//! item reaches the wire, so nobody can know a request id before its entry
//! is bound. An answer from any other connection is
//! [`BidirError::NotThisCall`] and leaves the question pending; the asker
//! still answers. An entry no pipe bound (the MCP bridge, the in-memory
//! transport) answers as before. This is the stopgap; BIDIR-9 moves the
//! question into the call itself and deletes this map.
//!
//! # Thread Safety
//!
//! The registry uses a RwLock for concurrent read access with exclusive write access.
//! Registrations and lookups are fast; response handling is done outside the lock.

use serde_json::Value;
use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};
use tokio::sync::oneshot;

use super::types::BidirError;

/// Type alias for the response sender (type-erased to Value)
type ResponseSender = oneshot::Sender<Value>;

/// One pending question: where its answer goes, and — once the pipe that
/// carried its `Request` item has bound it — the connection that asked.
struct Pending {
    sender: ResponseSender,
    /// The asker's connection (jsonrpsee's `ConnectionId.0`); `None` until
    /// bound, and forever on a transport with no connection to bind.
    asker: Option<usize>,
}

/// Global registry for pending bidirectional requests
///
/// This registry allows transports to correlate response messages with
/// the BidirChannel waiting for them.
static PENDING_RESPONSES: LazyLock<RwLock<HashMap<String, Pending>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// Register a pending request in the global registry
///
/// Called by BidirChannel when making a request over a transport that
/// doesn't natively support bidirectional (like MCP).
///
/// # Arguments
///
/// * `request_id` - Unique identifier for the request
/// * `sender` - Oneshot channel sender to forward the response
///
/// # Example
///
/// ```rust,ignore
/// let (tx, rx) = oneshot::channel();
/// register_pending_request("req-123", tx);
/// // Transport sends request...
/// // Later, _plexus_respond calls handle_pending_response("req-123", value)
/// let response = rx.await?;
/// ```
pub fn register_pending_request(request_id: String, sender: ResponseSender) {
    let mut registry = PENDING_RESPONSES.write().unwrap();
    registry.insert(request_id, Pending { sender, asker: None });
}

/// BIDIR-13: bind a pending request to the connection its `Request` item
/// is going out on — called by the pipe before it sends the item. The first
/// binding holds; returns whether this call bound it (`false`: no such
/// entry, or already bound).
pub fn bind_asker(request_id: &str, connection: usize) -> bool {
    let mut registry = PENDING_RESPONSES.write().unwrap();
    match registry.get_mut(request_id) {
        Some(p) if p.asker.is_none() => {
            p.asker = Some(connection);
            true
        }
        _ => false,
    }
}

/// Remove a pending request from the registry (e.g., on timeout)
///
/// # Arguments
///
/// * `request_id` - The request ID to remove
///
/// # Returns
///
/// The removed sender if it existed, or None
pub fn unregister_pending_request(request_id: &str) -> Option<ResponseSender> {
    let mut registry = PENDING_RESPONSES.write().unwrap();
    registry.remove(request_id).map(|p| p.sender)
}

/// Handle a response for a pending request, from no connection.
///
/// Called by transport tools like `_plexus_respond` when receiving a client
/// response. It is [`answer_pending`] with no connection: an entry bound to
/// an asker's connection refuses it (`NotThisCall`).
///
/// # Returns
///
/// * `Ok(())` if the response was successfully forwarded
/// * `Err(BidirError::UnknownRequest)` if no pending request with that ID
/// * `Err(BidirError::NotThisCall)` if the request is bound to a connection
/// * `Err(BidirError::ChannelClosed)` if the receiver was dropped (timeout/cancelled)
///
/// # Example
///
/// ```rust,ignore
/// // In _plexus_respond tool handler:
/// let result = handle_pending_response(request_id, response_data)?;
/// ```
pub fn handle_pending_response(request_id: &str, response_data: Value) -> Result<(), BidirError> {
    answer_pending(request_id, None, response_data)
}

/// BIDIR-13: deliver an answer from `from` (jsonrpsee's `ConnectionId.0`;
/// `None` when the caller has none). An entry bound to an asker takes an
/// answer from that connection alone: any other is
/// [`BidirError::NotThisCall`] and the entry stays, so the asker still
/// answers. An unbound entry takes any answer, as before.
pub fn answer_pending(request_id: &str, from: Option<usize>, response_data: Value) -> Result<(), BidirError> {
    // Remove from registry (takes ownership of sender) — only when the
    // answer is the asker's.
    let sender = {
        let mut registry = PENDING_RESPONSES.write().unwrap();
        match registry.get(request_id) {
            None => return Err(BidirError::UnknownRequest),
            Some(Pending { asker: Some(a), .. }) if from != Some(*a) => return Err(BidirError::NotThisCall),
            Some(_) => registry.remove(request_id).map(|p| p.sender),
        }
    };

    match sender {
        // Send response through channel
        Some(tx) => tx.send(response_data).map_err(|_| BidirError::ChannelClosed),
        None => Err(BidirError::UnknownRequest),
    }
}

/// Check if a request is pending
///
/// # Arguments
///
/// * `request_id` - The request ID to check
///
/// # Returns
///
/// `true` if a request with this ID is pending, `false` otherwise
pub fn is_request_pending(request_id: &str) -> bool {
    let registry = PENDING_RESPONSES.read().unwrap();
    registry.contains_key(request_id)
}

/// Get the count of pending requests (for monitoring/debugging)
pub fn pending_count() -> usize {
    let registry = PENDING_RESPONSES.read().unwrap();
    registry.len()
}

/// Clear all pending requests (for testing)
#[cfg(test)]
#[allow(dead_code)]
pub fn clear_all() {
    let mut registry = PENDING_RESPONSES.write().unwrap();
    registry.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests run concurrently and share a global registry.
    // Use unique request IDs and assert on per-ID presence (is_request_pending)
    // rather than global pending_count(), which races with concurrent tests.

    #[tokio::test]
    async fn test_register_and_handle() {
        let (tx, rx) = oneshot::channel();
        let request_id = format!("test-reg-handle-{}", uuid::Uuid::new_v4());

        // Register
        register_pending_request(request_id.clone(), tx);
        assert!(is_request_pending(&request_id));

        // Handle response
        let response = serde_json::json!({"confirmed": true});
        handle_pending_response(&request_id, response.clone()).unwrap();

        // Verify response received
        let received = rx.await.unwrap();
        assert_eq!(received, response);

        // Request should be removed
        assert!(!is_request_pending(&request_id));
    }

    #[tokio::test]
    async fn test_unknown_request() {
        let result = handle_pending_response(
            &format!("nonexistent-{}", uuid::Uuid::new_v4()),
            serde_json::json!({}),
        );
        assert!(matches!(result, Err(BidirError::UnknownRequest)));
    }

    #[tokio::test]
    async fn test_unregister() {
        let (tx, _rx) = oneshot::channel();
        let request_id = format!("test-unreg-{}", uuid::Uuid::new_v4());

        register_pending_request(request_id.clone(), tx);
        assert!(is_request_pending(&request_id));

        let removed = unregister_pending_request(&request_id);
        assert!(removed.is_some());
        assert!(!is_request_pending(&request_id));
    }

    #[tokio::test]
    async fn test_channel_closed() {
        let (tx, rx) = oneshot::channel();
        let request_id = format!("test-closed-{}", uuid::Uuid::new_v4());

        register_pending_request(request_id.clone(), tx);

        // Drop the receiver
        drop(rx);

        // Handle should fail with ChannelClosed
        let result = handle_pending_response(&request_id, serde_json::json!({}));
        assert!(matches!(result, Err(BidirError::ChannelClosed)));
    }

    // BIDIR-13: the asker's connection.

    #[tokio::test]
    async fn test_answer_from_other_connection_refused() {
        let (tx, rx) = oneshot::channel();
        let request_id = format!("test-asker-{}", uuid::Uuid::new_v4());
        register_pending_request(request_id.clone(), tx);
        assert!(bind_asker(&request_id, 7));
        assert!(!bind_asker(&request_id, 8), "the first binding holds");

        let r = answer_pending(&request_id, Some(8), serde_json::json!(true));
        assert!(matches!(r, Err(BidirError::NotThisCall)), "{r:?}");
        assert!(is_request_pending(&request_id), "a refused answer leaves the question");

        answer_pending(&request_id, Some(7), serde_json::json!(true)).unwrap();
        assert_eq!(rx.await.unwrap(), serde_json::json!(true));
        assert!(!is_request_pending(&request_id));
    }

    #[tokio::test]
    async fn test_unbound_entry_answers_from_anyone() {
        let (tx, rx) = oneshot::channel();
        let request_id = format!("test-unbound-{}", uuid::Uuid::new_v4());
        register_pending_request(request_id.clone(), tx);
        answer_pending(&request_id, Some(3), serde_json::json!(1)).unwrap();
        assert_eq!(rx.await.unwrap(), serde_json::json!(1));
    }

    #[tokio::test]
    async fn test_unchecked_answer_refused_when_bound() {
        let (tx, _rx) = oneshot::channel();
        let request_id = format!("test-unchecked-{}", uuid::Uuid::new_v4());
        register_pending_request(request_id.clone(), tx);
        bind_asker(&request_id, 1);
        let r = handle_pending_response(&request_id, serde_json::json!(1));
        assert!(matches!(r, Err(BidirError::NotThisCall)), "{r:?}");
        assert!(is_request_pending(&request_id));
        unregister_pending_request(&request_id);
    }
}
