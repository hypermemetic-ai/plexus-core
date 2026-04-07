//! MCP server bridge using rmcp with Plexus backend
//!
//! This module implements the MCP protocol using the rmcp crate,
//! bridging MCP tool calls to Plexus activation methods.

use std::sync::Arc;

use futures::StreamExt;
use rmcp::{
    ErrorData as McpError,
    ServerHandler,
    model::*,
    service::{RequestContext, RoleServer},
};
use serde_json::json;

use crate::plexus::bidirectional::{handle_pending_response, BidirError};
use crate::plexus::types::PlexusStreamItem;
use crate::plexus::{DynamicHub, PlexusError, PluginSchema};

// =============================================================================
// Schema Transformation
// =============================================================================

/// Convert Plexus activation schemas to rmcp Tool format
///
/// MCP requires all tool inputSchema to have "type": "object" at root.
/// schemars may produce schemas without this (e.g., for unit types).
fn schemas_to_rmcp_tools(schemas: Vec<PluginSchema>) -> Vec<Tool> {
    let mut tools: Vec<Tool> = schemas
        .into_iter()
        .flat_map(|activation| {
            let namespace = activation.namespace.clone();
            activation.methods.into_iter().map(move |method| {
                let name = format!("{}.{}", namespace, method.name);
                let description = method.description.clone();

                // Convert schemars::Schema to JSON, ensure "type": "object" exists
                let input_schema = method
                    .params
                    .and_then(|s| serde_json::to_value(s).ok())
                    .and_then(|v| v.as_object().cloned())
                    .map(|mut obj| {
                        // MCP requires "type": "object" at schema root
                        if !obj.contains_key("type") {
                            obj.insert("type".to_string(), json!("object"));
                        }
                        Arc::new(obj)
                    })
                    .unwrap_or_else(|| {
                        // Empty params = empty object schema
                        Arc::new(serde_json::Map::from_iter([
                            ("type".to_string(), json!("object")),
                        ]))
                    });

                Tool::new(name, description, input_schema)
            })
        })
        .collect();

    // Add the _plexus_respond tool for bidirectional communication
    tools.push(create_plexus_respond_tool());

    tools
}

/// Create the _plexus_respond tool for bidirectional communication
///
/// This tool allows MCP clients to respond to bidirectional requests
/// sent via logging notifications (type: "request").
fn create_plexus_respond_tool() -> Tool {
    let schema = Arc::new(serde_json::Map::from_iter([
        ("type".to_string(), json!("object")),
        (
            "properties".to_string(),
            json!({
                "request_id": {
                    "type": "string",
                    "description": "The request_id from the bidirectional request notification"
                },
                "response_data": {
                    "description": "The response data to send back to the server"
                }
            }),
        ),
        (
            "required".to_string(),
            json!(["request_id", "response_data"]),
        ),
    ]));

    Tool::new(
        "_plexus_respond".to_string(),
        "Respond to a bidirectional request from the server. \
         When you receive a logging notification with type 'request', \
         use this tool to send your response back."
            .to_string(),
        schema,
    )
}

// =============================================================================
// Error Mapping
// =============================================================================

/// Convert PlexusError to McpError
fn plexus_to_mcp_error(e: PlexusError) -> McpError {
    match e {
        PlexusError::ActivationNotFound(name) => {
            McpError::invalid_params(format!("Unknown activation: {}", name), None)
        }
        PlexusError::MethodNotFound { activation, method } => {
            McpError::invalid_params(format!("Unknown method: {}.{}", activation, method), None)
        }
        PlexusError::InvalidParams(reason) => McpError::invalid_params(reason, None),
        PlexusError::ExecutionError(error) => McpError::internal_error(error, None),
        PlexusError::HandleNotSupported(activation) => {
            McpError::invalid_params(format!("Handle resolution not supported: {}", activation), None)
        }
        PlexusError::TransportError(kind) => {
            McpError::internal_error(format!("Transport error: {}", kind), None)
        }
        PlexusError::Unauthenticated(reason) => {
            McpError::invalid_request(format!("Authentication required: {}", reason), None)
        }
    }
}

// =============================================================================
// Plexus MCP Bridge
// =============================================================================

/// MCP handler that bridges to Plexus RPC hub
#[derive(Clone)]
pub struct PlexusMcpBridge {
    hub: Arc<DynamicHub>,
}

impl PlexusMcpBridge {
    pub fn new(hub: Arc<DynamicHub>) -> Self {
        Self { hub }
    }

    /// Handle the _plexus_respond tool call
    ///
    /// Routes the response back to the waiting BidirChannel via the global registry.
    async fn handle_plexus_respond(
        &self,
        request: CallToolRequestParam,
    ) -> Result<CallToolResult, McpError> {
        let arguments = request
            .arguments
            .map(serde_json::Value::Object)
            .unwrap_or(json!({}));

        // Extract request_id and response_data
        let request_id = arguments
            .get("request_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpError::invalid_params("Missing required parameter: request_id", None))?
            .to_string();

        let response_data = arguments
            .get("response_data")
            .cloned()
            .ok_or_else(|| {
                McpError::invalid_params("Missing required parameter: response_data", None)
            })?;

        tracing::debug!(
            request_id = %request_id,
            "Handling _plexus_respond"
        );

        // Forward response through global registry
        match handle_pending_response(&request_id, response_data) {
            Ok(()) => Ok(CallToolResult::success(vec![Content::text(
                "Response delivered successfully",
            )])),
            Err(BidirError::UnknownRequest) => {
                tracing::warn!(request_id = %request_id, "Unknown request ID in _plexus_respond");
                Err(McpError::invalid_params(
                    format!("Unknown request ID: {}. The request may have timed out or been cancelled.", request_id),
                    None,
                ))
            }
            Err(BidirError::ChannelClosed) => {
                tracing::warn!(request_id = %request_id, "Channel closed in _plexus_respond");
                Err(McpError::internal_error(
                    "Response channel was closed (request may have timed out)",
                    None,
                ))
            }
            Err(e) => {
                tracing::error!(request_id = %request_id, error = ?e, "Error in _plexus_respond");
                Err(McpError::internal_error(format!("Failed to deliver response: {}", e), None))
            }
        }
    }
}

impl ServerHandler for PlexusMcpBridge {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::LATEST,
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .enable_logging()
                .build(),
            server_info: Implementation::from_build_env(),
            instructions: Some(
                "Plexus MCP server - provides access to all registered activations.".into(),
            ),
        }
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParam>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let schemas = self.hub.list_plugin_schemas();
        let tools = schemas_to_rmcp_tools(schemas);

        tracing::debug!("Listing {} tools", tools.len());

        Ok(ListToolsResult {
            tools,
            next_cursor: None,
            meta: None,
        })
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParam,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let method_name = &request.name;

        // Handle _plexus_respond tool specially
        if method_name == "_plexus_respond" {
            return self.handle_plexus_respond(request).await;
        }

        let arguments = request
            .arguments
            .map(serde_json::Value::Object)
            .unwrap_or(json!({}));

        tracing::debug!("Calling tool: {} with args: {:?}", method_name, arguments);

        // Get progress token if provided
        let progress_token = ctx.meta.get_progress_token();

        // Logger name: plexus.namespace.method (e.g., plexus.bash.execute)
        let logger = format!("plexus.{}", method_name);

        // Call Plexus RPC hub and get stream
        let stream = self
            .hub
            .route(method_name, arguments, None)
            .await
            .map_err(plexus_to_mcp_error)?;

        // Stream events via notifications AND buffer for final result
        let mut had_error = false;
        let mut buffered_data: Vec<serde_json::Value> = Vec::new();
        let mut error_messages: Vec<String> = Vec::new();

        tokio::pin!(stream);
        while let Some(item) = stream.next().await {
            // Check cancellation on each iteration
            if ctx.ct.is_cancelled() {
                return Err(McpError::internal_error("Cancelled", None));
            }

            match &item {
                PlexusStreamItem::Progress {
                    message,
                    percentage,
                    ..
                } => {
                    // Only send progress if client provided token
                    if let Some(ref token) = progress_token {
                        let _ = ctx
                            .peer
                            .notify_progress(ProgressNotificationParam {
                                progress_token: token.clone(),
                                progress: percentage.unwrap_or(0.0) as f64,
                                total: None,
                                message: Some(message.clone()),
                            })
                            .await;
                    }
                }

                PlexusStreamItem::Data {
                    content, content_type, ..
                } => {
                    // Buffer data for final result
                    buffered_data.push(content.clone());

                    // Also stream via notifications for real-time consumers
                    let _ = ctx
                        .peer
                        .notify_logging_message(LoggingMessageNotificationParam {
                            level: LoggingLevel::Info,
                            logger: Some(logger.clone()),
                            data: json!({
                                "type": "data",
                                "content_type": content_type,
                                "data": content,
                            }),
                        })
                        .await;
                }

                PlexusStreamItem::Error {
                    message, recoverable, ..
                } => {
                    // Buffer errors for final result
                    error_messages.push(message.clone());

                    let _ = ctx
                        .peer
                        .notify_logging_message(LoggingMessageNotificationParam {
                            level: LoggingLevel::Error,
                            logger: Some(logger.clone()),
                            data: json!({
                                "type": "error",
                                "error": message,
                                "recoverable": recoverable,
                            }),
                        })
                        .await;

                    if !recoverable {
                        had_error = true;
                    }
                }

                PlexusStreamItem::Request {
                    request_id,
                    request_data,
                    timeout_ms,
                } => {
                    // Send bidirectional request as logging notification
                    // Client responds via _plexus_respond tool call
                    tracing::debug!(
                        request_id = %request_id,
                        timeout_ms = timeout_ms,
                        "Sending bidirectional request notification"
                    );

                    let _ = ctx
                        .peer
                        .notify_logging_message(LoggingMessageNotificationParam {
                            level: LoggingLevel::Info,
                            logger: Some("plexus.bidir".into()),
                            data: json!({
                                "type": "request",
                                "request_id": request_id,
                                "request_data": request_data,
                                "timeout_ms": timeout_ms,
                            }),
                        })
                        .await;
                }

                PlexusStreamItem::Done { .. } => {
                    break;
                }
            }
        }

        // Return buffered data in the final result
        if had_error {
            let error_content = if error_messages.is_empty() {
                "Stream completed with errors".to_string()
            } else {
                error_messages.join("\n")
            };
            Ok(CallToolResult::error(vec![Content::text(error_content)]))
        } else {
            // Convert buffered data to content
            let text_content = if buffered_data.is_empty() {
                "(no output)".to_string()
            } else if buffered_data.len() == 1 {
                // Single value - return as text if string, otherwise JSON
                match &buffered_data[0] {
                    serde_json::Value::String(s) => s.clone(),
                    other => serde_json::to_string_pretty(other).unwrap_or_default(),
                }
            } else {
                // Multiple values - join strings or return as JSON array
                let all_strings = buffered_data.iter().all(|v| v.is_string());
                if all_strings {
                    buffered_data
                        .iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join("")
                } else {
                    serde_json::to_string_pretty(&buffered_data).unwrap_or_default()
                }
            };

            // Estimate tokens (~4 chars per token for JSON/text)
            let approx_tokens = (text_content.len() + 3) / 4;
            let content_with_tokens = format!(
                "{}\n\n[~{} tokens]",
                text_content,
                approx_tokens
            );

            Ok(CallToolResult::success(vec![Content::text(content_with_tokens)]))
        }
    }
}
