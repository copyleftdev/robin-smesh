//! LLM backend abstraction
//!
//! Supports OpenAI-compatible APIs and Anthropic Claude.

use async_openai::{
    config::OpenAIConfig,
    types::{
        ChatCompletionRequestMessage, ChatCompletionRequestSystemMessageArgs,
        ChatCompletionRequestUserMessageArgs, CreateChatCompletionRequestArgs,
    },
    Client,
};
use async_trait::async_trait;
use std::sync::Arc;
use thiserror::Error;

/// LLM backend errors
#[derive(Debug, Error)]
pub enum LlmError {
    #[error("API error: {0}")]
    Api(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Rate limited")]
    RateLimited,

    #[error("Empty response")]
    EmptyResponse,
}

/// Generic LLM backend trait
#[async_trait]
pub trait LlmBackend: Send + Sync {
    /// Generate a completion with system prompt
    async fn generate(&self, system: &str, user: &str) -> Result<String, LlmError>;

    /// Get the model name
    fn model_name(&self) -> &str;
}

/// OpenAI-compatible backend configuration
#[derive(Debug, Clone)]
pub struct OpenAIBackendConfig {
    /// API key
    pub api_key: String,
    /// Base URL (for OpenRouter, local servers, etc.)
    pub base_url: Option<String>,
    /// Model name
    pub model: String,
    /// Temperature (0.0 - 2.0)
    pub temperature: f32,
    /// Max tokens
    pub max_tokens: u16,
}

impl Default for OpenAIBackendConfig {
    fn default() -> Self {
        Self {
            api_key: String::new(),
            base_url: None,
            model: "gpt-4o-mini".to_string(),
            temperature: 0.0,
            max_tokens: 4096,
        }
    }
}

impl OpenAIBackendConfig {
    pub fn openai(api_key: &str, model: &str) -> Self {
        Self {
            api_key: api_key.to_string(),
            model: model.to_string(),
            ..Default::default()
        }
    }

    pub fn openrouter(api_key: &str, model: &str) -> Self {
        Self {
            api_key: api_key.to_string(),
            base_url: Some("https://openrouter.ai/api/v1".to_string()),
            model: model.to_string(),
            ..Default::default()
        }
    }

    pub fn local(base_url: &str, model: &str) -> Self {
        Self {
            api_key: "sk-local".to_string(),
            base_url: Some(base_url.to_string()),
            model: model.to_string(),
            ..Default::default()
        }
    }
}

/// OpenAI-compatible LLM backend
pub struct OpenAIBackend {
    client: Client<OpenAIConfig>,
    config: OpenAIBackendConfig,
}

impl OpenAIBackend {
    pub fn new(config: OpenAIBackendConfig) -> Result<Self, LlmError> {
        let mut openai_config = OpenAIConfig::new().with_api_key(&config.api_key);

        if let Some(base_url) = &config.base_url {
            openai_config = openai_config.with_api_base(base_url);
        }

        let client = Client::with_config(openai_config);

        Ok(Self { client, config })
    }
}

#[async_trait]
impl LlmBackend for OpenAIBackend {
    async fn generate(&self, system: &str, user: &str) -> Result<String, LlmError> {
        let messages = vec![
            ChatCompletionRequestMessage::System(
                ChatCompletionRequestSystemMessageArgs::default()
                    .content(system)
                    .build()
                    .map_err(|e| LlmError::Api(e.to_string()))?,
            ),
            ChatCompletionRequestMessage::User(
                ChatCompletionRequestUserMessageArgs::default()
                    .content(user)
                    .build()
                    .map_err(|e| LlmError::Api(e.to_string()))?,
            ),
        ];

        let request = CreateChatCompletionRequestArgs::default()
            .model(&self.config.model)
            .messages(messages)
            .temperature(self.config.temperature)
            .max_tokens(self.config.max_tokens)
            .build()
            .map_err(|e| LlmError::Api(e.to_string()))?;

        let response = self
            .client
            .chat()
            .create(request)
            .await
            .map_err(|e| LlmError::Api(e.to_string()))?;

        response
            .choices
            .first()
            .and_then(|c| c.message.content.clone())
            .ok_or(LlmError::EmptyResponse)
    }

    fn model_name(&self) -> &str {
        &self.config.model
    }
}

/// Anthropic Claude backend configuration
#[derive(Debug, Clone)]
pub struct AnthropicConfig {
    /// API key
    pub api_key: String,
    /// Model name (e.g., claude-3-5-sonnet-20241022)
    pub model: String,
    /// Max tokens
    pub max_tokens: u32,
}

impl AnthropicConfig {
    pub fn new(api_key: &str, model: &str) -> Self {
        Self {
            api_key: api_key.to_string(),
            model: model.to_string(),
            max_tokens: 4096,
        }
    }
}

/// Anthropic Claude backend
pub struct AnthropicBackend {
    client: reqwest::Client,
    config: AnthropicConfig,
}

impl AnthropicBackend {
    pub fn new(config: AnthropicConfig) -> Result<Self, LlmError> {
        let client = reqwest::Client::new();
        Ok(Self { client, config })
    }
}

#[async_trait]
impl LlmBackend for AnthropicBackend {
    async fn generate(&self, system: &str, user: &str) -> Result<String, LlmError> {
        let request_body = serde_json::json!({
            "model": self.config.model,
            "max_tokens": self.config.max_tokens,
            "system": system,
            "messages": [
                {"role": "user", "content": user}
            ]
        });

        let response = self
            .client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.config.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&request_body)
            .send()
            .await
            .map_err(|e| LlmError::Api(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(LlmError::Api(format!("Anthropic API error {}: {}", status, text)));
        }

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| LlmError::Api(e.to_string()))?;

        json["content"]
            .as_array()
            .and_then(|arr| arr.first())
            .and_then(|block| block["text"].as_str())
            .map(|s| s.to_string())
            .ok_or(LlmError::EmptyResponse)
    }

    fn model_name(&self) -> &str {
        &self.config.model
    }
}

/// Thread-safe reference to an LLM backend
pub type SharedBackend = Arc<dyn LlmBackend>;

/// Create a shared OpenAI-compatible backend
pub fn create_backend(config: OpenAIBackendConfig) -> Result<SharedBackend, LlmError> {
    Ok(Arc::new(OpenAIBackend::new(config)?))
}

/// Create a shared Anthropic backend
pub fn create_anthropic_backend(config: AnthropicConfig) -> Result<SharedBackend, LlmError> {
    Ok(Arc::new(AnthropicBackend::new(config)?))
}
