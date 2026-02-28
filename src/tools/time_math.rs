use async_trait::async_trait;
use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone, Utc};
use serde_json::json;

use microclaw_core::llm_types::ToolDefinition;

use super::{schema_object, Tool, ToolResult};

pub struct GetCurrentTimeTool {
    default_timezone: String,
}

impl GetCurrentTimeTool {
    pub fn new(default_timezone: String) -> Self {
        Self { default_timezone }
    }
}

pub struct CompareTimeTool {
    default_timezone: String,
}

impl CompareTimeTool {
    pub fn new(default_timezone: String) -> Self {
        Self { default_timezone }
    }
}

pub struct CalculateTool;

impl CalculateTool {
    pub fn new() -> Self {
        Self
    }
}

fn parse_timezone(tz_name: &str) -> Result<chrono_tz::Tz, String> {
    tz_name
        .parse::<chrono_tz::Tz>()
        .map_err(|_| format!("Invalid timezone: {tz_name}"))
}

fn parse_timestamp(value: &str, tz: chrono_tz::Tz) -> Result<DateTime<Utc>, String> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(value) {
        return Ok(dt.with_timezone(&Utc));
    }

    let naive_formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M",
    ];
    for fmt in naive_formats {
        if let Ok(naive) = NaiveDateTime::parse_from_str(value, fmt) {
            let local = tz.from_local_datetime(&naive).single().ok_or_else(|| {
                format!("Ambiguous or invalid local datetime in timezone {tz}: {value}")
            })?;
            return Ok(local.with_timezone(&Utc));
        }
    }

    if let Ok(date_only) = NaiveDate::parse_from_str(value, "%Y-%m-%d") {
        let naive = date_only
            .and_hms_opt(0, 0, 0)
            .ok_or_else(|| "Invalid date value".to_string())?;
        let local = tz.from_local_datetime(&naive).single().ok_or_else(|| {
            format!("Ambiguous or invalid local datetime in timezone {tz}: {value}")
        })?;
        return Ok(local.with_timezone(&Utc));
    }

    Err("Invalid timestamp. Use RFC3339 or local format like `YYYY-MM-DD HH:MM[:SS]`.".to_string())
}

#[async_trait]
impl Tool for GetCurrentTimeTool {
    fn name(&self) -> &str {
        "get_current_time"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: self.name().into(),
            description: "Get current time in UTC and a target timezone.".into(),
            input_schema: schema_object(
                json!({
                    "timezone": {
                        "type": "string",
                        "description": "Optional IANA timezone, e.g. Asia/Shanghai. Defaults to configured timezone."
                    }
                }),
                &[],
            ),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let tz_name = input
            .get("timezone")
            .and_then(|v| v.as_str())
            .unwrap_or(&self.default_timezone);
        let tz = match parse_timezone(tz_name) {
            Ok(tz) => tz,
            Err(e) => return ToolResult::error(e),
        };

        let now_utc = Utc::now();
        let now_local = now_utc.with_timezone(&tz);
        ToolResult::success(format!(
            "timezone: {tz}\nlocal_time: {}\nutc_time: {}\nunix_seconds: {}\nunix_millis: {}",
            now_local.to_rfc3339(),
            now_utc.to_rfc3339(),
            now_utc.timestamp(),
            now_utc.timestamp_millis()
        ))
    }
}

#[async_trait]
impl Tool for CompareTimeTool {
    fn name(&self) -> &str {
        "compare_time"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: self.name().into(),
            description:
                "Compare two timestamps and return which one is earlier/later plus the difference."
                    .into(),
            input_schema: schema_object(
                json!({
                    "left": {
                        "type": "string",
                        "description": "Left timestamp (RFC3339 or local datetime)"
                    },
                    "right": {
                        "type": "string",
                        "description": "Right timestamp (RFC3339 or local datetime)"
                    },
                    "timezone": {
                        "type": "string",
                        "description": "Timezone used when timestamps are provided without offset."
                    }
                }),
                &["left", "right"],
            ),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let left_raw = match input.get("left").and_then(|v| v.as_str()) {
            Some(v) => v,
            None => return ToolResult::error("Missing required parameter: left".into()),
        };
        let right_raw = match input.get("right").and_then(|v| v.as_str()) {
            Some(v) => v,
            None => return ToolResult::error("Missing required parameter: right".into()),
        };
        let tz_name = input
            .get("timezone")
            .and_then(|v| v.as_str())
            .unwrap_or(&self.default_timezone);
        let tz = match parse_timezone(tz_name) {
            Ok(tz) => tz,
            Err(e) => return ToolResult::error(e),
        };

        let left = match parse_timestamp(left_raw, tz) {
            Ok(v) => v,
            Err(e) => return ToolResult::error(format!("Invalid left timestamp: {e}")),
        };
        let right = match parse_timestamp(right_raw, tz) {
            Ok(v) => v,
            Err(e) => return ToolResult::error(format!("Invalid right timestamp: {e}")),
        };

        let delta = right - left;
        let delta_secs = delta.num_seconds();
        let abs_secs = delta_secs.unsigned_abs();
        let hours = abs_secs / 3600;
        let minutes = (abs_secs % 3600) / 60;
        let seconds = abs_secs % 60;
        let relation = if delta_secs > 0 {
            "left_is_earlier"
        } else if delta_secs < 0 {
            "left_is_later"
        } else {
            "equal"
        };

        ToolResult::success(format!(
            "timezone_for_naive_input: {tz}\nleft_utc: {}\nright_utc: {}\nrelation: {relation}\ndelta_seconds_right_minus_left: {delta_secs}\ndelta_hms_abs: {:02}:{:02}:{:02}",
            left.to_rfc3339(),
            right.to_rfc3339(),
            hours,
            minutes,
            seconds
        ))
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Number(f64),
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    LParen,
    RParen,
}

fn tokenize(expr: &str) -> Result<Vec<Token>, String> {
    let mut out = Vec::new();
    let mut i = 0usize;
    let bytes = expr.as_bytes();

    while i < bytes.len() {
        match bytes[i] as char {
            ' ' | '\t' | '\n' | '\r' => i += 1,
            '+' => {
                out.push(Token::Plus);
                i += 1;
            }
            '-' => {
                out.push(Token::Minus);
                i += 1;
            }
            '*' => {
                out.push(Token::Star);
                i += 1;
            }
            '/' => {
                out.push(Token::Slash);
                i += 1;
            }
            '%' => {
                out.push(Token::Percent);
                i += 1;
            }
            '(' => {
                out.push(Token::LParen);
                i += 1;
            }
            ')' => {
                out.push(Token::RParen);
                i += 1;
            }
            c if c.is_ascii_digit() || c == '.' => {
                let start = i;
                i += 1;
                while i < bytes.len() {
                    let ch = bytes[i] as char;
                    if ch.is_ascii_digit() || ch == '.' {
                        i += 1;
                    } else {
                        break;
                    }
                }
                let number = expr[start..i]
                    .parse::<f64>()
                    .map_err(|_| format!("Invalid number: {}", &expr[start..i]))?;
                if !number.is_finite() {
                    return Err("Non-finite number is not allowed".into());
                }
                out.push(Token::Number(number));
            }
            _ => {
                return Err(format!(
                    "Unsupported character in expression: {}",
                    bytes[i] as char
                ))
            }
        }
    }

    if out.is_empty() {
        return Err("Expression is empty".into());
    }
    Ok(out)
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn consume(&mut self) {
        self.pos += 1;
    }

    fn parse_expression(&mut self) -> Result<f64, String> {
        let mut value = self.parse_term()?;
        loop {
            match self.peek() {
                Some(Token::Plus) => {
                    self.consume();
                    value += self.parse_term()?;
                }
                Some(Token::Minus) => {
                    self.consume();
                    value -= self.parse_term()?;
                }
                _ => break,
            }
        }
        Ok(value)
    }

    fn parse_term(&mut self) -> Result<f64, String> {
        let mut value = self.parse_unary()?;
        loop {
            match self.peek() {
                Some(Token::Star) => {
                    self.consume();
                    value *= self.parse_unary()?;
                }
                Some(Token::Slash) => {
                    self.consume();
                    let rhs = self.parse_unary()?;
                    if rhs == 0.0 {
                        return Err("Division by zero".into());
                    }
                    value /= rhs;
                }
                Some(Token::Percent) => {
                    self.consume();
                    let rhs = self.parse_unary()?;
                    if rhs == 0.0 {
                        return Err("Modulo by zero".into());
                    }
                    value %= rhs;
                }
                _ => break,
            }
        }
        Ok(value)
    }

    fn parse_unary(&mut self) -> Result<f64, String> {
        match self.peek() {
            Some(Token::Plus) => {
                self.consume();
                self.parse_unary()
            }
            Some(Token::Minus) => {
                self.consume();
                Ok(-self.parse_unary()?)
            }
            _ => self.parse_primary(),
        }
    }

    fn parse_primary(&mut self) -> Result<f64, String> {
        match self.peek().cloned() {
            Some(Token::Number(n)) => {
                self.consume();
                Ok(n)
            }
            Some(Token::LParen) => {
                self.consume();
                let value = self.parse_expression()?;
                match self.peek() {
                    Some(Token::RParen) => {
                        self.consume();
                        Ok(value)
                    }
                    _ => Err("Missing closing ')'".into()),
                }
            }
            _ => Err("Expected a number or '('".into()),
        }
    }
}

fn eval_expression(expr: &str) -> Result<f64, String> {
    let tokens = tokenize(expr)?;
    let mut parser = Parser::new(tokens);
    let value = parser.parse_expression()?;
    if parser.peek().is_some() {
        return Err("Unexpected trailing tokens".into());
    }
    if !value.is_finite() {
        return Err("Result is non-finite".into());
    }
    Ok(value)
}

#[async_trait]
impl Tool for CalculateTool {
    fn name(&self) -> &str {
        "calculate"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: self.name().into(),
            description: "Evaluate a basic arithmetic expression. Supports +, -, *, /, %, parentheses, unary +/-.".into(),
            input_schema: schema_object(
                json!({
                    "expression": {
                        "type": "string",
                        "description": "Arithmetic expression, e.g. (2+3)*4-1"
                    }
                }),
                &["expression"],
            ),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> ToolResult {
        let expr = match input.get("expression").and_then(|v| v.as_str()) {
            Some(v) => v,
            None => return ToolResult::error("Missing required parameter: expression".into()),
        };

        match eval_expression(expr) {
            Ok(v) => ToolResult::success(format!("{v}")),
            Err(e) => ToolResult::error(format!("Invalid expression: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_get_current_time_tool() {
        let tool = GetCurrentTimeTool::new("UTC".into());
        let out = tool.execute(json!({ "timezone": "Asia/Shanghai" })).await;
        assert!(!out.is_error);
        assert!(out.content.contains("timezone: Asia/Shanghai"));
        assert!(out.content.contains("utc_time:"));
    }

    #[tokio::test]
    async fn test_compare_time_tool() {
        let tool = CompareTimeTool::new("UTC".into());
        let out = tool
            .execute(json!({
                "left": "2026-02-28T00:00:00Z",
                "right": "2026-02-28T01:00:00Z"
            }))
            .await;
        assert!(!out.is_error);
        assert!(out.content.contains("relation: left_is_earlier"));
        assert!(out.content.contains("delta_seconds_right_minus_left: 3600"));
    }

    #[tokio::test]
    async fn test_calculate_tool() {
        let tool = CalculateTool::new();
        let out = tool
            .execute(json!({ "expression": "(2 + 3) * 4 - 1"}))
            .await;
        assert!(!out.is_error);
        assert_eq!(out.content, "19");
    }

    #[test]
    fn test_eval_expression_negative_and_mod() {
        let v = eval_expression("-10 % 3 + 2").unwrap();
        assert_eq!(v, 1.0);
    }

    #[test]
    fn test_eval_expression_rejects_div_zero() {
        let err = eval_expression("1/0").unwrap_err();
        assert!(err.contains("Division by zero"));
    }
}
