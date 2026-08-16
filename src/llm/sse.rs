#[derive(Default)]
pub(crate) struct SseEventParser {
    pending: Vec<u8>,
    data_lines: Vec<String>,
}

impl SseEventParser {
    pub(crate) fn decode_line(line: Vec<u8>) -> String {
        match String::from_utf8(line) {
            Ok(line) => line,
            Err(err) => String::from_utf8_lossy(&err.into_bytes()).into_owned(),
        }
    }

    pub(crate) fn push_chunk(&mut self, chunk: impl AsRef<[u8]>) -> Vec<String> {
        self.pending.extend_from_slice(chunk.as_ref());
        let mut events = Vec::new();

        while let Some(pos) = self.pending.iter().position(|b| *b == b'\n') {
            let mut line = self.pending.drain(..=pos).collect::<Vec<_>>();
            if line.last() == Some(&b'\n') {
                line.pop();
            }
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            let line = Self::decode_line(line);
            if let Some(event_data) = self.handle_line(&line) {
                events.push(event_data);
            }
        }

        events
    }

    pub(crate) fn finish(&mut self) -> Vec<String> {
        let mut events = Vec::new();
        if !self.pending.is_empty() {
            let mut line = std::mem::take(&mut self.pending);
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            let line = Self::decode_line(line);
            if let Some(event_data) = self.handle_line(&line) {
                events.push(event_data);
            }
        }
        if let Some(event_data) = self.flush_event() {
            events.push(event_data);
        }
        events
    }

    pub(crate) fn handle_line(&mut self, line: &str) -> Option<String> {
        if line.is_empty() {
            return self.flush_event();
        }
        if line.starts_with(':') {
            return None;
        }

        let (field, value) = match line.split_once(':') {
            Some((f, v)) => {
                let v = v.strip_prefix(' ').unwrap_or(v);
                (f, v)
            }
            None => (line, ""),
        };

        if field == "data" {
            self.data_lines.push(value.to_string());
        }
        None
    }

    pub(crate) fn flush_event(&mut self) -> Option<String> {
        if self.data_lines.is_empty() {
            return None;
        }
        let data = self.data_lines.join("\n");
        self.data_lines.clear();
        Some(data)
    }
}

// ---------------------------------------------------------------------------
// Provider trait
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::llm::test_prelude::*;

    #[test]
    pub(crate) fn test_sse_event_parser_multiline_data() {
        let mut parser = SseEventParser::default();
        let events = parser
            .push_chunk("event: message\n: keep-alive\ndata: {\"type\":\"x\",\ndata: \"v\":1}\n\n");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], "{\"type\":\"x\",\n\"v\":1}");
    }

    #[test]
    pub(crate) fn test_sse_event_parser_finish_flushes_unterminated_event() {
        let mut parser = SseEventParser::default();
        let events = parser.push_chunk("data: hello");
        assert!(events.is_empty());
        let tail = parser.finish();
        assert_eq!(tail, vec!["hello".to_string()]);
    }

    #[test]
    pub(crate) fn test_sse_event_parser_preserves_split_utf8_bytes() {
        let mut parser = SseEventParser::default();
        let raw = "data: 主要\n\n".as_bytes();
        let split = raw.iter().position(|b| *b >= 0x80).unwrap() + 1;
        let head = parser.push_chunk(&raw[..split]);
        assert!(head.is_empty());
        let tail = parser.push_chunk(&raw[split..]);
        assert_eq!(tail, vec!["主要".to_string()]);
    }
}
