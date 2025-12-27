#![forbid(unsafe_code)]

use regex::Regex;

pub fn matches_pattern(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if pattern.contains('*') {
        let escaped = regex::escape(&pattern.replace('*', "\x00"));
        let regex_pattern = format!("^{}$", escaped.replace("\x00", ".*"));
        if let Ok(re) = Regex::new(&regex_pattern) {
            return re.is_match(value);
        }
    }
    pattern == value
}

pub fn validate_name(name: &str) -> crate::Result<()> {
    if name.is_empty() {
        return Err(crate::Error::PolicyValidation(
            "name cannot be empty".into(),
        ));
    }
    if name.len() > 128 {
        return Err(crate::Error::PolicyValidation(
            "name must be 128 chars or less".into(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(crate::Error::PolicyValidation(
            "name must contain only alphanumeric, dash, or underscore".into(),
        ));
    }
    Ok(())
}

pub fn validate_approver_id(id: &str) -> crate::Result<()> {
    if id.is_empty() {
        return Err(crate::Error::PolicyValidation(
            "approver_id cannot be empty".into(),
        ));
    }
    if id.len() > 256 {
        return Err(crate::Error::PolicyValidation(
            "approver_id must be 256 chars or less".into(),
        ));
    }
    if !id.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '@' || c == ':'
    }) {
        return Err(crate::Error::PolicyValidation(
            "approver_id contains invalid characters".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches_pattern() {
        assert!(matches_pattern("*", "anything"));
        assert!(matches_pattern("treasury-*", "treasury-hot-1"));
        assert!(matches_pattern("treasury-hot-*", "treasury-hot-1"));
        assert!(!matches_pattern("treasury-hot-*", "treasury-cold-1"));
        assert!(matches_pattern("exact", "exact"));
        assert!(!matches_pattern("exact", "other"));
    }

    #[test]
    fn test_regex_metachar_escaped() {
        assert!(!matches_pattern("treasury-(.*)", "treasury-anything"));
        assert!(matches_pattern("treasury-(.*)", "treasury-(.*)"));
        assert!(!matches_pattern("a]b[c", "abc"));
        assert!(matches_pattern("a]b[c", "a]b[c"));
    }

    #[test]
    fn test_validate_name() {
        assert!(validate_name("valid-name_123").is_ok());
        assert!(validate_name("").is_err());
        assert!(validate_name("has spaces").is_err());
        assert!(validate_name("has@special").is_err());
        let long_name = "a".repeat(129);
        assert!(validate_name(&long_name).is_err());
    }
}
