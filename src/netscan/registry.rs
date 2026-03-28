use std::io::{Error, ErrorKind};
use winreg::RegKey;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY};

#[derive(Debug)]
pub enum ValueResult<T> {
    Missing,
    Value(T),
    NotReadable(String),
}

pub fn open_hklm_subkey(path: &str) -> Result<RegKey, Error> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    hklm.open_subkey_with_flags(path, KEY_READ | KEY_WOW64_64KEY)
}

pub fn enumerate_subkeys(key: &RegKey) -> Result<Vec<String>, Error> {
    let mut names = Vec::new();
    for item in key.enum_keys() {
        match item {
            Ok(name) => names.push(name),
            Err(e) => return Err(e),
        }
    }
    Ok(names)
}

pub fn value_exists(key: &RegKey, name: &str) -> Result<bool, Error> {
    match key.get_raw_value(name) {
        Ok(_) => Ok(true),
        Err(e) => {
            if e.kind() == ErrorKind::NotFound {
                Ok(false)
            } else {
                Err(e)
            }
        }
    }
}

pub fn read_string(key: &RegKey, name: &str) -> ValueResult<String> {
    match key.get_value::<String, _>(name) {
        Ok(v) => ValueResult::Value(v),
        Err(e) => {
            if e.kind() == ErrorKind::NotFound {
                ValueResult::Missing
            } else {
                ValueResult::NotReadable(e.to_string())
            }
        }
    }
}

pub fn read_u32_like(key: &RegKey, name: &str) -> ValueResult<u32> {
    match key.get_value::<u32, _>(name) {
        Ok(v) => ValueResult::Value(v),
        Err(dw_err) => {
            if dw_err.kind() == ErrorKind::NotFound {
                return ValueResult::Missing;
            }

            match key.get_value::<String, _>(name) {
                Ok(text) => match parse_numeric_like(&text) {
                    Some(v) => ValueResult::Value(v),
                    None => ValueResult::NotReadable(format!(
                        "Не удалось интерпретировать '{}' как число",
                        text.trim()
                    )),
                },
                Err(text_err) => {
                    if text_err.kind() == ErrorKind::NotFound {
                        ValueResult::Missing
                    } else {
                        ValueResult::NotReadable(format!("DWORD: {}; STRING: {}", dw_err, text_err))
                    }
                }
            }
        }
    }
}

pub fn read_text_like(key: &RegKey, name: &str) -> ValueResult<String> {
    match key.get_value::<String, _>(name) {
        Ok(v) => ValueResult::Value(v.trim_matches('\0').trim().to_string()),
        Err(str_err) => {
            if str_err.kind() == ErrorKind::NotFound {
                return ValueResult::Missing;
            }

            match key.get_value::<u32, _>(name) {
                Ok(v) => ValueResult::Value(v.to_string()),
                Err(dw_err) => {
                    if dw_err.kind() == ErrorKind::NotFound {
                        ValueResult::Missing
                    } else {
                        ValueResult::NotReadable(format!("STRING: {}; DWORD: {}", str_err, dw_err))
                    }
                }
            }
        }
    }
}

fn parse_numeric_like(input: &str) -> Option<u32> {
    let trimmed = input.trim().trim_matches('\0');
    if trimmed.is_empty() {
        return None;
    }

    let lower = trimmed.to_ascii_lowercase();
    if let Some(hex) = lower.strip_prefix("0x") {
        return u32::from_str_radix(hex, 16).ok();
    }

    let digits = trimmed
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>();
    if !digits.is_empty() {
        return digits.parse::<u32>().ok();
    }

    None
}

#[cfg(test)]
mod tests {
    use super::parse_numeric_like;

    #[test]
    fn parse_numeric_like_handles_decimal_and_hex() {
        assert_eq!(parse_numeric_like("1514"), Some(1514));
        assert_eq!(parse_numeric_like("1514 Bytes"), Some(1514));
        assert_eq!(parse_numeric_like("0x1"), Some(1));
    }

    #[test]
    fn parse_numeric_like_rejects_plain_text() {
        assert_eq!(parse_numeric_like("Disabled"), None);
        assert_eq!(parse_numeric_like(""), None);
    }
}
