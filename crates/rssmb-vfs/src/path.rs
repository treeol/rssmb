//! Path normalization and validation for SMB paths.
//!
//! SMB clients use `\` as the path separator. The server must normalize
//! paths to the OS-native format, enforce case policy, prevent path
//! traversal attacks, and reject invalid path names per MS-SMB2 / MS-FSCC.
//!
//! All input paths are NFC-normalized to handle macOS NFD clients.

use std::path::PathBuf;
use unicode_normalization::UnicodeNormalization;

/// Maximum path length in UTF-16 code units (MS-FSCC MAX_PATH).
const MAX_PATH_UTF16: usize = 32_767;

/// Maximum component (name) length in UTF-16 code units (NTFS limit).
/// `pub(crate)`: used by `publish` to budget temp-name suffixes.
pub(crate) const MAX_COMPONENT_UTF16: usize = 255;

/// Characters that are forbidden in SMB path names.
///
/// - 0x00–0x1F: C0 control characters (NUL, CR, LF, …)
/// - 0x7F: DEL
/// - `< > : " | ? *`: reserved by Windows / SMB (note: `:` is the stream
///   separator in MS-FSCC §2.1.5)
const RESERVED_CHARS: &[char] = &['<', '>', ':', '"', '|', '?', '*'];

/// A normalized path within a share.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NormalizedPath {
    /// The normalized path components (no separators, no `.` or `..`).
    components: Vec<String>,
    /// Whether this is a directory path (ends with `\`).
    is_directory: bool,
}

impl NormalizedPath {
    /// Normalize an SMB path from the wire (using `\` separators).
    ///
    /// This function:
    /// 1. NFC-normalizes the input (macOS sends NFD).
    /// 2. Splits on `\` and `/`
    /// 3. Resolves `.` (current directory) — skipped
    /// 4. Rejects `..` (parent directory) — path traversal prevention
    /// 5. Rejects control/reserved characters, trailing dot/space, and
    ///    over-length components or total path
    /// 6. Converts to OS-native path separators
    ///
    /// Returns an error if path traversal is detected or the name is invalid.
    pub fn from_smb_path(path: &str) -> Result<Self, PathError> {
        if path.is_empty() {
            return Ok(Self {
                components: vec![],
                is_directory: true,
            });
        }

        // NFC normalization — macOS clients send NFD (decomposed) form.
        let nfc = path.nfc().collect::<String>();

        let is_directory = nfc.ends_with('\\') || nfc.ends_with('/');

        let mut components = Vec::new();
        for part in nfc.split(['\\', '/']) {
            if part.is_empty() || part == "." {
                continue;
            }
            if part == ".." {
                // Path traversal — never allow escaping share root
                return Err(PathError::TraversalDetected);
            }

            // Validate the component name.
            validate_component(part)?;

            components.push(part.to_string());
        }

        // Total UTF-16 length check (sum of components + separators).
        let total_utf16: usize = components
            .iter()
            .map(|c| c.encode_utf16().count())
            .sum::<usize>()
            + components.len().saturating_sub(1); // separators
        if total_utf16 > MAX_PATH_UTF16 {
            return Err(PathError::InvalidName);
        }

        Ok(Self {
            components,
            is_directory,
        })
    }

    /// Convert to an OS-native PathBuf relative to the share root.
    /// Uses the platform-native separator.
    pub fn to_pathbuf(&self) -> PathBuf {
        let mut path = PathBuf::new();
        for comp in &self.components {
            path.push(comp);
        }
        path
    }

    /// Get the path as a string with `\` separators (for SMB responses).
    pub fn to_smb_string(&self) -> String {
        self.components.join("\\")
    }

    /// Is this the root of the share (empty path)?
    pub fn is_root(&self) -> bool {
        self.components.is_empty()
    }

    /// Get the number of path components.
    pub fn depth(&self) -> usize {
        self.components.len()
    }

    /// Get the last component (file/directory name).
    pub fn file_name(&self) -> Option<&str> {
        self.components.last().map(|s| s.as_str())
    }

    /// Get the parent path.
    pub fn parent(&self) -> Option<NormalizedPath> {
        if self.components.is_empty() {
            return None;
        }
        let parent_components = self.components[..self.components.len() - 1].to_vec();
        Some(Self {
            components: parent_components,
            is_directory: true,
        })
    }
}

/// Validate a single path component (file/directory name).
///
/// Rejects:
/// - C0 control characters (0x00–0x1F) and DEL (0x7F)
/// - Reserved characters: `< > : " | ? *`
/// - Trailing dot or space (Windows strips them, causing ambiguity)
/// - Component length > 255 UTF-16 code units
fn validate_component(name: &str) -> Result<(), PathError> {
    // Length check: count UTF-16 code units (not chars — supplementary
    // plane characters like emoji use 2 UTF-16 units).
    let utf16_len: usize = name.encode_utf16().count();
    if utf16_len > MAX_COMPONENT_UTF16 {
        return Err(PathError::InvalidName);
    }

    // Character check: reject control chars, DEL, and reserved chars.
    for ch in name.chars() {
        let code = ch as u32;
        if code <= 0x1F || code == 0x7F {
            return Err(PathError::InvalidName);
        }
        if RESERVED_CHARS.contains(&ch) {
            return Err(PathError::InvalidName);
        }
    }

    // Trailing dot or space — Windows silently strips these, which can
    // cause security issues (e.g., `file.txt. ` vs `file.txt`).
    if name.ends_with('.') || name.ends_with(' ') {
        return Err(PathError::InvalidName);
    }

    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum PathError {
    #[error("path traversal detected (contains '..')")]
    TraversalDetected,
    #[error("invalid path name")]
    InvalidName,
    #[error("invalid path encoding")]
    InvalidEncoding,
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_simple_path() {
        let p = NormalizedPath::from_smb_path("docs\\file.txt").unwrap();
        assert_eq!(p.depth(), 2);
        assert_eq!(p.file_name(), Some("file.txt"));
        assert_eq!(p.to_smb_string(), "docs\\file.txt");
    }

    #[test]
    fn test_root_path() {
        let p = NormalizedPath::from_smb_path("").unwrap();
        assert!(p.is_root());
        assert_eq!(p.depth(), 0);
    }

    #[test]
    fn test_traversal_rejected() {
        assert!(NormalizedPath::from_smb_path("..\\..\\etc\\passwd").is_err());
        assert!(NormalizedPath::from_smb_path("docs\\..\\..\\escape").is_err());
    }

    #[test]
    fn test_dot_ignored() {
        let p = NormalizedPath::from_smb_path(".\\docs\\.\\file.txt").unwrap();
        assert_eq!(p.depth(), 2);
        assert_eq!(p.to_smb_string(), "docs\\file.txt");
    }

    #[test]
    fn test_forward_slash() {
        let p = NormalizedPath::from_smb_path("docs/file.txt").unwrap();
        assert_eq!(p.depth(), 2);
        assert_eq!(p.to_smb_string(), "docs\\file.txt");
    }

    #[test]
    fn test_directory_path() {
        let p = NormalizedPath::from_smb_path("docs\\").unwrap();
        assert!(p.is_directory);
    }

    #[test]
    fn test_parent() {
        let p = NormalizedPath::from_smb_path("docs\\subdir\\file.txt").unwrap();
        let parent = p.parent().unwrap();
        assert_eq!(parent.to_smb_string(), "docs\\subdir");
        assert!(parent.is_directory);
    }

    #[test]
    fn test_to_pathbuf() {
        let p = NormalizedPath::from_smb_path("docs\\file.txt").unwrap();
        let pb = p.to_pathbuf();
        assert_eq!(pb, PathBuf::from("docs").join("file.txt"));
    }

    // --- Name validation tests (Phase 1.2) ---

    #[test]
    fn test_reject_control_chars() {
        assert!(NormalizedPath::from_smb_path("file\x00.txt").is_err());
        assert!(NormalizedPath::from_smb_path("file\x01.txt").is_err());
        assert!(NormalizedPath::from_smb_path("file\x1f.txt").is_err());
        assert!(NormalizedPath::from_smb_path("file\x7f.txt").is_err());
        assert!(NormalizedPath::from_smb_path("file\n.txt").is_err());
        assert!(NormalizedPath::from_smb_path("file\r.txt").is_err());
        assert!(NormalizedPath::from_smb_path("file\t.txt").is_err());
    }

    #[test]
    fn test_reject_reserved_chars() {
        assert!(NormalizedPath::from_smb_path("file<.txt").is_err());
        assert!(NormalizedPath::from_smb_path("file>.txt").is_err());
        assert!(NormalizedPath::from_smb_path("file:.txt").is_err());
        assert!(NormalizedPath::from_smb_path("file\".txt").is_err());
        assert!(NormalizedPath::from_smb_path("file|.txt").is_err());
        assert!(NormalizedPath::from_smb_path("file?.txt").is_err());
        assert!(NormalizedPath::from_smb_path("file*.txt").is_err());
    }

    #[test]
    fn test_reject_trailing_dot() {
        assert!(NormalizedPath::from_smb_path("file.").is_err());
        assert!(NormalizedPath::from_smb_path("file.txt.").is_err());
        assert!(NormalizedPath::from_smb_path("dir.\\file.txt").is_err());
    }

    #[test]
    fn test_reject_trailing_space() {
        assert!(NormalizedPath::from_smb_path("file ").is_err());
        assert!(NormalizedPath::from_smb_path("file.txt ").is_err());
        assert!(NormalizedPath::from_smb_path("dir \\file.txt").is_err());
    }

    #[test]
    fn test_accept_valid_names() {
        assert!(NormalizedPath::from_smb_path("file.txt").is_ok());
        assert!(NormalizedPath::from_smb_path("file with spaces.txt").is_ok());
        assert!(NormalizedPath::from_smb_path("file.with.dots.txt").is_ok());
        assert!(NormalizedPath::from_smb_path("file-with-dashes.txt").is_ok());
        assert!(NormalizedPath::from_smb_path("file_with_underscores.txt").is_ok());
        assert!(NormalizedPath::from_smb_path("file+plus.txt").is_ok());
        assert!(NormalizedPath::from_smb_path("café.txt").is_ok());
        assert!(NormalizedPath::from_smb_path("file; semicolon.txt").is_ok());
        assert!(NormalizedPath::from_smb_path("file, comma.txt").is_ok());
    }

    #[test]
    fn test_nfc_normalization() {
        // NFD form: é = U+0065 + U+0301 (e + combining acute)
        let nfd = "caf\u{0065}\u{0301}.txt";
        let p = NormalizedPath::from_smb_path(nfd).unwrap();
        assert_eq!(p.file_name(), Some("café.txt"));
        // NFC form should be identical
        let nfc = "café.txt";
        let p2 = NormalizedPath::from_smb_path(nfc).unwrap();
        assert_eq!(p.to_smb_string(), p2.to_smb_string());
    }

    #[test]
    fn test_reject_long_component() {
        let long_name = "a".repeat(256);
        assert!(NormalizedPath::from_smb_path(&long_name).is_err());
    }

    #[test]
    fn test_utf16_supplementary_chars_counted_correctly() {
        // U+1F600 (😀) is a supplementary plane character — 1 char but
        // 2 UTF-16 code units. 128 of these = 256 UTF-16 units, which
        // should pass the 255 limit if counted as chars but fail as UTF-16.
        let emoji_128: String = "😀".repeat(128);
        assert!(
            NormalizedPath::from_smb_path(&emoji_128).is_err(),
            "128 emoji = 256 UTF-16 units, should exceed 255 limit"
        );
        // 127 emoji = 254 UTF-16 units — should pass.
        let emoji_127: String = "😀".repeat(127);
        assert!(
            NormalizedPath::from_smb_path(&emoji_127).is_ok(),
            "127 emoji = 254 UTF-16 units, should pass"
        );
    }

    #[test]
    fn test_accept_max_component() {
        let max_name = "a".repeat(255);
        assert!(NormalizedPath::from_smb_path(&max_name).is_ok());
    }

    #[test]
    fn test_reject_long_path() {
        // 255-char components * 130 = 255*130 + 129 separators = 33179 > 32767 (MAX_PATH).
        let max_component = "a".repeat(255);
        let mut path = String::new();
        for _ in 0..130 {
            if !path.is_empty() {
                path.push('\\');
            }
            path.push_str(&max_component);
        }
        assert!(NormalizedPath::from_smb_path(&path).is_err());
    }

    // ---- Property tests (Phase 6.4) ----

    proptest! {
        /// from_smb_path should never panic on arbitrary valid UTF-8.
        #[test]
        fn prop_from_smb_path_no_panic(s in ".*") {
            let _ = NormalizedPath::from_smb_path(&s);
        }

        /// A path with traversal (..) should always be rejected, regardless
        /// of where it appears.
        #[test]
        fn prop_traversal_always_rejected(
            prefix in ".*",
            suffix in ".*",
        ) {
            let path = format!("{}\\..\\{}", prefix, suffix);
            prop_assert!(NormalizedPath::from_smb_path(&path).is_err(),
                "traversal path accepted: {:?}", path);
        }

        /// A simple valid path (alphanumeric components separated by \)
        /// should always be accepted.
        #[test]
        fn prop_simple_valid_path(
            comps in proptest::collection::vec("[a-zA-Z0-9]{1,50}", 1..=10)
        ) {
            let path = comps.join("\\");
            let result = NormalizedPath::from_smb_path(&path);
            prop_assert!(result.is_ok(),
                "valid path rejected: {:?}", path);
        }

        /// NFC normalization: any input should produce a path whose
        /// components are in NFC form (idempotent — normalizing again
        /// should produce the same result).
        #[test]
        fn prop_nfc_idempotent(s in ".*") {
            if let Ok(p1) = NormalizedPath::from_smb_path(&s) {
                let smb_str = p1.to_smb_string();
                let p2 = NormalizedPath::from_smb_path(&smb_str).unwrap();
                prop_assert_eq!(p1.to_smb_string(), p2.to_smb_string(),
                    "NFC not idempotent for {:?}", s);
            }
        }

        /// Paths with control characters should always be rejected.
        #[test]
        fn prop_control_chars_rejected(c in 0u8..=0x1f) {
            let path = format!("file{}test", char::from_u32(c as u32).unwrap());
            prop_assert!(NormalizedPath::from_smb_path(&path).is_err(),
                "control char 0x{:02x} accepted", c);
        }
    }
}
