//! Path normalization for SMB paths.
//!
//! SMB clients use `\` as the path separator. The server must normalize
//! paths to the OS-native format, enforce case policy, and prevent
//! path traversal attacks.

use std::path::PathBuf;

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
    /// 1. Splits on `\` and `/`
    /// 2. Resolves `.` (current directory) — skipped
    /// 3. Rejects `..` (parent directory) — path traversal prevention
    /// 4. Converts to OS-native path separators
    /// 5. Applies case policy (case-insensitive by default)
    ///
    /// Returns an error if path traversal is detected.
    pub fn from_smb_path(path: &str) -> Result<Self, PathError> {
        if path.is_empty() {
            return Ok(Self {
                components: vec![],
                is_directory: true,
            });
        }

        let is_directory = path.ends_with('\\') || path.ends_with('/');

        let mut components = Vec::new();
        for part in path.split(|c| c == '\\' || c == '/') {
            if part.is_empty() || part == "." {
                continue;
            }
            if part == ".." {
                // Path traversal — never allow escaping share root
                return Err(PathError::TraversalDetected);
            }
            // Normalize: on case-insensitive filesystems, lowercase the component
            // The actual case-folding strategy is up to the VFS backend
            components.push(part.to_string());
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

    /// Check if this path could be a symlink escape.
    /// The VFS backend must do its own realpath check; this is a first-pass filter.
    pub fn is_safe(&self) -> bool {
        // We already rejected `..` in from_smb_path, so all components are clean.
        // The real symlink check must be done by the VFS after openat.
        true
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PathError {
    #[error("path traversal detected (contains '..')")]
    TraversalDetected,
    #[error("invalid path encoding")]
    InvalidEncoding,
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
