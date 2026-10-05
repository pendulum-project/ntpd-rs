use std::{
    io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

/// The documents a configuration is loaded from.
pub trait Files {
    /// The contents of a single document.
    fn read(&self, path: &Path) -> io::Result<String>;

    /// All the files/entries in a directory, in no particular order.
    fn list(&self, directory: &Path) -> io::Result<Vec<PathBuf>>;
}

/// The real filesystem.
pub struct Filesystem;

impl Files for Filesystem {
    fn read(&self, path: &Path) -> io::Result<String> {
        let meta = std::fs::metadata(path)?;
        let perm = meta.permissions();

        if perm.mode() as libc::mode_t & libc::S_IWOTH != 0 {
            warn!(
                "Unrestricted config file permissions on {}: Others can write.",
                path.display()
            );
        }
        std::fs::read_to_string(path)
    }

    fn list(&self, directory: &Path) -> io::Result<Vec<PathBuf>> {
        let meta = std::fs::metadata(directory)?;
        let perm = meta.permissions();

        if perm.mode() as libc::mode_t & libc::S_IWOTH != 0 {
            warn!(
                "Unrestricted config directory permissions on {}: Others can write.",
                directory.display()
            );
        }
        std::fs::read_dir(directory)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect()
    }
}

#[cfg(test)]
pub use memory::Memory;
use tracing::warn;

#[cfg(test)]
mod memory {
    use std::collections::{HashMap, HashSet};

    use super::*;

    /// Documents that only exist for the duration of a test.
    #[derive(Debug, Default)]
    pub struct Memory {
        documents: HashMap<PathBuf, String>,
        directories: HashSet<PathBuf>,
    }

    impl Memory {
        pub fn new() -> Self {
            Self::default()
        }

        /// Add a document, and the directory holding it.
        pub fn document(mut self, path: impl Into<PathBuf>, contents: &str) -> Self {
            let path = path.into();

            if let Some(parent) = path.parent() {
                self.directories.insert(parent.to_path_buf());
            }
            self.documents.insert(path, contents.to_owned());

            self
        }

        /// Add a directory holding no documents, which is not the same as one
        /// that does not exist.
        pub fn directory(mut self, path: impl Into<PathBuf>) -> Self {
            self.directories.insert(path.into());
            self
        }
    }

    fn not_found(what: &str) -> io::Error {
        io::Error::new(io::ErrorKind::NotFound, format!("no such {what}"))
    }

    impl Files for Memory {
        fn read(&self, path: &Path) -> io::Result<String> {
            self.documents
                .get(path)
                .cloned()
                .ok_or_else(|| not_found("document"))
        }

        fn list(&self, directory: &Path) -> io::Result<Vec<PathBuf>> {
            if !self.directories.contains(directory) {
                return Err(not_found("directory"));
            }

            Ok(self
                .documents
                .keys()
                .filter(|path| path.parent() == Some(directory))
                .cloned()
                .collect())
        }
    }
}
