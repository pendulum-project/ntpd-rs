//! Paths into the configuration tree, used to point at a setting in
//! diagnostics.

/// A segment of a path in the tree. Field names are static schema data, while
/// vector indexes are only known while walking a document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathSegment {
    Field(&'static str),
    Index(usize),
}

/// A path in the tree, such as `observability.log-level` or
/// `sources[2].address`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigPath(Vec<PathSegment>);

impl ConfigPath {
    pub(crate) fn root() -> Self {
        Self(vec![])
    }

    /// Run `f` with `field` appended to this path.
    pub fn at<R>(&mut self, field: &'static str, f: impl FnOnce(&mut Self) -> R) -> R {
        self.push_field(field);
        let result = f(self);
        self.pop();
        result
    }

    /// Run `f` with an element of a vector appended to this path.
    pub(crate) fn at_index<R>(&mut self, index: usize, f: impl FnOnce(&mut Self) -> R) -> R {
        self.0.push(PathSegment::Index(index));
        let result = f(self);
        self.pop();
        result
    }

    pub(crate) fn push_field(&mut self, field: &'static str) {
        self.0.push(PathSegment::Field(field));
    }

    pub(crate) fn pop(&mut self) {
        self.0.pop();
    }
}

impl std::fmt::Display for ConfigPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (pos, segment) in self.0.iter().enumerate() {
            match segment {
                PathSegment::Field(field) => {
                    if pos != 0 {
                        write!(f, ".")?;
                    }
                    write!(f, "{field}")?
                }
                PathSegment::Index(index) => write!(f, "[{index}]")?,
            }
        }

        Ok(())
    }
}
