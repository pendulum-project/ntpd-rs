//! Paths into the configuration tree, used to point at a setting in
//! diagnostics.

/// A segment of a path in the tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathSegment {
    Field(&'static str),
    Index(usize),
}

/// Converts a `&'static str` to a [`PathSegment::Field`].
impl From<&'static str> for PathSegment {
    fn from(value: &'static str) -> Self {
        PathSegment::Field(value)
    }
}

/// Converts a `usize` to a [`PathSegment::Index`].
impl From<usize> for PathSegment {
    fn from(value: usize) -> Self {
        PathSegment::Index(value)
    }
}

/// A path in the tree, such as `observability.log-level` or
/// `sources[2].address`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigPath(Vec<PathSegment>);

impl ConfigPath {
    pub fn root() -> Self {
        Self(vec![])
    }

    /// Run `f` with `segment` appended to this path.
    pub fn at<R>(&mut self, segment: impl Into<PathSegment>, f: impl FnOnce(&mut Self) -> R) -> R {
        self.push(segment);
        let result = f(self);
        self.pop();
        result
    }

    pub fn push(&mut self, segment: impl Into<PathSegment>) {
        self.0.push(segment.into());
    }

    pub fn pop(&mut self) {
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
