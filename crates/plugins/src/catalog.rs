use std::{collections::HashSet, fmt};

use impulse_contracts::PluginKind;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PluginCatalogBuildError {
    DuplicateKind(PluginKind),
}

impl fmt::Display for PluginCatalogBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateKind(kind) => {
                write!(
                    formatter,
                    "compiled plugin kind registered more than once: {kind:?}"
                )
            }
        }
    }
}

impl std::error::Error for PluginCatalogBuildError {}

#[derive(Clone, Debug)]
pub struct PluginCatalog {
    available_kinds: Box<[PluginKind]>,
}

impl PluginCatalog {
    pub fn new(
        available_kinds: impl IntoIterator<Item = PluginKind>,
    ) -> Result<Self, PluginCatalogBuildError> {
        let available_kinds = available_kinds.into_iter().collect::<Vec<_>>();
        let mut seen = HashSet::with_capacity(available_kinds.len());
        for kind in &available_kinds {
            if !seen.insert(*kind) {
                return Err(PluginCatalogBuildError::DuplicateKind(*kind));
            }
        }
        Ok(Self {
            available_kinds: available_kinds.into_boxed_slice(),
        })
    }

    #[must_use]
    pub fn contains(&self, kind: PluginKind) -> bool {
        self.available_kinds.contains(&kind)
    }

    #[must_use]
    pub fn available_kinds(&self) -> &[PluginKind] {
        &self.available_kinds
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.available_kinds.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.available_kinds.is_empty()
    }
}
