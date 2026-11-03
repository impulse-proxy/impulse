use crate::routing::{
    decision::RouteDecisionReason, matcher::best_matching_route_with_reason, route::IndexedRoute,
    util::canonical_uri_path,
};

#[derive(Default)]
pub struct TrieNode {
    pub routes: Vec<IndexedRoute>,
    children: Vec<TrieEdge>,
}

#[derive(Default)]
struct TrieEdge {
    byte: u8,
    node: Box<TrieNode>,
}

#[derive(Default)]
pub struct RouteTrie {
    root: TrieNode,
}

impl TrieNode {
    fn update_route(&mut self, candidate: IndexedRoute) {
        if let Some(existing) = self
            .routes
            .iter_mut()
            .find(|route| route.upstream_idx == candidate.upstream_idx)
        {
            *existing = candidate;
            return;
        }
        self.routes.push(candidate);
    }

    #[inline(always)]
    fn child(&self, byte: u8) -> Option<&TrieNode> {
        match self.children.binary_search_by_key(&byte, |edge| edge.byte) {
            Ok(idx) => Some(self.children[idx].node.as_ref()),
            Err(_) => None,
        }
    }

    #[inline(always)]
    fn child_or_insert(&mut self, byte: u8) -> &mut TrieNode {
        match self.children.binary_search_by_key(&byte, |edge| edge.byte) {
            Ok(idx) => self.children[idx].node.as_mut(),
            Err(idx) => {
                self.children.insert(
                    idx,
                    TrieEdge {
                        byte,
                        node: Box::<TrieNode>::default(),
                    },
                );
                self.children[idx].node.as_mut()
            }
        }
    }
}

impl RouteTrie {
    pub fn insert(&mut self, prefix: Option<&str>, route: IndexedRoute) {
        let prefix = prefix.unwrap_or("");
        let mut node = &mut self.root;

        if prefix.is_empty() {
            node.update_route(route);
            return;
        }

        for byte in prefix.as_bytes() {
            node = node.child_or_insert(*byte);
        }

        node.update_route(route);
    }

    pub fn longest_prefix(
        &self,
        path: &str,
        method: Option<&str>,
        upstream_methods: &[Option<String>],
    ) -> Option<IndexedRoute> {
        self.longest_prefix_with_reason(path, method, upstream_methods)
            .map(|(route, _)| route)
    }

    pub fn longest_prefix_with_reason(
        &self,
        path_and_query: &str,
        method: Option<&str>,
        upstream_methods: &[Option<String>],
    ) -> Option<(IndexedRoute, Option<RouteDecisionReason>)> {
        let path = canonical_uri_path(path_and_query);
        let mut node = &self.root;
        let mut best =
            best_matching_route_with_reason(&node.routes, &path, method, upstream_methods, None);

        for byte in path.as_bytes() {
            let Some(next) = node.child(*byte) else {
                break;
            };
            node = next;
            best = best_matching_route_with_reason(
                &node.routes,
                &path,
                method,
                upstream_methods,
                best,
            );
        }

        best
    }
}

#[cfg(test)]
mod tests {
    use crate::routing::{decision::RouteDecisionReason, route::IndexedRoute, trie::RouteTrie};

    fn route(upstream_idx: usize, path_len: usize) -> IndexedRoute {
        IndexedRoute {
            upstream_idx,
            path_len,
            host_specific: false,
            method_specific: false,
            order: upstream_idx,
        }
    }

    #[test]
    fn longest_prefix_returns_none_when_trie_is_empty() {
        let trie = RouteTrie::default();
        let upstream_methods = Vec::new();

        assert_eq!(trie.longest_prefix("/api", None, &upstream_methods), None);
        assert_eq!(
            trie.longest_prefix_with_reason("/api", None, &upstream_methods),
            None
        );
    }

    #[test]
    fn longest_prefix_prefers_longest_overlapping_prefix() {
        let mut trie = RouteTrie::default();
        let upstream_methods = vec![None, None];
        trie.insert(Some("/api"), route(0, "/api".len()));
        trie.insert(Some("/api/v1"), route(1, "/api/v1".len()));

        assert_eq!(
            trie.longest_prefix("/api/v1/users", None, &upstream_methods),
            Some(route(1, "/api/v1".len()))
        );
    }

    #[test]
    fn longest_prefix_uses_root_fallback_when_no_child_matches() {
        let mut trie = RouteTrie::default();
        let upstream_methods = vec![None];
        trie.insert(None, route(0, 0));

        assert_eq!(
            trie.longest_prefix("/unmatched", None, &upstream_methods),
            Some(route(0, 0))
        );
    }

    #[test]
    fn longest_prefix_matches_path_before_query() {
        let mut trie = RouteTrie::default();
        let upstream_methods = vec![None, None];
        trie.insert(None, route(0, 0));
        trie.insert(Some("/admin"), route(1, "/admin".len()));

        for request_target in ["/admin", "/admin?x=1", "/admin?", "/admin/sub?x=1"] {
            assert_eq!(
                trie.longest_prefix(request_target, None, &upstream_methods),
                Some(route(1, "/admin".len())),
                "request target: {request_target}"
            );
        }
    }

    #[test]
    fn longest_prefix_with_reason_reports_longer_prefix_preference() {
        let mut trie = RouteTrie::default();
        let upstream_methods = vec![None, None];
        trie.insert(None, route(0, 0));
        trie.insert(Some("/api"), route(1, "/api".len()));

        assert_eq!(
            trie.longest_prefix_with_reason("/api/users", None, &upstream_methods),
            Some((
                route(1, "/api".len()),
                Some(RouteDecisionReason::HostPathLongerOrEqual)
            ))
        );
    }
}
