#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::hash::Hash;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CycleError<K> {
    pub path: Vec<K>,
}

impl<K: fmt::Debug> fmt::Display for CycleError<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cycle detected: {:?}", self.path)
    }
}

impl<K: fmt::Debug> std::error::Error for CycleError<K> {}

const MAX_ID_LENGTH: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdValidationError {
    Empty,
    TooLong { len: usize, max: usize },
}

impl fmt::Display for IdValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "ID cannot be empty"),
            Self::TooLong { len, max } => {
                write!(f, "ID length {} exceeds maximum {}", len, max)
            }
        }
    }
}

impl std::error::Error for IdValidationError {}

fn validate_id(id: &str) -> Result<(), IdValidationError> {
    if id.is_empty() {
        return Err(IdValidationError::Empty);
    }
    if id.len() > MAX_ID_LENGTH {
        return Err(IdValidationError::TooLong {
            len: id.len(),
            max: MAX_ID_LENGTH,
        });
    }
    Ok(())
}

pub trait TCNode<K: Eq + Hash + Clone> {
    fn get_key(&self) -> K;
    fn out_edges(&self) -> Box<dyn Iterator<Item = &K> + '_>;
}

#[derive(Debug, Clone, Serialize)]
pub struct TransitiveClosure<K: Eq + Hash + Clone> {
    edges: HashMap<K, HashSet<K>>,
}

impl<K: Eq + Hash + Clone> Default for TransitiveClosure<K> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Eq + Hash + Clone> TransitiveClosure<K> {
    pub fn new() -> Self {
        Self {
            edges: HashMap::new(),
        }
    }

    pub fn compute<N: TCNode<K>>(nodes: &[N]) -> Result<Self, CycleError<K>> {
        let node_map: HashMap<K, &N> = nodes.iter().map(|n| (n.get_key(), n)).collect();
        let mut closure = Self::new();

        for node in nodes {
            let key = node.get_key();
            let reachable = Self::dfs_reachable(&key, &node_map)?;
            closure.edges.insert(key, reachable);
        }

        Ok(closure)
    }

    fn dfs_reachable<N: TCNode<K>>(
        start: &K,
        node_map: &HashMap<K, &N>,
    ) -> Result<HashSet<K>, CycleError<K>> {
        let mut visited = HashSet::new();
        let mut path = Vec::new();
        let mut path_set = HashSet::new();
        let mut result = HashSet::new();

        Self::dfs_visit(
            start,
            node_map,
            &mut visited,
            &mut path,
            &mut path_set,
            &mut result,
        )?;

        result.remove(start);
        Ok(result)
    }

    fn dfs_visit<N: TCNode<K>>(
        start: &K,
        node_map: &HashMap<K, &N>,
        visited: &mut HashSet<K>,
        path: &mut Vec<K>,
        path_set: &mut HashSet<K>,
        result: &mut HashSet<K>,
    ) -> Result<(), CycleError<K>> {
        let mut stack = vec![(start.clone(), false)];

        while let Some((current, is_exit)) = stack.pop() {
            if is_exit {
                path.pop();
                path_set.remove(&current);
                continue;
            }

            if path_set.contains(&current) {
                let cycle_start = path.iter().position(|k| k == &current).unwrap();
                let mut cycle_path: Vec<K> = path[cycle_start..].to_vec();
                cycle_path.push(current);
                return Err(CycleError { path: cycle_path });
            }

            if visited.contains(&current) {
                continue;
            }

            path.push(current.clone());
            path_set.insert(current.clone());
            visited.insert(current.clone());
            result.insert(current.clone());

            stack.push((current.clone(), true));

            if let Some(node) = node_map.get(&current) {
                for neighbor in node.out_edges() {
                    stack.push((neighbor.clone(), false));
                }
            }
        }

        Ok(())
    }

    pub fn is_reachable(&self, from: &K, to: &K) -> bool {
        self.edges.get(from).is_some_and(|set| set.contains(to))
    }

    pub fn is_ancestor(&self, ancestor: &K, descendant: &K) -> bool {
        self.is_reachable(ancestor, descendant)
    }

    pub fn get_reachable(&self, from: &K) -> Option<&HashSet<K>> {
        self.edges.get(from)
    }

    pub fn get_ancestors(&self, node: &K) -> HashSet<K> {
        self.edges
            .iter()
            .filter(|(_, reachable)| reachable.contains(node))
            .map(|(k, _)| k.clone())
            .collect()
    }

    pub fn get_descendants(&self, node: &K) -> HashSet<K> {
        self.edges.get(node).cloned().unwrap_or_default()
    }

    pub fn add_node(&mut self, key: K) {
        self.edges.entry(key).or_default();
    }

    pub fn add_edge(&mut self, from: K, to: K) -> Result<(), CycleError<K>> {
        if from == to {
            return Err(CycleError {
                path: vec![from.clone(), from],
            });
        }

        if self.is_reachable(&to, &from) {
            return Err(CycleError {
                path: vec![from.clone(), to, from],
            });
        }

        let mut to_reachable = self.edges.get(&to).cloned().unwrap_or_default();
        to_reachable.insert(to.clone());

        self.edges
            .entry(from.clone())
            .or_default()
            .extend(to_reachable.iter().cloned());

        for reachable in self.edges.values_mut() {
            if reachable.contains(&from) {
                reachable.extend(to_reachable.iter().cloned());
            }
        }

        Ok(())
    }

    pub fn node_count(&self) -> usize {
        self.edges.len()
    }

    pub fn edge_count(&self) -> usize {
        self.edges.values().map(|s| s.len()).sum()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct RoleId(pub String);

impl RoleId {
    pub fn new(id: impl Into<String>) -> Result<Self, IdValidationError> {
        let id = id.into();
        validate_id(&id)?;
        Ok(Self(id))
    }

    pub fn new_unchecked(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl From<&str> for RoleId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl fmt::Display for RoleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: RoleId,
    pub name: String,
    pub parent_roles: Vec<RoleId>,
    pub permissions: HashSet<String>,
}

impl Role {
    pub fn new(id: impl Into<RoleId>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            parent_roles: Vec::new(),
            permissions: HashSet::new(),
        }
    }

    pub fn with_parent(mut self, parent: impl Into<RoleId>) -> Self {
        self.parent_roles.push(parent.into());
        self
    }

    pub fn with_permission(mut self, permission: impl Into<String>) -> Self {
        self.permissions.insert(permission.into());
        self
    }
}

impl TCNode<RoleId> for Role {
    fn get_key(&self) -> RoleId {
        self.id.clone()
    }

    fn out_edges(&self) -> Box<dyn Iterator<Item = &RoleId> + '_> {
        Box::new(self.parent_roles.iter())
    }
}

#[derive(Debug, Clone)]
pub struct RoleHierarchy {
    roles: HashMap<RoleId, Role>,
    closure: TransitiveClosure<RoleId>,
}

impl RoleHierarchy {
    pub fn build(roles: Vec<Role>) -> Result<Self, CycleError<RoleId>> {
        let closure = TransitiveClosure::compute(&roles)?;
        let roles_map = roles.into_iter().map(|r| (r.id.clone(), r)).collect();

        Ok(Self {
            roles: roles_map,
            closure,
        })
    }

    pub fn get_role(&self, id: &RoleId) -> Option<&Role> {
        self.roles.get(id)
    }

    pub fn inherits_from(&self, role: &RoleId, ancestor: &RoleId) -> bool {
        self.closure.is_ancestor(role, ancestor)
    }

    pub fn get_all_permissions(&self, role_id: &RoleId) -> HashSet<String> {
        let mut permissions = HashSet::new();

        if let Some(role) = self.roles.get(role_id) {
            permissions.extend(role.permissions.iter().cloned());
        }

        for ancestor_id in self.closure.get_descendants(role_id) {
            if let Some(ancestor) = self.roles.get(&ancestor_id) {
                permissions.extend(ancestor.permissions.iter().cloned());
            }
        }

        permissions
    }

    pub fn get_ancestors(&self, role_id: &RoleId) -> HashSet<RoleId> {
        self.closure.get_descendants(role_id)
    }

    pub fn get_descendants(&self, role_id: &RoleId) -> HashSet<RoleId> {
        self.closure.get_ancestors(role_id)
    }

    pub fn roles(&self) -> impl Iterator<Item = &Role> {
        self.roles.values()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct EntityId(pub String);

impl EntityId {
    pub fn new(id: impl Into<String>) -> Result<Self, IdValidationError> {
        let id = id.into();
        validate_id(&id)?;
        Ok(Self(id))
    }

    pub fn new_unchecked(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl From<&str> for EntityId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl fmt::Display for EntityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum RelationType {
    ParentGroup,
    OwnerOf,
    DelegatesTo,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityNode {
    pub id: EntityId,
    pub entity_type: String,
    pub relations: Vec<(RelationType, EntityId)>,
}

impl EntityNode {
    pub fn new(id: impl Into<EntityId>, entity_type: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            entity_type: entity_type.into(),
            relations: Vec::new(),
        }
    }

    pub fn with_relation(mut self, rel_type: RelationType, target: impl Into<EntityId>) -> Self {
        self.relations.push((rel_type, target.into()));
        self
    }

    pub fn relations_of_type(&self, rel_type: &RelationType) -> Vec<&EntityId> {
        self.relations
            .iter()
            .filter(|(rt, _)| rt == rel_type)
            .map(|(_, id)| id)
            .collect()
    }
}

impl TCNode<EntityId> for EntityNode {
    fn get_key(&self) -> EntityId {
        self.id.clone()
    }

    fn out_edges(&self) -> Box<dyn Iterator<Item = &EntityId> + '_> {
        Box::new(self.relations.iter().map(|(_, id)| id))
    }
}

#[derive(Debug, Clone)]
pub struct EntityGraph {
    nodes: HashMap<EntityId, EntityNode>,
    closure: TransitiveClosure<EntityId>,
    relation_closures: HashMap<RelationType, TransitiveClosure<EntityId>>,
}

impl EntityGraph {
    pub fn build(nodes: Vec<EntityNode>) -> Result<Self, CycleError<EntityId>> {
        let closure = TransitiveClosure::compute(&nodes)?;

        let relation_types: HashSet<RelationType> = nodes
            .iter()
            .flat_map(|n| n.relations.iter().map(|(rt, _)| rt.clone()))
            .collect();

        let mut relation_closures = HashMap::new();
        for rel_type in relation_types {
            let filtered_nodes: Vec<FilteredEntityNode> = nodes
                .iter()
                .map(|n| FilteredEntityNode {
                    id: n.id.clone(),
                    edges: n
                        .relations_of_type(&rel_type)
                        .into_iter()
                        .cloned()
                        .collect(),
                })
                .collect();

            let rel_closure = TransitiveClosure::compute(&filtered_nodes)?;
            relation_closures.insert(rel_type, rel_closure);
        }

        let nodes_map = nodes.into_iter().map(|n| (n.id.clone(), n)).collect();

        Ok(Self {
            nodes: nodes_map,
            closure,
            relation_closures,
        })
    }

    pub fn get_node(&self, id: &EntityId) -> Option<&EntityNode> {
        self.nodes.get(id)
    }

    pub fn is_reachable(&self, from: &EntityId, to: &EntityId) -> bool {
        self.closure.is_reachable(from, to)
    }

    pub fn is_reachable_via(
        &self,
        from: &EntityId,
        to: &EntityId,
        rel_type: &RelationType,
    ) -> bool {
        self.relation_closures
            .get(rel_type)
            .is_some_and(|c| c.is_reachable(from, to))
    }

    pub fn get_ancestors(&self, id: &EntityId) -> HashSet<EntityId> {
        self.closure.get_ancestors(id)
    }

    pub fn get_descendants(&self, id: &EntityId) -> HashSet<EntityId> {
        self.closure.get_descendants(id)
    }

    pub fn get_ancestors_via(&self, id: &EntityId, rel_type: &RelationType) -> HashSet<EntityId> {
        self.relation_closures
            .get(rel_type)
            .map(|c| c.get_ancestors(id))
            .unwrap_or_default()
    }

    pub fn get_descendants_via(&self, id: &EntityId, rel_type: &RelationType) -> HashSet<EntityId> {
        self.relation_closures
            .get(rel_type)
            .map(|c| c.get_descendants(id))
            .unwrap_or_default()
    }

    pub fn nodes(&self) -> impl Iterator<Item = &EntityNode> {
        self.nodes.values()
    }
}

struct FilteredEntityNode {
    id: EntityId,
    edges: Vec<EntityId>,
}

impl TCNode<EntityId> for FilteredEntityNode {
    fn get_key(&self) -> EntityId {
        self.id.clone()
    }

    fn out_edges(&self) -> Box<dyn Iterator<Item = &EntityId> + '_> {
        Box::new(self.edges.iter())
    }
}

#[derive(Debug, Clone)]
pub struct HierarchyValidator<K: Eq + Hash + Clone> {
    closure: TransitiveClosure<K>,
    max_depth: Option<usize>,
}

impl<K: Eq + Hash + Clone + fmt::Debug> HierarchyValidator<K> {
    pub fn new(closure: TransitiveClosure<K>) -> Self {
        Self {
            closure,
            max_depth: None,
        }
    }

    pub fn with_max_depth(mut self, depth: usize) -> Self {
        self.max_depth = Some(depth);
        self
    }

    pub fn validate_max_depth<N: TCNode<K>>(&self, nodes: &[N]) -> Result<(), HierarchyError<K>> {
        if let Some(max) = self.max_depth {
            for node in nodes {
                let key = node.get_key();
                let depth = self.compute_depth(&key, nodes);
                if depth > max {
                    return Err(HierarchyError::MaxDepthExceeded {
                        node: key,
                        depth,
                        max,
                    });
                }
            }
        }
        Ok(())
    }

    fn compute_depth<N: TCNode<K>>(&self, start: &K, nodes: &[N]) -> usize {
        let node_map: HashMap<K, &N> = nodes.iter().map(|n| (n.get_key(), n)).collect();
        let mut memo: HashMap<K, usize> = HashMap::new();
        let mut visiting: HashSet<K> = HashSet::new();

        self.longest_from(start, &node_map, &mut memo, &mut visiting)
    }

    fn longest_from<N: TCNode<K>>(
        &self,
        start: &K,
        node_map: &HashMap<K, &N>,
        memo: &mut HashMap<K, usize>,
        visiting: &mut HashSet<K>,
    ) -> usize {
        let mut stack: Vec<(K, Vec<K>, usize, usize)> = Vec::new();
        let mut result: Option<usize> = None;

        let children: Vec<K> = node_map
            .get(start)
            .map(|n| n.out_edges().cloned().collect())
            .unwrap_or_default();

        stack.push((start.clone(), children, 0, 0));
        visiting.insert(start.clone());

        while let Some((_key, children, child_idx, max_depth)) = stack.last_mut() {
            if let Some(depth) = result.take() {
                *max_depth = (*max_depth).max(depth);
            }

            if *child_idx < children.len() {
                let child = children[*child_idx].clone();
                *child_idx += 1;

                if let Some(&cached) = memo.get(&child) {
                    result = Some(cached);
                    continue;
                }

                if visiting.contains(&child) {
                    result = Some(0);
                    continue;
                }

                let child_children: Vec<K> = node_map
                    .get(&child)
                    .map(|n| n.out_edges().cloned().collect())
                    .unwrap_or_default();

                visiting.insert(child.clone());
                stack.push((child, child_children, 0, 0));
            } else {
                let (key, children, _, max_depth) = stack.pop().unwrap();
                let depth = if children.is_empty() { 0 } else { 1 + max_depth };
                visiting.remove(&key);
                memo.insert(key, depth);
                result = Some(depth);
            }
        }

        result.unwrap_or(0)
    }

    pub fn would_create_cycle(&self, from: &K, to: &K) -> bool {
        from == to || self.closure.is_reachable(to, from)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HierarchyError<K> {
    CycleDetected(CycleError<K>),
    MaxDepthExceeded { node: K, depth: usize, max: usize },
    InvalidRelation { from: K, to: K, reason: String },
}

impl<K: fmt::Debug> fmt::Display for HierarchyError<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CycleDetected(e) => write!(f, "{}", e),
            Self::MaxDepthExceeded { node, depth, max } => {
                write!(
                    f,
                    "hierarchy depth {} at {:?} exceeds maximum {}",
                    depth, node, max
                )
            }
            Self::InvalidRelation { from, to, reason } => {
                write!(
                    f,
                    "invalid relation from {:?} to {:?}: {}",
                    from, to, reason
                )
            }
        }
    }
}

impl<K: fmt::Debug> std::error::Error for HierarchyError<K> {}

impl<K> From<CycleError<K>> for HierarchyError<K> {
    fn from(e: CycleError<K>) -> Self {
        Self::CycleDetected(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_hierarchy_no_cycle() {
        let roles = vec![
            Role::new("admin", "Administrator")
                .with_parent("manager")
                .with_permission("all"),
            Role::new("manager", "Manager")
                .with_parent("approver")
                .with_permission("manage"),
            Role::new("approver", "Approver").with_permission("approve"),
        ];

        let hierarchy = RoleHierarchy::build(roles).unwrap();

        assert!(hierarchy.inherits_from(&RoleId::new_unchecked("admin"), &RoleId::new_unchecked("manager")));
        assert!(hierarchy.inherits_from(&RoleId::new_unchecked("admin"), &RoleId::new_unchecked("approver")));
        assert!(hierarchy.inherits_from(&RoleId::new_unchecked("manager"), &RoleId::new_unchecked("approver")));
        assert!(!hierarchy.inherits_from(&RoleId::new_unchecked("approver"), &RoleId::new_unchecked("admin")));
    }

    #[test]
    fn test_role_hierarchy_cycle_detection() {
        let roles = vec![
            Role::new("a", "A").with_parent("b"),
            Role::new("b", "B").with_parent("c"),
            Role::new("c", "C").with_parent("a"),
        ];

        let result = RoleHierarchy::build(roles);
        assert!(result.is_err());
    }

    #[test]
    fn test_permission_inheritance() {
        let roles = vec![
            Role::new("admin", "Administrator")
                .with_parent("manager")
                .with_permission("delete"),
            Role::new("manager", "Manager")
                .with_parent("viewer")
                .with_permission("edit"),
            Role::new("viewer", "Viewer").with_permission("view"),
        ];

        let hierarchy = RoleHierarchy::build(roles).unwrap();
        let admin_perms = hierarchy.get_all_permissions(&RoleId::new_unchecked("admin"));

        assert!(admin_perms.contains("delete"));
        assert!(admin_perms.contains("edit"));
        assert!(admin_perms.contains("view"));
    }

    #[test]
    fn test_transitive_closure_add_edge() {
        let mut closure: TransitiveClosure<String> = TransitiveClosure::new();
        closure.add_node("a".to_string());
        closure.add_node("b".to_string());
        closure.add_node("c".to_string());

        closure.add_edge("a".to_string(), "b".to_string()).unwrap();
        closure.add_edge("b".to_string(), "c".to_string()).unwrap();

        assert!(closure.is_reachable(&"a".to_string(), &"b".to_string()));
        assert!(closure.is_reachable(&"a".to_string(), &"c".to_string()));
        assert!(closure.is_reachable(&"b".to_string(), &"c".to_string()));

        let result = closure.add_edge("c".to_string(), "a".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_entity_graph_relations() {
        let nodes = vec![
            EntityNode::new("group-a", "group").with_relation(RelationType::ParentGroup, "group-b"),
            EntityNode::new("group-b", "group").with_relation(RelationType::ParentGroup, "group-c"),
            EntityNode::new("group-c", "group"),
            EntityNode::new("wallet-1", "wallet").with_relation(RelationType::OwnerOf, "group-a"),
        ];

        let graph = EntityGraph::build(nodes).unwrap();

        assert!(graph.is_reachable_via(
            &EntityId::new_unchecked("group-a"),
            &EntityId::new_unchecked("group-c"),
            &RelationType::ParentGroup
        ));

        assert!(!graph.is_reachable_via(
            &EntityId::new_unchecked("wallet-1"),
            &EntityId::new_unchecked("group-c"),
            &RelationType::ParentGroup
        ));

        assert!(graph.is_reachable(&EntityId::new_unchecked("wallet-1"), &EntityId::new_unchecked("group-a")));
    }

    #[test]
    fn test_hierarchy_validator_max_depth() {
        let roles = vec![
            Role::new("l1", "Level 1").with_parent("l2"),
            Role::new("l2", "Level 2").with_parent("l3"),
            Role::new("l3", "Level 3").with_parent("l4"),
            Role::new("l4", "Level 4"),
        ];

        let closure = TransitiveClosure::compute(&roles).unwrap();
        let validator = HierarchyValidator::new(closure).with_max_depth(2);

        let result = validator.validate_max_depth(&roles);
        assert!(result.is_err());

        if let Err(HierarchyError::MaxDepthExceeded { depth, max, .. }) = result {
            assert_eq!(max, 2);
            assert!(depth > 2);
        }
    }

    #[test]
    fn test_self_loop_detection() {
        let mut closure: TransitiveClosure<String> = TransitiveClosure::new();
        closure.add_node("a".to_string());

        let result = closure.add_edge("a".to_string(), "a".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_role_id_validation_empty() {
        let result = RoleId::new("");
        assert!(matches!(result, Err(IdValidationError::Empty)));
    }

    #[test]
    fn test_role_id_validation_too_long() {
        let long_id = "x".repeat(257);
        let result = RoleId::new(long_id);
        assert!(matches!(
            result,
            Err(IdValidationError::TooLong { len: 257, max: 256 })
        ));
    }

    #[test]
    fn test_role_id_validation_valid() {
        let result = RoleId::new("valid-role-id");
        assert!(result.is_ok());
    }

    #[test]
    fn test_entity_id_validation_empty() {
        let result = EntityId::new("");
        assert!(matches!(result, Err(IdValidationError::Empty)));
    }

    #[test]
    fn test_entity_id_validation_too_long() {
        let long_id = "x".repeat(257);
        let result = EntityId::new(long_id);
        assert!(matches!(
            result,
            Err(IdValidationError::TooLong { len: 257, max: 256 })
        ));
    }

    #[test]
    fn test_entity_id_validation_valid() {
        let result = EntityId::new("valid-entity-id");
        assert!(result.is_ok());
    }

    #[test]
    fn test_deep_hierarchy_no_stack_overflow() {
        let depth = 1000;
        let mut roles: Vec<Role> = Vec::with_capacity(depth);
        for i in 0..depth {
            let role_id = format!("role-{}", i);
            let mut role = Role::new(role_id.as_str(), format!("Role {}", i));
            if i > 0 {
                role = role.with_parent(format!("role-{}", i - 1).as_str());
            }
            roles.push(role);
        }

        let result = RoleHierarchy::build(roles);
        assert!(result.is_ok());
    }
}
