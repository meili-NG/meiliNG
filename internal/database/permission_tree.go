package database

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// PermissionTree is the one place that knows a permission contains its
// descendants. Every "does this grant include that permission" question goes
// through it.
type PermissionTree struct {
	byID     map[uuid.UUID]Permission
	byScope  map[string]uuid.UUID
	children map[uuid.UUID][]uuid.UUID
}

func NewPermissionTree(permissions []Permission) *PermissionTree {
	t := &PermissionTree{
		byID:     make(map[uuid.UUID]Permission, len(permissions)),
		byScope:  make(map[string]uuid.UUID, len(permissions)),
		children: make(map[uuid.UUID][]uuid.UUID),
	}
	for _, p := range permissions {
		t.byID[p.ID] = p
		t.byScope[p.Scope] = p.ID
		if p.ParentID.Valid {
			t.children[p.ParentID.UUID] = append(t.children[p.ParentID.UUID], p.ID)
		}
	}
	return t
}

// LoadPermissionTree reads the whole permission table on every call; nothing is cached.
func LoadPermissionTree() (*PermissionTree, error) {
	db, err := GetDatabase()
	if err != nil {
		return nil, err
	}

	var permissions []Permission
	if err := db.Find(&permissions).Error; err != nil {
		return nil, err
	}
	return NewPermissionTree(permissions), nil
}

// WithLockedPermissionTree runs fn in a transaction that holds a row lock on
// every permission, so two concurrent parent changes cannot combine into a cycle.
func WithLockedPermissionTree(fn func(tx *gorm.DB, tree *PermissionTree) error) error {
	db, err := GetDatabase()
	if err != nil {
		return err
	}

	return db.Transaction(func(tx *gorm.DB) error {
		var permissions []Permission
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Find(&permissions).Error; err != nil {
			return err
		}
		return fn(tx, NewPermissionTree(permissions))
	})
}

func (t *PermissionTree) Has(id uuid.UUID) bool {
	_, ok := t.byID[id]
	return ok
}

// Ancestors returns the chain above id, nearest first. The visited set ends
// the walk if corrupt data forms a cycle.
func (t *PermissionTree) Ancestors(id uuid.UUID) []uuid.UUID {
	var ancestors []uuid.UUID
	visited := map[uuid.UUID]bool{id: true}
	for {
		parent := t.byID[id].ParentID
		if !parent.Valid || visited[parent.UUID] {
			return ancestors
		}
		visited[parent.UUID] = true
		ancestors = append(ancestors, parent.UUID)
		id = parent.UUID
	}
}

// Descendants returns every permission below id, at any depth.
func (t *PermissionTree) Descendants(id uuid.UUID) []Permission {
	var descendants []Permission
	visited := map[uuid.UUID]bool{id: true}
	queue := []uuid.UUID{id}
	for len(queue) > 0 {
		for _, child := range t.children[queue[0]] {
			if visited[child] {
				continue
			}
			visited[child] = true
			descendants = append(descendants, t.byID[child])
			queue = append(queue, child)
		}
		queue = queue[1:]
	}
	return descendants
}

func (t *PermissionTree) coveredBy(granted map[uuid.UUID]bool, id uuid.UUID) bool {
	if granted[id] {
		return true
	}
	for _, ancestor := range t.Ancestors(id) {
		if granted[ancestor] {
			return true
		}
	}
	return false
}

func permissionIDSet(permissions []Permission) map[uuid.UUID]bool {
	set := make(map[uuid.UUID]bool, len(permissions))
	for _, p := range permissions {
		set[p.ID] = true
	}
	return set
}

// Uncovered returns the requested permissions that granted does not hold,
// neither directly nor through an ancestor.
func (t *PermissionTree) Uncovered(granted []Permission, requested []Permission) []Permission {
	grantedSet := permissionIDSet(granted)
	var uncovered []Permission
	for _, p := range requested {
		if !t.coveredBy(grantedSet, p.ID) {
			uncovered = append(uncovered, p)
		}
	}
	return uncovered
}

// CoversScope reports whether granted holds the permission named scope,
// directly or through an ancestor.
func (t *PermissionTree) CoversScope(granted []Permission, scope string) bool {
	id, ok := t.byScope[scope]
	return ok && t.coveredBy(permissionIDSet(granted), id)
}

// Fold drops every permission that has an ancestor in the same set, for
// display only. Checking against what is still kept means a corrupt cycle
// loses all but one of its members instead of all of them.
func (t *PermissionTree) Fold(permissions []Permission) []Permission {
	kept := permissionIDSet(permissions)
	for _, p := range permissions {
		for _, ancestor := range t.Ancestors(p.ID) {
			if kept[ancestor] {
				delete(kept, p.ID)
				break
			}
		}
	}

	var folded []Permission
	for _, p := range permissions {
		if kept[p.ID] {
			folded = append(folded, p)
			delete(kept, p.ID)
		}
	}
	return folded
}

// ImpliedScopes returns the scopes plus the scope of every permission they
// contain, without duplicates.
func (t *PermissionTree) ImpliedScopes(scopes []string) []string {
	seen := make(map[string]bool)
	var implied []string
	add := func(scope string) {
		if !seen[scope] {
			seen[scope] = true
			implied = append(implied, scope)
		}
	}
	for _, scope := range scopes {
		add(scope)
		if id, ok := t.byScope[scope]; ok {
			for _, descendant := range t.Descendants(id) {
				add(descendant.Scope)
			}
		}
	}
	return implied
}

// WouldCycle reports whether making parentID the parent of id closes a loop.
func (t *PermissionTree) WouldCycle(id uuid.UUID, parentID uuid.UUID) bool {
	if id == parentID {
		return true
	}
	for _, ancestor := range t.Ancestors(parentID) {
		if ancestor == id {
			return true
		}
	}
	return false
}
