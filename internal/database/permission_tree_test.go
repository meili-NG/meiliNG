package database

import (
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/meili-NG/meiliNG/v2/internal/models"
	"github.com/meili-NG/meiliNG/v2/internal/utils"
)

func treePermission(scope string, parent *Permission) Permission {
	p := Permission{PermissionFields: models.PermissionFields{ID: uuid.New(), Scope: scope}}
	if parent != nil {
		p.ParentID = uuid.NullUUID{UUID: parent.ID, Valid: true}
	}
	return p
}

func scopesOf(permissions []Permission) []string {
	scopes := utils.Map(permissions, func(p Permission) string { return p.Scope })
	slices.Sort(scopes)
	return scopes
}

func TestPermissionTree(t *testing.T) {
	drive := treePermission("drive", nil)
	readonly := treePermission("drive.readonly", &drive)
	metadata := treePermission("drive.readonly.metadata", &readonly)
	mail := treePermission("mail", nil)
	tree := NewPermissionTree([]Permission{drive, readonly, metadata, mail})

	t.Run("ancestors are listed nearest first", func(t *testing.T) {
		if got := tree.Ancestors(metadata.ID); !slices.Equal(got, []uuid.UUID{readonly.ID, drive.ID}) {
			t.Fatalf("Ancestors(metadata) = %v", got)
		}
		if got := tree.Ancestors(drive.ID); len(got) != 0 {
			t.Fatalf("Ancestors(drive) = %v, want none", got)
		}
	})

	t.Run("descendants reach every depth", func(t *testing.T) {
		if got := scopesOf(tree.Descendants(drive.ID)); !slices.Equal(got, []string{"drive.readonly", "drive.readonly.metadata"}) {
			t.Fatalf("Descendants(drive) = %v", got)
		}
		if got := tree.Descendants(mail.ID); len(got) != 0 {
			t.Fatalf("Descendants(mail) = %v, want none", got)
		}
	})

	t.Run("a grant covers its descendants but never its parent", func(t *testing.T) {
		if got := tree.Uncovered([]Permission{drive}, []Permission{readonly, metadata, drive}); len(got) != 0 {
			t.Fatalf("parent grant left %v uncovered", scopesOf(got))
		}
		if got := scopesOf(tree.Uncovered([]Permission{readonly}, []Permission{drive, readonly, metadata, mail})); !slices.Equal(got, []string{"drive", "mail"}) {
			t.Fatalf("child grant left %v uncovered, want [drive mail]", got)
		}
		if got := scopesOf(tree.Uncovered(nil, []Permission{mail})); !slices.Equal(got, []string{"mail"}) {
			t.Fatalf("empty grant left %v uncovered, want [mail]", got)
		}
	})

	t.Run("scope lookups honour ancestor grants", func(t *testing.T) {
		if !tree.CoversScope([]Permission{drive}, "drive.readonly.metadata") {
			t.Fatal("drive grant should cover drive.readonly.metadata")
		}
		if tree.CoversScope([]Permission{metadata}, "drive") {
			t.Fatal("a child grant must not cover its ancestor")
		}
		if tree.CoversScope([]Permission{drive}, "unknown") {
			t.Fatal("an unknown scope is never covered")
		}
	})

	t.Run("fold drops permissions contained in another one of the set", func(t *testing.T) {
		if got := scopesOf(tree.Fold([]Permission{metadata, mail, drive, readonly})); !slices.Equal(got, []string{"drive", "mail"}) {
			t.Fatalf("Fold = %v, want [drive mail]", got)
		}
		if got := scopesOf(tree.Fold([]Permission{metadata, readonly})); !slices.Equal(got, []string{"drive.readonly"}) {
			t.Fatalf("Fold = %v, want [drive.readonly]", got)
		}
	})

	t.Run("implied scopes add descendants once", func(t *testing.T) {
		got := tree.ImpliedScopes([]string{"drive.readonly", "mail", "drive"})
		slices.Sort(got)
		if !slices.Equal(got, []string{"drive", "drive.readonly", "drive.readonly.metadata", "mail"}) {
			t.Fatalf("ImpliedScopes = %v", got)
		}
	})

	t.Run("cycle check rejects self and descendants only", func(t *testing.T) {
		if !tree.WouldCycle(drive.ID, drive.ID) {
			t.Fatal("a permission cannot be its own parent")
		}
		if !tree.WouldCycle(drive.ID, metadata.ID) {
			t.Fatal("a permission cannot move under its own descendant")
		}
		if tree.WouldCycle(metadata.ID, mail.ID) || tree.WouldCycle(mail.ID, metadata.ID) {
			t.Fatal("moving between unrelated branches is not a cycle")
		}
	})
}

// A cycle cannot be created through the API, but a walk over one written
// straight into the database must still end.
func TestPermissionTreeTerminatesOnCorruptCycle(t *testing.T) {
	a := treePermission("a", nil)
	b := treePermission("b", &a)
	c := treePermission("c", &b)
	a.ParentID = uuid.NullUUID{UUID: c.ID, Valid: true}
	self := treePermission("self", nil)
	self.ParentID = uuid.NullUUID{UUID: self.ID, Valid: true}
	tree := NewPermissionTree([]Permission{a, b, c, self})

	if got := tree.Ancestors(a.ID); !slices.Equal(got, []uuid.UUID{c.ID, b.ID}) {
		t.Fatalf("Ancestors(a) = %v, want [c b]", got)
	}
	if got := scopesOf(tree.Descendants(a.ID)); !slices.Equal(got, []string{"b", "c"}) {
		t.Fatalf("Descendants(a) = %v, want [b c]", got)
	}
	if got := tree.Ancestors(self.ID); len(got) != 0 {
		t.Fatalf("Ancestors(self) = %v, want none", got)
	}
	if got := tree.Descendants(self.ID); len(got) != 0 {
		t.Fatalf("Descendants(self) = %v, want none", got)
	}
	if got := tree.Fold([]Permission{a, b, c, self}); len(got) != 2 {
		t.Fatalf("Fold kept %v, want one member of the cycle plus self", scopesOf(got))
	}
	if !tree.WouldCycle(a.ID, b.ID) {
		t.Fatal("WouldCycle should report the existing loop")
	}
	if got := tree.ImpliedScopes([]string{"a", "self"}); len(got) != 4 {
		t.Fatalf("ImpliedScopes = %v, want all four scopes", got)
	}
}
