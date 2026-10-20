package perm

import "testing"

func TestLevelsAndBuiltin(t *testing.T) {
	a, an, v := BuiltinSet(Admin), BuiltinSet(Analyst), BuiltinSet(Viewer)
	if !a.Admin() || an.Admin() || v.Admin() {
		t.Fatal("administrator")
	}
	cases := []struct {
		s          Set
		mod, level string
		want       bool
	}{
		{an, "rules", "read", true}, {an, "rules", "test", true}, {an, "rules", "write", false},
		{v, "rules", "test", false}, {v, "alerts", "write", false}, {an, "alerts", "write", true},
		{a, "archive", "export", true}, {Set{"archive": "export"}, "archive", "read", true},
		{Set{"archive": "export"}, "archive", "write", false}, {v, "audit", "read", false}, {a, "nieznany", "read", false},
	}
	for _, c := range cases {
		if got := c.s.Has(c.mod, c.level); got != c.want {
			t.Errorf("%v %s.%s = %v", c.s, c.mod, c.level, got)
		}
	}
	for _, b := range Builtin {
		if err := b.Perms().Validate(); err != nil {
			t.Errorf("%s: %v", b.ID, err)
		}
	}
	if (Set{"rules": "admin"}).Validate() == nil || (Set{"x": "read"}).Validate() == nil {
		t.Fatal("walidacja")
	}
}
