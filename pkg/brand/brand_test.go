package brand_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"cyberboar.dev/cyberboar/pkg/brand"
)

func TestNoProductNameOutsideBrand(t *testing.T) {
	root := "../.."
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "testdata" || d.Name() == ".git") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") ||
			filepath.Base(filepath.Dir(path)) == "brand" {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		imports := map[*ast.BasicLit]bool{}
		for _, im := range f.Imports {
			imports[im.Path] = true
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if ok && lit.Kind == token.STRING && !imports[lit] && strings.Contains(strings.ToLower(lit.Value), strings.ToLower(brand.Name)) {
				t.Errorf("%s: product name in a string literal %s; use package brand", fset.Position(lit.Pos()), lit.Value)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
