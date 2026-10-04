package config

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// A doc comment never opens with the name of another function of its
// package: a function inserted between a comment and the function it
// documents takes that comment over.
func TestDocCommentsAboveTheirFunction(t *testing.T) {
	type decl struct {
		name, doc string
		pos       token.Position
	}
	names := map[string]map[string]bool{}
	var decls []decl
	fset := token.NewFileSet()
	for _, top := range []string{"../../cmd", "../../internal"} {
		err := filepath.WalkDir(top, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") {
				return err
			}
			f, err := parser.ParseFile(fset, p, nil, parser.ParseComments)
			if err != nil {
				return err
			}
			dir := filepath.Dir(p)
			if names[dir] == nil {
				names[dir] = map[string]bool{}
			}
			for _, dl := range f.Decls {
				fd, ok := dl.(*ast.FuncDecl)
				if !ok {
					continue
				}
				names[dir][fd.Name.Name] = true
				if fd.Doc != nil {
					decls = append(decls, decl{fd.Name.Name, fd.Doc.Text(), fset.Position(fd.Pos())})
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range decls {
		w := strings.Fields(d.doc)
		if len(w) > 0 && w[0] != d.name && names[filepath.Dir(d.pos.Filename)][w[0]] {
			t.Errorf("%s: the doc comment of %s opens with %s", d.pos, d.name, w[0])
		}
	}
}
