// Package web zawiera zbudowaną aplikację panelu (Vite → web/dist),
// wbudowywaną w siem-api. Budowanie: cd panel/web && npm ci && npm run build.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// FS zwraca pliki aplikacji albo nil, gdy frontend nie został zbudowany.
func FS() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return nil
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return nil
	}
	return sub
}
