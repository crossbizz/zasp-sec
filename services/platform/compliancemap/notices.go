package compliancemap

import (
	"embed"
	"strings"
)

//go:embed data/*.txt
var notices embed.FS

// CatalogNotices exposes licenses embedded in binaries that ship the index.
func CatalogNotices() string {
	files, err := notices.ReadDir("data")
	if err != nil {
		panic(err)
	}
	var text strings.Builder
	for _, file := range files {
		b, err := notices.ReadFile("data/" + file.Name())
		if err != nil {
			panic(err)
		}
		text.WriteString(file.Name() + "\n")
		text.Write(b)
		text.WriteString("\n")
	}
	return text.String()
}
