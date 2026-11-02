//go:build ignore

// Generates the ent client: go generate ./internal/store
package main

import (
	"log"

	"entgo.io/ent/entc"
	"entgo.io/ent/entc/gen"
)

func main() {
	err := entc.Generate("./schema", &gen.Config{
		Target:  "./ent",
		Package: "licenseforge.io/licenseforge/internal/store/ent",
		Features: []gen.Feature{
			gen.FeatureLock,            // SELECT ... FOR UPDATE (activation counting, ADR-0008)
			gen.FeatureExecQuery,       // raw exec for set_config (tenant context)
			gen.FeatureVersionedMigration,
		},
	})
	if err != nil {
		log.Fatal(err)
	}
}
