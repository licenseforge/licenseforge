// Package schema holds the ent schemas (ADR-0008). Generated code lives in
// internal/store/ent; regenerate with `go generate ./internal/store`.
package schema

import (
	"errors"
	"strings"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"entgo.io/ent/schema/mixin"
)

// notBlank rejects empty and whitespace-only strings, like the btrim CHECKs.
func notBlank(s string) error {
	if strings.TrimSpace(s) == "" {
		return errors.New("must not be blank")
	}
	return nil
}

// CHECK expressions must be written in PostgreSQL's normalized form (e.g.
// "(x)::text = ANY (ARRAY['a'::text])" rather than "x IN ('a')"), so the
// migration and the ent schema render identically (TestMigrationsMatchEntSchema).

// enumCheck renders "col must be one of values" in PostgreSQL's normalized
// form, from the same slice that feeds field.Enum().Values(), so the two can't
// disagree.
func enumCheck(col string, values []string) string {
	quoted := make([]string, len(values))
	for i, v := range values {
		quoted[i] = "'" + v + "'::text"
	}
	return "(" + col + ")::text = ANY (ARRAY[" + strings.Join(quoted, ", ") + "])"
}

// Enum values, shared by ent fields and CHECK constraints.
var (
	featureTypes = []string{"boolean", "limit"}
	expiryBases  = []string{"from_issue", "from_first_activation"}
	licenseTypes = []string{"dev", "trial", "paid", "community"}
	statuses     = []string{"active", "suspended", "revoked"}
	bindTypes    = []string{"machine", "cluster"}         // what an activation binds to
	bindPolicies = []string{"none", "machine", "cluster"} // what a plan/license requires; none = site license
	fpSources    = []string{"override", "env", "kubernetes", "machine-id"}
	modes        = []string{"online", "offline"}
)

// stringMapCheck: a JSON object whose values are all strings (external_refs),
// so rows always decode into map[string]string.
func stringMapCheck(col string) string {
	return `jsonb_typeof(` + col + `) = 'object' AND NOT jsonb_path_exists(` + col + `, 'strict $.*?(@.type() != "string")'::jsonpath)`
}

// Column types enforced by the database too, not only by ent's validators.
var (
	idType   = map[string]string{dialect.Postgres: "varchar(40)"}
	slugType = map[string]string{dialect.Postgres: "varchar(63)"}
	nameType = map[string]string{dialect.Postgres: "varchar(200)"}
)

// Slug and ID rules, shared by ent validators and database CHECK constraints.
const (
	slugPattern = `^[a-z][a-z0-9]*(-[a-z0-9]+)*$` // lowercase words joined by single dashes
	keyPattern  = `^[a-z][a-z0-9]*(_[a-z0-9]+)*$` // feature keys: snake_case, e.g. max_users
	maxSafeInt  = "9007199254740991"              // 2^53-1, JSON-safe (spec: limits)
	maxSeconds  = 3153600000                      // 36,500 days, the license format's duration limit
	idChars     = `[a-z2-7]{26}`
)

// prefixedID is a text primary key with a type prefix, e.g. "prd_…".
func prefixedID(newID func() string) ent.Field {
	return field.String("id").Immutable().NotEmpty().MaxLen(40).SchemaType(idType).DefaultFunc(newID)
}

// Timestamps adds created_at and updated_at.
type Timestamps struct{ mixin.Schema }

func (Timestamps) Fields() []ent.Field {
	return []ent.Field{
		field.Time("created_at").Immutable().Default(time.Now),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
	}
}

// TenantScoped adds the tenant_id column every tenant-owned table carries.
// Row-level security policies (migrations) filter on it; see ADR-0009.
type TenantScoped struct{ mixin.Schema }

func (TenantScoped) Fields() []ent.Field {
	return []ent.Field{field.String("tenant_id").Immutable().NotEmpty().MaxLen(40).SchemaType(idType)}
}

func (TenantScoped) Indexes() []ent.Index {
	return []ent.Index{index.Fields("tenant_id")}
}
