package api

import (
	"context"
	"encoding/json"

	"licenseforge.io/licenseforge/internal/api/apigen"
	"licenseforge.io/licenseforge/internal/catalog"
	"licenseforge.io/licenseforge/internal/customers"
	"licenseforge.io/licenseforge/internal/store/ent"
)

// nulls lists the fields of the merge-patch body in ctx set to null (the
// generated types can't tell null from absent).
func nulls(ctx context.Context, fields ...string) []string {
	var raw map[string]json.RawMessage
	body, _ := ctx.Value(bodyKey{}).([]byte)
	_ = json.Unmarshal(body, &raw) // strictInput decoded it already
	var out []string
	for _, k := range fields {
		if v, ok := raw[k]; ok && string(v) == "null" {
			out = append(out, k)
		}
	}
	return out
}

func (s *server) ListProducts(ctx context.Context, req apigen.ListProductsRequestObject) (apigen.ListProductsResponseObject, error) {
	limit, at, after, err := pageParams(req.Params.Limit, req.Params.Cursor, "prd")
	if err != nil {
		return nil, err
	}
	rows, err := s.Products.List(ctx, req.Params.Archived, limit+1, at, after)
	if err != nil {
		return nil, err
	}
	page := apigen.ListProducts200JSONResponse{Items: []apigen.Product{}}
	for i, p := range rows {
		if i == limit {
			c := encodeCursor(rows[i-1].CreatedAt, rows[i-1].ID)
			page.NextCursor = &c
			break
		}
		page.Items = append(page.Items, productView(p))
	}
	return page, nil
}

func (s *server) CreateProduct(ctx context.Context, req apigen.CreateProductRequestObject) (apigen.CreateProductResponseObject, error) {
	p, err := s.Products.Create(ctx, req.Body.Slug, req.Body.Name)
	if err != nil {
		return nil, err
	}
	return apigen.CreateProduct201JSONResponse(productView(p)), nil
}

func (s *server) GetProduct(ctx context.Context, req apigen.GetProductRequestObject) (apigen.GetProductResponseObject, error) {
	p, err := s.Products.Get(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return apigen.GetProduct200JSONResponse(productView(p)), nil
}

func (s *server) UpdateProduct(ctx context.Context, req apigen.UpdateProductRequestObject) (apigen.UpdateProductResponseObject, error) {
	p, err := s.Products.Update(ctx, req.Id, catalog.Patch{Name: req.Body.Name, Null: nulls(ctx, "name")})
	if err != nil {
		return nil, err
	}
	return apigen.UpdateProduct200JSONResponse(productView(p)), nil
}

func (s *server) ArchiveProduct(ctx context.Context, req apigen.ArchiveProductRequestObject) (apigen.ArchiveProductResponseObject, error) {
	p, err := s.Products.Archive(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return apigen.ArchiveProduct200JSONResponse(productView(p)), nil
}

func (s *server) ListCustomers(ctx context.Context, req apigen.ListCustomersRequestObject) (apigen.ListCustomersResponseObject, error) {
	limit, at, after, err := pageParams(req.Params.Limit, req.Params.Cursor, "cus")
	if err != nil {
		return nil, err
	}
	rows, err := s.Customers.List(ctx, limit+1, at, after)
	if err != nil {
		return nil, err
	}
	page := apigen.ListCustomers200JSONResponse{Items: []apigen.Customer{}}
	for i, c := range rows {
		if i == limit {
			cur := encodeCursor(rows[i-1].CreatedAt, rows[i-1].ID)
			page.NextCursor = &cur
			break
		}
		page.Items = append(page.Items, customerView(c))
	}
	return page, nil
}

func (s *server) CreateCustomer(ctx context.Context, req apigen.CreateCustomerRequestObject) (apigen.CreateCustomerResponseObject, error) {
	in := customers.Input{Name: req.Body.Name, Email: req.Body.Email}
	if req.Body.ExternalRefs != nil {
		in.ExternalRefs = *req.Body.ExternalRefs
	}
	c, err := s.Customers.Create(ctx, in)
	if err != nil {
		return nil, err
	}
	return apigen.CreateCustomer201JSONResponse(customerView(c)), nil
}

func (s *server) GetCustomer(ctx context.Context, req apigen.GetCustomerRequestObject) (apigen.GetCustomerResponseObject, error) {
	c, err := s.Customers.Get(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return apigen.GetCustomer200JSONResponse(customerView(c)), nil
}

func (s *server) UpdateCustomer(ctx context.Context, req apigen.UpdateCustomerRequestObject) (apigen.UpdateCustomerResponseObject, error) {
	b := req.Body
	patch := customers.Patch{Name: b.Name, Email: b.Email, Null: nulls(ctx, "name", "email", "external_refs")}
	if b.ExternalRefs != nil { // merge per key (RFC 7396): a null member (nil) deletes its key
		patch.ExternalRefs = *b.ExternalRefs
		if patch.ExternalRefs == nil {
			patch.ExternalRefs = map[string]*string{}
		}
	}
	c, err := s.Customers.Update(ctx, req.Id, patch)
	if err != nil {
		return nil, err
	}
	return apigen.UpdateCustomer200JSONResponse(customerView(c)), nil
}

func (s *server) ArchiveCustomer(ctx context.Context, req apigen.ArchiveCustomerRequestObject) (apigen.ArchiveCustomerResponseObject, error) {
	c, err := s.Customers.Archive(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return apigen.ArchiveCustomer200JSONResponse(customerView(c)), nil
}

func productView(p *ent.Product) apigen.Product {
	v := apigen.Product{Id: p.ID, Slug: p.Slug, Name: p.Name, CreatedAt: p.CreatedAt.UTC()}
	if p.ArchivedAt != nil {
		t := p.ArchivedAt.UTC()
		v.ArchivedAt = &t
	}
	return v
}

func customerView(c *ent.Customer) apigen.Customer {
	v := apigen.Customer{Id: c.ID, Name: c.Name, Email: c.Email, ExternalRefs: c.ExternalRefs, CreatedAt: c.CreatedAt.UTC()}
	if v.ExternalRefs == nil {
		v.ExternalRefs = map[string]string{}
	}
	if c.ArchivedAt != nil {
		t := c.ArchivedAt.UTC()
		v.ArchivedAt = &t
	}
	return v
}
