-- Product archive (ADR-0015): products are archived, never deleted. The
-- serving pools may set archived_at (the service sets it once); slug and
-- ownership stay immutable, and there is still no DELETE grant.
GRANT UPDATE ("archived_at") ON "products" TO licenseforge_app, licenseforge_platform;
