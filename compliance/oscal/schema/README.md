# Vendored OSCAL schema

`oscal_component_schema.json` is the official OSCAL **v1.2.3** component-definition JSON schema, unmodified. It is vendored so that validation runs offline.

- Source: <https://github.com/usnistgov/OSCAL/releases/download/v1.2.3/oscal_component_schema.json> (release [v1.2.3](https://github.com/usnistgov/OSCAL/releases/tag/v1.2.3))
- SHA-256: `95e76881151ececd5cb1a93ff0f70ad74b8cc1aa58771626ac8b262bf2c8e001`
- License: public domain (a work of the US government, NIST), with a CC0 1.0 dedication worldwide; see [OSCAL LICENSE.md](https://github.com/usnistgov/OSCAL/blob/v1.2.3/LICENSE.md). Source: National Institute of Standards and Technology.

To upgrade, replace the file with another release's schema, update the version, URL and hash here, `schemaID` in `../../compliance_test.go`, and `oscal-version` in `../component-definition.json`.
