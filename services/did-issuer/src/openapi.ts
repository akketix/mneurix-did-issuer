/** OpenAPI 3.1 document for the did-issuer service. Served at GET /v1/openapi.json.
 * Paths declare the v1 contract; handlers are stubbed in M1 (501) and filled in
 * M2+ (proctoring engine) / M3-M6 (DID issuance). */
export const openApiDoc = {
	openapi: "3.1.0",
	info: {
		title: "Mneurix DID Token Issuer",
		version: "0.1.0",
		description: "did:web + W3C Verifiable Credentials (VC-JOSE-COSE / SD-JWT VC) issuer.",
		license: { name: "Elastic License 2.0", url: "https://www.elastic.co/licensing/elastic-license" },
	},
	servers: [{ url: "/v1", description: "relative" }],
	components: {
		securitySchemes: {
			serviceToken: { type: "apiKey", in: "header", name: "x-mneurix-service-token" },
		},
		responses: {
			NotImplemented: {
				description: "Endpoint declared but not implemented in this milestone.",
				content: { "application/json": { schema: { $ref: "#/components/schemas/Error" } } },
			},
		},
		schemas: {
			Error: {
				type: "object",
				properties: {
					error: {
						type: "object",
						properties: { code: { type: "string" }, message: { type: "string" }, details: {} },
						required: ["code", "message"],
					},
				},
				required: ["error"],
			},
		},
	},
	paths: {
	"/.well-known/did.json": { get: { summary: "did:web DID document (canonical origin)", operationId: "wellKnownDid", security: [], responses: { "200": { description: "DID document" }, "501": { $ref: "#/components/responses/NotImplemented" } } } },
	"/.well-known/jwt-vc-issuer": { get: { summary: "SD-JWT VC issuer metadata", operationId: "wellKnownJwtVcIssuer", security: [], responses: { "200": { description: "Issuer metadata" }, "501": { $ref: "#/components/responses/NotImplemented" } } } },
	"/v1/dids": {
		post: {
			summary: "Mint a did:web identifier + publish its DID document",
			operationId: "post_v1_dids",
			security: [{ serviceToken: [] }],
			responses: {
				"200": { description: "OK" },
				"501": { $ref: "#/components/responses/NotImplemented" },
			},
		},
	},
	"/v1/dids/{did}": {
		get: {
			summary: "Resolve a did:web identifier (fan-out + quorum)",
			operationId: "get_v1_dids_did_",
			security: [{ serviceToken: [] }],
			responses: {
				"200": { description: "OK" },
				"501": { $ref: "#/components/responses/NotImplemented" },
			},
		},
	},
	"/v1/vcs:issue": {
		post: {
			summary: "Issue a Verifiable Credential (OB3 Data-Integrity or SD-JWT VC)",
			operationId: "post_v1_vcs_issue",
			security: [{ serviceToken: [] }],
			responses: {
				"200": { description: "OK" },
				"501": { $ref: "#/components/responses/NotImplemented" },
			},
		},
	},
	"/v1/presentations:verify": {
		post: {
			summary: "Verify a Verifiable Presentation / VC",
			operationId: "post_v1_presentations_verify",
			security: [{ serviceToken: [] }],
			responses: {
				"200": { description: "OK" },
				"501": { $ref: "#/components/responses/NotImplemented" },
			},
		},
	},
	"/v1/dids/{did}/keys:rotate": {
		post: {
			summary: "Rotate the assertion key (DID stays stable)",
			operationId: "post_v1_dids_did_keys_rotate",
			security: [{ serviceToken: [] }],
			responses: {
				"200": { description: "OK" },
				"501": { $ref: "#/components/responses/NotImplemented" },
			},
		},
	},
	"/v1/dids/{did}/keys:revoke": {
		post: {
			summary: "Revoke an assertion key (tombstone)",
			operationId: "post_v1_dids_did_keys_revoke",
			security: [{ serviceToken: [] }],
			responses: {
				"200": { description: "OK" },
				"501": { $ref: "#/components/responses/NotImplemented" },
			},
		},
	},
	"/v1/credentials/{id}/status": {
		get: {
			summary: "Credential revocation status (fail-closed)",
			operationId: "get_v1_credentials_id_status",
			security: [{ serviceToken: [] }],
			responses: {
				"200": { description: "OK" },
				"501": { $ref: "#/components/responses/NotImplemented" },
			},
		},
	},
	"/v1/dids/{did}/publish": {
		post: {
			summary: "Publish the DID document to all origins (quorum)",
			operationId: "post_v1_dids_did_publish",
			security: [{ serviceToken: [] }],
			responses: {
				"200": { description: "OK" },
				"501": { $ref: "#/components/responses/NotImplemented" },
			},
		},
	},
	},
} as const;
