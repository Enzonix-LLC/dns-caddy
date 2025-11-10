# Enzonix DNS provider for Caddy

`dns.providers.enzonix` is a [Caddy](https://caddyserver.com) module that lets you solve ACME DNS challenges using the Enzonix DNS API. The module only requires an API key to operate.

## Installation

Build Caddy with the Enzonix provider:

```bash
xcaddy build --with github.com/Enzonix-LLC/dns-caddy
```

## Configuration

### JSON

```json
{
  "module": "acme",
  "challenges": {
    "dns": {
      "provider": {
        "name": "enzonix",
        "api_key": "{env.ENZONIX_API_KEY}"
      }
    }
  }
}
```

### Caddyfile

```
tls {
	dns enzonix {env.ENZONIX_API_KEY}
}
```

#### Optional parameters

```
enzonix {
	api_key {env.ENZONIX_API_KEY}
	endpoint https://api.enzonix.com/v1/dns
	timeout 10s
}
```

- `api_key` (required): API token issued by Enzonix.
- `endpoint` (optional): Override the API base URL (useful for development or regional endpoints).
- `timeout` (optional): HTTP client timeout; defaults to `10s`.

## Authentication

Supply your Enzonix API key via the `api_key` field or an environment variable placeholder (`{env.ENZONIX_API_KEY}`).

## Development

1. Install dependencies with `go mod tidy`.
2. Run tests:

   ```bash
   go test ./...
   ```

## License

MIT © Enzonix

