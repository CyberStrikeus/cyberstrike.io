# @cyberstrike/sdk

Official JavaScript/TypeScript SDK for the Cyberstrike API.

## Structure

- **js/** - TypeScript SDK package
- **openapi.json** - OpenAPI specification

## Installation

```bash
npm install @cyberstrike/sdk
```

## Usage

```typescript
import { createClient } from "@cyberstrike/sdk/client"

const client = createClient({
  baseUrl: "https://api.cyberstrike.io",
  apiKey: process.env.CYBERSTRIKE_API_KEY
})

// Use the client to interact with the API
const sessions = await client.sessions.list()
```

## API Reference

See the [OpenAPI specification](./openapi.json) for the complete API reference.

## Development

```bash
cd packages/sdk/js

# Generate types from OpenAPI spec
bun run build

# Type check
bun run typecheck
```

## License

MIT
