# fake-r2

In-memory fake R2/S3 fixture for tests.

## Install

```bash
bun install @tscircuit/fake-r2
```

## Run tests

```bash
bun test
```

## Usage

```tsx
import { R2Server } from "lib/index";

const r2Server = new R2Server();

await r2Server.start();

r2Server.createBucket("uploads");
const apiKey = r2Server.createBucketApiKey();
const awsCredentials = r2Server.createAwsCredentials();
const putUrl = r2Server.createPresignedPutUrl("uploads", "hello.txt");
const getUrl = r2Server.createPresignedGetUrl("uploads", "hello.txt");

console.log(r2Server.url);
console.log(apiKey.authorizationHeader);
console.log(awsCredentials.accessKeyId);
console.log(putUrl);
console.log(getUrl);

await r2Server.stop();
```

## Routes

- `GET /health`
- `GET /`
- `POST /buckets/:bucket`
- `PUT /buckets/:bucket/objects/:key`
- `GET /buckets/:bucket/objects/:key`
- `DELETE /buckets/:bucket/objects/:key`

## Presigned Urls

- `createPresignedPutUrl(bucketName, objectKey, options?)`
- `createPresignedGetUrl(bucketName, objectKey, options?)`
- `createBucket(bucketName)` creates an in-memory bucket without an HTTP call
- `createAwsCredentials(options?)` returns credentials compatible with AWS SDK presigned URLs
