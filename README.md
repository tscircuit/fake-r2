# fake-r2

Fake R2 API (S3-api) for testing, capable of presigned urls, bucket uploading, auth etc.


```tsx
const r2Server = new R2Server()

await r2Server.start()

r2Server.createBucketApiKey() //etc.

console.log(r2Server.url)

await r2Server.stop()
```
