import { afterEach, expect, test } from "bun:test";
import {
  GetObjectCommand,
  PutObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { R2Server } from "lib/index";

let server: R2Server | undefined;

afterEach(async () => {
  await server?.stop();
  server = undefined;
});

test("starts, stores, and serves an object", async () => {
  server = new R2Server();
  await server.start();

  const apiKey = server.createBucketApiKey("uploads");

  const createBucketResponse = await fetch(`${server.url}/buckets/uploads`, {
    method: "POST",
    headers: {
      authorization: apiKey.authorizationHeader,
    },
  });

  expect(createBucketResponse.status).toBe(201);

  const putResponse = await fetch(
    `${server.url}/buckets/uploads/objects/hello.txt`,
    {
      method: "PUT",
      headers: {
        authorization: apiKey.authorizationHeader,
        "content-type": "text/plain",
      },
      body: "hello world",
    },
  );

  expect(putResponse.status).toBe(201);

  const getResponse = await fetch(
    `${server.url}/buckets/uploads/objects/hello.txt`,
    {
      headers: {
        authorization: apiKey.authorizationHeader,
      },
    },
  );

  expect(getResponse.status).toBe(200);
  expect(await getResponse.text()).toBe("hello world");
});

test("supports direct bucket creation and presigned urls", async () => {
  server = new R2Server();
  await server.start();

  server.createBucket("manual");
  await server.putObject("manual", "direct.txt", "direct body", "text/plain");

  const directObject = await server.getObject("manual", "direct.txt");
  expect(directObject?.contentType).toBe("text/plain");
  expect(new TextDecoder().decode(directObject?.body)).toBe("direct body");

  const putUrl = server.createPresignedPutUrl("manual", "signed.txt");
  const putResponse = await fetch(putUrl, {
    method: "PUT",
    headers: {
      "content-type": "text/plain",
    },
    body: "signed body",
  });

  expect(putResponse.status).toBe(201);

  const getUrl = server.createPresignedGetUrl("manual", "signed.txt");
  const getResponse = await fetch(getUrl);

  expect(getResponse.status).toBe(200);
  expect(await getResponse.text()).toBe("signed body");
});

test("accepts AWS SDK presigned urls", async () => {
  server = new R2Server();
  await server.start();
  server.createBucket("sdk");

  const credentials = server.createAwsCredentials({
    region: "us-east-1",
  });

  const client = new S3Client({
    region: credentials.region,
    credentials: {
      accessKeyId: credentials.accessKeyId,
      secretAccessKey: credentials.secretAccessKey,
      sessionToken: credentials.sessionToken,
    },
    endpoint: server.url,
    forcePathStyle: true,
  });

  const putUrl = await getSignedUrl(
    client,
    new PutObjectCommand({
      Bucket: "sdk",
      Key: "aws.txt",
      Body: "aws body",
    }),
    { expiresIn: 60 },
  );

  const putResponse = await fetch(putUrl, {
    method: "PUT",
    body: "aws body",
  });

  expect(putResponse.status).toBe(201);

  const getUrl = await getSignedUrl(
    client,
    new GetObjectCommand({
      Bucket: "sdk",
      Key: "aws.txt",
    }),
    { expiresIn: 60 },
  );

  const getResponse = await fetch(getUrl);

  expect(getResponse.status).toBe(200);
  expect(await getResponse.text()).toBe("aws body");
});
