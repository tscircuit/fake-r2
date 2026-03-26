import { createHash, createHmac, timingSafeEqual } from "node:crypto";

export type R2ServerOptions = {
  hostname?: string;
  port?: number;
};

export type BucketApiKey = {
  bucketName: string;
  token: string;
  authorizationHeader: string;
};

export type AwsCredentials = {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
  region: string;
};

export type AwsCredentialsOptions = {
  accessKeyId?: string;
  secretAccessKey?: string;
  sessionToken?: string;
  region?: string;
};

export type PresignedUrlOptions = {
  expiresInSeconds?: number;
};

export type PresignedUrlMethod = "GET" | "PUT";

type StoredObject = {
  body: Uint8Array;
  contentType: string;
};

type BucketRecord = Map<string, StoredObject>;

type AwsCredentialRecord = AwsCredentials & {
  createdAt: number;
};

const textEncoder = new TextEncoder();
const presignPathPrefix = "/buckets/";
const defaultPresignedUrlExpirySeconds = 15 * 60;
const awsSignatureAlgorithm = "AWS4-HMAC-SHA256";
const awsServiceName = "s3";

function jsonResponse(data: unknown, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers);
  headers.set("content-type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(data), {
    ...init,
    headers,
  });
}

function notFound(message: string): Response {
  return jsonResponse({ error: message }, { status: 404 });
}

function unauthorized(message: string): Response {
  return jsonResponse({ error: message }, { status: 401 });
}

function badRequest(message: string): Response {
  return jsonResponse({ error: message }, { status: 400 });
}

function toUtf8Bytes(value: string): Uint8Array {
  return textEncoder.encode(value);
}

function encodePathSegment(value: string): string {
  return encodeURIComponent(value);
}

function encodeObjectKey(objectKey: string): string {
  return objectKey
    .split("/")
    .map((segment) => encodePathSegment(segment))
    .join("/");
}

function uriEncode(value: string, encodeSlash = true): string {
  const bytes = textEncoder.encode(value);
  let encoded = "";

  for (const byte of bytes) {
    const char = String.fromCharCode(byte);
    const isUnreserved =
      (byte >= 0x41 && byte <= 0x5a) ||
      (byte >= 0x61 && byte <= 0x7a) ||
      (byte >= 0x30 && byte <= 0x39) ||
      byte === 0x2d ||
      byte === 0x2e ||
      byte === 0x5f ||
      byte === 0x7e;

    if (isUnreserved || (!encodeSlash && char === "/")) {
      encoded += char;
    } else {
      encoded += `%${byte.toString(16).toUpperCase().padStart(2, "0")}`;
    }
  }

  return encoded;
}

function canonicalizePath(pathname: string): string {
  const segments = pathname.split("/").filter((segment) => segment.length > 0);

  if (segments.length === 0) {
    return "/";
  }

  return `/${segments
    .map((segment) => uriEncode(decodeURIComponent(segment), true))
    .join("/")}`;
}

function canonicalizeQueryParameters(searchParams: URLSearchParams): string {
  const pairs: Array<{ key: string; value: string }> = [];

  for (const [key, value] of searchParams.entries()) {
    if (key === "X-Amz-Signature") {
      continue;
    }

    pairs.push({
      key: uriEncode(key, true),
      value: uriEncode(value, true),
    });
  }

  pairs.sort((left, right) => {
    if (left.key !== right.key) {
      return left.key < right.key ? -1 : 1;
    }

    if (left.value !== right.value) {
      return left.value < right.value ? -1 : 1;
    }

    return 0;
  });

  return pairs.map(({ key, value }) => `${key}=${value}`).join("&");
}

function hashSha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function deriveAwsSigningKey(
  secretAccessKey: string,
  dateStamp: string,
  region: string,
  service: string,
): Buffer {
  const kDate = createHmac("sha256", `AWS4${secretAccessKey}`)
    .update(dateStamp)
    .digest();
  const kRegion = createHmac("sha256", kDate).update(region).digest();
  const kService = createHmac("sha256", kRegion).update(service).digest();

  return createHmac("sha256", kService).update("aws4_request").digest();
}

function safeCompareStrings(left: string, right: string): boolean {
  const leftBytes = toUtf8Bytes(left);
  const rightBytes = toUtf8Bytes(right);

  if (leftBytes.length !== rightBytes.length) {
    return false;
  }

  return timingSafeEqual(leftBytes, rightBytes);
}

function toPresignedPayload(
  method: PresignedUrlMethod,
  bucketName: string,
  objectKey: string,
  expiresAt: number,
): string {
  return `${method}\n${bucketName}\n${objectKey}\n${expiresAt}`;
}

function normalizeExpiresInSeconds(
  expiresInSeconds: number | undefined,
): number {
  const value = expiresInSeconds ?? defaultPresignedUrlExpirySeconds;

  if (!Number.isFinite(value) || value <= 0) {
    throw new Error("expiresInSeconds must be a positive finite number");
  }

  return value;
}

function normalizeObjectPath(objectKey: string): string {
  return objectKey
    .split("/")
    .map((segment) => encodePathSegment(segment))
    .join("/");
}

export class R2Server {
  readonly #hostname: string;
  readonly #port: number;
  readonly #presignSecret: string;
  #server: Bun.Server<undefined> | undefined;
  #url: string | undefined;
  #buckets = new Map<string, BucketRecord>();
  #bucketTokens = new Map<string, string>();
  #awsCredentials = new Map<string, AwsCredentialRecord>();

  constructor(options: R2ServerOptions = {}) {
    this.#hostname = options.hostname ?? "127.0.0.1";
    this.#port = options.port ?? 0;
    this.#presignSecret = crypto.randomUUID();
  }

  get url(): string {
    if (this.#url == null) {
      throw new Error("R2Server has not been started");
    }

    return this.#url;
  }

  async start(): Promise<string> {
    if (this.#server != null) {
      return this.url;
    }

    this.#server = Bun.serve({
      hostname: this.#hostname,
      port: this.#port,
      fetch: this.#handleRequest,
    });
    this.#url = `http://${this.#hostname}:${this.#server.port}`;

    return this.url;
  }

  async stop(): Promise<void> {
    this.#server?.stop(true);
    this.#server = undefined;
    this.#url = undefined;
    this.#buckets.clear();
    this.#bucketTokens.clear();
    this.#awsCredentials.clear();
  }

  createBucket(bucketName: string): void {
    if (!this.#buckets.has(bucketName)) {
      this.#buckets.set(bucketName, new Map<string, StoredObject>());
    }
  }

  createBucketApiKey(bucketName = "default"): BucketApiKey {
    this.createBucket(bucketName);

    const token = crypto.randomUUID();
    this.#bucketTokens.set(token, bucketName);

    return {
      bucketName,
      token,
      authorizationHeader: `Bearer ${token}`,
    };
  }

  createAwsCredentials(options: AwsCredentialsOptions = {}): AwsCredentials {
    const accessKeyId =
      options.accessKeyId ??
      `AKIA${crypto.randomUUID().replaceAll("-", "").slice(0, 16).toUpperCase()}`;
    const secretAccessKey =
      options.secretAccessKey ??
      `${crypto.randomUUID().replaceAll("-", "")}${crypto.randomUUID().replaceAll("-", "")}`;
    const region = options.region ?? "us-east-1";

    this.#awsCredentials.set(accessKeyId, {
      accessKeyId,
      secretAccessKey,
      sessionToken: options.sessionToken,
      region,
      createdAt: Date.now(),
    });

    return {
      accessKeyId,
      secretAccessKey,
      sessionToken: options.sessionToken,
      region,
    };
  }

  createPresignedUrl(
    method: PresignedUrlMethod,
    bucketName: string,
    objectKey: string,
    options: PresignedUrlOptions = {},
  ): string {
    const expiresInSeconds = normalizeExpiresInSeconds(
      options.expiresInSeconds,
    );
    const expiresAt = Date.now() + expiresInSeconds * 1000;
    const url = new URL(this.url);

    url.pathname = `${presignPathPrefix}${encodePathSegment(bucketName)}/objects/${normalizeObjectPath(objectKey)}`;
    url.searchParams.set("method", method);
    url.searchParams.set("expires", String(expiresAt));
    url.searchParams.set(
      "signature",
      this.#signCustomPresignedRequest(
        method,
        bucketName,
        objectKey,
        expiresAt,
      ),
    );

    return url.toString();
  }

  createPresignedGetUrl(
    bucketName: string,
    objectKey: string,
    options: PresignedUrlOptions = {},
  ): string {
    return this.createPresignedUrl("GET", bucketName, objectKey, options);
  }

  createPresignedPutUrl(
    bucketName: string,
    objectKey: string,
    options: PresignedUrlOptions = {},
  ): string {
    return this.createPresignedUrl("PUT", bucketName, objectKey, options);
  }

  async putObject(
    bucketName: string,
    objectKey: string,
    body: BodyInit,
    contentType = "application/octet-stream",
  ): Promise<void> {
    this.createBucket(bucketName);

    const bytes =
      typeof body === "string"
        ? toUtf8Bytes(body)
        : body instanceof Uint8Array
          ? body
          : new Uint8Array(await new Response(body).arrayBuffer());

    this.#buckets.get(bucketName)?.set(objectKey, {
      body: bytes,
      contentType,
    });
  }

  async getObject(
    bucketName: string,
    objectKey: string,
  ): Promise<StoredObject | undefined> {
    return this.#buckets.get(bucketName)?.get(objectKey);
  }

  deleteObject(bucketName: string, objectKey: string): boolean {
    return this.#buckets.get(bucketName)?.delete(objectKey) ?? false;
  }

  #handleRequest = async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    const pathSegments = url.pathname.split("/").filter(Boolean);

    if (url.pathname === "/health") {
      return jsonResponse({ ok: true });
    }

    if (url.pathname === "/") {
      return jsonResponse({
        name: "fake-r2",
        status: "running",
      });
    }

    const route = this.#resolveObjectRoute(pathSegments);

    if (route == null) {
      return notFound("Unknown route");
    }

    if (route.kind === "custom-bucket" && request.method === "POST") {
      this.createBucket(route.bucketName);
      return jsonResponse({ bucketName: route.bucketName }, { status: 201 });
    }

    if (route.kind === "custom-bucket" && route.objectKey === "") {
      return badRequest("Expected an object key");
    }

    if (
      !this.#isAuthorized(request, route.bucketName) &&
      !this.#isCustomPresignedRequestAuthorized(
        request,
        route.bucketName,
        route.objectKey,
      ) &&
      !this.#isAwsPresignedRequestAuthorized(
        request,
        route.bucketName,
        route.objectKey,
      )
    ) {
      return unauthorized("Missing or invalid bucket API key");
    }

    if (request.method === "PUT") {
      this.createBucket(route.bucketName);
      const contentType =
        request.headers.get("content-type") ?? "application/octet-stream";
      const body = new Uint8Array(await request.arrayBuffer());

      this.#buckets.get(route.bucketName)?.set(route.objectKey, {
        body,
        contentType,
      });

      return jsonResponse(
        {
          bucketName: route.bucketName,
          objectKey: route.objectKey,
          contentType,
        },
        { status: 201 },
      );
    }

    if (request.method === "GET") {
      const object = await this.getObject(route.bucketName, route.objectKey);

      if (object == null) {
        return notFound("Object not found");
      }

      return new Response(object.body.slice(0), {
        headers: {
          "content-type": object.contentType,
        },
      });
    }

    if (request.method === "DELETE") {
      const deleted = this.deleteObject(route.bucketName, route.objectKey);

      if (!deleted) {
        return notFound("Object not found");
      }

      return new Response(null, { status: 204 });
    }

    return notFound("Unknown route");
  };

  #isAuthorized(request: Request, bucketName: string): boolean {
    const token = this.#getTokenFromRequest(request);

    if (token == null) {
      return !this.#bucketTokensHasBucket(bucketName);
    }

    return this.#bucketTokens.get(token) === bucketName;
  }

  #bucketTokensHasBucket(bucketName: string): boolean {
    for (const tokenBucketName of this.#bucketTokens.values()) {
      if (tokenBucketName === bucketName) {
        return true;
      }
    }

    return false;
  }

  #getTokenFromRequest(request: Request): string | undefined {
    const authorization = request.headers.get("authorization");
    if (authorization?.startsWith("Bearer ")) {
      return authorization.slice("Bearer ".length).trim();
    }

    return request.headers.get("x-api-key") ?? undefined;
  }

  #resolveObjectRoute(
    pathSegments: string[],
  ):
    | { kind: "custom-bucket"; bucketName: string; objectKey: string }
    | { kind: "s3-object"; bucketName: string; objectKey: string }
    | null {
    if (pathSegments[0] === "buckets") {
      if (pathSegments.length === 2) {
        return {
          kind: "custom-bucket",
          bucketName: pathSegments[1],
          objectKey: "",
        };
      }

      if (pathSegments.length > 3 && pathSegments[2] === "objects") {
        return {
          kind: "custom-bucket",
          bucketName: pathSegments[1],
          objectKey: pathSegments.slice(3).join("/"),
        };
      }

      return null;
    }

    if (pathSegments.length >= 2) {
      return {
        kind: "s3-object",
        bucketName: pathSegments[0],
        objectKey: pathSegments.slice(1).join("/"),
      };
    }

    return null;
  }

  #signCustomPresignedRequest(
    method: PresignedUrlMethod,
    bucketName: string,
    objectKey: string,
    expiresAt: number,
  ): string {
    return createHmac("sha256", this.#presignSecret)
      .update(toPresignedPayload(method, bucketName, objectKey, expiresAt))
      .digest("hex");
  }

  #isCustomPresignedRequestAuthorized(
    request: Request,
    bucketName: string,
    objectKey: string,
  ): boolean {
    const url = new URL(request.url);
    const method = url.searchParams.get("method");
    const expires = url.searchParams.get("expires");
    const signature = url.searchParams.get("signature");

    if (
      method == null ||
      expires == null ||
      signature == null ||
      method !== request.method
    ) {
      return false;
    }

    const expiresAt = Number(expires);
    if (!Number.isFinite(expiresAt) || Date.now() > expiresAt) {
      return false;
    }

    const expectedSignature = this.#signCustomPresignedRequest(
      method as PresignedUrlMethod,
      bucketName,
      objectKey,
      expiresAt,
    );

    return safeCompareStrings(signature, expectedSignature);
  }

  #isAwsPresignedRequestAuthorized(
    request: Request,
    bucketName: string,
    objectKey: string,
  ): boolean {
    const url = new URL(request.url);
    const algorithm = url.searchParams.get("X-Amz-Algorithm");
    const credential = url.searchParams.get("X-Amz-Credential");
    const date = url.searchParams.get("X-Amz-Date");
    const expires = url.searchParams.get("X-Amz-Expires");
    const signedHeaders = url.searchParams.get("X-Amz-SignedHeaders");
    const signature = url.searchParams.get("X-Amz-Signature");

    if (
      algorithm !== awsSignatureAlgorithm ||
      credential == null ||
      date == null ||
      expires == null ||
      signedHeaders == null ||
      signature == null
    ) {
      return false;
    }

    const credentialParts = credential.split("/");
    if (credentialParts.length !== 5) {
      return false;
    }

    const [accessKeyId, dateStamp, region, service, terminal] = credentialParts;
    if (terminal !== "aws4_request" || service !== awsServiceName) {
      return false;
    }

    const credentialRecord = this.#awsCredentials.get(accessKeyId);
    if (
      credentialRecord == null ||
      credentialRecord.region !== region ||
      !this.#isAwsSessionTokenValid(request, credentialRecord.sessionToken)
    ) {
      return false;
    }

    const expiresInSeconds = Number(expires);
    if (
      !Number.isFinite(expiresInSeconds) ||
      expiresInSeconds <= 0 ||
      expiresInSeconds > 604800
    ) {
      return false;
    }

    const requestTime = Date.parse(
      `${date.slice(0, 4)}-${date.slice(4, 6)}-${date.slice(6, 8)}T${date.slice(9, 11)}:${date.slice(11, 13)}:${date.slice(13, 15)}Z`,
    );
    if (!Number.isFinite(requestTime)) {
      return false;
    }

    const expiresAt = requestTime + expiresInSeconds * 1000;
    if (Date.now() > expiresAt) {
      return false;
    }

    const canonicalUri = canonicalizePath(url.pathname);
    const canonicalQuery = canonicalizeQueryParameters(url.searchParams);
    const signedHeadersList = signedHeaders
      .split(";")
      .map((header) => header.trim().toLowerCase())
      .filter(Boolean);
    const canonicalHeaders = this.#buildCanonicalHeaders(
      request,
      url,
      signedHeadersList,
    );

    if (canonicalHeaders == null) {
      return false;
    }

    const payloadHash =
      url.searchParams.get("X-Amz-Content-Sha256") ?? "UNSIGNED-PAYLOAD";
    const canonicalRequest = [
      request.method,
      canonicalUri,
      canonicalQuery,
      canonicalHeaders,
      signedHeadersList.join(";"),
      payloadHash,
    ].join("\n");
    const stringToSign = [
      awsSignatureAlgorithm,
      date,
      `${dateStamp}/${region}/${service}/aws4_request`,
      hashSha256Hex(canonicalRequest),
    ].join("\n");
    const signingKey = deriveAwsSigningKey(
      credentialRecord.secretAccessKey,
      dateStamp,
      region,
      service,
    );
    const expectedSignature = createHmac("sha256", signingKey)
      .update(stringToSign)
      .digest("hex");

    return safeCompareStrings(signature, expectedSignature);
  }

  #buildCanonicalHeaders(
    request: Request,
    url: URL,
    signedHeaders: string[],
  ): string | null {
    const headerValues = new Map<string, string>();
    request.headers.forEach((value, key) => {
      headerValues.set(key.toLowerCase(), value.trim().replace(/\s+/g, " "));
    });

    if (!headerValues.has("host")) {
      headerValues.set("host", url.host);
    }

    const lines: string[] = [];
    for (const headerName of signedHeaders) {
      const headerValue = headerValues.get(headerName);
      if (headerValue == null) {
        return null;
      }

      lines.push(`${headerName}:${headerValue}`);
    }

    return `${lines.join("\n")}\n`;
  }

  #isAwsSessionTokenValid(
    request: Request,
    expectedSessionToken: string | undefined,
  ): boolean {
    if (expectedSessionToken == null) {
      return true;
    }

    return (
      request.headers.get("x-amz-security-token") === expectedSessionToken ||
      new URL(request.url).searchParams.get("X-Amz-Security-Token") ===
        expectedSessionToken
    );
  }
}
