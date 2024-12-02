import { expect, describe, it } from "bun:test";

import { loadCrypto } from "../src/webCrypto.ts";
import {
  Client,
  ClientConstructor,
  DeterministicKeyConfig,
  KeyConfig,
  Server,
} from "../src/ohttp.ts";
import {
  InvalidEncodingError,
  InvalidContentTypeError,
} from "../src/errors.ts";


async function randomBytes(l: number): Promise<Uint8Array> {
  const buffer = new Uint8Array(l);
  const cryptoApi = await loadCrypto();
  cryptoApi.getRandomValues(buffer);
  return buffer;
}

function hexToArrayBuffer(input: string): Uint8Array {
  const view = new Uint8Array(input.length / 2)
  for (let i = 0; i < input.length; i += 2) {
    view[i / 2] = parseInt(input.substring(i, i + 2), 16)
  }
  return view;
}

describe("test OHTTP end-to-end", () => {
  it("Request label bug", async () => {
    const keyId = 0x01;
    const seed = new Uint8Array([
      0x45, 0x04, 0xe2, 0x24, 0x51, 0xe6, 0x53, 0x5c, 0xac, 0x1e, 0x89, 0x4e,
      0x35, 0xb0, 0x75, 0x41, 0xc0, 0x0f, 0x8a, 0xa2, 0x45, 0xb8, 0x36, 0x0c,
      0x06, 0x43, 0x3c, 0x46, 0x85, 0x9a, 0x79, 0xd7
    ]);
    const keyConfig = new DeterministicKeyConfig(keyId, seed);
    const server = new Server(keyConfig);

    const encodedClientRequestStr = "010020000100016f026e20fa4024c3852641f91177cf188c70b341d20e4f51ee8e8f1b6ad9a8566bd28fa76ce7869a0db0555f251db8411c32f4686661db5141d76e6dcc538c30a6e6cb6d0b1554ec9d5a6256b2fec49b47ebec510e70d12f249744d638a3275168e56e4c4cebd56288091ae448a1d42f6573611b32242907dfa3ed589e4537821d";
    const encodedClientRequest = hexToArrayBuffer(encodedClientRequestStr);

    const responseContext = await server.decodeAndDecapsulate(
      encodedClientRequest,
    );
    const receivedRequest = responseContext.request();
    expect(receivedRequest.url).toBe("https://ietf-wg-ohai.github.io/oblivious-http/draft-ietf-ohai-ohttp.html");
  });

  it("Happy Path", async () => {
    const keyId = 0x01;
    const keyConfig = new KeyConfig(keyId);
    const publicKeyConfig = await keyConfig.publicConfig();

    const encodedRequest = new TextEncoder().encode("Happy");
    const encodedResponse = new TextEncoder().encode("Path");

    const client = new Client(publicKeyConfig);
    const requestContext = await client.encapsulate(encodedRequest);
    const clientRequest = requestContext.request;

    const server = new Server(keyConfig);
    const responseContext = await server.decapsulate(clientRequest);
    expect(responseContext.encodedRequest).toEqual(encodedRequest);

    const serverResponse = await responseContext.encapsulate(encodedResponse);
    const finalResponse = await requestContext.decapsulate(serverResponse);
    expect(finalResponse).toEqual(encodedResponse);
  });

  it("Happy Path with encoding and decoding", async () => {
    const keyId = 0x01;
    const keyConfig = new KeyConfig(keyId);
    const server = new Server(keyConfig);

    const encodedKeyConfig = await server.encodeKeyConfig();

    const encodedRequest = new TextEncoder().encode("Happy");
    const encodedResponse = new TextEncoder().encode("Path");

    const constructor = new ClientConstructor();
    const client = await constructor.clientForConfig(encodedKeyConfig);
    const requestContext = await client.encapsulate(encodedRequest);
    const clientRequest = requestContext.request;
    const encodedClientRequest = clientRequest.encode();

    const responseContext = await server.decodeAndDecapsulate(
      encodedClientRequest,
    );
    expect(responseContext.encodedRequest).toEqual(encodedRequest);

    const serverResponse = await responseContext.encapsulate(encodedResponse);
    const encodedServerResponse = serverResponse.encode();

    const finalResponse = await requestContext.decodeAndDecapsulate(
      encodedServerResponse,
    );
    expect(finalResponse).toEqual(encodedResponse);
  });

  it("Happy Path with Request/Response encoding and decoding", async () => {
    const keyId = 0x01;
    const keyConfig = new KeyConfig(keyId);
    const publicKeyConfig = await keyConfig.publicConfig();

    const requestUrl = "https://target.example/query?foo=bar";
    const request = new Request(requestUrl);
    const response = new Response("baz", {
      headers: { "Content-Type": "text/plain" },
    });

    const client = new Client(publicKeyConfig);
    const requestContext = await client.encapsulateRequest(request);
    const clientRequest = requestContext.request;
    const encodedClientRequest = clientRequest.encode();

    const server = new Server(keyConfig);
    const responseContext = await server.decodeAndDecapsulate(
      encodedClientRequest,
    );
    const receivedRequest = responseContext.request();
    expect(receivedRequest.url).toBe("https://target.example/query");

    const serverResponse = await responseContext.encapsulateResponse(response);

    const finalResponse = await requestContext.decapsulateResponse(
      serverResponse,
    );
    expect(finalResponse.headers.get("Content-Type")).toBe("text/plain");
    const body = await finalResponse.arrayBuffer();
    expect(new TextDecoder().decode(new Uint8Array(body))).toBe("baz");
  });

  it("Happy Path with a deterministic KeyConfig", async () => {
    const keyId = 0x01;
    const seed = await randomBytes(32);

    // Create a pair of servers with the same config and make sure they result in the same public key configuration
    const keyConfig = new DeterministicKeyConfig(keyId, seed);
    const server = new Server(keyConfig);
    const sameConfig = new DeterministicKeyConfig(keyId, seed);
    const sameServer = new Server(sameConfig);
    const diffConfig = new KeyConfig(keyId);
    const diffServer = new Server(diffConfig);

    const configA = await server.encodeKeyConfig();
    const configB = await sameServer.encodeKeyConfig();
    const configC = await diffServer.encodeKeyConfig();
    expect(configA).toEqual(configB);
    expect(configA).not.toEqual(configC);

    const publicKeyConfig = await keyConfig.publicConfig();

    const requestUrl = "https://target.example/query?foo=bar";
    const request = new Request(requestUrl);
    const response = new Response("baz", {
      headers: { "Content-Type": "text/plain" },
    });

    const client = new Client(publicKeyConfig);
    const requestContext = await client.encapsulateRequest(request);
    const clientRequest = requestContext.request;
    const encodedClientRequest = clientRequest.encode();

    const responseContext = await server.decodeAndDecapsulate(
      encodedClientRequest,
    );
    const receivedRequest = responseContext.request();
    expect(receivedRequest.url).toBe("https://target.example/query");

    const serverResponse = await responseContext.encapsulateResponse(response);

    const finalResponse = await requestContext.decapsulateResponse(
      serverResponse,
    );
    expect(finalResponse.headers.get("Content-Type")).toBe("text/plain");
    const body = await finalResponse.arrayBuffer();
    expect(new TextDecoder().decode(new Uint8Array(body))).toBe("baz");
  });

  it("KeyConfig encoding and decoding", async () => {
    const keyId = 0x01;
    const seed = await randomBytes(32);

    // Create a pair of servers with the same config and make sure they result in the same public key configuration
    const keyConfig = new DeterministicKeyConfig(keyId, seed);
    const publicConfig = await keyConfig.publicConfig();
    const encodedConfig = await publicConfig.encode();

    // Skip past the 2-byte length prefix
    const config = encodedConfig.slice(2);
    
    // Ensure the preamble matches
    expect(config.slice(0, 3)).toEqual(new Uint8Array([0x01, 0x00, 0x20]));

    // Ensure the public key matches
    const encodedKey = new Uint8Array(
      await publicConfig.suite.kem.serializePublicKey(
        publicConfig.publicKey,
      ),
    );
    expect(config.slice(3, 3 + encodedKey.length)).toEqual(encodedKey);

    // Ensure the tail matches
    expect(
      config.slice(3 + encodedKey.length, 3 + encodedKey.length + 6)
    ).toEqual(new Uint8Array([0x00, 0x04, 0x00, 0x01, 0x00, 0x01]));

    // Verify length prefix is correct
    const length = (encodedConfig[0] << 8) | encodedConfig[1];
    expect(length).toEqual(config.length);
  });
});

describe("test key configuration format", () => {
  it("handles RFC9458 format key configurations", async () => {
    const keyId = 0x01;
    const keyConfig = new KeyConfig(keyId);
    const server = new Server(keyConfig);
    
    // Get the encoded config
    const config = await server.encodeKeyConfig();
    
    // First two bytes should be length prefix
    const length = (config[0] << 8) | config[1];
    expect(config.length).toBe(length + 2);
    
    // Should be parseable
    const constructor = new ClientConstructor();
    const client = await constructor.clientForConfig(config);
    
    // Verify with round trip
    const testData = new TextEncoder().encode("test");
    const requestContext = await client.encapsulate(testData);
    const responseContext = await server.decapsulate(requestContext.request);
    expect(responseContext.encodedRequest).toEqual(testData);
  });

  it("validates length prefix correctness", async () => {
    const keyId = 0x01;
    const keyConfig = new KeyConfig(keyId);
    const server = new Server(keyConfig);
    
    // Get valid encoded config
    const config = await server.encodeKeyConfig();
    
    // Corrupt the length prefix to be too long
    const corruptConfig = new Uint8Array(config);
    corruptConfig[0] = 0xFF;
    corruptConfig[1] = 0xFF;
    
    const constructor = new ClientConstructor();
    await expect(constructor.clientForConfig(corruptConfig))
      .rejects
      .toThrow(InvalidEncodingError);
  });

  it("handles concatenated key configs", async () => {
    const keyId1 = 0x01;
    const keyId2 = 0x02;
    const seed1 = await randomBytes(32);
    const seed2 = await randomBytes(32);
    
    // Create two different configs
    const keyConfig1 = new DeterministicKeyConfig(keyId1, seed1);
    const keyConfig2 = new DeterministicKeyConfig(keyId2, seed2);
    
    // Get their encoded forms (already length-prefixed)
    const config1 = await (await keyConfig1.publicConfig()).encode();
    const config2 = await (await keyConfig2.publicConfig()).encode();
    
    // Concatenate them
    const configList = new Uint8Array([...config1, ...config2]);
    
    // First config should be usable
    const constructor = new ClientConstructor();
    const client = await constructor.clientForConfig(configList);
    
    // Verify with round trip using first server
    const server = new Server(keyConfig1);
    const testData = new TextEncoder().encode("test");
    const requestContext = await client.encapsulate(testData);
    const responseContext = await server.decapsulate(requestContext.request);
    expect(responseContext.encodedRequest).toEqual(testData);
  });

  it("rejects configs without length prefix", async () => {
    const keyId = 0x01;
    const config = new KeyConfig(keyId);
    const publicConfig = await config.publicConfig();
    
    // Create raw bytes without length prefix
    const preamble = new Uint8Array([
      publicConfig.keyId & 0xFF,
      (publicConfig.kem >> 8) & 0xFF,
      publicConfig.kem & 0xFF,
    ]);
    const encodedKey = new Uint8Array(
      await publicConfig.suite.kem.serializePublicKey(publicConfig.publicKey)
    );
    const algorithms = new Uint8Array([0x00, 0x04, 0x00, 0x01, 0x00, 0x01]);
    const rawConfig = new Uint8Array([
      ...preamble,
      ...encodedKey,
      ...algorithms
    ]);
    
    const constructor = new ClientConstructor();
    await expect(constructor.clientForConfig(rawConfig))
      .rejects
      .toThrow(InvalidEncodingError);
  });
});

describe("error cases", () => {
  it("rejects invalid KEM ID", async () => {
    const keyId = 0x01;
    const keyConfig = new KeyConfig(keyId);
    const publicConfig = await keyConfig.publicConfig();
    const validConfig = await publicConfig.encode();
    
    // Corrupt the KEM ID (bytes 3-4 after length prefix)
    const invalidConfig = new Uint8Array(validConfig);
    invalidConfig[3] = 0xFF;  // Invalid KEM ID
    invalidConfig[4] = 0xFF;

    const constructor = new ClientConstructor();
    await expect(constructor.clientForConfig(invalidConfig))
      .rejects
      .toThrow();
  });

  it("rejects invalid KDF ID", async () => {
    const keyId = 0x01;
    const keyConfig = new KeyConfig(keyId);
    const publicConfig = await keyConfig.publicConfig();
    const validConfig = await publicConfig.encode();
    
    // Find offset of symmetric algorithms (after public key)
    const publicKeySize = publicConfig.suite.kem.publicKeySize;
    const symAlgoOffset = 2 + 3 + publicKeySize + 2;  // length prefix + preamble + pubkey + length
    
    // Corrupt the KDF ID
    const invalidConfig = new Uint8Array(validConfig);
    invalidConfig[symAlgoOffset] = 0xFF;  // Invalid KDF ID
    invalidConfig[symAlgoOffset + 1] = 0xFF;

    const constructor = new ClientConstructor();
    await expect(constructor.clientForConfig(invalidConfig))
      .rejects
      .toThrow();
  });

  it("rejects invalid AEAD ID", async () => {
    const keyId = 0x01;
    const keyConfig = new KeyConfig(keyId);
    const publicConfig = await keyConfig.publicConfig();
    const validConfig = await publicConfig.encode();
    
    // Find offset of AEAD ID
    const publicKeySize = publicConfig.suite.kem.publicKeySize;
    const aeadOffset = 2 + 3 + publicKeySize + 2 + 2;  // length prefix + preamble + pubkey + length + KDF
    
    // Corrupt the AEAD ID
    const invalidConfig = new Uint8Array(validConfig);
    invalidConfig[aeadOffset] = 0xFF;
    invalidConfig[aeadOffset + 1] = 0xFF;

    const constructor = new ClientConstructor();
    await expect(constructor.clientForConfig(invalidConfig))
      .rejects
      .toThrow();
  });

  it("rejects truncated public key", async () => {
    const keyId = 0x01;
    const keyConfig = new KeyConfig(keyId);
    const publicConfig = await keyConfig.publicConfig();
    const validConfig = await publicConfig.encode();
    
    // Truncate the config right after KEM ID
    const truncatedConfig = validConfig.slice(0, 5);  // length prefix + keyId + KEM ID

    const constructor = new ClientConstructor();
    await expect(constructor.clientForConfig(truncatedConfig))
      .rejects
      .toThrow(InvalidEncodingError);
  });

  it("rejects multiple KDF/AEAD pairs", async () => {
    const keyId = 0x01;
    const keyConfig = new KeyConfig(keyId);
    const publicConfig = await keyConfig.publicConfig();
    const validConfig = await publicConfig.encode();
    
    // Find where symmetric algorithms length is stored
    const publicKeySize = publicConfig.suite.kem.publicKeySize;
    const symAlgoLengthOffset = 2 + 3 + publicKeySize;
    
    // Modify length to indicate multiple pairs (8 bytes instead of 4)
    const invalidConfig = new Uint8Array(validConfig);
    invalidConfig[symAlgoLengthOffset] = 0x00;
    invalidConfig[symAlgoLengthOffset + 1] = 0x08;  // Double the normal length

    const constructor = new ClientConstructor();
    await expect(constructor.clientForConfig(invalidConfig))
      .rejects
      .toThrow(/only supports exactly one KDF\/AEAD pair/);
  });

  it("rejects invalid content type in request", async () => {
    const keyId = 0x01;
    const keyConfig = new KeyConfig(keyId);
    const server = new Server(keyConfig);

    const invalidRequest = new Request("https://example.com", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"  // Wrong content type
      }
    });

    await expect(server.decapsulateRequest(invalidRequest))
      .rejects
      .toThrow(InvalidContentTypeError);
  });

  it("rejects invalid content type in response", async () => {
    const keyId = 0x01;
    const keyConfig = new KeyConfig(keyId);
    const publicConfig = await keyConfig.publicConfig();
    
    const client = new Client(publicConfig);
    const requestContext = await client.encapsulate(new TextEncoder().encode("test"));

    const invalidResponse = new Response("test", {
      headers: {
        "Content-Type": "text/plain"  // Wrong content type
      }
    });

    await expect(requestContext.decapsulateResponse(invalidResponse))
      .rejects
      .toThrow(InvalidContentTypeError);
  });
});