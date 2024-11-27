import { loadCrypto } from "./webCrypto.js";
import { concatArrays, i2Osp, max } from "./utils.js";
import {
  InvalidConfigIdError,
  InvalidContentTypeError,
  InvalidEncodingError,
  InvalidHpkeCiphersuiteError,
} from "./errors.js";
import { AeadId, CipherSuite, KdfId, KemId } from "hpke-js";
import { BHttpDecoder, BHttpEncoder } from "@dajiaji/bhttp";

const invalidEncodingErrorString = "Invalid message encoding";
const invalidKeyIdErrorString = "Invalid configuration ID";
const invalidHpkeCiphersuiteErrorString = "Invalid HPKE ciphersuite";
const invalidContentTypeErrorString = "Invalid content type";

const requestInfoLabel = "message/bhttp request";
const responseInfoLabel = "message/bhttp response";
const aeadKeyLabel = "key";
const aeadNonceLabel = "nonce";
const requestHdrLength = 7; // len(keyID) + len(kemID) + len(kdfID) + len(aeadID)

async function randomBytes(l: number): Promise<Uint8Array> {
  const buffer = new Uint8Array(l);
  const cryptoApi = await loadCrypto();
  cryptoApi.getRandomValues(buffer);
  return buffer;
}

function checkHpkeCiphersuite(kem: KemId, kdf: KdfId, aead: AeadId) {
  if (
    kem !== KemId.DhkemX25519HkdfSha256 ||
    kdf !== KdfId.HkdfSha256 ||
    aead !== AeadId.Aes128Gcm
  ) {
    throw new InvalidHpkeCiphersuiteError(invalidHpkeCiphersuiteErrorString);
  }
}

function encodeSymmetricAlgorithms(kdf: KdfId, aead: AeadId): Uint8Array {
  return new Uint8Array([
    0x00,
    0x04, // Length
    (kdf >> 8) & 0xFF,
    kdf & 0xFF,
    (aead >> 8) & 0xFF,
    aead & 0xFF,
  ]);
}

export class KeyConfig {
  public keyId: number;
  public kem: KemId;
  public kdf: KdfId;
  public aead: AeadId;
  public keyPair: Promise<CryptoKeyPair>;

  constructor(keyId: number) {
    if (keyId < 0 || keyId > 255) {
      throw new InvalidConfigIdError(invalidKeyIdErrorString);
    }
    this.keyId = keyId;
    this.kem = KemId.DhkemX25519HkdfSha256;
    this.kdf = KdfId.HkdfSha256;
    this.aead = AeadId.Aes128Gcm;
    const suite = new CipherSuite({
      kem: this.kem,
      kdf: this.kdf,
      aead: this.aead,
    });
    this.keyPair = suite.generateKeyPair();
  }

  async publicConfig(): Promise<PublicKeyConfig> {
    const publicKey = (await this.keyPair).publicKey;
    return new PublicKeyConfig(
      this.keyId,
      this.kem,
      this.kdf,
      this.aead,
      publicKey,
    );
  }
}

export class DeterministicKeyConfig extends KeyConfig {
  constructor(keyId: number, ikm: Uint8Array) {
    super(keyId);
    if (keyId < 0 || keyId > 255) {
      throw new InvalidConfigIdError(invalidKeyIdErrorString);
    }
    this.keyId = keyId;
    this.kem = KemId.DhkemX25519HkdfSha256;
    this.kdf = KdfId.HkdfSha256;
    this.aead = AeadId.Aes128Gcm;
    const suite = new CipherSuite({
      kem: this.kem,
      kdf: this.kdf,
      aead: this.aead,
    });
    this.keyPair = suite.deriveKeyPair(ikm.buffer as ArrayBuffer);
  }
}

export class PublicKeyConfig {
  public keyId: number;
  public kem: KemId;
  public kdf: KdfId;
  public aead: AeadId;
  public suite: CipherSuite;
  public publicKey: CryptoKey;

  constructor(
    keyId: number,
    kem: KemId,
    kdf: KdfId,
    aead: AeadId,
    publicKey: CryptoKey,
  ) {
    if (keyId < 0 || keyId > 255) {
      throw new InvalidConfigIdError(invalidKeyIdErrorString);
    }
    this.keyId = keyId;

    checkHpkeCiphersuite(kem, kdf, aead);
    this.kem = kem;
    this.kdf = kdf;
    this.aead = aead;
    this.suite = new CipherSuite({
      kem: this.kem,
      kdf: this.kdf,
      aead: this.aead,
    });

    this.publicKey = publicKey;
  }

  async encode(): Promise<Uint8Array> {
    const preamble = new Uint8Array([
      this.keyId & 0xFF,
      (this.kem >> 8) & 0xFF,
      this.kem & 0xFF,
    ]);
    const encodedKey = new Uint8Array(
      await this.suite.kem.serializePublicKey(
        this.publicKey,
      ),
    );
    const algorithms = encodeSymmetricAlgorithms(
      this.kdf,
      this.aead,
    );
    return concatArrays(concatArrays(preamble, encodedKey), algorithms);
  }

  async encodeAsList(): Promise<Uint8Array> {
    const encodedConfig = await this.encode();
    return concatArrays(
      new Uint8Array([
        (encodedConfig.length >> 8) & 0xff,
        encodedConfig.length & 0xff,
      ]),
      encodedConfig
    );
  }
}

export class ServerResponse {
  public readonly responseNonce: Uint8Array;
  public readonly encResponse: Uint8Array;

  constructor(responseNonce: Uint8Array, encResponse: Uint8Array) {
    this.responseNonce = responseNonce;
    this.encResponse = encResponse;
  }

  encode(): Uint8Array {
    return concatArrays(this.responseNonce, this.encResponse);
  }
}

export class ServerResponseContext {
  public readonly encodedRequest: Uint8Array;
  private enc: Uint8Array;
  private secret: Uint8Array;
  private suite: CipherSuite;

  constructor(
    suite: CipherSuite,
    request: Uint8Array,
    secret: Uint8Array,
    enc: Uint8Array,
  ) {
    this.encodedRequest = request;
    this.enc = enc;
    this.secret = secret;
    this.suite = suite;
  }

  async encapsulate(encodedResponse: Uint8Array): Promise<ServerResponse> {
    const responseNonce = await randomBytes(
      max(this.suite.aead.keySize, this.suite.aead.nonceSize),
    );
    const salt = concatArrays(new Uint8Array(this.enc), responseNonce);

    const kdf = this.suite.kdf;
    const prk = await kdf.extract(salt.buffer as ArrayBuffer, this.secret.buffer as ArrayBuffer);
    const aeadKey = await kdf.expand(
      prk,
      new TextEncoder().encode(aeadKeyLabel).buffer as ArrayBuffer,
      this.suite.aead.keySize,
    );
    const aeadNonce = await kdf.expand(
      prk,
      new TextEncoder().encode(aeadNonceLabel).buffer as ArrayBuffer,
      this.suite.aead.nonceSize,
    );

    const aeadKeyS = this.suite.aead.createEncryptionContext(aeadKey);
    const encResponse = new Uint8Array(
      await aeadKeyS.seal(
        aeadNonce,
        encodedResponse.buffer as ArrayBuffer,
        new TextEncoder().encode("").buffer as ArrayBuffer,
      ),
    );

    return new ServerResponse(responseNonce, encResponse);
  }

  async encapsulateResponse(response: Response): Promise<Response> {
    const encoder = new BHttpEncoder();
    const encodedResponse = await encoder.encodeResponse(response);

    const serverResponse = await this.encapsulate(encodedResponse);
    return new Response(serverResponse.encode(), {
      status: 200,
      headers: {
        "Content-Type": "message/ohttp-res",
      },
    });
  }

  request(): Request {
    const decoder = new BHttpDecoder();
    return decoder.decodeRequest(this.encodedRequest);
  }
}

export class Server {
  private config: KeyConfig;

  constructor(config: KeyConfig) {
    this.config = config;
  }

  async decapsulate(
    clientRequest: ClientRequest,
  ): Promise<ServerResponseContext> {
    let info = new Uint8Array(new TextEncoder().encode(requestInfoLabel));
    info = concatArrays(info, new Uint8Array([0x00]));
    info = concatArrays(info, clientRequest.hdr);

    const recipientKeyPair = await this.config.keyPair;
    const recipient = await clientRequest.suite.createRecipientContext({
      recipientKey: recipientKeyPair,
      enc: clientRequest.enc.buffer as ArrayBuffer,
      info: info.buffer as ArrayBuffer,
    });

    const request = new Uint8Array(
      await recipient.open(clientRequest.encapsulatedReq.buffer as ArrayBuffer),
    );

    const exportContext = new TextEncoder().encode(responseInfoLabel);
    const secret = new Uint8Array(
      await recipient.export(exportContext.buffer as ArrayBuffer, clientRequest.suite.aead.keySize),
    );

    return new ServerResponseContext(
      clientRequest.suite,
      request,
      secret,
      clientRequest.enc,
    );
  }

  async decodeAndDecapsulate(msg: Uint8Array): Promise<ServerResponseContext> {
    if (msg.length < requestHdrLength) {
      throw new InvalidEncodingError(invalidEncodingErrorString);
    }
    const hdr = msg.slice(0, requestHdrLength);
    const keyId = hdr[0];
    const kemId = ((hdr[1] << 0xFF) | hdr[2]) as KemId;
    const kdfId = ((hdr[3] << 0xFF) | hdr[4]) as KdfId;
    const aeadId = ((hdr[5] << 0xFF) | hdr[6]) as AeadId;

    if (keyId != this.config.keyId) {
      throw new InvalidConfigIdError(invalidKeyIdErrorString);
    }
    checkHpkeCiphersuite(kemId, kdfId, aeadId);
    
    const suite = new CipherSuite({
      kem: kemId,
      kdf: kdfId,
      aead: aeadId,
    });
    
    const encSize = suite.kem.encSize;
    if (msg.length < requestHdrLength+encSize) {
      throw new InvalidEncodingError(invalidEncodingErrorString);
    }
    const enc = msg.slice(requestHdrLength, requestHdrLength+encSize);
    
    const encRequest = msg.slice(requestHdrLength+encSize, msg.length);
    return await this.decapsulate(new ClientRequest(suite, hdr, enc, encRequest));
  }

  async decapsulateRequest(request: Request): Promise<ServerResponseContext> {
    const { headers } = request;
    const contentType = headers.get("content-type");
    if (contentType != "message/ohttp-req") {
      throw new InvalidContentTypeError(invalidContentTypeErrorString);
    }

    const encapRequestBody = new Uint8Array(await request.arrayBuffer());
    return this.decodeAndDecapsulate(encapRequestBody);
  }

  async encodeKeyConfig(): Promise<Uint8Array> {
    const publicConfig = await this.config.publicConfig();
    return publicConfig.encode();
  }

  async encodeKeyConfigAsList(): Promise<Uint8Array> {
    const config = await this.config.publicConfig();
    return config.encodeAsList();
  }
}

export class ClientConstructor {
  private async parseKeyConfig(config: Uint8Array): Promise<PublicKeyConfig> {
    const keyId = config[0];
    const kemId = ((config[1] << 8) | config[2]) as KemId;
    
    // Create temp suite to get public key size
    const tempSuite = new CipherSuite({
      kem: kemId,
      kdf: KdfId.HkdfSha256,  // Placeholder
      aead: AeadId.Aes128Gcm, // Placeholder
    });
    const publicKeySize = tempSuite.kem.publicKeySize;
    
    const publicKeyBytes = config.slice(3, 3 + publicKeySize);
    
    // After public key, expect length of symmetric algorithms
    const offset = 3 + publicKeySize;
    const symAlgosLength = (config[offset] << 8) | config[offset + 1];
    
    if (offset + 2 + symAlgosLength > config.length) {
      throw new InvalidEncodingError('Invalid symmetric algorithms length');
    }

    // Read first KDF/AEAD pair
    const kdfId = ((config[offset + 2] << 8) | config[offset + 3]) as KdfId;
    const aeadId = ((config[offset + 4] << 8) | config[offset + 5]) as AeadId;

    // Create final suite and deserialize public key
    const suite = new CipherSuite({
      kem: kemId,
      kdf: kdfId,
      aead: aeadId,
    });

    const publicKey = await suite.kem.deserializePublicKey(publicKeyBytes.buffer as ArrayBuffer);

    return new PublicKeyConfig(
      keyId,
      kemId,
      kdfId,
      aeadId,
      publicKey,
    );
  }

  private async parseKeyConfigList(configList: Uint8Array): Promise<PublicKeyConfig> {
    let offset = 0;
    
    // Try to parse as a length-prefixed list first
    while (offset + 2 <= configList.length) {
      const configLength = (configList[offset] << 8) | configList[offset + 1];
      offset += 2;

      if (offset + configLength > configList.length) {
        // If parsing as list fails, try as single config
        return await this.parseKeyConfig(configList);
      }

      try {
        const config = configList.slice(offset, offset + configLength);
        return await this.parseKeyConfig(config);
      } catch (e) {
        // If first config fails, try next one
        offset += configLength;
        continue;
      }
    }

    // If we couldn't parse as list, try as single config
    return await this.parseKeyConfig(configList);
  }

  async clientForConfig(configList: Uint8Array): Promise<Client> {
    try {
      const config = await this.parseKeyConfigList(configList);
      return new Client(config);
    } catch (e) {
      throw new InvalidEncodingError('Failed to parse key configuration');
    }
  }
}

export class Client {
  private config: PublicKeyConfig;
  private suite: CipherSuite;

  constructor(config: PublicKeyConfig) {
    this.config = config;
    this.suite = new CipherSuite({
      kem: this.config.kem,
      kdf: this.config.kdf,
      aead: this.config.aead,
    });
  }

  async encapsulate(encodedRequest: Uint8Array): Promise<ClientRequestContext> {
    let hdr = new Uint8Array([this.config.keyId]);
    hdr = concatArrays(hdr, i2Osp(this.suite.kem.id, 2));
    hdr = concatArrays(hdr, i2Osp(this.suite.kdf.id, 2));
    hdr = concatArrays(hdr, i2Osp(this.suite.aead.id, 2));

    let info = new Uint8Array(new TextEncoder().encode(requestInfoLabel));
    info = concatArrays(info, new Uint8Array([0x00]));
    info = concatArrays(info, hdr);

    const publicKey = this.config.publicKey;
    const sender = await this.suite.createSenderContext({
      recipientPublicKey: publicKey,
      info: info.buffer as ArrayBuffer,
    });

    const encRequest = new Uint8Array(await sender.seal(encodedRequest.buffer as ArrayBuffer));
    const enc = new Uint8Array(sender.enc);
    const exportContext = new TextEncoder().encode(responseInfoLabel);
    const secret = new Uint8Array(
      await sender.export(exportContext.buffer as ArrayBuffer, this.suite.aead.keySize),
    );
    const clientRequest = new ClientRequestContext(
      this.suite,
      hdr,
      enc,
      encRequest,
      secret,
    );

    return clientRequest;
  }

  async encapsulateRequest(
    originalRequest: Request,
  ): Promise<ClientRequestContext> {
    const encoder = new BHttpEncoder();
    const encodedRequest = await encoder.encodeRequest(originalRequest);
    const encapRequestContext = await this.encapsulate(encodedRequest);
    return encapRequestContext;
  }
}

class ClientRequest {
  public readonly suite: CipherSuite;
  public readonly hdr: Uint8Array;
  public readonly enc: Uint8Array;
  public readonly encapsulatedReq: Uint8Array;

  constructor(suite: CipherSuite, hdr: Uint8Array, enc: Uint8Array, encapsulatedReq: Uint8Array) {
    this.suite = suite;
    this.hdr = hdr;
    this.enc = enc;
    this.encapsulatedReq = encapsulatedReq;
  }

  encode(): Uint8Array {
    var prefix = concatArrays(this.hdr, this.enc);
    return concatArrays(prefix, this.encapsulatedReq);
  }

  request(relayUrl: string): Request {
    const encapsulatedRequest = this.encode();
    return new Request(relayUrl, {
      method: "POST",
      body: encapsulatedRequest,
      headers: {
        "Content-Type": "message/ohttp-req",
      },
    });
  }
}

class ClientRequestContext {
  public readonly request: ClientRequest;
  private secret: Uint8Array;
  private suite: CipherSuite;

  constructor(
    suite: CipherSuite,
    hdr: Uint8Array,
    enc: Uint8Array,
    encapsulatedReq: Uint8Array,
    secret: Uint8Array,
  ) {
    this.request = new ClientRequest(suite, hdr, enc, encapsulatedReq);
    this.secret = secret;
    this.suite = suite;
  }

  async decapsulate(serverResponse: ServerResponse): Promise<Uint8Array> {
    const senderEnc = new Uint8Array(
      this.request.enc.buffer as ArrayBuffer,
      0,
      this.request.enc.length,
    );
    const salt = concatArrays(senderEnc, serverResponse.responseNonce);

    const kdf = this.suite.kdf;
    const prk = await kdf.extract(salt.buffer as ArrayBuffer, this.secret.buffer as ArrayBuffer);
    const aeadKey = await kdf.expand(
      prk,
      new TextEncoder().encode(aeadKeyLabel).buffer as ArrayBuffer,
      this.suite.aead.keySize,
    );
    const aeadNonce = await kdf.expand(
      prk,
      new TextEncoder().encode(aeadNonceLabel).buffer as ArrayBuffer,
      this.suite.aead.nonceSize,
    );

    const aeadKeyS = this.suite.aead.createEncryptionContext(aeadKey);
    const request = new Uint8Array(
      await aeadKeyS.open(
        aeadNonce,
        serverResponse.encResponse.buffer as ArrayBuffer,
        new TextEncoder().encode("").buffer as ArrayBuffer,
      ),
    );

    return request;
  }

  async decodeAndDecapsulate(msg: Uint8Array): Promise<Uint8Array> {
    const responseNonceLen = max(
      this.suite.aead.keySize,
      this.suite.aead.nonceSize,
    );
    const responseNonce = msg.slice(0, responseNonceLen);
    const encResponse = msg.slice(responseNonceLen, msg.length);
    return await this.decapsulate(
      new ServerResponse(responseNonce, encResponse),
    );
  }

  async decapsulateResponse(response: Response): Promise<Response> {
    const { headers } = response;
    const contentType = headers.get("content-type");
    if (contentType != "message/ohttp-res") {
      throw new InvalidContentTypeError(invalidContentTypeErrorString);
    }

    const encapResponseBody = new Uint8Array(await response.arrayBuffer());
    const encodedResponse = await this.decodeAndDecapsulate(encapResponseBody);

    const decoder = new BHttpDecoder();
    return decoder.decodeResponse(encodedResponse);
  }
}
