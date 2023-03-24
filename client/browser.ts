import ThresholdKey from "@tkey/core";
import { TorusServiceProvider } from "@tkey/service-provider-torus";
import { ShareSerializationModule } from "@tkey/share-serialization";
import { TorusStorageLayer } from "@tkey/storage-layer-torus";
import { getPubKeyPoint, ShareStore, TkeyError } from "@tkey/common-types";
import { generatePrivate } from "@toruslabs/eccrypto";
import BN from "bn.js";
import * as tss from "@toruslabs/tss-lib";
import { Client, utils } from "@toruslabs/tss-client";
const { generateEndpoints, getDKLSCoeff, setupSockets } = utils;
import { ec as EC } from "elliptic";
import keccak256 from "keccak256";
import { TorusLoginResponse } from "@toruslabs/customauth";
import { EthereumSigningProvider } from "@web3auth-mpc/ethereum-provider";
import Web3 from "web3";

const ec = new EC("secp256k1");

const tssImportUrl = "https://sapphire-dev-2-2.authnetwork.dev/tss/v1/clientWasm";

const DELIMITERS = {
  Delimiter1: "\u001c",
  Delimiter2: "\u0015",
  Delimiter3: "\u0016",
  Delimiter4: "\u0017",
};


const get = (key: string) => {
  return localStorage.getItem(key)
}

const set = (key: string, value: string) => {
  localStorage.setItem(key, value)
}

export class MpcLoginProvider {
  public tKey: ThresholdKey;

  public ethereumSigningProvider: EthereumSigningProvider;

  constructor() {
    this.ethereumSigningProvider = new EthereumSigningProvider({
      config: {
        /*
                      pass the chain config that you want to connect with
                      all chainConfig fields are required.
                      */
        chainConfig: {
          chainId: "0x5",
          rpcTarget: "https://rpc.ankr.com/eth_goerli",
          displayName: "Goerli Testnet",
          blockExplorer: "https://goerli.etherscan.io",
          ticker: "ETH",
          tickerName: "Ethereum",
        },
      },
    });
    // Authentication configs
    const torusSp = new TorusServiceProvider({
      useTSS: true,
      customAuthArgs: {
        baseUrl: `${window.location.origin}`,
        enableLogging: true,
      },
    });

    // Encrypted storage configs
    const storageLayer = new TorusStorageLayer({
      hostUrl: "https://sapphire-dev-2-1.authnetwork.dev/metadata",
      enableLogging: true,
    });

    // TKey
    const tKey = new ThresholdKey({
      enableLogging: true,
      modules: {
        shareSerialization: new ShareSerializationModule(),
      },
      serviceProvider: torusSp,
      storageLayer,
      manualSync: true,
    });

    this.tKey = tKey

  }
  async remoteSet (factorKey, metadataToSet) {
    await this.tKey.addLocalMetadataTransitions({
      input: [{ message: JSON.stringify(metadataToSet) }],
      privKey: [factorKey],
    });
    await this.tKey.syncLocalMetadataTransitions();
  }

  async remoteGet (factorKey) {
    const metadata = await this.tKey.storageLayer.getMetadata<{ message: string }>({
      privKey: factorKey,
    });
    return JSON.parse(metadata.message)
  }

  async init() {
    // Initialize service provider
    await (this.tKey.serviceProvider as TorusServiceProvider).init({});
  }


  // Register webauthn
  async triggerRegister() {
    await (this.tKey.serviceProvider as TorusServiceProvider).triggerLogin({
      typeOfLogin: "webauthn",
      verifier: "webauthntest",
      clientId: "webauthn",
      customState: {
        client: "great-company",
        webauthnURL: "https://peaceful-beach-75487.herokuapp.com/?register_only=true",
        localhostAll: "true",
        webauthnTransports: "ble",
        credTransports: "ble",
      },
    });
    return true;
  }

   // Login webauthn
   async triggerLogin () {
    const loginResponse = await (this.tKey.serviceProvider as TorusServiceProvider).triggerLogin({
      typeOfLogin: "webauthn",
      verifier: "webauthntest",
      clientId: "webauthn",
      customState: {
        client: "great-company",
        webauthnURL: "https://peaceful-beach-75487.herokuapp.com/",
        localhostAll: "true",
        loginOnly: "true",
        webauthnTransports: "ble",
        credTransports: "ble",
      },
    });
    console.log("loginResponse", loginResponse);
    set('loginResponse', JSON.stringify(loginResponse));
  }

  // Create or get device factor key, stored in localStorage
  getDeviceFactorKey () {
    if (!get('factorKey')) {
      set('factorKey', new BN(generatePrivate()).toString(16, 64))
    }
    return new BN(get('factorKey'), 'hex')
  }

  // Initialize TKey (must call triggerLogin first)
  async initializeTkey() {
    const deviceFactorKey = this.getDeviceFactorKey();
    const factorPub = getPubKeyPoint(deviceFactorKey);
    await this.tKey.initialize({
      useTSS: true,
      factorPub,
    });
    let deviceShare;
    try {
      deviceShare = await this.remoteGet(deviceFactorKey)
      if (deviceShare) {
        await this.tKey.inputShareStoreSafe(deviceShare, false);
      }
    } catch (e) {
      console.log(`error ${e}`)
    }
    
    await this.tKey.reconstructKey();
    const polyId = this.tKey.metadata.getLatestPublicPolynomial().getPolynomialID();
    const shares = this.tKey.shares[polyId];
    for (const shareIndex in shares) {
      if (shareIndex !== '1') {
        deviceShare = shares[shareIndex];
      }
    }
    await this.remoteSet(deviceFactorKey, deviceShare)
  }

  // Retrieve TSS share for device
  async getDeviceTSSShare() {
    return this.tKey.getTSSShare(this.getDeviceFactorKey());
  }

  async sign(msgHashBuffer: Buffer) {
    if (!msgHashBuffer) throw new Error("msgHashHex not provided")
    const msgHashHex = keccak256(msgHashBuffer).toString("hex");
    // get auth signatures from loginResponse (must call triggerLogin first)
    const loginResponse = get('loginResponse');
    if (!loginResponse) {
      throw new Error("Please call triggerLogin first");
    }
    const { signatures , userInfo } = JSON.parse(loginResponse) as TorusLoginResponse;
    const { tssShare, tssIndex } = await this.getDeviceTSSShare();
    
    const parties = 4;
    const clientIndex = parties - 1;
    // generate endpoints for servers
    const { endpoints, tssWSEndpoints, partyIndexes } = generateEndpoints(parties, clientIndex);
    const [sockets] = await Promise.all([
      setupSockets(tssWSEndpoints),
      tss.default(tssImportUrl),
    ]);

    const tssNonce = this.tKey.metadata.tssNonces[this.tKey.tssTag];
    const tssPubKey = this.tKey.getTSSPub();
    const pubKey = Buffer.from(
      `${tssPubKey.x.toString(16, 64)}${tssPubKey.y.toString(16, 64)}`,
      'hex',
    ).toString('base64');
    const participatingServerDKGIndexes = [1, 2, 3]; // can be randomized, or only pick servers that are online
    const dklsCoeff = getDKLSCoeff(true, participatingServerDKGIndexes, tssIndex);
    const denormalisedShare = dklsCoeff.mul(tssShare).umod(ec.curve.n);
    const share = Buffer.from(denormalisedShare.toString(16, 64), 'hex').toString('base64');
    const serverCoeffs = {};
    for (let i = 0; i < participatingServerDKGIndexes.length; i++) {
      const serverIndex = participatingServerDKGIndexes[i];
      serverCoeffs[serverIndex] = getDKLSCoeff(
        false,
        participatingServerDKGIndexes,
        tssIndex,
        serverIndex,
      ).toString('hex');
    }

    const verifier = userInfo.verifier;
    const verifierId = userInfo.verifierId;
    const randomSessionNonce = keccak256(generatePrivate().toString("hex") + Date.now());
    const vid = `${verifier}${DELIMITERS.Delimiter1}${verifierId}`;
  
    const session = `${vid}${DELIMITERS.Delimiter2}default${DELIMITERS.Delimiter3}${tssNonce}${
      DELIMITERS.Delimiter4
      }${randomSessionNonce.toString("hex")}`;

    const client = new Client(
      session,
      clientIndex,
      partyIndexes,
      endpoints,
      sockets,
      share,
      pubKey,
      true,
      tssImportUrl,
    );
    client.log = window.console.log

    client.precompute(tss, { signatures, server_coeffs: serverCoeffs });
    await client.ready();
    const msgHashBase64 = Buffer.from(msgHashHex, 'hex').toString('base64');
    const signature = await client.sign(tss, msgHashBase64, true, msgHashHex, 'keccak256', {
      signatures,
    });

    const pubk = ec.recoverPubKey(new BN(msgHashHex, "hex"), signature, signature.recoveryParam, "hex");
    const passed = ec.verify(msgHashHex, signature, pubk);
    await client.cleanup(tss, { signatures });
    if (!passed) {
      throw new Error('invalid signature')
    }
    return { v:  signature.recoveryParam, r: Buffer.from(signature.r.toString("hex"), "hex"), s: Buffer.from(signature.s.toString("hex"), "hex") };
  }

  // Reset account, for testing purposes
  async resetAccount() {
    await this.tKey.storageLayer.setMetadata({
      privKey: (this.tKey.serviceProvider as TorusServiceProvider).postboxKey,
      input: { message: "KEY_NOT_FOUND" },
    });
    window.location.reload();
  }

  async getWeb3Instance() {
    const tssPubKey =  this.tKey.getTSSPub();
    const compressedTSSPubKey = Buffer.from(`${tssPubKey.x.toString(16, 64)}${tssPubKey.y.toString(16, 64)}`, "hex");

    if (!tssPubKey) {
      throw new Error("Please login first")
    }
    await this.ethereumSigningProvider.setupProvider({ sign: this.sign.bind(this), getPublic: () => compressedTSSPubKey  });
    console.log(this.ethereumSigningProvider.provider);
    const web3 = new Web3(this.ethereumSigningProvider.provider as any);
    return web3;
  }

   async getAccounts() {
     const web3 = await this.getWeb3Instance();
    const address = (await web3.eth.getAccounts())[0];
    return address;
  };

  async signTransaction() {
    const web3 = await this.getWeb3Instance();
    const fromAddress = await this.getAccounts()
    const amount = web3.utils.toWei("0.0001"); // Convert 1 ether to wei

    const signedTx = await web3.eth.signTransaction({
      from: fromAddress,
      to: fromAddress,
      value: amount,
    })
    return signedTx;
  };
  
}


(async function () {
  const mpcProvider = new MpcLoginProvider();
  await mpcProvider.init();
  (window as any).mpcProvider = mpcProvider
})();