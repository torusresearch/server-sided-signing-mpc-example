import ThresholdKey from "@tkey/core";
import { TorusServiceProvider } from "@tkey/service-provider-torus";
import { ShareSerializationModule } from "@tkey/share-serialization";
import { TorusStorageLayer } from "@tkey/storage-layer-torus";
import { ecPoint, getPubKeyPoint, hexPoint, Point, ShareStore, TkeyError } from "@tkey/common-types";
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
import { addFactorPub, copyFactorPub } from "../rss"

enum SIGNING_MODE {
  BROWSER,
  SERVER,
}

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
  public mode: SIGNING_MODE;

  public tKey: ThresholdKey;

  public ethereumSigningProvider: EthereumSigningProvider;

  constructor() {
    this.mode =  SIGNING_MODE.SERVER;
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
    const d = new BN(get('factorKey'), 'hex');
    console.log("device factor key", d);
    return d
  }

  async sign(msgHashBuffer: Buffer) {
    const signature = await this.thirdPartyTSSServerSign(msgHashBuffer);
    return { v: signature.v, r: Buffer.from(signature.r.padStart(64, "0"), "hex"), s: Buffer.from(signature.s.padStart(64, "0"), "hex")}
  }

  // Initialize TKey (must call triggerLogin first)
  async initializeTkey() {
    const deviceFactorKey = this.getDeviceFactorKey();
    const serverFactorPubHex = await fetch("http://localhost:3000/factorPub").then(res => res.json()).then(res => res.factorPub)
    const serverFactorPub = new Point(serverFactorPubHex.x, serverFactorPubHex.y);
    await this.tKey.initialize({
      useTSS: true,
      factorPub: serverFactorPub,
    });
    let tkeyInput;
    try {
      tkeyInput = await this.remoteGet(deviceFactorKey)
      if (tkeyInput) {
        await this.tKey.inputShareStoreSafe(tkeyInput, false);
      }
    } catch (e) {
      console.log(`error ${e}`)
    }
    
    await this.tKey.reconstructKey();
    const polyId = this.tKey.metadata.getLatestPublicPolynomial().getPolynomialID();
    const shares = this.tKey.shares[polyId];
    for (const shareIndex in shares) {
      if (shareIndex !== '1') {
        tkeyInput = shares[shareIndex];
      }
    }
    await this.remoteSet(deviceFactorKey, tkeyInput)
  }

  // Reset account, for testing purposes
  async resetAccount() {
    await this.tKey.storageLayer.setMetadata({
      privKey: (this.tKey.serviceProvider as TorusServiceProvider).postboxKey,
      input: { message: "KEY_NOT_FOUND" },
    });
    window.localStorage.clear();
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
    console.log("address", address)
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
    console.log("signedTx", signedTx);
    return signedTx;
  };

  async thirdPartyTSSServerSign(msgHashBuffer: Buffer) {
    const serverFactorPubHex = await fetch("http://localhost:3000/factorPub").then(res => res.json()).then(res => res.factorPub)
    const serverFactorPub = new Point(serverFactorPubHex.x, serverFactorPubHex.y);
    const loginResponse = get('loginResponse');
    const { signatures , userInfo } = JSON.parse(loginResponse) as TorusLoginResponse;
    const response = await fetch("http://localhost:3000/sign", {
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      method: "POST",
      body: JSON.stringify({
        msgHash: msgHashBuffer.toString("hex"),
        vid: this.tKey.serviceProvider.getVerifierNameVerifierId(),
        tssNonce: this.tKey.metadata.tssNonces[this.tKey.tssTag],
        tssPubKey: this.tKey.getTSSPub(),
        signatures,
        factorEncs: this.tKey.getFactorEncs(serverFactorPub),
        tssCommits: this.tKey.getTSSCommits(),
      })
    }).then(res => res.json());
    console.log("thirdPartyTSSServerSign", response);
    return response;
  }
  
}

(async function () {
  const mpcProvider = new MpcLoginProvider();
  await mpcProvider.init();
  (window as any).mpcProvider = mpcProvider
})();