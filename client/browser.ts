import ThresholdKey from "@tkey-mpc/core";
import TorusUtils from "@toruslabs/torus.js";
import { TorusServiceProvider } from "@tkey-mpc/service-provider-torus";
import { ShareSerializationModule } from "@tkey-mpc/share-serialization";
import { TorusStorageLayer } from "@tkey-mpc/storage-layer-torus";
import { getPubKeyPoint, Point } from "@tkey-mpc/common-types";
import { generatePrivate } from "@toruslabs/eccrypto";
import BN from "bn.js";
import { TorusLoginResponse } from "@toruslabs/customauth";
import { EthereumSigningProvider } from "@web3auth-mpc/ethereum-provider";
import Web3 from "web3";
import { copyFactorPub } from "../rss"

const uiConsole = (...args: any[]): void => {
  const el = document.querySelector("#console>p");
  if (el) {
    el.innerHTML = JSON.stringify(args || {}, null, 2);
  }
  console.log(...args);
};

const chainConfig = {
  chainId: "0x5",
  rpcTarget: "https://rpc.ankr.com/eth_goerli",
  displayName: "Goerli Testnet",
  blockExplorer: "https://goerli.etherscan.io",
  ticker: "ETH",
  tickerName: "Ethereum",
};

const web3AuthClientId =
  "BEglQSgt4cUWcj6SKRdu5QkOXTsePmMcusG5EAoyjyOYKlVRjIF1iCNnMOTfpzCiunHRrMui8TIwQPXdkQ8Yxuk"; // get from https://dashboard.web3auth.io

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
        chainConfig,
      },
    });
    // Authentication configs
    const torusSp = new TorusServiceProvider({
      useTSS: true,
      customAuthArgs: {
        network: "sapphire_devnet",
        web3AuthClientId, 
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
    uiConsole("loginResponse", loginResponse);
    set('loginResponse', JSON.stringify(loginResponse));
    return loginResponse;
  }

  // Create or get device factor key, stored in localStorage
  getDeviceFactorKey () {
    if (!get('factorKey')) {
      set('factorKey', new BN(generatePrivate()).toString(16, 64))
    }
    const d = new BN(get('factorKey'), 'hex');
    uiConsole("device factor key", d);
    return d
  }

  async isMetadataPresent(privateKeyBN: BN) {
    const metadata = (await this.tKey.storageLayer.getMetadata({ privKey: privateKeyBN }));
    if (
      metadata &&
      Object.keys(metadata).length > 0 &&
      (metadata as any).message !== 'KEY_NOT_FOUND'
    ) {
      return true;
    } else {
      return false;
    }
  }

  // Initialize TKey (must call triggerLogin first)
  async initializeTkey() {
    const loginResponse: TorusLoginResponse = await this.triggerLogin();

    if (!loginResponse) {
      throw new Error("Login Failed, please try again");
    }
    const OAuthShare = new BN(TorusUtils.getPostboxKey(loginResponse), "hex");

    const existingUser = await this.isMetadataPresent(OAuthShare);
    const deviceFactorKey = this.getDeviceFactorKey();
    const factorPub = getPubKeyPoint(deviceFactorKey);
    let deviceShare;

    if(!existingUser) {
      const deviceTSSShare = new BN(generatePrivate());
      const deviceTSSIndex = 2;
      await this.tKey.initialize({ useTSS: true, factorPub, deviceTSSShare, deviceTSSIndex });

    } else {
      await this.tKey.initialize({
        useTSS: true,
        factorPub,
      });
      try {
        deviceShare = await this.remoteGet(deviceFactorKey)
        if (deviceShare) {
          await this.tKey.inputShareStoreSafe(deviceShare, false);
        }
      } catch (e) {
        uiConsole(`error ${e}`)
      }
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
    const t = this.tKey.getTSSShare(this.getDeviceFactorKey());
    uiConsole("device tss share", t);
    return t;
  }

  async sign(msgHashBuffer: Buffer) {
    const signature = await this.thirdPartyTSSServerSign(msgHashBuffer);
    return { v: signature.v, r: Buffer.from(signature.r.padStart(64, "0"), "hex"), s: Buffer.from(signature.s.padStart(64, "0"), "hex")}
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
    uiConsole(this.ethereumSigningProvider.provider);
    const web3 = new Web3(this.ethereumSigningProvider.provider as any);
    return web3;
  }

   async getAccounts() {
    const web3 = await this.getWeb3Instance();
    const address = (await web3.eth.getAccounts())[0];
    uiConsole("address", address)
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
    uiConsole("signedTx", signedTx);
    return signedTx;
  };

  async addThirdPartyTSSServer() {
    const serverFactorPubHex = await fetch("http://localhost:3000/factorPub").then(res => res.json()).then(res => res.factorPub)
    const serverFactorPub = new Point(serverFactorPubHex.x, serverFactorPubHex.y);
    const deviceFactorKey = await this.getDeviceFactorKey();
    await copyFactorPub(this.tKey, serverFactorPub, 2, deviceFactorKey);

    // manual sync
    await this.tKey._syncShareMetadata();
    await this.tKey.syncLocalMetadataTransitions();
  }

  async thirdPartyTSSServerSign(msgHashBuffer: Buffer) {
    const serverFactorPubHex = await fetch("http://localhost:3000/factorPub").then(res => res.json()).then(res => res.factorPub)
    const serverFactorPub = new Point(serverFactorPubHex.x, serverFactorPubHex.y);
    const loginResponse = JSON.parse(get('loginResponse')) as TorusLoginResponse;
    if (!loginResponse) {
      throw new Error("Please call triggerLogin first");
    }
    const signatures = loginResponse.sessionData.sessionTokenData.filter(i => Boolean(i)).map((session) => JSON.stringify({ data: session.token, sig: session.signature }));
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
    uiConsole("thirdPartyTSSServerSign", response);
    return response;
  }
  
}

(async function () {
  const mpcProvider = new MpcLoginProvider();
  await mpcProvider.init();
  (window as any).mpcProvider = mpcProvider
})();