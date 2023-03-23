const ThresholdKey = require("@tkey/core").default;
const { TorusServiceProvider } = require("@tkey/service-provider-torus");
const { ShareSerializationModule } = require("@tkey/share-serialization");
const { TorusStorageLayer } = require("@tkey/storage-layer-torus");
const { getPubKeyPoint, ShareStore, TkeyError } = require("@tkey/common-types")
const { generatePrivate } = require("@toruslabs/eccrypto")
const BN = require("bn.js");
const tss = require("@toruslabs/tss-lib");
const { Client, utils } = require("@toruslabs/tss-client");
const { generateEndpoints, getDKLSCoeff, setupSockets } = utils;
const EC = require("elliptic").ec
const ec = new EC("secp256k1");

function get(key) {
  return localStorage.getItem(key)
}

function set(key, value) {
  localStorage.setItem(key, value)
}


async function remoteSet (factorKey, metadataToSet) {
  await tKey.addLocalMetadataTransitions({
    input: [{ message: JSON.stringify(metadataToSet) }],
    privKey: [factorKey],
  });
  await this.tKey.syncLocalMetadataTransitions();
}

async function remoteGet (factorKey) {
  const metadata = await tKey.storageLayer.getMetadata({
    privKey: factorKey,
  });
  return JSON.parse(metadata.message)
}

(async function () {
  
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

  window.tKey = tKey;

  // Initialize service provider
  await tKey.serviceProvider.init();

  // Register webauthn
  window.triggerRegister = async function () {
    await tKey.serviceProvider.triggerLogin({
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
  window.triggerLogin = async function () {
    const loginResponse = await tKey.serviceProvider.triggerLogin({
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
    set('loginResponse', JSON.stringify(loginResponse));
  }

  // Create or get device factor key, stored in localStorage
  window.getDeviceFactorKey = function () {
    if (!get('factorKey')) {
      set('factorKey', new BN(generatePrivate()).toString(16, 64))
    }
    return new BN(get('factorKey'), 'hex')
  }

  // Initialize TKey (must call triggerLogin first)
  window.initializeTkey = async function () {
    const deviceFactorKey = window.getDeviceFactorKey();
    const factorPub = getPubKeyPoint(deviceFactorKey);
    await tKey.initialize({
      useTSS: true,
      factorPub,
    });
    try {
      let deviceShare = await remoteGet(deviceFactorKey)
      if (deviceShare) {
        await tKey.inputShareStoreSafe(deviceShare, false);
      }
    } catch (e) {
      console.log(`error ${e}`)
    }
    
    await tKey.reconstructKey();
    const polyId = tKey.metadata.getLatestPublicPolynomial().getPolynomialID();
    const shares = tKey.shares[polyId];
    for (const shareIndex in shares) {
      if (shareIndex !== '1') {
        deviceShare = shares[shareIndex];
      }
    }
    await remoteSet(deviceFactorKey, deviceShare)
  }

  // Retrieve TSS share for device
  window.getDeviceTSSShare = async function () {
    return tKey.getTSSShare(window.getDeviceFactorKey());
  }

  window.sign = async function (msgHashHex) {
    const tssImportUrl = "https://sapphire-dev-2-2.authnetwork.dev/tss/v1/clientWasm";
    if (!msgHashHex) throw new Error("msgHashHex not provided")
    // get auth signatures from loginResponse (must call triggerLogin first)
    const signatures = JSON.parse(get('loginResponse')).signatures;
    const { tssShare, tssIndex } = await window.getDeviceTSSShare();
    
    const parties = 4;
    const clientIndex = parties - 1;
    // generate endpoints for servers
    const { endpoints, tssWSEndpoints, partyIndexes } = generateEndpoints(parties, clientIndex);
    const [sockets] = await Promise.all([
      setupSockets(tssWSEndpoints),
      tss.default(tssImportUrl),
    ]);
    const tssPubKey = tKey.getTSSPub();
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
    const client = new Client(
      `${Math.floor(Math.random()*100000)}-${Date.now()}`,
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
    const signature = await client.sign(tss, msgHashBase64, true, '', '', {
      signatures,
    });
    const pubKeyECPoint = ecPoint(
      hexPoint({ x: tssPubKey.x.toString(16, 64), y: tssPubKey.y.toString(16, 64) }),
    );
    const passed = ec.verify(msgHashHex, signature, pubKeyECPoint);
    await client.cleanup(tss, { signatures });
    if (!passed) {
      throw new Error('invalid signature')
    }
    return signature
  }

  // Reset account, for testing purposes
  window.resetAccount = async function () {
    await tKey.storageLayer.setMetadata({
      privKey: tKey.serviceProvider.postboxKey,
      input: { message: "KEY_NOT_FOUND" },
    });
    window.location.reload();
  }

})();