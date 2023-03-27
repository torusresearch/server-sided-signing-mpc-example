const { generatePrivate } = require('@toruslabs/eccrypto');
const { utils, Client } = require('@toruslabs/tss-client')
const tss = require("./node")
console.log("WHAT IS TSS", tss)
const { generateEndpoints, setupSockets, getDKLSCoeff } = utils;
const { getPubKeyPoint, decrypt } = require('@tkey/common-types')
const keccak256 = require("keccak256");
const { TorusStorageLayer } = require("@tkey/storage-layer-torus");
const BN = require('bn.js')
var express = require('express');
const cors = require('cors');
var app = express();
var bodyParser = require('body-parser')
const { dotProduct, kCombinations, getLagrangeCoeffs } = require("./utils.js")
const EC = require('elliptic').ec
const ecCurve = new EC('secp256k1')

app.use(express.static('public'));
app.use(bodyParser.json())
app.use(cors({
  origin: '*'
}));

const tssImportUrl = "https://sapphire-dev-2-2.authnetwork.dev/tss/v1/clientWasm";

const DELIMITERS = {
  Delimiter1: "\u001c",
  Delimiter2: "\u0015",
  Delimiter3: "\u0016",
  Delimiter4: "\u0017",
};

const serverFactorKey = new BN(generatePrivate())
const serverFactorPub = getPubKeyPoint(serverFactorKey);

async function getTSSShare(factorEncs, tssCommits) {
  const { userEnc, serverEncs, tssIndex, type } = factorEncs;
  const tssShareBufs = await Promise.all(
    [decrypt(Buffer.from(serverFactorKey.toString(16, 64), "hex"), userEnc)].concat(
      serverEncs.map((factorEnc) => decrypt(Buffer.from(serverFactorKey.toString(16, 64), "hex"), factorEnc))
    )
  );

  const tssShareBNs = tssShareBufs.map((buf) => new BN(buf.toString("hex"), "hex"));
  const userDec = tssShareBNs[0];

  if (type === "direct") {
    const tssSharePub = ecCurve.g.mul(userDec);
    const tssCommitA0 = ecCurve.keyFromPublic({ x: tssCommits[0].x.toString(16, 64), y: tssCommits[0].y.toString(16, 64) }).getPublic();
    const tssCommitA1 = ecCurve.keyFromPublic({ x: tssCommits[1].x.toString(16, 64), y: tssCommits[1].y.toString(16, 64) }).getPublic();
    let _tssSharePub = tssCommitA0;
    for (let j = 0; j < tssIndex; j++) {
      _tssSharePub = _tssSharePub.add(tssCommitA1);
    }
    if (tssSharePub.getX().cmp(_tssSharePub.getX()) === 0 && tssSharePub.getY().cmp(_tssSharePub.getY()) === 0) {
      return { tssIndex, tssShare: userDec };
    }
    throw new Error("user decryption does not match tss commitments...");
  }

  // if type === "hierarchical"
  const serverDecs = tssShareBNs.slice(1); // 5 elems
  const serverIndexes = new Array(serverDecs.length).fill(null).map((_, i) => i + 1);

  const { threshold } = opts || {};

  const combis = kCombinations(serverDecs.length, threshold || Math.ceil(serverDecs.length / 2));
  for (let i = 0; i < combis.length; i++) {
    const combi = combis[i];
    const selectedServerDecs = serverDecs.filter((_, j) => combi.indexOf(j) > -1);
    const selectedServerIndexes = serverIndexes.filter((_, j) => combi.indexOf(j) > -1);
    const serverLagrangeCoeffs = selectedServerIndexes.map((x) => getLagrangeCoeffs(selectedServerIndexes, x));
    const serverInterpolated = dotProduct(serverLagrangeCoeffs, selectedServerDecs, ecCurve.n);
    const lagrangeCoeffs = [getLagrangeCoeffs([1, 99], 1), getLagrangeCoeffs([1, 99], 99)];
    const tssShare = dotProduct(lagrangeCoeffs, [serverInterpolated, userDec], ecCurve.n);
    const tssSharePub = ecCurve.g.mul(tssShare);
    const tssCommitA0 = ecCurve.keyFromPublic({ x: tssCommits[0].x.toString(16, 64), y: tssCommits[0].y.toString(16, 64) }).getPublic();
    const tssCommitA1 = ecCurve.keyFromPublic({ x: tssCommits[1].x.toString(16, 64), y: tssCommits[1].y.toString(16, 64) }).getPublic();
    let _tssSharePub = tssCommitA0;
    for (let j = 0; j < tssIndex; j++) {
      _tssSharePub = _tssSharePub.add(tssCommitA1);
    }
    if (tssSharePub.getX().cmp(_tssSharePub.getX()) === 0 && tssSharePub.getY().cmp(_tssSharePub.getY()) === 0) {
      return { tssIndex, tssShare };
    }
  }
  throw new Error("could not find any combination of server decryptions that match tss commitments...");
}

async function sign(msgHashBuffer, {
  vid,
  tssNonce,
  tssPubKey,
  signatures,
  factorEncs,
  tssCommits,
}) {
  if (!msgHashBuffer) throw new Error("msgHashHex not provided")
  const msgHashHex = keccak256(msgHashBuffer).toString("hex");
  const { tssShare, tssIndex } = await getTSSShare(factorEncs, tssCommits);

  const parties = 4;
  const clientIndex = parties - 1;
  // generate endpoints for servers
  const { endpoints, tssWSEndpoints, partyIndexes } = generateEndpoints(parties, clientIndex);
  const [sockets] = await Promise.all([
    setupSockets(tssWSEndpoints),
  ]);
  const pubKey = Buffer.from(
    `${tssPubKey.x.toString(16, 64)}${tssPubKey.y.toString(16, 64)}`,
    'hex',
  ).toString('base64');
  const participatingServerDKGIndexes = [1, 2, 3]; // can be randomized, or only pick servers that are online
  const dklsCoeff = getDKLSCoeff(true, participatingServerDKGIndexes, 2);
  const denormalisedShare = dklsCoeff.mul(tssShare).umod(ecCurve.n);
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

  const randomSessionNonce = keccak256(generatePrivate().toString("hex") + Date.now());

  const session = `${vid}${DELIMITERS.Delimiter2}default${DELIMITERS.Delimiter3}${tssNonce}${DELIMITERS.Delimiter4
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

  client.precompute(tss, { signatures, server_coeffs: serverCoeffs });
  await client.ready();
  const msgHashBase64 = Buffer.from(msgHashHex, 'hex').toString('base64');
  const signature = await client.sign(tss, msgHashBase64, true, msgHashHex, 'keccak256', {
    signatures,
  });

  const pubk = ecCurve.recoverPubKey(new BN(msgHashHex, "hex"), signature, signature.recoveryParam, "hex");
  const passed = ecCurve.verify(msgHashHex, signature, pubk);
  await client.cleanup(tss, { signatures });
  if (!passed) {
    throw new Error('invalid signature')
  }
  return { v: signature.recoveryParam, r: Buffer.from(signature.r.toString("hex"), "hex"), s: Buffer.from(signature.s.toString("hex"), "hex") };
}

app.get("/factorPub", async (req, res) => {
  res.send({ factorPub: serverFactorPub.toJSON() });
})


app.post("/sign", async (req, res) => {
  const { msgHash, vid, tssNonce, tssPubKey, signatures, factorEncs, tssCommits } = req.body;
  console.log(req.body)
  const msgHashBuffer = Buffer.from(msgHash, "hex");
  const signature = await sign(msgHashBuffer, {
    vid,
    tssNonce,
    tssPubKey,
    signatures,
    factorEncs,
    tssCommits
  });
  res.send({ 
    r: signature.r.toString("hex"),
    s: signature.s.toString("hex"),
    v: signature.v
   });

})
app.listen(3000);