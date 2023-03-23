export async function addFactorPub(tKey, newFactorPub, newFactorTSSIndex, inputFactorKey) {
  if (!tKey) {
    throw new Error('tkey does not exist, cannot add factor pub');
  }
  if (newFactorTSSIndex !== 2 && newFactorTSSIndex !== 3) {
    throw new Error('tssIndex must be 2 or 3');
  }
  if (
    !tKey.metadata.factorPubs ||
    !Array.isArray(tKey.metadata.factorPubs[tKey.tssTag])
  ) {
    throw new Error('factorPubs does not exist');
  }
  const existingFactorPubs = tKey.metadata.factorPubs[tKey.tssTag].slice();
  const updatedFactorPubs = existingFactorPubs.concat([newFactorPub]);
  const existingTSSIndexes = existingFactorPubs.map((fb) => tKey.getFactorEncs(fb).tssIndex);
  const updatedTSSIndexes = existingTSSIndexes.concat([newFactorTSSIndex]);
  const { tssShare, tssIndex } = await tKey.getTSSShare(inputFactorKey);
  tKey.metadata.addTSSData({
    tssTag: tKey.tssTag,
    factorPubs: updatedFactorPubs,
  });
  const rssNodeDetails = await tKey._getRssNodeDetails();
  const { serverEndpoints, serverPubKeys, serverThreshold } = rssNodeDetails;
  const randomSelectedServers = randomSelection(
    new Array(rssNodeDetails.serverEndpoints.length).fill(null).map((_, i) => i + 1),
    Math.ceil(rssNodeDetails.serverEndpoints.length / 2),
  );
  const verifierNameVerifierId = tKey.serviceProvider.getVerifierNameVerifierId();
  await tKey._refreshTSSShares(
    true,
    tssShare,
    tssIndex,
    updatedFactorPubs,
    updatedTSSIndexes,
    verifierNameVerifierId,
    {
      selectedServers: randomSelectedServers,
      serverEndpoints,
      serverPubKeys,
      serverThreshold,
      authSignatures: await this.getSignatures(),
    },
  );
  // TODO: needs manual sync after add factor pub
}

export async function copyFactorPub(tKey, newFactorPub, newFactorTSSIndex, inputFactorKey) {
  if (!tKey) {
    throw new Error('tkey does not exist, cannot copy factor pub');
  }
  if (newFactorTSSIndex !== 2 && newFactorTSSIndex !== 3) {
    throw new Error('input factor tssIndex must be 2 or 3');
  }
  if (
    !tKey.metadata.factorPubs ||
    !Array.isArray(tKey.metadata.factorPubs[tKey.tssTag])
  ) {
    throw new Error('factorPubs does not exist, failed in copy factor pub');
  }
  if (
    !tKey.metadata.factorEncs ||
    typeof tKey.metadata.factorEncs[tKey.tssTag] !== 'object'
  ) {
    throw new Error('factorEncs does not exist, failed in copy factor pub');
  }
  const existingFactorPubs = tKey.metadata.factorPubs[tKey.tssTag].slice();
  const updatedFactorPubs = existingFactorPubs.concat([newFactorPub]);
  const { tssShare, tssIndex } = await tKey.getTSSShare(inputFactorKey);
  if (tssIndex !== newFactorTSSIndex) {
    throw new Error('retrieved tssIndex does not match input factor tssIndex');
  }
  const factorEncs = JSON.parse(JSON.stringify(tKey.metadata.factorEncs[tKey.tssTag]));
  const factorPubID = newFactorPub.x.toString(16, 64);
  factorEncs[factorPubID] = {
    tssIndex: newFactorTSSIndex,
    type: 'direct',
    userEnc: await encrypt(
      Buffer.concat([
        Buffer.from('04', 'hex'),
        Buffer.from(newFactorPub.x.toString(16, 64), 'hex'),
        Buffer.from(newFactorPub.y.toString(16, 64), 'hex'),
      ]),
      Buffer.from(tssShare.toString(16, 64), 'hex'),
    ),
    serverEncs: [],
  };
  tKey.metadata.addTSSData({
    tssTag: tKey.tssTag,
    factorPubs: updatedFactorPubs,
    factorEncs,
  });
  // TODO: needs manual sync after copy factor pub
}

export async function deleteFactorPub(tKey, factorPub, inputFactorKey) {
  if (!tKey) {
    throw new Error('tkey does not exist, cannot add factor pub');
  }
  if (
    !tKey.metadata.factorPubs ||
    !Array.isArray(tKey.metadata.factorPubs[tKey.tssTag])
  ) {
    throw new Error('factorPubs does not exist');
  }
  const existingFactorPubs = tKey.metadata.factorPubs[tKey.tssTag].slice();
  const found = existingFactorPubs.filter((f) => f.x.eq(factorPub.x) && f.y.eq(factorPub.y));
  if (found.length === 0) throw new Error('could not find factorPub to delete');
  if (found.length > 1)
    throw new Error('found two or more factorPubs that match, error in metadata');
  const updatedFactorPubs = existingFactorPubs.filter(
    (f) => !f.x.eq(factorPub.x) || !f.y.eq(factorPub.y),
  );
  tKey.metadata.addTSSData({
    tssTag: tKey.tssTag,
    factorPubs: updatedFactorPubs,
  });

  const rssNodeDetails = await tKey._getRssNodeDetails();
  const randomSelectedServers = randomSelection(
    new Array(rssNodeDetails.serverEndpoints.length).fill(null).map((_, i) => i + 1),
    Math.ceil(rssNodeDetails.serverEndpoints.length / 2),
  );

  const updatedTSSIndexes = updatedFactorPubs.map((fb) => tKey.getFactorEncs(fb).tssIndex);

  const { tssShare, tssIndex } = await tKey.getTSSShare(inputFactorKey);

  await tKey._refreshTSSShares(
    false,
    tssShare,
    tssIndex,
    updatedFactorPubs,
    updatedTSSIndexes,
    this.serviceProvider.getVerifierNameVerifierId(),
    {
      ...rssNodeDetails,
      selectedServers: randomSelectedServers,
      authSignatures: await this.getSignatures(),
    },
  );
  // TODO: needs manual sync after delete factor pub
}
