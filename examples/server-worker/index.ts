import dotenv from 'dotenv';
import { constants } from 'http2';
import bodyParser from 'body-parser';
import { SSVKeys, KeyShares, EncryptShare } from 'ssv-keys';
import express, { Express, Request, Response } from 'express';

dotenv.config();

const app: Express = express();
const port = process.env.PORT;
const ssvKeys = new SSVKeys();

app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
const nonce = 0;
app.post('/key-shares/generate', async (req: Request, res: Response) => {
  const operators_ids = String(req.body['operators_ids'] || '')
    .split(',')
    .map((id) => Number(id.trim()))
    .filter(id => !!id);

  if (!operators_ids.length) {
    return res
      .status(constants.HTTP_STATUS_BAD_REQUEST)
      .json({ message: 'Operator IDs required' });
  }

  if (!operators_ids.length) {
    return res
      .status(constants.HTTP_STATUS_BAD_REQUEST)
      .json({ message: 'Operator IDs required' });
  }

  const operators_keys = String(req.body['operators_keys'] || '')
    .split(',')
    .map((key) => key.trim())
    .filter(key => !!key);

  if (!operators_keys.length) {
    return res
      .status(constants.HTTP_STATUS_BAD_REQUEST)
      .json({ message: 'Operator keys required' });
  }

  const keystore = req.body['keystore'];

  if (!keystore) {

    return res
      .status(constants.HTTP_STATUS_BAD_REQUEST)
      .json({ message: 'Keystore is required' });
  }

  const owner_address = String(req.body['owner_address'] || '')

  if (!owner_address.length) {
    return res
      .status(constants.HTTP_STATUS_BAD_REQUEST)
      .json({ message: 'Owner address is required' });
  }

  const password = String(req.body['password'] || '');

  if (!password.length) {
    return res
      .status(constants.HTTP_STATUS_BAD_REQUEST)
      .json({ message: 'Keystore password is required' });
  }

  const { publicKey, privateKey } = await ssvKeys.extractKeys(keystore, password);

  const operators = operators_keys.map((operatorKey, index) => ({
    id: operators_ids[index],
    operatorKey,
  }));

  const encryptedShares = await ssvKeys.buildShares(privateKey, operators);

  // Build final web3 transaction payload and update keyshares file with payload data
  const keyShares = new KeyShares();
  keyShares.update({ operators, publicKey });

  await keyShares.buildPayload({
    publicKey,
    operators,
    encryptedShares,
  },{
    ownerAddress: owner_address,
    ownerNonce: nonce,
    privateKey
  });
  keyShares.payload.readable.encryptedKeys = encryptedShares.map((share: EncryptShare) => share.privateKey);
  keyShares.payload.readable.publicKeys = encryptedShares.map((share: EncryptShare) => share.publicKey);

  console.log(`Built key shares for operators: ${String(operators_ids)} and public key: ${keystore.pubkey}`);
  res.json(JSON.parse(keyShares.toJson()));
});

app.listen(port, () => {
  console.log(`⚡️[server]: Server is running at https://localhost:${port}`);
});
