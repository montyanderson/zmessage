const util = require('util');
const crypto = require('crypto');

const generateKeyPair = util.promisify(crypto.generateKeyPair);

function getId(publicKey) {
	const hash = crypto.createHash('sha256');

	hash.update(publicKey);

	return hash.digest('base64');
}

module.exports = class Identity {
	constructor() {

	}

	async generate() {
		const { publicKey, privateKey } = await generateKeyPair('rsa', {
			modulusLength: 4096,
			publicKeyEncoding: {
				type: 'pkcs1',
				format: 'pem'
			}
		});

		this.publicKey = publicKey;
		this.privateKey = privateKey;

		this.id = getId(publicKey);
	}

	encrypt(recipientPublicKey, message) {
		const key = crypto.randomBytes(32);
		const nonce = crypto.randomBytes(16);

		const cipher = crypto.createCipheriv('aes-256-ctr', key, nonce);
		const encryptedMessage = cipher.update(message);
		cipher.final();

		const encryptedKey = crypto.publicEncrypt(recipientPublicKey, key);

		const sign = crypto.createSign('sha256');
		sign.write(message);
		sign.end();

		const signature = sign.sign(this.privateKey);

		return {
			nonce: nonce.toString('base64'),
			encryptedMessage: encryptedMessage.toString('base64'),
			encryptedKey: encryptedKey.toString('base64'),
			signature: signature.toString('base64')
		}
	}

	decrypt(recipientPublicKey, object) {
		const nonce = Buffer.from(object.nonce, 'base64');
		const encryptedMessage = Buffer.from(object.encryptedMessage, 'base64');
		const encryptedKey = Buffer.from(object.encryptedKey, 'base64');
		const signature = Buffer.from(object.signature, 'base64');

		const key = crypto.privateDecrypt(this.privateKey, encryptedKey);

		const decipher = crypto.createDecipheriv('aes-256-ctr', key, nonce);
		const message = decipher.update(encryptedMessage);
		decipher.final();

		const verify = crypto.createVerify('sha256');
		verify.update(message);

		if(verify.verify(recipientPublicKey, signature) !== true) {
			throw new Error('Bad Signature');
		}

		return message;
	}
};
