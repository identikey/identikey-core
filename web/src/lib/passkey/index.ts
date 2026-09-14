export {
	generateRegistrationChallenge,
	getWebAuthnConfig,
	type RegistrationChallengeParams,
	type WebAuthnConfig
} from './registration-options';

export {
	verifyAndStorePasskey,
	type VerifyAndStoreParams,
	type StoredPasskeyResult
} from './verify-registration';

export {
	verifyAuthenticationAssertion,
	type VerifyAuthenticationParams,
	type AuthenticationResult
} from './verify-authentication';

export {
	storePasskeyCredential,
	getPasskeyByCredentialId,
	getPasskeysByUserId,
	updatePasskeyCounter,
	deletePasskeyCredential,
	type StorePasskeyParams
} from './credential-store';

export {
	generateAuthenticationChallenge,
	type AuthenticationChallengeParams
} from './authentication-options';

export { PasskeyError, PasskeyErrorCode } from './errors';
