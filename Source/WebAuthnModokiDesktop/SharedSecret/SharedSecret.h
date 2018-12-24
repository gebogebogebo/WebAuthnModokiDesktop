//#pragma once

extern "C" __declspec(dllexport) int CreateSharedSecret(
	const char*	str_public_key_aG_x,		// I 64����
	const char*	str_public_key_aG_y,		// I 64����
	char*		str_public_key_bG_x,		// O 64����
	char*		str_public_key_bG_y,		// O 64����
	char*		str_sharedSecret			// O 64����
);

extern "C" __declspec(dllexport) int Aes256cbc_Enc(
	const char*			key,			// (I )Shared Secret(Hex������64����)
	const char*			in,				// (I )�Í����������f�[�^(Hex������32����)
	char*				out				// ( O)�Í������ꂽ�f�[�^(Hex������32����)
);

extern "C" __declspec(dllexport) int Aes256cbc_Dec(
	const char*			key,			// (I )Shared Secret(Hex������64����)
	const char*			in,				// (I )�Í����������f�[�^(Hex������32����)
	char*				out				// ( O)�Í������ꂽ�f�[�^(Hex������32����)
);

extern "C" __declspec(dllexport) int Verify_AttestaionSig(
	const char*			sigBaseSha256,	// (I )�������f�[�^��SHA256�n�b�V��(Hex������)
	const char*			x5c,			// (I )X5C�ؖ���(Hex������)
	const char*			sig				// (I )����(Hex������)
);

extern "C" __declspec(dllexport) int Verify_AssertionSig(
	const char*			sigBaseSha256,	// (I )�������f�[�^��SHA256�n�b�V��(Hex������)
	const char*			pubkeyPem,		// (I )AttestationPublicKey(PEM�`��������)
	const char*			sig				// (I )����(Hex������)
);
