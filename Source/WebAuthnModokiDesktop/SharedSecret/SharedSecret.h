//#pragma once

extern "C" __declspec(dllexport) int CreateSharedSecret(
	const char*	str_public_key_aG_x,		// I 64文字
	const char*	str_public_key_aG_y,		// I 64文字
	char*		str_public_key_bG_x,		// O 64文字
	char*		str_public_key_bG_y,		// O 64文字
	char*		str_sharedSecret			// O 64文字
);

extern "C" __declspec(dllexport) int Aes256cbc_Enc(
	const char*			key,			// (I )Shared Secret(Hex文字列64文字)
	const char*			in,				// (I )暗号化したいデータ(Hex文字列32文字)
	char*				out				// ( O)暗号化されたデータ(Hex文字列32文字)
);

extern "C" __declspec(dllexport) int Aes256cbc_Dec(
	const char*			key,			// (I )Shared Secret(Hex文字列64文字)
	const char*			in,				// (I )暗号化したいデータ(Hex文字列32文字)
	char*				out				// ( O)暗号化されたデータ(Hex文字列32文字)
);
