#ifndef TOKEN_H
#define TOKEN_H

#include "pkcs11.h"
#include "PKCSExceptions.h"
#include "CryptoProvider.h"

class Token {
private:
	std::shared_ptr<CryptoProvider> m_provider;
	std::shared_ptr<CK_TOKEN_INFO> m_info;
	unsigned char* m_label; 
public:

	Token(CryptoProvider* provider, CK_TOKEN_INFO* info) {
		m_provider = std::make_shared<CryptoProvider>(*provider);
		m_info = std::make_shared<CK_TOKEN_INFO>(*info);
		m_label = info->label;
	}

	std::shared_ptr<CryptoProvider> GetProviderPtr();
	std::shared_ptr<CK_TOKEN_INFO> GetInfo();
	unsigned char* GetLabel();
};

#endif