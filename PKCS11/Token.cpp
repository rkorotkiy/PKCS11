#include "Token.h"


std::shared_ptr<CryptoProvider> Token::GetProviderPtr() {
	return m_provider;
}

std::shared_ptr<CK_TOKEN_INFO> Token::GetInfo() {
	return m_info;
}

unsigned char* Token::GetLabel() {
	return m_label;
}