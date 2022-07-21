#ifndef KEYAES_H
#define KEYAES_H

#include "pkcs11.h"
#include "PKCSExceptions.h"
#include "BasicKey.h"

class KeyAES : public BasicKey {
private:

	CK_OBJECT_HANDLE h_Key;

	Session* m_session;
	std::shared_ptr<CK_FUNCTION_LIST> m_funcListPtr;

	CK_MECHANISM m_mechanism_aes_key_gen = {
		CKM_AES_KEY_GEN, NULL_PTR, 0
	};

	CK_MECHANISM m_mechanism_aes_mac_general = {
		CKM_AES_MAC_GENERAL, NULL_PTR, 0
	};

	CK_ATTRIBUTE* GetTemplatePtr(CK_ULONG valueLen, unsigned char* label);

public:

	KeyAES(Session* m_Session) : m_session(m_Session), m_funcListPtr(m_Session->GetFuncListPtr()) {};
	void Generate(CK_ULONG valueLen, unsigned char* label);

	int SignInit() override;
	int Sign(unsigned char* p_Data, unsigned char* Signature) override;
	int SignUpdate(unsigned char* Part) override;
	int SignFinal(unsigned char* p_Signature) override;

	int SignRecoverInit() override;
	int SignRecover(unsigned char* p_Data, unsigned char* p_Signature) override;

	int VerifyInit() override;
	int Verify(unsigned char* p_Data, unsigned char* p_Signature) override;
	int VerifyUpdate(unsigned char* p_Part) override;
	int VerifyFinal(unsigned char* p_Signature) override;

	int VerifyRecoverInit();
	int VerifyRecover(unsigned char* p_Signature, unsigned char* p_Data) override;

};

#endif