#ifndef KEYSRSA_H
#define KEYSRSA_H

#include "pkcs11.h"
#include "PKCSExceptions.h"
#include "BasicKey.h"

class KeysRSA : public BasicKey {
private:

	Session* m_session;
	std::shared_ptr<CK_FUNCTION_LIST> m_funcListPtr;
	CK_OBJECT_HANDLE h_privateKeyHandle;
	CK_OBJECT_HANDLE h_publicKeyHandle;

	CK_ATTRIBUTE* GetPubTemplatePtr(
		unsigned char* public_label,
		unsigned char* public_modulusBits,
		unsigned char* public_exponent
	);

	CK_ATTRIBUTE* GetPrivTemplatePtr(
		unsigned char* private_label,
		unsigned char* private_subject,
		unsigned char* private_id
	);

	CK_MECHANISM mechanism_rsa_pkcs_key_pair_gen = {
		CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0
	};

	CK_MECHANISM mechanism_rsa_pkcs = {
		CKM_RSA_PKCS, NULL_PTR, 0
	};

public:
	KeysRSA(Session* m_Session) : m_session(m_Session), m_funcListPtr(m_Session->GetFuncListPtr()) {};
	void Generate(
		unsigned char* public_label,
		unsigned char* public_modulusBits,
		unsigned char* public_exponent,
		unsigned char* private_label,
		unsigned char* private_subject,
		unsigned char* private_id);

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