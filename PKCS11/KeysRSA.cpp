#include "KeysRSA.h"

void KeysRSA::Generate(
	unsigned char* public_label,
	unsigned char* public_modulusBits,
	unsigned char* public_exponent,
	unsigned char* private_label,
	unsigned char* private_subject,
	unsigned char* private_id) {

	CK_RV rv;
	rv = m_funcListPtr->C_GenerateKeyPair(
		m_session->GetHandle(), 
		&mechanism_rsa_pkcs_key_pair_gen,
		GetPubTemplatePtr(public_label, public_modulusBits, public_exponent), 8,
		GetPrivTemplatePtr(private_label, private_subject, private_id), 9,
		&h_publicKeyHandle, &h_privateKeyHandle
	);

}

CK_ATTRIBUTE* KeysRSA::GetPubTemplatePtr(
	unsigned char* public_label,
	unsigned char* public_modulusBits,
	unsigned char* public_exponent
) {

	CK_OBJECT_CLASS objClass = CKO_PUBLIC_KEY;
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_UTF8CHAR* pub_label;
	CK_BYTE* modulusBits;
	CK_BYTE* exponent;
	CK_BBOOL True = CK_TRUE;

	CK_ATTRIBUTE RSAPublicKeyTemplate[8] = {
		{CKA_CLASS, &objClass, sizeof(objClass)},
		{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
		{CKA_TOKEN, &True, sizeof(true)},
		{CKA_LABEL, &pub_label, sizeof(pub_label) - 1},
		{CKA_WRAP, &True, sizeof(true)},
		{CKA_ENCRYPT, &True, sizeof(true)},
		{CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},
		{CKA_PUBLIC_EXPONENT, &exponent, sizeof(exponent)}
	};

	pub_label = public_label;
	modulusBits = public_modulusBits;
	exponent = public_exponent;

	return RSAPublicKeyTemplate;

}

CK_ATTRIBUTE* KeysRSA::GetPrivTemplatePtr(
	unsigned char* private_label,
	unsigned char* private_subject,
	unsigned char* private_id
) {

	CK_OBJECT_CLASS objClass = CKO_PRIVATE_KEY;
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_UTF8CHAR* pr_label;
	CK_BYTE* subject;
	CK_BYTE* id;
	CK_BBOOL True = CK_TRUE;

	CK_ATTRIBUTE RSAPrivateKeyTemplate[9] = {
		{CKA_CLASS, &objClass, sizeof(objClass)},
		{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
		{CKA_TOKEN, &True, sizeof(true)},
		{CKA_LABEL, &pr_label, sizeof(pr_label) - 1},
		{CKA_SUBJECT, &subject, sizeof(subject)},
		{CKA_ID, &id, sizeof(id)},
		{CKA_SENSITIVE, &True, sizeof(true)},
		{CKA_DECRYPT, &True, sizeof(true)},
		{CKA_SIGN, &True, sizeof(true)},
	};

	pr_label = private_label;
	subject = private_subject;
	id = private_id;

	return RSAPrivateKeyTemplate;

}



int KeysRSA::SignInit() {

	CK_RV rv;
	rv = m_funcListPtr->C_SignInit(m_session->GetHandle(), &mechanism_rsa_pkcs, h_publicKeyHandle);
	if (rv != CKR_OK)
		throw RetVal(rv);

}

int KeysRSA::Sign(unsigned char* p_Data, unsigned char* Signature) {

	unsigned long sigLen = sizeof(Signature);

	CK_RV rv;
	rv = m_funcListPtr->C_Sign(m_session->GetHandle(), p_Data, sizeof(p_Data), Signature, &sigLen);
	if (rv != CKR_OK)
		throw RetVal(rv);

}

int KeysRSA::SignUpdate(unsigned char* Part) {

	CK_RV rv;
	rv = m_funcListPtr->C_SignUpdate(m_session->GetHandle(), Part, sizeof(Part));
	if (rv != CKR_OK)
		throw RetVal(rv);

}

int KeysRSA::SignFinal(unsigned char* p_Signature) {

	unsigned long sigLen = sizeof(p_Signature);

	CK_RV rv;
	rv = m_funcListPtr->C_SignFinal(m_session->GetHandle(), p_Signature, &sigLen);
	if (rv != CKR_OK)
		throw RetVal(rv);

}

int KeysRSA::SignRecoverInit() {

	CK_RV rv;
	rv = m_funcListPtr->C_SignRecoverInit(m_session->GetHandle(), &mechanism_rsa_pkcs, h_publicKeyHandle);
	if (rv != CKR_OK)
		throw RetVal(rv);

}

int KeysRSA::SignRecover(unsigned char* p_Data, unsigned char* p_Signature) {

	unsigned long sigLen = sizeof(p_Signature);

	CK_RV rv;
	rv = m_funcListPtr->C_SignRecover(m_session->GetHandle(), p_Data, sizeof(p_Data), p_Signature, &sigLen);
	if (rv != CKR_OK)
		throw RetVal(rv);

}

int KeysRSA::VerifyInit() {

	CK_RV rv;
	rv = m_funcListPtr->C_VerifyInit(m_session->GetHandle(), &mechanism_rsa_pkcs, h_publicKeyHandle);
	if (rv != CKR_OK)
		throw RetVal(rv);

}

int KeysRSA::Verify(unsigned char* p_Data, unsigned char* p_Signature) {

	CK_RV rv;
	rv = m_funcListPtr->C_Verify(m_session->GetHandle(), p_Data, sizeof(p_Data), p_Signature, sizeof(p_Signature));
	if (rv != CKR_OK)
		throw RetVal(rv);

}

int KeysRSA::VerifyUpdate(unsigned char* p_Part) {

	CK_RV rv;
	rv = m_funcListPtr->C_VerifyUpdate(m_session->GetHandle(), p_Part, sizeof(p_Part));
	if (rv != CKR_OK)
		throw RetVal(rv);

}

int KeysRSA::VerifyFinal(unsigned char* p_Signature) {

	CK_RV rv;
	rv = m_funcListPtr->C_VerifyFinal(m_session->GetHandle(), p_Signature, sizeof(p_Signature));
	if (rv != CKR_OK)
		throw RetVal(rv);

}

int KeysRSA::VerifyRecoverInit() {

	CK_RV rv;
	rv = m_funcListPtr->C_VerifyRecoverInit(m_session->GetHandle(), &mechanism_rsa_pkcs, h_publicKeyHandle);
	if (rv != CKR_OK)
		throw RetVal(rv);

}

int KeysRSA::VerifyRecover(unsigned char* p_Signature, unsigned char* p_Data) {

	unsigned long sigLen = sizeof(p_Signature);

	CK_RV rv;
	rv = m_funcListPtr->C_VerifyRecover(m_session->GetHandle(), p_Signature, sizeof(p_Signature), p_Data, &sigLen);
	if (rv != CKR_OK)
		throw RetVal(rv);

}