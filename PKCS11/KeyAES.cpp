#include "KeyAES.h"

void KeyAES::Generate(CK_ULONG valueLen, unsigned char* label) {

	CK_RV rv;

	rv = m_funcListPtr->C_GenerateKey(m_session->GetHandle(), &m_mechanism_aes_key_gen, GetTemplatePtr(valueLen, label), 7, &h_Key);
	
}

CK_ATTRIBUTE* KeyAES::GetTemplatePtr(CK_ULONG valueLen, unsigned char* label) {

	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_AES;
	CK_BBOOL True = CK_TRUE;
	CK_UTF8CHAR* keyLabel;
	CK_ULONG keyValueLen;

	CK_ATTRIBUTE AESTemplate[6] = {          
		{CKA_CLASS, &objClass, sizeof(objClass)},
		{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
		{CKA_TOKEN, &True, sizeof(True)},
		{CKA_LABEL, &keyLabel, sizeof(keyLabel)},
		{CKA_VALUE_LEN, &keyValueLen, sizeof(keyValueLen)},
		{CKA_ENCRYPT, &True, sizeof(true)}
	};

	keyLabel = label;
	keyValueLen = valueLen;

	return AESTemplate;

}


int KeyAES::SignInit() {

	CK_RV rv;
	rv = m_funcListPtr->C_SignInit(m_session->GetHandle(), &m_mechanism_aes_mac_general, h_Key);
	if (rv != CKR_OK)
		throw RetVal(rv);

}

int KeyAES::Sign(unsigned char* p_Data, unsigned char* Signature) {

	unsigned long sigLen = sizeof(Signature);

	CK_RV rv;
	rv = m_funcListPtr->C_Sign(m_session->GetHandle(), p_Data, sizeof(p_Data), Signature, &sigLen);
	if (rv != CKR_OK)
		throw RetVal(rv);

}

int KeyAES::SignUpdate(unsigned char* Part) {



	CK_RV rv;
	rv = m_funcListPtr->C_SignUpdate(m_session->GetHandle(), Part, sizeof(Part));
	if (rv != CKR_OK)
		throw RetVal(rv);

}

int KeyAES::SignFinal(unsigned char* p_Signature) {

	unsigned long sigLen = sizeof(p_Signature);

	CK_RV rv;
	rv = m_funcListPtr->C_SignFinal(m_session->GetHandle(), p_Signature, &sigLen);
	if (rv != CKR_OK)
		throw RetVal(rv);

}

int KeyAES::SignRecoverInit() {

	CK_RV rv;
	rv = m_funcListPtr->C_SignRecoverInit(m_session->GetHandle(), &m_mechanism_aes_mac_general, h_Key);
	if (rv != CKR_OK)
		throw RetVal(rv);

}

int KeyAES::SignRecover(unsigned char* p_Data, unsigned char* p_Signature) {

	unsigned long sigLen = sizeof(p_Signature);

	CK_RV rv;
	rv = m_funcListPtr->C_SignRecover(m_session->GetHandle(), p_Data, sizeof(p_Data), p_Signature, &sigLen);
	if (rv != CKR_OK)
		throw RetVal(rv);

}

int KeyAES::VerifyInit() {

	CK_RV rv;
	rv = m_funcListPtr->C_VerifyInit(m_session->GetHandle(), &m_mechanism_aes_mac_general, h_Key);
	if (rv != CKR_OK)
		throw RetVal(rv);

}

int KeyAES::Verify(unsigned char* p_Data, unsigned char* p_Signature) {

	CK_RV rv;
	rv = m_funcListPtr->C_Verify(m_session->GetHandle(), p_Data, sizeof(p_Data), p_Signature, sizeof(p_Signature));
	if (rv != CKR_OK)
		throw RetVal(rv);

}

int KeyAES::VerifyUpdate(unsigned char* p_Part) {

	CK_RV rv;
	rv = m_funcListPtr->C_VerifyUpdate(m_session->GetHandle(), p_Part, sizeof(p_Part));
	if (rv != CKR_OK)
		throw RetVal(rv);

}

int KeyAES::VerifyFinal(unsigned char* p_Signature) {

	CK_RV rv;
	rv = m_funcListPtr->C_VerifyFinal(m_session->GetHandle(), p_Signature, sizeof(p_Signature));
	if (rv != CKR_OK)
		throw RetVal(rv);

}

int KeyAES::VerifyRecoverInit() {

	CK_RV rv;
	rv = m_funcListPtr->C_VerifyRecoverInit(m_session->GetHandle(), &m_mechanism_aes_mac_general, h_Key);
	if (rv != CKR_OK)
		throw RetVal(rv);

}

int KeyAES::VerifyRecover(unsigned char* p_Signature, unsigned char* p_Data) {

	unsigned long sigLen = sizeof(p_Signature);

	CK_RV rv;
	rv = m_funcListPtr->C_VerifyRecover(m_session->GetHandle(), p_Signature, sizeof(p_Signature), p_Data, &sigLen);
	if (rv != CKR_OK)
		throw RetVal(rv);

}