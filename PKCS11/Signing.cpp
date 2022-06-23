#include "Signing.h"

int Signing::SignInit(CK_MECHANISM* p_Mechanism, CK_OBJECT_HANDLE h_Key) {

	CK_RV rv;
	rv = m_funclistPtr->C_SignInit(h_session, p_Mechanism, h_Key);
	if (rv != CKR_OK)
		throw RetVal(rv);

}

int Signing::Sign(unsigned char* p_Data, unsigned char* Signature) {

	unsigned long sigLen = sizeof(Signature);

	CK_RV rv;
	rv = m_funclistPtr->C_Sign(h_session, p_Data, sizeof(p_Data), Signature, &sigLen);
	if (rv != CKR_OK)
		throw RetVal(rv);

}

int Signing::SignUpdate(unsigned char* Part) {



	CK_RV rv;
	rv = m_funclistPtr->C_SignUpdate(h_session, Part, sizeof(Part));
	if (rv != CKR_OK)
		throw RetVal(rv);

}

int Signing::SignFinal(unsigned char* p_Signature) {

	unsigned long sigLen = sizeof(p_Signature);

	CK_RV rv;
	rv = m_funclistPtr->C_SignFinal(h_session, p_Signature, &sigLen);
	if (rv != CKR_OK)
		throw RetVal(rv);

}

int Signing::SignRecoverInit(CK_MECHANISM_PTR p_Mechanism, CK_OBJECT_HANDLE h_Key) {

	CK_RV rv;
	rv = m_funclistPtr->C_SignRecoverInit(h_session, p_Mechanism, h_Key);
	if (rv != CKR_OK)
		throw RetVal(rv);

}

int Signing::SignRecover(unsigned char* p_Data, unsigned char* p_Signature) {

	unsigned long sigLen = sizeof(p_Signature);

	CK_RV rv;
	rv = m_funclistPtr->C_SignRecover(h_session, p_Data,sizeof(p_Data), p_Signature, &sigLen);
	if (rv != CKR_OK)
		throw RetVal(rv);

}

int Signing::VerifyInit(CK_MECHANISM_PTR p_Mechanism, CK_OBJECT_HANDLE h_Key) {

	CK_RV rv;
	rv = m_funclistPtr->C_VerifyInit(h_session, p_Mechanism, h_Key);
	if (rv != CKR_OK)
		throw RetVal(rv);

}

int Signing::Verify(unsigned char* p_Data, unsigned char* p_Signature) {

	CK_RV rv;
	rv = m_funclistPtr->C_Verify(h_session, p_Data, sizeof(p_Data), p_Signature, sizeof(p_Signature));
	if (rv != CKR_OK)
		throw RetVal(rv);

}

int Signing::VerifyUpdate(unsigned char* p_Part) {

	CK_RV rv;
	rv = m_funclistPtr->C_VerifyUpdate(h_session, p_Part, sizeof(p_Part));
	if (rv != CKR_OK)
		throw RetVal(rv);

}

int Signing::VerifyFinal(unsigned char* p_Signature) {

	CK_RV rv;
	rv = m_funclistPtr->C_VerifyFinal(h_session, p_Signature, sizeof(p_Signature));
		if (rv != CKR_OK)
			throw RetVal(rv);

}

int Signing::VerifyRecoverInit(CK_MECHANISM_PTR p_Mechanism, CK_OBJECT_HANDLE h_Key) {

	CK_RV rv;
	rv = m_funclistPtr->C_VerifyRecoverInit(h_session, p_Mechanism, h_Key);
	if (rv != CKR_OK)
		throw RetVal(rv);

}

int Signing::VerifyRecover(unsigned char* p_Signature, unsigned char* p_Data) {

	unsigned long sigLen = sizeof(p_Signature);

	CK_RV rv;
	rv = m_funclistPtr->C_VerifyRecover(h_session, p_Signature, sizeof(p_Signature), p_Data, &sigLen);
	if (rv != CKR_OK)
		throw RetVal(rv);

}