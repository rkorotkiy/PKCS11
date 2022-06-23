#ifndef SIGNING_H
#define SIGNING_H

#include "pkcs11.h"
#include "tdef.h"
#include "PKCSExceptions.h"
#include "Session.h"
#include <string>

class Signing {
private:
	CK_SESSION_HANDLE h_session;
	CK_FUNCTION_LIST* m_funclistPtr;
public:
	Signing(CK_SESSION_HANDLE h_Session) : h_session(h_Session), m_funclistPtr(m_funclistPtr) {}

	int SignInit(CK_MECHANISM* p_Mechanism, CK_OBJECT_HANDLE h_Key);
	int Sign(unsigned char* p_Data, unsigned char* Signature);
	int SignUpdate(unsigned char* Part);
	int SignFinal(unsigned char* p_Signature);

	int SignRecoverInit(CK_MECHANISM_PTR p_Mechanism, CK_OBJECT_HANDLE h_Key);
	int SignRecover(unsigned char* p_Data, unsigned char* p_Signature); 

	int VerifyInit(CK_MECHANISM_PTR p_Mechanism, CK_OBJECT_HANDLE h_Key);
	int Verify(unsigned char* p_Data, unsigned char* p_Signature);
	int VerifyUpdate(unsigned char* p_Part);
	int VerifyFinal(unsigned char* p_Signature);

	int VerifyRecoverInit(CK_MECHANISM_PTR p_Mechanism, CK_OBJECT_HANDLE h_Key);
	int VerifyRecover(unsigned char* p_signature, unsigned char* p_Data);
};





#endif

