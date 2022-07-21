#ifndef BASICKEY_H
#define BASICKEY_H

#include "pkcs11.h"
#include "PKCSExceptions.h"
#include "CryptoProvider.h"
#include "Session.h"

class BasicKey {                   
protected:

public:
	virtual int SignInit() = 0;
	virtual int Sign(unsigned char* p_Data, unsigned char* Signature) = 0;
	virtual int SignUpdate(unsigned char* Part) = 0;
	virtual int SignFinal(unsigned char* p_Signature) = 0;

	virtual int SignRecoverInit() = 0;
	virtual int SignRecover(unsigned char* p_Data, unsigned char* p_Signature) = 0;

	virtual int VerifyInit() = 0;
	virtual int Verify(unsigned char* p_Data, unsigned char* p_Signature) = 0;
	virtual int VerifyUpdate(unsigned char* p_Part) = 0;
	virtual int VerifyFinal(unsigned char* p_Signature) = 0;

	virtual int VerifyRecoverInit() = 0;
	virtual int VerifyRecover(unsigned char* p_Signature, unsigned char* p_Data) = 0;
};

#endif