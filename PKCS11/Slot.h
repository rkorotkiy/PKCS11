#ifndef SLOT_H
#define SLOT_H

#include "pkcs11.h"
#include "tdef.h"
#include "PKCSExceptions.h"
#include "Session.h"

class Slot {
private:
	CK_SLOT_ID m_id;
	CK_FUNCTION_LIST* m_funclistPtr;
public:
	Slot(CK_SLOT_ID id, FuncList* m_FunclistPtr) : m_id(id), m_funclistPtr(m_FunclistPtr) { }

	Session* OpenSession(CK_BYTE application);

	CK_TOKEN_INFO* GetTokenInfo();
	void InitToken(unsigned char* pin, unsigned char* label);

	//CK_FUNCTION_LIST* GetFuncListPtr();
	CK_SLOT_ID* GetSlotId();
};

#endif