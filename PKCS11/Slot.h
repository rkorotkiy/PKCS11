#ifndef SLOT_H
#define SLOT_H

#include "pkcs11.h"
#include "tdef.h"
#include "PKCSExceptions.h"
#include "Session.h"

class Slot {
private:
	CK_SLOT_ID m_id;
	std::shared_ptr<CK_FUNCTION_LIST> m_funcListPtr;
public:
	Slot(CK_SLOT_ID id, std::shared_ptr<CK_FUNCTION_LIST> m_FunclistPtr) : m_id(id), m_funcListPtr(m_FunclistPtr) { }

	Session* OpenSession(CK_BYTE application);

	CK_TOKEN_INFO* GetTokenInfo();
	void InitToken(unsigned char* pin, unsigned char* label);

	std::shared_ptr<CK_FUNCTION_LIST> GetFuncListPtr();

	CK_SLOT_ID* GetSlotId();
};

#endif