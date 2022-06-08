#ifndef BASICKEY_H
#define BASICKEY_H

#include "pkcs11.h"
#include "PKCSExceptions.h"
#include "CryptoProvider.h"
#include "Session.h"

class BasicKey {                   // абстрактная виртуальная функция generate
protected:
	Session* m_session;
	CK_FUNCTION_LIST* m_funcListPtr;
public:
	BasicKey(Session* m_Session, CK_FUNCTION_LIST* m_FuncListPtr) : m_session(m_Session), m_funcListPtr(m_FuncListPtr) { }
	Session* GetSession() { return m_session; }
	CK_FUNCTION_LIST* GetFuncListPtr() { return m_funcListPtr; };
};

#endif