#ifndef SESSION_H
#define SESSION_H

#include "tdef.h"
#include"pkcs11.h"
#include "PKCSExceptions.h"

class Session {
private:
	CK_SESSION_HANDLE h_session;
	std::shared_ptr<CK_FUNCTION_LIST> m_funcListPtr;
public:
	Session(CK_SESSION_HANDLE h_Session, std::shared_ptr<CK_FUNCTION_LIST> m_FuncListPtr) : h_session(h_Session), m_funcListPtr(m_FuncListPtr) { }

	void Login(CK_USER_TYPE userType, unsigned char* PIN);
	void Logout();

	void InitPin(unsigned char* PIN);

	void Close();

	CK_SESSION_HANDLE GetHandle();

	std::shared_ptr<CK_FUNCTION_LIST> GetFuncListPtr();
};

#endif