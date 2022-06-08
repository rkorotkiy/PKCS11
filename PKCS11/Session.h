#ifndef SESSION_H
#define SESSION_H

#include "tdef.h"
#include"pkcs11.h"
#include "PKCSExceptions.h"

class Session {
private:
	CK_SESSION_HANDLE h_session;
	CK_FUNCTION_LIST* m_funcListPtr;
public:
	Session(CK_SESSION_HANDLE h_Session, FuncList* m_FuncListPtr) : h_session(h_Session), m_funcListPtr(m_FuncListPtr) { }
	CK_SESSION_HANDLE GetHandle();

	void Login(CK_USER_TYPE userType, unsigned char* PIN);
	void Logout();

	void InitPin(unsigned char* PIN);

	void Close();
};

#endif