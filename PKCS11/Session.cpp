#include "Session.h"

void Session::Close() {
	CK_RV rv;

	rv = m_funcListPtr->C_CloseSession(h_session);
	if (rv != CKR_OK)
		throw RetVal(rv);

}

CK_SESSION_HANDLE Session::GetHandle() {
	return h_session;
}

void Session::Login(CK_USER_TYPE userType, unsigned char* PIN) {
	CK_RV rv;

	rv = m_funcListPtr->C_Login(h_session, userType, PIN, sizeof(PIN));

	if (rv != CKR_OK)
		throw RetVal(rv);
}

void Session::Logout() {
	CK_RV rv;

	rv = m_funcListPtr->C_Logout(h_session);

	if (rv != CKR_OK)
		throw RetVal(rv);
}

void Session::InitPin(unsigned char* PIN) {
	
	CK_RV rv;

	rv = m_funcListPtr->C_InitPIN(h_session, PIN, sizeof(PIN));

	if (rv != CKR_OK)
		throw RetVal(rv);
}

std::shared_ptr<CK_FUNCTION_LIST> Session::GetFuncListPtr() {
	return m_funcListPtr;
}