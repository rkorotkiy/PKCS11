#include "CryptoProvider.h"

CryptoProvider::CryptoProvider(const wchar_t* PATH_TO_DLL) {
	m_lib = LoadLibrary(PATH_TO_DLL);
}

void* CryptoProvider::LoadProc(HINSTANCE hLib, const char* FUNC_NAME) {
	return (void*)GetProcAddress(hLib, FUNC_NAME);
}

void CryptoProvider::SetFunctionList() {

	if (m_lib == NULL)
		throw  LibLoadErr();

	void* func = LoadProc(m_lib, "C_GetFunctionList");

	if (func == NULL)
		throw FuncLoadErr();

	int (*C_GetFuncList)(CK_FUNCTION_LIST**);               
	C_GetFuncList = (C_GetFunctionList_decl)func;

	CK_FUNCTION_LIST* m_FuncList;

	CK_RV rv = C_GetFuncList(&m_FuncList);

	m_funcListPtr = std::make_shared<CK_FUNCTION_LIST>(*m_FuncList);

	if (rv != CKR_OK)
		throw RetVal(rv);


}

void CryptoProvider::Initialize() {
	SetFunctionList();

	if (m_funcListPtr.get() == NULL)
		throw FuncListErr();

	CK_RV rv = m_funcListPtr->C_Initialize(NULL_PTR);

	if (rv != CKR_OK)
		throw RetVal(rv);

}

void CryptoProvider::Finalize() {
	if (m_funcListPtr.get() == NULL)
		throw FuncListErr();

	CK_RV rv = m_funcListPtr->C_Finalize(NULL_PTR);

	if (rv != CKR_OK)
		throw RetVal(rv);

}

void CryptoProvider::GetSlotCollection(CK_BBOOL tokenPresent, std::vector<Slot*>& slotStorage) {

	CK_ULONG pulCount;
	CK_RV rv = m_funcListPtr->C_GetSlotList(tokenPresent, NULL_PTR, &pulCount);

	if (rv != CKR_OK)
		throw RetVal(rv);

	if (pulCount <= 0)
		return;

	std::vector<CK_SLOT_ID> slotCollection;
	slotCollection.resize(pulCount);
	rv = m_funcListPtr->C_GetSlotList(tokenPresent, &slotCollection[0], &pulCount);

	if (rv != CKR_OK)
		throw RetVal(rv);

	for (size_t i = 0; i < pulCount; ++i) {
		slotStorage.push_back(new Slot(slotCollection[i], m_funcListPtr));
	}

}

std::shared_ptr<CK_FUNCTION_LIST> CryptoProvider::GetFuncListPtr() {
	return m_funcListPtr;
}

CryptoProvider::~CryptoProvider() {
	if (m_lib != NULL) {
		FreeLibrary(m_lib);
	}
}