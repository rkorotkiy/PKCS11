#ifndef CRYPTOPROVIDER_H
#define CRYPTOPROVIDER_H

#include <Windows.h>
#include <vector>
#include <libloaderapi.h>
#include <vector>

#include "pkcs11.h"
#include "tdef.h"
#include "PKCSExceptions.h"
#include "CryptoProvider.h"
#include "Slot.h"
#include <memory>

class CryptoProvider {
private:
	HINSTANCE m_lib;
	std::shared_ptr<CK_FUNCTION_LIST> m_funcListPtr;

	void* LoadProc(HINSTANCE, const char*);
public:
	CryptoProvider(const wchar_t*);
	~CryptoProvider();

	void SetFunctionList();
	void GetSlotCollection(CK_BBOOL tokenPresent, std::vector<Slot*>& slotStorage);
	void Initialize();
	void Finalize();

	std::shared_ptr<CK_FUNCTION_LIST> GetFuncListPtr();

};

#endif