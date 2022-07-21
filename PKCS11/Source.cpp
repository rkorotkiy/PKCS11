#include <Windows.h>
#include <vector>
#include <libloaderapi.h>

#include "pkcs11.h"
#include "tdef.h"

#include "CryptoProvider.h"
#include "Slot.h"
#include "Token.h"
#include "Session.h"
#include "BasicKey.h"
#include "KeyAES.h"
#include "KeysRSA.h"



void PrintSlots(std::vector<Slot*> slotStorage) {
	for (size_t i = 0; i < slotStorage.size(); ++i) {
		std::cout << slotStorage[i]->GetSlotId() << std::endl;
	}
}



int main() {

	setlocale(0, "");

	try {

		CryptoProvider provider(L"D:\\SoftHSM2\\lib\\softhsm2-x64.dll");

		CK_BYTE app = 1;

		CK_C_INITIALIZE_ARGS initArgs;

		provider.Initialize();

		
		/*typedef FuncList* (CryptoProvider::*FuncList_PF) ();

		FuncList_PF funcListPtr;
		funcListPtr = &CryptoProvider::GetFuncListPtr;*/


		std::vector<Slot*> slotStorage;
		provider.GetSlotCollection(true, slotStorage);

		std::vector<Token*> tokenCollection;

		unsigned char LABEL[32];
		unsigned char SOPIN[32];

		std::cout << "������� PIN S/O: ";
		std::cin >> SOPIN;

		for (size_t i = 0; i < slotStorage.size(); ++i) {
			std::cout << "������� �������� label ��� ������: ";
			std::cin >> LABEL;
			slotStorage[i]->InitToken(SOPIN, LABEL);
			Token token(&provider, slotStorage[i]->GetTokenInfo());
			tokenCollection.push_back(&token);
		}

		PrintSlots(slotStorage);

		Session* session;

		session = slotStorage[0]->OpenSession(1);

		unsigned char LoginPIN[255];
		std::cout << "������� PIN S/O: ";
		std::cin >> LoginPIN;

		session->Login(CKU_SO, LoginPIN);

		unsigned char UserInitPIN[256];
		std::cout << "������� PIN ������������ (�������������): ";
		std::cin >> UserInitPIN;

		session->InitPin(UserInitPIN);

		session->Logout();

		std::cout << "������� PIN ������������: ";
		std::cin >> LoginPIN;

		session->Login(CKU_USER, LoginPIN);

		KeyAES AES(session);

		unsigned char AESKeyLabel[256];

		std::cout << "������� Label ��� AES secret key: ";
		std::cin >> AESKeyLabel;

		AES.Generate(16, AESKeyLabel);

		KeysRSA RSA(session);

		unsigned char RSA_pubKeyLabel[256];
		unsigned char RSA_modulusBits[256];
		unsigned char RSA_exponent[256];
		unsigned char RSA_prKeylabel[256];
		unsigned char RSA_subject[256];
		unsigned char RSA_id[256];

		std::cout << "������� public key label: ";
		std::cin >> RSA_pubKeyLabel;
		std::cout << "������� modulus bits: ";
		std::cin >> RSA_modulusBits;
		std::cout << "������� exponent: ";
		std::cin >> RSA_exponent;
		std::cout << "������� private key label: ";
		std::cin >> RSA_prKeylabel;
		std::cout << "������� subject: ";
		std::cin >> RSA_subject;
		std::cout << "������� id: ";
		std::cin >> RSA_id;

		RSA.Generate(
			RSA_pubKeyLabel,
			RSA_modulusBits,
			RSA_exponent,
			RSA_prKeylabel,
			RSA_subject,
			RSA_id
		);

		session->Close();

		provider.Finalize();
	}
	catch (LibLoadErr LibEx) {
		std::cout << LibEx.what();
		return LibEx.errcode();
	}
	catch (FuncListErr FuncListEx) {
		std::cout << FuncListEx.what();
		return FuncListEx.errcode();
	}
	catch (FuncLoadErr FuncLoadEx) {
		std::cout << FuncLoadEx.what();
		return FuncLoadEx.errcode();
	}
	catch (RetVal RetEx) {
		std::cout << RetEx.what();
		return RetEx.errcode();
	}
}