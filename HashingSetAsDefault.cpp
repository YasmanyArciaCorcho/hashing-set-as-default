// HashingSetAsDefault.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <windows.h>    // Win32 SDK main header
#include <tchar.h>      // TCHAR mapping
#include <Sddl.h>       // ConvertSidToStringSid

#include <stdio.h>      // printf

#include <vector>       // STL vector container

#include <atlstr.h>     // CString

using namespace std;

wstring ConvertSidToString(PSID pSID) {
  ATLASSERT(pSID != NULL);
  if (pSID == NULL) {
    AtlThrow(E_POINTER);
  }

  LPTSTR pszSID = NULL;
  if (!ConvertSidToStringSid(pSID, &pszSID)) {
    AtlThrowLastWin32();
  }

  wstring result(pszSID);

  LocalFree(pszSID);
  pszSID = NULL;

  return result;
}

int CreateProgIdHash(wstring type, wstring prod_id, wstring& wst_hash) {
  wstring wst_string_sid;
  int sid = GetSid(wst_string_sid);
  wstring wst_plain = type + wst_string_sid + prod_id;

  if (sid != 0) {
    cout << "The user SID couldn't be found.";
    return -1;
  }

  wst_plain.append(GenerateDate(), 16);

  wcout << wst_string_sid;
  return 0;
}

int GetSid(wstring& string_sid) {
  HANDLE hToken = NULL;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
    _tprintf(_T("OpenProcessToken failed. GetLastError returned: %d\n"),
             GetLastError());
    return -1;
  }

  DWORD dwBufferSize = 0;
  if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &dwBufferSize) &&
      (GetLastError() != ERROR_INSUFFICIENT_BUFFER)) {
    _tprintf(_T("GetTokenInformation failed. GetLastError returned: %d\n"),
             GetLastError());

    CloseHandle(hToken);
    hToken = NULL;

    return -1;
  }


  vector<BYTE> buffer;
  buffer.resize(dwBufferSize);
  PTOKEN_USER pTokenUser = reinterpret_cast<PTOKEN_USER>(&buffer[0]);


  if (!GetTokenInformation(
    hToken,
    TokenUser,
    pTokenUser,
    dwBufferSize,
    &dwBufferSize)) {
    _tprintf(_T("2 GetTokenInformation failed. GetLastError returned: %d\n"),
             GetLastError());

    CloseHandle(hToken);
    hToken = NULL;

    return -1;
  }

  if (!IsValidSid(pTokenUser->User.Sid)) {
    _tprintf(_T("The owner SID is invalid.\n"));

    CloseHandle(hToken);
    hToken = NULL;


  }

  string_sid = ConvertSidToString(pTokenUser->User.Sid);

  CloseHandle(hToken);
  hToken = NULL;
  return 0;
}

wstring GenerateDate() {
  SYSTEMTIME systemTime;
  systemTime.wMilliseconds = 0;
  systemTime.wSecond = 0;
  FILETIME fileTime;
  SystemTimeToFileTime(&systemTime, &fileTime);
  WCHAR time[17] = { 0 };
  wsprintf(time, L"%08x%08x", fileTime.dwHighDateTime, fileTime.dwLowDateTime);
  return time;
}

wstring GetExperienceString() {
  return wstring();
}


#pragma region temporal data feed



#pragma endregion

int _tmain(int argc, _TCHAR* argv[]) {

}
// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
