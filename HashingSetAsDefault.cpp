#define _CRT_SECURE_NO_WARNINGS

#include <atlstr.h>     // CString
#include <algorithm>    // transform
#include <fstream>
#include <iostream>     // cout
#include <map>
#include "md5.h"
#include <Sddl.h>       // ConvertSidToStringSid
#include <Shlobj.h>
#include <stdio.h>      // printf
#include <tchar.h>      // TCHAR mapping
#include <vector>       // STL vector container
#include <windows.h>    // Win32 SDK main header

using namespace std;

#pragma region data in

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

int GetSpecialFolderPath(int csidl, wstring& folder_path) {
  TCHAR szPath[MAX_PATH];
  if (SUCCEEDED(SHGetFolderPath(NULL,
                                csidl,
                                NULL,
                                0,
                                szPath))) {
    folder_path = wstring(szPath);
    return 1;
  }
  return 0;
}

int GetSid(wstring& sid_str) {
  HANDLE hToken = NULL;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
    _tprintf(_T("OpenProcessToken failed. GetLastError returned: %d\n"),
             GetLastError());
    return 0;
  }

  DWORD dwBufferSize = 0;
  if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &dwBufferSize) &&
      (GetLastError() != ERROR_INSUFFICIENT_BUFFER)) {
    _tprintf(_T("GetTokenInformation failed. GetLastError returned: %d\n"),
             GetLastError());

    CloseHandle(hToken);
    hToken = NULL;

    return 0;
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

    return 0;
  }

  if (!IsValidSid(pTokenUser->User.Sid)) {
    _tprintf(_T("The owner SID is invalid.\n"));

    CloseHandle(hToken);
    hToken = NULL;
  }

  sid_str = ConvertSidToString(pTokenUser->User.Sid);

  CloseHandle(hToken);
  hToken = NULL;
  return 1;
}

wstring GenerateDate() {
  SYSTEMTIME system_time;
  GetSystemTime(&system_time);
  system_time.wMilliseconds = 0;
  system_time.wSecond = 0;
  FILETIME file_time;
  SystemTimeToFileTime(&system_time, &file_time);
  WCHAR time[17] = { 0 };
  wsprintf(time, L"%08x%08x", file_time.dwHighDateTime, file_time.dwLowDateTime);
  return time;
}

int GetExperienceString(wstring& experience_str) {
  std::u16string experience_base = u"User Choice set via Windows User Experience";
  wstring base_path;
  if (GetSpecialFolderPath(CSIDL_SYSTEMX86, base_path)) {
    base_path += L"\\shell32.dll";

    ifstream file(base_path, ios::in | ios::binary);
    file.seekg(0, ios::end);
    size_t size = (size_t)file.tellg();

    file.seekg(2, ios::beg);
    size -= 2;

    std::u16string u16((size / 2) + 1, '\0');
    file.read((char*)&u16[0], size);
    file.close();
    size_t len = experience_base.size();
    size_t i = 0;
    int begin = 0;
    int end = 0;
    for (i; i < size - len; i++) {
      if (memcmp(&experience_base[0], &u16[0] + i, len) == 0) {
        begin = i;
        char16_t right_curly_brace = '}';
        for (size_t j = i; j < size - len; j++) {
          if (memcmp(&right_curly_brace, &u16[0] + j, 1) == 0) {
            end = j + 1;
            break;
          }
        }
        break;
      }
    }
    experience_str = std::wstring(&u16[0] + begin, &u16[0] + end * 2);
    return 1;
  }
  return 0;
}

#pragma endregion

#pragma region base64 Encode and decode

static const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

static inline bool IsBase64(unsigned char c) {
  return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string Base64Encode(char* bytes_to_encode, unsigned int in_len) {
  std::string ret;
  int i = 0;
  int j = 0;
  unsigned char char_array_3[3];
  unsigned char char_array_4[4];

  while (in_len--) {
    char_array_3[i++] = *(bytes_to_encode++);
    if (i == 3) {
      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;

      for (i = 0; (i < 4); i++)
        ret += base64_chars[char_array_4[i]];
      i = 0;
    }
  }

  if (i) {
    for (j = i; j < 3; j++)
      char_array_3[j] = '\0';

    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
    char_array_4[3] = char_array_3[2] & 0x3f;

    for (j = 0; (j < i + 1); j++)
      ret += base64_chars[char_array_4[j]];

    while ((i++ < 3))
      ret += '=';

  }

  return ret;

}

#pragma endregion

#pragma region Windows Custom hash

vector<char> GetArrayOfByteFromInt(int number) {
  vector<char> chars;
  char* a_begin = reinterpret_cast<char*>(&number);
  char* a_end = a_begin + 4;
  copy(a_begin, a_end, back_inserter(chars));
  return chars;
}

long long GetLong(BYTE bytes[], int start_index = 0) {
  long long result = 0;
  result = (result << 8) + bytes[3 + start_index];
  result = (result << 8) + bytes[2 + start_index];
  result = (result << 8) + bytes[1 + start_index];
  result = (result << 8) + bytes[start_index];
  return result;
}

int ConvertToInt32(long long value) {
  BYTE bytes[4];
  bytes[0] = value & 0xFF; // 0x78
  bytes[1] = (value >> 8) & 0xFF; // 0x56
  bytes[2] = (value >> 16) & 0xFF; // 0x34
  bytes[3] = (value >> 24) & 0xFF; // 0x12
  return GetLong(bytes, 0);
}

long long  GetShiftRight(long long number, int shft_count) {
  if (number & 0x80000000)
    return (number >> shft_count) ^ 0xFFFF0000;
  return number >> shft_count;
}

std::wstring GetCustomHash(BYTE* bytes_base_info, BYTE* bytes_md5, int length_base) {
  int lenght = ((length_base & 4) <= 1) + GetShiftRight(length_base, 2) - 1;
  string base64_hash = "";

  if (lenght > 1) {
    int pdata = 0;
    long cache = 0;
    int counter = 0;
    int index = 0;
    long long md51 = 0;
    long md52 = 0;
    int outhash1 = 0;
    int outhash2 = 0;
    int r0 = 0;
    int r1[] = { 0,0 };
    int r2[] = { 0,0 };
    long r3 = 0;
    int r4[] = { 0,0 };
    int r5[] = { 0,0 };
    int r60 = 0;
    long r61 = 0;
    int r7[] = { 0,0 };

    md51 = (GetLong(bytes_md5) | 1) + 0x69FB0000L;
    md52 = (GetLong(bytes_md5, 4) | 1) + 0x13DB0000L;
    index = GetShiftRight((lenght - 2), 1);
    counter = index + 1;

    while (counter) {
      r0 = ConvertToInt32(GetLong(bytes_base_info, pdata) + (long)outhash1);
      r1[0] = ConvertToInt32(GetLong(bytes_base_info, (pdata + 4)));
      pdata = pdata + 8;
      r2[0] = ConvertToInt32((r0 * (long)md51) - (0x10FA9605L * GetShiftRight(r0, 16)));
      r2[1] = ConvertToInt32((0x79F8A395L * (long)r2[0]) + (0x689B6B9FL * GetShiftRight(r2[0], 16)));
      r3 = ConvertToInt32((0xEA970001L * r2[1]) - (0x3C101569L * GetShiftRight(r2[1], 16)));
      r4[0] = ConvertToInt32(r3 + r1[0]);
      r5[0] = ConvertToInt32(cache + r3);
      r60 = ConvertToInt32((r4[0] * (long)md52) - (0x3CE8EC25L * GetShiftRight(r4[0], 16)));
      r61 = ConvertToInt32((0x59C3AF2DL * r60) - (0x2232E0F1L * GetShiftRight(r60, 16)));
      outhash1 = ConvertToInt32((0x1EC90001L * r61) + (0x35BD1EC9L * GetShiftRight(r61, 16)));
      outhash2 = ConvertToInt32((long)r5[0] + (long)outhash1);
      cache = outhash2;
      counter = counter - 1;
    }

    BYTE out_hash[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    vector<char> buffer = GetArrayOfByteFromInt(outhash1);
    memcpy(&out_hash[0], &buffer[0], buffer.size());
    buffer = GetArrayOfByteFromInt(outhash2);
    memcpy(&out_hash[4], &buffer[0], buffer.size());

    pdata = 0;
    cache = 0;
    counter = 0;
    index = 0;
    md51 = 0;
    md52 = 0;
    outhash1 = 0;
    outhash2 = 0;
    r0 = 0;
    r1[0] = 0;
    r1[1] = 0;
    r2[0] = 0;
    r2[1] = 0;
    r3 = 0;
    r4[0] = 0;
    r4[1] = 0;
    r5[0] = 0;
    r5[1] = 0;
    r60 = 0;
    r61 = 0;
    r7[0] = 0;
    r7[1] = 0;

    md51 = GetLong(bytes_md5) | 1;
    md52 = GetLong(bytes_md5, 4) | 1;
    index = GetShiftRight((lenght - 2), 1);
    counter = index + 1;

    while (counter) {
      r0 = ConvertToInt32(GetLong(bytes_base_info, pdata) + (long)outhash1);
      pdata = pdata + 8;
      r1[0] = ConvertToInt32(r0 * (long)md51);
      r1[1] = ConvertToInt32((0xB1110000L * r1[0]) - (0x30674EEFL * GetShiftRight(r1[0], 16)));
      r2[0] = ConvertToInt32((0x5B9F0000L * r1[1]) - (0x78F7A461L * GetShiftRight(r1[1], 16)));
      r2[1] = ConvertToInt32((0x12CEB96DL * GetShiftRight(r2[0], 16)) - (0x46930000L * r2[0]));
      r3 = ConvertToInt32((0x1D830000L * r2[1]) + (0x257E1D83L * GetShiftRight(r2[1], 16)));
      r4[0] = ConvertToInt32(md52 * (r3 + (GetLong(bytes_base_info, (pdata - 4)))));
      r4[1] = ConvertToInt32((0x16F50000L * r4[0]) - (0x5D8BE90BL * GetShiftRight(r4[0], 16)));
      r5[0] = ConvertToInt32((0x96FF0000L * r4[1]) - (0x2C7C6901L * GetShiftRight(r4[1], 16)));
      r5[1] = ConvertToInt32((0x2B890000L * r5[0]) + (0x7C932B89L * GetShiftRight(r5[0], 16)));
      outhash1 = ConvertToInt32((0x9F690000L * r5[1]) - (0x405B6097L * GetShiftRight(r5[1], 16)));
      outhash2 = ConvertToInt32((long)outhash1 + cache + r3);
      cache = (long)outhash2;
      counter = counter - 1;
    }

    buffer = GetArrayOfByteFromInt(outhash1);
    memcpy(&out_hash[8], &buffer[0], buffer.size());
    buffer = GetArrayOfByteFromInt(outhash2);
    memcpy(&out_hash[12], &buffer[0], buffer.size());

    BYTE out_hash_base[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    int hash_value1 = (GetLong(out_hash, 8) ^ (GetLong(out_hash)));
    int hash_value2 = GetLong(out_hash, 12) ^ (GetLong(out_hash, 4));

    buffer = GetArrayOfByteFromInt(hash_value1);
    memcpy(&out_hash_base[0], &buffer[0], buffer.size());
    buffer = GetArrayOfByteFromInt(hash_value2);
    memcpy(&out_hash_base[4], &buffer[0], buffer.size());

    base64_hash = Base64Encode((char*)out_hash_base, 8);

  }

  return std::wstring(&base64_hash[0], &base64_hash[0] + base64_hash.size());
}

#pragma endregion

int GetSize(wstring base) {
  int result = 0;
  for (size_t i = 0; i < base.length(); i++) {
    if (base[i] == '}') {
      result++;
      break;
    }
    result++;
  }
  return result;
}

int CreateProgIdHash(wstring type, wstring prod_id, wstring& hash) {
  wstring wst_string_sid;
  int sid = GetSid(wst_string_sid);
  wstring wst_plain = type + wst_string_sid + prod_id;

  if (!sid) {
    _tprintf(_T("The user SID couldn't be found.\n"));
    return 0;
  }

  wst_plain += GenerateDate();

  wstring experience_str;
  if (!GetExperienceString(experience_str)) {
    _tprintf(_T("TThere were problems creating the experience key.\n"));
    return 0;
  }

  wst_plain += experience_str;

  std::transform(wst_plain.begin(), wst_plain.end(), wst_plain.begin(), ::tolower);

  wst_plain += L"\0";
  int wst_plain_len = GetSize(wst_plain) * 2 + 2;
  BYTE* bytes_string_plain = (BYTE*)wst_plain.c_str();
  MD5 md5;
  md5.update(bytes_string_plain, wst_plain_len);
  md5.finalize();
  BYTE* md5_digits = (BYTE*)md5.getdigest();
  string a = md5.hexdigest();

  BYTE test1[500];
  memcpy(&test1[0], &bytes_string_plain[0], 500);
  BYTE test2[500];
  memcpy(&test2[0], &md5_digits[0], 500);

  hash = GetCustomHash(bytes_string_plain, md5_digits, wst_plain_len);

  return 1;
}

int WriteProdIdAndHashKeys(wstring key, wstring prod_id, wstring hash) {
  const wchar_t* sk = key.c_str();

  HKEY hKey;
  LONG openRes = RegOpenKeyEx(HKEY_CURRENT_USER, sk, 0, 0x20019, &hKey);
  LONG delRes = RegDeleteKey(HKEY_CURRENT_USER, sk);

  HKEY runKey;
  long create_key = RegCreateKeyEx(HKEY_CURRENT_USER, sk, 0, NULL, 0, REG_OPTION_NON_VOLATILE | KEY_ALL_ACCESS, NULL, &runKey, nullptr);

  LPCTSTR value = TEXT("Hash");
  const wchar_t* data = hash.c_str();
  LONG setRes = RegSetValueEx(runKey, value, 0, REG_SZ, (LPBYTE)data, hash.size() * 2 + 1);
  value = TEXT("ProgId");
  const wchar_t* data1 = prod_id.c_str();
  setRes |= RegSetValueEx(runKey, value, 0, REG_SZ, (LPBYTE)data1, prod_id.size() * 2 + 1);

  LONG closeOut = RegCloseKey(hKey);
  RegCloseKey(runKey);

  SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, NULL, NULL);

  return !setRes;
}

bool WriteProtocolKeys(wstring protocol, wstring prod_id, wstring hash) {

  return WriteProdIdAndHashKeys(L"Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\" + protocol + L"\\UserChoice", prod_id, hash);
}

int WriteExtensionKeys(wstring extension_file, wstring prod_id, wstring hash) {
  return WriteProdIdAndHashKeys(L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\" + extension_file + L"\\UserChoice", prod_id, hash);
}

int _tmain(int argc, _TCHAR* argv[]) {
  wstring hash;
  wstring prod_id = L"WaveBrwsHTM.BJVGTK5OKSUDR2XUOD4KRNGMUY";
  if (CreateProgIdHash(L"http", prod_id, hash)) {
    WriteProtocolKeys(L"http", prod_id, hash);
  }
  if (CreateProgIdHash(L"https", prod_id, hash)) {
    WriteProtocolKeys(L"https", prod_id, hash);
  }
  if (CreateProgIdHash(L".htm", prod_id, hash)) {
    WriteExtensionKeys(L".htm", prod_id, hash);
  }
  if (CreateProgIdHash(L".html", prod_id, hash)) {
    WriteExtensionKeys(L".html", prod_id, hash);
  }
  if (CreateProgIdHash(L".pdf", prod_id, hash)) {
    WriteExtensionKeys(L".pdf", prod_id, hash);
  }
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
