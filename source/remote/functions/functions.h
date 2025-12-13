#pragma once
#include "../includes.h"

namespace Remote::Functions
{
extern std::string g_RemoteEncryptionKey;

std::string RandomString(int Length);
std::string GetServerAddress();
std::string GetServerName();
std::string RelativePathToFullPath(const std::string &RelativePath, const std::string RootPath = "garrysmod/");
std::string ResolvePath(std::filesystem::path &Path);
std::string VFSPathToFullPath(const std::string &VFSPath);
std::string FullPathToVFSPath(const std::string &FullPath);
std::string Encode(nlohmann::json Packet, bool IsBinary = false);
std::string Encode(const std::string &Data, bool IsBinary);
std::string Decode(const std::string &Data);
std::string Base64Encode(const std::string &Data);
std::string Base64Decode(const std::string &Data);
void ConnectRelay(const std::string &RelayURL, const std::string &Password);
} // namespace Remote::Functions