#include "functions.h"
#include "../socket/socket.h"
#include "../core/core.h"
#include <xor.hpp>

namespace Remote::Functions
{
std::string g_RemoteEncryptionKey;
bool g_LogActivity = false;

std::string RandomChar()
{
    return std::string(1, 'a' + rand() % 26);
}

std::string RandomString(int Length)
{
    std::string Result = "";
    for (int i = 0; i < Length; i++)
    {
        Result += RandomChar();
    }
    return Result;
}

std::string GetServerAddress()
{
    return g_pVEngineServer->GMOD_GetServerAddress();
}

std::string GetServerName()
{
    static ConVar *ServerName = g_pCvar->FindVar("hostname");
    return ServerName->GetString();
}

std::string RelativePathToFullPath(const std::string &RelativePath, const std::string RootPath)
{
    char RootFilePath[MAX_PATH];

    if (!g_pFullFileSystem->RelativePathToFullPath_safe(RootPath.c_str(), nullptr, RootFilePath))
        return std::string();

    return std::string(RootFilePath) + RelativePath;
}

std::string ResolvePath(std::filesystem::path &Path)
{
    try
    {
        std::string Root = RelativePathToFullPath("", "");
        std::filesystem::path RootPath = std::filesystem::weakly_canonical(Root);
        std::filesystem::path ResolvedPath = std::filesystem::weakly_canonical(Path);

        ResolvedPath = ResolvedPath.make_preferred();
        RootPath = RootPath.make_preferred();

        std::string ResolvedPathAsString = ResolvedPath.string();
        std::string RootPathAsString = RootPath.string();

        if (ResolvedPathAsString.find(RootPathAsString) == std::string::npos)
            return "";

        return ResolvedPathAsString;
    }
    catch (...)
    {
        return "";
    }
}

std::string VFSPathToFullPath(const std::string &VFSPath)
{
    std::filesystem::path Root = RelativePathToFullPath("", "");
    std::filesystem::path CleanedPath = VFSPath;

    if (CleanedPath.empty())
        CleanedPath = "/";

    std::string RootAsString = Root.string();
    std::string FullPath = RootAsString;

    FullPath += CleanedPath.string();

    while (FullPath.find("\\") != std::string::npos)
        FullPath.replace(FullPath.find("\\"), 1, "/");

    while (FullPath.find("//") != std::string::npos)
        FullPath.replace(FullPath.find("//"), 2, "/");

    std::filesystem::path Path = std::filesystem::path(FullPath);

    return ResolvePath(Path);
}

std::string FullPathToVFSPath(const std::string &FullPath)
{
    std::filesystem::path Root = RelativePathToFullPath("", "");
    std::string RootAsString = Root.string();
    std::filesystem::path Path = std::filesystem::path(FullPath);
    std::string PathAsString = Path.string();

    while (PathAsString.find("\\") != std::string::npos)
        PathAsString.replace(PathAsString.find("\\"), 1, "/");

    while (PathAsString.find("//") != std::string::npos)
        PathAsString.replace(PathAsString.find("//"), 2, "/");

    while (RootAsString.find("\\") != std::string::npos)
        RootAsString.replace(RootAsString.find("\\"), 1, "/");

    while (RootAsString.find("//") != std::string::npos)
        RootAsString.replace(RootAsString.find("//"), 2, "/");

    while (PathAsString.find(RootAsString) != std::string::npos)
        PathAsString.replace(PathAsString.find(RootAsString), RootAsString.length(), "");

    if (PathAsString.substr(0, 1) != "/")
        PathAsString = "/" + PathAsString;

    return PathAsString;
}

std::string Encode(const nlohmann::json Packet, bool IsBinary)
{
    std::string Plaintext = Packet.dump();

    if (g_RemoteEncryptionKey.empty())
        return IsBinary ? Plaintext : Base64Encode(Plaintext);

    std::string Xored = XORString(Plaintext, g_RemoteEncryptionKey);

    return IsBinary ? Xored : Base64Encode(Xored);
}

std::string Encode(const std::string &Data, bool IsBinary)
{
    if (g_RemoteEncryptionKey.empty())
        return IsBinary ? Data : Base64Encode(Data);

    std::string Xored = XORString(Data, g_RemoteEncryptionKey);

    return IsBinary ? Xored : Base64Encode(Xored);
}

std::string Decode(const std::string &Data)
{
    std::string Decoded = Base64Decode(Data);

    if (g_RemoteEncryptionKey.empty())
        return Decoded;

    return XORString(Decoded, g_RemoteEncryptionKey);
}

std::string Base64Encode(const std::string &Data)
{
    try
    {
        return base64::to_base64(Data);
    }
    catch (...)
    {
        return Data;
    }
}

std::string Base64Decode(const std::string &Data)
{
    try
    {
        return base64::from_base64(Data);
    }
    catch (...)
    {
        return Data;
    }
}

void ConnectRelay(const std::string &RelayURL, const std::string &Password)
{
    ix::initNetSystem();
    Socket::SocketServer::Singleton.Connect(RelayURL, Password);
}

void DisconnectRelay()
{
    ix::uninitNetSystem();
    Socket::SocketServer::Singleton.Disconnect();
}
} // namespace Remote::Functions