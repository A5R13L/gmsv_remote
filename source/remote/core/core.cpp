#include "core.h"
#include "../functions/functions.h"
#include "../json/json.hpp"

#ifdef REMOTE_32_SERVER
IFileSystem *g_pFullFileSystem = nullptr;
#endif

IVEngineServer *g_pVEngineServer = nullptr;
ICvar *g_pCvar = nullptr;

namespace Remote::Core
{
void Initialize(GarrysMod::Lua::ILuaBase *LUA)
{
    g_pFullFileSystem = InterfacePointers::Internal::Server::FileSystem();

    if (!g_pFullFileSystem)
    {
        Logger::Log(Logger::Error("Failed to get {red}IFileSystem {white}pointer!"));
        return;
    }

    g_pVEngineServer = InterfacePointers::VEngineServer();

    if (!g_pVEngineServer)
    {
        Logger::Log(Logger::Error("Failed to get {red}IVEngineServer {white}pointer!"));
        return;
    }

    g_pCvar = InterfacePointers::Cvar();

    if (!g_pCvar)
    {
        Logger::Log(Logger::Error("Failed to get {red}ICvar {white}pointer!"));
        return;
    }

    Logger::Log(Logger::Info("gmsv_remote loaded."));
    Logger::Log(Logger::Info("Version: {green}" REMOTE_VERSION "{white}."));

    std::string RemoteFolder = Functions::RelativePathToFullPath("gmsv_remote/", "");
    std::string Path = RemoteFolder + "config.json";
    nlohmann::json Config = LoadConfig(Path);

    if (!Config.is_object() || !Config.contains("relay") || !Config.contains("password"))
    {
        Logger::Log(Logger::Error(
                        "Missing required config values! Please check the config file at {cyan}%s{white} for errors."),
                    Path.c_str());
        return;
    }

    std::string EncryptionKey = JSON::String(Config, "encryption_key");

    if (!EncryptionKey.empty())
        Functions::g_RemoteEncryptionKey = EncryptionKey;

    std::string Relay = JSON::String(Config, "relay");

    Logger::Log(Logger::Info("Connecting to relay: {cyan}%s{white}..."), Relay.c_str());
    Functions::ConnectRelay(Relay, JSON::String(Config, "password"));
}

void Shutdown(GarrysMod::Lua::ILuaBase *LUA)
{
}

nlohmann::json LoadConfig(const std::filesystem::path &Path)
{
    nlohmann::json Config;
    std::string FilePathAsString = Path.string();

    if (!std::filesystem::exists(Path))
    {
        std::filesystem::path FolderPath = Path.parent_path();
        std::ofstream FileStream(Path);
        std::string DefaultPassword = Functions::RandomString(32);

        Logger::Log(Logger::Info("It looks like it's your first time running gmsv_remote. Setting up..."));
        std::filesystem::create_directory(FolderPath);

        Config = nlohmann::json::object(
            {{"password", DefaultPassword}, {"encryption_key", ""}, {"relay", "wss://gmsv_remote.asrieldev.workers.dev"}});

        std::string ConfigString = Config.dump(1, '\t');

        FileStream << ConfigString.c_str();
        FileStream.close();

        Logger::Log(Logger::Success("Finished setup! The server's relay password is: {cyan}%s{white}."),
                    DefaultPassword.c_str());

        Logger::Log(
            Logger::Warning(
                "Encryption is currently {cyan}disabled{white}. If you wish to enable it, please configure "
                "{yellow}%s{white}. "
                "After configuring, ensure your extension is configured to use the same encryption key. It is not "
                "required, but if you are using a {gray}untrusted{white} relay, it is recommended to do so."),
            FilePathAsString.c_str());

        return Config;
    }

    std::ifstream FileStream(Path);

    if (!FileStream.is_open())
    {
        Logger::Log(Logger::Error("Failed to open config file: {red}%s"), FilePathAsString.c_str());
        return Config;
    }

    try
    {
        std::stringstream ConfigFileStream;
        ConfigFileStream << FileStream.rdbuf();
        Config = nlohmann::json::parse(ConfigFileStream.str());
    }
    catch (const nlohmann::json::parse_error &Error)
    {
        Logger::Log(Logger::Error("Failed to parse config file: {red}%s"), Error.what());
        return Config;
    }

    FileStream.close();

    return Config;
}
} // namespace Remote::Core