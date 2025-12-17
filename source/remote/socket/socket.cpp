#include "socket.h"
#include "../logger/logger.h"
#include "../functions/functions.h"
#include "../json/json.hpp"
#include "../util.hpp"

namespace Remote::Socket
{
static ix::WebSocket g_WebSocket;
static std::map<std::string, int> CurrentRequestIDs;
static size_t SEARCH_RESULT_CHUNK_MAX_SIZE = 32 * 1024;
static auto SEARCH_RESULT_CHUNK_INTERVAL = std::chrono::milliseconds(750);
static size_t FILE_READ_CHUNK_BYTES = 256 * 1024;
static auto FILE_READ_CHUNK_INTERVAL = std::chrono::milliseconds(15);
SocketServer SocketServer::Singleton;

static size_t EstimatePacketSize(const nlohmann::json &Object)
{
    return Object["file"].get<std::string>().size() + Object["lineText"].get<std::string>().size() + 64;
}

SocketServer::SocketServer() : Connected(false), RelayURL(""), Password("")
{
}

SocketServer::~SocketServer()
{
    this->Disconnect();
}

void SocketServer::Connect(const std::string &_RelayURL, const std::string &_Password)
{
    this->RelayURL = _RelayURL;
    this->Password = _Password;

#ifdef SYSTEM_LINUX || __linux__
    ix::SocketTLSOptions TLSOptions;
    TLSOptions.disable_hostname_validation = true;
    TLSOptions.caFile = "NONE";

    g_WebSocket.setTLSOptions(TLSOptions);
#endif

    g_WebSocket.setExtraHeaders({{"Sec-WebSocket-Protocol", "gmsv_remote"}});
    g_WebSocket.setUrl(_RelayURL);
    g_WebSocket.disablePerMessageDeflate();
    g_WebSocket.enablePong();
    g_WebSocket.enableAutomaticReconnection();
    g_WebSocket.setPingInterval(5);
    g_WebSocket.setHandshakeTimeout(5);

    g_WebSocket.setOnMessageCallback([&](const ix::WebSocketMessagePtr &Message) {
        if (Message->type == ix::WebSocketMessageType::Open)
        {
            Logger::Log(Logger::Info("Relay connection established. Announcing server..."));

            std::string ServerAddress = Functions::GetServerAddress();
            bool Notified = false;

            while (ServerAddress.find("0.0.0.0") != std::string::npos)
            {
                if (!Notified)
                {
                    Logger::Log(Logger::Warning("Not connected to steam. Waiting..."));
                    Notified = true;
                }

                ServerAddress = Functions::GetServerAddress();
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }

            g_WebSocket.sendText(JSON::Stringify({
                {"type", "server_announce"},
                {"serverAddress", Functions::GetServerAddress()},
                {"serverPassword", this->Password},
            }));
        }
        else if (Message->type == ix::WebSocketMessageType::Message)
        {
            nlohmann::json Packet = JSON::Parse(Message->str);

            this->HandlePacket(Packet);
        }
        else if (Message->type == ix::WebSocketMessageType::Close)
        {
            std::string Reason = Message->errorInfo.reason;

            Logger::Log(Logger::Error("Relay connection lost: {red}%s {white}Reconnecting..."),
                        Reason.empty() ? "Unknown reason" : Reason.c_str());
        }
        else if (Message->type == ix::WebSocketMessageType::Error)
        {
            std::string Reason = Message->errorInfo.reason;

            Logger::Log(Logger::Error("Relay connection error: {red}%s {white}Reconnecting..."),
                        Reason.empty() ? "Unknown reason" : Reason.c_str());
        }
    });

    g_WebSocket.start();
}

void SocketServer::Disconnect()
{
    if (!Connected)
        return;

    g_WebSocket.stop();
    Connected = false;
}

void SocketServer::HandlePacket(const nlohmann::json &Packet)
{
    std::string Type = JSON::String(Packet, "type");

    if (Type.empty())
        return;

    if (Type == "server_registered")
        Logger::Log(Logger::Info("Server successfully announced to relay."));
    else if (Type == "client_hello")
    {
        std::string ClientTempId = JSON::String(Packet, "clientTempId");

        g_WebSocket.sendText(JSON::Stringify(
            {{"type", "client_notify"}, {"clientTempId", ClientTempId}, {"serverName", Functions::GetServerName()}}));

        if (Functions::g_LogActivity)
            Logger::Log(Logger::Info("Client {cyan}%s{white} connected to server."), ClientTempId.c_str());
    }
    else if (Type == "client_rpc")
    {
        int RequestId = JSON::Integer(Packet, "requestId");

        if (!JSON::ValidInteger(RequestId))
            return;

        std::string Action = JSON::String(Packet, "action");

        if (Action.empty())
            return;

        std::string PayloadString = JSON::String(Packet, "payload");

        if (PayloadString.empty())
            return;

        nlohmann::json Payload = JSON::Parse(Functions::Decode(PayloadString));

        if (Payload.is_null())
            return;

        std::string ClientId = JSON::String(Packet, "clientId");

        if (ClientId.empty())
            return;

        if (Action == "FS.ListFiles")
            this->HandleListFiles(ClientId, RequestId, Payload);
        else if (Action == "FS.Read")
            std::thread(&SocketServer::HandleRead, this, ClientId, RequestId, Payload).detach();
        else if (Action == "FS.Write")
            this->HandleWrite(ClientId, RequestId, Payload);
        else if (Action == "FS.Delete")
            this->HandleDelete(ClientId, RequestId, Payload);
        else if (Action == "FS.Mkdir")
            this->HandleMkdir(ClientId, RequestId, Payload);
        else if (Action == "FS.Rename")
            this->HandleRename(ClientId, RequestId, Payload);
        else if (Action == "FS.Copy")
            this->HandleCopy(ClientId, RequestId, Payload);
        else if (Action == "FS.Move")
            this->HandleMove(ClientId, RequestId, Payload);
        else if (Action == "FS.Exists")
            this->HandleExists(ClientId, RequestId, Payload);
        else if (Action == "FS.Stat")
            this->HandleStat(ClientId, RequestId, Payload);
        else if (Action == "FS.Truncate")
            this->HandleTruncate(ClientId, RequestId, Payload);
        else if (Action == "FS.Search")
            std::thread(&SocketServer::HandleSearch, this, ClientId, RequestId, Payload).detach();
    }
}

void SocketServer::SendRPCResponse(std::string &ClientId, int &RequestId, const nlohmann::json &Response)
{
    g_WebSocket.sendText(JSON::Stringify({
        {"type", "server_rpc_response"},
        {"clientId", ClientId},
        {"requestId", RequestId},
        {"response", Functions::Encode(Response)},
    }));
}

void SocketServer::StartRPCStream(std::string ClientId, int RequestId)
{
    g_WebSocket.sendText(JSON::Stringify({
        {"type", "server_rpc_stream_start"},
        {"clientId", ClientId},
        {"requestId", RequestId},
    }));
}

void SocketServer::SendRPCStreamChunk(std::string ClientId, int RequestId, const nlohmann::json &Chunk)
{
    g_WebSocket.sendText(JSON::Stringify({
        {"type", "server_rpc_stream_chunk"},
        {"clientId", ClientId},
        {"requestId", RequestId},
    }));

    g_WebSocket.sendBinary(Functions::Encode(Chunk, true));
}

void SocketServer::SendRPCStreamChunk(std::string ClientId, int RequestId, const std::string &Chunk)
{
    g_WebSocket.sendText(JSON::Stringify({
        {"type", "server_rpc_stream_chunk"},
        {"clientId", ClientId},
        {"requestId", RequestId},
    }));

    g_WebSocket.sendBinary(Functions::Encode(Chunk, true));
}

void SocketServer::StopRPCStream(std::string ClientId, int RequestId)
{
    g_WebSocket.sendText(JSON::Stringify({
        {"type", "server_rpc_stream_stop"},
        {"clientId", ClientId},
        {"requestId", RequestId},
    }));
}

void SocketServer::HandleListFiles(std::string ClientId, int RequestId, const nlohmann::json &Payload)
{
    std::string Path = JSON::String(Payload, "path");
    std::string FullPath = Functions::VFSPathToFullPath(Path);
    nlohmann::json Response = nlohmann::json::object();

    bool FileExists = std::filesystem::exists(FullPath);
    bool IsDirectory = std::filesystem::is_directory(FullPath);

    if (Path.empty() || FullPath.empty() || !FileExists || !IsDirectory)
    {
        Response["success"] = false;

        if (!FileExists)
            Response["error_code"] = "file_not_found";
        else if (!IsDirectory)
            Response["error_code"] = "not_a_directory";

        return this->SendRPCResponse(ClientId, RequestId, Response);
    }

    if (Functions::g_LogActivity)
        Logger::Log(Logger::Info("Client {cyan}%s{white} requested the the contents of directory: {cyan}%s{white}."),
                    ClientId.c_str(), Path.c_str());

    Response["success"] = true;
    Response["entries"] = nlohmann::json::array();

    for (const auto &Entry : std::filesystem::directory_iterator(FullPath))
    {
        nlohmann::json EntryObject = nlohmann::json::object({
            {"name", Entry.path().filename().string()},
            {"type", Entry.is_directory() ? "directory" : "File"},
            {"lastModified", std::filesystem::last_write_time(Entry.path()).time_since_epoch().count()},
        });

        if (!Entry.is_directory())
            EntryObject["size"] = Entry.file_size();

        Response["entries"].push_back(EntryObject);
    }

    this->SendRPCResponse(ClientId, RequestId, Response);
}

void SocketServer::HandleRead(std::string ClientId, int RequestId, const nlohmann::json &Payload)
{
    std::string Path = JSON::String(Payload, "path");
    std::string FullPath = Functions::VFSPathToFullPath(Path);
    nlohmann::json Response = nlohmann::json::object();

    bool FileExists = std::filesystem::exists(FullPath);
    bool IsRegularFile = std::filesystem::is_regular_file(FullPath);

    if (Path.empty() || !FileExists || !IsRegularFile)
    {
        Response["success"] = false;

        if (!FileExists)
            Response["error_code"] = "file_not_found";
        else if (!IsRegularFile)
            Response["error_code"] = "not_a_file";

        return this->SendRPCResponse(ClientId, RequestId, Response);
    }

    if (Functions::g_LogActivity)
        Logger::Log(Logger::Info("Client {cyan}%s{white} requested to read the contents of file: {cyan}%s{white}."),
                    ClientId.c_str(), Path.c_str());

    std::ifstream FileStream(FullPath, std::ios::binary);

    if (!FileStream)
    {
        Response["success"] = false;
        Response["error_code"] = "file_not_found";
        return this->SendRPCResponse(ClientId, RequestId, Response);
    }

    Response["success"] = true;

    this->SendRPCResponse(ClientId, RequestId, Response);

    size_t FileSize = std::filesystem::file_size(FullPath);

    if (FileSize == 0)
    {
        std::string EmptyBuffer = "";

        this->StartRPCStream(ClientId, RequestId);
        this->SendRPCStreamChunk(ClientId, RequestId, EmptyBuffer);
        this->StopRPCStream(ClientId, RequestId);
        return;
    }

    std::vector<char> ChunkBuffer(FILE_READ_CHUNK_BYTES);

    this->StartRPCStream(ClientId, RequestId);
    auto NextChunkTime = std::chrono::steady_clock::now();
    std::string ChunkString;

    while (FileStream)
    {
        FileStream.read(ChunkBuffer.data(), ChunkBuffer.size());

        std::streamsize BytesRead = FileStream.gcount();

        if (BytesRead <= 0)
            break;

        ChunkString.resize(BytesRead);
        std::memcpy(ChunkString.data(), ChunkBuffer.data(), BytesRead);
        this->SendRPCStreamChunk(ClientId, RequestId, ChunkString);

        NextChunkTime += FILE_READ_CHUNK_INTERVAL;
        std::this_thread::sleep_until(NextChunkTime);
    }

    this->StopRPCStream(ClientId, RequestId);
}

void SocketServer::HandleWrite(std::string ClientId, int RequestId, const nlohmann::json &Payload)
{
    std::string Path = JSON::String(Payload, "path");
    std::string FullPath = Functions::VFSPathToFullPath(Path);
    nlohmann::json Response = nlohmann::json::object();

    if (Path.empty() || FullPath.empty())
    {
        Response["success"] = false;
        Response["error_code"] = "file_not_found";

        return this->SendRPCResponse(ClientId, RequestId, Response);
    }

    std::string Data = JSON::String(Payload, "data");
    int Offset = JSON::Integer(Payload, "offset");

    if (!JSON::ValidInteger(Offset))
        Offset = 0;

    std::string DecodedData = Functions::Base64Decode(Data);
    std::fstream FileStream(FullPath, std::ios::binary | std::ios::in | std::ios::out | std::ios::ate);

    if (Functions::g_LogActivity)
        Logger::Log(
            Logger::Info(
                "Client {cyan}%s{white} requested to write to file: {cyan}%s{white} with {cyan}%d{white} byte%s."),
            ClientId.c_str(), Path.c_str(), DecodedData.size(), DecodedData.size() == 1 ? "" : "s");

    if (!FileStream)
    {
        FileStream.open(FullPath, std::ios::binary | std::ios::out);
        FileStream.close();
        FileStream.open(FullPath, std::ios::binary | std::ios::in | std::ios::out);
    }

    FileStream.seekp(Offset);
    FileStream.write(DecodedData.data(), DecodedData.size());

    Response["success"] = true;

    this->SendRPCResponse(ClientId, RequestId, Response);
}

void SocketServer::HandleDelete(std::string ClientId, int RequestId, const nlohmann::json &Payload)
{
    std::string Path = JSON::String(Payload, "path");
    std::string FullPath = Functions::VFSPathToFullPath(Path);
    nlohmann::json Response = nlohmann::json::object();

    bool FileExists = std::filesystem::exists(FullPath);

    if (Path.empty() || FullPath.empty() || !FileExists)
    {
        Response["success"] = false;
        Response["error_code"] = "file_not_found";

        return this->SendRPCResponse(ClientId, RequestId, Response);
    }

    bool IsDirectory = std::filesystem::is_directory(FullPath);

    if (Functions::g_LogActivity)
        Logger::Log(Logger::Info("Client {cyan}%s{white} requested to delete %s: {cyan}%s{white}."), ClientId.c_str(),
                    IsDirectory ? "directory" : "file", Path.c_str());

    try
    {
        if (IsDirectory)
            std::filesystem::remove_all(FullPath);
        else
            std::filesystem::remove(FullPath);

        Response["success"] = true;
    }
    catch (...)
    {
        Response["success"] = false;
    }

    this->SendRPCResponse(ClientId, RequestId, Response);
}

void SocketServer::HandleMkdir(std::string ClientId, int RequestId, const nlohmann::json &Payload)
{
    std::string Path = JSON::String(Payload, "path");
    std::string FullPath = Functions::VFSPathToFullPath(Path);
    nlohmann::json Response = nlohmann::json::object();

    bool DirectoryExists = std::filesystem::exists(FullPath);

    if (Path.empty() || FullPath.empty() || DirectoryExists)
    {
        Response["success"] = false;
        Response["error_code"] = "directory_already_exists";
        return this->SendRPCResponse(ClientId, RequestId, Response);
    }

    try
    {
        Response["success"] = std::filesystem::create_directories(FullPath);
    }
    catch (...)
    {
        Response["success"] = false;
    }

    this->SendRPCResponse(ClientId, RequestId, Response);
}

void SocketServer::HandleRename(std::string ClientId, int RequestId, const nlohmann::json &Payload)
{
    std::string From = JSON::String(Payload, "from");
    std::string FromFullPath = Functions::VFSPathToFullPath(From);
    std::string To = JSON::String(Payload, "to");
    std::string ToFullPath = Functions::VFSPathToFullPath(To);
    nlohmann::json Response = nlohmann::json::object();

    bool FromFileExists = std::filesystem::exists(FromFullPath);
    bool ToFileExists = std::filesystem::exists(ToFullPath);

    if (From.empty() || To.empty() || FromFullPath.empty() || ToFullPath.empty() || !FromFileExists || ToFileExists)
    {
        Response["success"] = false;

        if (!FromFileExists)
            Response["error_code"] = "file_not_found";
        else if (ToFileExists)
            Response["error_code"] = "file_already_exists";

        return this->SendRPCResponse(ClientId, RequestId, Response);
    }

    if (Functions::g_LogActivity)
        Logger::Log(
            Logger::Info("Client {cyan}%s{white} requested to rename file: {cyan}%s{white} to: {cyan}%s{white}."),
            ClientId.c_str(), From.c_str(), To.c_str());

    try
    {
        std::filesystem::create_directories(std::filesystem::path(ToFullPath).parent_path());
        std::filesystem::rename(FromFullPath, ToFullPath);
        Response["success"] = true;
    }
    catch (...)
    {
        Response["success"] = false;
    }

    this->SendRPCResponse(ClientId, RequestId, Response);
}

void SocketServer::HandleCopy(std::string ClientId, int RequestId, const nlohmann::json &Payload)
{
    std::string From = JSON::String(Payload, "from");
    std::string FromFullPath = Functions::VFSPathToFullPath(From);
    std::string To = JSON::String(Payload, "to");
    std::string ToFullPath = Functions::VFSPathToFullPath(To);
    nlohmann::json Response = nlohmann::json::object();

    bool FromFileExists = std::filesystem::exists(FromFullPath);
    bool ToFileExists = std::filesystem::exists(ToFullPath);

    if (From.empty() || To.empty() || FromFullPath.empty() || ToFullPath.empty() || !FromFileExists || ToFileExists)
    {
        Response["success"] = false;

        if (!FromFileExists)
            Response["error_code"] = "file_not_found";
        else if (ToFileExists)
            Response["error_code"] = "file_already_exists";

        return this->SendRPCResponse(ClientId, RequestId, Response);
    }

    if (Functions::g_LogActivity)
        Logger::Log(Logger::Info("Client {cyan}%s{white} requested to copy file: {cyan}%s{white} to: {cyan}%s{white}."),
                    ClientId.c_str(), From.c_str(), To.c_str());

    try
    {
        std::filesystem::create_directories(std::filesystem::path(ToFullPath).parent_path());
        std::filesystem::copy(FromFullPath, ToFullPath);
        Response["success"] = true;
    }
    catch (...)
    {
        Response["success"] = false;
    }

    this->SendRPCResponse(ClientId, RequestId, Response);
}

void SocketServer::HandleMove(std::string ClientId, int RequestId, const nlohmann::json &Payload)
{
    std::string From = JSON::String(Payload, "from");
    std::string FromFullPath = Functions::VFSPathToFullPath(From);
    std::string To = JSON::String(Payload, "to");
    std::string ToFullPath = Functions::VFSPathToFullPath(To);
    nlohmann::json Response = nlohmann::json::object();

    bool FromFileExists = std::filesystem::exists(FromFullPath);
    bool ToFileExists = std::filesystem::exists(ToFullPath);

    if (From.empty() || To.empty() || FromFullPath.empty() || ToFullPath.empty() || !FromFileExists || ToFileExists)
    {
        Response["success"] = false;

        if (!FromFileExists)
            Response["error_code"] = "file_not_found";
        else if (ToFileExists)
            Response["error_code"] = "file_already_exists";

        return this->SendRPCResponse(ClientId, RequestId, Response);
    }

    if (Functions::g_LogActivity)
        Logger::Log(Logger::Info("Client {cyan}%s{white} requested to move file: {cyan}%s{white} to: {cyan}%s{white}."),
                    ClientId.c_str(), From.c_str(), To.c_str());

    try
    {
        std::filesystem::create_directories(std::filesystem::path(ToFullPath).parent_path());
        std::filesystem::rename(FromFullPath, ToFullPath);
        Response["success"] = true;
    }
    catch (...)
    {
        Response["success"] = false;
    }

    this->SendRPCResponse(ClientId, RequestId, Response);
}

void SocketServer::HandleExists(std::string ClientId, int RequestId, const nlohmann::json &Payload)
{
    std::string Path = JSON::String(Payload, "path");
    std::string FullPath = Functions::VFSPathToFullPath(Path);
    nlohmann::json Response = nlohmann::json::object();

    if (Path.empty() || FullPath.empty())
    {
        Response["success"] = false;

        return this->SendRPCResponse(ClientId, RequestId, Response);
    }

    Response["success"] = true;
    Response["exists"] = std::filesystem::exists(FullPath);

    this->SendRPCResponse(ClientId, RequestId, Response);
}

void SocketServer::HandleStat(std::string ClientId, int RequestId, const nlohmann::json &Payload)
{
    std::string Path = JSON::String(Payload, "path");
    std::string FullPath = Functions::VFSPathToFullPath(Path);
    nlohmann::json Response = nlohmann::json::object();

    if (Path.empty() || FullPath.empty())
    {
        Response["success"] = false;

        return this->SendRPCResponse(ClientId, RequestId, Response);
    }

    try
    {
        bool IsDirectory = std::filesystem::is_directory(FullPath);

        Response["type"] = IsDirectory ? "directory" : "file";

        if (!IsDirectory)
            Response["size"] = std::filesystem::file_size(FullPath);

        Response["created"] = std::filesystem::last_write_time(FullPath).time_since_epoch().count();
        Response["modified"] = std::filesystem::last_write_time(FullPath).time_since_epoch().count();
        Response["success"] = true;
    }
    catch (...)
    {
        Response["success"] = false;
    }

    this->SendRPCResponse(ClientId, RequestId, Response);
}

void SocketServer::HandleTruncate(std::string ClientId, int RequestId, const nlohmann::json &Payload)
{
    std::string Path = JSON::String(Payload, "path");
    std::string FullPath = Functions::VFSPathToFullPath(Path);
    nlohmann::json Response = nlohmann::json::object();

    bool FileExists = std::filesystem::exists(FullPath);
    bool IsRegularFile = std::filesystem::is_regular_file(FullPath);

    if (Path.empty() || FullPath.empty() || !FileExists || !IsRegularFile)
    {
        Response["success"] = false;

        if (!FileExists)
            Response["error_code"] = "file_not_found";
        else if (!IsRegularFile)
            Response["error_code"] = "not_a_file";

        return this->SendRPCResponse(ClientId, RequestId, Response);
    }

    int Size = JSON::Integer(Payload, "size");

    if (!JSON::ValidInteger(Size) || Size < 0)
    {
        Response["success"] = false;

        return this->SendRPCResponse(ClientId, RequestId, Response);
    }

    if (Size >= std::filesystem::file_size(FullPath))
    {
        Response["success"] = true;

        return this->SendRPCResponse(ClientId, RequestId, Response);
    }

    try
    {
        std::filesystem::resize_file(FullPath, Size);

        Response["success"] = true;
    }
    catch (...)
    {
        Response["success"] = false;
    }

    this->SendRPCResponse(ClientId, RequestId, Response);
}

void SocketServer::HandleSearch(std::string ClientId, int RequestId, const nlohmann::json &Payload)
{
    static std::set<std::string> AllowedTextExtensions = {".txt", ".cfg", ".lua", ".ini", ".json", ".disabled", ".log"};
    static std::map<std::string, int> CurrentSearchIDs;

    std::string Query = JSON::String(Payload, "query");
    bool CaseSensitive = JSON::Boolean(Payload, "caseSensitive");
    bool UseRegex = JSON::Boolean(Payload, "useRegex");
    bool WholeWord = JSON::Boolean(Payload, "wholeWord");
    std::string IncludeFiles = JSON::String(Payload, "includeFiles");
    std::string ExcludeFiles = JSON::String(Payload, "excludeFiles");

    CurrentSearchIDs[ClientId] = RequestId;

    bool Success = !Query.empty();
    this->SendRPCResponse(ClientId, RequestId, {{"success", Success}});

    if (!Success)
        return;

    this->StartRPCStream(ClientId, RequestId);

    auto IncludeList = Split_Patterns(IncludeFiles);
    auto ExcludeList = Split_Patterns(ExcludeFiles);
    std::vector<std::filesystem::path> FilesToSearch;

    for (auto &Entry : std::filesystem::recursive_directory_iterator(Functions::RelativePathToFullPath("/")))
    {
        if (CurrentSearchIDs[ClientId] != RequestId)
            return;

        if (!Entry.is_regular_file())
            continue;

        const auto &Path = Entry.path();

        std::string ext = Path.extension().string();
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

        if (!AllowedTextExtensions.count(ext))
            continue;

        if (std::filesystem::file_size(Path) > 2 * 1024 * 1024)
            continue;

        std::string VFS = Functions::FullPathToVFSPath(Path.string());

        if (!IncludeList.empty() && !Matches_Any(IncludeList, VFS))
            continue;

        if (!ExcludeList.empty() && Matches_Any(ExcludeList, VFS))
            continue;

        FilesToSearch.push_back(Path);
    }

    unsigned WorkerCount = std::max(2u, std::thread::hardware_concurrency());
    std::atomic<bool> Cancel(false);
    std::atomic<size_t> Index(0);
    std::atomic<size_t> Active(WorkerCount);

    std::mutex QueueMutex;
    std::condition_variable QueueSignal;
    std::queue<nlohmann::json> Queue;

    std::vector<std::thread> Threads;
    Threads.reserve(WorkerCount);

    auto WorkerThread = [&] {
        while (true)
        {
            if (Cancel.load() || CurrentSearchIDs[ClientId] != RequestId)
                break;

            size_t i = Index.fetch_add(1);
            if (i >= FilesToSearch.size())
                break;

            const auto &Path = FilesToSearch[i];

            std::vector<MatchPosition_t> Matches;

            if (UseRegex)
                Matches = Stream_SearchRegex(Path, Query, CaseSensitive);
            else
            {
                std::ifstream FileStream(Path, std::ios::binary);

                if (!FileStream)
                    continue;

                Matches = Stream_Search(FileStream, Query, CaseSensitive);
            }

            nlohmann::json Chunk = nlohmann::json::array();

            for (auto &Match : Matches)
            {
                MatchInfo_t info = Stream_ExtractMatchInfo(Path, Match.Offset, Match.Length);

                if (WholeWord && !IsWholeWord(info.LineText, info.MatchStart, Match.Length))
                    continue;

                Chunk.push_back({{"file", Functions::FullPathToVFSPath(Path.string())},
                                 {"line", info.Line},
                                 {"lineText", info.LineText},
                                 {"matchStart", info.MatchStart},
                                 {"matchEnd", info.MatchEnd}});
            }

            if (!Chunk.empty())
            {
                std::lock_guard<std::mutex> Lock(QueueMutex);

                Queue.push(std::move(Chunk));
                QueueSignal.notify_one();
            }
        }

        Active--;
        QueueSignal.notify_one();
    };

    for (unsigned i = 0; i < WorkerCount; i++)
        Threads.emplace_back(WorkerThread);

    nlohmann::json Pending = nlohmann::json::array();
    size_t PendingBytes = 0;
    auto LastResultSent = std::chrono::steady_clock::now() - SEARCH_RESULT_CHUNK_INTERVAL;

    while (true)
    {
        if (CurrentSearchIDs[ClientId] != RequestId)
            break;

        std::unique_lock<std::mutex> Lock(QueueMutex);

        QueueSignal.wait_for(Lock, std::chrono::milliseconds(50), [&] { return !Queue.empty() || Active.load() == 0; });

        while (!Queue.empty())
        {
            auto Item = std::move(Queue.front());
            Queue.pop();

            for (auto &Match : Item)
            {
                size_t Size = EstimatePacketSize(Match);

                if (PendingBytes + Size > SEARCH_RESULT_CHUNK_MAX_SIZE)
                    break;

                Pending.push_back(std::move(Match));
                PendingBytes += Size;
            }
        }

        Lock.unlock();

        auto Now = std::chrono::steady_clock::now();

        if (!Pending.empty() && Now - LastResultSent >= SEARCH_RESULT_CHUNK_INTERVAL)
        {
            this->SendRPCStreamChunk(ClientId, RequestId, Pending);
            Pending.clear();
            PendingBytes = 0;
            LastResultSent = Now;
        }

        if (Active.load() == 0)
            break;
    }

    Cancel.store(true);

    for (auto &Thread : Threads)
        if (Thread.joinable())
            Thread.join();

    if (CurrentSearchIDs[ClientId] != RequestId)
        return;

    if (!Pending.empty())
        this->SendRPCStreamChunk(ClientId, RequestId, Pending);

    this->StopRPCStream(ClientId, RequestId);
}
} // namespace Remote::Socket