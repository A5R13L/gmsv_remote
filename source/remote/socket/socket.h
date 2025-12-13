#pragma once
#include "../includes.h"

namespace Remote::Socket
{
class SocketServer
{
  public:
    static SocketServer Singleton;
    SocketServer();
    ~SocketServer();
    void Connect(const std::string &RelayURL, const std::string &Password);
    void Disconnect();
    void HandlePacket(const nlohmann::json &Packet);
    void SendRPCResponse(std::string &ClientId, int &RequestId, const nlohmann::json &Response);
    void StartRPCStream(std::string ClientId, int RequestId);
    void SendRPCStreamChunk(std::string ClientId, int RequestId, const nlohmann::json &Chunk);
    void SendRPCStreamChunk(std::string ClientId, int RequestId, const std::string &Chunk);
    void StopRPCStream(std::string ClientId, int RequestId);
    void HandleListFiles(std::string ClientId, int RequestId, const nlohmann::json &Payload);
    void HandleRead(std::string ClientId, int RequestId, const nlohmann::json &Payload);
    void HandleWrite(std::string ClientId, int RequestId, const nlohmann::json &Payload);
    void HandleDelete(std::string ClientId, int RequestId, const nlohmann::json &Payload);
    void HandleMkdir(std::string ClientId, int RequestId, const nlohmann::json &Payload);
    void HandleRename(std::string ClientId, int RequestId, const nlohmann::json &Payload);
    void HandleCopy(std::string ClientId, int RequestId, const nlohmann::json &Payload);
    void HandleMove(std::string ClientId, int RequestId, const nlohmann::json &Payload);
    void HandleExists(std::string ClientId, int RequestId, const nlohmann::json &Payload);
    void HandleStat(std::string ClientId, int RequestId, const nlohmann::json &Payload);
    void HandleTruncate(std::string ClientId, int RequestId, const nlohmann::json &Payload);
    void HandleSearch(std::string ClientId, int RequestId, const nlohmann::json &Payload);
    void HandleReplace(std::string ClientId, int RequestId, const nlohmann::json &Payload);

  private:
    bool Connected = false;
    std::string RelayURL;
    std::string Password;
};
} // namespace Remote::Socket