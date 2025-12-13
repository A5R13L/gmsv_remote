#pragma once
#include "../includes.h"
#include "../logger/logger.h"

#ifdef REMOTE_32_SERVER
extern IFileSystem *g_pFullFileSystem;
#endif

extern IVEngineServer *g_pVEngineServer;
extern ICvar *g_pCvar;

namespace Remote::Core
{
void Initialize(GarrysMod::Lua::ILuaBase *LUA);
void Shutdown(GarrysMod::Lua::ILuaBase *LUA);
nlohmann::json LoadConfig(const std::filesystem::path &Path);
} // namespace Remote::Core