#pragma once
#include <GarrysMod/Lua/LuaBase.h>
#include <GarrysMod/Lua/Interface.h>
#include <GarrysMod/InterfacePointers.hpp>
#include <filesystem_base.h>
#include <eiface.h>
#include <icvar.h>
#include <string>
#include <iostream>
#include <functional>
#include <filesystem>
#include <fstream>
#include <thread>
#include <map>
#include <sstream>
#include <regex>
#include <set>
#include <queue>
#include <json.hpp>
#include <base64.hpp>
#include <IXWebSocket.h>
#include <IXNetSystem.h>

#ifndef REMOTE_VERSION
#define REMOTE_VERSION "unknown"
#endif

namespace Remote
{
} // namespace Remote