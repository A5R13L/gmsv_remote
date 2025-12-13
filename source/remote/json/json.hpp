#pragma once
#include "../includes.h"

namespace JSON
{
const int INVALID_INTEGER = -0x7FFFFFFF;

static std::string String(const nlohmann::json &Object, const std::string &Key)
{
    if (Object.is_null() || !Object.contains(Key) || !Object[Key].is_string())
        return "";

    return Object[Key].get<std::string>();
}

static int Integer(const nlohmann::json &Object, const std::string &Key)
{
    if (Object.is_null() || !Object.contains(Key) || !Object[Key].is_number_integer())
        return INVALID_INTEGER;

    return Object[Key].get<int>();
}

static bool Boolean(const nlohmann::json &Object, const std::string &Key)
{
    if (Object.is_null() || !Object.contains(Key) || !Object[Key].is_boolean())
        return false;

    return Object[Key].get<bool>();
}

static nlohmann::json Object(const nlohmann::json &Object, const std::string &Key)
{
    if (Object.is_null() || !Object.contains(Key) || !Object[Key].is_object())
        return nlohmann::json();

    return Object[Key].get<nlohmann::json>();
}

static std::string Stringify(const nlohmann::json &Object)
{
    return Object.dump();
}

static nlohmann::json Parse(const std::string &String)
{
    try
    {
        return nlohmann::json::parse(String);
    }
    catch (...)
    {
        return nlohmann::json();
    }
}

static bool ValidInteger(int &Value)
{
    return Value != INVALID_INTEGER;
}
} // namespace JSON