#pragma once
#include <string>

inline std::string XORString(const std::string &input, const std::string &key)
{
    std::string output;
    output.resize(input.size());

    for (size_t i = 0; i < input.size(); ++i)
        output[i] = input[i] ^ key[i % key.size()];

    return output;
}