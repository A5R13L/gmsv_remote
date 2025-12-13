#include "remote/core/core.h"

GMOD_MODULE_OPEN() {
    Remote::Core::Initialize(LUA);

    return 0;
}

GMOD_MODULE_CLOSE() {
    Remote::Core::Shutdown(LUA);

    return 0;
}