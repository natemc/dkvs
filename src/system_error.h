#pragma once

#include <system_error>

#define SYSTEM_ERROR_CODE(code, msg) \
    std::system_error(code, std::generic_category(), msg)
#define SYSTEM_ERROR_MSG(msg) SYSTEM_ERROR_CODE(errno, msg)
#define SYSTEM_ERROR(context) SYSTEM_ERROR_MSG(#context)
