#pragma once

#include "common.h"

typedef int (*parse_config_cb_t)(void* arg, const char* section, const char* name, const char* value);

int parse_config_file(const char* path, parse_config_cb_t cb, void* arg);
