#pragma once

#include "common.h"

struct pkg;
struct pfs;

int pkg_generate_gp4_project(struct pkg* pkg, struct pfs* pfs, const char* in_meta_data_file_path, const char* file_path, const char* output_directory, const char* out_meta_data_file_path, int use_random_passcode, int all_compressed);
