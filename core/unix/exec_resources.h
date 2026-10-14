/* Private early-exec resource service. Descriptors are always CLOEXEC: the
 * existing client broker transfers references to each new runtime image. */
#ifndef EXEC_RESOURCES_H
#define EXEC_RESOURCES_H

#include "../lib/dr_exec_resources.h"

bool
os_exec_resources_bootstrap(void);
void
os_exec_resources_release_bootstrap(void);
file_t
os_exec_resource_file(uint role);
file_t
os_exec_resource_take(uint role);
file_t
os_exec_resource_lookup(const char *name, const char **path);
bool
os_exec_resources_set_service(file_t broker);
file_t
os_exec_resources_service(void);
bool
os_exec_resources_register(uint64 nonce, file_t target, const char *path,
                           file_t proc_root);

#endif
