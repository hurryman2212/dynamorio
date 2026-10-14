/* Standard-stream identities are shared by private libc; their backing files
 * and follow/closed state belong to the current kernel descriptor table. */
#ifndef STDIO_ROLES_H
#define STDIO_ROLES_H

bool
os_stdio_init(void);
void
os_stdio_exit(void);
void
os_stdio_private_loaded(void);
/* Explicit native-to-managed start only, before thread synchronization. */
void
os_stdio_refresh(void);
void
os_stdio_fd_replaced(file_t fd);
void
os_stdio_fd_closing(file_t fd);
bool
os_stdio_tracks_syscall(int sysnum);
void
os_stdio_post_syscall(dcontext_t *dcontext, int sysnum, bool success, reg_t result);

/* Implemented by the file-table domain owner. Opening and rebinding aliases
 * keep creation, CLOEXEC and protected-FD registration in one transaction. */
bool
os_stdio_open_aliases(file_t aliases[3], uint enabled);
bool
os_stdio_bind_alias(file_t source, file_t alias);
bool
os_stdio_refresh_alias(file_t source, file_t alias);
uint
os_stdio_following(void);
void
os_stdio_stop_following(uint stream);
uint
os_stdio_pending(void);

#endif /* STDIO_ROLES_H */
