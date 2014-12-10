/*
 * The method is to intercept the exec() family of functions and handle them in
 * a more DIOS way.
 *
 * Interception is acheived by preprocessor defines and the implementations
 * here are taken from glibc 2.20.
 *
 * The magic happens in dizi_execve which checks if a executable is a DIOS
 * executable or a legacy executable and handles it appropriately.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>

#define HAVE_LIBC
#include <shared/dios.h>
#include <shared/types.h>
#include <shared/syscalls.h>

#include "libbb.h"

int dizi_execve(const char *filename, char *const argv[], char *const envp[]);
int dizi_execl(const char *path, const char *arg, ...);
int dizi_execle(const char *path, const char *arg, ...);
int dizi_execv(const char *path, char *const argv[]) ;
int dizi_execvp(const char *file, char *const argv[]) ;
int dizi_execlp(const char *file, const char *arg, ...) ;

#define __MAX_ALLOCA_CUTOFF 65536
#define __libc_use_alloca(size) (size <= __MAX_ALLOCA_CUTOFF)

int dizi_execl(const char *path, const char *arg, ...) {
  #define INITIAL_ARGV_MAX 1024
  size_t argv_max = INITIAL_ARGV_MAX;
  const char *initial_argv[INITIAL_ARGV_MAX];
  const char **argv = initial_argv;
  va_list args;
 
  argv[0] = arg;
 
  va_start (args, arg);
  unsigned int i = 0;
  while (argv[i++] != NULL)
  {
    if (i == argv_max)
    {
      argv_max *= 2;
      const char **nptr = realloc (argv == initial_argv ? NULL : argv,
      argv_max * sizeof (const char *));
      if (nptr == NULL)
      {
        if (argv != initial_argv)
          free (argv);
        return -1;
      }
      if (argv == initial_argv)
        /* We have to copy the already filled-in data ourselves. */
        memcpy (nptr, argv, i * sizeof (const char *));
     
      argv = nptr;
    }
   
    argv[i] = va_arg (args, const char *);
  }
  va_end (args);
 
  int ret = dizi_execve (path, (char *const *) argv, __environ);
  if (argv != initial_argv)
    free (argv);
 
  return ret;
}

int dizi_execle(const char *path, const char *arg, ...) {
  #define INITIAL_ARGV_MAX 1024
  size_t argv_max = INITIAL_ARGV_MAX;
  const char *initial_argv[INITIAL_ARGV_MAX];
  const char **argv = initial_argv;
  va_list args;
  argv[0] = arg;
 
  va_start (args, arg);
  unsigned int i = 0;
  while (argv[i++] != NULL)
  {
    if (i == argv_max)
    {
      argv_max *= 2;
      const char **nptr = realloc (argv == initial_argv ? NULL : argv,
      argv_max * sizeof (const char *));
      if (nptr == NULL)
      {
        if (argv != initial_argv)
          free (argv);
        return -1;
      }
      if (argv == initial_argv)
        /* We have to copy the already filled-in data ourselves. */
        memcpy (nptr, argv, i * sizeof (const char *));
 
      argv = nptr;
    }
 
    argv[i] = va_arg (args, const char *);
  }
 
  const char *const *envp = va_arg (args, const char *const *);
  va_end (args);
 
  int ret = dizi_execve (path, (char *const *) argv, (char *const *) envp);
  if (argv != initial_argv)
    free (argv);
 
  return ret;
}

int dizi_execv(const char *path, char *const argv[])  {
  return dizi_execve(path, argv, __environ);
}

/* The file is accessible but it is not an executable file. Invoke
 the shell to interpret it as a script. */
static void scripts_argv (const char *file, char *const argv[], int argc, char **new_argv)
{
  /* Construct an argument list for the shell. */
  new_argv[0] = (char *) _PATH_BSHELL;
  new_argv[1] = (char *) file;
  while (argc > 1)
  {
    new_argv[argc] = argv[argc - 1];
    --argc;
  }
}

int dizi_execvp(const char *file, char *const argv[])  {
  char** envp = __environ;

  if (*file == '\0')
  {
    /* We check the simple case first. */
    errno = (ENOENT);
    return -1;
  }
 
  if (strchr (file, '/') != NULL)
  {
    /* Don't search when it contains a slash. */
    dizi_execve (file, argv, envp);
   
    if (errno == ENOEXEC)
    {
      /* Count the arguments. */
      int argc = 0;
      while (argv[argc++])
      ;
      size_t len = (argc + 1) * sizeof (char *);
      char **script_argv;
      void *ptr = NULL;
      if (__libc_use_alloca (len))
        script_argv = alloca (len);
      else
        script_argv = ptr = malloc (len);
     
      if (script_argv != NULL)
      {
        scripts_argv (file, argv, argc, script_argv);
        dizi_execve (script_argv[0], script_argv, envp);
       
        free (ptr);
      }
    }
  }
  else
  {
    size_t pathlen;
    size_t alloclen = 0;
    char *path = getenv ("PATH");
    if (path == NULL)
    {
      pathlen = confstr (_CS_PATH, (char *) NULL, 0);
      alloclen = pathlen + 1;
    }
    else
      pathlen = strlen (path);
 
    size_t len = strlen (file) + 1;
    alloclen += pathlen + len + 1;
 
    char *name;
    char *path_malloc = NULL;
    if (__libc_use_alloca (alloclen))
      name = alloca (alloclen);
    else
    {
      path_malloc = name = malloc (alloclen);
      if (name == NULL)
      return -1;
    }
 
    if (path == NULL)
    {
      /* There is no `PATH' in the environment.
      The default search path is the current directory
      followed by the path `confstr' returns for `_CS_PATH'. */
      path = name + pathlen + len + 1;
      path[0] = ':';
      (void) confstr (_CS_PATH, path + 1, pathlen);
    }
 
    /* Copy the file name at the top. */
    name = (char *) memcpy (name + pathlen + 1, file, len);
    /* And add the slash. */
    *--name = '/';
 
    char **script_argv = NULL;
    void *script_argv_malloc = NULL;
    bool got_eacces = false;
    char *p = path;
    do
    {
      char *startp;
 
      path = p;
      p = __strchrnul (path, ':');
 
      if (p == path)
        /* Two adjacent colons, or a colon at the beginning or the end
        of `PATH' means to search the current directory. */
        startp = name + 1;
      else
        startp = (char *) memcpy (name - (p - path), path, p - path);
 
      /* Try to execute this name. If it works, execve will not return. */
      dizi_execve (startp, argv, envp);
 
      if (errno == ENOEXEC)
      {
        if (script_argv == NULL)
        {
          /* Count the arguments. */
          int argc = 0;
          while (argv[argc++]);
          size_t arglen = (argc + 1) * sizeof (char *);
          if (__libc_use_alloca (alloclen + arglen))
            script_argv = alloca (arglen);
          else
            script_argv = script_argv_malloc = malloc (arglen);
          if (script_argv == NULL)
          {
            /* A possible EACCES error is not as important as
            the ENOMEM. */
            got_eacces = false;
            break;
          }
          scripts_argv (startp, argv, argc, script_argv);
        }
 
        dizi_execve (script_argv[0], script_argv, envp);
      }
 
      switch (errno)
      {
      case EACCES:
        /* Record the we got a `Permission denied' error. If we end
        up finding no executable we can use, we want to diagnose
        that we did find one but were denied access. */
        got_eacces = true;
      case ENOENT:
      case ESTALE:
      case ENOTDIR:
        /* Those errors indicate the file is missing or not executable
        by us, in which case we want to just try the next path
        directory. */
      case ENODEV:
      case ETIMEDOUT:
        /* Some strange filesystems like AFS return even
        stranger error numbers. They cannot reasonably mean
        anything else so ignore those, too. */
      break;
 
      default:
        /* Some other error means we found an executable file, but
        something went wrong executing it; return the error to our
        caller. */
        return -1;
      }
    }
    while (*p++ != '\0');
 
    /* We tried every element and none of them worked. */
    if (got_eacces)
      /* At least one failure was due to permissions, so report that
      error. */
      errno = (EACCES);
 
    free (script_argv_malloc);
    free (path_malloc);
  }
 
  /* Return the error from the last attempt (probably ENOENT). */
  return -1;
}

int dizi_execlp(const char *file, const char *arg, ...)  {
  #define INITIAL_ARGV_MAX 1024
  size_t argv_max = INITIAL_ARGV_MAX;
  const char *initial_argv[INITIAL_ARGV_MAX];
  const char **argv = initial_argv;
  va_list args;
 
  argv[0] = arg;
 
  va_start (args, arg);
  unsigned int i = 0;
  while (argv[i++] != NULL)
  {
    if (i == argv_max)
    {
      argv_max *= 2;
      const char **nptr = realloc (argv == initial_argv ? NULL : argv,
      argv_max * sizeof (const char *));
      if (nptr == NULL)
      {
        if (argv != initial_argv)
          free (argv);
        return -1;
      }
      if (argv == initial_argv)
        /* We have to copy the already filled-in data ourselves. */
        memcpy (nptr, argv, i * sizeof (const char *));
 
      argv = nptr;
    }
 
    argv[i] = va_arg (args, const char *);
  }
  va_end (args);
 
  int ret = dizi_execvp (file, (char *const *) argv);
  if (argv != initial_argv)
    free (argv);
 
  return ret;
}

/*
 * Attempt to run as a DIOS executable. If it is not DIOS this will fail on the
 * lookup.
 * FIXME: Uses the hash of the file path which is a hack
 */
static int __run_dios_file(const char* filename, char *const argv[]) {
  dios_name_t name;
  sha256_ctx_t shactx;
  dios_ref_t* ref;
  uint64_t rc = 1;
  dios_ref_t* new_ref;

  dios_task_spec_t ts = {
    .input_count = 0,
    .output_count = 0,
    .argv = argv,
    .argc = 0,
  };

  // Count the arguments
  while (argv[++ts.argc]);

  // Convert filename to DIOS name
  sha256_begin(&shactx);
  if (strlen(filename) > 4096) {
    errno = EINVAL;
    return -1;
  }
  sha256_hash(&shactx, filename, strlen(filename));
  sha256_end(&shactx, &name);

  // name -> reference
  if (dios_lookup(D_NONE, &name, &ref, &rc) != 0)
    return -1;

  if (rc == 0) {
    errno = ENOENT;
    return -1;
  }

  // run task
  if (dios_run(D_NONE, ref, &ts, &new_ref) != 0) {
    return -1;
  }

  return 0;
}

// dizi_execve will call the correct version for legacy apps
#undef execve
extern int execve(const char* filename, char *const argv[], char *const envp[]);

int dizi_execve(const char *filename, char *const argv[], char *const envp[]) {
  // Try and run as a DIOS executable
  if (__run_dios_file(filename, argv) == 0) {
    // evecve is meant to replace the current process but with DIOS we spawn a
    // new one so 
    _Exit(0);
  }

  // If the failure was because it wasn't found then maybe it is legacy
  // If the failure was because DIOS is not loaded then try legacy
  if (errno == ENOENT || errno == ENOSYS) {
    return execve(filename, argv, envp);
  }

  return -1;
}
