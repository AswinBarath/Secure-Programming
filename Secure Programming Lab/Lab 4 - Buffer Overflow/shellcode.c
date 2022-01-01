#include
#include
#include
main()
{
char* argv[] = {"/bin/sh", NULL};
char* env[] = {"FLAG=1", NULL};
execve(argv[0], argv, env);
printf("execve failed");
}