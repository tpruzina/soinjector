#include <stdio.h>
#include <dlfcn.h>

void
print()
{
	print("load successful\n");
}

__attribute__((constructor)) void
loadMsg()
{
	print();
}
