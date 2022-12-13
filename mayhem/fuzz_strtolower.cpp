#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>

extern "C" void print_version(void);
extern "C" char *strtolower(char *str);

int dplaces_nr = -1;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    char* x = strdup(provider.ConsumeRandomLengthString().c_str());
    strtolower(x);
    free(x);

    return 0;
}