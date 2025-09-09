#include <dlfcn.h>
#include <stdio.h>
#include <stdbool.h>

int main(void) {
    void *h = dlopen("./SidecarCore", RTLD_NOW);
    if (!h) {
        printf("Erreur dlopen: %s\n", dlerror());
        return 1;
    }

    typedef bool (*fn_t)(void*);
    fn_t f = (fn_t)dlsym(h, "_SidecarDisplayIsSupportedReceivingDevice");
    if (!f) {
        printf("Erreur dlsym: %s\n", dlerror());
        return 1;
    }

    // appel de test (argument NULL pour simplifier)
    bool ok = f(NULL);
    printf("Résultat de l'appel: %d\n", ok);

    return 0;
}
