// IMP-007 ground-truth fixture: C++ objects WITHOUT virtual functions (base-class member,
// public/private members, operator new). Prints BLOCK <addr> <size> <path> lines, READY, blocks.
#include <cstdio>
#include <cstring>
#include <unistd.h>

class Base {
public:
    char *label;
    int id;
};

class Widget : public Base {
public:
    Widget *peer;
    int *data;
    long count;
};

struct Registry {
    Widget **slots;
    int nslots;
};

Widget *g_widget;
Registry g_registry;

int main()
{
    std::setvbuf(stdout, nullptr, _IOFBF, 1 << 16);
    g_widget = new Widget();
    g_widget->label = new char[20];
    std::strcpy(g_widget->label, "root-widget");
    g_widget->data = new int[12];
    g_widget->peer = new Widget();
    g_widget->peer->label = new char[31];
    g_widget->peer->data = new int[3];
    g_registry.nslots = 4;
    g_registry.slots = new Widget *[4];
    for (int i = 0; i < 4; i++) {
        g_registry.slots[i] = new Widget();
        g_registry.slots[i]->data = new int[5 + i];
    }
    std::printf("BLOCK %p %zu g_widget\n", (void *)g_widget, sizeof(Widget));
    std::printf("BLOCK %p 20 g_widget->label\n", (void *)g_widget->label);
    std::printf("BLOCK %p %zu g_widget->data\n", (void *)g_widget->data, 12 * sizeof(int));
    std::printf("BLOCK %p %zu g_widget->peer\n", (void *)g_widget->peer, sizeof(Widget));
    std::printf("BLOCK %p 31 g_widget->peer->label\n", (void *)g_widget->peer->label);
    std::printf("BLOCK %p %zu g_widget->peer->data\n", (void *)g_widget->peer->data, 3 * sizeof(int));
    std::printf("BLOCK %p %zu g_registry.slots\n", (void *)g_registry.slots, 4 * sizeof(Widget *));
    for (int i = 0; i < 4; i++) {
        std::printf("BLOCK %p %zu g_registry.slots[%d]\n", (void *)g_registry.slots[i], sizeof(Widget), i);
        std::printf("BLOCK %p %zu g_registry.slots[%d]->data\n", (void *)g_registry.slots[i]->data,
                    (5 + i) * sizeof(int), i);
    }
    std::printf("READY\n");
    std::fflush(stdout);
    for (;;)
        pause();
}
