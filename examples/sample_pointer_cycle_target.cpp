#include <unistd.h>
#include <cstdio>

struct NodeB;

struct SharedNode {
    int shared_val;
};

struct NodeA {
    NodeB* next_b;
    SharedNode* shared;
    int a_val;
};

struct NodeB {
    NodeA* next_a;
    SharedNode* shared;
    int b_val;
};

SharedNode g_shared{777};
NodeA g_node_a{nullptr, &g_shared, 100};
NodeB g_node_b{&g_node_a, &g_shared, 200};

int main() {
    g_node_a.next_b = &g_node_b;
    printf("Pointer and cycle sample running. PID: %d\n", getpid());
    fflush(stdout);
    while (true) {
        usleep(100000);
    }
    return 0;
}
