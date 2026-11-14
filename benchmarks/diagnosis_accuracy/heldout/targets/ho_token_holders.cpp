// Auth tokens: a token can be shared by the primary and the backup holder; each holder releases what it holds.
#include <unistd.h>

#include <cstring>

struct Token {
    long id;
    char text[40];
};

class Holder {
public:
    void hold(Token *t) { tok = t; }
    void release() { delete tok; }
    Token *tok = nullptr;
};

static Holder g_primary;
static Holder g_backup;
static Token *g_scratch[7];

static Token *make_token(long id)
{
    Token *t = new Token;
    t->id = id;
    std::strcpy(t->text, "bearer");
    return t;
}

int main()
{
    Token *shared = make_token(1);
    Token *other = make_token(2);
    g_primary.hold(shared);
    g_backup.hold(shared);
    for (int i = 0; i < 7; i++)
        g_scratch[i] = make_token(10 + i);
    for (int i = 0; i < 7; i++)
        delete g_scratch[i];
    g_primary.release();
    delete other;
    g_backup.release();
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
