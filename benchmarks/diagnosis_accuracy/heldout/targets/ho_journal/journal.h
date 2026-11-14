#ifndef JOURNAL_H
#define JOURNAL_H
struct rec {
    struct rec *link;
    unsigned seq;
    char payload[700];
};

struct journal_tab {
    struct rec *first;
    unsigned count;
};

extern struct journal_tab journal;
void journal_append(unsigned seq);
#endif
