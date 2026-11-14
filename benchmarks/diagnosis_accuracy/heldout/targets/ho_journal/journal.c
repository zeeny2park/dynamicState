/* Append-only journal of records, newest first. */
#include <string.h>
#include "journal.h"
#include "mem.h"

struct journal_tab journal;

void journal_append(unsigned seq)
{
    struct rec *r = mem_get(sizeof *r);
    r->seq = seq;
    memset(r->payload, (int)(seq & 0x7f), sizeof r->payload);
    r->link = journal.first;
    journal.first = r;
    journal.count++;
}
