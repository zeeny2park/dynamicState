extern int sink(int);

int clobbered(int val, int other)
{
    int a = sink(val);
    int b = sink(a + other);
    return b + val * 2 + other;
}
