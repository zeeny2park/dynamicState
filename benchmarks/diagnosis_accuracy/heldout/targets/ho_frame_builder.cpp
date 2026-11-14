// Wire frame builder: header and body are appended into one preallocated buffer.
#include <unistd.h>

#include <cstddef>
#include <cstring>

class FrameBuilder {
public:
    explicit FrameBuilder(size_t cap) : buf_(new unsigned char[cap]), cap_(cap) {}

    void append(const unsigned char *src, size_t n)
    {
        std::memcpy(buf_ + used_, src, n);
        used_ += n;
    }

    size_t used() const { return used_; }

private:
    unsigned char *buf_;
    size_t cap_;
    size_t used_ = 0;
};

static FrameBuilder *g_frame;
static unsigned char *g_trailer;

int main(int argc, char **)
{
    unsigned char header[32];
    unsigned char body[64];
    size_t body_len = 40 + (size_t)(argc - 1);
    std::memset(header, 'H', sizeof header);
    std::memset(body, 'B', sizeof body);
    g_frame = new FrameBuilder(48);
    g_trailer = new unsigned char[48];
    std::memset(g_trailer, 0, 48);
    g_frame->append(header, sizeof header);
    g_frame->append(body, body_len);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
