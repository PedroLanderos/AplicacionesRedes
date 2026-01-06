/*
  Mini-Plataforma P2P en C (Windows / WinSock2)
  - Chat P2P (directo y broadcast)
  - Busqueda distribuida (flood TTL)
  - Intercambio de archivos (GET)
  - Seguridad basica (PSK auth + XOR "cifrado" demo)
  - Voz por UDP (stream de archivo como demo)
*/

#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <process.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

// -------------------------- Config --------------------------
#define MAX_PEERS        64
#define MAX_LINE         4096
#define MAX_SHARE        128
#define MAX_SEEN         256
#define LISTEN_BACKLOG   16

// -------------------------- Utils --------------------------
static void die(const char* msg) {
    fprintf(stderr, "[FATAL] %s (err=%d)\n", msg, WSAGetLastError());
    exit(1);
}

static uint32_t fnv1a_32(const void* data, size_t len) {
    const unsigned char* p = (const unsigned char*)data;
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}

static void u32_to_hex8(uint32_t v, char out[9]) {
    static const char* hx = "0123456789abcdef";
    for (int i = 0; i < 8; i++) {
        out[7 - i] = hx[v & 0xF];
        v >>= 4;
    }
    out[8] = '\0';
}

static void bytes_to_hex(const uint8_t* in, size_t n, char* out /*2n+1*/) {
    static const char* hx = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = hx[(in[i] >> 4) & 0xF];
        out[2 * i + 1] = hx[in[i] & 0xF];
    }
    out[2 * n] = '\0';
}

static int hex_to_bytes(const char* in, uint8_t* out, size_t outcap) {
    size_t len = strlen(in);
    if (len % 2 != 0) return -1;
    size_t n = len / 2;
    if (n > outcap) return -1;

    for (size_t i = 0; i < n; i++) {
        char a = in[2 * i];
        char b = in[2 * i + 1];
        uint8_t da = 0, db = 0;

        if (a >= '0' && a <= '9') da = (uint8_t)(a - '0');
        else if (a >= 'a' && a <= 'f') da = (uint8_t)(a - 'a' + 10);
        else if (a >= 'A' && a <= 'F') da = (uint8_t)(a - 'A' + 10);
        else return -1;

        if (b >= '0' && b <= '9') db = (uint8_t)(b - '0');
        else if (b >= 'a' && b <= 'f') db = (uint8_t)(b - 'a' + 10);
        else if (b >= 'A' && b <= 'F') db = (uint8_t)(b - 'A' + 10);
        else return -1;

        out[i] = (uint8_t)((da << 4) | db);
    }
    return (int)n;
}

static void xor_crypt(uint8_t* data, size_t n, uint32_t key) {
    uint32_t s = key ? key : 0xA5A5A5A5u;
    for (size_t i = 0; i < n; i++) {
        s = 1664525u * s + 1013904223u;
        data[i] ^= (uint8_t)(s & 0xFF);
    }
}

static void trim_newline(char* s) {
    size_t n = strlen(s);
    while (n && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
        s[n - 1] = '\0';
        n--;
    }
}

static const char* strcasestr_simple(const char* haystack, const char* needle) {
    if (!haystack || !needle) return NULL;
    if (*needle == '\0') return haystack;

    for (const char* h = haystack; *h; h++) {
        const char* p1 = h;
        const char* p2 = needle;

        while (*p1 && *p2) {
            char c1 = *p1;
            char c2 = *p2;

            if (c1 >= 'A' && c1 <= 'Z') c1 = (char)(c1 - 'A' + 'a');
            if (c2 >= 'A' && c2 <= 'Z') c2 = (char)(c2 - 'A' + 'a');

            if (c1 != c2) break;

            p1++;
            p2++;
        }
        if (*p2 == '\0') return h;
    }
    return NULL;
}

static int starts_with(const char* s, const char* pre) {
    return strncmp(s, pre, strlen(pre)) == 0;
}

static void sockaddr_to_str(const struct sockaddr_in* a, char* out, size_t cap) {
    char ip[64];
    inet_ntop(AF_INET, &(a->sin_addr), ip, (DWORD)sizeof(ip));
    unsigned short port = ntohs(a->sin_port);
    _snprintf(out, cap, "%s:%hu", ip, port);
}

// -------------------------- Data Structures --------------------------
typedef struct {
    char path[MAX_PATH];
    char name[256];
    uint64_t size;
} SharedFile;

typedef struct {
    SOCKET sock;
    struct sockaddr_in addr;
    int active;

    int authed;
    uint32_t session_key;

    char user[64];

    char rbuf[MAX_LINE];
    int  rbuf_len;
} Peer;

typedef struct {
    char idhex[9];
} SeenId;

// -------------------------- Globals --------------------------
static Peer g_peers[MAX_PEERS];
static SharedFile g_share[MAX_SHARE];
static int g_share_count = 0;

static SeenId g_seen[MAX_SEEN];
static int g_seen_count = 0;

static CRITICAL_SECTION g_lock;

static SOCKET g_listen = INVALID_SOCKET;
static char g_username[64];
static char g_psk[128];
static uint16_t g_listen_port = 0;

// -------------------------- Command Queue --------------------------
typedef struct CmdNode {
    char line[MAX_LINE];
    struct CmdNode* next;
} CmdNode;

static CmdNode* g_cmd_head = NULL;
static CmdNode* g_cmd_tail = NULL;

static void enqueue_cmd(const char* line) {
    CmdNode* n = (CmdNode*)calloc(1, sizeof(CmdNode));
    strncpy(n->line, line, sizeof(n->line) - 1);
    n->next = NULL;

    EnterCriticalSection(&g_lock);
    if (!g_cmd_tail) {
        g_cmd_head = g_cmd_tail = n;
    } else {
        g_cmd_tail->next = n;
        g_cmd_tail = n;
    }
    LeaveCriticalSection(&g_lock);
}

static int dequeue_cmd(char* out, size_t cap) {
    EnterCriticalSection(&g_lock);
    CmdNode* n = g_cmd_head;
    if (!n) {
        LeaveCriticalSection(&g_lock);
        return 0;
    }
    g_cmd_head = n->next;
    if (!g_cmd_head) g_cmd_tail = NULL;
    LeaveCriticalSection(&g_lock);

    strncpy(out, n->line, cap - 1);
    out[cap - 1] = '\0';
    free(n);
    return 1;
}

// -------------------------- Peer Helpers --------------------------
static int add_peer(SOCKET s, struct sockaddr_in addr) {
    EnterCriticalSection(&g_lock);
    for (int i = 0; i < MAX_PEERS; i++) {
        if (!g_peers[i].active) {
            g_peers[i].sock = s;
            g_peers[i].addr = addr;
            g_peers[i].active = 1;
            g_peers[i].authed = 0;
            g_peers[i].session_key = 0;
            g_peers[i].user[0] = '\0';
            g_peers[i].rbuf_len = 0;
            LeaveCriticalSection(&g_lock);
            return i;
        }
    }
    LeaveCriticalSection(&g_lock);
    return -1;
}

static void remove_peer(int idx) {
    EnterCriticalSection(&g_lock);
    if (idx >= 0 && idx < MAX_PEERS && g_peers[idx].active) {
        closesocket(g_peers[idx].sock);
        g_peers[idx].active = 0;
    }
    LeaveCriticalSection(&g_lock);
}

static void list_peers(void) {
    EnterCriticalSection(&g_lock);
    printf("Peers:\n");
    for (int i = 0; i < MAX_PEERS; i++) {
        if (g_peers[i].active) {
            char addr[128];
            sockaddr_to_str(&g_peers[i].addr, addr, sizeof(addr));
            printf("  [%d] %s  authed=%d user=%s\n",
                i, addr, g_peers[i].authed,
                g_peers[i].user[0] ? g_peers[i].user : "(?)");
        }
    }
    LeaveCriticalSection(&g_lock);
}

static int send_raw(SOCKET s, const char* buf, int len) {
    int sent = 0;
    while (sent < len) {
        int n = send(s, buf + sent, len - sent, 0);
        if (n <= 0) return -1;
        sent += n;
    }
    return 0;
}

static int peer_send_plain_line(int idx, const char* line_plain) {
    EnterCriticalSection(&g_lock);
    int active = g_peers[idx].active;
    SOCKET s = active ? g_peers[idx].sock : INVALID_SOCKET;
    LeaveCriticalSection(&g_lock);
    if (!active) return -1;

    char out[MAX_LINE];
    _snprintf(out, sizeof(out), "%s\n", line_plain);
    return send_raw(s, out, (int)strlen(out));
}

static int peer_send_line(int idx, const char* plaintext_line) {
    EnterCriticalSection(&g_lock);
    Peer p = g_peers[idx];
    LeaveCriticalSection(&g_lock);

    if (!p.active) return -1;

    char out[MAX_LINE];
    if (!p.authed) {
        _snprintf(out, sizeof(out), "%s\n", plaintext_line);
        return send_raw(p.sock, out, (int)strlen(out));
    } else {
        size_t n = strlen(plaintext_line);
        if (n > 1400) n = 1400;
        uint8_t tmp[1600];
        memcpy(tmp, plaintext_line, n);

        xor_crypt(tmp, n, p.session_key);

        char hex[4000];
        bytes_to_hex(tmp, n, hex);

        _snprintf(out, sizeof(out), "ENC|%s\n", hex);
        return send_raw(p.sock, out, (int)strlen(out));
    }
}

static int peer_send_line_all(const char* plaintext_line) {
    int ok = 0;
    for (int i = 0; i < MAX_PEERS; i++) {
        EnterCriticalSection(&g_lock);
        int active = g_peers[i].active;
        int authed = g_peers[i].authed;
        LeaveCriticalSection(&g_lock);
        if (active && authed) {
            if (peer_send_line(i, plaintext_line) == 0) ok++;
        }
    }
    return ok;
}

// -------------------------- Shared Files --------------------------
static uint64_t file_size_u64(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) return 0;
    _fseeki64(f, 0, SEEK_END);
    __int64 sz = _ftelli64(f);
    fclose(f);
    return (sz < 0) ? 0 : (uint64_t)sz;
}

static const char* basename_simple(const char* path) {
    const char* s1 = strrchr(path, '\\');
    const char* s2 = strrchr(path, '/');
    const char* s = s1 > s2 ? s1 : s2;
    return s ? (s + 1) : path;
}

static void share_add(const char* path) {
    if (g_share_count >= MAX_SHARE) {
        printf("[share] Lista llena.\n");
        return;
    }
    uint64_t sz = file_size_u64(path);
    if (sz == 0) {
        printf("[share] No pude abrir archivo o es 0 bytes: %s\n", path);
        return;
    }
    SharedFile* sf = &g_share[g_share_count++];
    strncpy(sf->path, path, sizeof(sf->path) - 1);
    strncpy(sf->name, basename_simple(path), sizeof(sf->name) - 1);
    sf->size = sz;

    printf("[share] Compartiendo: %s (%llu bytes)\n", sf->name, (unsigned long long)sf->size);
}

static void share_list(void) {
    printf("Shared files:\n");
    for (int i = 0; i < g_share_count; i++) {
        printf("  - %s (%llu bytes) [%s]\n",
            g_share[i].name,
            (unsigned long long)g_share[i].size,
            g_share[i].path
        );
    }
}

static int share_find(const char* name, SharedFile* out) {
    for (int i = 0; i < g_share_count; i++) {
        if (_stricmp(g_share[i].name, name) == 0) {
            if (out) *out = g_share[i];
            return 1;
        }
    }
    return 0;
}

// -------------------------- Seen Search IDs --------------------------
static int seen_has(const char* idhex) {
    for (int i = 0; i < g_seen_count; i++) {
        if (_stricmp(g_seen[i].idhex, idhex) == 0) return 1;
    }
    return 0;
}

static void seen_add(const char* idhex) {
    if (seen_has(idhex)) return;
    if (g_seen_count < MAX_SEEN) {
        strncpy(g_seen[g_seen_count++].idhex, idhex, 9);
    } else {
        static int rr = 0;
        strncpy(g_seen[rr].idhex, idhex, 9);
        rr = (rr + 1) % MAX_SEEN;
    }
}

// -------------------------- Protocol Handling --------------------------
static void handle_app_message(int from_idx, const char* line_plain);

static int decode_incoming_allow_pre_auth(Peer* p, const char* line_in, char* out_plain, size_t cap) {
    if (!starts_with(line_in, "ENC|")) {
        strncpy(out_plain, line_in, cap - 1);
        out_plain[cap - 1] = '\0';
        return 0;
    }

    // Permite intentar descifrar si ya hay session_key aunque authed aún no esté en 1
    if (p->session_key == 0) return -1;

    const char* hex = line_in + 4;
    uint8_t tmp[2000];
    int n = hex_to_bytes(hex, tmp, sizeof(tmp));
    if (n < 0) return -1;

    xor_crypt(tmp, (size_t)n, p->session_key);
    size_t m = (size_t)n;
    if (m >= cap) m = cap - 1;
    memcpy(out_plain, tmp, m);
    out_plain[m] = '\0';
    return 0;
}

static void handle_auth(int idx, const char* line) {
    // AUTH|noncehex8|hashhex8|username
    char copy[MAX_LINE];
    strncpy(copy, line, sizeof(copy) - 1);
    copy[sizeof(copy) - 1] = '\0';

    char* tok = NULL;
    char* ctx = NULL;

    tok = strtok_s(copy, "|", &ctx); // AUTH
    tok = strtok_s(NULL, "|", &ctx); // nonce
    if (!tok) return;
    char noncehex[16]; strncpy(noncehex, tok, sizeof(noncehex) - 1); noncehex[sizeof(noncehex) - 1] = '\0';

    tok = strtok_s(NULL, "|", &ctx); // hash
    if (!tok) return;
    char hashhex[16]; strncpy(hashhex, tok, sizeof(hashhex) - 1); hashhex[sizeof(hashhex) - 1] = '\0';

    tok = strtok_s(NULL, "|", &ctx); // username
    if (!tok) tok = (char*)"peer";

    // expected hash = FNV(noncehex + psk)
    char material[512];
    _snprintf(material, sizeof(material), "%s%s", noncehex, g_psk);
    uint32_t h = fnv1a_32(material, strlen(material));
    char hhex[9];
    u32_to_hex8(h, hhex);

    if (_stricmp(hhex, hashhex) != 0) {
        printf("[auth] Peer %d auth FAILED.\n", idx);
        peer_send_plain_line(idx, "AUTHFAIL");
        remove_peer(idx);
        return;
    }

    // session key = FNV(psk + noncehex)
    char material2[512];
    _snprintf(material2, sizeof(material2), "%s%s", g_psk, noncehex);
    uint32_t sess = fnv1a_32(material2, strlen(material2));

    // Guarda session key pero NO marques authed todavía
    EnterCriticalSection(&g_lock);
    g_peers[idx].session_key = sess;
    strncpy(g_peers[idx].user, tok, sizeof(g_peers[idx].user) - 1);
    LeaveCriticalSection(&g_lock);

    // Manda AUTHOK EN PLANO (clave del arreglo)
    char okline[MAX_LINE];
    _snprintf(okline, sizeof(okline), "AUTHOK|%s", g_username);
    peer_send_plain_line(idx, okline);

    // Ahora sí: authed=1
    EnterCriticalSection(&g_lock);
    g_peers[idx].authed = 1;
    LeaveCriticalSection(&g_lock);

    printf("[auth] Peer %d authed as '%s'.\n", idx, tok);
}

static void handle_plain_control(int idx, const char* line) {
    if (starts_with(line, "AUTH|")) {
        handle_auth(idx, line);
        return;
    }

    if (starts_with(line, "AUTHOK|")) {
        const char* user = line + 7;

        EnterCriticalSection(&g_lock);
        g_peers[idx].authed = 1;
        if (user && *user) {
            strncpy(g_peers[idx].user, user, sizeof(g_peers[idx].user) - 1);
        }
        LeaveCriticalSection(&g_lock);

        printf("[auth] Auth OK with peer %d (server user: %s).\n", idx, user && *user ? user : "?");
        return;
    }

    if (starts_with(line, "AUTHOK")) {
        EnterCriticalSection(&g_lock);
        g_peers[idx].authed = 1;
        LeaveCriticalSection(&g_lock);
        printf("[auth] Auth OK with peer %d.\n", idx);
        return;
    }

    if (starts_with(line, "AUTHFAIL")) {
        printf("[auth] Server rejected auth.\n");
        remove_peer(idx);
        return;
    }
}

// -------------------------- File Receive (when we request GET) --------------------------
static void handle_file_incoming(int idx, const char* file_line_plain) {
    char copy[MAX_LINE];
    strncpy(copy, file_line_plain, sizeof(copy)-1);
    copy[sizeof(copy)-1]=0;

    char* ctx=NULL;
    strtok_s(copy, "|", &ctx); // FILE
    char* fname = strtok_s(NULL, "|", &ctx);
    char* szs   = strtok_s(NULL, "|", &ctx);
    if (!fname || !szs) return;

    uint64_t size = _strtoui64(szs, NULL, 10);
    if (size == 0) {
        printf("[file] Invalid size.\n");
        return;
    }

    char outpath[MAX_PATH];
    _snprintf(outpath, sizeof(outpath), "%s", fname);

    FILE* f = fopen(outpath, "wb");
    if (!f) {
        printf("[file] Cannot open output: %s\n", outpath);
        return;
    }

    EnterCriticalSection(&g_lock);
    SOCKET s = g_peers[idx].sock;
    LeaveCriticalSection(&g_lock);

    char buf[8192];
    uint64_t remaining = size;
    while (remaining > 0) {
        int want = (remaining > sizeof(buf)) ? (int)sizeof(buf) : (int)remaining;
        int n = recv(s, buf, want, 0);
        if (n <= 0) {
            printf("[file] Connection lost during file receive.\n");
            break;
        }
        fwrite(buf, 1, n, f);
        remaining -= (uint64_t)n;
    }
    fclose(f);

    if (remaining == 0) {
        printf("[file] Received '%s' (%llu bytes) saved as .\\%s\n",
            fname, (unsigned long long)size, outpath);
    }
}

// -------------------------- App Messages --------------------------
static void handle_app_message(int from_idx, const char* line_plain) {
    if (starts_with(line_plain, "CHAT|")) {
        char copy[MAX_LINE]; strncpy(copy, line_plain, sizeof(copy)-1); copy[sizeof(copy)-1]=0;
        char* ctx=NULL;
        strtok_s(copy, "|", &ctx);
        char* from = strtok_s(NULL, "|", &ctx);
        char* txt  = strtok_s(NULL, "", &ctx);
        if (!from) from = (char*)"unknown";
        if (!txt) txt = (char*)"";
        printf("[chat] %s: %s\n", from, txt);
        return;
    }

    if (starts_with(line_plain, "BCAST|")) {
        char copy[MAX_LINE]; strncpy(copy, line_plain, sizeof(copy)-1); copy[sizeof(copy)-1]=0;
        char* ctx=NULL;
        strtok_s(copy, "|", &ctx);
        char* from = strtok_s(NULL, "|", &ctx);
        char* txt  = strtok_s(NULL, "", &ctx);
        if (!from) from = (char*)"unknown";
        if (!txt) txt = (char*)"";
        printf("[bcast] %s: %s\n", from, txt);
        return;
    }

    if (starts_with(line_plain, "SRCH|")) {
        char copy[MAX_LINE]; strncpy(copy, line_plain, sizeof(copy)-1); copy[sizeof(copy)-1]=0;
        char* ctx=NULL;
        strtok_s(copy, "|", &ctx);
        char* idhex = strtok_s(NULL, "|", &ctx);
        char* ttl_s = strtok_s(NULL, "|", &ctx);
        char* oip   = strtok_s(NULL, "|", &ctx);
        char* oport = strtok_s(NULL, "|", &ctx);
        char* pat   = strtok_s(NULL, "", &ctx);

        if (!idhex || !ttl_s || !oip || !oport || !pat) return;
        int ttl = atoi(ttl_s);

        if (seen_has(idhex)) return;
        seen_add(idhex);

        for (int i = 0; i < g_share_count; i++) {
            if (strcasestr_simple(g_share[i].name, pat) != NULL) {
                char resp[MAX_LINE];
                _snprintf(resp, sizeof(resp), "SRCHRESP|%s|%s|%llu|%s|%hu",
                    idhex,
                    g_share[i].name,
                    (unsigned long long)g_share[i].size,
                    "0.0.0.0",
                    g_listen_port
                );
                peer_send_line(from_idx, resp);
            }
        }

        if (ttl > 0) {
            char fwd[MAX_LINE];
            _snprintf(fwd, sizeof(fwd), "SRCH|%s|%d|%s|%s|%s", idhex, ttl-1, oip, oport, pat);
            for (int i = 0; i < MAX_PEERS; i++) {
                if (i == from_idx) continue;
                EnterCriticalSection(&g_lock);
                int active = g_peers[i].active;
                int authed = g_peers[i].authed;
                LeaveCriticalSection(&g_lock);
                if (active && authed) peer_send_line(i, fwd);
            }
        }
        return;
    }

    if (starts_with(line_plain, "SRCHRESP|")) {
        char copy[MAX_LINE]; strncpy(copy, line_plain, sizeof(copy)-1); copy[sizeof(copy)-1]=0;
        char* ctx=NULL;
        strtok_s(copy, "|", &ctx);
        char* idhex = strtok_s(NULL, "|", &ctx);
        char* fn    = strtok_s(NULL, "|", &ctx);
        char* sz    = strtok_s(NULL, "|", &ctx);

        char addr[128];
        EnterCriticalSection(&g_lock);
        struct sockaddr_in a = g_peers[from_idx].addr;
        LeaveCriticalSection(&g_lock);
        sockaddr_to_str(&a, addr, sizeof(addr));

        printf("[search] Found id=%s file=%s size=%s at %s\n",
            idhex ? idhex : "?",
            fn ? fn : "?",
            sz ? sz : "?",
            addr
        );
        return;
    }

    if (starts_with(line_plain, "GET|")) {
        const char* fname = line_plain + 4;
        if (!fname || !fname[0]) return;

        SharedFile sf;
        if (!share_find(fname, &sf)) {
            peer_send_line(from_idx, "ERR|NOFILE");
            return;
        }

        char hdr[MAX_LINE];
        _snprintf(hdr, sizeof(hdr), "FILE|%s|%llu", sf.name, (unsigned long long)sf.size);
        peer_send_line(from_idx, hdr);

        FILE* f = fopen(sf.path, "rb");
        if (!f) {
            peer_send_line(from_idx, "ERR|OPENFAIL");
            return;
        }

        char buf[8192];
        uint64_t remaining = sf.size;
        while (remaining > 0) {
            size_t want = (remaining > sizeof(buf)) ? sizeof(buf) : (size_t)remaining;
            size_t got = fread(buf, 1, want, f);
            if (got == 0) break;

            EnterCriticalSection(&g_lock);
            SOCKET s = g_peers[from_idx].sock;
            LeaveCriticalSection(&g_lock);

            if (send_raw(s, buf, (int)got) != 0) break;
            remaining -= (uint64_t)got;
        }
        fclose(f);

        printf("[file] Sent '%s' (%llu bytes) to peer %d\n",
            sf.name, (unsigned long long)sf.size, from_idx);
        return;
    }

    if (starts_with(line_plain, "ERR|")) {
        printf("[err] %s\n", line_plain);
        return;
    }

    printf("[app] from peer %d: %s\n", from_idx, line_plain);
}

// -------------------------- Network Loop --------------------------
static void process_peer_data(int idx) {
    EnterCriticalSection(&g_lock);
    Peer* p = &g_peers[idx];
    SOCKET s = p->sock;
    LeaveCriticalSection(&g_lock);

    char tmp[2048];
    int n = recv(s, tmp, sizeof(tmp)-1, 0);
    if (n <= 0) {
        printf("[net] Peer %d disconnected.\n", idx);
        remove_peer(idx);
        return;
    }
    tmp[n] = '\0';

    EnterCriticalSection(&g_lock);
    if (!g_peers[idx].active) { LeaveCriticalSection(&g_lock); return; }

    Peer* pp = &g_peers[idx];

    if (pp->rbuf_len + n >= (int)sizeof(pp->rbuf)) {
        pp->rbuf_len = 0;
    }
    memcpy(pp->rbuf + pp->rbuf_len, tmp, n);
    pp->rbuf_len += n;
    pp->rbuf[pp->rbuf_len] = '\0';

    char* start = pp->rbuf;
    while (1) {
        char* nl = strchr(start, '\n');
        if (!nl) break;
        *nl = '\0';

        char line_in[MAX_LINE];
        strncpy(line_in, start, sizeof(line_in)-1);
        line_in[sizeof(line_in)-1]=0;
        trim_newline(line_in);

        start = nl + 1;

        char plain[MAX_LINE];

        // Intenta decodificar (permite ENC incluso pre-auth si ya hay session_key)
        if (decode_incoming_allow_pre_auth(pp, line_in, plain, sizeof(plain)) == 0) {
            // Si aún no está authed, procesa control; si ya, procesa app
            if (!pp->authed) {
                LeaveCriticalSection(&g_lock);
                handle_plain_control(idx, plain);
                EnterCriticalSection(&g_lock);
            } else {
                if (starts_with(plain, "FILE|")) {
                    LeaveCriticalSection(&g_lock);
                    handle_file_incoming(idx, plain);
                    EnterCriticalSection(&g_lock);
                } else if (starts_with(plain, "AUTH|") || starts_with(plain, "AUTHOK") || starts_with(plain, "AUTHFAIL")) {
                    LeaveCriticalSection(&g_lock);
                    handle_plain_control(idx, plain);
                    EnterCriticalSection(&g_lock);
                } else {
                    LeaveCriticalSection(&g_lock);
                    handle_app_message(idx, plain);
                    EnterCriticalSection(&g_lock);
                }
            }
        }
    }

    int remaining = (int)strlen(start);
    memmove(pp->rbuf, start, remaining);
    pp->rbuf_len = remaining;
    pp->rbuf[pp->rbuf_len] = '\0';

    LeaveCriticalSection(&g_lock);
}

static SOCKET create_listen_socket(uint16_t port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) die("socket()");

    u_long yes = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));

    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons(port);

    if (bind(s, (struct sockaddr*)&a, sizeof(a)) == SOCKET_ERROR) die("bind()");
    if (listen(s, LISTEN_BACKLOG) == SOCKET_ERROR) die("listen()");

    return s;
}

static int connect_peer(const char* ip, uint16_t port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) die("socket()");

    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &a.sin_addr) != 1) {
        closesocket(s);
        printf("[connect] Invalid IP: %s\n", ip);
        return -1;
    }

    if (connect(s, (struct sockaddr*)&a, sizeof(a)) == SOCKET_ERROR) {
        closesocket(s);
        printf("[connect] Failed to connect to %s:%hu\n", ip, port);
        return -1;
    }

    int idx = add_peer(s, a);
    if (idx < 0) {
        closesocket(s);
        printf("[connect] Peer list full.\n");
        return -1;
    }

    // nonce
    uint32_t nonce = (uint32_t)GetTickCount();
    char noncehex[9];
    u32_to_hex8(nonce, noncehex);

    // hash = FNV(noncehex + psk)
    char material[512];
    _snprintf(material, sizeof(material), "%s%s", noncehex, g_psk);
    uint32_t h = fnv1a_32(material, strlen(material));
    char hhex[9];
    u32_to_hex8(h, hhex);

    // session key = FNV(psk + noncehex)
    char material2[512];
    _snprintf(material2, sizeof(material2), "%s%s", g_psk, noncehex);
    uint32_t sess = fnv1a_32(material2, strlen(material2));

    EnterCriticalSection(&g_lock);
    g_peers[idx].session_key = sess;
    LeaveCriticalSection(&g_lock);

    char authline[MAX_LINE];
    _snprintf(authline, sizeof(authline), "AUTH|%s|%s|%s", noncehex, hhex, g_username);

    // AUTH SIEMPRE en plano
    peer_send_plain_line(idx, authline);

    printf("[connect] Connected peer idx=%d %s:%hu (sent AUTH)\n", idx, ip, port);
    return idx;
}

// -------------------------- Voice (UDP Stream Demo) --------------------------
static int voice_send_file_udp(const char* ip, uint16_t port, const char* filepath) {
    SOCKET us = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (us == INVALID_SOCKET) {
        printf("[voice] udp socket failed\n");
        return -1;
    }

    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &to.sin_addr) != 1) {
        closesocket(us);
        printf("[voice] invalid ip\n");
        return -1;
    }

    FILE* f = fopen(filepath, "rb");
    if (!f) {
        closesocket(us);
        printf("[voice] cannot open: %s\n", filepath);
        return -1;
    }

    printf("[voice] sending %s to %s:%hu via UDP...\n", filepath, ip, port);

    char buf[1024];
    int seq = 0;

    while (1) {
        size_t got = fread(buf, 1, sizeof(buf), f);
        if (got == 0) break;

        char pkt[1200];
        int hdr = _snprintf(pkt, sizeof(pkt), "VPKT|%d|", seq++);
        if (hdr < 0) hdr = 0;
        if ((size_t)hdr + got > sizeof(pkt)) got = sizeof(pkt) - (size_t)hdr;

        memcpy(pkt + hdr, buf, got);
        int total = hdr + (int)got;

        sendto(us, pkt, total, 0, (struct sockaddr*)&to, sizeof(to));
        Sleep(10);
    }

    fclose(f);
    closesocket(us);
    printf("[voice] done.\n");
    return 0;
}

static int voice_recv_udp(uint16_t port, const char* outfile) {
    SOCKET us = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (us == INVALID_SOCKET) {
        printf("[voice] udp socket failed\n");
        return -1;
    }

    struct sockaddr_in me;
    memset(&me, 0, sizeof(me));
    me.sin_family = AF_INET;
    me.sin_addr.s_addr = htonl(INADDR_ANY);
    me.sin_port = htons(port);

    if (bind(us, (struct sockaddr*)&me, sizeof(me)) == SOCKET_ERROR) {
        closesocket(us);
        printf("[voice] bind failed\n");
        return -1;
    }

    FILE* f = fopen(outfile, "wb");
    if (!f) {
        closesocket(us);
        printf("[voice] cannot open outfile\n");
        return -1;
    }

    printf("[voice] listening UDP on port %hu; writing to %s\n", port, outfile);
    printf("[voice] Press Ctrl+C to stop.\n");

    while (1) {
        char pkt[1600];
        struct sockaddr_in from;
        int fromlen = sizeof(from);
        int n = recvfrom(us, pkt, sizeof(pkt), 0, (struct sockaddr*)&from, &fromlen);
        if (n <= 0) continue;

        const char* p = strstr(pkt, "VPKT|");
        if (!p) continue;

        int bars = 0;
        int i;
        for (i = 0; i < n; i++) {
            if (pkt[i] == '|') {
                bars++;
                if (bars == 3) { i++; break; }
            }
        }
        if (bars < 3 || i >= n) continue;

        fwrite(pkt + i, 1, (size_t)(n - i), f);
        fflush(f);
    }

    fclose(f);
    closesocket(us);
    return 0;
}

// -------------------------- Command Thread --------------------------
static unsigned __stdcall cmd_thread(void* arg) {
    (void)arg;
    char line[MAX_LINE];

    while (1) {
        if (!fgets(line, sizeof(line), stdin)) break;
        trim_newline(line);
        if (line[0] == '\0') continue;
        enqueue_cmd(line);
    }
    return 0;
}

// -------------------------- Commands --------------------------
static void cmd_help(void) {
    printf(
        "Commands:\n"
        "  /help\n"
        "  /peers\n"
        "  /connect <ip> <port>\n"
        "  /msg <peerIndex> <text>\n"
        "  /broadcast <text>\n"
        "  /share add <filepath>\n"
        "  /share list\n"
        "  /search <pattern>\n"
        "  /get <ip> <port> <filename>\n"
        "  /voice_send <ip> <udpPort> <file>\n"
        "  /voice_recv <udpPort> <outfile>\n"
        "  /quit\n"
    );
}

static void cmd_search(const char* pattern) {
    char mat[256];
    _snprintf(mat, sizeof(mat), "%s%u", g_username, (unsigned)GetTickCount());
    uint32_t id = fnv1a_32(mat, strlen(mat));
    char idhex[9]; u32_to_hex8(id, idhex);

    seen_add(idhex);

    char msg[MAX_LINE];
    _snprintf(msg, sizeof(msg), "SRCH|%s|%d|%s|%hu|%s", idhex, 3, "0.0.0.0", g_listen_port, pattern);

    int sent = peer_send_line_all(msg);
    printf("[search] sent query id=%s to %d peers: '%s'\n", idhex, sent, pattern);
}

static void cmd_get_file(const char* ip, uint16_t port, const char* filename) {
    int idx = connect_peer(ip, port);
    if (idx < 0) return;

    Sleep(400);

    EnterCriticalSection(&g_lock);
    int authed = g_peers[idx].authed;
    LeaveCriticalSection(&g_lock);

    if (!authed) {
        printf("[get] Not authed yet; try again.\n");
        return;
    }

    char line[MAX_LINE];
    _snprintf(line, sizeof(line), "GET|%s", filename);
    peer_send_line(idx, line);

    printf("[get] requested '%s' from %s:%hu; will save in current folder\n", filename, ip, port);
}

// -------------------------- Main --------------------------
int main(int argc, char** argv) {
    if (argc < 4) {
        printf("Usage: %s <listenPort> <username> <psk>\n", argv[0]);
        printf("Example: %s 9001 pedro clave123\n", argv[0]);
        return 0;
    }

    g_listen_port = (uint16_t)atoi(argv[1]);
    strncpy(g_username, argv[2], sizeof(g_username) - 1);
    strncpy(g_psk, argv[3], sizeof(g_psk) - 1);

    InitializeCriticalSection(&g_lock);

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) die("WSAStartup");

    g_listen = create_listen_socket(g_listen_port);
    printf("[node] Listening on TCP port %hu as user '%s'\n", g_listen_port, g_username);
    printf("[node] PSK set (shared key). Use same PSK on all nodes.\n");
    cmd_help();

    uintptr_t th = _beginthreadex(NULL, 0, cmd_thread, NULL, 0, NULL);
    if (!th) die("_beginthreadex");

    while (1) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(g_listen, &rfds);

        SOCKET maxfd = g_listen;

        EnterCriticalSection(&g_lock);
        for (int i = 0; i < MAX_PEERS; i++) {
            if (g_peers[i].active) {
                FD_SET(g_peers[i].sock, &rfds);
                if (g_peers[i].sock > maxfd) maxfd = g_peers[i].sock;
            }
        }
        LeaveCriticalSection(&g_lock);

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 200000;

        int r = select((int)maxfd + 1, &rfds, NULL, NULL, &tv);
        if (r == SOCKET_ERROR) {
            printf("[net] select error\n");
            break;
        }

        if (FD_ISSET(g_listen, &rfds)) {
            struct sockaddr_in caddr;
            int clen = sizeof(caddr);
            SOCKET cs = accept(g_listen, (struct sockaddr*)&caddr, &clen);
            if (cs != INVALID_SOCKET) {
                int idx = add_peer(cs, caddr);
                char addr[128];
                sockaddr_to_str(&caddr, addr, sizeof(addr));
                if (idx >= 0) printf("[net] accepted peer idx=%d from %s (waiting AUTH)\n", idx, addr);
                else { printf("[net] peer list full; closing %s\n", addr); closesocket(cs); }
            }
        }

        for (int i = 0; i < MAX_PEERS; i++) {
            EnterCriticalSection(&g_lock);
            int active = g_peers[i].active;
            SOCKET ps = active ? g_peers[i].sock : INVALID_SOCKET;
            LeaveCriticalSection(&g_lock);

            if (active && FD_ISSET(ps, &rfds)) process_peer_data(i);
        }

        char cmdline[MAX_LINE];
        while (dequeue_cmd(cmdline, sizeof(cmdline))) {
            if (strcmp(cmdline, "/help") == 0) cmd_help();
            else if (strcmp(cmdline, "/peers") == 0) list_peers();
            else if (starts_with(cmdline, "/connect ")) {
                char ip[64]; int port=0;
                if (sscanf(cmdline, "/connect %63s %d", ip, &port) == 2) connect_peer(ip, (uint16_t)port);
                else printf("Usage: /connect <ip> <port>\n");
            } else if (starts_with(cmdline, "/msg ")) {
                int idx = -1;
                const char* p = cmdline + 5;
                idx = atoi(p);
                while (*p && *p != ' ') p++;
                while (*p == ' ') p++;
                if (idx >= 0 && idx < MAX_PEERS) {
                    char msg[MAX_LINE];
                    _snprintf(msg, sizeof(msg), "CHAT|%s|%s", g_username, p);
                    peer_send_line(idx, msg);
                } else printf("Usage: /msg <peerIndex> <text>\n");
            } else if (starts_with(cmdline, "/broadcast ")) {
                const char* text = cmdline + 11;
                char msg[MAX_LINE];
                _snprintf(msg, sizeof(msg), "BCAST|%s|%s", g_username, text);
                int k = peer_send_line_all(msg);
                printf("[bcast] sent to %d peers\n", k);
            } else if (starts_with(cmdline, "/share add ")) {
                const char* path = cmdline + 11;
                share_add(path);
            } else if (strcmp(cmdline, "/share list") == 0) share_list();
            else if (starts_with(cmdline, "/search ")) cmd_search(cmdline + 8);
            else if (starts_with(cmdline, "/get ")) {
                char ip[64], fn[256];
                int port = 0;
                if (sscanf(cmdline, "/get %63s %d %255s", ip, &port, fn) == 3) cmd_get_file(ip, (uint16_t)port, fn);
                else printf("Usage: /get <ip> <port> <filename>\n");
            } else if (starts_with(cmdline, "/voice_send ")) {
                char ip[64], file[MAX_PATH];
                int port=0;
                if (sscanf(cmdline, "/voice_send %63s %d %259s", ip, &port, file) == 3)
                    voice_send_file_udp(ip, (uint16_t)port, file);
                else printf("Usage: /voice_send <ip> <udpPort> <file>\n");
            } else if (starts_with(cmdline, "/voice_recv ")) {
                int port=0;
                char out[MAX_PATH];
                if (sscanf(cmdline, "/voice_recv %d %259s", &port, out) == 2)
                    voice_recv_udp((uint16_t)port, out);
                else printf("Usage: /voice_recv <udpPort> <outfile>\n");
            } else if (strcmp(cmdline, "/quit") == 0) {
                printf("Bye.\n");
                goto done;
            } else {
                printf("Unknown command. Use /help\n");
            }
        }
    }

done:
    EnterCriticalSection(&g_lock);
    for (int i = 0; i < MAX_PEERS; i++) {
        if (g_peers[i].active) closesocket(g_peers[i].sock);
        g_peers[i].active = 0;
    }
    LeaveCriticalSection(&g_lock);

    if (g_listen != INVALID_SOCKET) closesocket(g_listen);
    WSACleanup();
    DeleteCriticalSection(&g_lock);
    return 0;
}
