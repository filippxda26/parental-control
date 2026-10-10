#define _GNU_SOURCE
#include "../src/parental-control-dns.c"
#include <assert.h>
#include <stdio.h>

int main(void) {
    char name[254];
    size_t end = 0;
    unsigned char query[] = {0x12,0x34,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
        6,'o','r','i','g','i','n',6,'a','c','c','e','s','s',7,'z','a','n','e','t','r','a',
        2,'c','c',0,0,1,0,1};
    assert(question_name(query, sizeof(query), name, &end));
    assert(strcmp(name, "origin.access.zanetra.cc") == 0);
    assert(domain_matches(name, "origin.access.zanetra.cc"));
    assert(domain_matches("api.origin.access.zanetra.cc", name));
    assert(!domain_matches("panel.zanetra.cc", name));
    assert(!domain_matches("notorigin.access.zanetra.cc", name));
    assert(domain_matches("ORIGIN.ACCESS.ZANETRA.CC", name));
    assert(is_ip("203.0.113.5") && is_ip("2001:db8::1"));
    assert(!is_ip(name));
    assert(denied_reply(query, end) == sizeof(query));
    assert(query[2] == 0x81 && query[3] == 0x83);
    puts("DNS blacklist tests: OK");
    return 0;
}
