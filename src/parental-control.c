#define _GNU_SOURCE
#include <json-c/json.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <poll.h>
#include <pthread.h>
#include <fcntl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#define DEVICES "/etc/parental-control/devices.json"
#define SOCK "/var/run/parental-control.sock"
#define STATE "/var/lib/parental-control/state.json"
#define HISTORY "/var/lib/parental-control/history.json"
int parental_control_web_main(int argc,char**argv);
static void *web_thread_main(void *unused){(void)unused;parental_control_web_main(0,NULL);return NULL;}
#define NFT_RULES "/var/run/parental-control.nft"
static json_object *arr(void); static json_object *okmsg(const char*); static int sync_dhcp_macs(void); static const char *sval(json_object*,const char*,const char*); static int ival(json_object*,const char*,int); static int bval(json_object*,const char*,int); static int findid(const char*); static int mac_valid(const char*); static int night(json_object*); static int whitelist_active(json_object*); static int whitelist_ready(json_object*); static int nft_apply(void); static int nft_commit(void); static void state_device(json_object*,json_object*,int); static json_object *state_snapshot(void);
static json_object *root; static int manual[128],break_active[128],temporary_unblock[128]; static time_t brk_until[128],brk_until_mono[128];
static long long used_seconds[128], session_seconds[128], bonus_minutes[128];
static unsigned long long previous_inbound[128], previous_outbound[128];
static int counters_seen[128], blocked_cache[128], whitelist_cache[128], nft_dirty=1; static time_t last_active[128]; static int activity_fd=-1;
static char reset_date[16]="";
static void ensure_varlib(void){mkdir("/var/lib",0755);mkdir("/var/lib/parental-control",0755);}
static void date_now(char out[16]){time_t t=time(NULL);struct tm z;localtime_r(&t,&z);strftime(out,16,"%F",&z);}
static time_t monotonic_now(void){struct timespec ts;if(clock_gettime(CLOCK_MONOTONIC,&ts)==0)return ts.tv_sec;return time(NULL);}
static long long break_left(int i){if(i<0||i>=128||!break_active[i])return 0;time_t nowm=monotonic_now();long long left=brk_until_mono[i]>0?(long long)(brk_until_mono[i]-nowm):(long long)(brk_until[i]-time(NULL));return left>0?left:0;}
static void clear_break_state(int i){if(i<0||i>=128)return;break_active[i]=0;brk_until[i]=0;brk_until_mono[i]=0;}
static void start_break_state(int i,int seconds){if(i<0||i>=128||seconds<=0){clear_break_state(i);return;}break_active[i]=1;brk_until[i]=time(NULL)+seconds;brk_until_mono[i]=monotonic_now()+seconds;}
static ssize_t read_http_request(int fd,char*b,size_t cap){size_t used=0,need=0;while(used+1<cap){ssize_t r=read(fd,b+used,cap-used-1);if(r<0){if(errno==EINTR)continue;return-1;}if(!r)return-1;used+=(size_t)r;b[used]=0;char*sep=strstr(b,"\r\n\r\n");if(!sep)continue;size_t header_len=(size_t)(sep+4-b);if(!need){size_t body_len=0;char*cl=strcasestr(b,"Content-Length:");if(cl&&cl<sep){cl+=15;while(*cl==' '||*cl=='\t')cl++;char*end=NULL;unsigned long long v=strtoull(cl,&end,10);if(end==cl||v>cap-1-header_len)return-2;body_len=(size_t)v;}need=header_len+body_len;}if(used>=need)return(ssize_t)used;}return-2;}
static void save_state(void){
    ensure_varlib();
    json_object *j=state_snapshot();
    if(!j)return;
    char tmp[256];snprintf(tmp,sizeof tmp,"%s.tmp",STATE);
    if(json_object_to_file_ext(tmp,j,JSON_C_TO_STRING_PRETTY)==0){if(rename(tmp,STATE)!=0){fprintf(stderr,"parental-control: rename %s -> %s failed: %s\n",tmp,STATE,strerror(errno));unlink(tmp);}}
    else {fprintf(stderr,"parental-control: write %s failed: %s\n",tmp,strerror(errno));unlink(tmp);}
    json_object_put(j);
}
static void load_state(void){
    char today[16];date_now(today);
    json_object*j=json_object_from_file(STATE);
    if(!j){snprintf(reset_date,sizeof reset_date,"%s",today);return;}

    /* Compatibility with the older internal state format. */
    json_object*v=NULL,*a=NULL;
    if(json_object_object_get_ex(j,"states",&a)&&json_object_is_type(a,json_type_array)){
        if(json_object_object_get_ex(j,"reset_date",&v))snprintf(reset_date,sizeof reset_date,"%s",json_object_get_string(v));
        if(strcmp(reset_date,today)){snprintf(reset_date,sizeof reset_date,"%s",today);for(int x=0;x<(int)json_object_array_length(a);x++){json_object*o=json_object_array_get_idx(a,x);int i=findid(sval(o,"id",""));if(i>=0)manual[i]=bval(o,"manual_block",0);}json_object_put(j);return;}
        for(int x=0;x<(int)json_object_array_length(a);x++){
            json_object*o=json_object_array_get_idx(a,x);int i=findid(sval(o,"id",""));if(i<0)continue;
            used_seconds[i]=ival(o,"used_seconds",0);
            session_seconds[i]=ival(o,"session_seconds",0);
            brk_until[i]=(time_t)json_object_get_int64(json_object_object_get(o,"break_until"));
            if(brk_until[i]>0){long long left=(long long)(brk_until[i]-time(NULL));if(left>0)brk_until_mono[i]=monotonic_now()+(time_t)left;else{clear_break_state(i);session_seconds[i]=0;}}
            manual[i]=bval(o,"manual_block",0);
            temporary_unblock[i]=bval(o,"temporary_unblock",0);
            bonus_minutes[i]=ival(o,"bonus_minutes",0);
            last_active[i]=0;
            previous_inbound[i]=previous_outbound[i]=0;
            counters_seen[i]=0;
            break_active[i]=brk_until[i]>0&&brk_until_mono[i]>monotonic_now();
        }
        json_object_put(j);return;
    }

    /* Current format: the same JSON object that /api/state returns. */
    time_t saved_at=time(NULL);
    if(json_object_object_get_ex(j,"state_timestamp",&v))saved_at=(time_t)json_object_get_int64(v);
    struct tm z;localtime_r(&saved_at,&z);char saved_date[16];strftime(saved_date,sizeof saved_date,"%F",&z);
    snprintf(reset_date,sizeof reset_date,"%s",today);
    if(strcmp(saved_date,today)){if(json_object_object_get_ex(j,"devices",&a)&&json_object_is_type(a,json_type_array))for(int x=0;x<(int)json_object_array_length(a);x++){json_object*o=json_object_array_get_idx(a,x);int i=findid(sval(o,"id",""));if(i>=0)manual[i]=bval(o,"manual_blocked",0);}json_object_put(j);return;}

    if(json_object_object_get_ex(j,"devices",&a)&&json_object_is_type(a,json_type_array)){
        for(int x=0;x<(int)json_object_array_length(a);x++){
            json_object*o=json_object_array_get_idx(a,x);int i=findid(sval(o,"id",""));if(i<0)continue;
            used_seconds[i]=ival(o,"used_seconds",0);
            session_seconds[i]=ival(o,"session_used_seconds",0);
            manual[i]=bval(o,"manual_blocked",0);
            temporary_unblock[i]=bval(o,"temporary_unblock",0);
            bonus_minutes[i]=ival(o,"bonus_minutes",0);
            int ba=bval(o,"break_active",0),left=ival(o,"break_remaining_seconds",0);
            time_t elapsed=time(NULL)>saved_at?time(NULL)-saved_at:0;if(elapsed>0&&left>0)left=elapsed>=left?0:left-(int)elapsed;
            if(ba&&left>0)start_break_state(i,left);else{clear_break_state(i);if(ba)session_seconds[i]=0;}
            counters_seen[i]=0;
            previous_inbound[i]=previous_outbound[i]=0;
            last_active[i]=0;
        }
    }
    json_object_put(j);
}
static void reset_today_all(void){char today[16];date_now(today);snprintf(reset_date,sizeof reset_date,"%s",today);memset(used_seconds,0,sizeof used_seconds);memset(session_seconds,0,sizeof session_seconds);memset(bonus_minutes,0,sizeof bonus_minutes);memset(break_active,0,sizeof break_active);memset(temporary_unblock,0,sizeof temporary_unblock);memset(brk_until,0,sizeof brk_until);memset(brk_until_mono,0,sizeof brk_until_mono);save_state();}
static int read_nft_counters(unsigned long long *inb,unsigned long long *outb){
    memset(inb,0,sizeof(unsigned long long)*128); memset(outb,0,sizeof(unsigned long long)*128);
    FILE *f=popen("(/usr/sbin/nft list chain inet parental_control pc_forward 2>/dev/null || /usr/bin/nft list chain inet parental_control pc_forward 2>/dev/null)","r");
    if (!f) return 0;
    char line[2048];
    int found=0;
    while(fgets(line,sizeof line,f)){
        char *c=strstr(line,"comment \"pc:"); if(!c) continue;
        char *bp=strstr(line," bytes "); if(!bp) continue; unsigned long long bytes=strtoull(bp+7,NULL,10);
        c+=12; char *e=strchr(c,'\"'); if(!e)continue; *e=0; char *dir=strrchr(c,':'); if(!dir)continue; *dir++=0;
        int i=findid(c); if(i<0)continue; if(!strcmp(dir,"in"))inb[i]+=bytes; else if(!strcmp(dir,"out"))outb[i]+=bytes; else continue; found=1;
    } int rc=pclose(f);if(rc!=0)return-1;return found;
}
static int open_activity_socket(void){int fd=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));if(fd<0){fprintf(stderr,"parental-control: packet activity socket unavailable: %s\n",strerror(errno));return -1;}int fl=fcntl(fd,F_GETFL,0);if(fl>=0)fcntl(fd,F_SETFL,fl|O_NONBLOCK);fprintf(stderr,"parental-control: packet activity detection enabled\n");return fd;}
static int mac_bytes(const char*s,unsigned char out[6]){unsigned int b[6];if(!s||sscanf(s,"%2x:%2x:%2x:%2x:%2x:%2x",&b[0],&b[1],&b[2],&b[3],&b[4],&b[5])!=6)return 0;for(int i=0;i<6;i++)out[i]=(unsigned char)b[i];return 1;}
static int device_mac_count(json_object*d){int n=*sval(d,"mac","")?1:0;json_object*a=NULL;if(json_object_object_get_ex(d,"linked_macs",&a)&&json_object_is_type(a,json_type_array))n+=(int)json_object_array_length(a);return n;}
static const char*device_mac_at(json_object*d,int idx){const char*primary=sval(d,"mac","");if(*primary){if(idx==0)return primary;idx--;}json_object*a=NULL;if(json_object_object_get_ex(d,"linked_macs",&a)&&json_object_is_type(a,json_type_array)&&idx>=0&&idx<(int)json_object_array_length(a))return json_object_get_string(json_object_array_get_idx(a,idx));return "";}
static int device_has_mac(json_object*d,const char*mac){if(!mac||!*mac)return 0;int n=device_mac_count(d);for(int i=0;i<n;i++)if(!strcasecmp(device_mac_at(d,i),mac))return 1;return 0;}
static int read_packet_activity(unsigned long long *bytes){memset(bytes,0,sizeof(unsigned long long)*128);if(activity_fd<0)return 0;json_object*a=arr();unsigned char macs[128][17][6];int mc[128]={0};int n=(int)json_object_array_length(a);if(n>128)n=128;for(int i=0;i<n;i++){json_object*d=json_object_array_get_idx(a,i);int count=device_mac_count(d);if(count>17)count=17;for(int k=0;k<count;k++)if(mac_bytes(device_mac_at(d,k),macs[i][mc[i]]))mc[i]++;}unsigned char buf[65536];int packets=0;for(;packets<8192;packets++){ssize_t len=recv(activity_fd,buf,sizeof buf,MSG_DONTWAIT);if(len<0){if(errno==EAGAIN||errno==EWOULDBLOCK)break;if(errno==EINTR)continue;fprintf(stderr,"parental-control: packet activity recv failed: %s\n",strerror(errno));break;}if(len<14)continue;int matched=0;for(int i=0;i<n&&!matched;i++)for(int k=0;k<mc[i];k++)if(!memcmp(buf,macs[i][k],6)||!memcmp(buf+6,macs[i][k],6)){bytes[i]+=(unsigned long long)len;matched=1;break;}}return 1;}
static int automatic_blocked(json_object*d,int i){if(!bval(d,"enabled",1))return 0;long long lim=(long long)ival(d,"daily_limit_minutes",0)*60+bonus_minutes[i]*60;return night(d)||(bval(d,"break_enabled",0)&&break_left(i)>0)||(bval(d,"daily_limit_enabled",0)&&lim>0&&used_seconds[i]>=lim);}
static int is_blocked(json_object*d,int i){if(!bval(d,"enabled",1))return 0;return manual[i]||(!temporary_unblock[i]&&automatic_blocked(d,i));}
static void tick(void){static time_t last_dhcp_sync=0;time_t now_sync=monotonic_now();if(now_sync-last_dhcp_sync>=2){sync_dhcp_macs();last_dhcp_sync=now_sync;}
    static time_t last_mono=0; time_t mono=monotonic_now(); if(!last_mono){last_mono=mono;return;} int dt=(int)(mono-last_mono); if(dt<1)return; if(dt>60)dt=1; last_mono=mono;
    char today[16]; date_now(today); if(strcmp(today,reset_date))reset_today_all();
    unsigned long long activity_bytes[128],inb[128],outb[128];int packet_activity=read_packet_activity(activity_bytes);int have=packet_activity?0:read_nft_counters(inb,outb);json_object*a=arr(); int changed=0, rules_changed=0, whitelist_refresh_needed=0;
    if(have<0){nft_dirty=1;have=0;}
    for(int i=0;i<(int)json_object_array_length(a)&&i<128;i++){
        json_object*d=json_object_array_get_idx(a,i); if(break_active[i]&&break_left(i)<=0){clear_break_state(i);session_seconds[i]=0;changed=rules_changed=1;}
        if(temporary_unblock[i]&&!automatic_blocked(d,i)){temporary_unblock[i]=0;changed=1;}int before=is_blocked(d,i),break_enabled=bval(d,"break_enabled",0),cycle=bval(d,"session_limit_enabled",0)&&break_enabled,active=0;
        if(!cycle&&session_seconds[i]){session_seconds[i]=0;changed=1;}
        if(!break_enabled&&(break_active[i]||brk_until[i]||brk_until_mono[i])){clear_break_state(i);changed=1;if(before)rules_changed=1;}
        if(packet_activity){/* Packet capture sees background keepalives too. Require a real burst before starting/refreshing usage. */unsigned long long threshold=(unsigned long long)ival(d,"activity_threshold_bytes",4096);if(threshold<16384)threshold=16384;if(!before&&activity_bytes[i]>=threshold){active=1;last_active[i]=mono;}}
        else if(have){
            if(counters_seen[i]){int reset=inb[i]<previous_inbound[i]||outb[i]<previous_outbound[i];unsigned long long di=inb[i]>=previous_inbound[i]?inb[i]-previous_inbound[i]:inb[i]; unsigned long long do_=outb[i]>=previous_outbound[i]?outb[i]-previous_outbound[i]:outb[i]; unsigned long long threshold=(unsigned long long)ival(d,"activity_threshold_bytes",4096);if(threshold<1)threshold=1; /* A counter reset means nft rules were recreated while this device was passing traffic. Treat non-zero post-reset traffic as activity; otherwise use the per-device threshold. */ if(!before&&((reset&&(di+do_>0))||di+do_>=threshold)){active=1;last_active[i]=mono;}}
            else {counters_seen[i]=1;}
            previous_inbound[i]=inb[i]; previous_outbound[i]=outb[i]; changed=1;
        }
        int idle=packet_activity?60:ival(d,"idle_timeout_seconds",300); if(!before&&!active&&last_active[i]&&idle>0&&mono-last_active[i]<=idle)active=1;
        if(!bval(d,"enabled",1))active=0;
        if(active&&!before){if(bval(d,"daily_limit_enabled",0)){used_seconds[i]+=dt;changed=1;}if(cycle&&!break_active[i]){session_seconds[i]+=dt;changed=1;int lim=ival(d,"session_limit_minutes",0)*60;if(lim>0&&session_seconds[i]>=lim){temporary_unblock[i]=0;start_break_state(i,ival(d,"break_minutes",0)*60);changed=rules_changed=1;}}}
        int after=is_blocked(d,i),wl=whitelist_ready(d),restricted=after||wl;if(after!=before||restricted!=blocked_cache[i]||wl!=whitelist_cache[i]){fprintf(stderr,"parental-control: nft refresh reason=state-change device_id=%s before=%d after=%d restricted=%d blocked_cache=%d whitelist=%d whitelist_cache=%d\n",sval(d,"id",""),before,after,restricted,blocked_cache[i],wl,whitelist_cache[i]);rules_changed=1;}if(wl&&!manual[i])whitelist_refresh_needed=1;
    }
    static time_t last_whitelist_refresh=0;if(whitelist_refresh_needed&&(last_whitelist_refresh==0||now_sync-last_whitelist_refresh>=300)){rules_changed=1;last_whitelist_refresh=now_sync;}
    if(changed||rules_changed)save_state();
    if(rules_changed)nft_dirty=1;
    if(nft_dirty)nft_commit();
}

static void save(void){char tmp[256];snprintf(tmp,sizeof tmp,"%s.tmp",DEVICES);if(json_object_to_file_ext(tmp,root,JSON_C_TO_STRING_PRETTY)==0){if(rename(tmp,DEVICES)!=0){fprintf(stderr,"parental-control: rename %s -> %s failed: %s\n",tmp,DEVICES,strerror(errno));unlink(tmp);}}else{fprintf(stderr,"parental-control: write %s failed: %s\n",tmp,strerror(errno));unlink(tmp);}}
static void runtime_remove(int i){if(i<0||i>=128)return;for(int k=i;k<127;k++){manual[k]=manual[k+1];break_active[k]=break_active[k+1];temporary_unblock[k]=temporary_unblock[k+1];brk_until[k]=brk_until[k+1];brk_until_mono[k]=brk_until_mono[k+1];used_seconds[k]=used_seconds[k+1];session_seconds[k]=session_seconds[k+1];bonus_minutes[k]=bonus_minutes[k+1];previous_inbound[k]=previous_inbound[k+1];previous_outbound[k]=previous_outbound[k+1];counters_seen[k]=counters_seen[k+1];blocked_cache[k]=blocked_cache[k+1];whitelist_cache[k]=whitelist_cache[k+1];last_active[k]=last_active[k+1];}manual[127]=break_active[127]=temporary_unblock[127]=counters_seen[127]=blocked_cache[127]=whitelist_cache[127]=0;brk_until[127]=brk_until_mono[127]=last_active[127]=0;used_seconds[127]=session_seconds[127]=bonus_minutes[127]=0;previous_inbound[127]=previous_outbound[127]=0;}
static void make_device_id(const char*mac,char out[20]){char*p=out;memcpy(p,"device-",7);p+=7;for(const unsigned char*s=(const unsigned char*)mac;*s&&p<out+19;s++)if(isxdigit(*s))*p++=(char)tolower(*s);if(p==out+7){snprintf(out,20,"device-auto");return;}*p=0;}
static int make_unique_device_id(const char*mac,char out[64]){char base[20];make_device_id(mac,base);if(findid(base)<0){snprintf(out,64,"%s",base);return 0;}for(int n=2;n<1000;n++){snprintf(out,64,"%s-%d",base,n);if(findid(out)<0)return 0;}return-1;}
static json_object *arr(void){json_object *a=NULL;if(!root||!json_object_object_get_ex(root,"devices",&a)){root=json_object_new_object();a=json_object_new_array();json_object_object_add(root,"devices",a);}return a;}
static const char *sval(json_object *o,const char*k,const char*d){json_object*v=NULL;if(!o||!json_object_object_get_ex(o,k,&v)||!v||json_object_is_type(v,json_type_null))return d;const char*s=json_object_get_string(v);return s?s:d;}
static int ival(json_object *o,const char*k,int d){json_object*v=NULL;return o&&json_object_object_get_ex(o,k,&v)&&v&&!json_object_is_type(v,json_type_null)?json_object_get_int(v):d;}
static int bval(json_object *o,const char*k,int d){json_object*v=NULL;return o&&json_object_object_get_ex(o,k,&v)&&v&&!json_object_is_type(v,json_type_null)?json_object_get_boolean(v):d;}
static int findid(const char *id){json_object*a=arr();for(int i=0;i<(int)json_object_array_length(a);i++)if(!strcmp(sval(json_object_array_get_idx(a,i),"id",""),id))return i;return -1;}
typedef struct{long long expiry;char mac[32],ip[64],host[128];}DhcpLease;
static DhcpLease lease_cache[256];static int lease_cache_count=0;static time_t lease_cache_at=(time_t)-1;
static int lease_active(long long expiry){return expiry==0||expiry>(long long)time(NULL);}
static int read_leases(DhcpLease*out,int max){FILE*f=fopen("/tmp/dhcp.leases","r");if(!f)return 0;int n=0;char line[768];while(n<max&&fgets(line,sizeof line,f)){long long expiry=0;char mac[32]={0},ip[64]={0},host[128]={0};int fields=sscanf(line,"%lld %31s %63s %127s",&expiry,mac,ip,host);if(fields<3||!lease_active(expiry)||!mac_valid(mac))continue;out[n].expiry=expiry;snprintf(out[n].mac,sizeof out[n].mac,"%s",mac);snprintf(out[n].ip,sizeof out[n].ip,"%s",ip);snprintf(out[n].host,sizeof out[n].host,"%s",fields>=4?host:"");n++;}fclose(f);return n;}
static int cached_leases(DhcpLease**out){time_t now=time(NULL);if(lease_cache_at!=now){lease_cache_count=read_leases(lease_cache,256);lease_cache_at=now;}*out=lease_cache;return lease_cache_count;}
static int ipv6_neighbors_for_mac(const char*mac,char out[][INET6_ADDRSTRLEN],int max){if(!mac||!*mac||max<=0)return 0;FILE*f=popen("(ip -6 neigh show 2>/dev/null || /sbin/ip -6 neigh show 2>/dev/null || /usr/sbin/ip -6 neigh show 2>/dev/null)","r");if(!f)return 0;char line[512];int n=0;while(n<max&&fgets(line,sizeof line,f)){char ip[INET6_ADDRSTRLEN]={0},ll[32]={0};if(sscanf(line,"%45s",ip)!=1)continue;char*p=strstr(line," lladdr ");if(!p||sscanf(p+8,"%31s",ll)!=1||strcasecmp(ll,mac))continue;struct in6_addr a6;if(inet_pton(AF_INET6,ip,&a6)!=1)continue;int dup=0;for(int i=0;i<n;i++)if(!strcmp(out[i],ip)){dup=1;break;}if(!dup)snprintf(out[n++],INET6_ADDRSTRLEN,"%s",ip);}pclose(f);return n;}
static int time_valid(const char*s){if(!s||strlen(s)!=5||s[2]!=':'||!isdigit((unsigned char)s[0])||!isdigit((unsigned char)s[1])||!isdigit((unsigned char)s[3])||!isdigit((unsigned char)s[4]))return 0;int h=(s[0]-'0')*10+(s[1]-'0'),m=(s[3]-'0')*10+(s[4]-'0');return h>=0&&h<24&&m>=0&&m<60;}
static int night(json_object*d){if(!bval(d,"night_enabled",0))return 0;const char*start=sval(d,"night_start","22:00"),*end=sval(d,"night_end","08:00");if(!time_valid(start)||!time_valid(end))return 0;int sh,sm,eh,em;sscanf(start,"%d:%d",&sh,&sm);sscanf(end,"%d:%d",&eh,&em);time_t t=time(NULL);struct tm z;localtime_r(&t,&z);int n=z.tm_hour*60+z.tm_min,a=sh*60+sm,b=eh*60+em;return a<=b?(n>=a&&n<b):(n>=a||n<b);}
static int whitelist_active(json_object*d){if(!bval(d,"enabled",1)||!bval(d,"whitelist_enabled",0))return 0;const char*start=sval(d,"whitelist_start","08:00"),*end=sval(d,"whitelist_end","22:00");if(!time_valid(start)||!time_valid(end))return 0;int sh,sm,eh,em;sscanf(start,"%d:%d",&sh,&sm);sscanf(end,"%d:%d",&eh,&em);time_t t=time(NULL);struct tm z;localtime_r(&t,&z);int n=z.tm_hour*60+z.tm_min,a=sh*60+sm,b=eh*60+em;return a<=b?(n>=a&&n<b):(n>=a||n<b);}
static int whitelist_ready(json_object*d){json_object*entries=NULL;return whitelist_active(d)&&json_object_object_get_ex(d,"whitelist_entries",&entries)&&json_object_is_type(entries,json_type_array)&&json_object_array_length(entries)>0;}
static int whitelist_entry_valid(const char*s){if(!s||!*s||strlen(s)>253)return 0;struct in_addr a4;struct in6_addr a6;if(inet_pton(AF_INET,s,&a4)==1||inet_pton(AF_INET6,s,&a6)==1)return 1;size_t len=strlen(s);if(s[0]=='.'||s[len-1]=='.')return 0;int label=0;for(size_t i=0;i<len;i++){unsigned char c=(unsigned char)s[i];if(c=='.'){if(label<1||label>63||s[i-1]=='-')return 0;label=0;continue;}if(!(isalnum(c)||c=='-')||(label==0&&c=='-'))return 0;if(++label>63)return 0;}return label>0&&s[len-1]!='-';}
static void nft_allow_whitelist_address(FILE*f,const char*m,const char*id,int family,const void*addr,const char*device_ip,int have_ip4,char device_ip6[][INET6_ADDRSTRLEN],int ip6_count){char ip[INET6_ADDRSTRLEN];if(!inet_ntop(family,addr,ip,sizeof ip))return;if(family==AF_INET){fprintf(f,"add rule inet parental_control pc_forward ether saddr %s ip daddr %s accept comment \"pc:%s:wl4-out\"\n",m,ip,id);if(have_ip4)fprintf(f,"add rule inet parental_control pc_forward ip saddr %s ip daddr %s accept comment \"pc:%s:wl4-in\"\n",ip,device_ip,id);else fprintf(f,"add rule inet parental_control pc_forward ether daddr %s ip saddr %s accept comment \"pc:%s:wl4-in\"\n",m,ip,id);}else if(family==AF_INET6){fprintf(f,"add rule inet parental_control pc_forward ether saddr %s ip6 daddr %s accept comment \"pc:%s:wl6-out\"\n",m,ip,id);if(ip6_count){for(int v6=0;v6<ip6_count;v6++)fprintf(f,"add rule inet parental_control pc_forward ip6 saddr %s ip6 daddr %s accept comment \"pc:%s:wl6-in\"\n",ip,device_ip6[v6],id);}else fprintf(f,"add rule inet parental_control pc_forward ether daddr %s ip6 saddr %s accept comment \"pc:%s:wl6-in\"\n",m,ip,id);}}
static void nft_whitelist_rules(FILE*f,json_object*d,const char*m,const char*id,const char*device_ip,int have_ip4,char device_ip6[][INET6_ADDRSTRLEN],int ip6_count){json_object*entries=NULL;if(!whitelist_ready(d)||!json_object_object_get_ex(d,"whitelist_entries",&entries)||!json_object_is_type(entries,json_type_array))return;for(int x=0;x<(int)json_object_array_length(entries);x++){json_object*v=json_object_array_get_idx(entries,x);if(!v||!json_object_is_type(v,json_type_string))continue;const char*entry=json_object_get_string(v);struct in_addr a4;struct in6_addr a6;if(inet_pton(AF_INET,entry,&a4)==1){nft_allow_whitelist_address(f,m,id,AF_INET,&a4,device_ip,have_ip4,device_ip6,ip6_count);continue;}if(inet_pton(AF_INET6,entry,&a6)==1){nft_allow_whitelist_address(f,m,id,AF_INET6,&a6,device_ip,have_ip4,device_ip6,ip6_count);continue;}struct addrinfo hints={0},*res=NULL;hints.ai_family=AF_UNSPEC;hints.ai_socktype=SOCK_STREAM;if(getaddrinfo(entry,NULL,&hints,&res)!=0)continue;int emitted=0;for(struct addrinfo*ai=res;ai&&emitted<16;ai=ai->ai_next){if(ai->ai_family==AF_INET){struct sockaddr_in*sa=(struct sockaddr_in*)ai->ai_addr;nft_allow_whitelist_address(f,m,id,AF_INET,&sa->sin_addr,device_ip,have_ip4,device_ip6,ip6_count);emitted++;}else if(ai->ai_family==AF_INET6){struct sockaddr_in6*sa=(struct sockaddr_in6*)ai->ai_addr;nft_allow_whitelist_address(f,m,id,AF_INET6,&sa->sin6_addr,device_ip,have_ip4,device_ip6,ip6_count);emitted++;}}freeaddrinfo(res);}}
static void state_device(json_object*out,json_object*d,int i){
    json_object_object_add(out,"id",json_object_new_string(sval(d,"id","")));
    json_object_object_add(out,"name",json_object_new_string(sval(d,"name","")));

    json_object *h=NULL;
    const char *hostname=sval(d,"hostname","");
    if(json_object_object_get_ex(d,"hostnames",&h)&&json_object_is_type(h,json_type_array)&&json_object_array_length(h)>0)
        hostname=json_object_get_string(json_object_array_get_idx(h,0));
    json_object_object_add(out,"hostname",json_object_new_string(hostname));
    if(h)json_object_object_add(out,"hostnames",json_object_get(h));
    else {json_object*hs=json_object_new_array();if(*hostname)json_object_array_add(hs,json_object_new_string(hostname));json_object_object_add(out,"hostnames",hs);}

    json_object_object_add(out,"mac",json_object_new_string(sval(d,"mac","")));
    json_object_object_add(out,"mac_auto",json_object_new_boolean(bval(d,"mac_auto",0)));
    json_object*macs=json_object_new_array();
    json_object*ips=json_object_new_array();
    json_object*linked_devices=json_object_new_array();
    DhcpLease*state_leases=NULL;
    int state_lease_count=cached_leases(&state_leases);
    int mac_count=device_mac_count(d);
    int mac_claimed[17]={0};
    for(int mi=0;mi<mac_count;mi++)
        json_object_array_add(macs,json_object_new_string(device_mac_at(d,mi)));

    /* A configured Hostname is its own device. Resolve only that exact
       Hostname to DHCP, then attach the matching IP/MAC to that row. */
    json_object*cfg_hs=NULL;
    if(json_object_object_get_ex(d,"hostnames",&cfg_hs)&&json_object_is_type(cfg_hs,json_type_array)){
        for(int hi=0;hi<(int)json_object_array_length(cfg_hs);hi++){
            const char*host=json_object_get_string(json_object_array_get_idx(cfg_hs,hi));
            if(!host||!*host)continue;
            json_object*linked=json_object_new_object();
            json_object_object_add(linked,"hostname",json_object_new_string(host));

            int found=-1,ambiguous=0;
            for(int li=0;li<state_lease_count;li++){
                if(!*state_leases[li].host||!strcmp(state_leases[li].host,"*")||!strcmp(state_leases[li].host,"-")||strcasecmp(state_leases[li].host,host))continue;
                if(found<0)found=li;
                else if(strcasecmp(state_leases[found].mac,state_leases[li].mac))ambiguous=1;
            }
            if(found>=0&&!ambiguous){
                json_object_object_add(linked,"ip",json_object_new_string(state_leases[found].ip));
                json_object_object_add(linked,"mac",json_object_new_string(state_leases[found].mac));
                int dup=0;for(int ii=0;ii<(int)json_object_array_length(ips);ii++)if(!strcmp(json_object_get_string(json_object_array_get_idx(ips,ii)),state_leases[found].ip)){dup=1;break;}
                if(!dup)json_object_array_add(ips,json_object_new_string(state_leases[found].ip));
                for(int mi=0;mi<mac_count&&mi<17;mi++)if(!strcasecmp(device_mac_at(d,mi),state_leases[found].mac))mac_claimed[mi]=1;
            }
            json_object_array_add(linked_devices,linked);
        }
    }

    /* MAC-only devices stay separate. Do not copy a DHCP Hostname into them:
       a generic DHCP name such as "iPhone" is not the configured device name. */
    for(int mi=0;mi<mac_count;mi++){
        if(mi<17&&mac_claimed[mi])continue;
        const char*m=device_mac_at(d,mi);
        json_object*linked=json_object_new_object();
        json_object_object_add(linked,"mac",json_object_new_string(m));
        for(int li=0;li<state_lease_count;li++){
            if(strcasecmp(state_leases[li].mac,m))continue;
            if(*state_leases[li].ip){
                json_object_object_add(linked,"ip",json_object_new_string(state_leases[li].ip));
                int dup=0;for(int ii=0;ii<(int)json_object_array_length(ips);ii++)if(!strcmp(json_object_get_string(json_object_array_get_idx(ips,ii)),state_leases[li].ip)){dup=1;break;}
                if(!dup)json_object_array_add(ips,json_object_new_string(state_leases[li].ip));
            }
            break;
        }
        json_object_array_add(linked_devices,linked);
    }

    json_object_object_add(out,"macs",macs);
    json_object_object_add(out,"ips",ips);
    json_object_object_add(out,"linked_devices",linked_devices);
    if(json_object_array_length(ips)>0)
        json_object_object_add(out,"ip",json_object_new_string(json_object_get_string(json_object_array_get_idx(ips,0))));
    json_object_object_add(out,"enabled",json_object_new_boolean(bval(d,"enabled",1)));

    json_object_object_add(out,"daily_limit_minutes",json_object_new_int(ival(d,"daily_limit_minutes",0)));
    json_object_object_add(out,"session_limit_minutes",json_object_new_int(ival(d,"session_limit_minutes",60)));
    json_object_object_add(out,"break_minutes",json_object_new_int(ival(d,"break_minutes",60)));
    json_object_object_add(out,"daily_limit_enabled",json_object_new_boolean(bval(d,"daily_limit_enabled",0)));
    json_object_object_add(out,"session_limit_enabled",json_object_new_boolean(bval(d,"session_limit_enabled",0)));
    json_object_object_add(out,"break_enabled",json_object_new_boolean(bval(d,"break_enabled",0)));
    json_object_object_add(out,"night_enabled",json_object_new_boolean(bval(d,"night_enabled",0)));
    json_object_object_add(out,"night_start",json_object_new_string(sval(d,"night_start","22:00")));
    json_object_object_add(out,"night_end",json_object_new_string(sval(d,"night_end","08:00")));
    json_object_object_add(out,"speed_limit_enabled",json_object_new_boolean(bval(d,"speed_limit_enabled",0)));
    json_object_object_add(out,"speed_limit_mbps",json_object_new_int(ival(d,"speed_limit_mbps",5)));
    json_object_object_add(out,"whitelist_enabled",json_object_new_boolean(bval(d,"whitelist_enabled",0)));
    json_object_object_add(out,"whitelist_start",json_object_new_string(sval(d,"whitelist_start","08:00")));
    json_object_object_add(out,"whitelist_end",json_object_new_string(sval(d,"whitelist_end","22:00")));
    json_object_object_add(out,"whitelist_active",json_object_new_boolean(whitelist_active(d)));
    json_object*wl_entries=NULL;if(json_object_object_get_ex(d,"whitelist_entries",&wl_entries)&&json_object_is_type(wl_entries,json_type_array))json_object_object_add(out,"whitelist_entries",json_object_get(wl_entries));else json_object_object_add(out,"whitelist_entries",json_object_new_array());

    long long runtime_break_left=break_left(i);int n=night(d),ba=bval(d,"break_enabled",0)&&runtime_break_left>0;
    int daily_limit=ival(d,"daily_limit_minutes",0)*60+(int)bonus_minutes[i]*60;
    int dl=bval(d,"daily_limit_enabled",0)&&daily_limit>0&&used_seconds[i]>=daily_limit;
    int enabled=bval(d,"enabled",1),hard_blocked=is_blocked(d,i),wl_enforced=whitelist_ready(d)&&!manual[i],blocked=hard_blocked||wl_enforced;
    int cycle=bval(d,"session_limit_enabled",0)&&bval(d,"break_enabled",0),idle_timeout=ival(d,"idle_timeout_seconds",300);time_t activity_now=monotonic_now();long long since_traffic=last_active[i]>0?(long long)(activity_now-last_active[i]):-1;int traffic_idle=enabled&&cycle&&!ba&&!blocked&&(last_active[i]<=0||(idle_timeout>0?since_traffic>idle_timeout:since_traffic>1));
    json_object_object_add(out,"whitelist_enforced",json_object_new_boolean(wl_enforced));
    json_object_object_add(out,"traffic_idle",json_object_new_boolean(traffic_idle));
    long long session_limit=(long long)ival(d,"session_limit_minutes",60)*60;
    long long session_remaining=session_limit-session_seconds[i];if(session_remaining<0)session_remaining=0;
    long long daily_remaining=(long long)daily_limit-used_seconds[i];if(daily_remaining<0)daily_remaining=0;

    json_object_object_add(out,"used_seconds",json_object_new_int64(used_seconds[i]));
    json_object_object_add(out,"daily_limit_seconds",json_object_new_int(daily_limit));
    json_object_object_add(out,"daily_remaining_seconds",json_object_new_int64(daily_remaining));
    json_object_object_add(out,"session_used_seconds",json_object_new_int64(session_seconds[i]));
    json_object_object_add(out,"session_limit_seconds",json_object_new_int64(session_limit));
    json_object_object_add(out,"session_remaining_seconds",json_object_new_int64(session_remaining));
    long long break_remaining=ba?runtime_break_left:0;
    json_object_object_add(out,"break_active",json_object_new_boolean(ba));
    json_object_object_add(out,"break_remaining_seconds",json_object_new_int64(break_remaining));
    json_object_object_add(out,"bonus_minutes",json_object_new_int64(bonus_minutes[i]));
    json_object_object_add(out,"temporary_unblock",json_object_new_boolean(temporary_unblock[i]));
    json_object_object_add(out,"manual_blocked",json_object_new_boolean(manual[i]));
    json_object_object_add(out,"blocked",json_object_new_boolean(blocked));
    json_object_object_add(out,"access_allowed",json_object_new_boolean(!blocked));

    json_object_object_add(out,"block_reason",json_object_new_string(blocked?(manual[i]?"manual":n&&!temporary_unblock[i]?"night":ba&&!temporary_unblock[i]?"break":dl&&!temporary_unblock[i]?"daily_limit":wl_enforced?"whitelist":""):""));
    json_object *rs=json_object_new_array();
    if(enabled&&manual[i])json_object_array_add(rs,json_object_new_string("manual"));
    if(enabled&&n&&!temporary_unblock[i])json_object_array_add(rs,json_object_new_string("night"));
    if(enabled&&ba&&!temporary_unblock[i])json_object_array_add(rs,json_object_new_string("break"));
    if(enabled&&dl&&!temporary_unblock[i])json_object_array_add(rs,json_object_new_string("daily_limit"));
    if(enabled&&wl_enforced)json_object_array_add(rs,json_object_new_string("whitelist"));
    json_object_object_add(out,"block_reasons",rs);
}
static int arp_mac_for_ip(const char*ip,char*out,size_t n){FILE*f=fopen("/proc/net/arp","r");if(!f)return 0;char line[512],rip[64],mac[32];if(!fgets(line,sizeof line,f)){fclose(f);return 0;}while(fgets(line,sizeof line,f)){unsigned flags=0;if(sscanf(line,"%63s %*s %x %31s",rip,&flags,mac)==3&&!strcmp(rip,ip)&&(flags&2)&&mac_valid(mac)){snprintf(out,n,"%s",mac);fclose(f);return 1;}}fclose(f);return 0;}
static json_object *state_snapshot(void){
    json_object*j=okmsg("ok"),*ds=json_object_new_array();
    json_object*a=arr();
    for(int i=0;i<(int)json_object_array_length(a);i++){
        json_object*o=json_object_new_object();
        state_device(o,json_object_array_get_idx(a,i),i);
        json_object_array_add(ds,o);
    }
    json_object_object_add(j,"devices",ds);
    json_object_object_add(j,"state_timestamp",json_object_new_int64(time(NULL)));
    return j;
}
static int nft_apply(void){
    FILE*f=fopen(NFT_RULES,"w");if(!f)return -1;
    fprintf(f,"destroy table inet parental_control\nadd table inet parental_control\nadd chain inet parental_control pc_forward { type filter hook forward priority -5; policy accept; }\nadd chain inet parental_control pc_input { type filter hook input priority -5; policy accept; }\n");
    json_object*a=arr();
    for(int i=0;i<(int)json_object_array_length(a)&&i<128;i++){
        json_object*d=json_object_array_get_idx(a,i);int hard_block=is_blocked(d,i),wl=whitelist_ready(d)&&!manual[i],block=hard_block||wl;const char*id=sval(d,"id","");
        for(int mi=0;mi<device_mac_count(d);mi++){
            const char*m=device_mac_at(d,mi);if(!*m)continue;char device_ip[64]={0};DhcpLease*leases=NULL;int lc=cached_leases(&leases);for(int li=0;li<lc;li++)if(!strcasecmp(leases[li].mac,m)){snprintf(device_ip,sizeof device_ip,"%s",leases[li].ip);break;}struct in_addr device_ip4;int have_ip4=*device_ip&&inet_pton(AF_INET,device_ip,&device_ip4)==1;char device_ip6[8][INET6_ADDRSTRLEN];int ip6_count=ipv6_neighbors_for_mac(m,device_ip6,8);
            fprintf(f,"add rule inet parental_control pc_forward ether saddr %s counter comment \"pc:%s:out\"\n",m,id);
            if(have_ip4)fprintf(f,"add rule inet parental_control pc_forward ip daddr %s counter comment \"pc:%s:in\"\n",device_ip,id);
            for(int v6=0;v6<ip6_count;v6++)fprintf(f,"add rule inet parental_control pc_forward ip6 daddr %s counter comment \"pc:%s:in\"\n",device_ip6[v6],id);
            if(!have_ip4&&!ip6_count)fprintf(f,"add rule inet parental_control pc_forward ether daddr %s counter comment \"pc:%s:in\"\n",m,id);
            if(block){
                if(wl)nft_whitelist_rules(f,d,m,id,device_ip,have_ip4,device_ip6,ip6_count);
                fprintf(f,"add rule inet parental_control pc_forward ether saddr %s drop comment \"pc:%s:forward-src\"\n",m,id);
                if(have_ip4)fprintf(f,"add rule inet parental_control pc_forward ip daddr %s drop comment \"pc:%s:forward-dst4\"\n",device_ip,id);
                for(int v6=0;v6<ip6_count;v6++)fprintf(f,"add rule inet parental_control pc_forward ip6 daddr %s drop comment \"pc:%s:forward-dst6\"\n",device_ip6[v6],id);
                if(!have_ip4&&!ip6_count)fprintf(f,"add rule inet parental_control pc_forward ether daddr %s drop comment \"pc:%s:forward-dst\"\n",m,id);
                fprintf(f,"add rule inet parental_control pc_input ether saddr %s udp dport 67 accept comment \"pc:%s:input-dhcp4\"\n",m,id);
                fprintf(f,"add rule inet parental_control pc_input ether saddr %s udp dport 547 accept comment \"pc:%s:input-dhcp6\"\n",m,id);
                if(wl){fprintf(f,"add rule inet parental_control pc_input ether saddr %s udp dport 53 accept comment \"pc:%s:input-dns-udp\"\n",m,id);fprintf(f,"add rule inet parental_control pc_input ether saddr %s tcp dport 53 accept comment \"pc:%s:input-dns-tcp\"\n",m,id);}
                fprintf(f,"add rule inet parental_control pc_input ether saddr %s drop comment \"pc:%s:input-drop\"\n",m,id);
            }else if(bval(d,"speed_limit_enabled",0)&&ival(d,"speed_limit_mbps",0)>0){
                int kbytes_per_sec=ival(d,"speed_limit_mbps",0)*125;
                fprintf(f,"add rule inet parental_control pc_forward ether saddr %s limit rate over %d kbytes/second drop comment \"pc:%s:speed-up\"\n",m,kbytes_per_sec,id);
                if(have_ip4)fprintf(f,"add rule inet parental_control pc_forward ip daddr %s limit rate over %d kbytes/second drop comment \"pc:%s:speed-down4\"\n",device_ip,kbytes_per_sec,id);
                if(ip6_count){fprintf(f,"add rule inet parental_control pc_forward ip6 daddr { ");for(int v6=0;v6<ip6_count;v6++)fprintf(f,"%s%s",v6?", ":"",device_ip6[v6]);fprintf(f," } limit rate over %d kbytes/second drop comment \"pc:%s:speed-down6\"\n",kbytes_per_sec,id);}
                if(!have_ip4&&!ip6_count)fprintf(f,"add rule inet parental_control pc_forward ether daddr %s limit rate over %d kbytes/second drop comment \"pc:%s:speed-down\"\n",m,kbytes_per_sec,id);
            }
        }
    }
    fclose(f);int rc=system("/usr/sbin/nft -f " NFT_RULES " >/dev/null 2>&1 || /usr/bin/nft -f " NFT_RULES " >/dev/null 2>&1");return rc;
}
static int nft_commit(void){int rc=nft_apply();if(rc==0){nft_dirty=0;json_object*a=arr();for(int i=0;i<(int)json_object_array_length(a)&&i<128;i++){json_object*d=json_object_array_get_idx(a,i);blocked_cache[i]=is_blocked(d,i)||whitelist_ready(d);whitelist_cache[i]=whitelist_ready(d);}}else{nft_dirty=1;fprintf(stderr,"parental-control: nftables apply failed; will retry\n");}return rc;}

static int mac_valid(const char*m){if(!m||strlen(m)!=17)return 0;unsigned x[6];for(int i=0;i<17;i++){if(i%3==2){if(m[i]!=':')return 0;}else if(!isxdigit((unsigned char)m[i]))return 0;}if(sscanf(m,"%2x:%2x:%2x:%2x:%2x:%2x",&x[0],&x[1],&x[2],&x[3],&x[4],&x[5])!=6)return 0;if(x[0]&1)return 0;int all_zero=1,all_ff=1;for(int i=0;i<6;i++){if(x[i]!=0)all_zero=0;if(x[i]!=0xff)all_ff=0;}return !all_zero&&!all_ff;}
static int id_valid(const char*id){if(!id||!*id||strlen(id)>63)return 0;for(const unsigned char*p=(const unsigned char*)id;*p;p++)if(!(isalnum(*p)||*p=='-'||*p=='_'||*p=='.'))return 0;return 1;}
static int hostname_valid(const char *h){if(!h||!*h||strlen(h)>127)return 0;for(const unsigned char*p=(const unsigned char*)h;*p;p++)if(!(isalnum(*p)||*p=='-'||*p=='_'||*p=='.'))return 0;return 1;}
static int known_mac(const char *mac){json_object*a=arr();for(int i=0;i<(int)json_object_array_length(a);i++)if(device_has_mac(json_object_array_get_idx(a,i),mac))return 1;return 0;}
static int known_hostname(const char *host){json_object*a=arr();for(int i=0;i<(int)json_object_array_length(a);i++){json_object*d=json_object_array_get_idx(a,i),*hs;if(json_object_object_get_ex(d,"hostnames",&hs)&&json_object_is_type(hs,json_type_array))for(int k=0;k<(int)json_object_array_length(hs);k++)if(!strcasecmp(json_object_get_string(json_object_array_get_idx(hs,k)),host))return 1;}return 0;}
static json_object *discover_devices(void){json_object*out=json_object_new_array();DhcpLease*leases=NULL;int n=cached_leases(&leases);for(int i=0;i<n;i++){if(known_mac(leases[i].mac))continue;int duplicate=0;for(int k=0;k<i;k++)if(!strcasecmp(leases[k].mac,leases[i].mac)){duplicate=1;break;}if(duplicate)continue;json_object*o=json_object_new_object();json_object_object_add(o,"mac",json_object_new_string(leases[i].mac));json_object_object_add(o,"ip",json_object_new_string(leases[i].ip));if(*leases[i].host&&strcmp(leases[i].host,"*")&&strcmp(leases[i].host,"-")){json_object_object_add(o,"hostname",json_object_new_string(leases[i].host));json_object*h=json_object_new_array();json_object_array_add(h,json_object_new_string(leases[i].host));json_object_object_add(o,"hostnames",h);}json_object_object_add(o,"lease_expires",json_object_new_int64(leases[i].expiry));json_object_array_add(out,o);}return out;}
static int device_has_hostname(json_object*d,const char*host){json_object*hs;if(!host||!*host||!strcmp(host,"*")||!strcmp(host,"-"))return 0;if(json_object_object_get_ex(d,"hostnames",&hs)&&json_object_is_type(hs,json_type_array))for(int k=0;k<(int)json_object_array_length(hs);k++)if(!strcasecmp(json_object_get_string(json_object_array_get_idx(hs,k)),host))return 1;return 0;}
static int sync_dhcp_macs(void){
    DhcpLease*leases=NULL;int lease_count=cached_leases(&leases),changed=0;json_object*a=arr();
    for(int i=0;i<(int)json_object_array_length(a)&&i<128;i++){
        json_object*d=json_object_array_get_idx(a,i),*hs=NULL;
        if(!json_object_object_get_ex(d,"hostnames",&hs)||!json_object_is_type(hs,json_type_array))continue;
        for(int hi=0;hi<(int)json_object_array_length(hs);hi++){
            const char*host=json_object_get_string(json_object_array_get_idx(hs,hi));
            if(!host||!*host)continue;
            int candidate=-1,ambiguous=0;
            for(int l=0;l<lease_count;l++){
                if(!*leases[l].host||!strcmp(leases[l].host,"*")||!strcmp(leases[l].host,"-")||strcasecmp(host,leases[l].host))continue;
                if(candidate<0)candidate=l;
                else if(strcasecmp(leases[candidate].mac,leases[l].mac))ambiguous=1;
            }
            if(ambiguous){fprintf(stderr,"parental-control: DHCP link skipped device_id=%s hostname=%s reason=ambiguous-hostname\n",sval(d,"id",""),host);continue;}
            if(candidate<0)continue;
            const char*newmac=leases[candidate].mac;
            if(device_has_mac(d,newmac)||known_mac(newmac))continue;

            int primary_added=0,linked_added=0;
            json_object*lm=NULL;
            if(!*sval(d,"mac","")){
                json_object_object_add(d,"mac",json_object_new_string(newmac));
                json_object_object_add(d,"mac_auto",json_object_new_boolean(1));
                primary_added=1;
            }else{
                if(!json_object_object_get_ex(d,"linked_macs",&lm)||!json_object_is_type(lm,json_type_array)){
                    lm=json_object_new_array();json_object_object_add(d,"linked_macs",lm);
                }
                if(json_object_array_length(lm)>=16){fprintf(stderr,"parental-control: DHCP link skipped device_id=%s hostname=%s reason=linked-mac-limit\n",sval(d,"id",""),host);continue;}
                json_object_array_add(lm,json_object_new_string(newmac));
                linked_added=1;
            }

            nft_dirty=1;int rc=nft_commit();
            if(rc==0){
                counters_seen[i]=0;previous_inbound[i]=previous_outbound[i]=0;last_active[i]=0;
                save();save_state();changed=1;
                fprintf(stderr,"parental-control: DHCP device linked device_id=%s hostname=%s mac=%s ip=%s nft_result=success\n",sval(d,"id",""),host,newmac,leases[candidate].ip);
            }else{
                if(primary_added){json_object_object_add(d,"mac",json_object_new_string(""));json_object_object_add(d,"mac_auto",json_object_new_boolean(0));}
                if(linked_added&&lm&&json_object_array_length(lm)>0)json_object_array_del_idx(lm,json_object_array_length(lm)-1,1);
                nft_dirty=1;nft_commit();
                fprintf(stderr,"parental-control: DHCP device link rejected device_id=%s hostname=%s mac=%s ip=%s nft_result=failure\n",sval(d,"id",""),host,newmac,leases[candidate].ip);
            }
        }
    }
    return changed;
}
static void history_event(const char *device_id,const char *event){ensure_varlib();json_object*j=json_object_from_file(HISTORY);if(!j||!json_object_is_type(j,json_type_object)){if(j)json_object_put(j);j=json_object_new_object();}json_object*events;if(!json_object_object_get_ex(j,"events",&events)||!json_object_is_type(events,json_type_array)){events=json_object_new_array();json_object_object_add(j,"events",events);}json_object*o=json_object_new_object();json_object_object_add(o,"timestamp",json_object_new_int64(time(NULL)));json_object_object_add(o,"device_id",json_object_new_string(device_id?device_id:""));json_object_object_add(o,"event",json_object_new_string(event?event:""));json_object_array_add(events,o);while(json_object_array_length(events)>1000)json_object_array_del_idx(events,0,1);char tmp[256];snprintf(tmp,sizeof tmp,"%s.tmp",HISTORY);if(json_object_to_file_ext(tmp,j,JSON_C_TO_STRING_PRETTY)==0){if(rename(tmp,HISTORY)!=0){fprintf(stderr,"parental-control: rename %s -> %s failed: %s\n",tmp,HISTORY,strerror(errno));unlink(tmp);}}else{fprintf(stderr,"parental-control: write %s failed: %s\n",tmp,strerror(errno));unlink(tmp);}json_object_put(j);}
static json_object *history_read(void){json_object*j=json_object_from_file(HISTORY),*events=NULL;if(!j||!json_object_is_type(j,json_type_object)){if(j)json_object_put(j);j=json_object_new_object();}if(!json_object_object_get_ex(j,"events",&events)||!json_object_is_type(events,json_type_array)){json_object_object_del(j,"events");json_object_object_add(j,"events",json_object_new_array());}return j;}
static int field_type_if_present(json_object*d,const char*k,enum json_type t){json_object*v=NULL;return !json_object_object_get_ex(d,k,&v)||(v&&json_object_is_type(v,t));}
static int normalize_legacy_int_field(json_object*d,const char*k){json_object*v=NULL;if(!json_object_object_get_ex(d,k,&v))return 0;if(json_object_is_type(v,json_type_int))return 0;long long n=0;if(json_object_is_type(v,json_type_double)){double x=json_object_get_double(v);if(x!=(double)(long long)x)return-1;n=(long long)x;}else if(json_object_is_type(v,json_type_string)){const char*s=json_object_get_string(v);if(!s||!*s)return-1;char*end=NULL;errno=0;long long x=strtoll(s,&end,10);if(errno||end==s||*end)return-1;n=x;}else return-1;json_object_object_add(d,k,json_object_new_int64(n));return 1;}
static int normalize_legacy_bool_field(json_object*d,const char*k){json_object*v=NULL;if(!json_object_object_get_ex(d,k,&v))return 0;if(json_object_is_type(v,json_type_boolean))return 0;int b=-1;if(json_object_is_type(v,json_type_int)){long long n=json_object_get_int64(v);if(n==0||n==1)b=(int)n;}else if(json_object_is_type(v,json_type_string)){const char*s=json_object_get_string(v);if(s&&(!strcasecmp(s,"true")||!strcmp(s,"1")))b=1;else if(s&&(!strcasecmp(s,"false")||!strcmp(s,"0")))b=0;}if(b<0)return-1;json_object_object_add(d,k,json_object_new_boolean(b));return 1;}
static int normalize_legacy_device(json_object*d){if(!d||!json_object_is_type(d,json_type_object))return-1;int changed=0,r;const char*ints[]={"daily_limit_minutes","session_limit_minutes","break_minutes","idle_timeout_seconds","activity_threshold_bytes","speed_limit_mbps"};for(size_t i=0;i<sizeof(ints)/sizeof(ints[0]);i++){r=normalize_legacy_int_field(d,ints[i]);if(r<0)return-1;changed|=r;}json_object*idle_v=NULL;if(json_object_object_get_ex(d,"idle_timeout_seconds",&idle_v)&&json_object_is_type(idle_v,json_type_int)&&json_object_get_int(idle_v)==300){json_object_object_add(d,"idle_timeout_seconds",json_object_new_int(300));changed=1;}const char*bools[]={"enabled","daily_limit_enabled","session_limit_enabled","break_enabled","night_enabled","speed_limit_enabled","whitelist_enabled"};for(size_t i=0;i<sizeof(bools)/sizeof(bools[0]);i++){r=normalize_legacy_bool_field(d,bools[i]);if(r<0)return-1;changed|=r;}json_object*hs=NULL,*hv=NULL;if(!json_object_object_get_ex(d,"hostnames",&hs)&&json_object_object_get_ex(d,"hostname",&hv)&&json_object_is_type(hv,json_type_string)){const char*h=json_object_get_string(hv);if(h&&*h){hs=json_object_new_array();json_object_array_add(hs,json_object_new_string(h));json_object_object_add(d,"hostnames",hs);changed=1;}}return changed;}
static const char *validate_device(json_object*d,int editing){json_object*hs,*nv=NULL,*mv=NULL;if(!d||!json_object_is_type(d,json_type_object))return "invalid device settings";if(!json_object_object_get_ex(d,"name",&nv)||!json_object_is_type(nv,json_type_string)||!json_object_object_get_ex(d,"mac",&mv)||!json_object_is_type(mv,json_type_string))return "name and MAC must be strings";const char*name=json_object_get_string(nv),*mac=json_object_get_string(mv);if(!json_object_object_get_ex(d,"hostnames",&hs)||!json_object_is_type(hs,json_type_array)||json_object_array_length(hs)>16)return "name and 0-16 hostnames are required";int host_count=(int)json_object_array_length(hs);if(!name||!*name||strlen(name)>127||((*mac&&!mac_valid(mac))||(!*mac&&host_count<1)))return "valid MAC or at least one Hostname is required";json_object*lm=NULL;if(json_object_object_get_ex(d,"linked_macs",&lm)){if(!json_object_is_type(lm,json_type_array)||json_object_array_length(lm)>16)return "linked_macs must contain 0-16 MAC addresses";for(int mi=0;mi<(int)json_object_array_length(lm);mi++){json_object*mv2=json_object_array_get_idx(lm,mi);if(!mv2||!json_object_is_type(mv2,json_type_string)||!mac_valid(json_object_get_string(mv2)))return "invalid linked MAC";const char*mm=json_object_get_string(mv2);if(*mac&&!strcasecmp(mac,mm))return "duplicate linked MAC";for(int mk=0;mk<mi;mk++)if(!strcasecmp(mm,json_object_get_string(json_object_array_get_idx(lm,mk))))return "duplicate linked MAC";}}for(int i=0;i<(int)json_object_array_length(hs);i++){json_object*hv=json_object_array_get_idx(hs,i);if(!hv||!json_object_is_type(hv,json_type_string))return "hostname must be a string";const char*h=json_object_get_string(hv);if(!hostname_valid(h))return "invalid hostname";for(int k=0;k<i;k++)if(!strcasecmp(h,json_object_get_string(json_object_array_get_idx(hs,k))))return "duplicate hostname";if(!editing&&known_hostname(h))return "duplicate hostname";}const char*ints[]={"daily_limit_minutes","session_limit_minutes","break_minutes","idle_timeout_seconds","activity_threshold_bytes","speed_limit_mbps"};for(size_t i=0;i<sizeof(ints)/sizeof(ints[0]);i++)if(!field_type_if_present(d,ints[i],json_type_int))return "numeric device settings must be integers";const char*bools[]={"enabled","daily_limit_enabled","session_limit_enabled","break_enabled","night_enabled","speed_limit_enabled","whitelist_enabled"};for(size_t i=0;i<sizeof(bools)/sizeof(bools[0]);i++)if(!field_type_if_present(d,bools[i],json_type_boolean))return "device flags must be booleans";int daily=ival(d,"daily_limit_minutes",0),session=ival(d,"session_limit_minutes",0),brk=ival(d,"break_minutes",0),idle=ival(d,"idle_timeout_seconds",300),threshold=ival(d,"activity_threshold_bytes",4096),speed=ival(d,"speed_limit_mbps",5);if(daily<0||daily>1440||session<0||session>1440||brk<0||brk>1440)return "device limits must be between 0 and 1440 minutes";if(bval(d,"daily_limit_enabled",0)&&daily<1)return "daily limit must be at least 1 minute";if(bval(d,"session_limit_enabled",0)&&session<1)return "session limit must be at least 1 minute";if(bval(d,"break_enabled",0)&&brk<1)return "break must be at least 1 minute";if(idle<0||idle>86400)return "idle timeout must be between 0 and 86400 seconds";if(threshold<1||threshold>1073741824)return "activity threshold must be between 1 and 1073741824 bytes";if(speed<0||speed>10000)return "speed limit must be between 0 and 10000 Mbps";if(bval(d,"speed_limit_enabled",0)&&speed<1)return "speed limit must be at least 1 Mbps";if(bval(d,"night_enabled",0)){json_object*sv=NULL,*ev=NULL;if(!json_object_object_get_ex(d,"night_start",&sv)||!json_object_is_type(sv,json_type_string)||!time_valid(json_object_get_string(sv))||!json_object_object_get_ex(d,"night_end",&ev)||!json_object_is_type(ev,json_type_string)||!time_valid(json_object_get_string(ev)))return "invalid night time; use 24-hour HH:MM (00:00-23:59)";if(!strcmp(json_object_get_string(sv),json_object_get_string(ev)))return "night start and end must be different";}json_object*wls=NULL;if(json_object_object_get_ex(d,"whitelist_entries",&wls)){if(!json_object_is_type(wls,json_type_array)||json_object_array_length(wls)>64)return "whitelist must contain 0-64 domains or IP addresses";for(int wi=0;wi<(int)json_object_array_length(wls);wi++){json_object*wv=json_object_array_get_idx(wls,wi);if(!wv||!json_object_is_type(wv,json_type_string)||!whitelist_entry_valid(json_object_get_string(wv)))return "invalid whitelist domain or IP";for(int wk=0;wk<wi;wk++)if(!strcasecmp(json_object_get_string(wv),json_object_get_string(json_object_array_get_idx(wls,wk))))return "duplicate whitelist entry";}}if(bval(d,"whitelist_enabled",0)){json_object*sv=NULL,*ev=NULL;if(!wls||json_object_array_length(wls)==0)return "whitelist requires at least one domain or IP";if(!json_object_object_get_ex(d,"whitelist_start",&sv)||!json_object_is_type(sv,json_type_string)||!time_valid(json_object_get_string(sv))||!json_object_object_get_ex(d,"whitelist_end",&ev)||!json_object_is_type(ev,json_type_string)||!time_valid(json_object_get_string(ev)))return "invalid whitelist time; use 24-hour HH:MM (00:00-23:59)";if(!strcmp(json_object_get_string(sv),json_object_get_string(ev)))return "whitelist start and end must be different";}return NULL;}
static const char *status_reason(int code){switch(code){case 200:return "OK";case 400:return "Bad Request";case 404:return "Not Found";case 405:return "Method Not Allowed";case 409:return "Conflict";case 413:return "Payload Too Large";case 500:return "Internal Server Error";case 503:return "Service Unavailable";default:return "Error";}}
static void response(int c,int code,json_object*j){const char*b=json_object_to_json_string_ext(j,JSON_C_TO_STRING_PLAIN);dprintf(c,"HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",code,status_reason(code),strlen(b),b);}
static json_object *okmsg(const char*m){json_object*j=json_object_new_object();json_object_object_add(j,"success",json_object_new_boolean(1));if(m)json_object_object_add(j,"message",json_object_new_string(m));return j;}
static void handle(int c){char b[65536];ssize_t n=read_http_request(c,b,sizeof b);if(n==-2){json_object*j=okmsg("request too large");json_object_object_add(j,"success",json_object_new_boolean(0));response(c,413,j);json_object_put(j);return;}if(n<=0)return;b[n]=0;char method[8],path[512];if(sscanf(b,"%7s %511s",method,path)!=2)return;char *body=strstr(b,"\r\n\r\n");body=body?body+4:(char*)"";json_object*j=NULL;int code=200;
if(strcmp(method,"GET")&&(!strcmp(path,"/api/health")||!strcmp(path,"/api/status")||!strcmp(path,"/api/state")||!strcmp(path,"/api/discovered")||!strcmp(path,"/api/history"))){j=okmsg("method not allowed");json_object_object_add(j,"success",json_object_new_boolean(0));code=405;}
else if(!strcmp(path,"/api/health")||!strcmp(path,"/api/status")){j=okmsg("ok");json_object_object_add(j,"device_count",json_object_new_int(json_object_array_length(arr())));}
else if(!strcmp(path,"/api/state")){j=state_snapshot();}
else if(!strcmp(path,"/api/devices")&&!strcmp(method,"GET")){j=okmsg(NULL);json_object_object_add(j,"devices",json_object_get(arr()));}
else if(!strcmp(path,"/api/devices")&&!strcmp(method,"POST")){json_object*d=json_tokener_parse(body);const char*err=validate_device(d,0);if(json_object_array_length(arr())>=128){j=okmsg("device limit reached");json_object_object_add(j,"success",json_object_new_boolean(0));code=400;if(d)json_object_put(d);}else if(err){j=okmsg(err);json_object_object_add(j,"success",json_object_new_boolean(0));code=400;if(d)json_object_put(d);}else if(*sval(d,"mac","")&&known_mac(sval(d,"mac",""))){j=okmsg("duplicate device id or MAC");json_object_object_add(j,"success",json_object_new_boolean(0));code=409;json_object_put(d);}else{json_object*vdefault=NULL;if(!json_object_object_get_ex(d,"enabled",&vdefault))json_object_object_add(d,"enabled",json_object_new_boolean(1));if(!json_object_object_get_ex(d,"mac_auto",&vdefault))json_object_object_add(d,"mac_auto",json_object_new_boolean(!*sval(d,"mac","")));if(!json_object_object_get_ex(d,"activity_threshold_bytes",&vdefault))json_object_object_add(d,"activity_threshold_bytes",json_object_new_int(1));if(!json_object_object_get_ex(d,"idle_timeout_seconds",&vdefault))json_object_object_add(d,"idle_timeout_seconds",json_object_new_int(300));json_object_object_del(d,"id");char id[64];const char*id_seed=sval(d,"mac","");char host_seed[128]={0};if(!*id_seed){json_object*hs=NULL;if(json_object_object_get_ex(d,"hostnames",&hs)&&json_object_is_type(hs,json_type_array)&&json_object_array_length(hs)>0){snprintf(host_seed,sizeof host_seed,"%s",json_object_get_string(json_object_array_get_idx(hs,0)));id_seed=host_seed;}}if(make_unique_device_id(id_seed,id)!=0){j=okmsg("unable to allocate device id");json_object_object_add(j,"success",json_object_new_boolean(0));code=409;json_object_put(d);}else{json_object_object_add(d,"id",json_object_new_string(id));json_object_array_add(arr(),d);save();nft_dirty=1;nft_commit();save_state();history_event(sval(d,"id",""),"device created");j=okmsg("device created");}}}
else if(!strcmp(path,"/api/connect-candidate")&&!strcmp(method,"POST")){json_object*q=json_tokener_parse(body);const char*ip=q?sval(q,"ip",""):"";const char*label=q?sval(q,"label",""):"";struct in_addr ia;char mac[32]={0};int target=-1;if(*label){json_object*a=arr();for(int k=0;k<(int)json_object_array_length(a);k++)if(!strcasecmp(sval(json_object_array_get_idx(a,k),"name",""),label)){target=k;break;}}if(!*label||target<0){j=okmsg("profile not found");json_object_object_add(j,"success",json_object_new_boolean(0));code=404;}else if(!*ip||inet_pton(AF_INET,ip,&ia)!=1||!arp_mac_for_ip(ip,mac,sizeof mac)){j=okmsg("device is not present in ARP table");json_object_object_add(j,"success",json_object_new_boolean(0));code=404;}else{json_object*d=json_object_array_get_idx(arr(),target);int owner=-1;for(int k=0;k<(int)json_object_array_length(arr());k++)if(device_has_mac(json_object_array_get_idx(arr(),k),mac)){owner=k;break;}if(owner>=0&&owner!=target){j=okmsg("MAC already belongs to another profile");json_object_object_add(j,"success",json_object_new_boolean(0));code=409;}else{int added=0;if(!device_has_mac(d,mac)){if(!*sval(d,"mac","")){json_object_object_add(d,"mac",json_object_new_string(mac));json_object_object_add(d,"mac_auto",json_object_new_boolean(1));}else{json_object*lm=NULL;if(!json_object_object_get_ex(d,"linked_macs",&lm)||!json_object_is_type(lm,json_type_array)){lm=json_object_new_array();json_object_object_add(d,"linked_macs",lm);}json_object_array_add(lm,json_object_new_string(mac));}added=1;save();nft_dirty=1;nft_commit();save_state();history_event(sval(d,"id",""),"device linked by pairing");}j=okmsg(added?"device linked":"device already linked");json_object_object_add(j,"name",json_object_new_string(sval(d,"name","")));json_object_object_add(j,"ip",json_object_new_string(ip));json_object_object_add(j,"mac",json_object_new_string(mac));json_object_object_add(j,"added",json_object_new_boolean(added));}}if(q)json_object_put(q);}
else if(!strcmp(path,"/api/discovered")){j=okmsg(NULL);json_object_object_add(j,"devices",discover_devices());}
else if(!strcmp(path,"/api/history")){j=okmsg(NULL);json_object*h=history_read(),*e=NULL;if(json_object_object_get_ex(h,"events",&e))json_object_object_add(j,"events",json_object_get(e));else json_object_object_add(j,"events",json_object_new_array());json_object_put(h);}
else if(!strncmp(path,"/api/devices/",13)){char tmp[512];snprintf(tmp,sizeof tmp,"%s",path+13);char *slash=strchr(tmp,'/');if(slash)*slash++=0;int i=findid(tmp);if(i<0){j=okmsg("device not found");json_object_object_add(j,"success",json_object_new_boolean(0));code=404;}
else if(!slash&&!strcmp(method,"DELETE")){history_event(tmp,"device deleted");json_object_array_del_idx(arr(),i,1);runtime_remove(i);save();nft_dirty=1;nft_commit();save_state();j=okmsg("device deleted");}
else if(!slash&&!strcmp(method,"PUT")){json_object*d=json_tokener_parse(body);const char*err=validate_device(d,1);int duplicate=0;if(d){const char*newmac=sval(d,"mac","");if(*newmac)for(int k=0;k<(int)json_object_array_length(arr());k++)if(k!=i&&device_has_mac(json_object_array_get_idx(arr(),k),newmac))duplicate=1;json_object*lm_check=NULL;if(json_object_object_get_ex(d,"linked_macs",&lm_check)&&json_object_is_type(lm_check,json_type_array))for(int mi=0;mi<(int)json_object_array_length(lm_check);mi++){const char*mm=json_object_get_string(json_object_array_get_idx(lm_check,mi));for(int k=0;k<(int)json_object_array_length(arr());k++)if(k!=i&&device_has_mac(json_object_array_get_idx(arr(),k),mm))duplicate=1;}json_object*hs=NULL;if(json_object_object_get_ex(d,"hostnames",&hs)&&json_object_is_type(hs,json_type_array))for(int h=0;h<(int)json_object_array_length(hs);h++){const char*host=json_object_get_string(json_object_array_get_idx(hs,h));for(int k=0;k<(int)json_object_array_length(arr());k++)if(k!=i&&device_has_hostname(json_object_array_get_idx(arr(),k),host))duplicate=1;}}if(err){j=okmsg(err);json_object_object_add(j,"success",json_object_new_boolean(0));code=400;if(d)json_object_put(d);}else if(duplicate){j=okmsg("duplicate hostname or MAC");json_object_object_add(j,"success",json_object_new_boolean(0));code=409;json_object_put(d);}else{json_object *old=json_object_array_get_idx(arr(),i),*v=NULL,*present=NULL;int mac_changed=strcasecmp(sval(old,"mac",""),sval(d,"mac",""))!=0;if(json_object_object_get_ex(old,"id",&v))json_object_object_add(d,"id",json_object_get(v));const char*preserve[]={"enabled","mac_auto","activity_threshold_bytes","idle_timeout_seconds","speed_limit_enabled","speed_limit_mbps","whitelist_enabled","whitelist_start","whitelist_end","whitelist_entries"};for(size_t k=0;k<sizeof(preserve)/sizeof(preserve[0]);k++){present=NULL;if(!json_object_object_get_ex(d,preserve[k],&present)&&json_object_object_get_ex(old,preserve[k],&v))json_object_object_add(d,preserve[k],json_object_get(v));}json_object_array_put_idx(arr(),i,d);if(mac_changed){counters_seen[i]=0;previous_inbound[i]=previous_outbound[i]=0;last_active[i]=0;}if(!bval(d,"daily_limit_enabled",0)){used_seconds[i]=0;bonus_minutes[i]=0;}if(!bval(d,"session_limit_enabled",0)||!bval(d,"break_enabled",0))session_seconds[i]=0;if(!bval(d,"break_enabled",0)){clear_break_state(i);}else if(bval(d,"session_limit_enabled",0)){int lim=ival(d,"session_limit_minutes",0)*60;if(lim>0&&session_seconds[i]>=lim&&!break_active[i]){temporary_unblock[i]=0;start_break_state(i,ival(d,"break_minutes",0)*60);}}save();nft_dirty=1;nft_commit();save_state();history_event(tmp,"device updated");j=okmsg("device updated");}}
else if(slash&&!strcmp(method,"POST")){const char*ev="action applied";long long saved_used=used_seconds[i],saved_session=session_seconds[i],saved_bonus=bonus_minutes[i];int saved_break=break_active[i],saved_temp=temporary_unblock[i];time_t saved_until=brk_until[i],saved_until_mono=brk_until_mono[i];if(!strcmp(slash,"block")||!strcmp(slash,"unblock")){int old_manual=manual[i],old_temp=temporary_unblock[i];int requested=!strcmp(slash,"block"),auto_reason=automatic_blocked(json_object_array_get_idx(arr(),i),i);manual[i]=requested;temporary_unblock[i]=requested?0:auto_reason;counters_seen[i]=0;previous_inbound[i]=previous_outbound[i]=0;last_active[i]=0;nft_dirty=1;if(nft_commit()!=0){manual[i]=old_manual;temporary_unblock[i]=old_temp;nft_dirty=1;nft_commit();j=okmsg("nftables rule was not applied");json_object_object_add(j,"success",json_object_new_boolean(0));json_object_object_add(j,"nft_exit_status",json_object_new_int(1));code=500;response(c,code,j);json_object_put(j);return;}ev=requested?"blocked":"unblocked";}else if(!strcmp(slash,"break")){if(!bval(json_object_array_get_idx(arr(),i),"break_enabled",0)){j=okmsg("break is disabled");json_object_object_add(j,"success",json_object_new_boolean(0));code=400;response(c,code,j);json_object_put(j);return;}temporary_unblock[i]=0;start_break_state(i,ival(json_object_array_get_idx(arr(),i),"break_minutes",60)*60);ev="break started";}else if(!strcmp(slash,"bonus")){json_object*q=json_tokener_parse(body);int mins=q?ival(q,"minutes",0):0;if(q)json_object_put(q);if(mins<=0||mins>1440||bonus_minutes[i]+mins>1440){j=okmsg("invalid bonus");json_object_object_add(j,"success",json_object_new_boolean(0));response(c,400,j);json_object_put(j);return;}bonus_minutes[i]+=mins;ev="bonus added";}else if(!strcmp(slash,"reset-today")){used_seconds[i]=session_seconds[i]=bonus_minutes[i]=0;clear_break_state(i);temporary_unblock[i]=0;ev="today reset";}else if(!strcmp(slash,"reset_temporary_state")){temporary_unblock[i]=0;ev="temporary state reset";}else{j=okmsg("route not found");json_object_object_add(j,"success",json_object_new_boolean(0));code=404;response(c,code,j);json_object_put(j);return;}if(strcmp(slash,"block")&&strcmp(slash,"unblock")){nft_dirty=1;if(nft_commit()!=0){used_seconds[i]=saved_used;session_seconds[i]=saved_session;bonus_minutes[i]=saved_bonus;break_active[i]=saved_break;temporary_unblock[i]=saved_temp;brk_until[i]=saved_until;brk_until_mono[i]=saved_until_mono;nft_dirty=1;nft_commit();j=okmsg("nftables rule was not applied");json_object_object_add(j,"success",json_object_new_boolean(0));json_object_object_add(j,"nft_exit_status",json_object_new_int(1));code=500;response(c,code,j);json_object_put(j);return;}}save_state();history_event(tmp,ev);j=okmsg(ev);}else{j=okmsg("route not found");json_object_object_add(j,"success",json_object_new_boolean(0));code=404;}}
else{j=okmsg("route not found");json_object_object_add(j,"success",json_object_new_boolean(0));code=404;}response(c,code,j);json_object_put(j);}
int main(void){signal(SIGPIPE,SIG_IGN);root=json_object_from_file(DEVICES);if(!root){if(access(DEVICES,F_OK)==0){fprintf(stderr,"parental-control: failed to parse %s; refusing to replace it with an empty config\n",DEVICES);return 1;}root=json_object_new_object();json_object_object_add(root,"devices",json_object_new_array());save();}json_object*startup_devices=NULL;if(!json_object_is_type(root,json_type_object)||!json_object_object_get_ex(root,"devices",&startup_devices)||!json_object_is_type(startup_devices,json_type_array)||json_object_array_length(startup_devices)>128){fprintf(stderr,"parental-control: invalid %s: expected object with devices array (max 128)\n",DEVICES);return 1;}int config_normalized=0;for(int i=0;i<(int)json_object_array_length(startup_devices);i++){json_object*d=json_object_array_get_idx(startup_devices,i),*idv=NULL;int normalized=normalize_legacy_device(d);if(normalized<0){fprintf(stderr,"parental-control: invalid legacy field type in device %d in %s\n",i,DEVICES);return 1;}config_normalized|=normalized;const char*id=(json_object_object_get_ex(d,"id",&idv)&&json_object_is_type(idv,json_type_string))?json_object_get_string(idv):"";const char*err=validate_device(d,1);if(!id_valid(id)||err){fprintf(stderr,"parental-control: invalid device %d in %s: %s\n",i,DEVICES,!id_valid(id)?"invalid id":err);return 1;}for(int k=0;k<i;k++){json_object*other=json_object_array_get_idx(startup_devices,k);if(!strcmp(id,sval(other,"id",""))){fprintf(stderr,"parental-control: duplicate device id in %s\n",DEVICES);return 1;}for(int mi=0;mi<device_mac_count(d);mi++)if(device_has_mac(other,device_mac_at(d,mi))){fprintf(stderr,"parental-control: duplicate MAC in %s\n",DEVICES);return 1;}json_object*hs=NULL;if(json_object_object_get_ex(d,"hostnames",&hs)&&json_object_is_type(hs,json_type_array))for(int h=0;h<(int)json_object_array_length(hs);h++)if(device_has_hostname(other,json_object_get_string(json_object_array_get_idx(hs,h)))){fprintf(stderr,"parental-control: duplicate hostname in %s\n",DEVICES);return 1;}}}if(config_normalized){fprintf(stderr,"parental-control: normalized legacy device settings in %s\n",DEVICES);save();}unlink(SOCK);int s=socket(AF_UNIX,SOCK_STREAM,0);struct sockaddr_un a={.sun_family=AF_UNIX};strncpy(a.sun_path,SOCK,sizeof(a.sun_path)-1);mkdir("/var/run",0755);if(bind(s,(struct sockaddr*)&a,sizeof a)||listen(s,32)){perror("parental-control");return 1;}chmod(SOCK,0660);load_state();sync_dhcp_macs();save_state();nft_dirty=1;if(nft_commit()!=0){fprintf(stderr,"parental-control: initial nftables apply failed\n");close(s);unlink(SOCK);return 1;}activity_fd=open_activity_socket();pthread_t web_thread;if(pthread_create(&web_thread,NULL,web_thread_main,NULL)!=0){fprintf(stderr,"parental-control: failed to start integrated web server\n");close(s);unlink(SOCK);return 1;}pthread_detach(web_thread);for(;;){struct pollfd pfd={.fd=s,.events=POLLIN};int r=poll(&pfd,1,1000);tick();if(r>0&&(pfd.revents&POLLIN)){int c=accept(s,NULL,NULL);if(c>=0){struct timeval tv={.tv_sec=5,.tv_usec=0};setsockopt(c,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);setsockopt(c,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof tv);handle(c);close(c);}}}}
