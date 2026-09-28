static void *lookup(void *map, const void *key, size_t n) {
    static struct payload_args scratch;
    if(map==&payload_scratch) return &scratch;
    if(map==&capture_loss) return &losses[*(const __u32 *)key];
    for(int i=0;i<32;i++) if(entries[i].map==map && entries[i].keylen==n && !memcmp(entries[i].key,key,n)) return entries[i].value.bytes;
    return NULL;
}
static int chunks;
static void gadget_submit_buf(void *ctx, void *map, void *p, size_t size) {
    (void)ctx; (void)map; (void)size;
    struct httpevent *e=p;
    assert(e->buf_len<=MAX_DATAEVENT_BUFFER);
    assert(e->timestamp_raw==1 && e->proc.pid==1 && e->socket_inode==123);
    fwrite(e->buf,1,e->buf_len,stdout); chunks++;
    gadget_discard_buf(e);
}
int main(int argc, char **argv) {
    assert(argc==6);
    char data[600000]; size_t len=fread(data,1,sizeof(data),stdin);
    long ret=strtol(argv[2],NULL,10); if(ret<0) ret=len;
    size_t split=strtoul(argv[3],NULL,10);
    fail_reserve=atoi(argv[4]); fail_copy=atoi(argv[5]);
    struct syscall_trace_enter enter={.args={0,(__u64)data,len}};
    struct syscall_trace_exit exit={.ret=ret};
    bool rx=argv[1][0]=='r';
    if(strlen(argv[1])==1) {
        pre_receive_syscalls(&enter); process_packet(&exit,rx ? "read" : "write",rx);
    } else {
        struct iovec iov[40]; size_t off=0,n=0;
        while(off<len && n<40) { size_t size=split && split<len-off ? split : len-off; iov[n++]=(struct iovec){data+off,size}; off+=size; }
        assert(off==len);
        enter.args[1]=(__u64)iov; enter.args[2]=n;
        pre_process_iovec(&enter); process_msg(&exit,rx ? "readv" : "writev",rx);
    }
    int first_chunks=chunks;
    if(losses[0]+losses[1]+losses[2]) {
        char tail[]="later body";
        enter.args[1]=(__u64)tail; enter.args[2]=sizeof(tail)-1; exit.ret=sizeof(tail)-1;
        pre_receive_syscalls(&enter); process_packet(&exit,"write",rx);
        assert(first_chunks==chunks); // no body continuation can bridge a hole
    }
    fprintf(stderr,"%d %llu %llu %llu\n",chunks,(unsigned long long)losses[0],(unsigned long long)losses[1],(unsigned long long)losses[2]);
}
