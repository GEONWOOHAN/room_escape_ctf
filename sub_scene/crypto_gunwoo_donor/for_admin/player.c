#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <zlib.h>

#define N 64
#define BS 16
#define POLICIES 3

static const unsigned policy_classes[POLICIES]={3,8,13};
static const uint64_t admin_values[POLICIES]={0xa11d0001ULL,0,0x5641554c54000001ULL};
static const uint64_t guest_values[POLICIES]={0x4755455354ULL,10001337ULL,0};
static const unsigned char class_code[]={1,2,5,0,0,0,5,2,3,0,0,0,4,1,6,2,4,2,15,0,0,0,8,255};
static const unsigned char step_code[]={1,3,7,7,4,3,6,9,4,3,7,13,4,255};
static const unsigned char layout_seed_code[]={1,2,0x63,0x7c,0xa5,0x6d,4,255};
static const unsigned char policy_seed_code[]={1,2,0x91,0xe1,0x0b,0xc4,4,255};

static uint32_t vm(const unsigned char*code,uint32_t input){
    uint32_t stack[16];unsigned sp=0,pc=0;
    for(;;){
        unsigned op=code[pc++];uint32_t a,b;
        if(op==1)stack[sp++]=input;
        else if(op==2){memcpy(&a,code+pc,4);pc+=4;stack[sp++]=a;}
        else if(op==3)stack[sp]=stack[sp-1],sp++;
        else if(op==4){b=stack[--sp];a=stack[--sp];stack[sp++]=a^b;}
        else if(op==5){b=stack[--sp];a=stack[--sp];stack[sp++]=a*b;}
        else if(op==6)stack[sp-1]>>=code[pc++];
        else if(op==7)stack[sp-1]<<=code[pc++];
        else if(op==8){b=stack[--sp];stack[sp-1]&=b;}
        else if(op==255)return stack[sp-1];
        else return 0;
    }
}
static unsigned tweak_class(unsigned i){return vm(class_code,i);}
static uint32_t step(uint32_t x){return vm(step_code,x);}

static void make_layout(uint32_t epoch,unsigned out[N]){
    uint32_t state=vm(layout_seed_code,epoch);unsigned logical[N],physical[N];
    for(unsigned i=0;i<N;i++)out[i]=i;
    for(unsigned group=0;group<16;group++){
        unsigned count=0;
        for(unsigned i=0;i<N;i++)if(tweak_class(i)==group){logical[count]=i;physical[count++]=i;}
        for(unsigned i=count-1;i;i--){state=step(state);unsigned j=state%(i+1),t=physical[i];physical[i]=physical[j];physical[j]=t;}
        for(unsigned i=0;i<count;i++)out[logical[i]]=physical[i];
    }
}

#if defined(__GNUC__)
#define NOINLINE __attribute__((noinline))
#else
#define NOINLINE
#endif

static NOINLINE void policy_positions(uint32_t epoch,unsigned donors[POLICIES],unsigned targets[POLICIES],unsigned decoys[POLICIES]){
    uint32_t state=vm(policy_seed_code,epoch);
    for(unsigned kind=0;kind<POLICIES;kind++){
        unsigned members[4],remaining[2],count=0,rest=0;
        for(unsigned i=0;i<N;i++)if(tweak_class(i)==policy_classes[kind])members[count++]=i;
        state=step(state);unsigned donor_at=state%count;
        state=step(state);unsigned target_at=(donor_at+1+state%(count-1))%count;
        for(unsigned i=0;i<count;i++)if(i!=donor_at&&i!=target_at)remaining[rest++]=i;
        state=step(state);unsigned decoy_at=remaining[state%rest];
        donors[kind]=members[donor_at];targets[kind]=members[target_at];decoys[kind]=members[decoy_at];
    }
}
static uint32_t rol32(uint32_t value,unsigned count){return(value<<count)|(value>>(32-count));}
static NOINLINE uint32_t routed_epoch(uint32_t epoch,uint32_t route){return epoch^rol32(route,11)^0x51a7c3d9u;}
static uint32_t session_stamp(uint32_t epoch){return step(epoch*0x9e3779b1u+0x7f4a7c15u);}
static uint32_t route_seal(uint32_t epoch,uint32_t route){return step(route^rol32(epoch,7)^0xa5c31f27u);}
static NOINLINE void active_positions(uint32_t epoch,uint32_t route,unsigned donors[POLICIES],unsigned targets[POLICIES],unsigned decoys[POLICIES]){
    unsigned pd[POLICIES],pt[POLICIES],px[POLICIES],rd[POLICIES],rt[POLICIES],rx[POLICIES];
    policy_positions(epoch,pd,pt,px);policy_positions(routed_epoch(epoch,route),rd,rt,rx);
    donors[0]=pd[0];targets[0]=pt[0];decoys[0]=px[0];
    for(unsigned i=1;i<POLICIES;i++){donors[i]=rd[i];targets[i]=rt[i];decoys[i]=rx[i];}
}

static uint16_t generation(uint32_t e){return(uint16_t)((e>>16)^e^0x5243u);}
static void record(unsigned char out[BS],unsigned kind,uint16_t gen,uint64_t value){
    memset(out,0,BS);out[0]=0xd7;out[1]=(unsigned char)kind;memcpy(out+2,&gen,2);memcpy(out+4,&value,8);
    uint32_t sum=(uint32_t)crc32(0,out,12);memcpy(out+12,&sum,4);
}
static void local_key(uint32_t epoch,uint32_t route,unsigned char out[32]){
    static const uint32_t words[8]={0x17c8d2a1u,0xb96403efu,0x52ad718cu,0xe30f46b5u,0x8a216dc7u,0x4fd59032u,0xc61be874u,0x0953afdeu};
    unsigned char material[48];memcpy(material,words,32);memcpy(material+32,&epoch,4);memcpy(material+36,&route,4);memcpy(material+40,"probe-v5",8);SHA256(material,48,out);
}
static void aes_block(const unsigned char in[BS],unsigned char out[BS],const unsigned char key[32],int dec){
    EVP_CIPHER_CTX*ctx=EVP_CIPHER_CTX_new();int used=0,final=0;
    if(dec)EVP_DecryptInit_ex(ctx,EVP_aes_256_ecb(),NULL,key,NULL);else EVP_EncryptInit_ex(ctx,EVP_aes_256_ecb(),NULL,key,NULL);
    EVP_CIPHER_CTX_set_padding(ctx,0);
    if(dec){EVP_DecryptUpdate(ctx,out,&used,in,BS);EVP_DecryptFinal_ex(ctx,out+used,&final);}else{EVP_EncryptUpdate(ctx,out,&used,in,BS);EVP_EncryptFinal_ex(ctx,out+used,&final);}
    EVP_CIPHER_CTX_free(ctx);
}
static void gf_double(unsigned char block[BS]){
    unsigned carry=block[0]>>7;
    for(unsigned i=0;i<BS-1;i++)block[i]=(unsigned char)((block[i]<<1)|(block[i+1]>>7));
    block[BS-1]<<=1;if(carry)block[BS-1]^=0x87;
}
static void tweak(unsigned i,uint32_t epoch,const unsigned char key[32],unsigned char out[BS]){
    unsigned char nonce[BS]={0};memcpy(nonce,&epoch,4);memcpy(nonce+4,"DONOR-XEX-v6",12);aes_block(nonce,out,key,0);
    for(unsigned n=0;n<tweak_class(i);n++)gf_double(out);
}
static void xex(const unsigned char in[BS],unsigned char out[BS],unsigned i,const unsigned char key[32],uint32_t epoch,int dec){
    unsigned char m[BS],x[BS],y[BS];tweak(i,epoch,key,m);
    for(int j=0;j<BS;j++)x[j]=in[j]^m[j];
    aes_block(x,y,key,dec);for(int j=0;j<BS;j++)out[j]=y[j]^m[j];
}
static void initialize(unsigned char mem[N][BS],uint32_t epoch,uint32_t route){
    unsigned map[N],donors[POLICIES],targets[POLICIES],decoys[POLICIES];unsigned char plain[N][BS],d[32],label[32],key[32];
    make_layout(epoch,map);active_positions(epoch,route,donors,targets,decoys);local_key(epoch,route,key);
    for(unsigned i=0;i<N;i++){int n=snprintf((char*)label,sizeof(label),"padding:%u:%u",i,epoch);SHA256(label,n,d);memcpy(plain[i],d,BS);}
    for(unsigned i=0;i<POLICIES;i++){record(plain[donors[i]],i+1,generation(epoch),admin_values[i]);record(plain[targets[i]],i+1,generation(epoch),guest_values[i]);record(plain[decoys[i]],i+1,generation(epoch)+1,admin_values[i]);}
    for(unsigned i=0;i<N;i++)xex(plain[i],mem[map[i]],map[i],key,epoch,0);
}

static int command_is(const char *line,const char *command){
    size_t n=strlen(command);
    return !strncmp(line,command,n)&&(line[n]=='\0'||line[n]=='\n'||line[n]=='\r');
}
static int hex_nibble(unsigned char c){
    if(c>='0'&&c<='9')return c-'0';
    c=(unsigned char)tolower(c);
    return c>='a'&&c<='f'?c-'a'+10:-1;
}
static int parse_block(const char *hex,unsigned char out[BS]){
    if(strlen(hex)!=2*BS)return 0;
    for(int i=0;i<BS;i++){
        int high=hex_nibble((unsigned char)hex[2*i]);
        int low=hex_nibble((unsigned char)hex[2*i+1]);
        if(high<0||low<0)return 0;
        out[i]=(unsigned char)((high<<4)|low);
    }
    return 1;
}
static int whitespace_only(const char *text){
    while(*text)if(!isspace((unsigned char)*text++))return 0;
    return 1;
}

int main(void){
    uint32_t session[2],epoch,route;unsigned char mem[N][BS],want[BS],got[BS],key[32];unsigned map[N],donors[POLICIES],targets[POLICIES],decoys[POLICIES];char line[256],hex[33];int index,consumed,writes=3;
    if(RAND_bytes((unsigned char*)session,sizeof(session))!=1)return 1;
    epoch=session[0];route=session[1];
    initialize(mem,epoch,route);make_layout(epoch,map);active_positions(epoch,route,donors,targets,decoys);local_key(epoch,route,key);
    printf("DONOR local processor / build 6.2\nsession stamp:%08x\nwrite budget:%d\ncommands: sheath | diagnose | transplant <index> <32-hex> | attest | quit\n",session_stamp(epoch),writes);
    while(printf("donor> "),fflush(stdout),fgets(line,sizeof(line),stdin)){
        if(command_is(line,"sheath")){for(int i=0;i<N;i++){printf("%02d:",i);for(int j=0;j<BS;j++)printf("%02x",mem[i][j]);puts("");}}
        else if(sscanf(line,"transplant %d %32s %n",&index,hex,&consumed)==2&&whitespace_only(line+consumed)&&index>=0&&index<N&&strlen(hex)==32){
            unsigned char block[BS];
            if(!parse_block(hex,block)){puts("rejected");continue;}
            if(!writes){puts("write budget exhausted");continue;}
            memcpy(mem[index],block,BS);printf("accepted (%d writes left)\n",--writes);
        }else if(command_is(line,"diagnose")){
            xex(mem[map[targets[0]]],got,map[targets[0]],key,epoch,1);record(want,1,generation(epoch),admin_values[0]);
            if(!memcmp(want,got,BS))printf("routing capsule:%08x\n",route_seal(epoch,route));else puts("diagnostic access denied");
        }else if(command_is(line,"attest")){
            int ok=1;for(unsigned i=0;i<POLICIES;i++){record(want,i+1,generation(epoch),admin_values[i]);xex(mem[map[targets[i]]],got,map[targets[i]],key,epoch,1);ok&=!memcmp(want,got,BS);}puts(ok?"LOCAL ATTESTATION ACCEPTED":"attestation rejected");
        }else if(command_is(line,"quit"))break;else puts("unknown command");
    }return 0;
}
