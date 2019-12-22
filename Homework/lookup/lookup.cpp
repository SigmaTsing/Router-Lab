#include "router.h"
#include "router_hal.h"
#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include<stdio.h>

/*
  RoutingTable Entry 的定义如下：
  typedef struct {
    uint32_t addr; // 大端序，IPv4 地址
    uint32_t len; // 小端序，前缀长度
    uint32_t if_index; // 小端序，出端口编号
    uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
  } RoutingTableEntry;

  约定 addr 和 nexthop 以 **大端序** 存储。
  这意味着 1.2.3.4 对应 0x04030201 而不是 0x01020304。
  保证 addr 仅最低 len 位可能出现非零。
  当 nexthop 为零时这是一条直连路由。
  你可以在全局变量中把路由表以一定的数据结构格式保存下来。
*/

RoutingTableEntry table[10100];
int next[10100];
int front[10100];
int p_table=0;
// int fin=0;

/**
 * @brief 插入/删除一条路由表表项
 * @param insert 如果要插入则为 true ，要删除则为 false
 * @param entry 要插入/删除的表项
 * 
 * 插入时如果已经存在一条 addr 和 len 都相同的表项，则替换掉原有的。
 * 删除时按照 addr 和 len 匹配。
 */
bool check(uint32_t a, uint32_t b){
  // printf("%x %x %x %x\n", (b>>8)&0xff, (b>>16)&0xff, (b>>24)&0xff, b&0xff);
  // printf("%x %x %x %x\n", (a>>8)&0xff, (a>>16)&0xff, (a>>24)&0xff, a&0xff);
  return (((b>>8)&0xff)==0 || ((b>>8)&0xff)== ((a>>8)&0xff))&&
        (((b>>16)&0xff)==0 || ((b>>16)&0xff)== ((a>>16)&0xff))&&
        (((b>>24)&0xff)==0 || ((b>>24)&0xff)== ((a>>24)&0xff))&&
        ((b&0xff)==0 || (b&0xff)== (a&0xff));
}

void init(){
  p_table=0;
  next[0]=0;
  // fin=0;
}

uint32_t clo(uint32_t mask){
  uint32_t cnt=0;
  for(int i=0;i<=31;i++){
    if(((mask>>i)&0x1)==1){
      cnt++;
    }else{
      return cnt;
    }
  }
  return cnt;
}

uint32_t genMask(uint32_t len){
  return htonl(0xffffffff << (32 - len));
}


void vertical(uint32_t reidx, RipPacket *resp){
  resp->numEntries=0;
  // for(int i=0;i<p_table;i++){
  for(int i=next[0];next[i]!=0;i=next[i]){
    if(table[i].if_index!=reidx){
      resp->entries[resp->numEntries]={
        .addr=table[i].addr,
        .mask=genMask(table[i].len),
        .nexthop=table[i].nexthop,
        .metric=table[i].metric
      };
      resp->numEntries++;
    }
  }
}

void vertical_d(uint32_t reidx, RipPacket *resp, int *len){
  *len=0;
  for(int i=next[0];next[i]!=0;i=next[i]){
    if(table[i].if_index!=reidx){
      resp[*len].entries[resp[*len].numEntries]={
        .addr=table[i].addr,
        .mask=genMask(table[i].len),
        .nexthop=table[i].nexthop,
        .metric=table[i].metric
      };
      resp[*len].numEntries++;
      if(resp[*len].numEntries>24){
        *len=*len+1;
        resp[*len].numEntries=0;
      }
    }
  }
}

void vertical_2(uint32_t reidx, RipPacket *resp, uint32_t ip){
  resp->numEntries=0;
  // for(int i=0;i<p_table;i++){
  for(int i=next[0];next[i]!=0;i=next[i]){
    if(table[i].if_index!=reidx){
      resp->entries[resp->numEntries]={
        .addr=table[i].addr,
        .mask=genMask(table[i].len),
        // .nexthop=table[i].nexthop,
        .nexthop=ip,
        .metric=table[i].metric
      };
      resp->numEntries++;
    }
  }
}

void vertical_2d(uint32_t reidx, RipPacket *resp, uint32_t ip, int *len){
  *len=0;
  for(int i=next[0];next[i]!=0;i=next[i]){
    if(table[i].if_index!=reidx){
      resp[*len].entries[resp[*len].numEntries]={
        .addr=table[i].addr,
        .mask=genMask(table[i].len),
        .nexthop=ip,
        .metric=table[i].metric
      };
      resp[*len].numEntries++;
      if(resp[*len].numEntries>24){
        *len=*len+1;
        resp[*len].numEntries=0;
      }
    }
  }
}

void printAll(){
  // for(int i=0;i<p_table;i++){
  //printf("printing %d", next[0]);
  for(int i=next[0];next[i]!=0;i=next[i]){
    printf("|addr: %x |len: %u |if_index: %u |nexthop: %x | metric: %u \n", table[i].addr, table[i].len, table[i].if_index, table[i].nexthop, table[i].metric);
  }
}

void update(bool insert, RoutingTableEntry entry) {
  // TODO:
  // printf("inserting addr %x\n", entry.addr);
  if(insert){
    for(int i=next[0];next[i]!=0;i=next[i]){
      if(table[i].addr==entry.addr && table[i].len==entry.len){
        if(entry.metric<=table[i].metric){
          table[i]=entry;
          // printf("inserted %u %u\n", table[i].metric, entry.metric);
          return;
        }else
          // printf("metric biger, ignore\n");
        return;
      }
    }
    table[p_table]=entry;
    next[p_table]=p_table+1;    
    front[p_table+1]=p_table;
    next[p_table+1]=0;
    p_table++;
    if(p_table>10000) printf(" @@@  ALERT  @@@\n");
    // printf("inserted num %d\n",  p_table);
    // fin=p_table;
    // table[p_table++]=entry;
    //next
  }else{
    // for(int i=0;i<p_table;i++){
  for(int i=next[0];next[i]!=0;i=next[i]){
      if(table[i].addr==entry.addr && table[i].len==entry.len){
        // for(int j=i;j<p_table-1;j++) table[i]=table[i+1];
        // p_table--;
        front[next[i]]=front[i];
        next[front[i]]=next[i];
        return;
      }
    }
  }
}

/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，大端序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */
bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index) {
  // TODO:
  *nexthop = 0;
  *if_index = 0;
  bool cz=false;
  // for(int i=0;i<p_table;i++){
  for(int i=next[0];next[i]!=0;i=next[i]){
    if(check(addr,table[i].addr)){
      *nexthop=table[i].nexthop;
      *if_index=table[i].if_index;
      cz=true;
      if(addr==table[i].addr)
        return true;
    }
  }
  return cz;
}
  void RipFill(RipPacket *resp, int *size, uint32_t src_addr){
    resp->numEntries=0;
    // for(int i=0;i<p_table;i++){
    for(int i=next[0];next[i]!=0;i=next[i]){
      if(check(src_addr, table[i].addr)){
        continue;
      }else{
        RoutingTableEntry entry=table[i];
        resp->entries[resp->numEntries]={
          .addr=table[i].addr,
          .mask=genMask(table[i].len),
          .nexthop=table[i].nexthop,
          .metric=table[i].metric
        };
        resp->numEntries++;
      }
    }
  }
  
