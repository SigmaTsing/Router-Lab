#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include<stdio.h>

/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(for response) and 0(for request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
  由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
  需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 * 
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系（见上面结构体注释），Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
  // TODO:
  uint32_t iplen=(packet[2]<<8)+packet[3];
  // printf("%x %x ",iplen, len);
  if(iplen>len) return false;
  uint32_t iphlen=(packet[0]&0xf)*4+8;
  if((packet[iphlen]!=1 && packet[iphlen]!=2) || packet[iphlen+1]!=2 || packet[iphlen+2]!=0 || packet[iphlen+3]!=0) return false;
  // printf("%u ",iphlen);
  output->command = packet[iphlen];
  iphlen=iphlen+4;
  output->numEntries=(iplen-iphlen)/20;
  for(int i=0;i<output->numEntries;i++,iphlen+=20){
    if((packet[iphlen+1]!=2 && output->command==2 )||( packet[iphlen+1]!=0 && output->command==1) || packet[iphlen]!=0 || packet[iphlen+2]!=0 || packet[iphlen+3]!=0) return false;
    output->entries[i].addr=(packet[iphlen+7]<<24)+(packet[iphlen+6]<<16)+(packet[iphlen+5]<<8)+packet[iphlen+4];
    output->entries[i].mask=(packet[iphlen+11]<<24)+(packet[iphlen+10]<<16)+(packet[iphlen+9]<<8)+packet[iphlen+8];
    output->entries[i].nexthop=(packet[iphlen+15]<<24)+(packet[iphlen+14]<<16)+(packet[iphlen+13]<<8)+packet[iphlen+12];
    output->entries[i].metric=(packet[iphlen+19]<<0)+(packet[iphlen+18]<<8)+(packet[iphlen+17]<<16)+(packet[iphlen+16]<<24);
    // if(packet[iphlen+19]>16 || packet[iphlen+19]<=0 || packet[iphlen+18]!=0 ||packet[iphlen+17]!=0 ||packet[iphlen+16]!=0) return false;
    if(output->entries[i].metric>16) return false;
    else if(output->entries[i].metric==0) return false;
    int j;
    //uint32_t mask0=output->entries[i].mask;
    //uint32_t mask1=0;
    //for(int k=0;k<32;k++){
    //  mask1=(mask1|(((mask0>>(31-k))&0x1)<<k));
    //}
    //mask0=ntohl(output->entries[i].mask);
    //printf("mask: %x  %x  \n", mask0, output->entries[i].mask);
    uint32_t mask0 = packet[iphlen+11]|(packet[iphlen+10]<<8)|(packet[iphlen+9]<<16)|(packet[iphlen+8]<<24);
    if((mask0|mask0-1)!=0xFFFFFFFF){
      return false;
    }
    //mask0=mask1;
    //mask0=((((mask0>>0)&0xff)<<24)|(((mask0>>8)&0xff)<<16)|(((mask0>>16)&0xff)<<8)|(((mask0>>24)&0xff)<<0));
    /*if((mask0&0x1) == 0){
      for(j=0;j<32;j++){
        if(((mask0>>j)&0x1 )== 1) break;
      }
      //printf("break at %d\n", j);
      for(j=j+1;j<32;j++){
        if(((mask0>>j)&0x1) == 0) { printf(" bad\n"); return false; }
      }
    }else{
      for(j=0;j<32;j++){
        if(((mask0>>j)&0x1) == 0) break;
      }
      //printf("break at %d\n", j);
      for(j=j+1;j<32;j++){
        if(((mask0>>j)&0x1) == 1) { printf(" bad\n"); return false; }
      }*/
    
  }
  return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 * 
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、Zero、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
  // TODO:
  if(rip->command==2) buffer[0]=0x02;
  else buffer[0]=0x01;
  buffer[1]=0x02;buffer[2]=0x00;buffer[3]=0x00;
  uint32_t base=8;

  for(int j=0,i=4;j<rip->numEntries;j++,i+=20){
    if(rip->command==2) buffer[i+1]=0x02;
    else buffer[i+1]=0x00;
    // printf("out %x %x %x %x out", rip->entries[j].addr,  rip->entries[j].mask, rip->entries[j].nexthop, rip->entries[j].metric);
    buffer[i+0]=0x00;buffer[i+2]=0x00;buffer[i+3]=0x00;
    buffer[i+4]= ((rip->entries[j].addr>>0)&0xff);
    buffer[i+5]= ((rip->entries[j].addr>>8)&0xff);
    buffer[i+6]= ((rip->entries[j].addr>>16)&0xff);
    buffer[i+7]= ((rip->entries[j].addr>>24)&0xff);

    buffer[i+8]= ((rip->entries[j].mask>>0)&0xff);
    buffer[i+9]= ((rip->entries[j].mask>>8)&0xff);
    buffer[i+10]= ((rip->entries[j].mask>>16)&0xff);
    buffer[i+11]= ((rip->entries[j].mask>>24)&0xff);

    buffer[i+12]= ((rip->entries[j].nexthop>>0)&0xff);
    buffer[i+13]= ((rip->entries[j].nexthop>>8)&0xff);
    buffer[i+14]= ((rip->entries[j].nexthop>>16)&0xff);
    buffer[i+15]= ((rip->entries[j].nexthop>>24)&0xff);

    buffer[i+16]= ((rip->entries[j].metric>>24)&0xff);
    buffer[i+17]= ((rip->entries[j].metric>>16)&0xff);
    buffer[i+18]= ((rip->entries[j].metric>>8)&0xff);
    buffer[i+19]= ((rip->entries[j].metric>>0)&0xff);
  }
  return 4+20*rip->numEntries;
}
