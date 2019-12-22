#include <stdint.h>
#include <stdlib.h>
#include<stdio.h>

/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以从 checksum 题中复制代码到这里使用。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */
uint16_t IPChecksum(uint8_t *packet, size_t len) {
  // TODO:
  uint16_t t0;
  uint32_t ans=0;
  for(int i=0;i<(packet[0]&0xf)*2;i++){
  if(i==5) continue;
  t0=(packet[i*2]<<8)+(packet[i*2+1]);
  ans+=t0;
  while((ans>>16)!=0)
    ans=(ans&0xffff)+(ans>>16);
}
  ans=~ans;
  return ans&0xffff;
}


bool forward(uint8_t *packet, size_t len) {
  // TODO:
  uint16_t t0,t1;
  t0=(packet[10]<<8)+packet[11];
  t1=IPChecksum(packet, len);
  if(t1!=t0) return false;
  packet[8]=packet[8]-0x1;
  //if(packet[10]==0x0) packet[10]=0xff;
  //else packet[10]=packet[10]-0x1;
  t1=IPChecksum(packet, len);
  packet[10]=t1>>8;
  packet[11]=t1&0xff;
  // for(int i=0;i<(packet[0]&0xf)*4;i++) printf("%x ",packet[i]);
  return true;
}
