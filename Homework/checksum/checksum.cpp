#include <stdint.h>
#include <stdlib.h>

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
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
  t0=(packet[10]<<8)+packet[11];
  return t0 == (ans&0xffff);
}
