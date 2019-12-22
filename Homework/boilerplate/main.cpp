#include "rip.h"
#include "router.h"
#include "router_hal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern void update(bool insert, RoutingTableEntry entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);
extern void RipFill(RipPacket *resp, int *size, uint32_t src_addr);
extern uint32_t clo(uint32_t mask);
extern void vertical(uint32_t reidx, RipPacket *resp);
extern void printAll();
extern uint16_t IPChecksum(uint8_t *packet, size_t len);
extern void vertical_2(uint32_t reidx, RipPacket *resp, uint32_t ip);
extern void vertical_d(uint32_t reidx, RipPacket *resp, int *len);
extern void vertical_2d(uint32_t reidx, RipPacket *resp, uint32_t ip, int *len);

uint8_t packet[2048];
uint8_t output[2048];
// 0: 10.0.0.1
// 1: 10.0.1.1
// 2: 10.0.2.1
// 3: 10.0.3.1
// 你可以按需进行修改，注意端序
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0204a8c0, 0x0205a8c0, 0x0102000a,
                                     0x0103000a};

int main(int argc, char *argv[]) {
  // 0a.
  int res = HAL_Init(1, addrs);
  if (res < 0) {
    return res;
  }

  // 0b. Add direct routes
  // For example:
  // 10.0.0.0/24 if 0
  // 10.0.1.0/24 if 1
  // 10.0.2.0/24 if 2
  // 10.0.3.0/24 if 3
  for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
    RoutingTableEntry entry = {
        .addr = addrs[i] & 0x00FFFFFF, // big endian
        .len = 24,        // small endian
        .if_index = i,    // small endian
        .nexthop = 0,      // big endian, means direct
        .metric = 0x01
    };
    //printf("updating %x %d\n", entry.addr, entry.metric);
    update(true, entry);
  }

  uint64_t last_time = 0;
  int cnt0=0;

  while (1) {
    uint64_t time = HAL_GetTicks();
    if (time > last_time + 5 * 1000) {
      // What to do?
      // send complete routing table to every interface
      // ref. RFC2453 3.8
      // multicast MAC for 224.0.0.9 is 01:00:5e:00:00:09

      for(uint i=0;i<N_IFACE_ON_BOARD;i++){
        RipPacket resp[500];
        // TODO: fill resp
        macaddr_t ad0;
        ad0[0]=0x01;
        ad0[1]=0x00;
        ad0[2]=0x5e;
        ad0[3]=0x00;
        ad0[4]=0x00;
        ad0[5]=0x09;

        int len0=0;
        vertical_2d(uint32_t(i), resp, addrs[i], &len0);
        printf("printing  %d\n", len0);
        for(int j=0;j<=len0;j++){
          resp[j].command=2;
          // vertical(uint32_t(i), &resp);
          printf("vertical result: %d\n", resp[j].numEntries);
          output[0] = 0x45;
          output[1] = 0x00;
          output[4] = 0x00;
          output[5]=0x00;
          output[6]=0x00;
          output[7] = 0x00;
          output[8] = 0x01;
          output[9] = 0x11;
          // output[12]= packet[16];
          // output[13]= packet[17];
          // output[14]= packet[18];
          // output[15]= packet[19];
          output[10]=0x00;
          output[11]=0x00;
          output[12]=addrs[i]&0xff;
          output[13]=((addrs[i]>>8)&0xff);
          output[14]=((addrs[i]>>16)&0xff);
          output[15]=((addrs[i]>>24)&0xff);
          output[16]= 0xe0;
          output[17]= 0x00;
          output[18]= 0x00;
          output[19]= 0x09;
          // ...
          // UDP
          // port = 520
          output[20] = 0x02;
          output[21] = 0x08;
          output[22] = 0x02;
          output[23] = 0x08;
          // RIP
          uint32_t rip_len = assemble(&resp[j], &output[20 + 8]);
          uint32_t ip_len=20+8+rip_len;
          output[2]=((ip_len>>8)&0xff);
          output[3]=(ip_len&0xff);
          //UDP len
          uint32_t udp_len = rip_len+8;
          output[24]=((udp_len>>8)&0xff);
          output[25]=(udp_len&0xff);
          // checksum calculation for ip and udp
          uint16_t csum = IPChecksum(output, 20);
          output[10]= csum>>8;
          output[11]=csum&0xff;
          // if you don't want to calculate udp checksum, set it to zero
          output[26] = 0x00;
          output[27] = 0x00;
          // send it back
          //printf("sending rip_len:%u  |  if_index: %u | output: %u | src_mac:  01:00:5e:00:00:09 \n", rip_len, i, output);
          HAL_SendIPPacket(i, output, rip_len + 20 + 8, ad0);
        }
      }
      printAll();
      printf("5s Timer %d\n", cnt0);
      cnt0++;
      last_time = time;
    }

    macaddr_t src_mac;
    macaddr_t dst_mac;
    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac, dst_mac,
                              1000, &if_index);
    //printf("if_index %u\n", if_index);
    if (res == HAL_ERR_EOF) {
      break;
    } else if (res < 0) {
      return res;
    } else if (res == 0) {
      // Timeout
      continue;
    } else if (res > sizeof(packet)) {
      // packet is truncated, ignore it
      continue;
    }

    // 1. validate
    if (!validateIPChecksum(packet, res)) {
      printf("Invalid IP Checksum\n");
      continue;
    }
    in_addr_t src_addr, dst_addr;
    // extract src_addr and dst_addr from packet
    // big endian
    src_addr=packet[12]|(packet[13]<<8)|(packet[14]<<16)|(packet[15]<<24);
    dst_addr=packet[16]|(packet[17]<<8)|(packet[18]<<16)|(packet[19]<<24);

    // 2. check whether dst is me
    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
      if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
        dst_is_me = true;
        break;
      }
    }
    // TODO: Handle rip multicast address(224.0.0.9)?
    // if(dst_addr==0x090000e0)
    //   dst_is_me=true;
    uint32_t t0=0x090000e0;
    if (memcmp(&dst_addr, &t0, sizeof(in_addr_t)) == 0) {
        dst_is_me = true;
    }

    if (dst_is_me) {
      // 3a.1
      RipPacket rip;
      // check and validate
      if (disassemble(packet, res, &rip)) {
        if (rip.command == 1) {
          // 3a.3 request, ref. RFC2453 3.9.1
          // only need to respond to whole table requests in the lab
          // RipPacket resp;
          
          RipPacket resp[500];
          int len0=0;
          // TODO: fill resp

          // resp.command=2;
          // vertical(if_index, &resp);

          vertical_d(if_index, resp, &len0);
          for(int j=0;j<=len0;j++){
            resp[j].command=2;

            // vertical_2(uint32_t(i), &resp, addrs[i]);
            printf("vertical result: %u \n", resp[j].numEntries);
            // assemble
            // IP
            output[0] = 0x45;
            output[1] = 0x00;
            output[4] = 0x00;
            output[5] = 0x00;
            output[6] = 0x00;
            output[7] = 0x00;
            output[8] = 0x01;
            output[9] = 0x11;
            output[10]=0x00;
            output[11]=0x00;
            output[12]=addrs[if_index]&0xff;
            output[13]=((addrs[if_index]>>8)&0xff);
            output[14]=((addrs[if_index]>>16)&0xff);
            output[15]=((addrs[if_index]>>24)&0xff);
            output[16]= packet[12];
            output[17]= packet[13];
            output[18]= packet[14];
            output[19]= packet[15];
            // ...
            // UDP
            // port = 520
            output[20] = 0x02;
            output[21] = 0x08;
            output[22] = 0x02;
            output[23] = 0x08;
            // RIP
            uint32_t rip_len = assemble(&resp[j], &output[20 + 8]);
            uint32_t ip_len=20+8+rip_len;
            output[2]=((ip_len>>8)&0xff);
            output[3]=(ip_len&0xff);
            //UDP len
            uint32_t udp_len = rip_len+8;
            output[24]=((udp_len>>8)&0xff);
            output[25]=(udp_len&0xff);
            // checksum calculation for ip and udp
            uint16_t csum = IPChecksum(output, 20);
            output[10]= csum>>8;
            output[11]=csum&0xff;
            // if you don't want to calculate udp checksum, set it to zero
            output[26] = 0x00;
            output[27] = 0x00;
            // send it back
            //printf("sending rip_len:%u  |  if_index: %u | output: %u | src_mac: %u \n", rip_len, if_index, output, src_mac);
            HAL_SendIPPacket(if_index, output, rip_len + 20 + 8, src_mac);
          }
        } else {
          // 3a.2 response, ref. RFC2453 3.9.2
          // update routing table
          // new metric = ?
          // uint32_t metric, nexthop;
          bool cz;
          // update metric, if_index, nexthop
          //printf("num Entry %u if_index %u\n", rip.numEntries, if_index);
          for(int i=0;i<rip.numEntries;i++){
            RoutingTableEntry entry = {
              .addr=rip.entries[i].addr,
              .len=clo(rip.entries[i].mask),
              .if_index=uint32_t(if_index),
              .nexthop=src_addr,
              .metric=rip.entries[i].metric
            };
            if(rip.entries[i].metric+1>16){
              // update(false, entry);
              // printf("invalidate entry "+rip.entries[i].addr);
              //tbd:send inval resp
            }else{
              //printf("updating %x %d\n", rip.entries[i].addr, rip.entries[i].metric);
              entry.metric+=1;
              update(true, entry);
              //printf("updated %x %d\n", rip.entries[i].addr, rip.entries[i].metric);              
            }
          }
          // what is missing from RoutingTableEntry?
          // TODO: use query and update
          // triggered updates? ref. RFC2453 3.10.1
          
        }
      }else{
      }
    } else {
      // 3b.1 dst is not me
      // forward
      // beware of endianness
      uint32_t nexthop, dest_if;
      if (query(dst_addr, &nexthop, &dest_if)) {
        // found
        macaddr_t dest_mac;
        // direct routing
        if (nexthop == 0) {
          nexthop = dst_addr;
        }
        if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0) {
          // found
          memcpy(output, packet, res);
          // update ttl and checksum
          forward(output, res);
          // TODO: you might want to check ttl=0 case
          HAL_SendIPPacket(dest_if, output, res, dest_mac);
        } else {
          // not found
          // you can drop it
          printf("ARP not found for %x\n", nexthop);
        }
      } else {
        // not found
        // optionally you can send ICMP Host Unreachable
        printf("IP not found for %x\n", src_addr);
      }
    }
  }
  return 0;
}
