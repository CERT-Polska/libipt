#ifndef DEBUG_H
#define DEBUG_H
#include "intel-pt.h"
#include "pt_image.h"

#include "pt_block_decoder.h"
#include "pt_packet.h"
#include "pt_packet_decoder.h"
#include "pt_insn_decoder.h"

void debug_print(int n, int status, const char* func_name);
void debug_checkpoint(int n, const char* func_name);
void debug_info(const char* msg);
int handle_no_map(struct pt_block_decoder *ptdec, struct pt_block* block, uint64_t* offset, struct pt_packet_decoder* pkt_dec);
void print_n_packets(struct pt_config *config, uint64_t offset, int n);
void print_pt_block_decoder(struct pt_block_decoder *ptdec);
void print_section(struct pt_section_list* section);
void print_sections(struct pt_section_list* sections);
struct pt_packet_decoder* init_pkt_decoder(const struct pt_config *config, uint64_t offset);

#endif