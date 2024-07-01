#include <stdio.h>
#include <stdlib.h>

#include "debug.h"


void print_pt_block_decoder(struct pt_block_decoder *ptdec)
{
	printf("ptdec: ip: %lx\n", ptdec->ip);
	print_section(ptdec->image->sections);
	return;
}

void print_section(struct pt_section_list* section)
{
	printf("section: %s, vaddr: %lx, size: %lx\n",
		section->section.section->filename,
		section->section.vaddr,
		section->section.size);
	return;
}

void print_sections(struct pt_section_list* sections)
{
	struct pt_section_list* section = sections;

	while (section != NULL)
	{
		print_section(section);
		section = section->next;
	}

	return;
}

void debug_print(int n, int status, const char* func_name)
{
	printf("debug_print_%d, func: %s(err string):\n", n, func_name);
	printf("%s\n\n", pt_errstr(pt_errcode(status)));

	return;
}

void debug_checkpoint(int n, const char* func_name)
{
	printf("DEBUG_CHECKPOINT_%d, func: %s:\n\n", n, func_name);

	return;
}

void debug_info(const char* msg)
{
	printf("DEBUG_INFO %s\n", msg);

	return;
}

void print_pkt_type(struct pt_packet* packet)
{
	switch (packet->type)
		{
		case ppt_invalid:
			printf("packet_type: ppt_invalid, code: %d\n", packet->type);
			break;
		case ppt_unknown:
			printf("packet_type: ppt_unknown, code: %d\n", packet->type);
			break;
		case ppt_pad:
			printf("packet_type: ppt_pad, code: %d\n", packet->type);
			break;
		case ppt_psb:
			printf("packet_type: ppt_psb, code: %d\n", packet->type);
			break;
		case ppt_psbend:
			printf("packet_type: ppt_psbend, code: %d\n", packet->type);
			break;
		case ppt_fup:
			printf("packet_type: ppt_fup, code: %d\n", packet->type);
			break;
		case ppt_tip:
			printf("packet_type: ppt_tip, code: %d, ip: %lx\n",
				packet->type,
				packet->payload.ip.ip);
			break;
		case ppt_tip_pge:
			printf("packet_type: ppt_tip_pge, code: %d, ip: %lx\n",
				packet->type,
				packet->payload.ip.ip);
			break;
		case ppt_tip_pgd:
			printf("packet_type: ppt_tip_pgd, code: %d, ip: %lx\n",
				packet->type,
				packet->payload.ip.ip);
			break;
		case ppt_tnt_8:
			printf("packet_type: ppt_tnt_8, code: %d, payload: %lx\n",
				packet->type,
				packet->payload.tnt.payload);
			break;
		case ppt_tnt_64:
			printf("packet_type: ppt_tnt_64, code: %d, payload: %lx\n",
				packet->type, packet->payload.tnt.payload);
			break;
		case ppt_mode:
			printf("packet_type: ppt_mode, code: %d\n", packet->type);
			break;
		case ppt_pip:
			printf("packet_type: ppt_pip, code: %d\n", packet->type);
			break;
		case ppt_vmcs:
			printf("packet_type: ppt_vmcs, code: %d\n", packet->type);
			break;
		case ppt_cbr:
			printf("packet_type: ppt_cbr, code: %d\n", packet->type);
			break;
		case ppt_tsc:
			printf("packet_type: ppt_tsc, code: %d\n", packet->type);
			break;
		case ppt_tma:
			printf("packet_type: ppt_tma, code: %d\n", packet->type);
			break;
		case ppt_mtc:
			printf("packet_type: ppt_mtc, code: %d\n", packet->type);
			break;
		case ppt_cyc:
			printf("packet_type: ppt_cyc, code: %d\n", packet->type);
			break;
		case ppt_stop:
			printf("packet_type: ppt_stop, code: %d\n", packet->type);
			break;
		case ppt_ovf:
			printf("packet_type: ppt_ovf, code: %d\n", packet->type);
			break;
		case ppt_mnt:
			printf("packet_type: ppt_mnt, code: %d\n", packet->type);
			break;
		case ppt_exstop:
			printf("packet_type: ppt_exstop, code: %d\n", packet->type);
			break;
		case ppt_mwait:
			printf("packet_type: ppt_mwait, code: %d\n", packet->type);
			break;
		case ppt_pwre:
			printf("packet_type: ppt_pwre, code: %d\n", packet->type);
			break;
		case ppt_pwrx:
			printf("packet_type: ppt_pwrx, code: %d\n", packet->type);
			break;
		case ppt_ptw:
			printf("packet_type: ppt_ptw, code: %d\n", packet->type);
			break;
		default:
			printf("packet_type: unknown, code: %d\n", packet->type);
			break;
		}
}

void print_n_packets(struct pt_config *config, uint64_t offset, int n)
{
	struct pt_packet_decoder *decoder;
	struct pt_packet packet;
	int errcode;
	int size = 0;
	uint64_t new_ip = 0;

	decoder = pt_pkt_alloc_decoder(config);
	if (!decoder)
	{
		printf("failed to allocate decoder2\n");
		return;
	}

	errcode = pt_pkt_sync_set(decoder, offset);
	if (errcode < 0)
	{
		pt_pkt_free_decoder(decoder);
		printf("failed to sync decoder\n");
		return;
	}

	for (size_t i = 0; i < n; i++)
	{
		size = pt_pkt_next(decoder, &packet, sizeof(packet));
		switch (packet.type)
		{
		case ppt_invalid:
			printf("packet_type: ppt_invalid, code: %d\n", packet.type);
			break;
		case ppt_unknown:
			printf("packet_type: ppt_unknown, code: %d\n", packet.type);
			break;
		case ppt_pad:
			printf("packet_type: ppt_pad, code: %d\n", packet.type);
			break;
		case ppt_psb:
			printf("packet_type: ppt_psb, code: %d\n", packet.type);
			break;
		case ppt_psbend:
			printf("packet_type: ppt_psbend, code: %d\n", packet.type);
			break;
		case ppt_fup:
			printf("packet_type: ppt_fup, code: %d\n", packet.type);
			break;
		case ppt_tip:
			printf("packet_type: ppt_tip, code: %d, ip: %lx\n",
				packet.type,
				packet.payload.ip.ip);
			break;
		case ppt_tip_pge:
			printf("packet_type: ppt_tip_pge, code: %d, ip: %lx\n",
				packet.type,
				packet.payload.ip.ip);
			break;
		case ppt_tip_pgd:
			printf("packet_type: ppt_tip_pgd, code: %d, ip: %lx\n",
				packet.type,
				packet.payload.ip.ip);
			break;
		case ppt_tnt_8:
			printf("packet_type: ppt_tnt_8, code: %d, payload: %lx\n",
				packet.type,
				packet.payload.tnt.payload);
			break;
		case ppt_tnt_64:
			printf("packet_type: ppt_tnt_64, code: %d, payload: %lx\n",
				packet.type,
				packet.payload.tnt.payload);
			break;
		case ppt_mode:
			printf("packet_type: ppt_mode, code: %d\n", packet.type);
			break;
		case ppt_pip:
			printf("packet_type: ppt_pip, code: %d\n", packet.type);
			break;
		case ppt_vmcs:
			printf("packet_type: ppt_vmcs, code: %d\n", packet.type);
			break;
		case ppt_cbr:
			printf("packet_type: ppt_cbr, code: %d\n", packet.type);
			break;
		case ppt_tsc:
			printf("packet_type: ppt_tsc, code: %d\n", packet.type);
			break;
		case ppt_tma:
			printf("packet_type: ppt_tma, code: %d\n", packet.type);
			break;
		case ppt_mtc:
			printf("packet_type: ppt_mtc, code: %d\n", packet.type);
			break;
		case ppt_cyc:
			printf("packet_type: ppt_cyc, code: %d\n", packet.type);
			break;
		case ppt_stop:
			printf("packet_type: ppt_stop, code: %d\n", packet.type);
			break;
		case ppt_ovf:
			printf("packet_type: ppt_ovf, code: %d\n", packet.type);
			break;
		case ppt_mnt:
			printf("packet_type: ppt_mnt, code: %d\n", packet.type);
			break;
		case ppt_exstop:
			printf("packet_type: ppt_exstop, code: %d\n", packet.type);
			break;
		case ppt_mwait:
			printf("packet_type: ppt_mwait, code: %d\n", packet.type);
			break;
		case ppt_pwre:
			printf("packet_type: ppt_pwre, code: %d\n", packet.type);
			break;
		case ppt_pwrx:
			printf("packet_type: ppt_pwrx, code: %d\n", packet.type);
			break;
		case ppt_ptw:
			printf("packet_type: ppt_ptw, code: %d\n", packet.type);
			break;
		
		default:
			break;
		}

	}
	pt_pkt_free_decoder(decoder);
	return;
}
