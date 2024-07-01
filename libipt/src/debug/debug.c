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

static uint64_t handle_packet(struct pt_packet *packet, uint64_t* new_ip)
{
	uint64_t status = packet->type;

	switch (packet->type)
	{
	case ppt_tip:
		*new_ip = packet->payload.ip.ip;
		break;
	case ppt_tip_pge:
		*new_ip = packet->payload.ip.ip;
		break;
	case ppt_tip_pgd:
		// todo
		// *new_ip = packet->payload.ip.ip;
		break;
	case ppt_tnt_64:
		break;
	case ppt_tnt_8:
		break;
	case ppt_fup:
		*new_ip = packet->payload.ip.ip;
		break;
	case ppt_psb:
		break;
	case ppt_psbend:
		break;
	case ppt_pad:
		break;
	case ppt_ptw:
		break;
	case ppt_cbr:
		break;
	default:
		status = -1;
		break;
	}

	return status;
}

uint64_t check_sections(struct pt_block_decoder *ptdec, uint64_t ip)
{
	struct pt_section_list* section = ptdec->image->sections;
	struct pt_section_list* init_section = ptdec->image->sections;

	while (section != NULL)
	{
		if (section->section.vaddr <= ip && ip < (section->section.vaddr + section->section.size))
		{
			ptdec->scache.isid = section->isid;
			ptdec->scache.msec = section->section;
			return section->section.vaddr;
		}
		section = section->next;
	}

	return 0;
}

struct pt_packet_decoder* init_pkt_decoder(const struct pt_config *config, uint64_t offset)
{
	struct pt_packet_decoder *pkt_dec;
	int errcode;

	pkt_dec = pt_pkt_alloc_decoder(config);
	if (!pkt_dec)
	{
		printf("failed to allocate decoder1\n");
		return NULL;
	}

	errcode = pt_pkt_sync_set(pkt_dec, offset);
	if (errcode < 0)
	{
		printf("failed to sync decoder\n");
		return NULL;
	}
	
	return pkt_dec;
}

static int next_packet(struct pt_packet_decoder* pkt_dec, struct pt_packet* packet)
{
	int size = pt_pkt_next(pkt_dec, packet, sizeof(*packet));

	if (size < 0)
	{
		switch (size)
		{
		case -pte_bad_opc:
			printf("pte_bad_opc\n");
			break;
		case -pte_bad_packet:
			printf("pte_bad_packet\n");
			break;
		case -pte_eos:
			printf("pte_eos\n");
			return -pte_eos;
		case -pte_invalid:
			printf("pte_invalid\n");
			break;
		case -pte_nosync:
			printf("pte_nosync\n");
			break;
		
		default:
			break;
		}

	}
	return size;
}

uint64_t search_prev_full_tip(struct pt_block_decoder *ptdec,
							uint64_t offset,
							const uint8_t* pos)
{
	struct pt_packet_decoder* pkt_dec = init_pkt_decoder(&ptdec->evdec.pacdec.config, offset);
	struct pt_packet packet;
	int size;
	uint64_t ip;
	uint64_t full_tip_ip = 0;
	uint64_t pkt_type;
	uint64_t full_tip_mask = 0xffffffff;
	uint64_t short_tip_mask = 0xfffffff;

	int status = pt_pkt_sync_backward(pkt_dec);
	if (status < 0)
	{
		return status;
	}

	while (pkt_dec->pos < pos)
	{
		size = next_packet(pkt_dec, &packet);
		pkt_type = handle_packet(&packet, &ip);
		if (pkt_type == ppt_tip || pkt_type == ppt_tip_pge)
		{
			ip = packet.payload.ip.ip;
			if ((ip & short_tip_mask) != ip)
			{
				full_tip_ip = ip;
			}
		}
	}

	pt_pkt_free_decoder(pkt_dec);
	return full_tip_ip;
}

int handle_tip(struct pt_block_decoder *ptdec,
				uint64_t new_ip,
				struct pt_block* block,
				uint64_t offset)
{
	uint64_t section_va;
	const uint8_t* pos = ptdec->evdec.pacdec.pos;

	if ((new_ip & 0xffff) == new_ip)
	{
		uint64_t last_tip_ip = search_prev_full_tip(ptdec, offset, pos);

		if (!last_tip_ip)
		{
			return -1;
		}

		new_ip = (last_tip_ip & 0xffffffffffff0000) | new_ip;
	}

	ptdec->evdec.ip.ip = new_ip;
	ptdec->ip = new_ip;
	block->end_ip = new_ip;
	block->ip = new_ip;
	block->isid = ptdec->scache.isid;

	if (section_va = check_sections(ptdec, new_ip))
	{
		return 1;
	}

	return -1;
}

int handle_no_map(struct pt_block_decoder *ptdec,
				struct pt_block* block,
				uint64_t* offset,
				struct pt_packet_decoder* pkt_dec)
{
	struct pt_packet packet;

	int status;
	int size = 0;

	uint64_t last_ip = ptdec->evdec.ip.ip;
	uint64_t new_ip = last_ip;
	uint64_t section_va;
	uint64_t errcode;

	*offset = ptdec->evdec.pacdec.pos - ptdec->evdec.pacdec.config.begin;

	errcode = pt_pkt_sync_set(pkt_dec, *offset);
	if (errcode < 0)
	{
		printf("failed to sync decoder\n");
		return -1;
	}

	while (1)
	{
		size = next_packet(&ptdec->evdec.pacdec, &packet);

		if (size < 0)
		{
			return size;
		}

		status = handle_packet(&packet, &new_ip);

		switch (status)
		{
		case ppt_psb:
			// no difference
			// ptdec->evdec.pacdec.sync = ptdec->evdec.pacdec.pos;
			return status;
		case ppt_fup:
		case ppt_tip:
		case ppt_tip_pgd:
		case ppt_tip_pge:
			if (handle_tip(ptdec, new_ip, block, *offset) > 0)
			{
				return status;
			}
			break;
		case -1:
			break;
		default:
			break;
		}
	}

	return status;
}
