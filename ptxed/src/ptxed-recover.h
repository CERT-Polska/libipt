#ifndef PTXED_RECOVER_H
#define PTXED_RECOVER_H
#include "intel-pt.h"
#include "pt_image.h"

#include "pt_block_decoder.h"
#include "pt_packet.h"
#include "pt_packet_decoder.h"
#include "pt_insn_decoder.h"

#include <xed-interface.h>
#include <stdio.h>
#include "debug.h"


int sync_pt_block_decoder(struct pt_block_decoder* ptdec_src, struct pt_block_decoder* ptdec_dst);


/* The type of decoder to be used. */
enum ptxed_decoder_type {
	pdt_insn_decoder,
	pdt_block_decoder
};

/* The decoder to use. */
struct ptxed_decoder {
	/* The decoder type. */
	enum ptxed_decoder_type type;

	/* The actual decoder. */
	union {
		/* If @type == pdt_insn_decoder */
		struct pt_insn_decoder *insn;

		/* If @type == pdt_block_decoder */
		struct pt_block_decoder *block;
	} variant;

	/* Decoder-specific configuration.
	 *
	 * We use a set of structs to store the configuration for multiple
	 * decoders.
	 *
	 * - block decoder.
	 */
	struct {
		/* A collection of decoder-specific flags. */
		struct pt_conf_flags flags;
	} block;

	/* - instruction flow decoder. */
	struct {
		/* A collection of decoder-specific flags. */
		struct pt_conf_flags flags;
	} insn;


	/* The image section cache. */
	struct pt_image_section_cache *iscache;

#if defined(FEATURE_SIDEBAND)
	/* The sideband session. */
	struct pt_sb_session *session;

#if defined(FEATURE_PEVENT)
	/* The perf event sideband decoder configuration. */
	struct pt_sb_pevent_config pevent;
#endif /* defined(FEATURE_PEVENT) */
#endif /* defined(FEATURE_SIDEBAND) */
};

/* A collection of options. */
struct ptxed_options {
#if defined(FEATURE_SIDEBAND)
	/* Sideband dump flags. */
	uint32_t sb_dump_flags;
#endif
	/* Do not print the instruction. */
	uint32_t dont_print_insn:1;

	/* Remain as quiet as possible - excluding error messages. */
	uint32_t quiet:1;

	/* Print statistics (overrides quiet). */
	uint32_t print_stats:1;

	/* Print information about section loads and unloads. */
	uint32_t track_image:1;

	/* Track blocks in the output.
	 *
	 * This only applies to the block decoder.
	 */
	uint32_t track_blocks:1;

	/* Print in AT&T format. */
	uint32_t att_format:1;

	/* Print the offset into the trace file. */
	uint32_t print_offset:1;

	/* Print the current timestamp. */
	uint32_t print_time:1;

	/* Print the raw bytes for an insn. */
	uint32_t print_raw_insn:1;

	/* Perform checks. */
	uint32_t check:1;

	/* Print the time stamp of events. */
	uint32_t print_event_time:1;

	/* Print the ip of events. */
	uint32_t print_event_ip:1;

#if defined(FEATURE_SIDEBAND)
	/* Print sideband warnings. */
	uint32_t print_sb_warnings:1;
#endif
};

/* A collection of flags selecting which stats to collect/print. */
enum ptxed_stats_flag {
	/* Collect number of instructions. */
	ptxed_stat_insn		= (1 << 0),

	/* Collect number of blocks. */
	ptxed_stat_blocks	= (1 << 1)
};

/* A collection of statistics. */
struct ptxed_stats {
	/* The number of instructions. */
	uint64_t insn;

	/* The number of blocks.
	 *
	 * This only applies to the block decoder.
	 */
	uint64_t blocks;

	/* A collection of flags saying which statistics to collect/print. */
	uint32_t flags;
};


void pt_decode_block_recover(struct pt_block_decoder *ptdec_orig,
							struct pt_block* block_orig,
							uint64_t offset_orig,
							struct pt_packet_decoder* pkt_dec,
							uint64_t time_orig,
							struct ptxed_decoder *decoder_orig,
							const struct ptxed_options *options_orig,
 							struct pt_image_section_cache *iscache,
 							struct ptxed_stats *stats,
							struct pt_block_decoder *ptdec_cpy);

#endif