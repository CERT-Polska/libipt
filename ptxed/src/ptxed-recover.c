#include "ptxed-recover.h"

// todo move

static xed_machine_mode_enum_t translate_mode(enum pt_exec_mode mode)
{
	switch (mode) {
	case ptem_unknown:
		return XED_MACHINE_MODE_INVALID;

	case ptem_16bit:
		return XED_MACHINE_MODE_LEGACY_16;

	case ptem_32bit:
		return XED_MACHINE_MODE_LEGACY_32;

	case ptem_64bit:
		return XED_MACHINE_MODE_LONG_64;
	}

	return XED_MACHINE_MODE_INVALID;
}

static const char *visualize_iclass(enum pt_insn_class iclass)
{
	switch (iclass) {
	case ptic_error:
		return "unknown/error";

	case ptic_other:
		return "other";

	case ptic_call:
		return "near call";

	case ptic_return:
		return "near return";

	case ptic_jump:
		return "near jump";

	case ptic_cond_jump:
		return "cond jump";

	case ptic_far_call:
		return "far call";

	case ptic_far_return:
		return "far return";

	case ptic_far_jump:
		return "far jump";

	case ptic_ptwrite:
		return "ptwrite";
	}

	return "undefined";
}

static void check_insn_iclass(const xed_inst_t *inst,
			      const struct pt_insn *insn, uint64_t offset)
{
	xed_category_enum_t category;
	xed_iclass_enum_t iclass;

	if (!inst || !insn) {
		printf("[internal error]\n");
		return;
	}

	category = xed_inst_category(inst);
	iclass = xed_inst_iclass(inst);

	switch (insn->iclass) {
	case ptic_error:
		break;

	case ptic_ptwrite:
	case ptic_other:
		switch (category) {
		default:
			return;

		case XED_CATEGORY_CALL:
		case XED_CATEGORY_RET:
		case XED_CATEGORY_UNCOND_BR:
		case XED_CATEGORY_SYSCALL:
		case XED_CATEGORY_SYSRET:
			break;

		case XED_CATEGORY_COND_BR:
			switch (iclass) {
			case XED_ICLASS_XBEGIN:
			case XED_ICLASS_XEND:
				return;

			default:
				break;
			}
			break;

		case XED_CATEGORY_INTERRUPT:
			switch (iclass) {
			case XED_ICLASS_BOUND:
				return;

			default:
				break;
			}
			break;
		}
		break;

	case ptic_call:
		if (iclass == XED_ICLASS_CALL_NEAR)
			return;

		break;

	case ptic_return:
		if (iclass == XED_ICLASS_RET_NEAR)
			return;

		break;

	case ptic_jump:
		if (iclass == XED_ICLASS_JMP)
			return;

		break;

	case ptic_cond_jump:
		if (category == XED_CATEGORY_COND_BR)
			return;

		break;

	case ptic_far_call:
		switch (iclass) {
		default:
			break;

		case XED_ICLASS_CALL_FAR:
		case XED_ICLASS_INT:
		case XED_ICLASS_INT1:
		case XED_ICLASS_INT3:
		case XED_ICLASS_INTO:
		case XED_ICLASS_SYSCALL:
		case XED_ICLASS_SYSCALL_32:
		case XED_ICLASS_SYSENTER:
		case XED_ICLASS_VMCALL:
			return;
		}
		break;

	case ptic_far_return:
		switch (iclass) {
		default:
			break;

		case XED_ICLASS_RET_FAR:
		case XED_ICLASS_IRET:
		case XED_ICLASS_IRETD:
		case XED_ICLASS_IRETQ:
		case XED_ICLASS_SYSRET:
		case XED_ICLASS_SYSRET_AMD:
		case XED_ICLASS_SYSEXIT:
		case XED_ICLASS_VMLAUNCH:
		case XED_ICLASS_VMRESUME:
			return;
		}
		break;

	case ptic_far_jump:
		if (iclass == XED_ICLASS_JMP_FAR)
			return;

		break;
	}

	/* If we get here, @insn->iclass doesn't match XED's classification. */
	printf("[%" PRIx64 ", %" PRIx64 ": iclass error: iclass: %s, "
	       "xed iclass: %s, category: %s]\n", offset, insn->ip,
	       visualize_iclass(insn->iclass), xed_iclass_enum_t2str(iclass),
	       xed_category_enum_t2str(category));

}

static void check_insn_decode(xed_decoded_inst_t *inst,
			      const struct pt_insn *insn, uint64_t offset)
{
	xed_error_enum_t errcode;

	if (!inst || !insn) {
		printf("[internal error]\n");
		return;
	}

	xed_decoded_inst_set_mode(inst, translate_mode(insn->mode),
				  XED_ADDRESS_WIDTH_INVALID);

	/* Decode the instruction (again).
	 *
	 * We may have decoded the instruction already for printing.  In this
	 * case, we will decode it twice.
	 *
	 * The more common use-case, however, is to check the instruction class
	 * while not printing instructions since the latter is too expensive for
	 * regular use with long traces.
	 */
	errcode = xed_decode(inst, insn->raw, insn->size);
	if (errcode != XED_ERROR_NONE) {
		printf("[%" PRIx64 ", %" PRIx64 ": xed error: (%u) %s]\n",
		       offset, insn->ip, errcode,
		       xed_error_enum_t2str(errcode));
		return;
	}

	if (!xed_decoded_inst_valid(inst)) {
		printf("[%" PRIx64 ", %" PRIx64 ": xed error: "
		       "invalid instruction]\n", offset, insn->ip);
		return;
	}
}

static void check_insn(const struct pt_insn *insn, uint64_t offset)
{
	xed_decoded_inst_t inst;

	if (!insn) {
		printf("[internal error]\n");
		return;
	}

	if (insn->isid <= 0)
		printf("[%" PRIx64 ", %" PRIx64 ": check error: "
		       "bad isid]\n", offset, insn->ip);

	xed_decoded_inst_zero(&inst);
	check_insn_decode(&inst, insn, offset);

	/* We need a valid instruction in order to do further checks.
	 *
	 * Invalid instructions have already been diagnosed.
	 */
	if (!xed_decoded_inst_valid(&inst))
		return;

	check_insn_iclass(xed_decoded_inst_inst(&inst), insn, offset);
}

static void print_raw_insn(const struct pt_insn *insn)
{
	uint8_t length, idx;

	if (!insn) {
		printf("[internal error]");
		return;
	}

	length = insn->size;
	if (sizeof(insn->raw) < length)
		length = sizeof(insn->raw);

	for (idx = 0; idx < length; ++idx)
		printf(" %02x", insn->raw[idx]);

	for (; idx < pt_max_insn_size; ++idx)
		printf("   ");
}

static void xed_print_insn(const xed_decoded_inst_t *inst, uint64_t ip,
			   const struct ptxed_options *options)
{
	xed_print_info_t pi;
	char buffer[256];
	xed_bool_t ok;

	if (!inst || !options) {
		printf(" [internal error]");
		return;
	}

	if (options->print_raw_insn) {
		xed_uint_t length, i;

		length = xed_decoded_inst_get_length(inst);
		for (i = 0; i < length; ++i)
			printf(" %02x", xed_decoded_inst_get_byte(inst, i));

		for (; i < pt_max_insn_size; ++i)
			printf("   ");
	}

	xed_init_print_info(&pi);
	pi.p = inst;
	pi.buf = buffer;
	pi.blen = sizeof(buffer);
	pi.runtime_address = ip;

	if (options->att_format)
		pi.syntax = XED_SYNTAX_ATT;

	ok = xed_format_generic(&pi);
	if (!ok) {
		printf(" [xed print error]");
		return;
	}

	printf("  %s", buffer);
}

static void print_insn(const struct pt_insn *insn, xed_state_t *xed,
		       const struct ptxed_options *options, uint64_t offset,
		       uint64_t time)
{
	if (!insn || !options) {
		printf("[internal error]\n");
		return;
	}

	if (options->print_offset)
		printf("%016" PRIx64 "  ", offset);

	if (options->print_time)
		printf("%016" PRIx64 "  ", time);

	if (insn->speculative)
		printf("? ");

	printf("%016" PRIx64, insn->ip);

	if (!options->dont_print_insn) {
		xed_machine_mode_enum_t mode;
		xed_decoded_inst_t inst;
		xed_error_enum_t errcode;

		mode = translate_mode(insn->mode);

		xed_state_set_machine_mode(xed, mode);
		xed_decoded_inst_zero_set_mode(&inst, xed);

		errcode = xed_decode(&inst, insn->raw, insn->size);
		switch (errcode) {
		case XED_ERROR_NONE:
			xed_print_insn(&inst, insn->ip, options);
			break;

		default:
			print_raw_insn(insn);

			printf(" [xed decode error: (%u) %s]", errcode,
			       xed_error_enum_t2str(errcode));
			break;
		}
	}

	printf("\n");
}

static const char *print_exec_mode(enum pt_exec_mode mode)
{
	switch (mode) {
	case ptem_unknown:
		return "<unknown>";

	case ptem_16bit:
		return "16-bit";

	case ptem_32bit:
		return "32-bit";

	case ptem_64bit:
		return "64-bit";
	}

	return "<invalid>";
}

static void print_event(const struct pt_event *event,
			const struct ptxed_options *options, uint64_t offset)
{
	if (!event || !options) {
		printf("[internal error]\n");
		return;
	}

	printf("[");

	if (options->print_offset)
		printf("%016" PRIx64 "  ", offset);

	if (options->print_event_time && event->has_tsc)
		printf("%016" PRIx64 "  ", event->tsc);

	switch (event->type) {
	case ptev_enabled:
		printf("%s", event->variant.enabled.resumed ? "resumed" :
		       "enabled");

		if (options->print_event_ip)
			printf(", ip: %016" PRIx64, event->variant.enabled.ip);
		break;

	case ptev_disabled:
		printf("disabled");

		if (options->print_event_ip && !event->ip_suppressed)
			printf(", ip: %016" PRIx64, event->variant.disabled.ip);
		break;

	case ptev_async_disabled:
		printf("disabled");

		if (options->print_event_ip) {
			printf(", at: %016" PRIx64,
			       event->variant.async_disabled.at);

			if (!event->ip_suppressed)
				printf(", ip: %016" PRIx64,
				       event->variant.async_disabled.ip);
		}
		break;

	case ptev_async_branch:
		printf("interrupt");

		if (options->print_event_ip) {
			printf(", from: %016" PRIx64,
			       event->variant.async_branch.from);

			if (!event->ip_suppressed)
				printf(", to: %016" PRIx64,
				       event->variant.async_branch.to);
		}
		break;

	case ptev_paging:
		printf("paging, cr3: %016" PRIx64 "%s",
		       event->variant.paging.cr3,
		       event->variant.paging.non_root ? ", nr" : "");
		break;

	case ptev_async_paging:
		printf("paging, cr3: %016" PRIx64 "%s",
		       event->variant.async_paging.cr3,
		       event->variant.async_paging.non_root ? ", nr" : "");

		if (options->print_event_ip)
			printf(", ip: %016" PRIx64,
			       event->variant.async_paging.ip);
		break;

	case ptev_overflow:
		printf("overflow");

		if (options->print_event_ip && !event->ip_suppressed)
			printf(", ip: %016" PRIx64, event->variant.overflow.ip);
		break;

	case ptev_exec_mode:
		printf("exec mode: %s",
		       print_exec_mode(event->variant.exec_mode.mode));

		if (options->print_event_ip && !event->ip_suppressed)
			printf(", ip: %016" PRIx64,
			       event->variant.exec_mode.ip);
		break;

	case ptev_tsx:
		if (event->variant.tsx.aborted)
			printf("aborted");
		else if (event->variant.tsx.speculative)
			printf("begin transaction");
		else
			printf("committed");

		if (options->print_event_ip && !event->ip_suppressed)
			printf(", ip: %016" PRIx64, event->variant.tsx.ip);
		break;

	case ptev_stop:
		printf("stopped");
		break;

	case ptev_vmcs:
		printf("vmcs, base: %016" PRIx64, event->variant.vmcs.base);
		break;

	case ptev_async_vmcs:
		printf("vmcs, base: %016" PRIx64,
		       event->variant.async_vmcs.base);

		if (options->print_event_ip)
			printf(", ip: %016" PRIx64,
			       event->variant.async_vmcs.ip);
		break;

	case ptev_exstop:
		printf("exstop");

		if (options->print_event_ip && !event->ip_suppressed)
			printf(", ip: %016" PRIx64, event->variant.exstop.ip);
		break;

	case ptev_mwait:
		printf("mwait %" PRIx32 " %" PRIx32,
		       event->variant.mwait.hints, event->variant.mwait.ext);

		if (options->print_event_ip && !event->ip_suppressed)
			printf(", ip: %016" PRIx64, event->variant.mwait.ip);
		break;

	case ptev_pwre:
		printf("pwre c%u.%u", (event->variant.pwre.state + 1) & 0xf,
		       (event->variant.pwre.sub_state + 1) & 0xf);

		if (event->variant.pwre.hw)
			printf(" hw");
		break;


	case ptev_pwrx:
		printf("pwrx ");

		if (event->variant.pwrx.interrupt)
			printf("int: ");

		if (event->variant.pwrx.store)
			printf("st: ");

		if (event->variant.pwrx.autonomous)
			printf("hw: ");

		printf("c%u (c%u)", (event->variant.pwrx.last + 1) & 0xf,
		       (event->variant.pwrx.deepest + 1) & 0xf);
		break;

	case ptev_ptwrite:
		printf("ptwrite: %" PRIx64, event->variant.ptwrite.payload);

		if (options->print_event_ip && !event->ip_suppressed)
			printf(", ip: %016" PRIx64, event->variant.ptwrite.ip);
		break;

	case ptev_tick:
		printf("tick");

		if (options->print_event_ip && !event->ip_suppressed)
			printf(", ip: %016" PRIx64, event->variant.tick.ip);
		break;

	case ptev_cbr:
		printf("cbr: %x", event->variant.cbr.ratio);
		break;

	case ptev_mnt:
		printf("mnt: %" PRIx64, event->variant.mnt.payload);
		break;
	}

	printf("]\n");
}

static void diagnose(struct ptxed_decoder *decoder, uint64_t ip,
		     const char *errtype, int errcode)
{
	int err;
	uint64_t pos;

	err = -pte_internal;
	pos = 0ull;

	switch (decoder->type) {
	case pdt_insn_decoder:
		err = pt_insn_get_offset(decoder->variant.insn, &pos);
		break;

	case pdt_block_decoder:
		err = pt_blk_get_offset(decoder->variant.block, &pos);
		break;
	}

	if (err < 0) {
		printf("could not determine offset: %s\n",
		       pt_errstr(pt_errcode(err)));
		printf("[?, %" PRIx64 ": %s: %s]\n", ip, errtype,
		       pt_errstr(pt_errcode(errcode)));
	} else
		printf("[%" PRIx64 ", %" PRIx64 ": %s: %s]\n", pos,
		       ip, errtype, pt_errstr(pt_errcode(errcode)));
}

#if defined(FEATURE_SIDEBAND)

static int ptxed_sb_event(struct ptxed_decoder *decoder,
			  const struct pt_event *event,
			  const struct ptxed_options *options)
{
	struct pt_image *image;
	int errcode;

	if (!decoder || !event || !options)
		return -pte_internal;

	image = NULL;
	errcode = pt_sb_event(decoder->session, &image, event, sizeof(*event),
			      stdout, options->sb_dump_flags);
	if (errcode < 0)
		return errcode;

	if (!image)
		return 0;

	switch (decoder->type) {
	case pdt_insn_decoder:
		return pt_insn_set_image(decoder->variant.insn, image);

	case pdt_block_decoder:
		return pt_blk_set_image(decoder->variant.block, image);
	}

	return -pte_internal;
}

#endif /* defined(FEATURE_SIDEBAND) */

static int xed_next_ip(uint64_t *pip, const xed_decoded_inst_t *inst,
		       uint64_t ip)
{
	xed_uint_t length, disp_width;

	if (!pip || !inst)
		return -pte_internal;

	length = xed_decoded_inst_get_length(inst);
	if (!length) {
		printf("[xed error: failed to determine instruction length]\n");
		return -pte_bad_insn;
	}

	ip += length;

	/* If it got a branch displacement it must be a branch.
	 *
	 * This includes conditional branches for which we don't know whether
	 * they were taken.  The next IP won't be used in this case as a
	 * conditional branch ends a block.  The next block will start with the
	 * correct IP.
	 */
	disp_width = xed_decoded_inst_get_branch_displacement_width(inst);
	if (disp_width)
		ip += (uint64_t) (int64_t)
			xed_decoded_inst_get_branch_displacement(inst);

	*pip = ip;
	return 0;
}

static int block_fetch_insn(struct pt_insn *insn, const struct pt_block *block,
			    uint64_t ip, struct pt_image_section_cache *iscache)
{
	if (!insn || !block)
		return -pte_internal;

	/* We can't read from an empty block. */
	if (!block->ninsn)
		return -pte_invalid;

	memset(insn, 0, sizeof(*insn));
	insn->mode = block->mode;
	insn->isid = block->isid;
	insn->ip = ip;

	/* The last instruction in a block may be truncated. */
	if ((ip == block->end_ip) && block->truncated) {
		if (!block->size || (sizeof(insn->raw) < (size_t) block->size))
			return -pte_bad_insn;

		insn->size = block->size;
		memcpy(insn->raw, block->raw, insn->size);
	} else {
		int size;

		size = pt_iscache_read(iscache, insn->raw, sizeof(insn->raw),
				       insn->isid, ip);
		if (size < 0)
			return size;

		insn->size = (uint8_t) size;
	}

	return 0;
}

static void diagnose_block(struct ptxed_decoder *decoder,
			   const char *errtype, int errcode,
			   const struct pt_block *block)
{
	uint64_t ip;
	int err;

	if (!decoder || !block) {
		printf("ptxed: internal error");
		return;
	}

	/* Determine the IP at which to report the error.
	 *
	 * Depending on the type of error, the IP varies between that of the
	 * last instruction in @block or the next instruction outside of @block.
	 *
	 * When the block is empty, we use the IP of the block itself,
	 * i.e. where the first instruction should have been.
	 */
	if (!block->ninsn)
		ip = block->ip;
	else {
		ip = block->end_ip;

		switch (errcode) {
		case -pte_nomap:
		case -pte_bad_insn: {
			struct pt_insn insn;
			xed_decoded_inst_t inst;
			xed_error_enum_t xederr;

			/* Decode failed when trying to fetch or decode the next
			 * instruction.  Since indirect or conditional branches
			 * end a block and don't cause an additional fetch, we
			 * should be able to reach that IP from the last
			 * instruction in @block.
			 *
			 * We ignore errors and fall back to the IP of the last
			 * instruction.
			 */
			err = block_fetch_insn(&insn, block, ip,
					       decoder->iscache);
			if (err < 0)
				break;

			xed_decoded_inst_zero(&inst);
			xed_decoded_inst_set_mode(&inst,
						  translate_mode(insn.mode),
						  XED_ADDRESS_WIDTH_INVALID);

			xederr = xed_decode(&inst, insn.raw, insn.size);
			if (xederr != XED_ERROR_NONE)
				break;

			(void) xed_next_ip(&ip, &inst, insn.ip);
		}
			break;

		default:
			break;
		}
	}

	diagnose(decoder, ip, errtype, errcode);
}

static void print_block(struct ptxed_decoder *decoder,
			const struct pt_block *block,
			const struct ptxed_options *options,
			const struct ptxed_stats *stats,
			uint64_t offset, uint64_t time)
{
	xed_machine_mode_enum_t mode;
	xed_state_t xed;
	uint64_t ip;
	uint16_t ninsn;

	if (!block || !options) {
		printf("[internal error]\n");
		return;
	}

	if (options->track_blocks) {
		printf("[block");
		if (stats)
			printf(" %" PRIx64, stats->blocks);
		printf("]\n");
	}

	mode = translate_mode(block->mode);
	xed_state_init2(&xed, mode, XED_ADDRESS_WIDTH_INVALID);

	/* There's nothing to do for empty blocks. */
	ninsn = block->ninsn;
	if (!ninsn)
		return;

	ip = block->ip;
	for (;;) {
		struct pt_insn insn;
		xed_decoded_inst_t inst;
		xed_error_enum_t xederrcode;
		int errcode;

		if (options->print_offset)
			printf("%016" PRIx64 "  ", offset);

		if (options->print_time)
			printf("%016" PRIx64 "  ", time);

		if (block->speculative)
			printf("? ");

		printf("%016" PRIx64, ip);

		errcode = block_fetch_insn(&insn, block, ip, decoder->iscache);
		if (errcode < 0) {
			printf(" [fetch error: %s]\n",
			       pt_errstr(pt_errcode(errcode)));
			break;
		}

		xed_decoded_inst_zero_set_mode(&inst, &xed);

		xederrcode = xed_decode(&inst, insn.raw, insn.size);
		if (xederrcode != XED_ERROR_NONE) {
			print_raw_insn(&insn);

			printf(" [xed decode error: (%u) %s]\n", xederrcode,
			       xed_error_enum_t2str(xederrcode));
			break;
		}

		if (!options->dont_print_insn)
			xed_print_insn(&inst, insn.ip, options);

		printf("\n");

		ninsn -= 1;
		if (!ninsn)
			break;

		errcode = xed_next_ip(&ip, &inst, ip);
		if (errcode < 0) {
			diagnose(decoder, ip, "reconstruct error", errcode);
			break;
		}
	}

	/* Decode should have brought us to @block->end_ip. */
	if (ip != block->end_ip){
		printf("nosync2\n");
		diagnose(decoder, ip, "reconstruct error", -pte_nosync);
		}
}

static void check_block(const struct pt_block *block,
			struct pt_image_section_cache *iscache,
			uint64_t offset)
{
	struct pt_insn insn;
	xed_decoded_inst_t inst;
	uint64_t ip;
	uint16_t ninsn;
	int errcode;

	if (!block) {
		printf("[internal error]\n");
		return;
	}

	/* There's nothing to check for an empty block. */
	ninsn = block->ninsn;
	if (!ninsn)
		return;

	if (block->isid <= 0)
		printf("[%" PRIx64 ", %" PRIx64 ": check error: "
		       "bad isid]\n", offset, block->ip);

	ip = block->ip;
	do {
		errcode = block_fetch_insn(&insn, block, ip, iscache);
		if (errcode < 0) {
			printf("[%" PRIx64 ", %" PRIx64 ": fetch error: %s]\n",
			       offset, ip, pt_errstr(pt_errcode(errcode)));
			return;
		}

		xed_decoded_inst_zero(&inst);
		check_insn_decode(&inst, &insn, offset);

		/* We need a valid instruction in order to do further checks.
		 *
		 * Invalid instructions have already been diagnosed.
		 */
		if (!xed_decoded_inst_valid(&inst))
			return;

		errcode = xed_next_ip(&ip, &inst, ip);
		if (errcode < 0) {
			printf("[%" PRIx64 ", %" PRIx64 ": error: %s]\n",
			       offset, ip, pt_errstr(pt_errcode(errcode)));
			return;
		}
	} while (--ninsn);

	/* We reached the end of the block.  Both @insn and @inst refer to the
	 * last instruction in @block.
	 *
	 * Check that we reached the end IP of the block.
	 */
	if (insn.ip != block->end_ip) {
		printf("[%" PRIx64 ", %" PRIx64 ": error: did not reach end: %"
		       PRIx64 "]\n", offset, insn.ip, block->end_ip);
	}

	/* Check the last instruction's classification, if available. */
	insn.iclass = block->iclass;
	if (insn.iclass)
		check_insn_iclass(xed_decoded_inst_inst(&inst), &insn, offset);
}

static int drain_events_block(struct ptxed_decoder *decoder, uint64_t *time,
			      int status, const struct ptxed_options *options)
{
	struct pt_block_decoder *ptdec;
	int errcode;

	if (!decoder || !time || !options)
		return -pte_internal;

	ptdec = decoder->variant.block;

	while (status & pts_event_pending) {
		struct pt_event event;
		uint64_t offset;

		offset = 0ull;
		if (options->print_offset) {
			errcode = pt_blk_get_offset(ptdec, &offset);
			if (errcode < 0)
				return errcode;
		}

		status = pt_blk_event(ptdec, &event, sizeof(event));
		if (status < 0)
			return status;

		*time = event.tsc;

		if (!options->quiet && !event.status_update)
			print_event(&event, options, offset);

#if defined(FEATURE_SIDEBAND)
		errcode = ptxed_sb_event(decoder, &event, options);
		if (errcode < 0)
			return errcode;
#endif /* defined(FEATURE_SIDEBAND) */
	}

	return status;
}

// todo until here

int sync_pt_event_queue(struct pt_event_queue* src, struct pt_event_queue* dst)
{
	dst->begin = src->begin;
	dst->end = src->end;

	int count = evq_max;
	for (size_t i = 0; i < count; i++)
	{
		dst->queue[i] = src->queue[i];
	}

	dst->standalone = src->standalone;

	return 0;
}

int sync_pt_packet_decoder(struct pt_packet_decoder* src, struct pt_packet_decoder*dst)
{
	dst->config = src->config;
	dst->pos = src->pos;
	dst->sync = src->sync;

	return 0;
}

int	sync_pt_event_decoder(struct pt_event_decoder* evdec_src, struct pt_event_decoder* evdec_dst)
{
	evdec_dst->bound = evdec_src->bound;
	evdec_dst->csd = evdec_src->csd;
	evdec_dst->csl = evdec_src->csl;
	evdec_dst->enabled = evdec_src->enabled;
	evdec_dst->event = evdec_src->event;
	
	sync_pt_event_queue(&evdec_src->evq, &evdec_dst->evq);
	
	evdec_dst->flags = evdec_src->flags;
	evdec_dst->iflag = evdec_src->iflag;
	evdec_dst->ip = evdec_src->ip;
	evdec_dst->mode_exec_valid = evdec_src->mode_exec_valid;

	sync_pt_packet_decoder(&evdec_src->pacdec, &evdec_dst->pacdec);

	evdec_dst->packet = evdec_src->packet;
	evdec_dst->status = evdec_src->status;
	evdec_dst->tcal = evdec_src->tcal;
	evdec_dst->time = evdec_src->time;

	return 0;
}

int sync_retstack(struct pt_retstack* src, struct pt_retstack* dst)
{
	dst->bottom = src->bottom;

	int count = pt_retstack_size + 1;
	for (size_t i = 0; i < count; i++)
	{
		dst->stack[i] = src->stack[i];
	}

	dst->top = src->top;

	return 0;
}

int sync_scache(struct pt_msec_cache* src, struct pt_msec_cache* dst)
{
	dst->isid = src->isid;
	dst->msec = src->msec;

	return 0;
}

int copy_pt_block(struct pt_block* src, struct pt_block* dst)
{
	dst->end_ip = src->end_ip;
	dst->iclass = src->iclass;
	dst->ip = src->ip;
	dst->isid = src->isid;
	dst->mode = src->mode;
	dst->ninsn = src->ninsn;

	int count = pt_max_insn_size;
	for (size_t i = 0; i < count; i++)
	{
		dst->raw[i] = src->raw[i];
	}
	
	dst->size = src->size;
	dst->speculative = src->speculative;
	dst->truncated = src->truncated;
	
	return 0;
}

int sync_pt_block_decoder(struct pt_block_decoder* ptdec_src, struct pt_block_decoder* ptdec_dst)
{
	ptdec_dst->asid = ptdec_src->asid;
	ptdec_dst->bound_iret = ptdec_src->bound_iret;
	ptdec_dst->bound_paging = ptdec_src->bound_paging;
	ptdec_dst->bound_ptwrite = ptdec_src->bound_ptwrite;
	ptdec_dst->bound_uiret = ptdec_src->bound_uiret;
	ptdec_dst->bound_vmcs = ptdec_src->bound_vmcs;
	ptdec_dst->bound_vmentry = ptdec_src->bound_vmentry;
	ptdec_dst->cbr = ptdec_src->cbr;
	ptdec_dst->default_image = ptdec_src->default_image;	// todo check
	ptdec_dst->enabled = ptdec_src->enabled;

	ptdec_dst->evdec;
	
	ptdec_dst->event = ptdec_src->event;	// todo check
	ptdec_dst->flags = ptdec_src->flags;	// todo check
	ptdec_dst->has_tsc = ptdec_src->has_tsc;
	ptdec_dst->iext = ptdec_src->iext;
	ptdec_dst->image = ptdec_src->image;
	ptdec_dst->insn = ptdec_src->insn;
	ptdec_dst->ip = ptdec_src->ip;
	ptdec_dst->lost_cyc = ptdec_src->lost_cyc;
	ptdec_dst->lost_mtc = ptdec_src->lost_mtc;
	ptdec_dst->mode = ptdec_src->mode;
	ptdec_dst->process_insn = ptdec_src->process_insn;

	ptdec_dst->retstack;
	ptdec_dst->scache;
	
	ptdec_dst->speculative = ptdec_src->speculative;
	ptdec_dst->status = ptdec_src->status;
	ptdec_dst->tsc = ptdec_src->tsc;
	
	sync_pt_event_decoder(&ptdec_src->evdec, &ptdec_dst->evdec);
	sync_retstack(&ptdec_src->retstack, &ptdec_dst->retstack);
	sync_scache(&ptdec_src->scache, &ptdec_dst->scache);
	
	return 0;
}


void pt_decode_block_recover(struct pt_block_decoder *ptdec_orig,
							struct pt_block* block_orig,
							uint64_t offset_orig,
							struct pt_packet_decoder* pkt_dec,
							uint64_t time_orig,
							struct ptxed_decoder *decoder_orig,
							const struct ptxed_options *options_orig,
 							struct pt_image_section_cache *iscache,
 							struct ptxed_stats *stats,
							struct pt_block_decoder *ptdec)
{
	printf("%s enter #######################################################################\n", __func__);

	int status;
	int err;
	uint64_t time = time_orig;
	uint64_t offset = offset_orig;

	struct ptxed_decoder *decoder = decoder_orig;
	sync_pt_block_decoder(ptdec_orig, ptdec);

	const struct ptxed_options options = *options_orig;

	struct pt_block block;
	copy_pt_block(block_orig, &block);

	for (;;) {
			status = drain_events_block(decoder, &time, status,
								&options);

			if (status < 0)
			{
				if (status == -pte_nomap || status == -pte_bad_query)
				{
					int st = handle_no_map(ptdec, &block, &offset, pkt_dec);
					if (st == ppt_tip || st == ppt_tip_pge || st == ppt_tip_pgd || st == ppt_fup)
					{
						printf("found1: %lx %lx\n", ptdec->ip, ptdec->evdec.ip.ip);
						status = 0;
						// continue;
					}
					else if (st == -pte_eos)
					{
						printf("handle1 eos\n");
						break;
					}
					else if (st == ppt_psb)
					{
						break;
					}
					else
					{
						break;
					}
				}
			}

			if (status & pts_eos) {
				if (!(status & pts_ip_suppressed) &&
				    !options.quiet)
					printf("[end of trace]\n");

				status = -pte_eos;
				break;
			}

			if (options.print_offset || options.check) {
				int errcode;

				errcode = pt_blk_get_offset(ptdec, &offset);

				if (errcode < 0)
					break;
			}

			status = pt_blk_next(ptdec, &block, sizeof(block));

			if (status < 0) {
				/* Even in case of errors, we may have succeeded
				 * in decoding some instructions.
				 */
				if (block.ninsn) {
					if (stats) {
						stats->insn += block.ninsn;
						stats->blocks += 1;
					}

					if (!options.quiet)
					{
						print_block(decoder, &block,
							    &options, stats,
							    offset, time);
					}

					if (options.check)
					{
						check_block(&block, iscache,
							    offset);
					}
				}

				// if (status == -pte_nomap || status == -pte_bad_query)
				if (status == -pte_nomap)
				{

					uint64_t new_ip;

					int st = handle_no_map(ptdec, &block, &offset, pkt_dec);

					if (st == ppt_tip || st == ppt_tip_pge || st == ppt_tip_pgd || st == ppt_fup)
					{
						printf("found2: %lx %lx\n", ptdec->ip, ptdec->evdec.ip.ip);
						status = 0;
					}
					else if (st == -pte_eos)
					{
						printf("handle1 eos\n");
						break;
					}
					else if (st == ppt_psb)
					{
						break;
					}
					else
					{
						break;
					}

				}
			}

			if (stats)
			{
				stats->insn += block.ninsn;
				stats->blocks += 1;
			}
			if (!options.quiet)
			{
				print_block(decoder, &block, &options, stats,
					    offset, time);
			}
			if (options.check)
			{
				check_block(&block, iscache, offset);
			}
		}

    ret:
	printf("%s exit #######################################################################\n", __func__);

    return;
}