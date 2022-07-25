#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <rmap.h>



/**
 * @brief valiidates a command code
 *
 * @param cmd the command code
 *
 * @returns 0 on success, error otherwise
 */

static int rmap_validate_cmd_code(uint8_t cmd)
{
	switch (cmd) {
	case RMAP_READ_ADDR_SINGLE:
	case RMAP_READ_ADDR_INC:
	case RMAP_READ_MODIFY_WRITE_ADDR_INC:
	case RMAP_WRITE_ADDR_SINGLE:
	case RMAP_WRITE_ADDR_INC:
	case RMAP_WRITE_ADDR_SINGLE_REPLY:
	case RMAP_WRITE_ADDR_INC_REPLY:
	case RMAP_WRITE_ADDR_SINGLE_VERIFY:
	case RMAP_WRITE_ADDR_INC_VERIFY:
	case RMAP_WRITE_ADDR_SINGLE_VERIFY_REPLY:
	case RMAP_WRITE_ADDR_INC_VERIFY_REPLY:
		return 0;
	default:
		return -1;
	}
}


/**
 * @brief get the minimum header size given the RMAP instruction
 *
 * @param pkt a struct rmap_pkt
 *
 * @returns header size or -1 on error
 */

static int rmap_get_min_hdr_size(struct rmap_pkt *pkt)
{


	switch (pkt->ri.cmd) {
	case RMAP_READ_ADDR_SINGLE:
	case RMAP_READ_ADDR_INC:
	case RMAP_READ_MODIFY_WRITE_ADDR_INC:

		if (pkt->ri.cmd_resp)
			return RMAP_HDR_MIN_SIZE_READ_CMD;

		return RMAP_HDR_MIN_SIZE_READ_REP;

	case RMAP_WRITE_ADDR_SINGLE:
	case RMAP_WRITE_ADDR_INC:
	case RMAP_WRITE_ADDR_SINGLE_REPLY:
	case RMAP_WRITE_ADDR_INC_REPLY:
	case RMAP_WRITE_ADDR_SINGLE_VERIFY:
	case RMAP_WRITE_ADDR_INC_VERIFY:
	case RMAP_WRITE_ADDR_SINGLE_VERIFY_REPLY:
	case RMAP_WRITE_ADDR_INC_VERIFY_REPLY:

		if (pkt->ri.cmd_resp)
			return RMAP_HDR_MIN_SIZE_WRITE_CMD;

		return RMAP_HDR_MIN_SIZE_WRITE_REP;

	default:
		return -1;
	}
}


/**
 * @brief create an RMAP packet and set defaults
 *
 *
 * @note initialises protocol id to 1 and all others to 0
 *
 * @returns a struct rmap_pkt or NULL on error
 */
struct rmap_pkt *rmap_create_packet(void)
{
	struct rmap_pkt *pkt;


	pkt = (struct rmap_pkt *) calloc(sizeof(struct rmap_pkt), 1);
	if (pkt)
		pkt->proto_id = RMAP_PROTOCOL_ID;

	return pkt;
}


/**
 * @brief destroys an RMAP packet
 *
 * @param pkt a struct rmap_pkt
 *
 * @note this will NOT deallocate and pointer references assigned by the user
 */

void rmap_destroy_packet(struct rmap_pkt *pkt)
{
	free(pkt);
}


/**
 * @brief completely destroys an RMAP packet
 *
 * @param pkt a struct rmap_pkt
 *
 * @note this will attempt to deallocate any pointer references assigned by the
 * 	 user
 * @warning use with care
 */

void rmap_erase_packet(struct rmap_pkt *pkt)
{
	free(pkt->path);
	free(pkt->rpath);
	free(pkt->data);
	free(pkt);
}

/**
 * @brief set the destination (target) logical address
 *
 * @param pkt	a struct rmap_pkt
 * @param addr	the destination logical address
 */

void rmap_set_dst(struct rmap_pkt *pkt, uint8_t addr)
{
	if (pkt)
		pkt->dst = addr;
}


/**
 * @brief set the source (initiator) logical address
 *
 * @param pkt	a struct rmap_pkt
 * @param addr	the source logical address
 */

void rmap_set_src(struct rmap_pkt *pkt, uint8_t addr)
{
	if (pkt)
		pkt->src = addr;
}


/**
 * @brief set the command authorisation key
 *
 * @param pkt	a struct rmap_pkt
 * @param key	the authorisation key
 */

void rmap_set_key(struct rmap_pkt *pkt, uint8_t key)
{
	if (pkt)
		pkt->key = key;
}


/**
 * @brief set the reply address path
 *
 * @param pkt	a struct rmap_pkt
 * @param rpath the reply path
 * @param len   the number of elements in the reply path
 *
 * @note see ECSS‐E‐ST‐50‐52C 5.1.6 for return path rules
 *
 * @returns 0 on success, -1 on error
 */

int rmap_set_reply_path(struct rmap_pkt *pkt, uint8_t *rpath, uint8_t len)
{
	if (!pkt)
		return -1;

	if (!rpath && len)
		return -1;

	if (len > RMAP_MAX_REPLY_PATH_LEN)
		return -1;

	if (len & 0x3)
		return -1;

	pkt->rpath     = rpath;
	pkt->rpath_len = len;

	/* number of 32 bit words needed to contain the path */
	pkt->ri.reply_addr_len = len >> 2;

	return 0;
}


/**
 * @brief set an RMAP command
 *
 * @param pkt	a struct rmap_pkt
 * @param cmd	the selected command
 *
 * @param returns -1 on error
 */

int rmap_set_cmd(struct rmap_pkt *pkt, uint8_t cmd)
{
	if (!pkt)
		return -1;

	if (rmap_validate_cmd_code(cmd))
		return -1;


	pkt->ri.cmd      = cmd & 0xF;
	pkt->ri.cmd_resp = 1;

	return 0;
}


/**
 * @brief set an RMAP transaction identifier
 *
 * @param pkt	a struct rmap_pkt
 * @param id	the transaction identifier
 */

void rmap_set_tr_id(struct rmap_pkt *pkt, uint16_t id)
{
	if (!pkt)
		return;

	pkt->tr_id = id;
}


/**
 * @brief set a data address
 *
 * @param pkt	a struct rmap_pkt
 * @param addr	the address
 */

void rmap_set_data_addr(struct rmap_pkt *pkt, uint32_t addr)
{
	if (!pkt)
		return;

	pkt->addr = addr;
}

/**
 * @brief set an RMAP command
 *
 * @param pkt	a struct rmap_pkt
 * @param len	the data length (in bytes)
 *
 * @param returns -1 on error
 *
 * @note the length is at most 2^24-1 bytes
 * @note if the RMAP command is of 'SINGLE' type, only multiples of 4
 *	 will result in successfull execution of the command (at least
 *	 with the GRSPW2 core)
 */

int rmap_set_data_len(struct rmap_pkt *pkt, uint32_t len)
{
	if (!pkt)
		return -1;

	if (len > RMAP_MAX_DATA_LEN)
		return -1;

	pkt->data_len = len;

	return 0;
}


/**
 * @brief build an rmap header
 *
 * @param pkt	a struct rmap_pkt
 * @param hdr	the header buffer; if NULL, the function returns the needed size
 *
 * @returns -1 on error, size of header otherwise
 */

int rmap_build_hdr(struct rmap_pkt *pkt, uint8_t *hdr)
{
	int i;
	int n = 0;


	if (!pkt)
		return -1;

	if (!hdr) {
		n = rmap_get_min_hdr_size(pkt);
		n += pkt->path_len;
		n += pkt->rpath_len;
		return n;
	}


	for (i = 0; i < pkt->path_len; i++)
		hdr[n++] = pkt->path[i];	/* routing path to target */

	hdr[n++] = pkt->dst;			/* target logical address */
	hdr[n++] = pkt->proto_id;		/* protocol id */
	hdr[n++] = pkt->instruction;		/* instruction */
	hdr[n++] = pkt->key;			/* key/status */

	for (i = 0; i < pkt->rpath_len; i++)
		hdr[n++] = pkt->rpath[i];	/* return path to source */

	hdr[n++] = pkt->src;			/* source logical address */
	hdr[n++] = (uint8_t) (pkt->tr_id >> 8);	/* MSB of transaction id */
	hdr[n++] = (uint8_t)  pkt->tr_id;	/* LSB of transaction id */


	/* commands have a data address */
	if (pkt->ri.cmd_resp) {
		hdr[n++] = 0x0;	/* extended address field (unused) */
		hdr[n++] = (uint8_t) (pkt->addr >> 24); /* data addr MSB */
		hdr[n++] = (uint8_t) (pkt->addr >> 16);
		hdr[n++] = (uint8_t) (pkt->addr >>  8);
		hdr[n++] = (uint8_t)  pkt->addr;	/* data addr LSB */
	} else if (pkt->ri.cmd & (RMAP_CMD_BIT_WRITE | RMAP_CMD_BIT_REPLY)) {
		/* all headers have data length unless they are a write reply */
		return n;
	}

	hdr[n++] = (uint8_t) (pkt->data_len >> 16); /* data len MSB */
	hdr[n++] = (uint8_t) (pkt->data_len >>  8);
	hdr[n++] = (uint8_t)  pkt->data_len;	    /* data len LSB */

	return n;
}


/**
 * @brief create an rmap packet from a buffer
 *
 * @param buf the buffer, with the target path stripped away, i.e.
 *	  starting with <logical address>, <protocol id>, ...
 *
 * @note there is no size checking, be careful
 *
 * @returns an rmap packet, containing the decoded buffer including any data,
 *	    NULL on error
 */

struct rmap_pkt *rmap_pkt_from_buffer(uint8_t *buf)
{
	size_t n, i;

	struct rmap_pkt *pkt = NULL;


	if (!buf)
		goto error;

	if (buf[RMAP_PROTOCOL_ID] != RMAP_PROTOCOL_ID) {
		printf("Not an RMAP packet, got %x but expected %x\n",
		       buf[RMAP_PROTOCOL_ID], RMAP_PROTOCOL_ID);
		goto error;
	}

	pkt = rmap_create_packet();
	if (!pkt) {
		printf("Error creating packet\n");
		goto error;
	}

	pkt->dst         = buf[RMAP_DEST_ADDRESS];
	pkt->proto_id    = buf[RMAP_PROTOCOL_ID];
	pkt->instruction = buf[RMAP_INSTRUCTION];
	pkt->key         = buf[RMAP_CMD_DESTKEY];


	pkt->rpath_len = pkt->ri.reply_addr_len << 2;

	pkt->rpath = (uint8_t *) malloc(pkt->rpath_len);
	if (!pkt->rpath)
		goto error;

	for (i = 0; i < pkt->rpath_len; i++)
		pkt->rpath[i] = buf[RMAP_REPLY_ADDR_START + i];


	n = pkt->rpath_len; /* rpath skip */

	pkt->src   = buf[RMAP_SRC_ADDR + n];
	pkt->tr_id = ((uint16_t) buf[RMAP_TRANS_ID_BYTE0 + n] << 8) |
	              (uint16_t) buf[RMAP_TRANS_ID_BYTE1 + n];

	/* commands have a data address */
	if (pkt->ri.cmd_resp) {
		pkt->addr = ((uint32_t) buf[RMAP_ADDR_BYTE0 + n] << 24) |
			    ((uint32_t) buf[RMAP_ADDR_BYTE1 + n] << 16) |
			    ((uint32_t) buf[RMAP_ADDR_BYTE2 + n] <<  8) |
			     (uint32_t) buf[RMAP_ADDR_BYTE3 + n];
		n += 4; /* addr skip, extended byte is incorporated in define */
	}

	/* all headers have data length unless they are a write reply */
	if (((pkt->ri.cmd ^ (RMAP_CMD_BIT_WRITE | RMAP_CMD_BIT_REPLY))
	      & (RMAP_CMD_BIT_WRITE | RMAP_CMD_BIT_REPLY))) {

		pkt->data_len = ((uint32_t) buf[RMAP_DATALEN_BYTE0 + n] << 16) |
				((uint32_t) buf[RMAP_DATALEN_BYTE1 + n] <<  8) |
			         (uint32_t) buf[RMAP_DATALEN_BYTE2 + n];
	}

	if (pkt->data_len) {
		pkt->data = (uint8_t *) malloc(pkt->data_len);
		if (!pkt->data)
			goto error;

		for (i = 0; i < pkt->data_len; i++)
			pkt->data[i] = buf[RMAP_DATA_START + n + i];
	}


	return pkt;

error:
	if (pkt) {
		free(pkt->data);
		free(pkt->rpath);
		free(pkt);
	}

	return NULL;
}



/**** UNFINISHED INFO STUFF BELOW ******/

__extension__
static int rmap_check_status(uint8_t status)
{


	printf("Status: ");

	switch (status) {
	case RMAP_STATUS_SUCCESS:
		printf("Command executed successfully");
		break;
	case RMAP_STATUS_GENERAL_ERROR:
		printf("General error code");
		break;
	case RMAP_STATUS_UNUSED_TYPE_OR_CODE:
		printf("Unused RMAP Packet Type or Command Code");
		break;
	case RMAP_STATUS_INVALID_KEY:
		printf("Invalid key");
		break;
	case RMAP_STATUS_INVALID_DATA_CRC:
		printf("Invalid Data CRC");
		break;
	case RMAP_STATUS_EARLY_EOP:
		printf("Early EOP");
		break;
	case RMAP_STATUS_TOO_MUCH_DATA:
		printf("Too much data");
		break;
	case RMAP_STATUS_EEP:
		printf("EEP");
		break;
	case RMAP_STATUS_RESERVED:
		printf("Reserved");
		break;
	case RMAP_STATUS_VERIFY_BUFFER_OVERRRUN:
		printf("Verify buffer overrrun");
		break;
	case RMAP_STATUS_CMD_NOT_IMPL_OR_AUTH:
		printf("RMAP Command not implemented or not authorised");
		break;
	case RMAP_STATUS_RMW_DATA_LEN_ERROR:
		printf("RMW Data Length error");
		break;
	case RMAP_STATUS_INVALID_TARGET_LOGICAL_ADDR:
		printf("Invalid Target Logical Address");
		break;
	default:
		printf("Reserved unused error code %d", status);
		break;
	}

	printf("\n");


	return status;
}




static void rmap_process_read_reply(uint8_t *pkt)
{
	uint32_t i;

	uint32_t len = 0;


	len |= ((uint32_t) pkt[RMAP_DATALEN_BYTE0]) << 16;
	len |= ((uint32_t) pkt[RMAP_DATALEN_BYTE1]) <<  8;
	len |= ((uint32_t) pkt[RMAP_DATALEN_BYTE2]) <<  0;


	printf("Data length is %d bytes:\n\t", len);

	for (i = 0; i < len; i++)
		printf("%02x:", pkt[RMAP_DATA_START + i]);

	printf("\n");
}




static void rmap_parse_cmd_pkt(uint8_t *pkt)
{
	(void) pkt;
	printf("rmap_parse_cmd_pkt() not implemented\n");
}


static void rmap_parse_reply_pkt(uint8_t *pkt)
{
	struct rmap_instruction *ri;


	ri = (struct rmap_instruction *) &pkt[RMAP_INSTRUCTION];


	switch (ri->cmd) {

	case RMAP_READ_ADDR_SINGLE:
		printf("Read single address\n");
		rmap_process_read_reply(pkt);
		break;
	case RMAP_READ_ADDR_INC:
		printf("Read incrementing address\n");
		rmap_process_read_reply(pkt);
		break;
	default:
		printf("Unknown command type\n");
		return;
	}
}


/**
 * parse an RMAP packet:
 *
 * expected format: <logical address> <protocol id> ...
 */

void rmap_parse_pkt(uint8_t *pkt)
{
	struct rmap_instruction *ri;

	if (pkt[RMAP_PROTOCOL_ID] != RMAP_PROTOCOL_ID) {
		printf("Not an RMAP packet, got %x but expected %x\n",
		       pkt[RMAP_PROTOCOL_ID], RMAP_PROTOCOL_ID);
		return;
	}


	ri = (struct rmap_instruction *) &pkt[RMAP_INSTRUCTION];

	if (ri->cmd_resp) {
		printf("This is a command packet\n");
		rmap_parse_cmd_pkt(pkt);
	} else {
		printf("This is a reply packet\n");
		if (!rmap_check_status(pkt[RMAP_REPLY_STATUS]))
			rmap_parse_reply_pkt(pkt);
	}
}

