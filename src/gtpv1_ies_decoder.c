/*
 * Copyright (c) 2022 Great Software Laboratory (GS Lab)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. 
 */

#include "../include/gtpv1_ies_decoder.h"

int get_length(uint8_t type){
	switch (type)
	{
		case GTPV1_IE_CAUSE:
			return GTPV1_IE_CAUSE_LEN;
		case GTPV1_IE_IMSI:
			return GTPV1_IE_IMSI_LEN;
		case GTPV1_IE_ROUTEING_AREA_IDENTITY:
			return GTPV1_IE_ROUTEING_AREA_IDENTITY_LEN;
		case GTPV1_IE_TEMPORARY_LOGICAL_LINK_IDENTIFIER:
			return GTPV1_IE_TEMPORARY_LOGICAL_LINK_IDENTIFIER_LEN;
		case GTPV1_IE_PACKET_TMSI:
			return GTPV1_IE_PACKET_TMSI_LEN;
		case GTPV1_IE_REORDERING_REQ:
			return GTPV1_IE_REORDERING_REQ_LEN;
		case GTPV1_IE_AUTH_TRIPLET:
			return GTPV1_IE_AUTH_TRIPLET_LEN;
		case GTPV1_IE_MAP_CAUSE:
			return GTPV1_IE_MAP_CAUSE_LEN;
		case GTPV1_IE_P_TMSI_SIGNATURE:
			return GTPV1_IE_P_TMSI_SIGNATURE_LEN;
		case GTPV1_IE_MS_VALIDATED:
			return GTPV1_IE_MS_VALIDATED_LEN;
		case GTPV1_IE_RECOVERY:
			return GTPV1_IE_RECOVERY_LEN;
		case GTPV1_IE_SELECTION_MODE:
			return GTPV1_IE_SELECTION_MODE_LEN;
		case GTPV1_IE_TEID_DATA_1:
			return GTPV1_IE_TEID_DATA_1_LEN;
		case GTPV1_IE_TEID_CONTROL_PLANE:
			return GTPV1_IE_TEID_CONTROL_PLANE_LEN;
		case GTPV1_IE_TEID_DATA_2:
			return GTPV1_IE_TEID_DATA_2_LEN;
		case GTPV1_IE_TEARDOWN_IND:
			return GTPV1_IE_TEARDOWN_IND_LEN;
		case GTPV1_IE_NSAPI:
			return GTPV1_IE_NSAPI_LEN;
		case GTPV1_IE_RANAP_CAUSE:
			return GTPV1_IE_RANAP_CAUSE_LEN;
		case GTPV1_IE_RAB_CONTEXT:
			return GTPV1_IE_RAB_CONTEXT_LEN;
		case GTPV1_IE_RADIO_PRIORITY_SMS:
			return GTPV1_IE_RADIO_PRIORITY_SMS_LEN;
		case GTPV1_IE_RADIO_PRIORITY:
			return GTPV1_IE_RADIO_PRIORITY_LEN;
		case GTPV1_IE_PACKET_FLOW_ID:
			return GTPV1_IE_PACKET_FLOW_ID_LEN;
		case GTPV1_IE_CHRGNG_CHAR:
			return GTPV1_IE_CHRGNG_CHAR_LEN;
		case GTPV1_IE_TRACE_REFERENCE:
			return GTPV1_IE_TRACE_REFERENCE_LEN;
		case GTPV1_IE_TRACE_TYPE:
			return GTPV1_IE_TRACE_TYPE_LEN;
		case GTPV1_IE_MS_NOT_RECHABLE_REASON:
			return GTPV1_IE_MS_NOT_RECHABLE_REASON_LEN;
		case GTPV1_IE_CHARGING_ID:
			return GTPV1_IE_CHARGING_ID_LEN;
		default:
			return -1;
	}
}

int16_t decode_gtpv1_header(const uint8_t *buf, gtpv1_header_t *header) {

	if(buf == NULL || header == NULL){
		return -1;
	}
	uint16_t count = 0;
	uint16_t decoded = 0;

	header->version = decode_bits(buf, count, 3, &decoded);
	count += decoded;
	header->protocol_type = decode_bits(buf, count, 1, &decoded);
	count += decoded;
	header->spare = decode_bits(buf, count, 1, &decoded);
	count += decoded;
	header->extension_header = decode_bits(buf, count, 1, &decoded);
	count += decoded;
	header->seq_num_flag = decode_bits(buf, count, 1, &decoded);
	count += decoded;
	header->n_pdu_flag = decode_bits(buf, count, 1, &decoded);
	count += decoded;

	header->message_type = decode_bits(buf, count, 8, &decoded);
	count += decoded;
	header->message_len = decode_bits(buf, count, 16, &decoded);
	count += decoded;
	header->teid = decode_bits(buf, count, 32, &decoded);
	count += decoded;

	if(header->seq_num_flag == 1 || header->n_pdu_flag == 1 || header->extension_header == 1) {
		header->seq = decode_bits(buf, count, 16, &decoded);
		count += decoded;
		header->n_pdu_number = decode_bits(buf, count, 8, &decoded);
		count += decoded;
		header->next_extension_header_type = decode_bits(buf, count, 8, &decoded);
		count += decoded;
	}
	return count/CHAR_SIZE;
}

int16_t decode_gtpv1_ie_header(const uint8_t *buf, gtpv1_ie_header_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t count = 0;
	uint16_t decoded = 0;
	value->type = decode_bits(buf, count, 8, &decoded);
	count += decoded;
	if((value->type >> 7) == 1 ) {
		value->length = decode_bits(buf, count, 16, &decoded);
		count += decoded;
	} else {
		value->length = get_length(value->type);
	}
	return count;
}

void decode_imsi(const uint8_t *buf, int len, uint64_t *imsi) {

	char hex[16] = {0};
	bool flag = false;

	for(uint32_t i = 0; i < len; i++) {
		if (i == len -1 && (((buf[i] & 0xF0)>>4) == 0x0F)) {
			sprintf(hex + i*2 , "%02x", (buf[i] & 0x0F)<<4);
			flag = true;
		}
		else
			sprintf(hex + i*2 , "%02x",(((buf[i] & 0x0F)<<4) | ((buf[i] & 0xF0)>>4)));
	}
	sscanf(hex, "%lu", imsi);
	if (flag)
		*imsi /= 10;
	return;
}

int16_t decode_gtpv1_imsi_ie(const uint8_t *buf, gtpv1_imsi_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));

	decode_imsi((uint8_t *)buf + total_decoded/CHAR_SIZE, sizeof(uint64_t),
							&value->imsi_number_digits);
	total_decoded += sizeof(uint64_t) * CHAR_SIZE;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_teid_ie(const uint8_t *buf, gtpv1_teid_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->teid = decode_bits(buf, total_decoded, 32, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_nsapi_ie(const uint8_t *buf, gtpv1_nsapi_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));

	uint16_t decoded = 0;
	value->spare = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->nsapi_value = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_apn_ie(const uint8_t *buf, gtpv1_apn_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;

	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	memcpy(&value->apn_value, buf + (total_decoded/CHAR_SIZE), value->header.length);
	total_decoded += value->header.length * CHAR_SIZE;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_pdp_address(const uint8_t *buf, gtpv1_pdp_addr_t *value, uint16_t total_decoded, uint16_t length, uint8_t number) {

	uint16_t decoded = 0;
	if (number == 0x21 && length == 4){
		value->ipv4 = decode_bits(buf, total_decoded, 32, &decoded);
		total_decoded += decoded;
	} else if (number == 0x57 && length == 16){
		memcpy(&value->ipv6, buf + (total_decoded/CHAR_SIZE), IPV6_ADDR_LEN);
		total_decoded += IPV6_ADDR_LEN * CHAR_SIZE;
	} else if (number == 0x8D){
		if (length == 4) {
			value->ipv4 = decode_bits(buf, total_decoded, 32, &decoded);
			total_decoded += decoded;
		} else if (length == 16) {
			memcpy(&value->ipv6, buf + (total_decoded/CHAR_SIZE), IPV6_ADDR_LEN);
			total_decoded += IPV6_ADDR_LEN * CHAR_SIZE;
		} else if (length == 20) {
			value->ipv4= decode_bits(buf, total_decoded, 32, &decoded);
			total_decoded += decoded;
			memcpy(&value->ipv6, buf + (total_decoded/CHAR_SIZE), IPV6_ADDR_LEN);
			total_decoded += IPV6_ADDR_LEN * CHAR_SIZE;
		}
	} else {
		return 0;
	}
	return total_decoded;
}

int16_t decode_gsn_address(const uint8_t *buf, gtpv1_gsn_addr_t *value, uint16_t total_decoded, uint16_t length) {

	uint16_t decoded = 0;
	if (length == 4) {
		value->ipv4 = decode_bits(buf, total_decoded, 32, &decoded);
		total_decoded += decoded;
	} else if(length == 16) {
		memcpy(&value->ipv6, buf + (total_decoded/CHAR_SIZE), IPV6_ADDR_LEN);
		total_decoded += IPV6_ADDR_LEN * CHAR_SIZE;
	} else {
		return 0;
	}
	return total_decoded;
}

int16_t decode_gtpv1_gsn_address_ie(const uint8_t *buf, gtpv1_gsn_addr_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));

	total_decoded = decode_gsn_address(buf, &(value->gsn_address), total_decoded, value->header.length);
	return total_decoded/CHAR_SIZE;
}

int16_t decode_qos(const uint8_t *buf, gtpv1_qos_t *value, uint16_t total_decoded, uint16_t length){

	uint16_t decoded = 0;

	value->allocation_retention_priority = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	total_decoded += 2;
	value->delay_class = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	value->reliablity_class = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	value->peak_throughput = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	total_decoded += 1;
	value->precedence_class = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	total_decoded += 3;
	value->mean_throughput = decode_bits(buf, total_decoded, 5, &decoded);
	total_decoded += decoded;
	value->traffic_class = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	value->delivery_order = decode_bits(buf, total_decoded, 2, &decoded);
	total_decoded += decoded;
	value->delivery_erroneous_sdu = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	value->max_sdu_size = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	value->max_bitrate_uplink = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	value->max_bitrate_downlink = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	value->residual_ber = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->sdu_error_ratio = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->transfer_delay = decode_bits(buf, total_decoded, 6, &decoded);
	total_decoded += decoded;
	value->traffic_handling_priority = decode_bits(buf, total_decoded, 2, &decoded);
	total_decoded += decoded;
	value->guaranteed_bitrate_uplink = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	value->guaranteed_bitrate_downlink = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	total_decoded += 3;
	value->signalling_indication = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->source_statistics_descriptor = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	if (length > 12) {
		value->max_bitrate_downlink_ext1 = decode_bits(buf, total_decoded, 8, &decoded);
		total_decoded += decoded;
		value->guaranteed_bitrate_downlink_ext1 = decode_bits(buf, total_decoded, 8, &decoded);
		total_decoded += decoded;
	}
	if (length > 14) {
		value->max_bitrate_uplink_ext1 = decode_bits(buf, total_decoded, 8, &decoded);
		total_decoded += decoded;
		value->guaranteed_bitrate_uplink_ext1 = decode_bits(buf, total_decoded, 8, &decoded);
		total_decoded += decoded;
	}
	if (length > 16) {
		value->max_bitrate_downlink_ext2 = decode_bits(buf, total_decoded, 8, &decoded);
		total_decoded += decoded;
		value->guaranteed_bitrate_downlink_ext2 = decode_bits(buf, total_decoded, 8, &decoded);
		total_decoded += decoded;
	}
	if (length > 18) {
		value->max_bitrate_uplink_ext2 = decode_bits(buf, total_decoded, 8, &decoded);
		total_decoded += decoded;
		value->guaranteed_bitrate_uplink_ext2 = decode_bits(buf, total_decoded, 8, &decoded);
		total_decoded += decoded;
	}

	return total_decoded;
}

int16_t decode_gtpv1_qos_ie(const uint8_t *buf, gtpv1_qos_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));

	total_decoded = decode_qos(buf, &(value->qos), total_decoded, value->header.length);
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_cause_ie(const uint8_t *buf, gtpv1_cause_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->cause_value = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_selection_mode_ie(const uint8_t *buf, gtpv1_selection_mode_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->spare2 = decode_bits(buf, total_decoded, 6, &decoded);
	total_decoded += decoded;
	value->selec_mode = decode_bits(buf, total_decoded, 2, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_chrgng_char_ie(const uint8_t *buf, gtpv1_chrgng_char_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));

	uint16_t decoded = 0;
	value->chrgng_char_val = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_msisdn_ie(const uint8_t *buf, gtpv1_msisdn_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));

	memcpy(&value->msisdn_number_digits, buf + (total_decoded/CHAR_SIZE), value->header.length);
	total_decoded +=  (value->header.length) * CHAR_SIZE;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_imei_ie(const uint8_t *buf, gtpv1_imei_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));

	uint16_t decoded = 0;
	value->imei_sv = decode_bits(buf, total_decoded, 64, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_traffic_flow_tmpl_ie(const uint8_t *buf, gtpv1_traffic_flow_tmpl_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));

	uint16_t decoded = 0;
	value->tft_op_code = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	value->e_bit = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->no_packet_filters = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	if(value->tft_op_code == 5){
		for(uint8_t itr=0; itr<value->no_packet_filters; itr++){
			value->packet_filter_list_del[itr].spare = decode_bits(buf, total_decoded, 4, &decoded);
			total_decoded += decoded;
			value->packet_filter_list_del[itr].filter_id = decode_bits(buf, total_decoded, 4, &decoded);
			total_decoded += decoded;
		}
	} else if(value->tft_op_code == 1 || value->tft_op_code == 3 || value->tft_op_code == 4){
		for(uint8_t itr=0; itr<value->no_packet_filters; itr++){
			value->packet_filter_list_new[itr].spare= decode_bits(buf, total_decoded, 2, &decoded);
			total_decoded += decoded;
			value->packet_filter_list_new[itr].filter_direction = decode_bits(buf, total_decoded, 2, &decoded);
			total_decoded += decoded;
			value->packet_filter_list_new[itr].filter_id = decode_bits(buf, total_decoded, 4, &decoded);
			total_decoded += decoded;
			value->packet_filter_list_new[itr].filter_eval_precedence = decode_bits(buf, total_decoded, 8, &decoded);
			total_decoded += decoded;
			value->packet_filter_list_new[itr].filter_content_length = decode_bits(buf, total_decoded, 8, &decoded);
			total_decoded += decoded;
			for(uint8_t i=0; i<value->packet_filter_list_new[itr].filter_content_length; i++){
				value->packet_filter_list_new[itr].filter_content[i] = decode_bits(buf, total_decoded, 8, &decoded);
				total_decoded += decoded;
			}
		}
	}
	else if(value->tft_op_code == 0){
		return total_decoded/CHAR_SIZE;
	}
	uint16_t rem_len = (value->header.length-(total_decoded/CHAR_SIZE))+3;
	if (value->e_bit == 1){
		for(uint8_t itr=0; itr<rem_len; itr++){
			value->parameters_list[itr].parameter_id = decode_bits(buf, total_decoded, 8, &decoded);
			total_decoded += decoded;
			value->parameters_list[itr].parameter_content_length = decode_bits(buf, total_decoded, 8, &decoded);
			total_decoded += decoded;
			for(uint8_t i=0; i<value->parameters_list[itr].parameter_content_length; i++){
				value->parameters_list[itr].parameter_content[i] = decode_bits(buf, total_decoded, 8, &decoded);
				total_decoded += decoded;
			}
			rem_len = rem_len - value->parameters_list[itr].parameter_content_length - 2;
		}
	}
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_rat_type_ie(const uint8_t *buf, gtpv1_rat_type_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));

	uint16_t decoded = 0;
	value->rat_type = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_reordering_req_ie(const uint8_t *buf, gtpv1_reordering_req_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->spare = decode_bits(buf, total_decoded, 7, &decoded);
	total_decoded += decoded;
	value->reord_req = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_recovery_ie(const uint8_t *buf, gtpv1_recovery_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->restart_counter = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_charging_id_ie(const uint8_t *buf, gtpv1_charging_id_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->chrgng_id_val = decode_bits(buf, total_decoded, 32, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_end_user_address_ie(const uint8_t *buf, gtpv1_end_user_address_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->spare = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->pdp_type_org = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->pdp_type_number = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	if (value->pdp_type_org == 1) {
		total_decoded = decode_pdp_address(buf, &(value->pdp_address), total_decoded, value->header.length-2, value->pdp_type_number);
	}
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_protocol_config_options_ie(const uint8_t *buf, gtpv1_protocol_config_options_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;
	value->pco.pco_flag_ext = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->pco.pco_flag_spare = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;	
	value->pco.pco_cfg_proto = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;	
	value->pco.pco_content_count = 0;
	int length = value->header.length-1;

	while(length > 0){	
	value->pco.pco_content[value->pco.pco_content_count].prot_or_cont_id = decode_bits(buf, 
				total_decoded, 16, &decoded);
		total_decoded += decoded;
		value->pco.pco_content[value->pco.pco_content_count].length = decode_bits(buf, 
				total_decoded, 8, &decoded);
		total_decoded += decoded;
		memcpy(value->pco.pco_content[value->pco.pco_content_count].content, buf + (total_decoded/CHAR_SIZE), 
				value->pco.pco_content[value->pco.pco_content_count].length);
		total_decoded += value->pco.pco_content[value->pco.pco_content_count].length * 8;
		length -= (value->pco.pco_content[value->pco.pco_content_count].length + 3);
		value->pco.pco_content_count++;
	}

	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_charging_gateway_addr_ie(const uint8_t *buf, gtpv1_charging_gateway_addr_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	if (value->header.length == 4) {
		value->ipv4_addr = decode_bits(buf, total_decoded, 32, &decoded);
		total_decoded += decoded;
	} else if (value->header.length == 16) {
		memcpy(&value->ipv6_addr, buf + (total_decoded/CHAR_SIZE), IPV6_ADDR_LEN);
		total_decoded += IPV6_ADDR_LEN * CHAR_SIZE;
	}
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_common_flag_ie(const uint8_t *buf, gtpv1_common_flag_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->dual_addr_bearer_flag = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->upgrade_qos_supported = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->nrsn = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->no_qos_negotiation = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->mbms_counting_information = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ran_procedures_ready = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->mbms_service_type = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->prohibit_payload_compression = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_apn_restriction_ie(const uint8_t *buf, gtpv1_apn_restriction_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->restriction_type_value = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_ms_info_change_reporting_action_ie(const uint8_t *buf, gtpv1_ms_info_change_reporting_action_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));

	uint16_t decoded = 0;
	value->action = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_bearer_control_mode_ie(const uint8_t *buf, gtpv1_bearer_control_mode_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));

	uint16_t decoded = 0;
	value->bearer_control_mode = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_evolved_allocation_retention_priority_1_ie(const uint8_t *buf, gtpv1_evolved_allocation_retention_priority_1_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));

	uint16_t decoded = 0;
	value->spare = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->pci = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->pl = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->spare2 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->pvi = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_extended_common_flag_ie(const uint8_t *buf, gtpv1_extended_common_flag_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->uasi = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->bdwi = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->pcri = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->vb = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->retloc = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->cpsr = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ccrsi = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->unauthenticated_imsi = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_csg_information_reporting_action_ie(const uint8_t *buf, gtpv1_csg_information_reporting_action_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->spare = decode_bits(buf, total_decoded, 5, &decoded);
	total_decoded += decoded;
	value->ucuhc = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ucshc = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->uccsg = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_apn_ambr_ie(const uint8_t *buf, gtpv1_apn_ambr_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->apn_ambr_uplink = decode_bits(buf, total_decoded, 32, &decoded);
	total_decoded += decoded;
	value->apn_ambr_downlink = decode_bits(buf, total_decoded, 32, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_ggsn_back_off_time_ie(const uint8_t *buf, gtpv1_ggsn_back_off_time_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->timer_unit = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	value->timer_value = decode_bits(buf, total_decoded, 5, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_extended_common_flag_2_ie(const uint8_t *buf, gtpv1_extended_common_flag_2_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->spare = decode_bits(buf, total_decoded, 5, &decoded);
	total_decoded += decoded;
	value->pmts_mi = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->dtci = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->pnsi = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_private_extension_ie(const uint8_t *buf, gtpv1_private_extension_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->extension_identifier = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;
	memcpy(&value->extension_value, buf + (total_decoded/CHAR_SIZE), value->header.length-2);
	total_decoded +=  (value->header.length-2) * CHAR_SIZE;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_routing_area_identity_value(const uint8_t *buf, gtpv1_routing_area_identity_value_t *value, uint16_t total_decoded) {

	uint16_t decoded = 0;

	value->mcc_digit_2 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->mcc_digit_1 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->mnc_digit_3 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->mcc_digit_3 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->mnc_digit_2 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->mnc_digit_1 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->lac = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;
	value->rac = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;

	if(value->mnc_digit_3 == 0xf) {
		value->mnc_digit_3 = value->mnc_digit_2;
		value->mnc_digit_2 = value->mnc_digit_1;
		value->mnc_digit_1 = 0;
	}

	return total_decoded;
}

int16_t decode_gtpv1_routing_area_identity_ie(const uint8_t *buf, gtpv1_routing_area_identity_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	total_decoded = decode_routing_area_identity_value(buf, &(value->rai_value), total_decoded);
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_trace_reference_ie(const uint8_t *buf, gtpv1_trace_reference_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->trace_reference = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_trace_type_ie(const uint8_t *buf, gtpv1_trace_type_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->trace_type = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_trigger_id_ie(const uint8_t *buf, gtpv1_trigger_id_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));

	memcpy(&value->trigger_id, buf + (total_decoded/CHAR_SIZE), value->header.length);
	total_decoded +=  (value->header.length) * CHAR_SIZE;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_omc_identity_ie(const uint8_t *buf, gtpv1_omc_identity_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;

	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	memcpy(&value->omc_identity, buf + (total_decoded/CHAR_SIZE), value->header.length);
	total_decoded +=  (value->header.length) * CHAR_SIZE;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_user_location_information_ie(const uint8_t *buf, gtpv1_user_location_information_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->geographic_location_type = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	value->mcc_digit_2 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->mcc_digit_1 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->mnc_digit_3 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->mcc_digit_3 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->mnc_digit_2 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->mnc_digit_1 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->lac = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;
	value->ci_sac_rac = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;

	if(value->mnc_digit_3 == 0xf) {
		value->mnc_digit_3 = value->mnc_digit_2;
		value->mnc_digit_2 = value->mnc_digit_1;
		value->mnc_digit_1 = 0;
	}

	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_ms_time_zone_ie(const uint8_t *buf, gtpv1_ms_time_zone_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->time_zone = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	value->spare = decode_bits(buf, total_decoded, 6, &decoded);
	total_decoded += decoded;
	value->daylight_saving_time = decode_bits(buf, total_decoded, 2, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_camel_charging_information_container_ie(const uint8_t *buf, gtpv1_camel_charging_information_container_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));

	memcpy(&value->camel_information_pdp_ie, buf + (total_decoded/CHAR_SIZE), value->header.length);
	total_decoded +=  (value->header.length) * CHAR_SIZE;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_additional_trace_information_ie(const uint8_t *buf, gtpv1_additional_trace_information_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->trace_reference_2 = decode_bits(buf, total_decoded, 24, &decoded);
	total_decoded += decoded;
	value->trace_recording_session_reference = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;
	value->spare1 = decode_bits(buf, total_decoded, 6, &decoded);
	total_decoded += decoded;
	value->triggering_events_in_ggsn_mbms_ctxt = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->triggering_events_in_ggsn_pdp_ctxt = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->trace_depth = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	value->spare2 = decode_bits(buf, total_decoded, 5, &decoded);
	total_decoded += decoded;
	value->list_of_interfaces_in_ggsn_gmb = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->list_of_interfaces_in_ggsn_gi = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->list_of_interfaces_in_ggsn_gn = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->trace_activity_control = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_correlation_id_ie(const uint8_t *buf, gtpv1_correlation_id_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->correlation_id = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_user_csg_information_ie(const uint8_t *buf, gtpv1_user_csg_information_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->mcc_digit_2 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->mcc_digit_1 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->mnc_digit_3 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->mcc_digit_3 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->mnc_digit_2 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->mnc_digit_1 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->spare = decode_bits(buf, total_decoded, 5, &decoded);
	total_decoded += decoded;
	value->csg_id = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	value->csg_id_II = decode_bits(buf, total_decoded, 24, &decoded);
	total_decoded += decoded;
	value->access_mode = decode_bits(buf, total_decoded, 2, &decoded);
	total_decoded += decoded;
	value->spare2 = decode_bits(buf, total_decoded, 5, &decoded);
	total_decoded += decoded;
	value->cmi = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;

	if(value->mnc_digit_3 == 0xf) {
		value->mnc_digit_3 = value->mnc_digit_2;
		value->mnc_digit_2 = value->mnc_digit_1;
		value->mnc_digit_1 = 0;
	}
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_signalling_priority_indication_ie(const uint8_t *buf, gtpv1_signalling_priority_indication_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->spare = decode_bits(buf, total_decoded, 7, &decoded);
	total_decoded += decoded;
	value->lapi = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_cn_operator_selection_entity_ie(const uint8_t *buf, gtpv1_cn_operator_selection_entity_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->spare = decode_bits(buf, total_decoded, 6, &decoded);
	total_decoded += decoded;
	value->selection_entity = decode_bits(buf, total_decoded, 2, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_mapped_ue_usage_type_ie(const uint8_t *buf, gtpv1_mapped_ue_usage_type_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->mapped_ue_usage_type = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_up_function_selection_indication_ie(const uint8_t *buf, gtpv1_up_function_selection_indication_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->spare = decode_bits(buf, total_decoded, 7, &decoded);
	total_decoded += decoded;
	value->dcnr = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_teardown_ind_ie(const uint8_t *buf, gtpv1_teardown_ind_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->spare = decode_bits(buf, total_decoded, 7, &decoded);
	total_decoded += decoded;
	value->teardown_ind = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_uli_timestamp_ie(const uint8_t *buf, gtpv1_uli_timestamp_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->timestamp_value = decode_bits(buf, total_decoded, 32, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_direct_tunnel_flag_ie(const uint8_t *buf, gtpv1_direct_tunnel_flag_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->spare = decode_bits(buf, total_decoded, 5, &decoded);
	total_decoded += decoded;
	value->ei = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->gcsi = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->dti = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_map_cause_ie(const uint8_t *buf, gtpv1_map_cause_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->map_cause_value = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_ms_not_rechable_reason_ie(const uint8_t *buf, gtpv1_ms_not_rechable_reason_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->reason_for_absence = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_temporary_logical_link_identifier_ie(const uint8_t *buf, gtpv1_temporary_logical_link_identifier_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->tlli = decode_bits(buf, total_decoded, 32, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_packet_tmsi_ie(const uint8_t *buf, gtpv1_packet_tmsi_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->p_tmsi= decode_bits(buf, total_decoded, 32, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_p_tmsi_signature_ie(const uint8_t *buf, gtpv1_p_tmsi_signature_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->p_tmsi_signature = decode_bits(buf, total_decoded, 24, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_ms_validated_ie(const uint8_t *buf, gtpv1_ms_validated_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->spare = decode_bits(buf, total_decoded, 7, &decoded);
	total_decoded += decoded;
	value->ms_validated = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_sgsn_number_ie(const uint8_t *buf, gtpv1_sgsn_number_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	memcpy(&value->sgsn_number, buf + (total_decoded/CHAR_SIZE), value->header.length);
	decoded +=  (value->header.length) * CHAR_SIZE;
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_hop_counter_ie(const uint8_t *buf, gtpv1_hop_counter_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->hop_counter = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_rab_context_ie(const uint8_t *buf, gtpv1_rab_context_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->spare = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->nsapi = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->dl_gtp_u_sequence_number = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;
	value->ul_gtp_u_sequence_number = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;
	value->dl_pdcp_sequence_number = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;
	value->ul_pdcp_sequence_number = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_radio_priority_sms_ie(const uint8_t *buf, gtpv1_radio_priority_sms_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->spare = decode_bits(buf, total_decoded, 5, &decoded);
	total_decoded += decoded;
	value->radio_priority_sms = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_radio_priority_ie(const uint8_t *buf, gtpv1_radio_priority_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->nsapi = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->spare = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->radio_priority = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_packet_flow_id_ie(const uint8_t *buf, gtpv1_packet_flow_id_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->spare = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->nsapi = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->packet_flow_id = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_radio_priority_lcs_ie(const uint8_t *buf, gtpv1_radio_priority_lcs_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->spare = decode_bits(buf, total_decoded, 5, &decoded);
	total_decoded += decoded;
	value->radio_priority_lcs = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_used_cipher_value_umts_keys_and_quintuplets(const uint8_t *buf, 
		gtpv1_used_cipher_value_umts_keys_and_quintuplets_t *value, uint16_t total_decoded) {

	uint16_t decoded = 0;
	value->gupii = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ugipai = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->used_gprs_integrity_protection_algo = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	value->ksi = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	total_decoded += SKIP_SEQ_MODE;
	value->no_of_vectors = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	value->used_cipher = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	memcpy(&value->ck, buf + (total_decoded/CHAR_SIZE), CK_LEN);
	total_decoded +=  CK_LEN * CHAR_SIZE;
	memcpy(&value->ik, buf + (total_decoded/CHAR_SIZE), IK_LEN);
	total_decoded +=  IK_LEN * CHAR_SIZE;
	value->quintuplet_length = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;
	for(int i=0; i < value->no_of_vectors; i++) {
		total_decoded = decode_auth_quintuplet_value(buf, &(value->quintuplet[i]), total_decoded);	
	}
	return total_decoded;
}

int16_t decode_gtpv1_gsm_keys_and_triplet(const uint8_t *buf, gtpv1_gsm_key_and_triplet_t *value, uint16_t total_decoded) {

	uint16_t decoded = 0;
	value->spare = decode_bits(buf, total_decoded, 5, &decoded);
	total_decoded += decoded;

	value->cksn = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	total_decoded += SKIP_SEQ_MODE;
	value->no_of_vectors = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	value->used_cipher = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	value->kc = decode_bits(buf, total_decoded, 64, &decoded);
	total_decoded += decoded;
	for(int i=0; i < value->no_of_vectors ; i++) {
		total_decoded = decode_auth_triplet_value(buf, &(value->triplet[i]),
					total_decoded);
	}
	return total_decoded;
}

int16_t decode_gtpv1_umts_keys_and_quintuplets(const uint8_t *buf, gtpv1_umts_keys_and_quintuplets_t *value, uint16_t total_decoded) {

	uint16_t decoded = 0;
	value->gupii = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ugipai = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->used_gprs_integrity_protection_algo = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	value->ksi = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	total_decoded += SKIP_SEQ_MODE;
	value->no_of_vectors = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	value->spare = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	memcpy(&value->ck, buf + (total_decoded/CHAR_SIZE), CK_LEN);
	total_decoded +=  CK_LEN * CHAR_SIZE;
	memcpy(&value->ik, buf + (total_decoded/CHAR_SIZE), IK_LEN);
	total_decoded +=  IK_LEN * CHAR_SIZE;
	value->quintuplet_length = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;
	for(int i=0; i < value->no_of_vectors; i++) {
		total_decoded = decode_auth_quintuplet_value(buf, &(value->quintuplet[i]), total_decoded);
	}
	return total_decoded;
}

int16_t decode_gtpv1_gsm_keys_and_umts_quintuplets(const uint8_t *buf, gtpv1_gsm_keys_and_umts_quintuplets_t *value, uint16_t total_decoded){

	uint16_t decoded = 0;
	value->spare = decode_bits(buf, total_decoded, 5, &decoded);
	total_decoded += decoded;
	value->cksn = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	total_decoded += SKIP_SEQ_MODE;
	value->no_of_vectors = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	value->used_cipher = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	value->kc = decode_bits(buf, total_decoded, 64, &decoded);
	total_decoded += decoded;
	value->quintuplet_length = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;
	for(int i=0; i < value->no_of_vectors; i++) {		
		total_decoded = decode_auth_quintuplet_value(buf, &(value->quintuplet[i]), total_decoded);
	}
	return total_decoded;
}

int16_t decode_ms_network_capability_value(const uint8_t *buf, gtpv1_ms_network_capability_value_t *value, 
						uint16_t total_decoded) {
	uint16_t decoded = 0;
	value->GEA_1 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->sm_capabilities_via_dedicated_channels = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->sm_capabilities_via_gprs_channels = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ucs2_support = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ss_screening_indicator = decode_bits(buf, total_decoded, 2, &decoded);
	total_decoded += decoded;
	value->solsa_capability = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->revision_level_indicator = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->pfc_feature_mode = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->GEA_2 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->GEA_3 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->GEA_4 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->GEA_5 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->GEA_6 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->GEA_7 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->lcs_va_capability = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ps_ge_ut_iu_mode_capability = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ps_ge_ut_s1_mode_capability = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->emm_combined_procedure_capability = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->isr_support = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->srvcc_to_ge_ut_capability = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->epc_capability = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->nf_capability = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ge_network_sharing_capability = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->user_plane_integrity_protection_support = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->GIA_4 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->GIA_5 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->GIA_6 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->GIA_7 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ePCO_ie_indicator = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->restriction_on_use_of_enhanced_coverage_capability = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->dual_connectivity_of_e_ut_with_nr_capability = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	return total_decoded;
}

/*
int16_t decode_gtpv1_mobile_identity_ie(const uint8_t *buf, gtpv1_mobile_identity_ie_t *value, 
						uint16_t total_decoded) {

	uint16_t decoded = 0;
	value->iei = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	value->length = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	total_decoded += 5;
	value->type_of_identity = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded -= 5;
	if(value->type_of_identity == 5) {
		total_decoded += 2;
		value->identity_digit.tmgi_and_optional_mbms_identity.mbms_sess_indic = decode_bits(buf,
						total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->identity_digit.tmgi_and_optional_mbms_identity.mcc_mnc_indic = decode_bits(buf,
						total_decoded, 1, &decoded);
		total_decoded += decoded;
	} else {
		value->identity_digit.identity_digit_1 = decode_bits(buf, total_decoded, 4, &decoded);
		total_decoded += decoded;
	}

	value->odd_even_indic = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->type_of_identity = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;

	if(value->type_of_identity == 5) {
		value->identity.mbms_mnc_mcc_identity.mbms_service_id = decode_bits(buf, total_decoded, 24, &decoded);
		total_decoded += decoded;
		value->identity.mbms_mnc_mcc_identity.mcc_digit_2 = decode_bits(buf, total_decoded, 4, &decoded);
		total_decoded += decoded;
		value->identity.mbms_mnc_mcc_identity.mcc_digit_1 = decode_bits(buf, total_decoded, 4, &decoded);
		total_decoded += decoded;
		value->identity.mbms_mnc_mcc_identity.mnc_digit_3 = decode_bits(buf, total_decoded, 4, &decoded);
		total_decoded += decoded;
		value->identity.mbms_mnc_mcc_identity.mcc_digit_3 = decode_bits(buf, total_decoded, 4, &decoded);
		total_decoded += decoded;
		value->identity.mbms_mnc_mcc_identity.mnc_digit_2 = decode_bits(buf, total_decoded, 4, &decoded);
		total_decoded += decoded;
		value->identity.mbms_mnc_mcc_identity.mnc_digit_1 = decode_bits(buf, total_decoded, 4, &decoded);
		total_decoded += decoded;
		value->identity.mbms_mnc_mcc_identity.mbms_session_identity = decode_bits(buf, total_decoded,
						8, &decoded);
		total_decoded += decoded;
	} else {
		value->identity.identity_digit_p.identity_digit_p_1 = decode_bits(buf, total_decoded, 4, &decoded);
		total_decoded += decoded;
		value->identity.identity_digit_p.identity_digit_p = decode_bits(buf, total_decoded, 4, &decoded);
		total_decoded += decoded;
	}

	return total_decoded; 
}
*/

int16_t decode_gtpv1_mm_context_ie(const uint8_t *buf, gtpv1_mm_context_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;

	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));	
	total_decoded += 8;
	uint16_t decoded = 0;

	value->security_mode = decode_bits(buf, total_decoded, 2, &decoded);
	total_decoded -= 8;
	if(value->security_mode == 0) {
		total_decoded = decode_gtpv1_used_cipher_value_umts_keys_and_quintuplets(buf, 
				&(value->mm_context.used_cipher_value_umts_keys_and_quintuplets), total_decoded);
	} else if(value->security_mode == 1) {
		total_decoded = decode_gtpv1_gsm_keys_and_triplet(buf, 
				&(value->mm_context.gsm_keys_and_triplet), total_decoded);
	} else if(value->security_mode == 2) {
		total_decoded = decode_gtpv1_umts_keys_and_quintuplets(buf, 
				&(value->mm_context.umts_keys_and_quintuplets), total_decoded);
	} else if(value->security_mode == 3) {
		total_decoded = decode_gtpv1_gsm_keys_and_umts_quintuplets(buf, 
				&(value->mm_context.gsm_keys_and_umts_quintuplets), total_decoded);
	}
	value->drx_parameter.split_pg_cycle_code = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	value->drx_parameter.cycle_length = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->drx_parameter.ccch = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->drx_parameter.timer = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	value->ms_network_capability_length = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	total_decoded  = decode_ms_network_capability_value(buf, &(value->ms_network_capability), total_decoded);
	value->container_length = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;
//	total_decoded = decode_gtpv1_mobile_identity_ie(buf, &(value->container), total_decoded);
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_pdp_context_ie(const uint8_t *buf, gtpv1_pdp_context_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->ea = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->vaa = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->asi = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->order = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->nsapi = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->spare = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->sapi = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->qos_sub_length = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	total_decoded = decode_qos(buf, &(value->qos_sub), total_decoded, value->qos_sub_length);
	value->qos_req_length = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	total_decoded = decode_qos(buf, &(value->qos_req), total_decoded, value->qos_req_length);
	value->qos_neg_length = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	total_decoded = decode_qos(buf, &(value->qos_neg), total_decoded, value->qos_neg_length);
	value->sequence_number_down = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;
	value->sequence_number_up = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;
	value->send_npdu_number = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	value->rcv_npdu_number = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	value->uplink_teid_cp = decode_bits(buf, total_decoded, 32, &decoded);
	total_decoded += decoded;
	value->uplink_teid_data1 = decode_bits(buf, total_decoded, 32, &decoded);
	total_decoded += decoded;
	value->pdp_ctxt_identifier = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	value->spare2 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->pdp_type_org = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->pdp_type_number1 = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	value->pdp_address_length1 = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	if (value->pdp_type_org == 1) {
		total_decoded = decode_pdp_address(buf, &(value->pdp_address1), total_decoded, value->pdp_address_length1, value->pdp_type_number1);
	}
	value->ggsn_addr_cp_length = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	total_decoded = decode_gsn_address(buf, &(value->ggsn_addr_cp), total_decoded, value->ggsn_addr_cp_length);
	value->ggsn_addr_ut_length = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	total_decoded = decode_gsn_address(buf, &(value->ggsn_addr_ut), total_decoded, value->ggsn_addr_ut_length);
	value->apn_length = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	memcpy(&value->apn, buf + (total_decoded/CHAR_SIZE), value->apn_length);
	total_decoded +=  (value->apn_length) * CHAR_SIZE;
	value->spare3 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->transaction_identifier1 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->transaction_identifier2 = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	if(value->ea == 1){
		value->pdp_type_number2 = decode_bits(buf, total_decoded, 8, &decoded);
		total_decoded += decoded;
		value->pdp_address_length2 = decode_bits(buf, total_decoded, 8, &decoded);
		total_decoded += decoded;
		total_decoded = decode_pdp_address(buf, &(value->pdp_address2), total_decoded, value->pdp_address_length2, value->pdp_type_number2);
	}
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_pdp_context_prioritization_ie(const uint8_t *buf, gtpv1_pdp_context_prioritization_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;

	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_mbms_ue_context_ie(const uint8_t *buf, gtpv1_mbms_ue_context_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->linked_nsapi = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->spare1 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->uplink_teid_cp = decode_bits(buf, total_decoded, 32, &decoded);
	total_decoded += decoded;
	value->enhanced_nsapi = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	value->spare2 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->pdp_type_org = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->pdp_type_number = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	value->pdp_address_length = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	if (value->pdp_type_org == 1) {
		total_decoded = decode_pdp_address(buf, &(value->pdp_address), total_decoded, value->pdp_address_length, value->pdp_type_number);
	}
	value->ggsn_addr_cp_length = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	total_decoded = decode_gsn_address(buf, &(value->ggsn_addr_cp), total_decoded, value->ggsn_addr_cp_length);
	value->apn_length = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	memcpy(&value->apn, buf + (total_decoded/CHAR_SIZE), value->apn_length);
	total_decoded +=  (value->apn_length) * CHAR_SIZE;
	value->spare3 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->transaction_identifier1 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->transaction_identifier2 = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_rfsp_index_ie(const uint8_t *buf, gtpv1_rfsp_index_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->rfsp_index = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_fqdn_ie(const uint8_t *buf, gtpv1_fqdn_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	memcpy(&value->fqdn, buf + (total_decoded/CHAR_SIZE), value->header.length);
	decoded +=  (value->header.length) * CHAR_SIZE;
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_evolved_allocation_retention_priority_II_ie(
		const uint8_t *buf, gtpv1_evolved_allocation_retention_priority_II_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->spare = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->nsapi = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->spare2 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->pci = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->pl = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->spare3 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->pvi = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_ue_network_capability_ie(const uint8_t *buf, gtpv1_ue_network_capability_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->eea0 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->eea1_128 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->eea2_128 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->eea3_128 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->eea4 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->eea5 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->eea6 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->eea7 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->eia0 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->eia1_128 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->eia2_128 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->eia3_128 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->eia4 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->eia5 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->eia6 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->eia7 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	if(value->header.length > 2) {
		value->uea0 = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->uea1 = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->uea2 = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->uea3 = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->uea4 = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->uea5 = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->uea6 = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->uea7 = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
	}
	if(value->header.length > 3) {
		value->ucs2 = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->uia1 = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->uia2 = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->uia3 = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->uia4 = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->uia5 = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->uia6 = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->uia7 = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
	}
	if(value->header.length > 4) {
		value->prose_dd = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->prose = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->h245_ash = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->acc_csfb = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->lpp = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->lcs = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->srvcc1x = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->nf = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
	}
	if(value->header.length > 5) {
		value->epco = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->hc_cp_ciot = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->erw_opdn = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->s1_udata = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->up_ciot = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->cp_ciot = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->prose_relay = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->prose_dc = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
	}
	if(value->header.length > 6) {
		value->bearers_15 = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->sgc = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->n1mode = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->dcnr = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->cp_backoff = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->restrict_ec = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->v2x_pc5 = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->multiple_drb = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
	}
	if(value->header.length > 7) {
		total_decoded += 3;
		value->v2xnr_pcf = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->up_mt_edt = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->cp_mt_edt = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->wusa = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->racs = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
	}
	if(value->header.length > 8) {
		total_decoded += CHAR_SIZE;
	}
	if(value->header.length > 9) {
		total_decoded += CHAR_SIZE;
	}
	if(value->header.length > 10) {
		total_decoded += CHAR_SIZE;
	}
	if(value->header.length > 11) {
		total_decoded += CHAR_SIZE;
	}
	if(value->header.length > 12) {
		total_decoded += CHAR_SIZE;
	}
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_ue_ambr_ie(const uint8_t *buf, gtpv1_ue_ambr_ie_t *value) {
	
	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->subscribed_ue_ambr_for_uplink = decode_bits(buf, total_decoded, 32, &decoded);
	total_decoded += decoded;
	value->subscribed_ue_ambr_for_downlink = decode_bits(buf, total_decoded, 32, &decoded);
	total_decoded += decoded;

	if(value->header.length > (total_decoded/CHAR_SIZE))
	{
		value->authorized_ue_ambr_for_uplink = decode_bits(buf, total_decoded, 32, &decoded);
		total_decoded += decoded;
	}
	if( value->header.length > (total_decoded/CHAR_SIZE))
	{
		value->authorized_ue_ambr_for_downlink = decode_bits(buf, total_decoded, 32, &decoded);
		total_decoded += decoded;
	}

	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_apn_ambr_with_nsapi_ie(const uint8_t *buf, gtpv1_apn_ambr_with_nsapi_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->spare = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->nsapi = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->authorized_apn_ambr_for_uplink = decode_bits(buf, total_decoded, 32, &decoded);
	total_decoded += decoded;
	value->authorized_apn_ambr_for_downlink = decode_bits(buf, total_decoded, 32, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}
int16_t decode_gtpv1_signalling_priority_indication_with_nsapi_ie(const uint8_t *buf, gtpv1_signalling_priority_indication_with_nsapi_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->spare = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->nsapi = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->spare2 = decode_bits(buf, total_decoded, 7, &decoded);
	total_decoded += decoded;
	value->lapi = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_higher_bitrates_than_16_mbps_flag_ie(const uint8_t *buf, gtpv1_higher_bitrates_than_16_mbps_flag_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;
	
	value->higher_bitrates_than_16_mbps_flag = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_selection_mode_with_nsapi_ie(const uint8_t *buf, gtpv1_selection_mode_with_nsapi_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->spare = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->nsapi = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->spare2 = decode_bits(buf, total_decoded, 6, &decoded);
	total_decoded += decoded;
	value->selection_mode_value = decode_bits(buf, total_decoded, 2, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}
int16_t decode_gtpv1_local_home_network_id_with_nsapi_ie(const uint8_t *buf, gtpv1_local_home_network_id_with_nsapi_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->spare = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->nsapi = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	memcpy(&value->local_home_network_id_with_nsapi, buf + (total_decoded/CHAR_SIZE), value->header.length-1);
	decoded +=  (value->header.length-1) * CHAR_SIZE;
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_ue_usage_type_ie(const uint8_t *buf, gtpv1_ue_usage_type_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->ue_usage_type_value = decode_bits(buf, total_decoded, 32, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_ue_scef_pdn_connection_ie(const uint8_t *buf, gtpv1_ue_scef_pdn_connection_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->apn_length = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	memcpy(&value->apn, buf + (total_decoded/CHAR_SIZE), value->apn_length);
	total_decoded +=  (value->apn_length) * CHAR_SIZE;
	value->spare = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->nsapi = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->scef_id_length = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	memcpy(value->scef_id, buf + (total_decoded/CHAR_SIZE), value->scef_id_length);
	total_decoded +=  (value->scef_id_length) * CHAR_SIZE;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_iov_updates_counter_ie(const uint8_t *buf, gtpv1_iov_updates_counter_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->iov_updates_counter = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_ran_transparent_container_ie(const uint8_t *buf, gtpv1_ran_transparent_container_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));

	memcpy(&value->rtc_field, buf + (total_decoded/CHAR_SIZE), value->header.length);
	total_decoded +=  (value->header.length) * CHAR_SIZE;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_rim_routing_addr_ie(const uint8_t *buf, gtpv1_rim_routing_addr_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));

	memcpy(&value->rim_routing_addr, buf + (total_decoded/CHAR_SIZE), value->header.length);
	total_decoded +=  (value->header.length) * CHAR_SIZE;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_rim_routing_addr_disc_ie(const uint8_t *buf, gtpv1_rim_routing_addr_disc_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->spare = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->discriminator = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_selected_plmn_id_ie(const uint8_t *buf, gtpv1_selected_plmn_id_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->mcc_digit_2 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->mcc_digit_1 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->mnc_digit_1 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->mcc_digit_3 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->mnc_digit_3 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->mnc_digit_2 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;

	if(value->mnc_digit_1 == 0xf) {
		value->mnc_digit_1 = value->mnc_digit_2;
		value->mnc_digit_2 = value->mnc_digit_3;
		value->mnc_digit_3 = 0xf;
	}

	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_mbms_protocol_config_options_ie(const uint8_t *buf, gtpv1_mbms_protocol_config_options_ie_t *value) {
	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));

	memcpy(&value->mbms_protocol_configuration, buf + (total_decoded/CHAR_SIZE), value->header.length);
	total_decoded +=  (value->header.length) * CHAR_SIZE;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_teid_data_2_ie(const uint8_t *buf, gtpv1_teid_data_2_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->spare = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->nsapi = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->teid = decode_bits(buf, total_decoded, 32, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_ranap_cause_ie(const uint8_t *buf, gtpv1_ranap_cause_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->ranap_cause = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_target_identification_ie(const uint8_t *buf, gtpv1_target_identification_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->mcc_digit_2 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->mcc_digit_1 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->mnc_digit_3 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->mcc_digit_3 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->mnc_digit_2 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->mnc_digit_1 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->lac = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;
	value->rac = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	value->rnc_id = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;
	if(value->header.length == 10){
		value->extended_rnc_id = decode_bits(buf, total_decoded, 16, &decoded);
		total_decoded += decoded;
	}
	if(value->mnc_digit_3 == 0xf) {
		value->mnc_digit_3 = value->mnc_digit_2;
		value->mnc_digit_2 = value->mnc_digit_1;
		value->mnc_digit_1 = 0;
	}
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_utran_transparent_container_ie(const uint8_t *buf, gtpv1_utran_transparent_container_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));

	memcpy(&value->utran_transparent_field, buf + (total_decoded/CHAR_SIZE), value->header.length);
	total_decoded +=  (value->header.length) * CHAR_SIZE;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_rab_setup_info_ie(const uint8_t *buf, gtpv1_rab_setup_info_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->spare = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->nsapi = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	if(value->header.length == 1){
		return total_decoded/CHAR_SIZE;
	}
	value->teid = decode_bits(buf, total_decoded, 32, &decoded);
	total_decoded += decoded;
	total_decoded = decode_gsn_address(buf, &(value->rnc_ip_addr), total_decoded, value->header.length-5);
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_bss_container_ie(const uint8_t *buf, gtpv1_bss_container_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));

	memcpy(&value->bss_container, buf + (total_decoded/CHAR_SIZE), value->header.length);
	total_decoded +=  (value->header.length) * CHAR_SIZE;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_cell_identification_ie(const uint8_t *buf, gtpv1_cell_identification_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;
	total_decoded = decode_routing_area_identity_value(buf, &(value->target_cell_id.rai_value), total_decoded);
	value->target_cell_id.cell_identity = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;
	value->source_type = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	if(value->source_type == 0) {
		total_decoded = decode_routing_area_identity_value(buf, &(value->ID.source_cell_id.rai_value), 
										total_decoded);
		value->ID.source_cell_id.cell_identity = decode_bits(buf, total_decoded, 16, &decoded);
		total_decoded += decoded;
	}
	else if(value->source_type == 1) {
		total_decoded = decode_routing_area_identity_value(buf, &(value->ID.rnc_id.rai_value),
										total_decoded);
		total_decoded += 4;
		value->ID.rnc_id.rnc_id_value_1 = decode_bits(buf, total_decoded, 4, &decoded);
		total_decoded += decoded;
		value->ID.rnc_id.rnc_id_value_1 = decode_bits(buf, total_decoded, 8, &decoded);
		total_decoded += decoded;
	}
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_bssgp_cause_ie(const uint8_t *buf, gtpv1_bssgp_cause_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->bssgp_cause = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_list_of_setup_pfcs_ie(const uint8_t *buf, gtpv1_list_of_setup_pfcs_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->list.no_of_pfcs = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	if(value->list.no_of_pfcs < 12){
		for(uint8_t i=0; i<value->list.no_of_pfcs; i++){
			value->list.pfi_list[i].spare = decode_bits(buf, total_decoded, 1, &decoded);
			total_decoded += decoded;
			value->list.pfi_list[i].pfi_value = decode_bits(buf, total_decoded, 7, &decoded);
			total_decoded += decoded;
		}
	}
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_ps_handover_xid_param_ie(const uint8_t *buf, gtpv1_ps_handover_xid_param_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->spare = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->sapi = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->xid_param_length = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	memcpy(&value->xid_param, buf + (total_decoded/CHAR_SIZE), value->header.length - 2);
	total_decoded +=  (value->header.length - 2) * CHAR_SIZE;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_reliable_inter_rat_handover_info_ie(const uint8_t *buf, gtpv1_reliable_inter_rat_handover_info_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->handover_info = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_csg_id_ie(const uint8_t *buf, gtpv1_csg_id_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->spare = decode_bits(buf, total_decoded, 5, &decoded);
	total_decoded += decoded;
	value->csg_id = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	value->csg_id2 = decode_bits(buf, total_decoded, 24, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_csg_membership_indication_ie(const uint8_t *buf, gtpv1_csg_membership_indication_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->spare = decode_bits(buf, total_decoded, 7, &decoded);
	total_decoded += decoded;
	value->cmi = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_additional_mm_ctxt_for_srvcc_ie(const uint8_t *buf, gtpv1_additional_mm_ctxt_for_srvcc_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}	
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->ms_classmark_2.ms_classmark_2_len = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	value->ms_classmark_2.spare1 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_2.rev_level = decode_bits(buf, total_decoded, 2, &decoded);
	total_decoded += decoded;
	value->ms_classmark_2.es_ind = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_2.a5_1 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_2.rf_power_cap = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	value->ms_classmark_2.spare2 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_2.ps_cap = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_2.ss_screen_ind = decode_bits(buf, total_decoded, 2, &decoded);
	total_decoded += decoded;
	value->ms_classmark_2.sm_cap = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_2.vbs = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_2.vgcs = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_2.fc = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_2.cm3 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_2.spare3 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_2.lcsvacap = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_2.ucs2 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_2.solsa = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_2.cmsp = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_2.a5_3 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_2.a5_2 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;

	value->ms_classmark_3.ms_classmark_3_len = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	value->ms_classmark_3.spare1 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_3.mult_band_supp = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	if(value->ms_classmark_3.mult_band_supp == 0){
		value->ms_classmark_3.a5_bits = decode_bits(buf, total_decoded, 4, &decoded);
		total_decoded += decoded;
	} else if (value->ms_classmark_3.mult_band_supp == 5 || value->ms_classmark_3.mult_band_supp == 6){
		value->ms_classmark_3.a5_bits = decode_bits(buf, total_decoded, 4, &decoded);
		total_decoded += decoded;
		value->ms_classmark_3.assoc_radio_cap_2 = decode_bits(buf, total_decoded, 4, &decoded);
		total_decoded += decoded;
		value->ms_classmark_3.assoc_radio_cap_1 = decode_bits(buf, total_decoded, 4, &decoded);
		total_decoded += decoded;
	} else if (value->ms_classmark_3.mult_band_supp == 1 || value->ms_classmark_3.mult_band_supp == 2 || value->ms_classmark_3.mult_band_supp == 4){
		value->ms_classmark_3.a5_bits = decode_bits(buf, total_decoded, 4, &decoded);
		total_decoded += decoded;
		value->ms_classmark_3.spare2 = decode_bits(buf, total_decoded, 4, &decoded);
		total_decoded += decoded;
		value->ms_classmark_3.assoc_radio_cap_1 = decode_bits(buf, total_decoded, 4, &decoded);
		total_decoded += decoded;
	}
	value->ms_classmark_3.r_support = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	if(value->ms_classmark_3.r_support){
		value->ms_classmark_3.r_gsm_assoc_radio_cap = decode_bits(buf, total_decoded, 3, &decoded);
		total_decoded += decoded;
	}
	value->ms_classmark_3.hscsd_mult_slot_cap = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	if(value->ms_classmark_3.hscsd_mult_slot_cap){
		value->ms_classmark_3.hscsd_mult_slot_class = decode_bits(buf, total_decoded, 5, &decoded);
		total_decoded += decoded;
	}
	value->ms_classmark_3.ucs2_treatment = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_3.extended_meas_cap = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_3.ms_meas_cap = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	if(value->ms_classmark_3.ms_meas_cap){
		value->ms_classmark_3.sms_value = decode_bits(buf, total_decoded, 4, &decoded);
		total_decoded += decoded;
		value->ms_classmark_3.sm_value = decode_bits(buf, total_decoded, 4, &decoded);
		total_decoded += decoded;
	}
	value->ms_classmark_3.ms_pos_method_cap = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	if(value->ms_classmark_3.ms_pos_method_cap){
		value->ms_classmark_3.ms_pos_method = decode_bits(buf, total_decoded, 5, &decoded);
		total_decoded += decoded;
	}
	value->ms_classmark_3.ecsd_multislot_cap = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	if(value->ms_classmark_3.ecsd_multislot_cap){
		value->ms_classmark_3.ecsd_multislot_class = decode_bits(buf, total_decoded, 5, &decoded);
		total_decoded += decoded;
	}
	value->ms_classmark_3.psk8_struct = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	if(value->ms_classmark_3.psk8_struct){
		value->ms_classmark_3.mod_cap = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->ms_classmark_3.rf_pwr_cap_1 = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		if(value->ms_classmark_3.rf_pwr_cap_1){
			value->ms_classmark_3.rf_pwr_cap_1_val = decode_bits(buf, total_decoded, 2, &decoded);
			total_decoded += decoded;
		}
		value->ms_classmark_3.rf_pwr_cap_2 = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		if(value->ms_classmark_3.rf_pwr_cap_2){
			value->ms_classmark_3.rf_pwr_cap_2_val = decode_bits(buf, total_decoded, 2, &decoded);
			total_decoded += decoded;
		}
	}
	value->ms_classmark_3.gsm_400_bands_supp = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	if(value->ms_classmark_3.gsm_400_bands_supp){
		value->ms_classmark_3.gsm_400_bands_val = decode_bits(buf, total_decoded, 2, &decoded);
		total_decoded += decoded;
		value->ms_classmark_3.gsm_400_assoc_radio_cap = decode_bits(buf, total_decoded, 4, &decoded);
		total_decoded += decoded;
	}
	value->ms_classmark_3.gsm_850_assoc_radio_cap = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	if(value->ms_classmark_3.gsm_850_assoc_radio_cap){
		value->ms_classmark_3.gsm_850_assoc_radio_cap_val = decode_bits(buf, total_decoded, 4, &decoded);
		total_decoded += decoded;
	}
	value->ms_classmark_3.gsm_1900_assoc_radio_cap = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	if(value->ms_classmark_3.gsm_1900_assoc_radio_cap){
		value->ms_classmark_3.gsm_1900_assoc_radio_cap_val = decode_bits(buf, total_decoded, 4, &decoded);
		total_decoded += decoded;
	}
	value->ms_classmark_3.umts_fdd_rat_cap = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_3.umts_tdd_rat_cap = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_3.cdma2000_rat_cap = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_3.dtm_gprs_multislot_class = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	if(value->ms_classmark_3.dtm_gprs_multislot_class){
		value->ms_classmark_3.dtm_gprs_multislot_val = decode_bits(buf, total_decoded, 2, &decoded);
		total_decoded += decoded;
		value->ms_classmark_3.single_slot_dtm = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->ms_classmark_3.dtm_egprs_multislot_class = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		if(value->ms_classmark_3.dtm_egprs_multislot_class){
			value->ms_classmark_3.dtm_egprs_multislot_val = decode_bits(buf, total_decoded, 2, &decoded);
			total_decoded += decoded;
		}
	}
	value->ms_classmark_3.single_band_supp = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	if(value->ms_classmark_3.single_band_supp){
		value->ms_classmark_3.single_band_supp_val = decode_bits(buf, total_decoded, 4, &decoded);
		total_decoded += decoded;
	}
	value->ms_classmark_3.gsm_750_assoc_radio_cap = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	if(value->ms_classmark_3.gsm_750_assoc_radio_cap){
		value->ms_classmark_3.gsm_750_assoc_radio_cap_val = decode_bits(buf, total_decoded, 4, &decoded);
		total_decoded += decoded;
	}
	value->ms_classmark_3.umts_1_28_mcps_tdd_rat_cap = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_3.geran_feature_package = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_3.ext_dtm_gprs_multislot_class = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	if(value->ms_classmark_3.ext_dtm_gprs_multislot_class){
		value->ms_classmark_3.ext_dtm_gprs_multislot_val = decode_bits(buf, total_decoded, 2, &decoded);
		total_decoded += decoded;
		value->ms_classmark_3.ext_dtm_egprs_multislot_val = decode_bits(buf, total_decoded, 2, &decoded);
		total_decoded += decoded;
	}
	value->ms_classmark_3.high_multislot_cap = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	if(value->ms_classmark_3.high_multislot_cap){
		value->ms_classmark_3.high_multislot_val = decode_bits(buf, total_decoded, 2, &decoded);
		total_decoded += decoded;
	}
	value->ms_classmark_3.geran_iu_mode_supp = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_3.geran_feature_package_2 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_3.gmsk_multislot_power_prof = decode_bits(buf, total_decoded, 2, &decoded);
	total_decoded += decoded;
	value->ms_classmark_3.psk8_multislot_power_prof = decode_bits(buf, total_decoded, 2, &decoded);
	total_decoded += decoded;
	value->ms_classmark_3.t_gsm_400_bands_supp = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	if(value->ms_classmark_3.t_gsm_400_bands_supp){
		value->ms_classmark_3.t_gsm_400_bands_val = decode_bits(buf, total_decoded, 2, &decoded);
		total_decoded += decoded;
		value->ms_classmark_3.t_gsm_400_assoc_radio_cap = decode_bits(buf, total_decoded, 4, &decoded);
		total_decoded += decoded;
	}
	value->ms_classmark_3.t_gsm_900_assoc_radio_cap = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_3.dl_advanced_rx_perf = decode_bits(buf, total_decoded, 2, &decoded);
	total_decoded += decoded;
	value->ms_classmark_3.dtm_enhancements_cap = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_3.dtm_gprs_high_multislot_cap = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	if(value->ms_classmark_3.dtm_gprs_high_multislot_cap){
		value->ms_classmark_3.dtm_gprs_high_multislot_val = decode_bits(buf, total_decoded, 3, &decoded);
		total_decoded += decoded;
		value->ms_classmark_3.offset_required = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->ms_classmark_3.dtm_egprs_high_multislot_cap = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		if(value->ms_classmark_3.dtm_egprs_high_multislot_cap){
			value->ms_classmark_3.dtm_egprs_high_multislot_val = decode_bits(buf, total_decoded, 3, &decoded);
			total_decoded += decoded;
		}
	}
	value->ms_classmark_3.repeated_acch_capability = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_3.gsm_710_assoc_radio_cap = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	if(value->ms_classmark_3.gsm_710_assoc_radio_cap){
		value->ms_classmark_3.gsm_710_assoc_radio_val = decode_bits(buf, total_decoded, 4, &decoded);
		total_decoded += decoded;
	}
	value->ms_classmark_3.t_gsm_810_assoc_radio_cap = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	if(value->ms_classmark_3.t_gsm_810_assoc_radio_cap){
		value->ms_classmark_3.t_gsm_810_assoc_radio_val = decode_bits(buf, total_decoded, 4, &decoded);
		total_decoded += decoded;
	}
	value->ms_classmark_3.ciphering_mode_setting_cap = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_3.add_pos_cap = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_3.e_utra_fdd_supp = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_3.e_utra_tdd_supp = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_3.e_utra_meas_rep_supp = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_3.prio_resel_supp = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_3.utra_csg_cells_rep = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_3.vamos_level = decode_bits(buf, total_decoded, 2, &decoded);
	total_decoded += decoded;
	value->ms_classmark_3.tighter_capability = decode_bits(buf, total_decoded, 2, &decoded);
	total_decoded += decoded;
	value->ms_classmark_3.sel_ciph_dl_sacch = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_3.cs_ps_srvcc_geran_utra = decode_bits(buf, total_decoded, 2, &decoded);
	total_decoded += decoded;
	value->ms_classmark_3.cs_ps_srvcc_geran_eutra = decode_bits(buf, total_decoded, 2, &decoded);
	total_decoded += decoded;
	value->ms_classmark_3.geran_net_sharing = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_3.e_utra_wb_rsrq_meas_supp = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_3.er_band_support = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_3.utra_mult_band_ind_supp = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_3.e_utra_mult_band_ind_supp = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_3.extended_tsc_set_cap_supp = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_3.extended_earfcn_val_range = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ms_classmark_3.spare3 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;

	value->sup_codec_list_len = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	uint8_t length_rem = value->sup_codec_list_len;
	uint8_t itr = 0;
	while(length_rem > 0){
		value->sup_codec_list[itr].sysid = decode_bits(buf, total_decoded, 8, &decoded);
		total_decoded += decoded;
		value->sup_codec_list[itr].len_bitmap_sysid = decode_bits(buf, total_decoded, 8, &decoded);
		total_decoded += decoded;
		if(value->sup_codec_list[itr].len_bitmap_sysid == 1){
			value->sup_codec_list[itr].codec_bitmap_1_8 = decode_bits(buf, total_decoded, 8, &decoded);
			total_decoded += decoded;
		} else if (value->sup_codec_list[itr].len_bitmap_sysid > 1){
			value->sup_codec_list[itr].codec_bitmap_1_8 = decode_bits(buf, total_decoded, 8, &decoded);
			total_decoded += decoded;
			value->sup_codec_list[itr].codec_bitmap_9_16 = decode_bits(buf, total_decoded, 8, &decoded);
			total_decoded += decoded;
		}
		length_rem -= (value->sup_codec_list[itr].len_bitmap_sysid + 2);
		itr++;
	}
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_additional_flags_for_srvcc_ie(const uint8_t *buf, gtpv1_additional_flags_for_srvcc_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->spare = decode_bits(buf, total_decoded, 7, &decoded);
	total_decoded += decoded;
	value->ics = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_stn_sr_ie(const uint8_t *buf, gtpv1_stn_sr_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}	
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->nanpi = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	for(uint8_t i=0; i<value->header.length-1; i++){
		value->digits[i].digit1 = decode_bits(buf, total_decoded, 4, &decoded);
		total_decoded += decoded;
		value->digits[i].digit2 = decode_bits(buf, total_decoded, 4, &decoded);
		total_decoded += decoded;
	}
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_c_msisdn_ie(const uint8_t *buf, gtpv1_c_msisdn_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));

	memcpy(&value->msisdn, buf + (total_decoded/CHAR_SIZE), value->header.length);
	total_decoded +=  (value->header.length) * CHAR_SIZE;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_extended_ranap_cause_ie(const uint8_t *buf, gtpv1_extended_ranap_cause_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->extended_ranap_cause = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_enodeb_id_ie(const uint8_t *buf, gtpv1_enodeb_id_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->enodeb_type = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	value->mcc_digit_2 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->mcc_digit_1 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->mnc_digit_3 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->mcc_digit_3 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->mnc_digit_2 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->mnc_digit_1 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	if(value->mnc_digit_3 == 0xf) {
		value->mnc_digit_3 = value->mnc_digit_2;
		value->mnc_digit_2 = value->mnc_digit_1;
		value->mnc_digit_1 = 0;
	}
	value->spare = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	if(value->enodeb_type == 0){
		value->macro_enodeb_id = decode_bits(buf, total_decoded, 4, &decoded);
		total_decoded += decoded;
		value->macro_enodeb_id2 = decode_bits(buf, total_decoded, 16, &decoded);
		total_decoded += decoded;
	}
	if(value->enodeb_type == 1){
		value->home_enodeb_id = decode_bits(buf, total_decoded, 4, &decoded);
		total_decoded += decoded;
		value->home_enodeb_id2 = decode_bits(buf, total_decoded, 24, &decoded);
		total_decoded += decoded;
	}
	value->tac = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_node_identifier_ie(const uint8_t *buf, gtpv1_node_identifier_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->len_of_node_name = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	memcpy(&value->node_name, buf + (total_decoded/CHAR_SIZE), value->len_of_node_name);
	total_decoded +=  (value->len_of_node_name) * CHAR_SIZE;
	value->len_of_node_realm = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	memcpy(&value->node_realm, buf + (total_decoded/CHAR_SIZE), value->len_of_node_realm);
	total_decoded +=  (value->len_of_node_realm) * CHAR_SIZE;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_auth_triplet_value(const uint8_t *buf, gtpv1_auth_triplet_value_t *value, uint16_t total_decoded) {
	
	uint16_t decoded = 0;
	memcpy(&value->rand, buf + (total_decoded/CHAR_SIZE), RAND_LEN);
	total_decoded +=  RAND_LEN * CHAR_SIZE;
	value->sres = decode_bits(buf, total_decoded, 32, &decoded);
	total_decoded += decoded;
	value->kc = decode_bits(buf, total_decoded, 64, &decoded);
	total_decoded += decoded;
	return total_decoded;
}

int16_t decode_gtpv1_auth_triplet_ie(const uint8_t *buf, gtpv1_auth_triplet_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	total_decoded = decode_auth_triplet_value(buf, &(value->auth_triplet_value), total_decoded);
	return total_decoded/CHAR_SIZE;
}

int16_t decode_auth_quintuplet_value(const uint8_t *buf, gtpv1_auth_quintuplet_value_t *value, uint16_t total_decoded) {

	uint16_t decoded = 0;
	memcpy(&value->rand, buf + (total_decoded/CHAR_SIZE), RAND_LEN);
	total_decoded +=  RAND_LEN * CHAR_SIZE;
	value->xres_length = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	memcpy(&value->xres, buf + (total_decoded/CHAR_SIZE), value->xres_length);
	total_decoded +=  value->xres_length * CHAR_SIZE;
	memcpy(&value->ck, buf + (total_decoded/CHAR_SIZE), CK_LEN);
	total_decoded +=  CK_LEN * CHAR_SIZE;
	memcpy(&value->ik, buf + (total_decoded/CHAR_SIZE), IK_LEN);
	total_decoded +=  IK_LEN * CHAR_SIZE;
	value->autn_length = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	memcpy(&value->autn, buf + (total_decoded/CHAR_SIZE), value->autn_length);
	total_decoded +=  value->autn_length * CHAR_SIZE;
	return total_decoded;
}

int16_t decode_gtpv1_auth_quintuplet_ie(const uint8_t *buf, gtpv1_auth_quintuplet_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	total_decoded  = decode_auth_quintuplet_value(buf, &(value->auth_quintuplet_value), total_decoded);
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_src_rnc_pdcp_ctxt_info_ie(const uint8_t *buf, gtpv1_src_rnc_pdcp_ctxt_info_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));

	memcpy(&value->rrc_container, buf + (total_decoded/CHAR_SIZE), value->header.length);
	total_decoded +=  (value->header.length) * CHAR_SIZE;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_pdu_numbers_ie(const uint8_t *buf, gtpv1_pdu_numbers_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	total_decoded += decode_gtpv1_ie_header(buf, &(value->header));
	uint16_t decoded = 0;

	value->spare = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->nsapi = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->dl_gtpu_seqn_nbr = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;
	value->ul_gtpu_seqn_nbr = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;
	value->snd_npdu_nbr = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;
	value->rcv_npdu_nbr = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

int16_t decode_gtpv1_extension_header_type_list_ie(const uint8_t *buf, gtpv1_extension_header_type_list_ie_t *value) {

	if(buf == NULL || value == NULL){
		return -1;
	}
	uint16_t total_decoded = 0;
	uint16_t decoded = 0;
	value->type = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	value->length = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	for(uint8_t i=0; i<value->length; i++){
		value->extension_type_list[i] = decode_bits(buf, total_decoded, 8, &decoded);
		total_decoded += decoded;
	}
	return total_decoded/CHAR_SIZE;
}

