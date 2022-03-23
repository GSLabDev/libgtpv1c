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

#include "../include/gtpv1_ies_encoder.h"

int16_t encode_gtpv1_header(const  gtpv1_header_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_bits(value->version, 3, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->protocol_type, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->spare, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->extension_header, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->seq_num_flag, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->n_pdu_flag, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);

	encoded += encode_bits(value->message_type, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->message_len, 16, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->teid, 32, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);

	if (value->seq_num_flag || value->n_pdu_flag || value->extension_header)
	{
		encoded += encode_bits(value->seq, 16, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->n_pdu_number, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->next_extension_header_type, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_ie_header(const gtpv1_ie_header_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_bits(value->type, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	if ( (value->type >> 7) == 1)
	{
		encoded += encode_bits(value->length, 16, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	return encoded;
}

void encode_imsi(uint64_t val, int len, uint8_t *imsi) {
	uint8_t buf[32] = {0};
	snprintf((char *)buf, 32, "%" PRIu64, val);

	for (int i=0; i<len; i++)
		imsi[i] = ((buf[i*2 + 1] & 0xF) << 4) | ((buf[i*2] & 0xF));

	uint8_t odd = strlen((char *)buf)%2;
	if (odd)
		imsi[len -1] = (0xF << 4) | ((buf[(len-1)*2] & 0xF));
	return;
}

int16_t encode_gtpv1_imsi_ie(const gtpv1_imsi_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encode_imsi(value->imsi_number_digits, 8, buf + (encoded/CHAR_SIZE));
	encoded += sizeof(uint64_t) * CHAR_SIZE;
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_selection_mode_ie(const gtpv1_selection_mode_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare2, 6, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->selec_mode, 2, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_teid_ie(const gtpv1_teid_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->teid, 32, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_nsapi_ie(const gtpv1_nsapi_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->nsapi_value, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_chrgng_char_ie(const gtpv1_chrgng_char_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->chrgng_char_val, 16, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_end_user_address_ie(const gtpv1_end_user_address_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->pdp_type_org, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->pdp_type_number, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	if (value->pdp_type_org == 1) {
		encoded = encode_pdp_address(&value->pdp_address, buf, encoded, value->header.length-2, value->pdp_type_number);
	}
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_apn_ie(const gtpv1_apn_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	memcpy(buf + (encoded/CHAR_SIZE), &value->apn_value, value->header.length);
	encoded += (value->header.length) * CHAR_SIZE ;
	return encoded/CHAR_SIZE;
}

int16_t encode_pdp_address(const gtpv1_pdp_addr_t *value, uint8_t *buf, uint16_t encoded, uint16_t length, uint8_t number){
	if (number == 0x21 && length == 4){
		encoded += encode_bits(value->ipv4, 32, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	} else if (number == 0x57 && length == 16){
		memcpy(buf + (encoded/CHAR_SIZE), &value->ipv6, IPV6_ADDR_LEN);
		encoded += IPV6_ADDR_LEN * CHAR_SIZE ;
	} else if (number == 0x8D){
		if (length == 4) {
			encoded += encode_bits(value->ipv4, 32, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		} else if (length == 16) {
			memcpy(buf + (encoded/CHAR_SIZE), &value->ipv6, IPV6_ADDR_LEN);
			encoded += IPV6_ADDR_LEN * CHAR_SIZE ;
		} else if (length == 20) {
			encoded += encode_bits(value->ipv4, 32, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
			memcpy(buf + (encoded/CHAR_SIZE), &value->ipv6, IPV6_ADDR_LEN);
			encoded += IPV6_ADDR_LEN * CHAR_SIZE ;
		}
	} else {
		return 0;
	}
	return encoded;
}

int16_t encode_gsn_address(const gtpv1_gsn_addr_t *value, uint8_t *buf, uint16_t encoded, uint16_t length){
	if(length == 4){
		encoded += encode_bits(value->ipv4, 32, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	} else if (length == 16){
		memcpy(buf + (encoded/CHAR_SIZE), &value->ipv6, IPV6_ADDR_LEN);
		encoded += IPV6_ADDR_LEN * CHAR_SIZE ;
	} else {
		return 0;
	}
	return encoded;
}

int16_t encode_gtpv1_gsn_address_ie(const gtpv1_gsn_addr_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));

	encoded = encode_gsn_address(&value->gsn_address, buf, encoded, value->header.length);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_msisdn_ie(const gtpv1_msisdn_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	memcpy(buf + (encoded/CHAR_SIZE), &value->msisdn_number_digits, value->header.length);
	encoded += (value->header.length) * CHAR_SIZE ;
	return encoded/CHAR_SIZE;
}

int16_t encode_qos(const gtpv1_qos_t *value, uint8_t *buf, uint16_t encoded, uint16_t length) {
	encoded += encode_bits(value->allocation_retention_priority, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->spare1, 2, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->delay_class, 3, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->reliablity_class, 3, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->peak_throughput, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->spare2, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->precedence_class, 3, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->spare3, 3, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mean_throughput, 5, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->traffic_class, 3, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->delivery_order, 2, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->delivery_erroneous_sdu, 3, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->max_sdu_size, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->max_bitrate_uplink, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->max_bitrate_downlink, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->residual_ber, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->sdu_error_ratio, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->transfer_delay, 6, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->traffic_handling_priority, 2, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->guaranteed_bitrate_uplink, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->guaranteed_bitrate_downlink, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->spare4, 3, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->signalling_indication, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->source_statistics_descriptor, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	if (length > 12) {
		encoded += encode_bits(value->max_bitrate_downlink_ext1, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->guaranteed_bitrate_downlink_ext1, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	if (length > 14) {
		encoded += encode_bits(value->max_bitrate_uplink_ext1, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->guaranteed_bitrate_uplink_ext1, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	if (length > 16) {
		encoded += encode_bits(value->max_bitrate_downlink_ext2, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->guaranteed_bitrate_downlink_ext2, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	if (length > 18) {
		encoded += encode_bits(value->max_bitrate_uplink_ext2, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->guaranteed_bitrate_uplink_ext2, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	return encoded;
}

int16_t encode_gtpv1_qos_ie(const gtpv1_qos_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded = encode_qos(&value->qos, buf, encoded, value->header.length);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_traffic_flow_tmpl_ie(const gtpv1_traffic_flow_tmpl_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->tft_op_code, 3, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->e_bit, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->no_packet_filters, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	if(value->tft_op_code == 5){
		for(uint8_t itr=0; itr<value->no_packet_filters; itr++){
			encoded += encode_bits(value->packet_filter_list_del[itr].spare, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
			encoded += encode_bits(value->packet_filter_list_del[itr].filter_id, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		}
	} else if(value->tft_op_code == 1 || value->tft_op_code == 3 || value->tft_op_code == 4){
		for(uint8_t itr=0; itr<value->no_packet_filters; itr++){
			encoded += encode_bits(value->packet_filter_list_new[itr].spare, 2, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
			encoded += encode_bits(value->packet_filter_list_new[itr].filter_direction, 2, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
			encoded += encode_bits(value->packet_filter_list_new[itr].filter_id, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
			encoded += encode_bits(value->packet_filter_list_new[itr].filter_eval_precedence, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
			encoded += encode_bits(value->packet_filter_list_new[itr].filter_content_length, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
			for(uint8_t i=0; i<value->packet_filter_list_new[itr].filter_content_length; i++){
				encoded += encode_bits(value->packet_filter_list_new[itr].filter_content[i], 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
			}
		}
	} else if(value->tft_op_code == 0){
		return encoded/CHAR_SIZE;
	}	
	uint16_t rem_len = (value->header.length-(encoded/CHAR_SIZE))+3;
	if (value->e_bit == 1){
		for(uint8_t itr=0; itr<rem_len; itr++){
			encoded += encode_bits(value->parameters_list[itr].parameter_id, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
			encoded += encode_bits(value->parameters_list[itr].parameter_content_length, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
			for(uint8_t i=0; i<value->parameters_list[itr].parameter_content_length; i++){
				encoded += encode_bits(value->parameters_list[itr].parameter_content[i], 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
			}
			rem_len = rem_len - value->parameters_list[itr].parameter_content_length - 2;
		}
	}
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_imei_ie(const gtpv1_imei_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->imei_sv, 64, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_rat_type_ie(const gtpv1_rat_type_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->rat_type, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_routing_area_identity_value(gtpv1_routing_area_identity_value_t *value, uint8_t *buf, uint16_t encoded) {
	if(value->mnc_digit_1 == 0) {
		value->mnc_digit_1 = value->mnc_digit_2;
		value->mnc_digit_2 = value->mnc_digit_3;
		value->mnc_digit_3 = 0xf;
	}
	encoded += encode_bits(value->mcc_digit_2, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mcc_digit_1, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mnc_digit_3, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mcc_digit_3, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mnc_digit_2, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mnc_digit_1, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->lac, 16, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->rac, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded;
}

int16_t encode_gtpv1_routing_area_identity_ie(gtpv1_routing_area_identity_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded = encode_routing_area_identity_value(&value->rai_value, buf, encoded);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_trace_reference_ie(const gtpv1_trace_reference_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->trace_reference, 16, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_trace_type_ie(const gtpv1_trace_type_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->trace_type, 16, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_trigger_id_ie(const gtpv1_trigger_id_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	memcpy(buf + (encoded/CHAR_SIZE), &value->trigger_id, value->header.length);
	encoded += (value->header.length) * CHAR_SIZE ;
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_omc_identity_ie(const gtpv1_omc_identity_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	memcpy(buf + (encoded/CHAR_SIZE), &value->omc_identity, value->header.length);
	encoded += (value->header.length) * CHAR_SIZE ;
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_user_location_information_ie(gtpv1_user_location_information_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));	
	if(value->mnc_digit_1 == 0) {
		value->mnc_digit_1 = value->mnc_digit_2;
		value->mnc_digit_2 = value->mnc_digit_3;
		value->mnc_digit_3 = 0xf;
	}
	encoded += encode_bits(value->geographic_location_type, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mcc_digit_2, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mcc_digit_1, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mnc_digit_3, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mcc_digit_3, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mnc_digit_2, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mnc_digit_1, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->lac, 16, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ci_sac_rac, 16, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_ms_time_zone_ie(const gtpv1_ms_time_zone_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->time_zone, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->spare, 6, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->daylight_saving_time, 2, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_camel_charging_information_container_ie(const gtpv1_camel_charging_information_container_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	memcpy(buf + (encoded/CHAR_SIZE), &value->camel_information_pdp_ie, value->header.length);
	encoded += (value->header.length) * CHAR_SIZE ;
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_additional_trace_information_ie(const gtpv1_additional_trace_information_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->trace_reference_2, 24, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->trace_recording_session_reference, 16, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->spare1, 6, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->triggering_events_in_ggsn_mbms_ctxt, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->triggering_events_in_ggsn_pdp_ctxt, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->trace_depth, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->spare2, 5, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->list_of_interfaces_in_ggsn_gmb, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->list_of_interfaces_in_ggsn_gi, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->list_of_interfaces_in_ggsn_gn, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->trace_activity_control, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_correlation_id_ie(const gtpv1_correlation_id_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->correlation_id, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_user_csg_information_ie(gtpv1_user_csg_information_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));	
	if(value->mnc_digit_1 == 0) {
		value->mnc_digit_1 = value->mnc_digit_2;
		value->mnc_digit_2 = value->mnc_digit_3;
		value->mnc_digit_3 = 0xf;
	}
	encoded += encode_bits(value->mcc_digit_2, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mcc_digit_1, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mnc_digit_3, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mcc_digit_3, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mnc_digit_2, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mnc_digit_1, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->spare, 5, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->csg_id, 3, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->csg_id_II, 24, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->access_mode, 2, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->spare2, 5, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->cmi, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_signalling_priority_indication_ie(const gtpv1_signalling_priority_indication_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 7, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->lapi, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_cn_operator_selection_entity_ie(const gtpv1_cn_operator_selection_entity_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 6, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->selection_entity, 2, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_mapped_ue_usage_type_ie(const gtpv1_mapped_ue_usage_type_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->mapped_ue_usage_type, 16, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_up_function_selection_indication_ie(const gtpv1_up_function_selection_indication_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 7, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->dcnr, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_cause_ie(const gtpv1_cause_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->cause_value, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_reordering_req_ie(const gtpv1_reordering_req_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 7, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->reord_req, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_recovery_ie(const gtpv1_recovery_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->restart_counter, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_charging_id_ie(const gtpv1_charging_id_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->chrgng_id_val, 32, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_protocol_config_options_ie(const gtpv1_protocol_config_options_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->pco.pco_flag_ext, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->pco.pco_flag_spare, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->pco.pco_cfg_proto, 3, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	for(int i = 0; i < value->pco.pco_content_count; i++) {
		encoded += encode_bits(value->pco.pco_content[i].prot_or_cont_id, 16, buf + (encoded/CHAR_SIZE), 
				encoded % CHAR_SIZE);
		encoded += encode_bits(value->pco.pco_content[i].length, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		memcpy(buf + (encoded/CHAR_SIZE), value->pco.pco_content[i].content, value->pco.pco_content[i].length);
		encoded += value->pco.pco_content[i].length * CHAR_SIZE;
	}
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_charging_gateway_addr_ie(const gtpv1_charging_gateway_addr_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	if (value->header.length == 4) {
		encoded += encode_bits(value->ipv4_addr, 32, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	} else if (value->header.length == 16) {
		memcpy(buf + (encoded/CHAR_SIZE), &value->ipv6_addr, IPV6_ADDR_LEN);
		encoded += IPV6_ADDR_LEN * CHAR_SIZE ;
	}
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_common_flag_ie(const gtpv1_common_flag_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->dual_addr_bearer_flag, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->upgrade_qos_supported, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->nrsn, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->no_qos_negotiation, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mbms_counting_information, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ran_procedures_ready, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mbms_service_type, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->prohibit_payload_compression, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_apn_restriction_ie(const gtpv1_apn_restriction_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->restriction_type_value, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_ms_info_change_reporting_action_ie(const gtpv1_ms_info_change_reporting_action_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->action, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_bearer_control_mode_ie(const gtpv1_bearer_control_mode_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->bearer_control_mode, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_evolved_allocation_retention_priority_1_ie(const gtpv1_evolved_allocation_retention_priority_1_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->pci, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->pl, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->spare2, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->pvi, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_extended_common_flags_ie(const gtpv1_extended_common_flag_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->uasi, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->bdwi, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->pcri, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->vb, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->retloc, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->cpsr, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ccrsi, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->unauthenticated_imsi, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_csg_information_reporting_action_ie(const gtpv1_csg_information_reporting_action_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 5, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ucuhc, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ucshc, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->uccsg, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_apn_ambr_ie(const gtpv1_apn_ambr_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->apn_ambr_uplink, 32, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->apn_ambr_downlink, 32, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_ggsn_back_off_time_ie(const gtpv1_ggsn_back_off_time_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->timer_unit, 3, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->timer_value, 5, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_extended_common_flag_2_ie(const gtpv1_extended_common_flag_2_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 5, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->pmts_mi, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->dtci, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->pnsi, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_private_extension_ie(const gtpv1_private_extension_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->extension_identifier, 16, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	memcpy(buf + (encoded/CHAR_SIZE), &value->extension_value, value->header.length-2);
	encoded += (value->header.length-2) * CHAR_SIZE ;
	return encoded/CHAR_SIZE; 
	}

int16_t encode_gtpv1_teardown_ind_ie(const gtpv1_teardown_ind_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 7, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->teardown_ind, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_uli_timestamp_ie(const gtpv1_uli_timestamp_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->timestamp_value, 32, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_direct_tunnel_flag_ie(const gtpv1_direct_tunnel_flag_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 5, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ei, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->gcsi, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->dti, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_map_cause_ie(const gtpv1_map_cause_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->map_cause_value, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_ms_not_rechable_reason_ie(const gtpv1_ms_not_rechable_reason_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->reason_for_absence, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_temporary_logical_link_identifier_ie(const gtpv1_temporary_logical_link_identifier_ie_t *value, 
		uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->tlli, 32, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_packet_tmsi_ie(const gtpv1_packet_tmsi_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->p_tmsi, 32, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_p_tmsi_signature_ie(const gtpv1_p_tmsi_signature_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->p_tmsi_signature, 24, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_ms_validated_ie(const gtpv1_ms_validated_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 7, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_validated, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_sgsn_number_ie(const gtpv1_sgsn_number_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	memcpy(buf + (encoded/CHAR_SIZE), &value->sgsn_number, value->header.length);
	encoded += (value->header.length) * CHAR_SIZE ;
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_hop_counter_ie(const gtpv1_hop_counter_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->hop_counter, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_rab_context_ie(const gtpv1_rab_context_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->nsapi, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->dl_gtp_u_sequence_number, 16, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ul_gtp_u_sequence_number, 16, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->dl_pdcp_sequence_number, 16, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ul_pdcp_sequence_number, 16, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_radio_priority_sms_ie(const gtpv1_radio_priority_sms_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 5, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->radio_priority_sms, 3, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_radio_priority_ie(const gtpv1_radio_priority_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->nsapi, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->spare, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->radio_priority, 3, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_packet_flow_id_ie(const gtpv1_packet_flow_id_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->nsapi, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->packet_flow_id, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_radio_priority_lcs_ie(const gtpv1_radio_priority_lcs_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 5, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->radio_priority_lcs, 3, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_used_cipher_value_umts_keys_and_quintuplets(const gtpv1_used_cipher_value_umts_keys_and_quintuplets_t *value, uint8_t *buf, uint16_t encoded, uint8_t seq_mode) {

	encoded += encode_bits(value->gupii, 1,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);	
	encoded += encode_bits(value->ugipai, 1,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);	
	encoded += encode_bits(value->used_gprs_integrity_protection_algo, 3,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);	
	encoded += encode_bits(value->ksi, 3,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);	
	encoded += encode_bits(seq_mode, 2,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->no_of_vectors, 3,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);	
	encoded += encode_bits(value->used_cipher, 3,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);	
	memcpy(buf + (encoded/CHAR_SIZE), &value->ck, CK_LEN);
	encoded += CK_LEN * CHAR_SIZE;
	memcpy(buf + (encoded/CHAR_SIZE), &value->ik, IK_LEN);
	encoded += IK_LEN * CHAR_SIZE;
	encoded += encode_bits(value->quintuplet_length, 16, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);	
	
	for(int i=0; i < value->no_of_vectors; i++) {
		encoded =  encode_auth_quintuplet_value(&value->quintuplet[i], buf, encoded);
	}

	return encoded;
}

int16_t encode_gtpv1_gsm_keys_and_triplet(gtpv1_gsm_key_and_triplet_t *value, uint8_t *buf, uint16_t encoded, uint8_t seq_mode) {

	value->spare = 0xf;
	encoded += encode_bits(value->spare, 5, 
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->cksn, 3, 	
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(seq_mode, 2, 
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->no_of_vectors, 3, 
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->used_cipher, 3, 
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->kc, 64, 
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	
	for(int i=0; i < value->no_of_vectors ; i++) {
		encoded = encode_auth_triplet_value(&value->triplet[i], buf, encoded);
	}
	return encoded;
}

int16_t encode_gtpv1_umts_keys_and_quintuplets(gtpv1_umts_keys_and_quintuplets_t *value, uint8_t *buf,
						uint16_t encoded, uint8_t seq_mode) {

	encoded += encode_bits(value->gupii, 1, 
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);	
	encoded += encode_bits(value->ugipai, 1, 
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);	
	encoded += encode_bits(value->used_gprs_integrity_protection_algo, 3, 
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);	
	encoded += encode_bits(value->ksi, 3, 
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);	
	encoded += encode_bits(seq_mode, 2, 
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->no_of_vectors, 3, 
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	value->spare = 0x7;
	encoded += encode_bits(value->spare, 3, 
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);	
	memcpy(buf + (encoded/CHAR_SIZE), &value->ck, CK_LEN);
	encoded += CK_LEN * CHAR_SIZE;
	memcpy(buf + (encoded/CHAR_SIZE), &value->ik, IK_LEN);
	encoded += IK_LEN * CHAR_SIZE;
	encoded += encode_bits(value->quintuplet_length, 16, 
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);	
	for(int i=0; i < value->no_of_vectors; i++)
	{
		encoded =  encode_auth_quintuplet_value(&value->quintuplet[i], buf, encoded);
	}
	return encoded;
}

int16_t encode_gtpv1_gsm_keys_and_umts_quintuplets(gtpv1_gsm_keys_and_umts_quintuplets_t *value, uint8_t *buf, 
						uint16_t encoded, uint8_t seq_mode) {

	value->spare = 0xf;
	encoded += encode_bits(value->spare, 5, 
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);	
	encoded += encode_bits(value->cksn, 3, 
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);	
	encoded += encode_bits(seq_mode, 2, 
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->no_of_vectors, 3, 
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);	
	encoded += encode_bits(value->used_cipher, 3, 
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);	
	encoded += encode_bits(value->kc, 64, 
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->quintuplet_length, 16,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);

	for(int i=0; i < value->no_of_vectors; i++) {
		encoded =  encode_auth_quintuplet_value(&value->quintuplet[i], buf, encoded);
	}
	return encoded;
}

int16_t encode_ms_network_capability_value(const gtpv1_ms_network_capability_value_t *value, uint8_t *buf, 
						uint16_t encoded) {
	
	encoded += encode_bits(value->GEA_1, 1,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->sm_capabilities_via_dedicated_channels, 1,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->sm_capabilities_via_gprs_channels, 1,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ucs2_support, 1,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ss_screening_indicator, 2,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->solsa_capability, 1,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->revision_level_indicator, 1,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->pfc_feature_mode, 1,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->GEA_2, 1,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->GEA_3, 1,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->GEA_4, 1,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->GEA_5, 1,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->GEA_6, 1,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->GEA_7, 1,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->lcs_va_capability, 1,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ps_ge_ut_iu_mode_capability, 1,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ps_ge_ut_s1_mode_capability, 1,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->emm_combined_procedure_capability, 1,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->isr_support, 1,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->srvcc_to_ge_ut_capability, 1,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->epc_capability, 1,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->nf_capability, 1,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ge_network_sharing_capability, 1,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->user_plane_integrity_protection_support, 1,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->GIA_4, 1,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->GIA_5, 1,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->GIA_6, 1,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->GIA_7, 1,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ePCO_ie_indicator, 1,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->restriction_on_use_of_enhanced_coverage_capability, 1,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->dual_connectivity_of_e_ut_with_nr_capability, 1,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded;
}

/*
int16_t encode_mobile_identity_ie(gtpv1_mobile_identity_ie_t *value, uint8_t *buf, 
						uint16_t encoded) {

	encoded += encode_bits(value->iei, 8,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->length, 8,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	if(value->type_of_identity == 5) {
		encoded += encode_bits(value->identity_digit.tmgi_and_optional_mbms_identity.spare, 2,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->identity_digit.tmgi_and_optional_mbms_identity.mbms_sess_indic, 1,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->identity_digit.tmgi_and_optional_mbms_identity.mcc_mnc_indic, 1,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	} else {
		if(value->type_of_identity == 4) {
			value->identity_digit.identity_digit_1 = 15;
		}
		encoded += encode_bits(value->identity_digit.identity_digit_1, 4,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}

	encoded += encode_bits(value->odd_even_indic, 1,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->type_of_identity, 3,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	
	if(value->type_of_identity == 5) {
		encoded += encode_bits(value->identity.mbms_mnc_mcc_identity.mbms_service_id, 24,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->identity.mbms_mnc_mcc_identity.mcc_digit_2, 4,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->identity.mbms_mnc_mcc_identity.mcc_digit_1, 4,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->identity.mbms_mnc_mcc_identity.mnc_digit_3, 4,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->identity.mbms_mnc_mcc_identity.mcc_digit_3, 4,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->identity.mbms_mnc_mcc_identity.mnc_digit_2, 4,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->identity.mbms_mnc_mcc_identity.mnc_digit_1, 4,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->identity.mbms_mnc_mcc_identity.mbms_session_identity, 8,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	} else  {
		if(value->identity_digit.identity_digit_1 == 3) {
			value->identity.identity_digit_p.identity_digit_p_1 = 15;	
		}

		encoded += encode_bits(value->identity.identity_digit_p.identity_digit_p_1, 4,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->identity.identity_digit_p.identity_digit_p, 4,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	
	return encoded+18;
}
*/


int16_t encode_gtpv1_mm_context_ie(gtpv1_mm_context_ie_t *value, uint8_t *buf) {	

	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));

	if(value->security_mode == 0) {
		encoded = encode_gtpv1_used_cipher_value_umts_keys_and_quintuplets(
				&(value->mm_context.used_cipher_value_umts_keys_and_quintuplets),
				buf, encoded, value->security_mode);
	} else if(value->security_mode == 1) {
		encoded = encode_gtpv1_gsm_keys_and_triplet(&(value->mm_context.gsm_keys_and_triplet),
				buf, encoded, value->security_mode);
	} else if(value->security_mode == 2) {
		encoded = encode_gtpv1_umts_keys_and_quintuplets(&(value->mm_context.umts_keys_and_quintuplets),
				buf, encoded, value->security_mode);
	} else if(value->security_mode == 3) {
		encoded = encode_gtpv1_gsm_keys_and_umts_quintuplets(&(value->mm_context.gsm_keys_and_umts_quintuplets),
				buf, encoded, value->security_mode);
	}

	encoded += encode_bits(value->drx_parameter.split_pg_cycle_code, 8, 
							buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->drx_parameter.cycle_length, 4, 
							buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->drx_parameter.ccch, 1, 
							buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->drx_parameter.timer, 3, 
							buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_network_capability_length, 8, 
							buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded = encode_ms_network_capability_value(&(value->ms_network_capability), buf, encoded);
	encoded += encode_bits(value->container_length, 16,
							buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
//	encoded = encode_mobile_identity_ie(&(value->container), buf, encoded);

	return encoded/CHAR_SIZE;
} 

int16_t encode_gtpv1_pdp_context_ie(const gtpv1_pdp_context_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->ea, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->vaa, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->asi, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->order, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->nsapi, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->spare, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->sapi, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->qos_sub_length, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded = encode_qos(&value->qos_sub, buf, encoded, value->qos_sub_length);
	encoded += encode_bits(value->qos_req_length, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded = encode_qos(&value->qos_req, buf, encoded, value->qos_req_length);
	encoded += encode_bits(value->qos_neg_length, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded = encode_qos(&value->qos_neg, buf, encoded, value->qos_neg_length);
	encoded += encode_bits(value->sequence_number_down, 16, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->sequence_number_up, 16, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->send_npdu_number, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->rcv_npdu_number, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->uplink_teid_cp, 32, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->uplink_teid_data1, 32, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->pdp_ctxt_identifier, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->spare2, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->pdp_type_org, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->pdp_type_number1, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->pdp_address_length1, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	if (value->pdp_type_org == 1) {
		encoded = encode_pdp_address(&value->pdp_address1, buf, encoded, value->pdp_address_length1, value->pdp_type_number1);
	}
	encoded += encode_bits(value->ggsn_addr_cp_length, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded = encode_gsn_address(&value->ggsn_addr_cp, buf, encoded, value->ggsn_addr_cp_length);
	encoded += encode_bits(value->ggsn_addr_ut_length, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded = encode_gsn_address(&value->ggsn_addr_ut, buf, encoded, value->ggsn_addr_ut_length);
	encoded += encode_bits(value->apn_length, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	memcpy(buf + (encoded/CHAR_SIZE), &value->apn, value->apn_length);
	encoded += (value->apn_length) * CHAR_SIZE ;
	encoded += encode_bits(value->spare3, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->transaction_identifier1, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->transaction_identifier2, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	if(value->ea == 1){
		encoded += encode_bits(value->pdp_type_number2, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->pdp_address_length2, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded = encode_pdp_address(&value->pdp_address2, buf, encoded, value->pdp_address_length2, value->pdp_type_number2);
	}
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_pdp_context_prioritization_ie(const gtpv1_pdp_context_prioritization_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_mbms_ue_context_ie(const gtpv1_mbms_ue_context_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->linked_nsapi, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->spare1, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->uplink_teid_cp, 32, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->enhanced_nsapi, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->spare2, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->pdp_type_org, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->pdp_type_number, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->pdp_address_length, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	if (value->pdp_type_org == 1) {
		encoded = encode_pdp_address(&value->pdp_address, buf, encoded, value->pdp_address_length, value->pdp_type_number);
	}
	encoded += encode_bits(value->ggsn_addr_cp_length, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded = encode_gsn_address(&value->ggsn_addr_cp, buf, encoded, value->ggsn_addr_cp_length);
	encoded += encode_bits(value->apn_length, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	memcpy(buf + (encoded/CHAR_SIZE), &value->apn, value->apn_length);
	encoded += (value->apn_length) * CHAR_SIZE ;
	encoded += encode_bits(value->spare3, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->transaction_identifier1, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->transaction_identifier2, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_rfsp_index_ie(const gtpv1_rfsp_index_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->rfsp_index, 16, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_fqdn_ie(const gtpv1_fqdn_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	memcpy(buf + (encoded/CHAR_SIZE), &value->fqdn, value->header.length);
	encoded += (value->header.length) * CHAR_SIZE ;
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_evolved_allocation_retention_priority_II_ie(
		const gtpv1_evolved_allocation_retention_priority_II_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->nsapi, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->spare2, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->pci, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->pl, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->spare3, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->pvi, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_ue_network_capability_ie(const gtpv1_ue_network_capability_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->eea0, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->eea1_128, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->eea2_128, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->eea3_128, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->eea4, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->eea5, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->eea6, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->eea7, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->eia0, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->eia1_128, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->eia2_128, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->eia3_128, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->eia4, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->eia5, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->eia6, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->eia7, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	if(value->header.length > 2) {
		encoded += encode_bits(value->uea0, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->uea1, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->uea2, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->uea3, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->uea4, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->uea5, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->uea6, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->uea7, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	if(value->header.length > 3) {
		encoded += encode_bits(value->ucs2, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->uia1, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->uia2, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->uia3, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->uia4, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->uia5, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->uia6, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->uia7, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	if(value->header.length > 4) {
		encoded += encode_bits(value->prose_dd, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->prose, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->h245_ash, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->acc_csfb, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->lpp, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->lcs, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->srvcc1x, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->nf, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	if(value->header.length > 5) {
		encoded += encode_bits(value->epco, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->hc_cp_ciot, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->erw_opdn, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->s1_udata, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->up_ciot, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->cp_ciot, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->prose_relay, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->prose_dc, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	if(value->header.length > 6) {
		encoded += encode_bits(value->bearers_15, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->sgc, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->n1mode, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->dcnr, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->cp_backoff , 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->restrict_ec, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->v2x_pc5, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->multiple_drb, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	if(value->header.length > 7) {
		encoded += encode_bits(value->spare1, 3, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->v2xnr_pcf, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->up_mt_edt, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->cp_mt_edt, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->wusa, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->racs, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	if(value->header.length > 8) {
		encoded += encode_bits(value->spare2, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	if(value->header.length > 9) {
		encoded += encode_bits(value->spare3, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	if(value->header.length > 10) {
		encoded += encode_bits(value->spare4, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	if(value->header.length > 11) {
		encoded += encode_bits(value->spare5, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	if(value->header.length > 12) {
		encoded += encode_bits(value->spare6, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_ue_ambr_ie(const gtpv1_ue_ambr_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->subscribed_ue_ambr_for_uplink, 32, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->subscribed_ue_ambr_for_downlink, 32, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);

	if(value->authorized_ue_ambr_for_uplink > 0)
	{
		encoded += encode_bits(value->authorized_ue_ambr_for_uplink, 32, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}

	if(value->authorized_ue_ambr_for_downlink > 0 )
	{
		encoded += encode_bits(value->authorized_ue_ambr_for_downlink, 32, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}

	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_apn_ambr_with_nsapi_ie(const gtpv1_apn_ambr_with_nsapi_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->nsapi, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->authorized_apn_ambr_for_uplink, 32, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->authorized_apn_ambr_for_downlink, 32, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_signalling_priority_indication_with_nsapi_ie(
		const gtpv1_signalling_priority_indication_with_nsapi_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->nsapi, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->spare2, 7, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->lapi, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_higher_bitrates_than_16_mbps_flag_ie(const gtpv1_higher_bitrates_than_16_mbps_flag_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->higher_bitrates_than_16_mbps_flag, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_selection_mode_with_nsapi_ie(const gtpv1_selection_mode_with_nsapi_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->nsapi, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->spare2, 6, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->selection_mode_value, 2, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_local_home_network_id_with_nsapi_ie(
		const gtpv1_local_home_network_id_with_nsapi_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->nsapi, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	memcpy(buf + (encoded/CHAR_SIZE), &value->local_home_network_id_with_nsapi, value->header.length-1);
	encoded += (value->header.length - 1) * CHAR_SIZE ;
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_ue_usage_type_ie(const gtpv1_ue_usage_type_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->ue_usage_type_value, 32, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_ue_scef_pdn_connection_ie(const gtpv1_ue_scef_pdn_connection_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->apn_length, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	memcpy(buf + (encoded/CHAR_SIZE), &value->apn, value->apn_length);
	encoded += (value->apn_length) * CHAR_SIZE ;
	encoded += encode_bits(value->spare, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->nsapi, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->scef_id_length, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	memcpy(buf + (encoded/CHAR_SIZE), &value->scef_id, value->scef_id_length);
	encoded += (value->scef_id_length) * CHAR_SIZE ;
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_iov_updates_counter_ie(const gtpv1_iov_updates_counter_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->iov_updates_counter, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_ran_transparent_container_ie(const gtpv1_ran_transparent_container_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	memcpy(buf + (encoded/CHAR_SIZE), &value->rtc_field, value->header.length);
	encoded += (value->header.length) * CHAR_SIZE ;
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_rim_routing_addr_ie(const gtpv1_rim_routing_addr_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	memcpy(buf + (encoded/CHAR_SIZE), &value->rim_routing_addr, value->header.length);
	encoded += (value->header.length) * CHAR_SIZE ;
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_rim_routing_addr_disc_ie(const gtpv1_rim_routing_addr_disc_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->discriminator, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_selected_plmn_id_ie(gtpv1_selected_plmn_id_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	if(value->mnc_digit_1 == 0) {
		value->mnc_digit_1 = 0xf;
	}
	encoded += encode_bits(value->mcc_digit_2, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mcc_digit_1, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mnc_digit_1, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mcc_digit_3, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mnc_digit_3, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mnc_digit_2, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_mbms_protocol_config_options_ie(const gtpv1_mbms_protocol_config_options_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	memcpy(buf + (encoded/CHAR_SIZE), &value->mbms_protocol_configuration, value->header.length);
	encoded += (value->header.length) * CHAR_SIZE ;
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_teid_data_2_ie(const gtpv1_teid_data_2_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->nsapi, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->teid, 32, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_ranap_cause_ie(const gtpv1_ranap_cause_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->ranap_cause, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_target_identification_ie(gtpv1_target_identification_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));

	if(value->mnc_digit_1 == 0) {
		value->mnc_digit_1 = value->mnc_digit_2;
		value->mnc_digit_2 = value->mnc_digit_3;
		value->mnc_digit_3 = 0xf;
	}
	encoded += encode_bits(value->mcc_digit_2, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mcc_digit_1, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mnc_digit_3, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mcc_digit_3, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mnc_digit_2, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mnc_digit_1, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->lac, 16, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->rac, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->rnc_id, 16, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	if(value->header.length == 10){
		encoded += encode_bits(value->extended_rnc_id, 16, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_utran_transparent_container_ie(const gtpv1_utran_transparent_container_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	memcpy(buf + (encoded/CHAR_SIZE), &value->utran_transparent_field, value->header.length);
	encoded += (value->header.length) * CHAR_SIZE ;
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_rab_setup_info_ie(const gtpv1_rab_setup_info_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->nsapi, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	if(value->header.length == 1){
		return encoded/CHAR_SIZE;
	}
	encoded += encode_bits(value->teid, 32, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded = encode_gsn_address(&value->rnc_ip_addr, buf, encoded, value->header.length-5);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_bss_container_ie(const gtpv1_bss_container_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	memcpy(buf + (encoded/CHAR_SIZE), &value->bss_container, value->header.length);
	encoded += (value->header.length) * CHAR_SIZE ;
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_cell_identification_ie(gtpv1_cell_identification_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded  = encode_routing_area_identity_value(&value->target_cell_id.rai_value, buf, encoded);
	encoded += encode_bits(value->target_cell_id.cell_identity, 16, 
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->source_type, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	if(value->source_type == 0) {
		encoded  = encode_routing_area_identity_value(&value->ID.source_cell_id.rai_value, buf, encoded);
		encoded += encode_bits(value->ID.source_cell_id.cell_identity, 16,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	else if(value->source_type == 1) {
		encoded  = encode_routing_area_identity_value(&value->ID.rnc_id.rai_value, buf, encoded);
		encoded += encode_bits(value->ID.rnc_id.spare, 4,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->ID.rnc_id.rnc_id_value_1, 4,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->ID.rnc_id.rnc_id_value_2, 8,
						buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_bssgp_cause_ie(const gtpv1_bssgp_cause_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->bssgp_cause, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_list_of_setup_pfcs_ie(const gtpv1_list_of_setup_pfcs_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->list.no_of_pfcs, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	if(value->list.no_of_pfcs < 12){
		for(uint8_t i=0; i<value->list.no_of_pfcs; i++){
			encoded += encode_bits(value->list.pfi_list[i].spare, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
			encoded += encode_bits(value->list.pfi_list[i].pfi_value, 7, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		}
	}
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_ps_handover_xid_param_ie(const gtpv1_ps_handover_xid_param_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->sapi, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->xid_param_length, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	memcpy(buf + (encoded/CHAR_SIZE), &value->xid_param, value->header.length - 2);
	encoded += (value->header.length - 2) * CHAR_SIZE ;
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_reliable_inter_rat_handover_info_ie(const gtpv1_reliable_inter_rat_handover_info_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->handover_info, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_csg_id_ie(const gtpv1_csg_id_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 5, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->csg_id, 3, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->csg_id2, 24, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_csg_membership_indication_ie(const gtpv1_csg_membership_indication_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 7, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->cmi, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_additional_mm_ctxt_for_srvcc_ie(const gtpv1_additional_mm_ctxt_for_srvcc_ie_t *value, uint8_t *buf){
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->ms_classmark_2.ms_classmark_2_len, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_2.spare1, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_2.rev_level, 2, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_2.es_ind, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_2.a5_1, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_2.rf_power_cap, 3, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_2.spare2, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_2.ps_cap, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_2.ss_screen_ind, 2, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_2.sm_cap, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_2.vbs, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_2.vgcs, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_2.fc, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_2.cm3, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_2.spare3, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_2.lcsvacap, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_2.ucs2, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_2.solsa, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_2.cmsp, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_2.a5_3, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_2.a5_2, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);

	encoded += encode_bits(value->ms_classmark_3.ms_classmark_3_len, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_3.spare1, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_3.mult_band_supp, 3, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	if(value->ms_classmark_3.mult_band_supp == 0){
		encoded += encode_bits(value->ms_classmark_3.a5_bits, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	} else if (value->ms_classmark_3.mult_band_supp == 5 || value->ms_classmark_3.mult_band_supp == 6){
		encoded += encode_bits(value->ms_classmark_3.a5_bits, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->ms_classmark_3.assoc_radio_cap_2, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->ms_classmark_3.assoc_radio_cap_1, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	} else if (value->ms_classmark_3.mult_band_supp == 1 || value->ms_classmark_3.mult_band_supp == 2 || value->ms_classmark_3.mult_band_supp == 4){
		encoded += encode_bits(value->ms_classmark_3.a5_bits, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->ms_classmark_3.spare2, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->ms_classmark_3.assoc_radio_cap_1, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	encoded += encode_bits(value->ms_classmark_3.r_support, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	if(value->ms_classmark_3.r_support){
		encoded += encode_bits(value->ms_classmark_3.r_gsm_assoc_radio_cap, 3, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	encoded += encode_bits(value->ms_classmark_3.hscsd_mult_slot_cap, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	if(value->ms_classmark_3.hscsd_mult_slot_cap){
		encoded += encode_bits(value->ms_classmark_3.hscsd_mult_slot_class, 5, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	encoded += encode_bits(value->ms_classmark_3.ucs2_treatment, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_3.extended_meas_cap, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_3.ms_meas_cap, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	if(value->ms_classmark_3.ms_meas_cap){
		encoded += encode_bits(value->ms_classmark_3.sms_value, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->ms_classmark_3.sm_value, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	encoded += encode_bits(value->ms_classmark_3.ms_pos_method_cap, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	if(value->ms_classmark_3.ms_pos_method_cap){
		encoded += encode_bits(value->ms_classmark_3.ms_pos_method, 5, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	encoded += encode_bits(value->ms_classmark_3.ecsd_multislot_cap, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	if(value->ms_classmark_3.ecsd_multislot_cap){
		encoded += encode_bits(value->ms_classmark_3.ecsd_multislot_class, 5, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	encoded += encode_bits(value->ms_classmark_3.psk8_struct, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	if(value->ms_classmark_3.psk8_struct){
		encoded += encode_bits(value->ms_classmark_3.mod_cap, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->ms_classmark_3.rf_pwr_cap_1, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		if(value->ms_classmark_3.rf_pwr_cap_1){
			encoded += encode_bits(value->ms_classmark_3.rf_pwr_cap_1_val, 2, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		}
		encoded += encode_bits(value->ms_classmark_3.rf_pwr_cap_2, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		if(value->ms_classmark_3.rf_pwr_cap_2){
			encoded += encode_bits(value->ms_classmark_3.rf_pwr_cap_2_val, 2, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		}
	}
	encoded += encode_bits(value->ms_classmark_3.gsm_400_bands_supp, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	if(value->ms_classmark_3.gsm_400_bands_supp){
		encoded += encode_bits(value->ms_classmark_3.gsm_400_bands_val, 2, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->ms_classmark_3.gsm_400_assoc_radio_cap, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	encoded += encode_bits(value->ms_classmark_3.gsm_850_assoc_radio_cap, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	if(value->ms_classmark_3.gsm_850_assoc_radio_cap){
		encoded += encode_bits(value->ms_classmark_3.gsm_850_assoc_radio_cap_val, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	encoded += encode_bits(value->ms_classmark_3.gsm_1900_assoc_radio_cap, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	if(value->ms_classmark_3.gsm_1900_assoc_radio_cap){
		encoded += encode_bits(value->ms_classmark_3.gsm_1900_assoc_radio_cap_val, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	encoded += encode_bits(value->ms_classmark_3.umts_fdd_rat_cap, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_3.umts_tdd_rat_cap, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_3.cdma2000_rat_cap, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_3.dtm_gprs_multislot_class, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	if(value->ms_classmark_3.dtm_gprs_multislot_class){
		encoded += encode_bits(value->ms_classmark_3.dtm_gprs_multislot_val, 2, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->ms_classmark_3.single_slot_dtm, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->ms_classmark_3.dtm_egprs_multislot_class, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		if(value->ms_classmark_3.dtm_egprs_multislot_class){
			encoded += encode_bits(value->ms_classmark_3.dtm_egprs_multislot_val, 2, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		}
	}
	encoded += encode_bits(value->ms_classmark_3.single_band_supp, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	if(value->ms_classmark_3.gsm_850_assoc_radio_cap){
		encoded += encode_bits(value->ms_classmark_3.single_band_supp_val, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	encoded += encode_bits(value->ms_classmark_3.gsm_750_assoc_radio_cap, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	if(value->ms_classmark_3.gsm_1900_assoc_radio_cap){
		encoded += encode_bits(value->ms_classmark_3.gsm_750_assoc_radio_cap_val, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	encoded += encode_bits(value->ms_classmark_3.umts_1_28_mcps_tdd_rat_cap, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_3.geran_feature_package, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_3.ext_dtm_gprs_multislot_class, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	if(value->ms_classmark_3.ext_dtm_gprs_multislot_class){
		encoded += encode_bits(value->ms_classmark_3.ext_dtm_gprs_multislot_val, 2, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->ms_classmark_3.ext_dtm_egprs_multislot_val, 2, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	encoded += encode_bits(value->ms_classmark_3.high_multislot_cap, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	if(value->ms_classmark_3.high_multislot_cap){
		encoded += encode_bits(value->ms_classmark_3.high_multislot_val, 2, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	encoded += encode_bits(value->ms_classmark_3.geran_iu_mode_supp, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_3.geran_feature_package_2, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_3.gmsk_multislot_power_prof, 2, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_3.psk8_multislot_power_prof, 2, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_3.t_gsm_400_bands_supp, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	if(value->ms_classmark_3.t_gsm_400_bands_supp){
		encoded += encode_bits(value->ms_classmark_3.t_gsm_400_bands_val, 2, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->ms_classmark_3.t_gsm_400_assoc_radio_cap, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	encoded += encode_bits(value->ms_classmark_3.t_gsm_900_assoc_radio_cap, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_3.dl_advanced_rx_perf, 2, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_3.dtm_enhancements_cap, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_3.dtm_gprs_high_multislot_cap, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	if(value->ms_classmark_3.dtm_gprs_high_multislot_cap){
		encoded += encode_bits(value->ms_classmark_3.dtm_gprs_high_multislot_val, 3, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->ms_classmark_3.offset_required, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->ms_classmark_3.dtm_egprs_high_multislot_cap, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		if(value->ms_classmark_3.dtm_egprs_high_multislot_cap){
			encoded += encode_bits(value->ms_classmark_3.dtm_egprs_high_multislot_val, 3, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		}
	}
	encoded += encode_bits(value->ms_classmark_3.repeated_acch_capability, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_3.gsm_710_assoc_radio_cap, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	if(value->ms_classmark_3.gsm_710_assoc_radio_cap){
		encoded += encode_bits(value->ms_classmark_3.gsm_710_assoc_radio_val, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	encoded += encode_bits(value->ms_classmark_3.t_gsm_810_assoc_radio_cap, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	if(value->ms_classmark_3.t_gsm_810_assoc_radio_cap){
		encoded += encode_bits(value->ms_classmark_3.t_gsm_810_assoc_radio_val, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	encoded += encode_bits(value->ms_classmark_3.ciphering_mode_setting_cap, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_3.add_pos_cap, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_3.e_utra_fdd_supp, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_3.e_utra_tdd_supp, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_3.e_utra_meas_rep_supp, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_3.prio_resel_supp, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_3.utra_csg_cells_rep, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_3.vamos_level, 2, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_3.tighter_capability, 2, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_3.sel_ciph_dl_sacch, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_3.cs_ps_srvcc_geran_utra, 2, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_3.cs_ps_srvcc_geran_eutra, 2, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_3.geran_net_sharing, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_3.e_utra_wb_rsrq_meas_supp, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_3.er_band_support, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_3.utra_mult_band_ind_supp, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_3.e_utra_mult_band_ind_supp, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_3.extended_tsc_set_cap_supp, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_3.extended_earfcn_val_range, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ms_classmark_3.spare3, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);

	encoded += encode_bits(value->sup_codec_list_len, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	uint8_t length_rem = value->sup_codec_list_len;
	uint8_t itr = 0;
	while(length_rem > 0){
		encoded += encode_bits(value->sup_codec_list[itr].sysid, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->sup_codec_list[itr].len_bitmap_sysid, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		if(value->sup_codec_list[itr].len_bitmap_sysid == 1){
			encoded += encode_bits(value->sup_codec_list[itr].codec_bitmap_1_8, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		} else if (value->sup_codec_list[itr].len_bitmap_sysid > 1){
			encoded += encode_bits(value->sup_codec_list[itr].codec_bitmap_1_8, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
			encoded += encode_bits(value->sup_codec_list[itr].codec_bitmap_9_16, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		}
		length_rem -= (value->sup_codec_list[itr].len_bitmap_sysid + 2);
		itr++;
	}
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_additional_flags_for_srvcc_ie(const gtpv1_additional_flags_for_srvcc_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 7, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ics, 1, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_stn_sr_ie(const gtpv1_stn_sr_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->nanpi, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	for(uint8_t i=0; i<value->header.length-1; i++){
		encoded += encode_bits(value->digits[i].digit1, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->digits[i].digit2, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_c_msisdn_ie(const gtpv1_c_msisdn_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	memcpy(buf + (encoded/CHAR_SIZE), &value->msisdn, value->header.length);
	encoded += (value->header.length) * CHAR_SIZE ;
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_extended_ranap_cause_ie(const gtpv1_extended_ranap_cause_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->extended_ranap_cause, 16, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_enodeb_id_ie(gtpv1_enodeb_id_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	if(value->mnc_digit_1 == 0) {
		value->mnc_digit_1 = value->mnc_digit_2;
		value->mnc_digit_2 = value->mnc_digit_3;
		value->mnc_digit_3 = 0xf;
	}
	encoded += encode_bits(value->enodeb_type, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mcc_digit_2, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mcc_digit_1, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mnc_digit_3, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mcc_digit_3, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mnc_digit_2, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mnc_digit_1, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->spare, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	if(value->enodeb_type == 0){
		encoded += encode_bits(value->macro_enodeb_id, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->macro_enodeb_id2, 16, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	if(value->enodeb_type == 1){
		encoded += encode_bits(value->home_enodeb_id, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
		encoded += encode_bits(value->home_enodeb_id2, 24, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	encoded += encode_bits(value->tac, 16, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_node_identifier_ie(const gtpv1_node_identifier_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->len_of_node_name, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	memcpy(buf + (encoded/CHAR_SIZE), &value->node_name, value->len_of_node_name);
	encoded += (value->len_of_node_name) * CHAR_SIZE ;
	encoded += encode_bits(value->len_of_node_realm, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	memcpy(buf + (encoded/CHAR_SIZE), &value->node_realm, value->len_of_node_realm);
	encoded += (value->len_of_node_realm) * CHAR_SIZE ;
	return encoded/CHAR_SIZE;
}

int16_t encode_auth_triplet_value(const gtpv1_auth_triplet_value_t *value, uint8_t *buf, uint16_t encoded) {
	memcpy(buf + (encoded/CHAR_SIZE), &value->rand, RAND_LEN);
	encoded += RAND_LEN * CHAR_SIZE;
	encoded += encode_bits(value->sres, 32, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->kc, 64, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded;
}

int16_t encode_gtpv1_auth_triplet_ie(const gtpv1_auth_triplet_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded = encode_auth_triplet_value(&value->auth_triplet_value, buf, encoded);
	return encoded/CHAR_SIZE;
}

int16_t encode_auth_quintuplet_value(const gtpv1_auth_quintuplet_value_t *value, uint8_t *buf, uint16_t encoded) {
	
	memcpy(buf + (encoded/CHAR_SIZE), &value->rand, RAND_LEN);
	encoded += RAND_LEN * CHAR_SIZE;
	encoded += encode_bits(value->xres_length, 8, 
				buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);	
	memcpy(buf + (encoded/CHAR_SIZE), &value->xres, value->xres_length);
	encoded += value->xres_length * CHAR_SIZE;
	memcpy(buf + (encoded/CHAR_SIZE), &value->ck, CK_LEN);
	encoded += CK_LEN * CHAR_SIZE;
	memcpy(buf + (encoded/CHAR_SIZE), &value->ik, IK_LEN);
	encoded += IK_LEN * CHAR_SIZE;
	encoded += encode_bits(value->autn_length, 8, 
					buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	memcpy(buf + (encoded/CHAR_SIZE), &value->autn, value->autn_length);
	encoded += value->autn_length * CHAR_SIZE;
	
	return encoded;
}

int16_t encode_gtpv1_auth_quintuplet_ie(const gtpv1_auth_quintuplet_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded  = encode_auth_quintuplet_value(&value->auth_quintuplet_value, buf, encoded);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_src_rnc_pdcp_ctxt_info_ie(const gtpv1_src_rnc_pdcp_ctxt_info_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	memcpy(buf + (encoded/CHAR_SIZE), &value->rrc_container, value->header.length);
	encoded += (value->header.length) * CHAR_SIZE ;
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_pdu_numbers_ie(const gtpv1_pdu_numbers_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_gtpv1_ie_header(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->nsapi, 4, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->dl_gtpu_seqn_nbr, 16, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ul_gtpu_seqn_nbr, 16, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->snd_npdu_nbr, 16, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->rcv_npdu_nbr, 16, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

int16_t encode_gtpv1_extension_header_type_list_ie(const gtpv1_extension_header_type_list_ie_t *value, uint8_t *buf) {
	if(value == NULL || buf == NULL){
		return -1;
	}
	uint16_t encoded = 0;
	encoded += encode_bits(value->type, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	encoded += encode_bits(value->length, 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	for(uint8_t i=0; i<value->length; i++){
		encoded += encode_bits(value->extension_type_list[i], 8, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);
	}
	return encoded/CHAR_SIZE;
}

