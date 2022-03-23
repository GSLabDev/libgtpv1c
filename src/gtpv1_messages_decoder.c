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

#include "../include/gtpv1_messages_decoder.h"

int decode_gtpv1_echo_req(uint8_t *buf, gtpv1_echo_req_t *value){
	
	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0;

	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}
	count = 0;
		
	while (count < buf_len) {
		
		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);

		if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length);
	}

	return count + head_count;
}

int decode_gtpv1_echo_rsp(uint8_t *buf, gtpv1_echo_rsp_t *value){

	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0;

	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}
	count = 0;

	while (count < buf_len) {

		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);

		if (ie_header->type == GTPV1_IE_RECOVERY) {
			count += decode_gtpv1_recovery_ie(buf + count, &value->recovery);
		} else if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length);
	}
	return count + head_count;
}

int decode_gtpv1_version_not_supported(uint8_t *buf, gtpv1_version_not_supported_t *value) {

	uint16_t count = 0;
	
	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);

	return count;
}

int decode_gtpv1_create_pdp_ctxt_req(uint8_t *buf, gtpv1_create_pdp_ctxt_req_t *value) {
	
	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0; 
	
	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}
	
	count = 0;
	uint8_t n_cnt = 0, gsn_cnt = 0;
	
	while (count < buf_len) {
	
		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);
	
		if (ie_header->type == GTPV1_IE_NSAPI && n_cnt == 0) {
			count += decode_gtpv1_nsapi_ie(buf + count, &value->nsapi);
			n_cnt++;
		} else if (ie_header->type == GTPV1_IE_NSAPI && n_cnt == 1) {
			count += decode_gtpv1_nsapi_ie(buf + count, &value->linked_nsapi);
		} else if (ie_header->type == GTPV1_IE_IMSI) {
			count += decode_gtpv1_imsi_ie(buf + count, &value->imsi);
		} else if (ie_header->type == GTPV1_IE_APN) {
			count += decode_gtpv1_apn_ie(buf + count, &value->apn);
		} else if (ie_header->type == GTPV1_IE_TEID_DATA_1) {
			count += decode_gtpv1_teid_ie(buf + count, &value->tunn_endpt_idnt_data_1);
		} else if (ie_header->type == GTPV1_IE_TEID_CONTROL_PLANE) {
			count += decode_gtpv1_teid_ie(buf + count, &value->tunn_endpt_idnt_control_plane);
		} else if (ie_header->type == GTPV1_IE_RAT_TYPE) {
			count += decode_gtpv1_rat_type_ie(buf + count, &value->rat_type);
		} else if (ie_header->type == GTPV1_IE_GSN_ADDR && gsn_cnt == 0) {
			count += decode_gtpv1_gsn_address_ie(buf + count, &value->sgsn_address_for_signalling);
			gsn_cnt++;
		} else if (ie_header->type == GTPV1_IE_GSN_ADDR && gsn_cnt == 1) {
			count += decode_gtpv1_gsn_address_ie(buf + count, &value->sgsn_address_for_user_traffic);
		} else if (ie_header->type == GTPV1_IE_QOS) {
			count += decode_gtpv1_qos_ie(buf + count, &value->qos_profile);
		} else if (ie_header->type == GTPV1_IE_SELECTION_MODE) {
			count += decode_gtpv1_selection_mode_ie(buf + count, &value->selection_mode);
		} else if (ie_header->type == GTPV1_IE_CHRGNG_CHAR) {
			count += decode_gtpv1_chrgng_char_ie(buf + count, &value->chrgng_char);
		} else if (ie_header->type == GTPV1_IE_END_USER_ADDR) {
			count += decode_gtpv1_end_user_address_ie(buf + count, &value->end_user_address);
		} else if (ie_header->type == GTPV1_IE_MSISDN) {
			count += decode_gtpv1_msisdn_ie(buf + count, &value->msisdn);
		} else if (ie_header->type == GTPV1_IE_PROTOCOL_CONFIG_OPTIONS) {
			count += decode_gtpv1_protocol_config_options_ie(buf + count, &value->protocol_config_options);
		} else if (ie_header->type == GTPV1_IE_TFT) {
			count += decode_gtpv1_traffic_flow_tmpl_ie(buf + count, &value->tft);
		} else if (ie_header->type == GTPV1_IE_IMEI_SV) {
			count += decode_gtpv1_imei_ie(buf + count, &value->imei_sv);
		} else if (ie_header->type == GTPV1_IE_ROUTEING_AREA_IDENTITY) {
			count += decode_gtpv1_routing_area_identity_ie(buf + count, &value->routing_area_identity);
		} else if (ie_header->type == GTPV1_IE_TRACE_REFERENCE) {
			count += decode_gtpv1_trace_reference_ie(buf + count, &value->trace_reference);
		} else if (ie_header->type == GTPV1_IE_TRACE_TYPE) {
			count += decode_gtpv1_trace_type_ie(buf + count, &value->trace_type);
		} else if (ie_header->type == GTPV1_IE_TRIGGER_ID) {
			count += decode_gtpv1_trigger_id_ie(buf + count, &value->trigger_id);
		} else if (ie_header->type == GTPV1_IE_OMC_IDENTITY) {
			count += decode_gtpv1_omc_identity_ie(buf + count, &value->omc_identity);
		} else if (ie_header->type == GTPV1_IE_USER_LOCATION_INFORMATION) {
			count += decode_gtpv1_user_location_information_ie(buf + count, &value->user_location_information);
		} else if (ie_header->type == GTPV1_IE_MS_TIME_ZONE) {
			count += decode_gtpv1_ms_time_zone_ie(buf + count, &value->ms_time_zone);
		} else if (ie_header->type == GTPV1_IE_CAMEL_CHARGING_INFORMATION_CONTAINER) {
			count += decode_gtpv1_camel_charging_information_container_ie(buf + count, 
					&value->camel_charging_information_container);
		} else if (ie_header->type == GTPV1_IE_ADDITIONAL_TRACE_INFORMATION) {
			count += decode_gtpv1_additional_trace_information_ie(buf + count, &value->additional_trace_information);
		} else if (ie_header->type == GTPV1_IE_CORRELATION_ID) {
			count += decode_gtpv1_correlation_id_ie(buf + count, &value->correlation_id);
		} else if (ie_header->type == GTPV1_IE_USER_CSG_INFORMATION) {
			count += decode_gtpv1_user_csg_information_ie(buf + count, &value->user_csg_information);
		} else if (ie_header->type == GTPV1_IE_SIGNALLING_PRIORITY_INDICATION) {
			count += decode_gtpv1_signalling_priority_indication_ie(buf + count, 
					&value->signalling_priority_indication);
		} else if (ie_header->type == GTPV1_IE_CN_OPERATOR_SELECTION_ENTITY) {
			count += decode_gtpv1_cn_operator_selection_entity_ie(buf + count, &value->cn_operator_selection_entity);
		} else if (ie_header->type == GTPV1_IE_MAPPED_UE_USAGE_TYPE) {
			count += decode_gtpv1_mapped_ue_usage_type_ie(buf + count, &value->mapped_ue_usage_type);
		} else if (ie_header->type == GTPV1_IE_UP_FUNCTION_SELECTION_INDICATION) {
			count += decode_gtpv1_up_function_selection_indication_ie(buf + count, 
					&value->up_function_selection_indication);
		} else if (ie_header->type == GTPV1_IE_RECOVERY) {
			count += decode_gtpv1_recovery_ie(buf + count, &value->recovery);
		} else if (ie_header->type == GTPV1_IE_COMMON_FLAG) {
			count += decode_gtpv1_common_flag_ie(buf + count, &value->common_flag);
		} else if (ie_header->type == GTPV1_IE_APN_RESTRICTION) {
			count += decode_gtpv1_apn_restriction_ie(buf + count, &value->apn_restriction);
		} else if (ie_header->type == GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_I) {
			count += decode_gtpv1_evolved_allocation_retention_priority_1_ie(buf + count, 
					&value->evolved_allocation_retention_priority_1);
		} else if (ie_header->type == GTPV1_IE_EXTENDED_COMMON_FLAG) {
			count += decode_gtpv1_extended_common_flag_ie(buf + count, &value->extended_common_flag);
		} else if (ie_header->type == GTPV1_IE_APN_AMBR) {
			count += decode_gtpv1_apn_ambr_ie(buf + count, &value->apn_ambr);
		} else if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length);
	}
	return count + head_count;
}

int decode_gtpv1_create_pdp_ctxt_rsp(uint8_t *buf, gtpv1_create_pdp_ctxt_rsp_t *value) {
	
	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0;

	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}
	
	count = 0;
	uint8_t gsn_cnt = 0, charging_cnt = 0;
	
	while (count < buf_len) {

		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);

		if (ie_header->type == GTPV1_IE_CAUSE) {
			count += decode_gtpv1_cause_ie(buf + count, &value->cause);
		} else if (ie_header->type == GTPV1_IE_REORDERING_REQ) {
			count += decode_gtpv1_reordering_req_ie(buf + count, &value->reordering_req);
		} else if (ie_header->type == GTPV1_IE_RECOVERY) {
			count += decode_gtpv1_recovery_ie(buf + count, &value->recovery);
		} else if (ie_header->type == GTPV1_IE_TEID_DATA_1) {
			count += decode_gtpv1_teid_ie(buf + count, &value->tunn_endpt_idnt_data_1);
		} else if (ie_header->type == GTPV1_IE_TEID_CONTROL_PLANE) {
			count += decode_gtpv1_teid_ie(buf + count, &value->tunn_endpt_idnt_control_plane);
		} else if (ie_header->type == GTPV1_IE_NSAPI) {
			count += decode_gtpv1_nsapi_ie(buf + count, &value->nsapi);
		} else if (ie_header->type == GTPV1_IE_END_USER_ADDR) {
			count += decode_gtpv1_end_user_address_ie(buf + count, &value->end_user_address);
		} else if (ie_header->type == GTPV1_IE_GSN_ADDR && gsn_cnt == 0) {
			count += decode_gtpv1_gsn_address_ie(buf + count, &value->gsn_addr_1);
			gsn_cnt++;
		} else if (ie_header->type == GTPV1_IE_GSN_ADDR && gsn_cnt == 1) {
			count += decode_gtpv1_gsn_address_ie(buf + count, &value->gsn_addr_2);
			gsn_cnt++;
		} else if (ie_header->type == GTPV1_IE_GSN_ADDR && gsn_cnt == 2) {
			count += decode_gtpv1_gsn_address_ie(buf + count, &value->gsn_addr_3);
			gsn_cnt++;
		} else if (ie_header->type == GTPV1_IE_GSN_ADDR && gsn_cnt == 3) {
			count += decode_gtpv1_gsn_address_ie(buf + count, &value->gsn_addr_4);
		} else if (ie_header->type == GTPV1_IE_CHARGING_ID) {
			count += decode_gtpv1_charging_id_ie(buf + count, &value->charging_id);
		} else if (ie_header->type == GTPV1_IE_QOS) {
			count += decode_gtpv1_qos_ie(buf + count, &value->qos_profile);
		} else if (ie_header->type == GTPV1_IE_CHARGING_GATEWAY_ADDR && charging_cnt == 0) {
			count += decode_gtpv1_charging_gateway_addr_ie(buf + count, &value->charging_gateway_addr);
			charging_cnt++;
		} else if (ie_header->type == GTPV1_IE_CHARGING_GATEWAY_ADDR && charging_cnt == 1) {
			count += decode_gtpv1_charging_gateway_addr_ie(buf + count, &value->alt_charging_gateway_addr);
		} else if (ie_header->type == GTPV1_IE_COMMON_FLAG) {
			count += decode_gtpv1_common_flag_ie(buf + count, &value->common_flag);
		} else if (ie_header->type == GTPV1_IE_APN_RESTRICTION) {
			count += decode_gtpv1_apn_restriction_ie(buf + count, &value->apn_restriction);
		} else if (ie_header->type == GTPV1_IE_MS_INFO_CHANGE_REPORTING_ACTION) {
			count += decode_gtpv1_ms_info_change_reporting_action_ie(buf + count,
					&value->ms_info_change_reporting_action);
		} else if (ie_header->type == GTPV1_IE_BEARER_CONTROL_MODE) {
			count += decode_gtpv1_bearer_control_mode_ie(buf + count, &value->bearer_control);
		} else if (ie_header->type == GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_I) {
			count += decode_gtpv1_evolved_allocation_retention_priority_1_ie(buf + count,
					&value->evolved_allocation_retention_priority_1);
		} else if (ie_header->type == GTPV1_IE_PROTOCOL_CONFIG_OPTIONS) {
			count += decode_gtpv1_protocol_config_options_ie(buf + count, &value->protocol_config_options);
		} else if (ie_header->type == GTPV1_IE_EXTENDED_COMMON_FLAG) {
			count += decode_gtpv1_extended_common_flag_ie(buf + count, &value->extended_common_flag);
		} else if (ie_header->type == GTPV1_IE_CSG_INFORMATION_REPORTING_ACTION) {
			count += decode_gtpv1_csg_information_reporting_action_ie(buf + count,
					&value->csg_information_reporting_action);
		} else if (ie_header->type == GTPV1_IE_APN_AMBR) {
			count += decode_gtpv1_apn_ambr_ie(buf + count, &value->apn_ambr);
		} else if (ie_header->type == GTPV1_IE_GGSN_BACK_OFF_TIME) {
			count += decode_gtpv1_ggsn_back_off_time_ie(buf + count, &value->ggsn_back_off_time);
		} else if (ie_header->type == GTPV1_IE_EXTENDED_COMMON_FLAGS_II) {
			count += decode_gtpv1_extended_common_flag_2_ie(buf + count, &value->extended_common_flag_2);
		} else if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length) ;

	}
	
	return count + head_count;
}

int decode_gtpv1_update_pdp_ctxt_req_sgsn(uint8_t *buf, gtpv1_update_pdp_ctxt_req_sgsn_t *value){

	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0;

	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}

	count = 0;
	uint8_t gsn_cnt = 0;

	while (count < buf_len) {

		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);

		if (ie_header->type == GTPV1_IE_IMSI) {
			count += decode_gtpv1_imsi_ie(buf + count, &value->imsi);
		} else if (ie_header->type == GTPV1_IE_ROUTEING_AREA_IDENTITY) {
			count += decode_gtpv1_routing_area_identity_ie(buf + count, &value->routing_area_identity);
		} else if (ie_header->type == GTPV1_IE_RECOVERY) {
			count += decode_gtpv1_recovery_ie(buf + count, &value->recovery);
		} else if (ie_header->type == GTPV1_IE_TEID_DATA_1) {
			count += decode_gtpv1_teid_ie(buf + count, &value->tunn_endpt_idnt_data_1);
		} else if (ie_header->type == GTPV1_IE_TEID_CONTROL_PLANE) {
			count += decode_gtpv1_teid_ie(buf + count, &value->tunn_endpt_idnt_control_plane);
		} else if (ie_header->type == GTPV1_IE_NSAPI) {
			count += decode_gtpv1_nsapi_ie(buf + count, &value->nsapi);
		} else if (ie_header->type == GTPV1_IE_TRACE_REFERENCE) {
			count += decode_gtpv1_trace_reference_ie(buf + count, &value->trace_reference);
		} else if (ie_header->type == GTPV1_IE_TRACE_TYPE) {
			count += decode_gtpv1_trace_type_ie(buf + count, &value->trace_type);
		} else if (ie_header->type == GTPV1_IE_PROTOCOL_CONFIG_OPTIONS) {
			count += decode_gtpv1_protocol_config_options_ie(buf + count, &value->protocol_config_options);
		} else if (ie_header->type == GTPV1_IE_GSN_ADDR && gsn_cnt == 0) {
			count += decode_gtpv1_gsn_address_ie(buf + count, &value->gsn_addr_1);
			gsn_cnt++;
		} else if (ie_header->type == GTPV1_IE_GSN_ADDR && gsn_cnt == 1) {
			count += decode_gtpv1_gsn_address_ie(buf + count, &value->gsn_addr_2);
			gsn_cnt++;
		} else if (ie_header->type == GTPV1_IE_GSN_ADDR && gsn_cnt == 2) {
			count += decode_gtpv1_gsn_address_ie(buf + count, &value->gsn_addr_3);
			gsn_cnt++;
		} else if (ie_header->type == GTPV1_IE_GSN_ADDR && gsn_cnt == 3) {
			count += decode_gtpv1_gsn_address_ie(buf + count, &value->gsn_addr_4);
		} else if (ie_header->type == GTPV1_IE_QOS) {
			count += decode_gtpv1_qos_ie(buf + count, &value->qos_profile);
		} else if (ie_header->type == GTPV1_IE_TFT) {
			count += decode_gtpv1_traffic_flow_tmpl_ie(buf + count, &value->tft);
		} else if (ie_header->type == GTPV1_IE_TRIGGER_ID) {
			count += decode_gtpv1_trigger_id_ie(buf + count, &value->trigger_id);
		} else if (ie_header->type == GTPV1_IE_OMC_IDENTITY) {
			count += decode_gtpv1_omc_identity_ie(buf + count, &value->omc_identity);
		} else if (ie_header->type == GTPV1_IE_COMMON_FLAG) {
			count += decode_gtpv1_common_flag_ie(buf + count, &value->common_flag);
		} else if (ie_header->type == GTPV1_IE_RAT_TYPE) {
			count += decode_gtpv1_rat_type_ie(buf + count, &value->rat_type);
		} else if (ie_header->type == GTPV1_IE_USER_LOCATION_INFORMATION) {
			count += decode_gtpv1_user_location_information_ie(buf + count, &value->user_location_information);
		} else if (ie_header->type == GTPV1_IE_MS_TIME_ZONE) {
			count += decode_gtpv1_ms_time_zone_ie(buf + count, &value->ms_time_zone);
		} else if (ie_header->type == GTPV1_IE_ADDITIONAL_TRACE_INFORMATION) {
			count += decode_gtpv1_additional_trace_information_ie(buf + count, &value->additional_trace_information);
		} else if (ie_header->type == GTPV1_IE_DIRECT_TUNNEL_FLAG) {
			count += decode_gtpv1_direct_tunnel_flag_ie(buf + count, &value->direct_tunnel_flag);
		} else if (ie_header->type == GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_I) {
			count += decode_gtpv1_evolved_allocation_retention_priority_1_ie(buf + count,
					&value->evolved_allocation_retention_priority_1);
		} else if (ie_header->type == GTPV1_IE_EXTENDED_COMMON_FLAG) {
			count += decode_gtpv1_extended_common_flag_ie(buf + count, &value->extended_common_flag);
		} else if (ie_header->type == GTPV1_IE_USER_CSG_INFORMATION) {
			count += decode_gtpv1_user_csg_information_ie(buf + count, &value->user_csg_information);
		} else if (ie_header->type == GTPV1_IE_APN_AMBR) {
			count += decode_gtpv1_apn_ambr_ie(buf + count, &value->apn_ambr);
		} else if (ie_header->type == GTPV1_IE_SIGNALLING_PRIORITY_INDICATION) {
			count += decode_gtpv1_signalling_priority_indication_ie(buf + count,
					&value->signalling_priority_indication);
		} else if (ie_header->type == GTPV1_IE_CN_OPERATOR_SELECTION_ENTITY) {
			count += decode_gtpv1_cn_operator_selection_entity_ie(buf + count, &value->cn_operator_selection_entity);
		} else if (ie_header->type == GTPV1_IE_IMEI_SV) {
			count += decode_gtpv1_imei_ie(buf + count, &value->imei_sv);
		} else if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length);
	}
	return count + head_count;
}

int decode_gtpv1_update_pdp_ctxt_req_ggsn(uint8_t *buf, gtpv1_update_pdp_ctxt_req_ggsn_t *value){

	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0;

	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}

	count = 0;

	while (count < buf_len) {

		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);

		if (ie_header->type == GTPV1_IE_IMSI) {
			count += decode_gtpv1_imsi_ie(buf + count, &value->imsi);
		} else if (ie_header->type == GTPV1_IE_RECOVERY) {
			count += decode_gtpv1_recovery_ie(buf + count, &value->recovery);
		} else if (ie_header->type == GTPV1_IE_NSAPI) {
			count += decode_gtpv1_nsapi_ie(buf + count, &value->nsapi);
		} else if (ie_header->type == GTPV1_IE_END_USER_ADDR) {
			count += decode_gtpv1_end_user_address_ie(buf + count, &value->end_user_address);
		} else if (ie_header->type == GTPV1_IE_PROTOCOL_CONFIG_OPTIONS) {
			count += decode_gtpv1_protocol_config_options_ie(buf + count, &value->protocol_config_options);
		} else if (ie_header->type == GTPV1_IE_QOS) {
			count += decode_gtpv1_qos_ie(buf + count, &value->qos_profile);
		} else if (ie_header->type == GTPV1_IE_TFT) {
			count += decode_gtpv1_traffic_flow_tmpl_ie(buf + count, &value->tft);
		} else if (ie_header->type == GTPV1_IE_COMMON_FLAG) {
			count += decode_gtpv1_common_flag_ie(buf + count, &value->common_flag);
		} else if (ie_header->type == GTPV1_IE_APN_RESTRICTION) {
			count += decode_gtpv1_apn_restriction_ie(buf + count, &value->apn_restriction);
		} else if (ie_header->type == GTPV1_IE_MS_INFO_CHANGE_REPORTING_ACTION) {
			count += decode_gtpv1_ms_info_change_reporting_action_ie(buf + count,
					&value->ms_info_change_reporting_action);
		} else if (ie_header->type == GTPV1_IE_DIRECT_TUNNEL_FLAG) {
			count += decode_gtpv1_direct_tunnel_flag_ie(buf + count, &value->direct_tunnel_flag);
		} else if (ie_header->type == GTPV1_IE_BEARER_CONTROL_MODE) {
			count += decode_gtpv1_bearer_control_mode_ie(buf + count, &value->bearer_control);
		} else if (ie_header->type == GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_I) {
			count += decode_gtpv1_evolved_allocation_retention_priority_1_ie(buf + count,
					&value->evolved_allocation_retention_priority_1);
		} else if (ie_header->type == GTPV1_IE_EXTENDED_COMMON_FLAG) {
			count += decode_gtpv1_extended_common_flag_ie(buf + count, &value->extended_common_flag);
		} else if (ie_header->type == GTPV1_IE_CSG_INFORMATION_REPORTING_ACTION) {
			count += decode_gtpv1_csg_information_reporting_action_ie(buf + count,
					&value->csg_information_reporting_action);
		} else if (ie_header->type == GTPV1_IE_APN_AMBR) {
			count += decode_gtpv1_apn_ambr_ie(buf + count, &value->apn_ambr);
		} else if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length);
	}
	return count + head_count;
}

int decode_gtpv1_update_pdp_ctxt_rsp_ggsn(uint8_t *buf, gtpv1_update_pdp_ctxt_rsp_ggsn_t *value){

	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0;

	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}

	count = 0;
	uint8_t gsn_cnt = 0, charging_cnt = 0;

	while (count < buf_len) {

		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);

		if (ie_header->type == GTPV1_IE_CAUSE) {
			count += decode_gtpv1_cause_ie(buf + count, &value->cause);
		} else if (ie_header->type == GTPV1_IE_RECOVERY) {
			count += decode_gtpv1_recovery_ie(buf + count, &value->recovery);
		} else if (ie_header->type == GTPV1_IE_TEID_DATA_1) {
			count += decode_gtpv1_teid_ie(buf + count, &value->tunn_endpt_idnt_data_1);
		} else if (ie_header->type == GTPV1_IE_TEID_CONTROL_PLANE) {
			count += decode_gtpv1_teid_ie(buf + count, &value->tunn_endpt_idnt_control_plane);
		} else if (ie_header->type == GTPV1_IE_CHARGING_ID) {
			count += decode_gtpv1_charging_id_ie(buf + count, &value->charging_id);
		} else if (ie_header->type == GTPV1_IE_PROTOCOL_CONFIG_OPTIONS) {
			count += decode_gtpv1_protocol_config_options_ie(buf + count, &value->protocol_config_options);
		} else if (ie_header->type == GTPV1_IE_GSN_ADDR && gsn_cnt == 0) {
			count += decode_gtpv1_gsn_address_ie(buf + count, &value->gsn_addr_1);
			gsn_cnt++;
		} else if (ie_header->type == GTPV1_IE_GSN_ADDR && gsn_cnt == 1) {
			count += decode_gtpv1_gsn_address_ie(buf + count, &value->gsn_addr_2);
			gsn_cnt++;
		} else if (ie_header->type == GTPV1_IE_GSN_ADDR && gsn_cnt == 2) {
			count += decode_gtpv1_gsn_address_ie(buf + count, &value->gsn_addr_3);
			gsn_cnt++;
		} else if (ie_header->type == GTPV1_IE_GSN_ADDR && gsn_cnt == 3) {
			count += decode_gtpv1_gsn_address_ie(buf + count, &value->gsn_addr_4);
		} else if (ie_header->type == GTPV1_IE_QOS) {
			count += decode_gtpv1_qos_ie(buf + count, &value->qos_profile);
		} else if (ie_header->type == GTPV1_IE_CHARGING_GATEWAY_ADDR && charging_cnt == 0) {
			count += decode_gtpv1_charging_gateway_addr_ie(buf + count, &value->charging_gateway_addr);
			charging_cnt++;
		} else if (ie_header->type == GTPV1_IE_CHARGING_GATEWAY_ADDR && charging_cnt == 1) {
			count += decode_gtpv1_charging_gateway_addr_ie(buf + count, &value->alt_charging_gateway_addr);
		} else if (ie_header->type == GTPV1_IE_COMMON_FLAG) {
			count += decode_gtpv1_common_flag_ie(buf + count, &value->common_flag);
		} else if (ie_header->type == GTPV1_IE_APN_RESTRICTION) {
			count += decode_gtpv1_apn_restriction_ie(buf + count, &value->apn_restriction);
		} else if (ie_header->type == GTPV1_IE_BEARER_CONTROL_MODE) {
			count += decode_gtpv1_bearer_control_mode_ie(buf + count, &value->bearer_control);
		} else if (ie_header->type == GTPV1_IE_MS_INFO_CHANGE_REPORTING_ACTION) {
			count += decode_gtpv1_ms_info_change_reporting_action_ie(buf + count,
					&value->ms_info_change_reporting_action);
		} else if (ie_header->type == GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_I) {
			count += decode_gtpv1_evolved_allocation_retention_priority_1_ie(buf + count,
					&value->evolved_allocation_retention_priority_1);
		} else if (ie_header->type == GTPV1_IE_CSG_INFORMATION_REPORTING_ACTION) {
			count += decode_gtpv1_csg_information_reporting_action_ie(buf + count,
					&value->csg_information_reporting_action);
		} else if (ie_header->type == GTPV1_IE_APN_AMBR) {
			count += decode_gtpv1_apn_ambr_ie(buf + count, &value->apn_ambr);
		} else if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length);
	}
	return count + head_count;
}

int decode_gtpv1_update_pdp_ctxt_rsp_sgsn(uint8_t *buf, gtpv1_update_pdp_ctxt_rsp_sgsn_t *value){

	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0;

	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}

	count = 0;

	while (count < buf_len) {

		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);

		if (ie_header->type == GTPV1_IE_CAUSE) {
			count += decode_gtpv1_cause_ie(buf + count, &value->cause);
		} else if (ie_header->type == GTPV1_IE_RECOVERY) {
			count += decode_gtpv1_recovery_ie(buf + count, &value->recovery);
		} else if (ie_header->type == GTPV1_IE_TEID_DATA_1) {
			count += decode_gtpv1_teid_ie(buf + count, &value->tunn_endpt_idnt_data_1);
		} else if (ie_header->type == GTPV1_IE_PROTOCOL_CONFIG_OPTIONS) {
			count += decode_gtpv1_protocol_config_options_ie(buf + count, &value->protocol_config_options);
		} else if (ie_header->type == GTPV1_IE_GSN_ADDR) {
			count += decode_gtpv1_gsn_address_ie(buf + count, &value->sgsn_address_for_user_traffic);
		} else if (ie_header->type == GTPV1_IE_QOS) {
			count += decode_gtpv1_qos_ie(buf + count, &value->qos_profile);
		} else if (ie_header->type == GTPV1_IE_USER_LOCATION_INFORMATION) {
			count += decode_gtpv1_user_location_information_ie(buf + count, &value->user_location_information);
		} else if (ie_header->type == GTPV1_IE_MS_TIME_ZONE) {
			count += decode_gtpv1_ms_time_zone_ie(buf + count, &value->ms_time_zone);
		} else if (ie_header->type == GTPV1_IE_DIRECT_TUNNEL_FLAG) {
			count += decode_gtpv1_direct_tunnel_flag_ie(buf + count, &value->direct_tunnel_flag);
		} else if (ie_header->type == GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_I) {
			count += decode_gtpv1_evolved_allocation_retention_priority_1_ie(buf + count,
					&value->evolved_allocation_retention_priority_1);
		} else if (ie_header->type == GTPV1_IE_APN_AMBR) {
			count += decode_gtpv1_apn_ambr_ie(buf + count, &value->apn_ambr);
		} else if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length);
	}
	return count + head_count;
}

int decode_gtpv1_delete_pdp_ctxt_req(uint8_t *buf, gtpv1_delete_pdp_ctxt_req_t *value){

	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0;
	
	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}
	
	count = 0;
	
	while (count < buf_len){
		
		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);
		
		if (ie_header->type == GTPV1_IE_CAUSE) {
			count += decode_gtpv1_cause_ie(buf + count, &value->cause);
		} else if (ie_header->type == GTPV1_IE_TEARDOWN_IND) {
			count += decode_gtpv1_teardown_ind_ie(buf + count, &value->teardown_ind);
		} else if (ie_header->type == GTPV1_IE_NSAPI) {
			count += decode_gtpv1_nsapi_ie(buf + count, &value->nsapi);
		} else if (ie_header->type == GTPV1_IE_PROTOCOL_CONFIG_OPTIONS) {
			count += decode_gtpv1_protocol_config_options_ie(buf + count, &value->protocol_config_options);
		} else if (ie_header->type == GTPV1_IE_USER_LOCATION_INFORMATION) {
			count += decode_gtpv1_user_location_information_ie(buf + count, &value->user_location_information);
		} else if (ie_header->type == GTPV1_IE_MS_TIME_ZONE) {
			count += decode_gtpv1_ms_time_zone_ie(buf + count, &value->ms_time_zone);
		} else if (ie_header->type == GTPV1_IE_EXTENDED_COMMON_FLAG) {
			count += decode_gtpv1_extended_common_flag_ie(buf + count, &value->extended_common_flag);
		} else if (ie_header->type == GTPV1_IE_ULI_TIMESTAMP) {
			count += decode_gtpv1_uli_timestamp_ie(buf + count, &value->uli_timestamp);
		} else if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length) ;
	}
	return count + head_count;
}

int decode_gtpv1_delete_pdp_ctxt_rsp(uint8_t *buf, gtpv1_delete_pdp_ctxt_rsp_t *value){

	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0;
	
	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;
	
	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}
	
	count = 0;
	
	while (count < buf_len){
		
		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);
		
		if (ie_header->type == GTPV1_IE_CAUSE) {
			count += decode_gtpv1_cause_ie(buf + count, &value->cause);
		} else if (ie_header->type == GTPV1_IE_PROTOCOL_CONFIG_OPTIONS) {
			count += decode_gtpv1_protocol_config_options_ie(buf + count, &value->protocol_config_options);
		} else if (ie_header->type == GTPV1_IE_USER_LOCATION_INFORMATION) {
			count += decode_gtpv1_user_location_information_ie(buf + count, &value->user_location_information);
		} else if (ie_header->type == GTPV1_IE_MS_TIME_ZONE) {
			count += decode_gtpv1_ms_time_zone_ie(buf + count, &value->ms_time_zone);
		} else if (ie_header->type == GTPV1_IE_ULI_TIMESTAMP) {
			count += decode_gtpv1_uli_timestamp_ie(buf + count, &value->uli_timestamp);
		} else if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length) ;
	}
	return count + head_count;
}

int decode_gtpv1_initiate_pdp_ctxt_active_req(uint8_t *buf, gtpv1_initiate_pdp_ctxt_active_req_t *value) {
		
	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0;

	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}

	count = 0;

	while (count < buf_len){
	
		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);
		if (ie_header->type == GTPV1_IE_NSAPI) {
			count += decode_gtpv1_nsapi_ie(buf + count, &value->linked_nsapi);
		} else if (ie_header->type == GTPV1_IE_PROTOCOL_CONFIG_OPTIONS) {
			count += decode_gtpv1_protocol_config_options_ie(buf + count, &value->protocol_config_options);
		} else if (ie_header->type == GTPV1_IE_QOS) {
			count += decode_gtpv1_qos_ie(buf + count, &value->qos_profile);
		} else if (ie_header->type == GTPV1_IE_TFT) {
			count += decode_gtpv1_traffic_flow_tmpl_ie(buf + count, &value->tft);
		} else if (ie_header->type == GTPV1_IE_CORRELATION_ID) {
			count += decode_gtpv1_correlation_id_ie(buf + count, &value->correlation_id);
		} else if (ie_header->type == GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_I) {
			count += decode_gtpv1_evolved_allocation_retention_priority_1_ie(buf + count,
					&value->evolved_allocation_retention_priority_1);
		} else if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length);
	}
	
	return count + head_count;
}

int decode_gtpv1_initiate_pdp_ctxt_active_rsp(uint8_t *buf, gtpv1_initiate_pdp_ctxt_active_rsp_t *value) {
	
	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0;
	
	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;
	
	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}	
	
	count = 0;
	
	while (count < buf_len) {
		
		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);
		
		if (ie_header->type == GTPV1_IE_CAUSE) {
			count += decode_gtpv1_cause_ie(buf + count, &value->cause);
		} else if (ie_header->type == GTPV1_IE_PROTOCOL_CONFIG_OPTIONS) {
			count += decode_gtpv1_protocol_config_options_ie(buf + count, &value->protocol_config_options);
		} else if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length);
	}
	
	return count + head_count;
}

int decode_gtpv1_pdu_notification_req(uint8_t *buf, gtpv1_pdu_notification_req_t *value){

	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0;

	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}

	count = 0;

	while (count < buf_len){
		
		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);

		if (ie_header->type == GTPV1_IE_IMSI) {
			count += decode_gtpv1_imsi_ie(buf + count, &value->imsi);
		} else if (ie_header->type == GTPV1_IE_TEID_CONTROL_PLANE) {
			count += decode_gtpv1_teid_ie(buf + count, &value->tunn_endpt_idnt_control_plane);
		} else if (ie_header->type == GTPV1_IE_END_USER_ADDR) {
			count += decode_gtpv1_end_user_address_ie(buf + count, &value->end_user_address);
		} else if (ie_header->type == GTPV1_IE_APN) {
			count += decode_gtpv1_apn_ie(buf + count, &value->apn);
		} else if (ie_header->type == GTPV1_IE_PROTOCOL_CONFIG_OPTIONS) {
			count += decode_gtpv1_protocol_config_options_ie(buf + count, &value->protocol_config_options);
		} else if (ie_header->type == GTPV1_IE_GSN_ADDR) {
			count += decode_gtpv1_gsn_address_ie(buf + count, &value->ggsn_addr_control_plane);
		} else if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length) ;
	}
	return count + head_count;
}

int decode_gtpv1_pdu_notification_rsp(uint8_t *buf, gtpv1_pdu_notification_rsp_t *value){

	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0;

	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}

	count = 0;

	while (count < buf_len){

		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);

		if (ie_header->type == GTPV1_IE_CAUSE) {
			count += decode_gtpv1_cause_ie(buf + count, &value->cause);
		}  else if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length) ;
	}
	return count + head_count;
}

int decode_gtpv1_pdu_notification_reject_req(uint8_t *buf, gtpv1_pdu_notification_reject_req_t *value){

	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0;

	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}

	count = 0;

	while (count < buf_len){

		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);

		if (ie_header->type == GTPV1_IE_CAUSE) {
			count += decode_gtpv1_cause_ie(buf + count, &value->cause);
		} else if (ie_header->type == GTPV1_IE_TEID_CONTROL_PLANE) {
			count += decode_gtpv1_teid_ie(buf + count, &value->tunn_endpt_idnt_control_plane);
		} else if (ie_header->type == GTPV1_IE_END_USER_ADDR) {
			count += decode_gtpv1_end_user_address_ie(buf + count, &value->end_user_address);
		} else if (ie_header->type == GTPV1_IE_APN) {
			count += decode_gtpv1_apn_ie(buf + count, &value->apn);
		} else if (ie_header->type == GTPV1_IE_PROTOCOL_CONFIG_OPTIONS) {
			count += decode_gtpv1_protocol_config_options_ie(buf + count, &value->protocol_config_options);
		} else if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length) ;
	}
	return count + head_count;
}

int decode_gtpv1_pdu_notification_reject_rsp(uint8_t *buf, gtpv1_pdu_notification_reject_rsp_t *value){

	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0;

	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}

	count = 0;

	while (count < buf_len){

		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);

		if (ie_header->type == GTPV1_IE_CAUSE) {
			count += decode_gtpv1_cause_ie(buf + count, &value->cause);
		}  else if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length) ;
	}
	return count + head_count;
}

int decode_gtpv1_send_routeing_info_for_gprs_req(uint8_t *buf, gtpv1_send_routeing_info_for_gprs_req_t *value){

	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0;

	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}

	count = 0;

	while (count < buf_len){

		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);

		if (ie_header->type == GTPV1_IE_IMSI) {
			count += decode_gtpv1_imsi_ie(buf + count, &value->imsi);
		}  else if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length) ;
	}
	return count + head_count;
}

int decode_gtpv1_send_routeing_info_for_gprs_rsp(uint8_t *buf, gtpv1_send_routeing_info_for_gprs_rsp_t *value){

	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0;

	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}

	count = 0;

	while (count < buf_len){

		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);

		if (ie_header->type == GTPV1_IE_CAUSE) {
			count += decode_gtpv1_cause_ie(buf + count, &value->cause);
		} else if (ie_header->type == GTPV1_IE_IMSI) {
			count += decode_gtpv1_imsi_ie(buf + count, &value->imsi);
		} else if (ie_header->type == GTPV1_IE_MAP_CAUSE) {
			count += decode_gtpv1_map_cause_ie(buf + count, &value->map_cause);
		} else if (ie_header->type == GTPV1_IE_MS_NOT_RECHABLE_REASON) {
			count += decode_gtpv1_ms_not_rechable_reason_ie(buf + count, &value->ms_not_rechable_reason);
		} else if (ie_header->type == GTPV1_IE_GSN_ADDR) {
			count += decode_gtpv1_gsn_address_ie(buf + count, &value->gsn_addr);
		} else if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length) ;
	}
	return count + head_count;
}

int decode_gtpv1_failure_report_req(uint8_t *buf, gtpv1_failure_report_req_t *value){

	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0;

	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}

	count = 0;

	while (count < buf_len){

		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);

		if (ie_header->type == GTPV1_IE_IMSI) {
			count += decode_gtpv1_imsi_ie(buf + count, &value->imsi);
		} else if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length) ;
	}
	return count + head_count;
}

int decode_gtpv1_failure_report_rsp(uint8_t *buf, gtpv1_failure_report_rsp_t *value){

	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0;

	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}

	count = 0;

	while (count < buf_len){

		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);

		if (ie_header->type == GTPV1_IE_CAUSE) {
			count += decode_gtpv1_cause_ie(buf + count, &value->cause);
		} else if (ie_header->type == GTPV1_IE_MAP_CAUSE) {
			count += decode_gtpv1_map_cause_ie(buf + count, &value->map_cause);
		} else if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length) ;
	}
	return count + head_count;
}

int decode_gtpv1_note_ms_gprs_present_req(uint8_t *buf, gtpv1_note_ms_gprs_present_req_t *value){

	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0;

	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}

	count = 0;

	while (count < buf_len){

		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);

		if (ie_header->type == GTPV1_IE_IMSI) {
			count += decode_gtpv1_imsi_ie(buf + count, &value->imsi);
		} else if (ie_header->type == GTPV1_IE_GSN_ADDR) {
			count += decode_gtpv1_gsn_address_ie(buf + count, &value->gsn_addr);
		} else if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length) ;
	}
	return count + head_count;
}

int decode_gtpv1_note_ms_gprs_present_rsp(uint8_t *buf, gtpv1_note_ms_gprs_present_rsp_t *value){

	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0;

	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}

	count = 0;

	while (count < buf_len){

		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);

		if (ie_header->type == GTPV1_IE_CAUSE) {
			count += decode_gtpv1_cause_ie(buf + count, &value->cause);
		} else if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length) ;
	}
	return count + head_count;
}

int decode_gtpv1_sgsn_context_req(uint8_t *buf, gtpv1_sgsn_ctxt_req_t *value) {
	
	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0;

	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}

	count = 0;
	uint8_t gsn_cnt = 0;

	while (count < buf_len) {

		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);
	
		if (ie_header->type == GTPV1_IE_IMSI) {
			count += decode_gtpv1_imsi_ie(buf + count, &value->imsi);
		} else if (ie_header->type == GTPV1_IE_ROUTEING_AREA_IDENTITY) {
			count += decode_gtpv1_routing_area_identity_ie(buf + count, &value->routing_area_identity);
		} else if (ie_header->type == GTPV1_IE_TEMPORARY_LOGICAL_LINK_IDENTIFIER) {
			count += decode_gtpv1_temporary_logical_link_identifier_ie(buf + count, 
					&value->temporary_logical_link_identifier);
		} else if (ie_header->type == GTPV1_IE_PACKET_TMSI) {
			count += decode_gtpv1_packet_tmsi_ie(buf + count, &value->packet_tmsi);
		} else if (ie_header->type == GTPV1_IE_P_TMSI_SIGNATURE) {
			count += decode_gtpv1_p_tmsi_signature_ie(buf + count, &value->p_tmsi_signature);
		} else if (ie_header->type == GTPV1_IE_MS_VALIDATED) {
			count += decode_gtpv1_ms_validated_ie(buf + count, &value->ms_validated);
		} else if (ie_header->type == GTPV1_IE_TEID_CONTROL_PLANE) {
			count += decode_gtpv1_teid_ie(buf + count, &value->tunn_endpt_idnt_control_plane);
		} else if (ie_header->type == GTPV1_IE_GSN_ADDR && gsn_cnt == 0){
			count += decode_gtpv1_gsn_address_ie(buf + count, &value->sgsn_address_for_control_plane);
			gsn_cnt++;
		} else if (ie_header->type == GTPV1_IE_GSN_ADDR && gsn_cnt == 1){
			count += decode_gtpv1_gsn_address_ie(buf + count, &value->alternative_sgsn_address_for_control_plane);
		} else if (ie_header->type == GTPV1_IE_SGSN_NUMBER) {
			count += decode_gtpv1_sgsn_number_ie(buf + count, &value->sgsn_number);
		} else if (ie_header->type == GTPV1_IE_RAT_TYPE) {
			count += decode_gtpv1_rat_type_ie(buf + count, &value->rat_type);
		} else if (ie_header->type == GTPV1_IE_HOP_COUNTER) {
			count += decode_gtpv1_hop_counter_ie(buf + count, &value->hop_counter);
		} else if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length);
	}
	return count + head_count;
}

int decode_gtpv1_sgsn_context_rsp(uint8_t *buf, gtpv1_sgsn_ctxt_rsp_t *value) {
	
	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0; 

	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}

	count = 0;
	uint8_t gsn_cnt = 0, rfsp_cnt = 0;

	while (count < buf_len) {
		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);
		if (ie_header->type == GTPV1_IE_CAUSE) {
			count += decode_gtpv1_cause_ie(buf + count, &value->cause);
		} else if (ie_header->type == GTPV1_IE_IMSI) {
			count += decode_gtpv1_imsi_ie(buf + count, &value->imsi);
		} else if (ie_header->type == GTPV1_IE_TEID_CONTROL_PLANE) {
			count += decode_gtpv1_teid_ie(buf + count, &value->tunn_endpt_idnt_control_plane);
		} else if (ie_header->type == GTPV1_IE_RAB_CONTEXT) {
			count += decode_gtpv1_rab_context_ie(buf + count, &value->rab_context);
		} else if (ie_header->type == GTPV1_IE_RADIO_PRIORITY_SMS) {
			count += decode_gtpv1_radio_priority_sms_ie(buf + count, &value->radio_priority_sms);
		} else if (ie_header->type == GTPV1_IE_RADIO_PRIORITY) {
			count += decode_gtpv1_radio_priority_ie(buf + count, &value->radio_priority);
		} else if (ie_header->type == GTPV1_IE_PACKET_FLOW_ID) {
			count += decode_gtpv1_packet_flow_id_ie(buf + count, &value->packet_flow_id);
		} else if (ie_header->type == GTPV1_IE_CHRGNG_CHAR) {
			count += decode_gtpv1_chrgng_char_ie(buf + count, &value->chrgng_char);
		} else if (ie_header->type == GTPV1_IE_RADIO_PRIORITY_LCS) {
			count += decode_gtpv1_radio_priority_lcs_ie(buf + count, &value->radio_priority_lcs);
		} else if (ie_header->type == GTPV1_IE_MM_CONTEXT) {
			count += decode_gtpv1_mm_context_ie(buf + count, &value->mm_context);
		} else if (ie_header->type == GTPV1_IE_PDP_CONTEXT) {
			count += decode_gtpv1_pdp_context_ie(buf + count, &value->pdp_context);
		} else if (ie_header->type == GTPV1_IE_GSN_ADDR && gsn_cnt == 0) {
			count += decode_gtpv1_gsn_address_ie(buf + count, &value->gsn_addr_1);
			gsn_cnt++;
		} else if (ie_header->type == GTPV1_IE_GSN_ADDR && gsn_cnt == 1) {
			count += decode_gtpv1_gsn_address_ie(buf + count, &value->gsn_addr_2);
			gsn_cnt++;
		} else if (ie_header->type == GTPV1_IE_GSN_ADDR && gsn_cnt == 2) {
			count += decode_gtpv1_gsn_address_ie(buf + count, &value->gsn_addr_3);
		} else if (ie_header->type == GTPV1_IE_PDP_CONTEXT_PRIORITIZATION) {
			count += decode_gtpv1_pdp_context_prioritization_ie(buf + count, &value->pdp_context_prioritization);
		} else if (ie_header->type == GTPV1_IE_MBMS_UE_CONTEXT) {
			count += decode_gtpv1_mbms_ue_context_ie(buf + count, &value->mbms_ue_context);
		} else if (ie_header->type == GTPV1_IE_RFSP_INDEX && rfsp_cnt == 0) {
			count += decode_gtpv1_rfsp_index_ie(buf + count, &value->subscribed_rfsp_index);
			rfsp_cnt++;
		} else if (ie_header->type == GTPV1_IE_RFSP_INDEX && rfsp_cnt == 1) {
			count += decode_gtpv1_rfsp_index_ie(buf + count, &value->rfsp_index_in_use);
		} else if (ie_header->type == GTPV1_IE_FQDN) {
			count += decode_gtpv1_fqdn_ie(buf + count, &value->co_located_ggsn_pgw_fqdn);
		} else if (ie_header->type == GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_II) {
			count += decode_gtpv1_evolved_allocation_retention_priority_II_ie(buf + count, &value->evolved_allocation_retention_priority_II);
		} else if (ie_header->type == GTPV1_IE_EXTENDED_COMMON_FLAG) {
			count += decode_gtpv1_extended_common_flag_ie(buf + count, &value->extended_common_flag);
		} else if (ie_header->type == GTPV1_IE_UE_NETWORK_CAPABILITY) {
			count += decode_gtpv1_ue_network_capability_ie(buf + count, &value->ue_network_capability);
		} else if (ie_header->type == GTPV1_IE_UE_AMBR) {
			count += decode_gtpv1_ue_ambr_ie(buf + count, &value->ue_ambr);
		} else if (ie_header->type == GTPV1_IE_APN_AMBR_WITH_NSAPI) {
			count += decode_gtpv1_apn_ambr_with_nsapi_ie(buf + count, &value->apn_ambr_with_nsapi);
		} else if (ie_header->type == GTPV1_IE_SIGNALLING_PRIORITY_INDICATION_WITH_NSAPI) {
			count += decode_gtpv1_signalling_priority_indication_with_nsapi_ie(buf + count, &value->signalling_priority_indication_with_nsapi);
		} else if (ie_header->type == GTPV1_IE_HIGER_BITRATES_THAN_16_MBPS_FLAG) {
			count += decode_gtpv1_higher_bitrates_than_16_mbps_flag_ie(buf + count, &value->higher_bitrates_than_16_mbps_flag);
		} else if (ie_header->type == GTPV1_IE_SELECTION_MODE_WITH_NSAPI) {
			count += decode_gtpv1_selection_mode_with_nsapi_ie(buf + count, &value->selection_mode_with_nsapi);
		} else if (ie_header->type == GTPV1_IE_LOCAL_HOME_NETWORK_ID_WITH_NSAPI) {
			count += decode_gtpv1_local_home_network_id_with_nsapi_ie(buf + count, &value->local_home_network_id_with_nsapi);
		} else if (ie_header->type == GTPV1_IE_UE_USAGE_TYPE) {
			count += decode_gtpv1_ue_usage_type_ie(buf + count, &value->ue_usage_type);
		} else if (ie_header->type == GTPV1_IE_EXTENDED_COMMON_FLAGS_II) {
			count += decode_gtpv1_extended_common_flag_2_ie(buf + count, &value->extended_common_flag_2);
		} else if (ie_header->type == GTPV1_IE_UE_SCEF_PDN_CONNTECTION) {
			count += decode_gtpv1_ue_scef_pdn_connection_ie(buf + count, &value->ue_scef_pdn_connection);
		} else if (ie_header->type == GTPV1_IE_IOV_UPDATES_COUNTER) {
			count += decode_gtpv1_iov_updates_counter_ie(buf + count, &value->iov_updates_counter);
		} else if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length);
	}
	return count + head_count;
}

int decode_gtpv1_ue_registration_query_req(uint8_t *buf, gtpv1_ue_registration_query_req_t *value){

	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0;

	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}

	count = 0;

	while (count < buf_len){

		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);

		if (ie_header->type == GTPV1_IE_IMSI) {
			count += decode_gtpv1_imsi_ie(buf + count, &value->imsi);
		} else if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length) ;
	}
	return count + head_count;
}

int decode_gtpv1_ue_registration_query_rsp(uint8_t *buf, gtpv1_ue_registration_query_rsp_t *value){

	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0;

	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}

	count = 0;

	while (count < buf_len){

		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);

		if (ie_header->type == GTPV1_IE_CAUSE) {
			count += decode_gtpv1_cause_ie(buf + count, &value->cause);
		} else if (ie_header->type == GTPV1_IE_IMSI) {
			count += decode_gtpv1_imsi_ie(buf + count, &value->imsi);
		} else if (ie_header->type == GTPV1_IE_SELECTED_PLMN_ID) {
			count += decode_gtpv1_selected_plmn_id_ie(buf + count, &value->plmn_id);
		} else if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length) ;
	}
	return count + head_count;
}

int decode_gtpv1_ran_info_relay(uint8_t *buf, gtpv1_ran_info_relay_t *value){

	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0;

	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}

	count = 0;

	while (count < buf_len){

		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);

		if (ie_header->type == GTPV1_IE_RAN_TRANSPARENT_CONTAINER) {
			count += decode_gtpv1_ran_transparent_container_ie(buf + count, &value->ran_transparent_container);
		} else if (ie_header->type == GTPV1_IE_RIM_ROUTING_ADDR) {
			count += decode_gtpv1_rim_routing_addr_ie(buf + count, &value->rim_addr);
		} else if (ie_header->type == GTPV1_IE_RIM_ROUTING_ADDR_DISCRIMINATOR) {
			count += decode_gtpv1_rim_routing_addr_disc_ie(buf + count, &value->rim_addr_disc);
		} else if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length) ;
	}
	return count + head_count;
}

int decode_gtpv1_mbms_notification_req(uint8_t *buf, gtpv1_mbms_notification_req_t *value){

	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0;

	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}

	count = 0;

	while (count < buf_len){

		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);

		if (ie_header->type == GTPV1_IE_IMSI) {
			count += decode_gtpv1_imsi_ie(buf + count, &value->imsi);
		} else if (ie_header->type == GTPV1_IE_TEID_CONTROL_PLANE) {
			count += decode_gtpv1_teid_ie(buf + count, &value->tunn_endpt_idnt_control_plane);
		} else if (ie_header->type == GTPV1_IE_NSAPI) {
			count += decode_gtpv1_nsapi_ie(buf + count, &value->nsapi);
		} else if (ie_header->type == GTPV1_IE_END_USER_ADDR) {
			count += decode_gtpv1_end_user_address_ie(buf + count, &value->end_user_address);
		} else if (ie_header->type == GTPV1_IE_APN) {
			count += decode_gtpv1_apn_ie(buf + count, &value->apn);
		} else if (ie_header->type == GTPV1_IE_GSN_ADDR ) {
			count += decode_gtpv1_gsn_address_ie(buf + count, &value->ggsn_addr_control_plane);
		} else if (ie_header->type == GTPV1_IE_MBMS_PROTOCOL_CONFIG_OPTIONS ) {
			count += decode_gtpv1_mbms_protocol_config_options_ie(buf + count, &value->mbms_protocol);
		} else if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length) ;
	}
	return count + head_count;
}

int decode_gtpv1_mbms_notification_rsp(uint8_t *buf, gtpv1_mbms_notification_rsp_t *value){

	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0;

	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}

	count = 0;

	while (count < buf_len){

		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);

		if (ie_header->type == GTPV1_IE_CAUSE) {
			count += decode_gtpv1_cause_ie(buf + count, &value->cause);
		} else if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length) ;
	}
	return count + head_count;
}

int decode_gtpv1_forward_relocation_req(uint8_t *buf, gtpv1_forward_relocation_req_t *value){

	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0;

	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}

	count = 0;
	uint8_t gsn_cnt = 0, rfsp_cnt = 0;
	while (count < buf_len){

		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);

		if (ie_header->type == GTPV1_IE_IMSI) {
			count += decode_gtpv1_imsi_ie(buf + count, &value->imsi);
		} else if (ie_header->type == GTPV1_IE_TEID_CONTROL_PLANE) {
			count += decode_gtpv1_teid_ie(buf + count, &value->tunn_endpt_idnt_control_plane);
		} else if (ie_header->type == GTPV1_IE_RANAP_CAUSE) {
			count += decode_gtpv1_ranap_cause_ie(buf + count, &value->ranap_cause);
		} else if (ie_header->type == GTPV1_IE_PACKET_FLOW_ID) {
			count += decode_gtpv1_packet_flow_id_ie(buf + count, &value->packet_flow_id);
		} else if (ie_header->type == GTPV1_IE_CHRGNG_CHAR) {
			count += decode_gtpv1_chrgng_char_ie(buf + count, &value->chrgng_char);
		} else if (ie_header->type == GTPV1_IE_MM_CONTEXT) {
			count += decode_gtpv1_mm_context_ie(buf + count, &value->mm_context);
		} else if (ie_header->type == GTPV1_IE_PDP_CONTEXT) {
			count += decode_gtpv1_pdp_context_ie(buf + count, &value->pdp_context);
		} else if (ie_header->type == GTPV1_IE_GSN_ADDR && gsn_cnt == 0) {
			count += decode_gtpv1_gsn_address_ie(buf + count, &value->gsn_addr_1);
			gsn_cnt++;
		} else if (ie_header->type == GTPV1_IE_GSN_ADDR && gsn_cnt == 1) {
			count += decode_gtpv1_gsn_address_ie(buf + count, &value->gsn_addr_2);
			gsn_cnt++;
		} else if (ie_header->type == GTPV1_IE_GSN_ADDR && gsn_cnt == 2) {
			count += decode_gtpv1_gsn_address_ie(buf + count, &value->gsn_addr_3);
		} else if (ie_header->type == GTPV1_IE_TARGET_IDENTIFICATION) {
			count += decode_gtpv1_target_identification_ie(buf + count, &value->target_id);
		} else if (ie_header->type == GTPV1_IE_UTRAN_TRANSPARENT_CONTAINER) {
			count += decode_gtpv1_utran_transparent_container_ie(buf + count, &value->utran_container);
		} else if (ie_header->type == GTPV1_IE_PDP_CONTEXT_PRIORITIZATION) {
			count += decode_gtpv1_pdp_context_prioritization_ie(buf + count, &value->pdp_context_prioritization);
		} else if (ie_header->type == GTPV1_IE_MBMS_UE_CONTEXT) {
			count += decode_gtpv1_mbms_ue_context_ie(buf + count, &value->mbms_ue_context);
		} else if (ie_header->type == GTPV1_IE_SELECTED_PLMN_ID) {
			count += decode_gtpv1_selected_plmn_id_ie(buf + count, &value->plmn_id);
		} else if (ie_header->type == GTPV1_IE_BSS_CONTAINER) {
			count += decode_gtpv1_bss_container_ie(buf + count, &value->bss_container);
		} else if (ie_header->type == GTPV1_IE_CELL_IDENTIFICATION) {
			count += decode_gtpv1_cell_identification_ie(buf + count, &value->cell_id);
		} else if (ie_header->type == GTPV1_IE_BSSGP_CAUSE) {
			count += decode_gtpv1_bssgp_cause_ie(buf + count, &value->bssgp_cause);
		} else if (ie_header->type == GTPV1_IE_PS_HANDOVER_XID_PARAM) {
			count += decode_gtpv1_ps_handover_xid_param_ie(buf + count, &value->xid_param);
		} else if (ie_header->type == GTPV1_IE_DIRECT_TUNNEL_FLAG) {
			count += decode_gtpv1_direct_tunnel_flag_ie(buf + count, &value->direct_tunnel_flag);
		} else if (ie_header->type == GTPV1_IE_RELIABLE_INTER_RAT_HANDOVER_INFO) {
			count += decode_gtpv1_reliable_inter_rat_handover_info_ie(buf + count, &value->inter_rat_handover);
		} else if (ie_header->type == GTPV1_IE_RFSP_INDEX && rfsp_cnt == 0) {
			count += decode_gtpv1_rfsp_index_ie(buf + count, &value->subscribed_rfsp_index);
			rfsp_cnt++;
		} else if (ie_header->type == GTPV1_IE_RFSP_INDEX && rfsp_cnt == 1) {
			count += decode_gtpv1_rfsp_index_ie(buf + count, &value->rfsp_index_in_use);
		} else if (ie_header->type == GTPV1_IE_FQDN) {
			count += decode_gtpv1_fqdn_ie(buf + count, &value->co_located_ggsn_pgw_fqdn);
		} else if (ie_header->type == GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_II) {
			count += decode_gtpv1_evolved_allocation_retention_priority_II_ie(buf + count, &value->evolved_allocation_retention_priority_II);
		} else if (ie_header->type == GTPV1_IE_EXTENDED_COMMON_FLAG) {
			count += decode_gtpv1_extended_common_flag_ie(buf + count, &value->extended_common_flag);
		} else if (ie_header->type == GTPV1_IE_CSG_ID) {
			count += decode_gtpv1_csg_id_ie(buf + count, &value->csg_id);
		} else if (ie_header->type == GTPV1_IE_CSG_MEMB_INDCTN) {
			count += decode_gtpv1_csg_membership_indication_ie(buf + count, &value->csg_member);
		} else if (ie_header->type == GTPV1_IE_UE_NETWORK_CAPABILITY) {
			count += decode_gtpv1_ue_network_capability_ie(buf + count, &value->ue_network_capability);
		} else if (ie_header->type == GTPV1_IE_UE_AMBR) {
			count += decode_gtpv1_ue_ambr_ie(buf + count, &value->ue_ambr);
		} else if (ie_header->type == GTPV1_IE_APN_AMBR_WITH_NSAPI) {
			count += decode_gtpv1_apn_ambr_with_nsapi_ie(buf + count, &value->apn_ambr_with_nsapi);
		} else if (ie_header->type == GTPV1_IE_SIGNALLING_PRIORITY_INDICATION_WITH_NSAPI) {
			count += decode_gtpv1_signalling_priority_indication_with_nsapi_ie(buf + count, &value->signalling_priority_indication_with_nsapi);
		} else if (ie_header->type == GTPV1_IE_HIGER_BITRATES_THAN_16_MBPS_FLAG) {
			count += decode_gtpv1_higher_bitrates_than_16_mbps_flag_ie(buf + count, &value->higher_bitrates_than_16_mbps_flag);
		} else if (ie_header->type == GTPV1_IE_ADDTL_MM_CTXT_SRVCC) {
			count += decode_gtpv1_additional_mm_ctxt_for_srvcc_ie(buf + count, &value->add_mm_ctxt);
		} else if (ie_header->type == GTPV1_IE_ADDTL_FLGS_SRVCC) {
			count += decode_gtpv1_additional_flags_for_srvcc_ie(buf + count, &value->add_flag_srvcc);
		} else if (ie_header->type == GTPV1_IE_STN_SR) {
			count += decode_gtpv1_stn_sr_ie(buf + count, &value->stn_sr);
		} else if (ie_header->type == GTPV1_IE_C_MSISDN) {
			count += decode_gtpv1_c_msisdn_ie(buf + count, &value->c_msisdn);
		} else if (ie_header->type == GTPV1_IE_EXTENDED_RANAP_CAUSE) {
			count += decode_gtpv1_extended_ranap_cause_ie(buf + count, &value->ext_ranap_cause);
		} else if (ie_header->type == GTPV1_IE_ENODEB_ID) {
			count += decode_gtpv1_enodeb_id_ie(buf + count, &value->enodeb_id);
		} else if (ie_header->type == GTPV1_IE_SELECTION_MODE_WITH_NSAPI) {
			count += decode_gtpv1_selection_mode_with_nsapi_ie(buf + count, &value->selection_mode_with_nsapi);
		} else if (ie_header->type == GTPV1_IE_UE_USAGE_TYPE) {
			count += decode_gtpv1_ue_usage_type_ie(buf + count, &value->ue_usage_type);
		} else if (ie_header->type == GTPV1_IE_EXTENDED_COMMON_FLAGS_II) {
			count += decode_gtpv1_extended_common_flag_2_ie(buf + count, &value->extended_common_flag_2);
		} else if (ie_header->type == GTPV1_IE_UE_SCEF_PDN_CONNTECTION) {
			count += decode_gtpv1_ue_scef_pdn_connection_ie(buf + count, &value->ue_scef_pdn_connection);
		} else if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length) ;
	}
	return count + head_count;
}

int decode_gtpv1_forward_relocation_rsp(uint8_t *buf, gtpv1_forward_relocation_rsp_t *value){

	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0;

	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}

	count = 0;
	uint8_t gsn_cnt = 0;

	while (count < buf_len){

		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);

		if (ie_header->type == GTPV1_IE_CAUSE) {
			count += decode_gtpv1_cause_ie(buf + count, &value->cause);
		} else if (ie_header->type == GTPV1_IE_TEID_CONTROL_PLANE) {
			count += decode_gtpv1_teid_ie(buf + count, &value->teid_control_plane);
		} else if (ie_header->type == GTPV1_IE_TEID_DATA_2) {
			count += decode_gtpv1_teid_data_2_ie(buf + count, &value->teid_2);
		} else if (ie_header->type == GTPV1_IE_RANAP_CAUSE) {
			count += decode_gtpv1_ranap_cause_ie(buf + count, &value->ranap_cause);
		} else if (ie_header->type == GTPV1_IE_GSN_ADDR && gsn_cnt == 0) {
			count += decode_gtpv1_gsn_address_ie(buf + count, &value->sgsn_addr_control_plane);
			gsn_cnt++;
		} else if (ie_header->type == GTPV1_IE_GSN_ADDR && gsn_cnt == 1) {
			count += decode_gtpv1_gsn_address_ie(buf + count, &value->sgsn_addr_user_traffic);
		} else if (ie_header->type == GTPV1_IE_UTRAN_TRANSPARENT_CONTAINER) {
			count += decode_gtpv1_utran_transparent_container_ie(buf + count, &value->utran_container);
		} else if (ie_header->type == GTPV1_IE_RAB_SETUP_INFO) {
			count += decode_gtpv1_rab_setup_info_ie(buf + count, &value->rab_setup_info);
		} else if (ie_header->type == GTPV1_IE_ADDITIONAL_RAB_SETUP_INFO) {
			count += decode_gtpv1_rab_setup_info_ie(buf + count, &value->add_rab_setup_info);
		} else if (ie_header->type == GTPV1_IE_SGSN_NUMBER) {
			count += decode_gtpv1_sgsn_number_ie(buf + count, &value->sgsn_number);
		} else if (ie_header->type == GTPV1_IE_BSS_CONTAINER) {
			count += decode_gtpv1_bss_container_ie(buf + count, &value->bss_container);
		} else if (ie_header->type == GTPV1_IE_BSSGP_CAUSE) {
			count += decode_gtpv1_bssgp_cause_ie(buf + count, &value->bssgp_cause);
		} else if (ie_header->type == GTPV1_IE_LIST_OF_SET_UP_PFCS) {
			count += decode_gtpv1_list_of_setup_pfcs_ie(buf + count, &value->list_pfcs);
		} else if (ie_header->type == GTPV1_IE_EXTENDED_RANAP_CAUSE) {
			count += decode_gtpv1_extended_ranap_cause_ie(buf + count, &value->ext_ranap_cause);
		} else if (ie_header->type == GTPV1_IE_NODE_IDENTIFIER) {
			count += decode_gtpv1_node_identifier_ie(buf + count, &value->node_id);
		} else if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length) ;
	}
	return count + head_count;
}

int decode_gtpv1_ms_info_change_notification_req(uint8_t *buf, gtpv1_ms_info_change_notification_req_t *value) {

	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0; 
	
	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}
	
	count = 0;
	
	while (count < buf_len) {
	
		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);

		if (ie_header->type == GTPV1_IE_IMSI) {
			count += decode_gtpv1_imsi_ie(buf + count, &value->imsi);
		} else if (ie_header->type == GTPV1_IE_NSAPI) {
			count += decode_gtpv1_nsapi_ie(buf + count, &value->linked_nsapi);	
		} else if (ie_header->type == GTPV1_IE_RAT_TYPE) {
			count += decode_gtpv1_rat_type_ie(buf + count, &value->rat_type);
		} else if (ie_header->type == GTPV1_IE_USER_LOCATION_INFORMATION) {
			count += decode_gtpv1_user_location_information_ie(buf + count, &value->user_location_information);
		} else if (ie_header->type == GTPV1_IE_IMEI_SV) {
			count += decode_gtpv1_imei_ie(buf + count, &value->imei_sv);
		} else if (ie_header->type == GTPV1_IE_EXTENDED_COMMON_FLAG) {
			count += decode_gtpv1_extended_common_flag_ie(buf + count, &value->extended_common_flag);
		} else if (ie_header->type == GTPV1_IE_USER_CSG_INFORMATION) {
			count += decode_gtpv1_user_csg_information_ie(buf + count, &value->user_csg_information);
		} else if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length) ;
	}

	return count + head_count;
}

int decode_gtpv1_ms_info_change_notification_rsp(uint8_t *buf, gtpv1_ms_info_change_notification_rsp_t *value) {

	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0; 
	
	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}
	
	count = 0;
	
	while (count < buf_len) {
	
		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);

		if (ie_header->type == GTPV1_IE_CAUSE) {
			count += decode_gtpv1_cause_ie(buf + count, &value->cause);
		} else if (ie_header->type == GTPV1_IE_IMSI) {
			count += decode_gtpv1_imsi_ie(buf + count, &value->imsi);	
		} else if (ie_header->type == GTPV1_IE_NSAPI) {
			count += decode_gtpv1_nsapi_ie(buf + count, &value->linked_nsapi);
		} else if (ie_header->type == GTPV1_IE_IMEI_SV) {
			count += decode_gtpv1_imei_ie(buf + count, &value->imei_sv);	
		} else if (ie_header->type == GTPV1_IE_MS_INFO_CHANGE_REPORTING_ACTION) {
			count += decode_gtpv1_ms_info_change_reporting_action_ie(buf + count, 
					&value->ms_info_change_reporting_action);
		} else if (ie_header->type == GTPV1_IE_CSG_INFORMATION_REPORTING_ACTION) {
			count += decode_gtpv1_csg_information_reporting_action_ie(buf + count, 
					&value->csg_information_reporting_action);
		} else if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length) ;
	}
	
	return count + head_count;
}

int decode_gtpv1_identification_req(uint8_t *buf, gtpv1_identification_req_t *value){

	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0;

	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}

	count = 0;

	while (count < buf_len){

		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);

		if (ie_header->type == GTPV1_IE_ROUTEING_AREA_IDENTITY) {
			count += decode_gtpv1_routing_area_identity_ie(buf + count, &value->routing_area_identity);
		} else if (ie_header->type == GTPV1_IE_PACKET_TMSI) {
			count += decode_gtpv1_packet_tmsi_ie(buf + count, &value->packet_tmsi);
		} else if (ie_header->type == GTPV1_IE_P_TMSI_SIGNATURE) {
			count += decode_gtpv1_p_tmsi_signature_ie(buf + count, &value->p_tmsi_signature);
		} else if (ie_header->type == GTPV1_IE_GSN_ADDR ) {
			count += decode_gtpv1_gsn_address_ie(buf + count, &value->sgsn_addr_control_plane);
		} else if (ie_header->type == GTPV1_IE_HOP_COUNTER) {
			count += decode_gtpv1_hop_counter_ie(buf + count, &value->hop_counter);
		} else if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length) ;
	}
	return count + head_count;
}

int decode_gtpv1_identification_rsp(uint8_t *buf, gtpv1_identification_rsp_t *value){

	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0;

	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}

	count = 0;

	while (count < buf_len){

		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);

		if (ie_header->type == GTPV1_IE_CAUSE) {
			count += decode_gtpv1_cause_ie(buf + count, &value->cause);
		} else if (ie_header->type == GTPV1_IE_IMSI) {
			count += decode_gtpv1_imsi_ie(buf + count, &value->imsi);
		} else if (ie_header->type == GTPV1_IE_AUTH_TRIPLET) {
			count += decode_gtpv1_auth_triplet_ie(buf + count, &value->auth_triplet);
		} else if (ie_header->type == GTPV1_IE_AUTH_QUINTUPLET) {
			count += decode_gtpv1_auth_quintuplet_ie(buf + count, &value->auth_quintuplet);
		} else if (ie_header->type == GTPV1_IE_UE_USAGE_TYPE) {
			count += decode_gtpv1_ue_usage_type_ie(buf + count, &value->ue_usage_type);
		} else if (ie_header->type == GTPV1_IE_IOV_UPDATES_COUNTER) {
			count += decode_gtpv1_iov_updates_counter_ie(buf + count, &value->iov_updates_counter);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length) ;
	}
	return count + head_count;
}

int decode_gtpv1_relocation_cancel_req(uint8_t *buf, gtpv1_relocation_cancel_req_t *value){

	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0;

	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}

	count = 0;

	while (count < buf_len){

		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);

		if (ie_header->type == GTPV1_IE_IMSI) {
			count += decode_gtpv1_imsi_ie(buf + count, &value->imsi);
		} else if (ie_header->type == GTPV1_IE_IMEI_SV) {
			count += decode_gtpv1_imei_ie(buf + count, &value->imei_sv);
		} else if (ie_header->type == GTPV1_IE_EXTENDED_COMMON_FLAG) {
			count += decode_gtpv1_extended_common_flag_ie(buf + count, &value->extended_common_flag);
		} else if (ie_header->type == GTPV1_IE_EXTENDED_RANAP_CAUSE) {
			count += decode_gtpv1_extended_ranap_cause_ie(buf + count, &value->ext_ranap_cause);
		} else if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length) ;
	}
	return count + head_count;
}

int decode_gtpv1_relocation_cancel_rsp(uint8_t *buf, gtpv1_relocation_cancel_rsp_t *value) {

	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0;

	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}

	count = 0;

	while (count < buf_len){

		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);

		if (ie_header->type == GTPV1_IE_CAUSE) {
			count += decode_gtpv1_cause_ie(buf + count, &value->cause);
		} else if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length) ;
	}

	return count + head_count;
}

int decode_gtpv1_forward_relocation_complete_ack(uint8_t *buf, gtpv1_forward_relocation_complete_ack_t *value) {

	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0;

	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}

	count = 0;

	while (count < buf_len){

		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);

		if (ie_header->type == GTPV1_IE_CAUSE) {
			count += decode_gtpv1_cause_ie(buf + count, &value->cause);
		} else if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length) ;
	}

	return count + head_count;
}


int decode_gtpv1_forward_relocation_complete(uint8_t *buf, gtpv1_forward_relocation_complete_t *value) {

	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0;

	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}

	count = 0;

	while (count < buf_len){

		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);

		if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length) ;
	}

	return count + head_count;
}

int decode_gtpv1_forward_srns_context_ack(uint8_t *buf, gtpv1_forward_srns_context_ack_t *value) {

	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0;

	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}

	count = 0;

	while (count < buf_len){

		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);

		if (ie_header->type == GTPV1_IE_CAUSE) {
			count += decode_gtpv1_cause_ie(buf + count, &value->cause);
		} else if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length) ;
	}

	return count + head_count;
}

int decode_gtpv1_forward_srns_ctxt(uint8_t *buf, gtpv1_forward_srns_ctxt_t *value) {

	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0;

	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}

	count = 0;

	while (count < buf_len){

		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);

		if (ie_header->type == GTPV1_IE_RAB_CONTEXT) {
			count += decode_gtpv1_rab_context_ie(buf + count, &value->rab_context);
		} else if (ie_header->type == GTPV1_IE_SRC_RNC_PDCP_CTXT_INFO) {
			count += decode_gtpv1_src_rnc_pdcp_ctxt_info_ie(buf + count, &value->pdcp_ctxt);
		} else if (ie_header->type == GTPV1_IE_PDU_NUMBERS) {
			count += decode_gtpv1_pdu_numbers_ie(buf + count, &value->pdu_num);
		} else if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length) ;
	}

	return count + head_count;
}

int decode_gtpv1_sgsn_context_ack(uint8_t *buf, gtpv1_sgsn_context_ack_t *value) {

	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0;

	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}

	count = 0;

	while (count < buf_len){

		gtpv1_ie_header_t *ie_header = (gtpv1_ie_header_t *) (buf + count);

		if (ie_header->type == GTPV1_IE_CAUSE) {
			count += decode_gtpv1_cause_ie(buf + count, &value->cause);	
		} else if (ie_header->type == GTPV1_IE_TEID_DATA_2) {
			count += decode_gtpv1_teid_data_2_ie(buf + count, &value->teid_2);
		} else if (ie_header->type == GTPV1_IE_GSN_ADDR) {
			count += decode_gtpv1_gsn_address_ie(buf + count, &value->sgsn_addr_user_traffic);	
		} else if (ie_header->type == GTPV1_IE_SGSN_NUMBER) {
			count += decode_gtpv1_sgsn_number_ie(buf + count, &value->sgsn_number);
		} else if (ie_header->type == GTPV1_IE_NODE_IDENTIFIER) {
			count += decode_gtpv1_node_identifier_ie(buf + count, &value->node_id);
		} else if (ie_header->type == GTPV1_IE_PRIVATE_EXTENSION) {
			count += decode_gtpv1_private_extension_ie(buf + count, &value->private_extension);
		} else
			count += sizeof(gtpv1_ie_header_t) + ntohs(ie_header->length) ;
	}

	return count + head_count;
}

int decode_gtpv1_supported_extension_headers_notification(uint8_t *buf, gtpv1_supported_extension_headers_notification_t *value) {

	uint16_t count = 0;
	uint16_t buf_len = 0;
	uint16_t head_count = 0;

	if(buf == NULL|| value == NULL) {
		return -1;
	}

	count += decode_gtpv1_header(buf + count, &value->header);
	head_count = count;

	if (value->header.extension_header == 1 || value->header.seq_num_flag == 1 || value->header.n_pdu_flag == 1) {
		buf_len = value->header.message_len - 4;
		buf += sizeof(gtpv1_header_t);
	} else {
		buf_len = value->header.message_len;
		buf += sizeof(gtpv1_header_t) - 4;
	}

	count = 0;

	while (count < buf_len){

		gtpv1_extension_header_type_list_ie_t *ext_header = (gtpv1_extension_header_type_list_ie_t*) (buf + count);

		if (ext_header->type == GTPV1_IE_EXTENSION_HEADER_TYPE_LIST) {
			count += decode_gtpv1_extension_header_type_list_ie(buf + count, &value->ext_header_list);
		} else
			count += sizeof(ext_header) + ntohs(ext_header->length) ;
	}

	return count + head_count;
}
