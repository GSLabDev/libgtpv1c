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

#include "../include/gtpv1_messages_encoder.h"

int encode_gtpv1_echo_req(gtpv1_echo_req_t *value, uint8_t *buf) {

	uint16_t encoded = 0;
	
	if (value == NULL || buf == NULL) {
		return -1;
	}

	encoded += encode_gtpv1_header(&value->header, buf +encoded);
	
	if ((value->private_extension.header.type == GTPV1_IE_PRIVATE_EXTENSION) &&
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension),
				buf + encoded);
	}
	
	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);
	return encoded;
}

int encode_gtpv1_echo_rsp(gtpv1_echo_rsp_t *value, uint8_t *buf) {

	uint16_t encoded = 0;

	if(value == NULL || buf == NULL) {
		return -1;
	}

	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if (value->recovery.header.type == GTPV1_IE_RECOVERY) {
		encoded += encode_gtpv1_recovery_ie(&(value->recovery),
				buf + encoded);
	}

	if ((value->private_extension.header.type == GTPV1_IE_PRIVATE_EXTENSION) &&
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension),
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;
}

int encode_gtpv1_version_not_supported(gtpv1_version_not_supported_t *value, uint8_t *buf) {

	uint16_t encoded = 0;
	
	if(value == NULL || buf == NULL) {
		return -1;
	}
	
	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	return encoded;
}

int encode_gtpv1_create_pdp_ctxt_req(gtpv1_create_pdp_ctxt_req_t *value, uint8_t *buf) {
	
	uint16_t encoded = 0;

	if(value == NULL || buf == NULL) {
		return -1;
	}

	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if (value->imsi.header.type == GTPV1_IE_IMSI) {
		encoded += encode_gtpv1_imsi_ie(&(value->imsi), 
				buf + encoded);
	}

	if (value->selection_mode.header.type == GTPV1_IE_SELECTION_MODE) {
		encoded += encode_gtpv1_selection_mode_ie(&(value->selection_mode), 
				buf + encoded);
	}

	if (value->nsapi.header.type == GTPV1_IE_NSAPI) {
		encoded += encode_gtpv1_nsapi_ie(&(value->nsapi), 
				buf + encoded);
	}

	if (value->tunn_endpt_idnt_data_1.header.type == GTPV1_IE_TEID_DATA_1) {
		encoded += encode_gtpv1_teid_ie(&(value->tunn_endpt_idnt_data_1), 
				buf + encoded);
	}

	if (value->tunn_endpt_idnt_control_plane.header.type == GTPV1_IE_TEID_CONTROL_PLANE) {
		encoded += encode_gtpv1_teid_ie(&(value->tunn_endpt_idnt_control_plane), 
				buf + encoded);
	}

	if (value->linked_nsapi.header.type == GTPV1_IE_NSAPI) {
		encoded += encode_gtpv1_nsapi_ie(&(value->linked_nsapi), 
				buf + encoded);
	}

	if (value->chrgng_char.header.type == GTPV1_IE_CHRGNG_CHAR) {
		encoded += encode_gtpv1_chrgng_char_ie(&(value->chrgng_char), 
				buf + encoded);
	}

	if ((value->end_user_address.header.type == GTPV1_IE_END_USER_ADDR) && 
			(value->end_user_address.header.length >= 0)) {
		encoded += encode_gtpv1_end_user_address_ie(&(value->end_user_address),
				buf + encoded);
	}

	if ((value->protocol_config_options.header.type == GTPV1_IE_PROTOCOL_CONFIG_OPTIONS) &&
			(value->protocol_config_options.header.length >= 0)) {
		encoded += encode_gtpv1_protocol_config_options_ie(&(value->protocol_config_options),
				buf + encoded);
	}

	if ((value->apn.header.type == GTPV1_IE_APN) && 
			(value->apn.header.length >= 0 )) {
		encoded += encode_gtpv1_apn_ie(&(value->apn), 
				buf + encoded);
	}

	if ((value->sgsn_address_for_signalling.header.type == GTPV1_IE_GSN_ADDR) && 
			(value->sgsn_address_for_signalling.header.length >= 0)) {
		encoded += encode_gtpv1_gsn_address_ie(&(value->sgsn_address_for_signalling), 
				buf + encoded);
	}

	if ((value->sgsn_address_for_user_traffic.header.type == GTPV1_IE_GSN_ADDR) && 
			(value->sgsn_address_for_user_traffic.header.length >= 0)) {
		encoded += encode_gtpv1_gsn_address_ie(&(value->sgsn_address_for_user_traffic), 
				buf + encoded);
	}

	if ((value->msisdn.header.type == GTPV1_IE_MSISDN) && 
			(value->msisdn.header.length >= 0)) {
		encoded += encode_gtpv1_msisdn_ie(&(value->msisdn), 
				buf + encoded);
	}

	if ((value->qos_profile.header.type == GTPV1_IE_QOS) && 
			(value->qos_profile.header.length >= 0)) {
		encoded += encode_gtpv1_qos_ie(&(value->qos_profile), 
				buf + encoded);
	}

	if ((value->tft.header.type == GTPV1_IE_TFT) && 
			(value->tft.header.length >= 0)) {
		encoded += encode_gtpv1_traffic_flow_tmpl_ie(&(value->tft), 
				buf + encoded);
	}

	if ((value->imei_sv.header.type == GTPV1_IE_IMEI_SV) && 
			(value->imei_sv.header.length >= 0)) {
		encoded += encode_gtpv1_imei_ie(&(value->imei_sv), 
				buf + encoded);
	}

	if ((value->rat_type.header.type == GTPV1_IE_RAT_TYPE) && 
			(value->rat_type.header.length >= 0)) {
		encoded += encode_gtpv1_rat_type_ie(&(value->rat_type), 
				buf + encoded);
	}

	if (value->routing_area_identity.header.type == GTPV1_IE_ROUTEING_AREA_IDENTITY) {
		encoded += encode_gtpv1_routing_area_identity_ie(&(value->routing_area_identity),
				buf + encoded);
	}

	if (value->trace_reference.header.type == GTPV1_IE_TRACE_REFERENCE) {
		encoded += encode_gtpv1_trace_reference_ie(&(value->trace_reference), 
				buf + encoded);
	}

	if (value->trace_type.header.type == GTPV1_IE_TRACE_TYPE) {
		encoded += encode_gtpv1_trace_type_ie(&(value->trace_type), 
				buf + encoded);
	}

	if ((value->trigger_id.header.type == GTPV1_IE_TRIGGER_ID) && 
			(value->trigger_id.header.length >= 0)) {
		encoded += encode_gtpv1_trigger_id_ie(&(value->trigger_id), 
				buf + encoded);
	}

	if ((value->omc_identity.header.type == GTPV1_IE_OMC_IDENTITY) && 
			(value->omc_identity.header.length >= 0)) {
		encoded += encode_gtpv1_omc_identity_ie(&(value->omc_identity ), 
				buf + encoded);
	}

	if ((value->user_location_information.header.type == 
				GTPV1_IE_USER_LOCATION_INFORMATION) && 
			(value->user_location_information.header.length >= 0)) {
		encoded += encode_gtpv1_user_location_information_ie(
				&(value->user_location_information ), buf + encoded);
	}

	if ((value->ms_time_zone.header.type == GTPV1_IE_MS_TIME_ZONE) && 
			(value->ms_time_zone.header.length >= 0)) {
		encoded += encode_gtpv1_ms_time_zone_ie(&(value->ms_time_zone), 
				buf + encoded);
	}

	if ((value->camel_charging_information_container.header.type == 
				GTPV1_IE_CAMEL_CHARGING_INFORMATION_CONTAINER) && 
			(value->camel_charging_information_container.header.length >= 0)) {
		encoded += encode_gtpv1_camel_charging_information_container_ie(
				&(value->camel_charging_information_container), buf + encoded);
	}

	if ((value->additional_trace_information.header.type == 
				GTPV1_IE_ADDITIONAL_TRACE_INFORMATION) && 
			(value->additional_trace_information.header.length >= 0)) {
		encoded += encode_gtpv1_additional_trace_information_ie(
				&(value->additional_trace_information), buf + encoded);
	}

	if ((value->correlation_id.header.type == GTPV1_IE_CORRELATION_ID) && 
			(value->correlation_id.header.length >= 0)) {
		encoded += encode_gtpv1_correlation_id_ie(&(value->correlation_id), 
				buf + encoded);
	}

	if ((value->user_csg_information.header.type == GTPV1_IE_USER_CSG_INFORMATION) && 
			(value->user_csg_information.header.length >= 0)) {
		encoded += encode_gtpv1_user_csg_information_ie(&(value->user_csg_information), 
				buf + encoded);
	}

	if ((value->signalling_priority_indication.header.type == 
				GTPV1_IE_SIGNALLING_PRIORITY_INDICATION) && 
			(value->signalling_priority_indication.header.length >= 0)) {
		encoded += encode_gtpv1_signalling_priority_indication_ie(
				&(value->signalling_priority_indication), buf + encoded);
	}

	if ((value->cn_operator_selection_entity.header.type == 
				GTPV1_IE_CN_OPERATOR_SELECTION_ENTITY) && 
			(value->cn_operator_selection_entity.header.length >= 0)) {
		encoded += encode_gtpv1_cn_operator_selection_entity_ie(
				&(value->cn_operator_selection_entity), buf + encoded);
	}

	if ((value->mapped_ue_usage_type.header.type == GTPV1_IE_MAPPED_UE_USAGE_TYPE) && 
			(value->mapped_ue_usage_type.header.length >= 0)) {
		encoded += encode_gtpv1_mapped_ue_usage_type_ie(&(value->mapped_ue_usage_type), 
				buf + encoded);
	}

	if ((value->up_function_selection_indication.header.type == 
				GTPV1_IE_UP_FUNCTION_SELECTION_INDICATION) && 
			(value->up_function_selection_indication.header.length >= 0)) {
		encoded += encode_gtpv1_up_function_selection_indication_ie(
				&(value->up_function_selection_indication), buf + encoded);
	}

	if (value->recovery.header.type == GTPV1_IE_RECOVERY) {
		encoded += encode_gtpv1_recovery_ie(&(value->recovery), 
				buf + encoded);
	}

	if ((value->common_flag.header.type == GTPV1_IE_COMMON_FLAG) && 
			(value->common_flag.header.length >= 0)) {
		encoded += encode_gtpv1_common_flag_ie(&(value->common_flag), 
				buf + encoded);
	}

	if ((value->apn_restriction.header.type == GTPV1_IE_APN_RESTRICTION) && 
			(value->apn_restriction.header.length >= 0)) {
		encoded += encode_gtpv1_apn_restriction_ie(&(value->apn_restriction), 
				buf + encoded);
	}

	if ((value->evolved_allocation_retention_priority_1.header.type == 
				GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_I) && 
			(value->evolved_allocation_retention_priority_1.header.length >= 0)) {
		encoded += encode_gtpv1_evolved_allocation_retention_priority_1_ie(
				&(value->evolved_allocation_retention_priority_1), buf + encoded);
	}

	if ((value->extended_common_flag.header.type == GTPV1_IE_EXTENDED_COMMON_FLAG) && 
			(value->extended_common_flag.header.length >= 0)) {
		encoded += encode_gtpv1_extended_common_flags_ie(&(value->extended_common_flag), 
				buf + encoded);
	}

	if ((value->apn_ambr.header.type == GTPV1_IE_APN_AMBR) && 
			(value->apn_ambr.header.length >= 0)) {
		encoded += encode_gtpv1_apn_ambr_ie(&(value->apn_ambr), 
				buf + encoded);
	}

	if ((value->private_extension.header.type == GTPV1_IE_PRIVATE_EXTENSION) && 
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension), 
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;
}

int encode_gtpv1_create_pdp_ctxt_rsp(gtpv1_create_pdp_ctxt_rsp_t *value, uint8_t *buf) {
	
	uint16_t encoded = 0;
	
	if(value == NULL || buf == NULL) {
		return -1;
	}

	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if (value->cause.header.type == GTPV1_IE_CAUSE) {
		encoded += encode_gtpv1_cause_ie(&(value->cause), 
				buf + encoded);
	}

	if (value->reordering_req.header.type == GTPV1_IE_REORDERING_REQ) {
		encoded += encode_gtpv1_reordering_req_ie(&(value->reordering_req), 
				buf + encoded);
	}

	if (value->recovery.header.type == GTPV1_IE_RECOVERY) {
		encoded += encode_gtpv1_recovery_ie(&(value->recovery), 
				buf + encoded);
	}

	if (value->tunn_endpt_idnt_data_1.header.type == GTPV1_IE_TEID_DATA_1) {
		encoded += encode_gtpv1_teid_ie(&(value->tunn_endpt_idnt_data_1), 
				buf + encoded);
	}

	if (value->tunn_endpt_idnt_control_plane.header.type == GTPV1_IE_TEID_CONTROL_PLANE) {
		encoded += encode_gtpv1_teid_ie(&(value->tunn_endpt_idnt_control_plane), 
				buf + encoded);
	}

	if (value->nsapi.header.type == GTPV1_IE_NSAPI) {
		encoded += encode_gtpv1_nsapi_ie(&(value->nsapi), 
				buf + encoded);
	}

	if (value->charging_id.header.type == GTPV1_IE_CHARGING_ID) {
		encoded += encode_gtpv1_charging_id_ie(&(value->charging_id), 
				buf + encoded);
	}

	if ((value->end_user_address.header.type == GTPV1_IE_END_USER_ADDR) && 
			(value->end_user_address.header.length >= 0)) {
		encoded += encode_gtpv1_end_user_address_ie(&(value->end_user_address), 
				buf + encoded);
	}

	if ((value->protocol_config_options.header.type == GTPV1_IE_PROTOCOL_CONFIG_OPTIONS) && 
			(value->protocol_config_options.header.length >= 0)) {
		encoded += encode_gtpv1_protocol_config_options_ie(&(value->protocol_config_options), 
				buf + encoded);
	}

	if ((value->gsn_addr_1.header.type == GTPV1_IE_GSN_ADDR) && 
			(value->gsn_addr_1.header.length >= 0)) {
		encoded += encode_gtpv1_gsn_address_ie(&(value->gsn_addr_1), 
				buf + encoded);
	}

	if ((value->gsn_addr_2.header.type == GTPV1_IE_GSN_ADDR) && 
			(value->gsn_addr_2.header.length >= 0)) {
		encoded += encode_gtpv1_gsn_address_ie(&(value->gsn_addr_2), 
				buf + encoded);
	}

	if ((value->gsn_addr_3.header.type == GTPV1_IE_GSN_ADDR) && 
			(value->gsn_addr_3.header.length >= 0)) {
		encoded += encode_gtpv1_gsn_address_ie(&(value->gsn_addr_3), 
				buf + encoded);
	}

	if ((value->gsn_addr_4.header.type == GTPV1_IE_GSN_ADDR) && 
			(value->gsn_addr_4.header.length >= 0)) {
		encoded += encode_gtpv1_gsn_address_ie(&(value->gsn_addr_4), 
				buf + encoded);
	}

	if ((value->qos_profile.header.type == GTPV1_IE_QOS) && 
			(value->qos_profile.header.length >= 0)) {
		encoded += encode_gtpv1_qos_ie(&(value->qos_profile), 
				buf + encoded);
	}

	if ((value->charging_gateway_addr.header.type == GTPV1_IE_CHARGING_GATEWAY_ADDR) && 
			(value->charging_gateway_addr.header.length >= 0)) {
		encoded += encode_gtpv1_charging_gateway_addr_ie(&(value->charging_gateway_addr), 
				buf + encoded);
	}

	if ((value->alt_charging_gateway_addr.header.type == GTPV1_IE_CHARGING_GATEWAY_ADDR) && 
			(value->alt_charging_gateway_addr.header.length >= 0)) {
		encoded += encode_gtpv1_charging_gateway_addr_ie(&(value->alt_charging_gateway_addr), 
				buf + encoded);
	}

	if ((value->common_flag.header.type == GTPV1_IE_COMMON_FLAG) && 
			(value->common_flag.header.length >= 0)) {
		encoded += encode_gtpv1_common_flag_ie(&(value->common_flag), 
				buf + encoded);
	}

	if ((value->apn_restriction.header.type == GTPV1_IE_APN_RESTRICTION) && 
			(value->apn_restriction.header.length >= 0)) {
		encoded += encode_gtpv1_apn_restriction_ie(&(value->apn_restriction), 
				buf + encoded);
	}

	if ((value->ms_info_change_reporting_action.header.type == 
				GTPV1_IE_MS_INFO_CHANGE_REPORTING_ACTION) && 
			(value->ms_info_change_reporting_action.header.length >= 0)) {
		encoded += encode_gtpv1_ms_info_change_reporting_action_ie(
				&(value->ms_info_change_reporting_action), buf + encoded);

	}

	if ((value->bearer_control.header.type == GTPV1_IE_BEARER_CONTROL_MODE) && 
			(value->bearer_control.header.length >= 0)) {
		encoded += encode_gtpv1_bearer_control_mode_ie(&(value->bearer_control), 
				buf + encoded);

	}

	if ((value->evolved_allocation_retention_priority_1.header.type == 
				GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_I) && 
			(value->evolved_allocation_retention_priority_1.header.length >= 0)) {
		encoded += encode_gtpv1_evolved_allocation_retention_priority_1_ie(
				&(value->evolved_allocation_retention_priority_1), buf + encoded);

	}

	if ((value->extended_common_flag.header.type == GTPV1_IE_EXTENDED_COMMON_FLAG) && 
			(value->extended_common_flag.header.length >= 0)) {
		encoded += encode_gtpv1_extended_common_flags_ie(&(value->extended_common_flag), 
				buf + encoded);
	}

	if ((value->csg_information_reporting_action.header.type == 
				GTPV1_IE_CSG_INFORMATION_REPORTING_ACTION) && 
			(value->csg_information_reporting_action.header.length >= 0)) {
		encoded += encode_gtpv1_csg_information_reporting_action_ie(
				&(value->csg_information_reporting_action), buf + encoded);
	}

	if ((value->apn_ambr.header.type == GTPV1_IE_APN_AMBR) && 
			(value->apn_ambr.header.length >= 0)) {
		encoded += encode_gtpv1_apn_ambr_ie(&(value->apn_ambr), 
				buf + encoded);

	}

	if ((value->ggsn_back_off_time.header.type == GTPV1_IE_GGSN_BACK_OFF_TIME) && 
			(value->ggsn_back_off_time.header.length >= 0)) {
		encoded += encode_gtpv1_ggsn_back_off_time_ie(&(value->ggsn_back_off_time), 
				buf + encoded);
	}

	if ((value->extended_common_flag_2.header.type == 
				GTPV1_IE_EXTENDED_COMMON_FLAGS_II) && 
			(value->extended_common_flag_2.header.length >= 0)) {
		encoded += encode_gtpv1_extended_common_flag_2_ie(
				&(value->extended_common_flag_2), buf + encoded);
	}


	if ((value->private_extension.header.type == GTPV1_IE_PRIVATE_EXTENSION) && 
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension), 
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;
}

int encode_gtpv1_update_pdp_ctxt_req_sgsn(gtpv1_update_pdp_ctxt_req_sgsn_t *value, uint8_t *buf)
{
	uint16_t encoded = 0;
	
	if(value == NULL || buf == NULL) {
		return -1;
	}

	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if (value->imsi.header.type == GTPV1_IE_IMSI) {
		encoded += encode_gtpv1_imsi_ie(&(value->imsi), buf + encoded);
	}

	if (value->routing_area_identity.header.type == GTPV1_IE_ROUTEING_AREA_IDENTITY) {
		encoded += encode_gtpv1_routing_area_identity_ie(&(value->routing_area_identity), 
				buf + encoded);
	}

	if (value->recovery.header.type == GTPV1_IE_RECOVERY) {
		encoded += encode_gtpv1_recovery_ie(&(value->recovery), 
				buf + encoded);
	}

	if (value->tunn_endpt_idnt_data_1.header.type == GTPV1_IE_TEID_DATA_1) {
		encoded += encode_gtpv1_teid_ie(&(value->tunn_endpt_idnt_data_1), 
				buf + encoded);
	}

	if (value->tunn_endpt_idnt_control_plane.header.type == GTPV1_IE_TEID_CONTROL_PLANE) {
		encoded += encode_gtpv1_teid_ie(&(value->tunn_endpt_idnt_control_plane), 
				buf + encoded);
	}

	if (value->nsapi.header.type == GTPV1_IE_NSAPI) {
		encoded += encode_gtpv1_nsapi_ie(&(value->nsapi), 
				buf + encoded);
	}

	if (value->trace_reference.header.type == GTPV1_IE_TRACE_REFERENCE) {
		encoded += encode_gtpv1_trace_reference_ie(&(value->trace_reference), 
				buf + encoded);
	}

	if (value->trace_type.header.type == GTPV1_IE_TRACE_TYPE) {
		encoded += encode_gtpv1_trace_type_ie(&(value->trace_type), 
				buf + encoded);
	}

	if ((value->protocol_config_options.header.type == GTPV1_IE_PROTOCOL_CONFIG_OPTIONS) && 
			(value->protocol_config_options.header.length >= 0)) {
		encoded += encode_gtpv1_protocol_config_options_ie(&(value->protocol_config_options), 
				buf + encoded);
	}

	if ((value->gsn_addr_1.header.type == GTPV1_IE_GSN_ADDR) && 
			(value->gsn_addr_1.header.length >= 0)) {
		encoded += encode_gtpv1_gsn_address_ie(&(value->gsn_addr_1), 
				buf + encoded);
	}

	if ((value->gsn_addr_2.header.type == GTPV1_IE_GSN_ADDR) && 
			(value->gsn_addr_2.header.length >= 0)) {
		encoded += encode_gtpv1_gsn_address_ie(&(value->gsn_addr_2), 
				buf + encoded);
	}

	if ((value->gsn_addr_3.header.type == GTPV1_IE_GSN_ADDR) && 
			(value->gsn_addr_3.header.length >= 0)) {
		encoded += encode_gtpv1_gsn_address_ie(&(value->gsn_addr_3), 
				buf + encoded);
	}

	if ((value->gsn_addr_4.header.type == GTPV1_IE_GSN_ADDR) && 
			(value->gsn_addr_4.header.length >= 0)) {
		encoded += encode_gtpv1_gsn_address_ie(&(value->gsn_addr_4), 
				buf + encoded);
	}

	if ((value->qos_profile.header.type == GTPV1_IE_QOS) && 
			(value->qos_profile.header.length >= 0)) {
		encoded += encode_gtpv1_qos_ie(&(value->qos_profile), 
				buf + encoded);
	}

	if ((value->tft.header.type == GTPV1_IE_TFT) && 
			(value->tft.header.length >= 0)) {
		encoded += encode_gtpv1_traffic_flow_tmpl_ie(&(value->tft), 
				buf + encoded);
	}

	if ((value->trigger_id.header.type == GTPV1_IE_TRIGGER_ID) && 
			(value->trigger_id.header.length >= 0)) {
		encoded += encode_gtpv1_trigger_id_ie(&(value->trigger_id), 
				buf + encoded);
	}

	if ((value->omc_identity.header.type == GTPV1_IE_OMC_IDENTITY) && 
			(value->omc_identity.header.length >= 0)) {
		encoded += encode_gtpv1_omc_identity_ie(&(value->omc_identity ), 
				buf + encoded);
	}

	if ((value->common_flag.header.type == GTPV1_IE_COMMON_FLAG) && 
			(value->common_flag.header.length >= 0)) {
		encoded += encode_gtpv1_common_flag_ie(&(value->common_flag), 
				buf + encoded);
	}

	if ((value->rat_type.header.type == GTPV1_IE_RAT_TYPE) && 
			(value->rat_type.header.length >= 0)) {
		encoded += encode_gtpv1_rat_type_ie(&(value->rat_type), 
				buf + encoded);
	}

	if ((value->user_location_information.header.type == GTPV1_IE_USER_LOCATION_INFORMATION) && 
			(value->user_location_information.header.length >= 0)) {
		encoded += encode_gtpv1_user_location_information_ie(&(value->user_location_information ), 
				buf + encoded);
	}

	if ((value->ms_time_zone.header.type == GTPV1_IE_MS_TIME_ZONE) && 
			(value->ms_time_zone.header.length >= 0)) {
		encoded += encode_gtpv1_ms_time_zone_ie(&(value->ms_time_zone), 
				buf + encoded);
	}

	if ((value->additional_trace_information.header.type == GTPV1_IE_ADDITIONAL_TRACE_INFORMATION) && 
			(value->additional_trace_information.header.length >= 0)) {
		encoded += encode_gtpv1_additional_trace_information_ie(&(value->additional_trace_information)
				, buf + encoded);
	}
	
	if ((value->direct_tunnel_flag.header.type == GTPV1_IE_DIRECT_TUNNEL_FLAG) &&
			(value->direct_tunnel_flag.header.length >= 0)) {
		encoded += encode_gtpv1_direct_tunnel_flag_ie(&(value->direct_tunnel_flag),
				buf + encoded);
	}

	if ((value->evolved_allocation_retention_priority_1.header.type == 
				GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_I) && 
			(value->evolved_allocation_retention_priority_1.header.length >= 0)) {
		encoded += encode_gtpv1_evolved_allocation_retention_priority_1_ie(
				&(value->evolved_allocation_retention_priority_1), buf + encoded);
	}

	if ((value->extended_common_flag.header.type == GTPV1_IE_EXTENDED_COMMON_FLAG) && 
			(value->extended_common_flag.header.length >= 0)) {
		encoded += encode_gtpv1_extended_common_flags_ie(&(value->extended_common_flag), 
				buf + encoded);
	}

	if ((value->user_csg_information.header.type == GTPV1_IE_USER_CSG_INFORMATION) && 
			(value->user_csg_information.header.length >= 0)) {
		encoded += encode_gtpv1_user_csg_information_ie(&(value->user_csg_information), 
				buf + encoded);
	}

	if ((value->apn_ambr.header.type == GTPV1_IE_APN_AMBR) && 
			(value->apn_ambr.header.length >= 0)) {
		encoded += encode_gtpv1_apn_ambr_ie(&(value->apn_ambr), 
				buf + encoded);
	}

	if ((value->signalling_priority_indication.header.type == 
				GTPV1_IE_SIGNALLING_PRIORITY_INDICATION) && 
			(value->signalling_priority_indication.header.length >= 0)) {
		encoded += encode_gtpv1_signalling_priority_indication_ie(
				&(value->signalling_priority_indication), buf + encoded);
	}

	if ((value->cn_operator_selection_entity.header.type == 
				GTPV1_IE_CN_OPERATOR_SELECTION_ENTITY) && 
			(value->cn_operator_selection_entity.header.length >= 0)) {
		encoded += encode_gtpv1_cn_operator_selection_entity_ie(
				&(value->cn_operator_selection_entity), buf + encoded);
	}

	if ((value->imei_sv.header.type == GTPV1_IE_IMEI_SV) && 
			(value->imei_sv.header.length >= 0)) {
		encoded += encode_gtpv1_imei_ie(&(value->imei_sv), 
				buf + encoded);
	}

	if ((value->private_extension.header.type == GTPV1_IE_PRIVATE_EXTENSION) && 
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension), 
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;
}

int encode_gtpv1_update_pdp_ctxt_req_ggsn(gtpv1_update_pdp_ctxt_req_ggsn_t *value, uint8_t *buf)
{
	uint16_t encoded = 0;
	
	if(value == NULL || buf == NULL) {
		return -1;
	}

	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if (value->imsi.header.type == GTPV1_IE_IMSI) {
		encoded += encode_gtpv1_imsi_ie(&(value->imsi), buf + encoded);
	}

	if (value->recovery.header.type == GTPV1_IE_RECOVERY) {
		encoded += encode_gtpv1_recovery_ie(&(value->recovery), 
				buf + encoded);
	}

	if (value->nsapi.header.type == GTPV1_IE_NSAPI) {
		encoded += encode_gtpv1_nsapi_ie(&(value->nsapi), 
				buf + encoded);
	}

	if ((value->end_user_address.header.type == GTPV1_IE_END_USER_ADDR) &&
			(value->end_user_address.header.length >= 0)) {
		encoded += encode_gtpv1_end_user_address_ie(&(value->end_user_address),
				buf + encoded);
	}

	if ((value->protocol_config_options.header.type == GTPV1_IE_PROTOCOL_CONFIG_OPTIONS) && 
			(value->protocol_config_options.header.length >= 0)) {
		encoded += encode_gtpv1_protocol_config_options_ie(&(value->protocol_config_options), 
				buf + encoded);
	}

	if ((value->qos_profile.header.type == GTPV1_IE_QOS) && 
			(value->qos_profile.header.length >= 0)) {
		encoded += encode_gtpv1_qos_ie(&(value->qos_profile), 
				buf + encoded);
	}

	if ((value->tft.header.type == GTPV1_IE_TFT) && 
			(value->tft.header.length >= 0)) {
		encoded += encode_gtpv1_traffic_flow_tmpl_ie(&(value->tft), 
				buf + encoded);
	}

	if ((value->common_flag.header.type == GTPV1_IE_COMMON_FLAG) && 
			(value->common_flag.header.length >= 0)) {
		encoded += encode_gtpv1_common_flag_ie(&(value->common_flag), 
				buf + encoded);
	}

	if ((value->apn_restriction.header.type == GTPV1_IE_APN_RESTRICTION) &&
			(value->apn_restriction.header.length >= 0)) {
		encoded += encode_gtpv1_apn_restriction_ie(&(value->apn_restriction),
				buf + encoded);
	}

	if ((value->ms_info_change_reporting_action.header.type ==
			GTPV1_IE_MS_INFO_CHANGE_REPORTING_ACTION) &&
			(value->ms_info_change_reporting_action.header.length >= 0)) {
		encoded += encode_gtpv1_ms_info_change_reporting_action_ie(
				&(value->ms_info_change_reporting_action), buf + encoded);
	}

	if ((value->direct_tunnel_flag.header.type == GTPV1_IE_DIRECT_TUNNEL_FLAG) &&
			(value->direct_tunnel_flag.header.length >= 0)) {
		encoded += encode_gtpv1_direct_tunnel_flag_ie(&(value->direct_tunnel_flag),
				buf + encoded);
	}

	if ((value->bearer_control.header.type == GTPV1_IE_BEARER_CONTROL_MODE) &&
			(value->bearer_control.header.length >= 0)) {
		encoded += encode_gtpv1_bearer_control_mode_ie(&(value->bearer_control),
				buf + encoded);
	}

	if ((value->evolved_allocation_retention_priority_1.header.type == 
				GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_I) && 
			(value->evolved_allocation_retention_priority_1.header.length >= 0)) {
		encoded += encode_gtpv1_evolved_allocation_retention_priority_1_ie(
				&(value->evolved_allocation_retention_priority_1), buf + encoded);
	}

	if ((value->extended_common_flag.header.type == GTPV1_IE_EXTENDED_COMMON_FLAG) && 
			(value->extended_common_flag.header.length >= 0)) {
		encoded += encode_gtpv1_extended_common_flags_ie(&(value->extended_common_flag), 
				buf + encoded);
	}

	if ((value->csg_information_reporting_action.header.type ==
			GTPV1_IE_CSG_INFORMATION_REPORTING_ACTION) &&
			(value->csg_information_reporting_action.header.length >= 0)) {
		encoded += encode_gtpv1_csg_information_reporting_action_ie(
				&(value->csg_information_reporting_action), buf + encoded);
	}

	if ((value->apn_ambr.header.type == GTPV1_IE_APN_AMBR) && 
			(value->apn_ambr.header.length >= 0)) {
		encoded += encode_gtpv1_apn_ambr_ie(&(value->apn_ambr), 
				buf + encoded);
	}

	if ((value->private_extension.header.type == GTPV1_IE_PRIVATE_EXTENSION) && 
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension), 
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;
}

int encode_gtpv1_update_pdp_ctxt_rsp_ggsn(gtpv1_update_pdp_ctxt_rsp_ggsn_t *value, uint8_t *buf)
{	
	uint16_t encoded = 0;

	if(value == NULL || buf == NULL) {
		return -1;
	}

	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if (value->cause.header.type == GTPV1_IE_CAUSE) {
		encoded += encode_gtpv1_cause_ie(&(value->cause), 
				buf + encoded);
	}

	if (value->recovery.header.type == GTPV1_IE_RECOVERY) {
		encoded += encode_gtpv1_recovery_ie(&(value->recovery), 
				buf + encoded);
	}

	if (value->tunn_endpt_idnt_data_1.header.type == GTPV1_IE_TEID_DATA_1) {
		encoded += encode_gtpv1_teid_ie(&(value->tunn_endpt_idnt_data_1), 
				buf + encoded);
	}

	if (value->tunn_endpt_idnt_control_plane.header.type == GTPV1_IE_TEID_CONTROL_PLANE) {
		encoded += encode_gtpv1_teid_ie(&(value->tunn_endpt_idnt_control_plane), 
				buf + encoded);
	}

	if (value->charging_id.header.type == GTPV1_IE_CHARGING_ID) {
		encoded += encode_gtpv1_charging_id_ie(&(value->charging_id), 
				buf + encoded);
	}

	if ((value->protocol_config_options.header.type == 
				GTPV1_IE_PROTOCOL_CONFIG_OPTIONS) && 
			(value->protocol_config_options.header.length >= 0)) {
		encoded += encode_gtpv1_protocol_config_options_ie(&(value->protocol_config_options),
				buf + encoded);
	}

	if ((value->gsn_addr_1.header.type == GTPV1_IE_GSN_ADDR) && 
			(value->gsn_addr_1.header.length >= 0)) {
		encoded += encode_gtpv1_gsn_address_ie(&(value->gsn_addr_1), 
				buf + encoded);
	}

	if ((value->gsn_addr_2.header.type == GTPV1_IE_GSN_ADDR) && 
			(value->gsn_addr_2.header.length >= 0)) {
		encoded += encode_gtpv1_gsn_address_ie(&(value->gsn_addr_2), 
				buf + encoded);
	}

	if ((value->gsn_addr_3.header.type == GTPV1_IE_GSN_ADDR) && 
			(value->gsn_addr_3.header.length >= 0)) {
		encoded += encode_gtpv1_gsn_address_ie(&(value->gsn_addr_3), 
				buf + encoded);
	}

	if ((value->gsn_addr_4.header.type == GTPV1_IE_GSN_ADDR) && 
			(value->gsn_addr_4.header.length >= 0)) {
		encoded += encode_gtpv1_gsn_address_ie(&(value->gsn_addr_4), 
				buf + encoded);
	}

	if ((value->qos_profile.header.type == GTPV1_IE_QOS) && 
			(value->qos_profile.header.length >= 0)) {
		encoded += encode_gtpv1_qos_ie(&(value->qos_profile), 
				buf + encoded);
	}

	if ((value->charging_gateway_addr.header.type == GTPV1_IE_CHARGING_GATEWAY_ADDR) && 
			(value->charging_gateway_addr.header.length >= 0)) {
		encoded += encode_gtpv1_charging_gateway_addr_ie(&(value->charging_gateway_addr), 
				buf + encoded);
	}

	if ((value->alt_charging_gateway_addr.header.type == GTPV1_IE_CHARGING_GATEWAY_ADDR) && 
			(value->alt_charging_gateway_addr.header.length >= 0)) {
		encoded += encode_gtpv1_charging_gateway_addr_ie(&(value->alt_charging_gateway_addr), 
				buf + encoded);
	}

	if ((value->common_flag.header.type == GTPV1_IE_COMMON_FLAG) && 
			(value->common_flag.header.length >= 0)) {
		encoded += encode_gtpv1_common_flag_ie(&(value->common_flag), 
				buf + encoded);
	}

	if ((value->apn_restriction.header.type == GTPV1_IE_APN_RESTRICTION) && 
			(value->apn_restriction.header.length >= 0)) {
		encoded += encode_gtpv1_apn_restriction_ie(&(value->apn_restriction), 
				buf + encoded);
	}

	if ((value->bearer_control.header.type == GTPV1_IE_BEARER_CONTROL_MODE) && 
			(value->bearer_control.header.length >= 0)) {
		encoded += encode_gtpv1_bearer_control_mode_ie(&(value->bearer_control), 
				buf + encoded);
	}

	if ((value->ms_info_change_reporting_action.header.type == 
				GTPV1_IE_MS_INFO_CHANGE_REPORTING_ACTION) && 
			(value->ms_info_change_reporting_action.header.length >= 0)) {
		encoded += encode_gtpv1_ms_info_change_reporting_action_ie(
				&(value->ms_info_change_reporting_action), buf + encoded);
	}

	if ((value->evolved_allocation_retention_priority_1.header.type == 
				GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_I) && 
			(value->evolved_allocation_retention_priority_1.header.length >= 0)) {
		encoded += encode_gtpv1_evolved_allocation_retention_priority_1_ie(
				&(value->evolved_allocation_retention_priority_1), buf + encoded);
	}

	if ((value->csg_information_reporting_action.header.type == 
				GTPV1_IE_CSG_INFORMATION_REPORTING_ACTION) && 
			(value->csg_information_reporting_action.header.length >= 0)) {
		encoded += encode_gtpv1_csg_information_reporting_action_ie(
				&(value->csg_information_reporting_action), buf + encoded);
	}

	if ((value->apn_ambr.header.type == GTPV1_IE_APN_AMBR) && 
			(value->apn_ambr.header.length >= 0)) {
		encoded += encode_gtpv1_apn_ambr_ie(&(value->apn_ambr), 
				buf + encoded);
	}

	if ((value->private_extension.header.type == 
			GTPV1_IE_PRIVATE_EXTENSION) && 
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension), 
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;
}

int encode_gtpv1_update_pdp_ctxt_rsp_sgsn(gtpv1_update_pdp_ctxt_rsp_sgsn_t *value, uint8_t *buf)
{	
	uint16_t encoded = 0;

	if(value == NULL || buf == NULL) {
		return -1;
	}

	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if (value->cause.header.type == GTPV1_IE_CAUSE) {
		encoded += encode_gtpv1_cause_ie(&(value->cause), 
				buf + encoded);
	}

	if (value->recovery.header.type == GTPV1_IE_RECOVERY) {
		encoded += encode_gtpv1_recovery_ie(&(value->recovery), 
				buf + encoded);
	}
	
	if (value->tunn_endpt_idnt_data_1.header.type == GTPV1_IE_TEID_DATA_1) {
		encoded += encode_gtpv1_teid_ie(&(value->tunn_endpt_idnt_data_1), 
				buf + encoded);
	}

	if ((value->protocol_config_options.header.type == 
				GTPV1_IE_PROTOCOL_CONFIG_OPTIONS) && 
			(value->protocol_config_options.header.length >= 0)) {
		encoded += encode_gtpv1_protocol_config_options_ie(&(value->protocol_config_options),
				buf + encoded);
	}

	if ((value->sgsn_address_for_user_traffic.header.type == GTPV1_IE_GSN_ADDR) && 
			(value->sgsn_address_for_user_traffic.header.length >= 0)) {
		encoded += encode_gtpv1_gsn_address_ie(&(value->sgsn_address_for_user_traffic), 
				buf + encoded);
	}

	if ((value->qos_profile.header.type == GTPV1_IE_QOS) && 
			(value->qos_profile.header.length >= 0)) {
		encoded += encode_gtpv1_qos_ie(&(value->qos_profile), 
				buf + encoded);
	}

	if ((value->user_location_information.header.type ==
			GTPV1_IE_USER_LOCATION_INFORMATION) &&
			(value->user_location_information.header.length >= 0)) {
		encoded += encode_gtpv1_user_location_information_ie(
				&(value->user_location_information ), buf + encoded);
	}

	if ((value->ms_time_zone.header.type == GTPV1_IE_MS_TIME_ZONE) &&
			(value->ms_time_zone.header.length >= 0)) {
		encoded += encode_gtpv1_ms_time_zone_ie(&(value->ms_time_zone),
				buf + encoded);
	}

	if ((value->direct_tunnel_flag.header.type == GTPV1_IE_DIRECT_TUNNEL_FLAG) &&
			(value->direct_tunnel_flag.header.length >= 0)) {
		encoded += encode_gtpv1_direct_tunnel_flag_ie(&(value->direct_tunnel_flag),
				buf + encoded);
	}

	if ((value->evolved_allocation_retention_priority_1.header.type == 
				GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_I) && 
			(value->evolved_allocation_retention_priority_1.header.length >= 0)) {
		encoded += encode_gtpv1_evolved_allocation_retention_priority_1_ie(
				&(value->evolved_allocation_retention_priority_1), buf + encoded);
	}

	if ((value->apn_ambr.header.type == GTPV1_IE_APN_AMBR) && 
			(value->apn_ambr.header.length >= 0)) {
		encoded += encode_gtpv1_apn_ambr_ie(&(value->apn_ambr), 
				buf + encoded);
	}

	if ((value->private_extension.header.type == 
			GTPV1_IE_PRIVATE_EXTENSION) && 
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension), 
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;
}

int encode_gtpv1_delete_pdp_ctxt_req(gtpv1_delete_pdp_ctxt_req_t *value, uint8_t *buf) {
	
	uint16_t encoded = 0;

	if(value == NULL || buf == NULL) {
		return -1;
	}

	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if (value->cause.header.type == GTPV1_IE_CAUSE) {	
		encoded += encode_gtpv1_cause_ie(&(value->cause), 
				buf + encoded); 
	}

	if (value->teardown_ind.header.type == GTPV1_IE_TEARDOWN_IND) {
		encoded += encode_gtpv1_teardown_ind_ie(&(value->teardown_ind), 
				buf + encoded);
	}

	if (value->nsapi.header.type == GTPV1_IE_NSAPI) {
		encoded += encode_gtpv1_nsapi_ie(&(value->nsapi), 
				buf + encoded);	
	}	

	if ((value->protocol_config_options.header.type == GTPV1_IE_PROTOCOL_CONFIG_OPTIONS) && 
			(value->protocol_config_options.header.length >= 0)) {
		encoded += encode_gtpv1_protocol_config_options_ie(&(value->protocol_config_options), 
				buf + encoded);
	}

	if ((value->user_location_information.header.type == GTPV1_IE_USER_LOCATION_INFORMATION) && 
			(value->user_location_information.header.length >= 0)) {
		encoded += encode_gtpv1_user_location_information_ie(
				&(value->user_location_information ), buf + encoded);
	}


	if ((value->ms_time_zone.header.type == GTPV1_IE_MS_TIME_ZONE) && 
			(value->ms_time_zone.header.length >= 0)) {
		encoded += encode_gtpv1_ms_time_zone_ie(&(value->ms_time_zone), 
				buf + encoded);
	}

	if ((value->extended_common_flag.header.type == GTPV1_IE_EXTENDED_COMMON_FLAG) && 
			(value->extended_common_flag.header.length >= 0)) {
		encoded += encode_gtpv1_extended_common_flags_ie(&(value->extended_common_flag), 
				buf + encoded);
	}

	if ((value->uli_timestamp.header.type == GTPV1_IE_ULI_TIMESTAMP) && 
			(value->uli_timestamp.header.length >= 0)) {
		encoded += encode_gtpv1_uli_timestamp_ie(&(value->uli_timestamp), 
				buf + encoded);
	}
	
	if ((value->private_extension.header.type == GTPV1_IE_PRIVATE_EXTENSION) && 
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension), 
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;

}

int encode_gtpv1_delete_pdp_ctxt_rsp(gtpv1_delete_pdp_ctxt_rsp_t *value, uint8_t *buf) {

	uint16_t encoded = 0;

	if(value == NULL || buf == NULL) {
		return -1;
	}

	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if (value->cause.header.type == GTPV1_IE_CAUSE) {
		encoded += encode_gtpv1_cause_ie(&(value->cause), 
				buf + encoded);
	}
	
	if ((value->protocol_config_options.header.type == GTPV1_IE_PROTOCOL_CONFIG_OPTIONS) && 
			(value->protocol_config_options.header.length >= 0)) {
		encoded += encode_gtpv1_protocol_config_options_ie(&(value->protocol_config_options), 
				buf + encoded);
	}
	
	if ((value->user_location_information.header.type == GTPV1_IE_USER_LOCATION_INFORMATION) && 
			(value->user_location_information.header.length >= 0)) {
		encoded += encode_gtpv1_user_location_information_ie(
				&(value->user_location_information ), buf + encoded);
	}

	if ((value->ms_time_zone.header.type == GTPV1_IE_MS_TIME_ZONE) && 
			(value->ms_time_zone.header.length >= 0)) {
		encoded += encode_gtpv1_ms_time_zone_ie(&(value->ms_time_zone), 
				buf + encoded);
	}

	if ((value->uli_timestamp.header.type == GTPV1_IE_ULI_TIMESTAMP) && 
			(value->uli_timestamp.header.length >= 0)) {
		encoded += encode_gtpv1_uli_timestamp_ie(&(value->uli_timestamp), 
				buf + encoded);
	}

	if ((value->private_extension.header.type == GTPV1_IE_PRIVATE_EXTENSION) && 
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension), 
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;
}

int encode_gtpv1_initiate_pdp_ctxt_active_req(gtpv1_initiate_pdp_ctxt_active_req_t *value, uint8_t *buf) {

	uint16_t encoded = 0;

	if(value == NULL || buf == NULL) {
		return -1;
	}

	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if (value->linked_nsapi.header.type == GTPV1_IE_NSAPI) {
		encoded += encode_gtpv1_nsapi_ie(&(value->linked_nsapi),
				buf + encoded);
	}

	if ((value->protocol_config_options.header.type == GTPV1_IE_PROTOCOL_CONFIG_OPTIONS) &&
			(value->protocol_config_options.header.length >= 0)) {
		encoded += encode_gtpv1_protocol_config_options_ie(&(value->protocol_config_options),
				buf + encoded);
	}

	if ((value->qos_profile.header.type == GTPV1_IE_QOS) &&
			(value->qos_profile.header.length >= 0)) {
		encoded += encode_gtpv1_qos_ie(&(value->qos_profile),
				buf + encoded);
	}

	if ((value->tft.header.type == GTPV1_IE_TFT) &&
			(value->tft.header.length >= 0)) {
		encoded += encode_gtpv1_traffic_flow_tmpl_ie(&(value->tft),
				buf + encoded);
	}

	if ((value->correlation_id.header.type == GTPV1_IE_CORRELATION_ID) &&
			(value->correlation_id.header.length >= 0)) {
		encoded += encode_gtpv1_correlation_id_ie(&(value->correlation_id),
				buf + encoded);
	}

	if ((value->evolved_allocation_retention_priority_1.header.type == 
				GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_I) &&
			(value->evolved_allocation_retention_priority_1.header.length >= 0)) {
		encoded += encode_gtpv1_evolved_allocation_retention_priority_1_ie(
				&(value->evolved_allocation_retention_priority_1), buf + encoded);
	}

	if ((value->private_extension.header.type == GTPV1_IE_PRIVATE_EXTENSION) &&
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension),
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;
}

int encode_gtpv1_pdu_notification_req(gtpv1_pdu_notification_req_t *value, uint8_t *buf) {

	uint16_t encoded = 0;
	
	if(value == NULL || buf == NULL) {
		return -1;
	}
	
	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if (value->imsi.header.type == GTPV1_IE_IMSI) {
		encoded += encode_gtpv1_imsi_ie(&(value->imsi),
				buf + encoded);
	}

	if (value->tunn_endpt_idnt_control_plane.header.type == GTPV1_IE_TEID_CONTROL_PLANE) {
		encoded += encode_gtpv1_teid_ie(&(value->tunn_endpt_idnt_control_plane),
				buf + encoded);
	}

	if ((value->end_user_address.header.type == GTPV1_IE_END_USER_ADDR) &&
			(value->end_user_address.header.length >= 0)) {
		encoded += encode_gtpv1_end_user_address_ie(&(value->end_user_address),
				buf + encoded);
	}

	if ((value->apn.header.type == GTPV1_IE_APN) &&
			(value->apn.header.length >= 0 )) {
		encoded += encode_gtpv1_apn_ie(&(value->apn),
				buf + encoded);
	}

	if ((value->protocol_config_options.header.type == GTPV1_IE_PROTOCOL_CONFIG_OPTIONS) &&
			(value->protocol_config_options.header.length >= 0)) {
		encoded += encode_gtpv1_protocol_config_options_ie(&(value->protocol_config_options),
				buf + encoded);
	}

	if ((value->ggsn_addr_control_plane.header.type == GTPV1_IE_GSN_ADDR) &&
			(value->ggsn_addr_control_plane.header.length >= 0)) {
		encoded += encode_gtpv1_gsn_address_ie(&(value->ggsn_addr_control_plane),
				buf + encoded);
	}

	if ((value->private_extension.header.type == GTPV1_IE_PRIVATE_EXTENSION) &&
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension),
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;
}

int encode_gtpv1_initiate_pdp_ctxt_active_rsp(gtpv1_initiate_pdp_ctxt_active_rsp_t *value, uint8_t *buf) {
	
	uint16_t encoded = 0;

	if(value == NULL || buf == NULL) {
		return -1;
	}

	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if (value->cause.header.type == GTPV1_IE_CAUSE) {
		encoded += encode_gtpv1_cause_ie(&(value->cause),
				buf + encoded);
	}
	
	if ((value->private_extension.header.type == GTPV1_IE_PRIVATE_EXTENSION) &&
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension),
				buf + encoded);
	}

	if ((value->protocol_config_options.header.type == GTPV1_IE_PROTOCOL_CONFIG_OPTIONS) &&
			(value->protocol_config_options.header.length >= 0)) {
		encoded += encode_gtpv1_protocol_config_options_ie(&(value->protocol_config_options),
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;
}

int encode_gtpv1_pdu_notification_rsp(gtpv1_pdu_notification_rsp_t *value, uint8_t *buf) {

	uint16_t encoded = 0;
	
	if(value == NULL || buf == NULL) {
		return -1;
	}

	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if (value->cause.header.type == GTPV1_IE_CAUSE) {
		encoded += encode_gtpv1_cause_ie(&(value->cause),
				buf + encoded);
	}
	
	if ((value->private_extension.header.type == GTPV1_IE_PRIVATE_EXTENSION) &&
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension),
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;
}

int encode_gtpv1_pdu_notification_reject_req(gtpv1_pdu_notification_reject_req_t *value, uint8_t *buf) {

	uint16_t encoded = 0;

	if(value == NULL || buf == NULL) {
		return -1;
	}

	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if (value->cause.header.type == GTPV1_IE_CAUSE) {
		encoded += encode_gtpv1_cause_ie(&(value->cause),
				buf + encoded);
	}

	if (value->tunn_endpt_idnt_control_plane.header.type == GTPV1_IE_TEID_CONTROL_PLANE) {
		encoded += encode_gtpv1_teid_ie(&(value->tunn_endpt_idnt_control_plane),
				buf + encoded);
	}

	if ((value->end_user_address.header.type == GTPV1_IE_END_USER_ADDR) &&
			(value->end_user_address.header.length >= 0)) {
		encoded += encode_gtpv1_end_user_address_ie(&(value->end_user_address),
				buf + encoded);
	}

	if ((value->apn.header.type == GTPV1_IE_APN) &&
			(value->apn.header.length >= 0 )) {
		encoded += encode_gtpv1_apn_ie(&(value->apn),
				buf + encoded);
	}

	if ((value->protocol_config_options.header.type == GTPV1_IE_PROTOCOL_CONFIG_OPTIONS) &&
			(value->protocol_config_options.header.length >= 0)) {
		encoded += encode_gtpv1_protocol_config_options_ie(&(value->protocol_config_options),
				buf + encoded);
	}

	if ((value->private_extension.header.type == GTPV1_IE_PRIVATE_EXTENSION) &&
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension),
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;
}

int encode_gtpv1_pdu_notification_reject_rsp(gtpv1_pdu_notification_reject_rsp_t *value, uint8_t *buf) {

	uint16_t encoded = 0;

	if(value == NULL || buf == NULL) {
		return -1;
	}

	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if (value->cause.header.type == GTPV1_IE_CAUSE) {
		encoded += encode_gtpv1_cause_ie(&(value->cause),
				buf + encoded);
	}

	if ((value->private_extension.header.type == GTPV1_IE_PRIVATE_EXTENSION) &&
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension),
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;
}

int encode_gtpv1_send_routeing_info_for_gprs_req(gtpv1_send_routeing_info_for_gprs_req_t *value, uint8_t *buf) {

	uint16_t encoded = 0;
	
	if(value == NULL || buf == NULL) {
		return -1;
	}

	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if (value->imsi.header.type == GTPV1_IE_IMSI) {
		encoded += encode_gtpv1_imsi_ie(&(value->imsi),
				buf + encoded);
	}

	if ((value->private_extension.header.type == GTPV1_IE_PRIVATE_EXTENSION) &&
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension),
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;
}

int encode_gtpv1_send_routeing_info_for_gprs_rsp(gtpv1_send_routeing_info_for_gprs_rsp_t *value, uint8_t *buf) {

	uint16_t encoded = 0;

	if(value == NULL || buf == NULL) {
		return -1;
	}

	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if (value->cause.header.type == GTPV1_IE_CAUSE) {
		encoded += encode_gtpv1_cause_ie(&(value->cause),
				buf + encoded);
	}

	if (value->imsi.header.type == GTPV1_IE_IMSI) {
		encoded += encode_gtpv1_imsi_ie(&(value->imsi),
				buf + encoded);
	}

	if (value->map_cause.header.type == GTPV1_IE_MAP_CAUSE) {
		encoded += encode_gtpv1_map_cause_ie(&(value->map_cause),
				buf + encoded);
	}

	if (value->ms_not_rechable_reason.header.type == GTPV1_IE_MS_NOT_RECHABLE_REASON) {
		encoded += encode_gtpv1_ms_not_rechable_reason_ie(&(value->ms_not_rechable_reason),
				buf + encoded);
	}

	if ((value->gsn_addr.header.type == GTPV1_IE_GSN_ADDR) &&
			(value->gsn_addr.header.length >= 0)) {
		encoded += encode_gtpv1_gsn_address_ie(&(value->gsn_addr),
				buf + encoded);
	}

	if ((value->private_extension.header.type == GTPV1_IE_PRIVATE_EXTENSION) &&
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension),
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;
}

int encode_gtpv1_failure_report_req(gtpv1_failure_report_req_t *value, uint8_t *buf) {

	uint16_t encoded = 0;

	if(value == NULL || buf == NULL) {
		return -1;
	}

	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if (value->imsi.header.type == GTPV1_IE_IMSI) {
		encoded += encode_gtpv1_imsi_ie(&(value->imsi),
				buf + encoded);
	}

	if ((value->private_extension.header.type == GTPV1_IE_PRIVATE_EXTENSION) &&
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension),
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;
}

int encode_gtpv1_failure_report_rsp(gtpv1_failure_report_rsp_t *value, uint8_t *buf) {

	uint16_t encoded = 0;

	if(value == NULL || buf == NULL) {
		return -1;
	}

	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if (value->cause.header.type == GTPV1_IE_CAUSE) {
		encoded += encode_gtpv1_cause_ie(&(value->cause),
				buf + encoded);
	}

	if (value->map_cause.header.type == GTPV1_IE_MAP_CAUSE) {
		encoded += encode_gtpv1_map_cause_ie(&(value->map_cause),
				buf + encoded);
	}

	if ((value->private_extension.header.type == GTPV1_IE_PRIVATE_EXTENSION) &&
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension),
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;
}

int encode_gtpv1_note_ms_gprs_present_req(gtpv1_note_ms_gprs_present_req_t *value, uint8_t *buf) {

	uint16_t encoded = 0;

	if(value == NULL || buf == NULL) {
		return -1;
	}

	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if (value->imsi.header.type == GTPV1_IE_IMSI) {
		encoded += encode_gtpv1_imsi_ie(&(value->imsi),
				buf + encoded);
	}

	if ((value->gsn_addr.header.type == GTPV1_IE_GSN_ADDR) &&
			(value->gsn_addr.header.length >= 0)) {
		encoded += encode_gtpv1_gsn_address_ie(&(value->gsn_addr),
				buf + encoded);
	}

	if ((value->private_extension.header.type == GTPV1_IE_PRIVATE_EXTENSION) &&
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension),
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;
}

int encode_gtpv1_note_ms_gprs_present_rsp(gtpv1_note_ms_gprs_present_rsp_t *value, uint8_t *buf) {

	uint16_t encoded = 0;
	
	if(value == NULL || buf == NULL) {
		return -1;
	}

	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if (value->cause.header.type == GTPV1_IE_CAUSE) {
		encoded += encode_gtpv1_cause_ie(&(value->cause),
				buf + encoded);
	}

	if ((value->private_extension.header.type == GTPV1_IE_PRIVATE_EXTENSION) &&
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension),
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;
}

int encode_gtpv1_sgsn_context_req(gtpv1_sgsn_ctxt_req_t *value, uint8_t *buf) {

	uint16_t encoded = 0;
	
	if(value == NULL || buf == NULL) {
		return -1;
	}

	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if (value->imsi.header.type == GTPV1_IE_IMSI) {
		encoded += encode_gtpv1_imsi_ie(&(value->imsi), buf + encoded);
	}

	if (value->routing_area_identity.header.type == GTPV1_IE_ROUTEING_AREA_IDENTITY) {
		encoded += encode_gtpv1_routing_area_identity_ie(&(value->routing_area_identity),
				buf + encoded);
	}

	if (value->temporary_logical_link_identifier.header.type == GTPV1_IE_TEMPORARY_LOGICAL_LINK_IDENTIFIER) {
		encoded += encode_gtpv1_temporary_logical_link_identifier_ie(&(value->temporary_logical_link_identifier),
				buf + encoded);
	}

	if (value->packet_tmsi.header.type == GTPV1_IE_PACKET_TMSI) {
		encoded += encode_gtpv1_packet_tmsi_ie(&(value->packet_tmsi),
				buf + encoded);
	}

	if (value->p_tmsi_signature.header.type == GTPV1_IE_P_TMSI_SIGNATURE) {
		encoded += encode_gtpv1_p_tmsi_signature_ie(&(value->p_tmsi_signature),
				buf + encoded);
	}

	if (value->ms_validated.header.type == GTPV1_IE_MS_VALIDATED) {
		encoded += encode_gtpv1_ms_validated_ie(&(value->ms_validated),
				buf + encoded);
	}

	if (value->tunn_endpt_idnt_control_plane.header.type == GTPV1_IE_TEID_CONTROL_PLANE) {
		encoded += encode_gtpv1_teid_ie(&(value->tunn_endpt_idnt_control_plane),
				buf + encoded);
	}

	if ((value->sgsn_address_for_control_plane.header.type == GTPV1_IE_GSN_ADDR) &&
			(value->sgsn_address_for_control_plane.header.length >= 0)) {
		encoded += encode_gtpv1_gsn_address_ie(&(value->sgsn_address_for_control_plane),
				buf + encoded);
	}

	if ((value->alternative_sgsn_address_for_control_plane.header.type == GTPV1_IE_GSN_ADDR) &&
			(value->alternative_sgsn_address_for_control_plane.header.length >= 0)) {
		encoded += encode_gtpv1_gsn_address_ie(&(value->alternative_sgsn_address_for_control_plane),
				buf + encoded);
	}

	if ((value->sgsn_number.header.type == GTPV1_IE_SGSN_NUMBER) &&
			(value->sgsn_number.header.length >= 0)) {
		encoded += encode_gtpv1_sgsn_number_ie(&(value->sgsn_number),
				buf + encoded);
	}

	if ((value->rat_type.header.type == GTPV1_IE_RAT_TYPE) &&
			(value->rat_type.header.length >= 0)) {
		encoded += encode_gtpv1_rat_type_ie(&(value->rat_type),
				buf + encoded);
	}

	if ((value->hop_counter.header.type == GTPV1_IE_HOP_COUNTER) &&
			(value->hop_counter.header.length >= 0)) {
		encoded += encode_gtpv1_hop_counter_ie(&(value->hop_counter),
				buf + encoded);
	}

	if ((value->private_extension.header.type == GTPV1_IE_PRIVATE_EXTENSION) &&
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension),
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);
	return encoded;
}


int encode_gtpv1_sgsn_context_rsp(gtpv1_sgsn_ctxt_rsp_t *value, uint8_t *buf) {

	uint16_t encoded = 0;
	
	if(value == NULL || buf == NULL) {
		return -1;
	}

	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if (value->cause.header.type == GTPV1_IE_CAUSE) {
		encoded += encode_gtpv1_cause_ie(&(value->cause),
				buf + encoded);
	}

	if (value->imsi.header.type == GTPV1_IE_IMSI) {
		encoded += encode_gtpv1_imsi_ie(&(value->imsi),
				buf + encoded);
	}

	if (value->tunn_endpt_idnt_control_plane.header.type == GTPV1_IE_TEID_CONTROL_PLANE) {
		encoded += encode_gtpv1_teid_ie(&(value->tunn_endpt_idnt_control_plane),
				buf + encoded);
	}

	if (value->rab_context.header.type == GTPV1_IE_RAB_CONTEXT) {
		encoded += encode_gtpv1_rab_context_ie(&(value->rab_context),
				buf + encoded);
	}

	if (value->radio_priority_sms.header.type == GTPV1_IE_RADIO_PRIORITY_SMS) {
		encoded += encode_gtpv1_radio_priority_sms_ie(&(value->radio_priority_sms),
				buf + encoded);
	}

	if (value->radio_priority.header.type == GTPV1_IE_RADIO_PRIORITY) {
		encoded += encode_gtpv1_radio_priority_ie(&(value->radio_priority),
				buf + encoded);
	}

	if (value->packet_flow_id.header.type == GTPV1_IE_PACKET_FLOW_ID) {
		encoded += encode_gtpv1_packet_flow_id_ie(&(value->packet_flow_id),
				buf + encoded);
	}

	if (value->chrgng_char.header.type == GTPV1_IE_CHRGNG_CHAR) {
		encoded += encode_gtpv1_chrgng_char_ie(&(value->chrgng_char),
				buf + encoded);
	}

	if ((value->radio_priority_lcs.header.type == GTPV1_IE_RADIO_PRIORITY_LCS) &&
			(value->radio_priority_lcs.header.length >= 0)) {
		encoded += encode_gtpv1_radio_priority_lcs_ie(&(value->radio_priority_lcs),
				buf + encoded);
	}

	if ((value->mm_context.header.type == GTPV1_IE_MM_CONTEXT) &&
			(value->mm_context.header.length >= 0)) {
		encoded += encode_gtpv1_mm_context_ie(&(value->mm_context),
				buf + encoded);
	}

	if ((value->pdp_context.header.type == GTPV1_IE_PDP_CONTEXT) &&
			(value->pdp_context.header.length >= 0)) {
		encoded += encode_gtpv1_pdp_context_ie(&(value->pdp_context),
				buf + encoded);
	}

	if ((value->gsn_addr_1.header.type == GTPV1_IE_GSN_ADDR) &&
			(value->gsn_addr_1.header.length >= 0)) {
		encoded += encode_gtpv1_gsn_address_ie(&(value->gsn_addr_1),
				buf + encoded);
	}

	if ((value->pdp_context_prioritization.header.type == GTPV1_IE_PDP_CONTEXT_PRIORITIZATION) &&
			(value->pdp_context_prioritization.header.length >= 0)) {
		encoded += encode_gtpv1_pdp_context_prioritization_ie(&(value->pdp_context_prioritization),
				buf + encoded);
	}

	if ((value->mbms_ue_context.header.type == GTPV1_IE_MBMS_UE_CONTEXT) &&
			(value->mbms_ue_context.header.length >= 0)) {
		encoded += encode_gtpv1_mbms_ue_context_ie(&(value->mbms_ue_context),
				buf + encoded);
	}

	if ((value->subscribed_rfsp_index.header.type == GTPV1_IE_RFSP_INDEX) &&
			(value->subscribed_rfsp_index.header.length >= 0)) {
		encoded += encode_gtpv1_rfsp_index_ie(&(value->subscribed_rfsp_index),
				buf + encoded);
	}

	if ((value->rfsp_index_in_use.header.type == GTPV1_IE_RFSP_INDEX) &&
			(value->rfsp_index_in_use.header.length >= 0)) {
		encoded += encode_gtpv1_rfsp_index_ie(&(value->rfsp_index_in_use),
				buf + encoded);
	}

	if ((value->co_located_ggsn_pgw_fqdn.header.type == GTPV1_IE_FQDN) &&
			(value->co_located_ggsn_pgw_fqdn.header.length >= 0)) {
		encoded += encode_gtpv1_fqdn_ie(&(value->co_located_ggsn_pgw_fqdn),
				buf + encoded);
	}

	if ((value->evolved_allocation_retention_priority_II.header.type == 
				GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_II) &&
			(value->evolved_allocation_retention_priority_II.header.length >= 0)) {
		encoded += encode_gtpv1_evolved_allocation_retention_priority_II_ie(
				&(value->evolved_allocation_retention_priority_II),
				buf + encoded);
	}

	if ((value->extended_common_flag.header.type == GTPV1_IE_EXTENDED_COMMON_FLAG) &&
			(value->extended_common_flag.header.length >= 0)) {
		encoded += encode_gtpv1_extended_common_flags_ie(&(value->extended_common_flag),
				buf + encoded);
	}

	if ((value->ue_network_capability.header.type == GTPV1_IE_UE_NETWORK_CAPABILITY) &&
			(value->ue_network_capability.header.length >= 0)) {
		encoded += encode_gtpv1_ue_network_capability_ie(&(value->ue_network_capability),
				buf + encoded);
	}

	if ((value->ue_ambr.header.type == GTPV1_IE_UE_AMBR) &&
			(value->ue_ambr.header.length >= 0)) {
		encoded += encode_gtpv1_ue_ambr_ie(&(value->ue_ambr),
				buf + encoded);
	}

	if ((value->apn_ambr_with_nsapi.header.type == GTPV1_IE_APN_AMBR_WITH_NSAPI) &&
			(value->apn_ambr_with_nsapi.header.length >= 0)) {
		encoded += encode_gtpv1_apn_ambr_with_nsapi_ie(&(value->apn_ambr_with_nsapi),
				buf + encoded);
	}

	if ((value->signalling_priority_indication_with_nsapi.header.type == 
				GTPV1_IE_SIGNALLING_PRIORITY_INDICATION_WITH_NSAPI) &&
			(value->signalling_priority_indication_with_nsapi.header.length >= 0)) {
		encoded += encode_gtpv1_signalling_priority_indication_with_nsapi_ie(&
				(value->signalling_priority_indication_with_nsapi),
				buf + encoded);
	}

	if ((value->higher_bitrates_than_16_mbps_flag.header.type == GTPV1_IE_HIGER_BITRATES_THAN_16_MBPS_FLAG) &&
			(value->higher_bitrates_than_16_mbps_flag.header.length >= 0)) {
		encoded += encode_gtpv1_higher_bitrates_than_16_mbps_flag_ie(&(value->higher_bitrates_than_16_mbps_flag),
				buf + encoded);
	}

	if ((value->selection_mode_with_nsapi.header.type == GTPV1_IE_SELECTION_MODE_WITH_NSAPI) &&
			(value->selection_mode_with_nsapi.header.length >= 0)) {
		encoded += encode_gtpv1_selection_mode_with_nsapi_ie(&(value->selection_mode_with_nsapi),
				buf + encoded);
	}

	if ((value->local_home_network_id_with_nsapi.header.type == GTPV1_IE_LOCAL_HOME_NETWORK_ID_WITH_NSAPI) &&
			(value->local_home_network_id_with_nsapi.header.length >= 0)) {
		encoded += encode_gtpv1_local_home_network_id_with_nsapi_ie(&(value->local_home_network_id_with_nsapi),
				buf + encoded);
	}

	if ((value->ue_usage_type.header.type == GTPV1_IE_UE_USAGE_TYPE) &&
			(value->ue_usage_type.header.length >= 0)) {
		encoded += encode_gtpv1_ue_usage_type_ie(&(value->ue_usage_type),
				buf + encoded);
	}

	if ((value->extended_common_flag_2.header.type == GTPV1_IE_EXTENDED_COMMON_FLAGS_II) && 
			(value->extended_common_flag_2.header.length >= 0)) {
		encoded += encode_gtpv1_extended_common_flag_2_ie(&(value->extended_common_flag_2), buf + encoded);
	}

	if ((value->ue_scef_pdn_connection.header.type == GTPV1_IE_UE_SCEF_PDN_CONNTECTION) &&
			(value->ue_scef_pdn_connection.header.length >= 0)) {
		encoded += encode_gtpv1_ue_scef_pdn_connection_ie(&(value->ue_scef_pdn_connection),
				buf + encoded);
	}

	if ((value->gsn_addr_2.header.type == GTPV1_IE_GSN_ADDR) &&
			(value->gsn_addr_2.header.length >= 0)) {
		encoded += encode_gtpv1_gsn_address_ie(&(value->gsn_addr_2),
				buf + encoded);
	} 

	if ((value->gsn_addr_3.header.type == GTPV1_IE_GSN_ADDR) &&
			(value->gsn_addr_3.header.length >= 0)) {
		encoded += encode_gtpv1_gsn_address_ie(&(value->gsn_addr_3),
				buf + encoded);
	}

	if ((value->iov_updates_counter.header.type == GTPV1_IE_IOV_UPDATES_COUNTER) &&
			(value->iov_updates_counter.header.length >= 0)) {
		encoded += encode_gtpv1_iov_updates_counter_ie(&(value->iov_updates_counter),
				buf + encoded);
	}

	if ((value->private_extension.header.type == GTPV1_IE_PRIVATE_EXTENSION) &&
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension),
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);
	return encoded;
}

int encode_gtpv1_ue_registration_query_req(gtpv1_ue_registration_query_req_t *value, uint8_t *buf) {

	uint16_t encoded = 0;
	
	if(value == NULL || buf == NULL) {
		return -1;
	}

	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if (value->imsi.header.type == GTPV1_IE_IMSI) {
		encoded += encode_gtpv1_imsi_ie(&(value->imsi),
				buf + encoded);
	}

	if ((value->private_extension.header.type == GTPV1_IE_PRIVATE_EXTENSION) &&
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension),
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;
}

int encode_gtpv1_ue_registration_query_rsp(gtpv1_ue_registration_query_rsp_t *value, uint8_t *buf) {

	uint16_t encoded = 0;

	if(value == NULL || buf == NULL) {
		return -1;
	}

	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if (value->cause.header.type == GTPV1_IE_CAUSE) {
		encoded += encode_gtpv1_cause_ie(&(value->cause),
				buf + encoded);
	}

	if (value->imsi.header.type == GTPV1_IE_IMSI) {
		encoded += encode_gtpv1_imsi_ie(&(value->imsi),
				buf + encoded);
	}

	if ((value->plmn_id.header.type == GTPV1_IE_SELECTED_PLMN_ID) &&
			(value->plmn_id.header.length >= 0)) {
		encoded += encode_gtpv1_selected_plmn_id_ie(&(value->plmn_id),
				buf + encoded);
	}

	if ((value->private_extension.header.type == GTPV1_IE_PRIVATE_EXTENSION) &&
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension),
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;
}

int encode_gtpv1_ran_info_relay(gtpv1_ran_info_relay_t *value, uint8_t *buf) {

	uint16_t encoded = 0;
	
	if(value == NULL || buf == NULL) {
		return -1;
	}

	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if ((value->ran_transparent_container.header.type == GTPV1_IE_RAN_TRANSPARENT_CONTAINER) &&
			(value->ran_transparent_container.header.length >= 0)) {
		encoded += encode_gtpv1_ran_transparent_container_ie(&(value->ran_transparent_container),
				buf + encoded);
	}

	if ((value->rim_addr.header.type == GTPV1_IE_RIM_ROUTING_ADDR) &&
			(value->rim_addr.header.length >= 0)) {
		encoded += encode_gtpv1_rim_routing_addr_ie(&(value->rim_addr),
				buf + encoded);
	}

	if (value->rim_addr_disc.header.type == GTPV1_IE_RIM_ROUTING_ADDR_DISCRIMINATOR) {
		encoded += encode_gtpv1_rim_routing_addr_disc_ie(&(value->rim_addr_disc),
				buf + encoded);
	}

	if ((value->private_extension.header.type == GTPV1_IE_PRIVATE_EXTENSION) &&
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension),
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;
}

int encode_gtpv1_mbms_notification_req(gtpv1_mbms_notification_req_t *value, uint8_t *buf) {

	uint16_t encoded = 0;
	
	if(value == NULL || buf == NULL) {
		return -1;
	}

	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if (value->imsi.header.type == GTPV1_IE_IMSI) {
		encoded += encode_gtpv1_imsi_ie(&(value->imsi),
				buf + encoded);
	}

	if (value->tunn_endpt_idnt_control_plane.header.type == GTPV1_IE_TEID_CONTROL_PLANE) {
		encoded += encode_gtpv1_teid_ie(&(value->tunn_endpt_idnt_control_plane),
				buf + encoded);
	}

	if (value->nsapi.header.type == GTPV1_IE_NSAPI) {
		encoded += encode_gtpv1_nsapi_ie(&(value->nsapi),
				buf + encoded);
	}

	if ((value->end_user_address.header.type == GTPV1_IE_END_USER_ADDR) &&
			(value->end_user_address.header.length >= 0)) {
		encoded += encode_gtpv1_end_user_address_ie(&(value->end_user_address),
				buf + encoded);
	}

	if ((value->apn.header.type == GTPV1_IE_APN) &&
			(value->apn.header.length >= 0 )) {
		encoded += encode_gtpv1_apn_ie(&(value->apn),
				buf + encoded);
	}

	if ((value->ggsn_addr_control_plane.header.type == GTPV1_IE_GSN_ADDR) &&
			(value->ggsn_addr_control_plane.header.length >= 0)) {
		encoded += encode_gtpv1_gsn_address_ie(&(value->ggsn_addr_control_plane),
				buf + encoded);
	}

	if ((value->mbms_protocol.header.type == GTPV1_IE_MBMS_PROTOCOL_CONFIG_OPTIONS) &&
			(value->mbms_protocol.header.length >= 0)) {
		encoded += encode_gtpv1_mbms_protocol_config_options_ie(&(value->mbms_protocol),
				buf + encoded);
	}

	if ((value->private_extension.header.type == GTPV1_IE_PRIVATE_EXTENSION) &&
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension),
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;
}

int encode_gtpv1_mbms_notification_rsp(gtpv1_mbms_notification_rsp_t *value, uint8_t *buf) {

	uint16_t encoded = 0;
	
	if(value == NULL || buf == NULL) {
		return -1;
	}

	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if (value->cause.header.type == GTPV1_IE_CAUSE) {
		encoded += encode_gtpv1_cause_ie(&(value->cause),
				buf + encoded);
	}

	if ((value->private_extension.header.type == GTPV1_IE_PRIVATE_EXTENSION) &&
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension),
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;
}

int encode_gtpv1_forward_relocation_req(gtpv1_forward_relocation_req_t *value, uint8_t *buf){

	uint16_t encoded = 0;
	
	if(value == NULL || buf == NULL) {
		return -1;
	}
	
	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if (value->imsi.header.type == GTPV1_IE_IMSI) {
		encoded += encode_gtpv1_imsi_ie(&(value->imsi),
				buf + encoded);
	}

	if (value->tunn_endpt_idnt_control_plane.header.type == GTPV1_IE_TEID_CONTROL_PLANE) {
		encoded += encode_gtpv1_teid_ie(&(value->tunn_endpt_idnt_control_plane),
				buf + encoded);
	}

	if (value->ranap_cause.header.type == GTPV1_IE_RANAP_CAUSE) {
		encoded += encode_gtpv1_ranap_cause_ie(&(value->ranap_cause),
				buf + encoded);
	}

	if (value->packet_flow_id.header.type == GTPV1_IE_PACKET_FLOW_ID) {
		encoded += encode_gtpv1_packet_flow_id_ie(&(value->packet_flow_id),
				buf + encoded);
	}

	if (value->chrgng_char.header.type == GTPV1_IE_CHRGNG_CHAR) {
		encoded += encode_gtpv1_chrgng_char_ie(&(value->chrgng_char),
				buf + encoded);
	}

	if ((value->mm_context.header.type == GTPV1_IE_MM_CONTEXT) &&
			(value->mm_context.header.length >= 0)) {
		encoded += encode_gtpv1_mm_context_ie(&(value->mm_context),
				buf + encoded);
	}

	if ((value->pdp_context.header.type == GTPV1_IE_PDP_CONTEXT) &&
			(value->pdp_context.header.length >= 0)) {
		encoded += encode_gtpv1_pdp_context_ie(&(value->pdp_context),
				buf + encoded);
	}

	if ((value->gsn_addr_1.header.type == GTPV1_IE_GSN_ADDR) &&
			(value->gsn_addr_1.header.length >= 0)) {
		encoded += encode_gtpv1_gsn_address_ie(&(value->gsn_addr_1),
				buf + encoded);
	}

	if ((value->target_id.header.type == GTPV1_IE_TARGET_IDENTIFICATION) &&
			(value->target_id.header.length >= 0)) {
		encoded += encode_gtpv1_target_identification_ie(&(value->target_id),
				buf + encoded);
	}

	if ((value->utran_container.header.type == GTPV1_IE_UTRAN_TRANSPARENT_CONTAINER) &&
			(value->utran_container.header.length >= 0)) {
		encoded += encode_gtpv1_utran_transparent_container_ie(&(value->utran_container),
				buf + encoded);
	}

	if ((value->pdp_context_prioritization.header.type == GTPV1_IE_PDP_CONTEXT_PRIORITIZATION) &&
			(value->pdp_context_prioritization.header.length >= 0)) {
		encoded += encode_gtpv1_pdp_context_prioritization_ie(&(value->pdp_context_prioritization),
				buf + encoded);
	}

	if ((value->mbms_ue_context.header.type == GTPV1_IE_MBMS_UE_CONTEXT) &&
			(value->mbms_ue_context.header.length >= 0)) {
		encoded += encode_gtpv1_mbms_ue_context_ie(&(value->mbms_ue_context),
				buf + encoded);
	}

	if ((value->plmn_id.header.type == GTPV1_IE_SELECTED_PLMN_ID) &&
			(value->plmn_id.header.length >= 0)) {
		encoded += encode_gtpv1_selected_plmn_id_ie(&(value->plmn_id),
				buf + encoded);
	}

	if ((value->bss_container.header.type == GTPV1_IE_BSS_CONTAINER) &&
			(value->bss_container.header.length >= 0)) {
		encoded += encode_gtpv1_bss_container_ie(&(value->bss_container),
				buf + encoded);
	}

	if ((value->cell_id.header.type == GTPV1_IE_CELL_IDENTIFICATION) &&
			(value->cell_id.header.length >= 0)) {
		encoded += encode_gtpv1_cell_identification_ie(&(value->cell_id),
				buf + encoded);
	}

	if ((value->bssgp_cause.header.type == GTPV1_IE_BSSGP_CAUSE) &&
			(value->bssgp_cause.header.length >= 0)) {
		encoded += encode_gtpv1_bssgp_cause_ie(&(value->bssgp_cause),
				buf + encoded);
	}

	if ((value->xid_param.header.type == GTPV1_IE_PS_HANDOVER_XID_PARAM) &&
			(value->xid_param.header.length >= 0)) {
		encoded += encode_gtpv1_ps_handover_xid_param_ie(&(value->xid_param),
				buf + encoded);
	}

	if ((value->direct_tunnel_flag.header.type == GTPV1_IE_DIRECT_TUNNEL_FLAG) &&
			(value->direct_tunnel_flag.header.length >= 0)) {
		encoded += encode_gtpv1_direct_tunnel_flag_ie(&(value->direct_tunnel_flag),
				buf + encoded);
	}

	if ((value->inter_rat_handover.header.type == GTPV1_IE_RELIABLE_INTER_RAT_HANDOVER_INFO) &&
			(value->inter_rat_handover.header.length >= 0)) {
		encoded += encode_gtpv1_reliable_inter_rat_handover_info_ie(&(value->inter_rat_handover),
				buf + encoded);
	}

	if ((value->subscribed_rfsp_index.header.type == GTPV1_IE_RFSP_INDEX) &&
			(value->subscribed_rfsp_index.header.length >= 0)) {
		encoded += encode_gtpv1_rfsp_index_ie(&(value->subscribed_rfsp_index),
				buf + encoded);
	}

	if ((value->rfsp_index_in_use.header.type == GTPV1_IE_RFSP_INDEX) &&
			(value->rfsp_index_in_use.header.length >= 0)) {
		encoded += encode_gtpv1_rfsp_index_ie(&(value->rfsp_index_in_use),
				buf + encoded);
	}

	if ((value->co_located_ggsn_pgw_fqdn.header.type == GTPV1_IE_FQDN) &&
			(value->co_located_ggsn_pgw_fqdn.header.length >= 0)) {
		encoded += encode_gtpv1_fqdn_ie(&(value->co_located_ggsn_pgw_fqdn),
				buf + encoded);
	}

	if ((value->evolved_allocation_retention_priority_II.header.type ==
				GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_II) &&
			(value->evolved_allocation_retention_priority_II.header.length >= 0)) {
		encoded += encode_gtpv1_evolved_allocation_retention_priority_II_ie(
				&(value->evolved_allocation_retention_priority_II),
				buf + encoded);
	}

	if ((value->extended_common_flag.header.type == GTPV1_IE_EXTENDED_COMMON_FLAG) &&
			(value->extended_common_flag.header.length >= 0)) {
		encoded += encode_gtpv1_extended_common_flags_ie(&(value->extended_common_flag),
				buf + encoded);
	}

	if ((value->csg_id.header.type == GTPV1_IE_CSG_ID) &&
			(value->csg_id.header.length >= 0)) {
		encoded += encode_gtpv1_csg_id_ie(&(value->csg_id),
				buf + encoded);
	}

	if ((value->csg_member.header.type == GTPV1_IE_CSG_MEMB_INDCTN) &&
			(value->csg_member.header.length >= 0)) {
		encoded += encode_gtpv1_csg_membership_indication_ie(&(value->csg_member),
				buf + encoded);
	}

	if ((value->ue_network_capability.header.type == GTPV1_IE_UE_NETWORK_CAPABILITY) &&
			(value->ue_network_capability.header.length >= 0)) {
		encoded += encode_gtpv1_ue_network_capability_ie(&(value->ue_network_capability),
				buf + encoded);
	}

	if ((value->ue_ambr.header.type == GTPV1_IE_UE_AMBR) &&
			(value->ue_ambr.header.length >= 0)) {
		encoded += encode_gtpv1_ue_ambr_ie(&(value->ue_ambr),
				buf + encoded);
	}

	if ((value->apn_ambr_with_nsapi.header.type == GTPV1_IE_APN_AMBR_WITH_NSAPI) &&
			(value->apn_ambr_with_nsapi.header.length >= 0)) {
		encoded += encode_gtpv1_apn_ambr_with_nsapi_ie(&(value->apn_ambr_with_nsapi),
				buf + encoded);
	}

	if ((value->signalling_priority_indication_with_nsapi.header.type ==
				GTPV1_IE_SIGNALLING_PRIORITY_INDICATION_WITH_NSAPI) &&
			(value->signalling_priority_indication_with_nsapi.header.length >= 0)) {
		encoded += encode_gtpv1_signalling_priority_indication_with_nsapi_ie(&
				(value->signalling_priority_indication_with_nsapi),
				buf + encoded);
	}

	if ((value->higher_bitrates_than_16_mbps_flag.header.type == GTPV1_IE_HIGER_BITRATES_THAN_16_MBPS_FLAG) &&
			(value->higher_bitrates_than_16_mbps_flag.header.length >= 0)) {
		encoded += encode_gtpv1_higher_bitrates_than_16_mbps_flag_ie(&(value->higher_bitrates_than_16_mbps_flag),
				buf + encoded);
	}

	if ((value->add_mm_ctxt.header.type == GTPV1_IE_ADDTL_MM_CTXT_SRVCC) &&
			(value->add_mm_ctxt.header.length >= 0)) {
		encoded += encode_gtpv1_additional_mm_ctxt_for_srvcc_ie(&(value->add_mm_ctxt),
				buf + encoded);
	}

	if ((value->add_flag_srvcc.header.type == GTPV1_IE_ADDTL_FLGS_SRVCC) &&
			(value->add_flag_srvcc.header.length >= 0)) {
		encoded += encode_gtpv1_additional_flags_for_srvcc_ie(&(value->add_flag_srvcc),
				buf + encoded);
	}

	if ((value->stn_sr.header.type == GTPV1_IE_STN_SR) &&
			(value->stn_sr.header.length >= 0)) {
		encoded += encode_gtpv1_stn_sr_ie(&(value->stn_sr),
				buf + encoded);
	}

	if ((value->c_msisdn.header.type == GTPV1_IE_C_MSISDN) &&
			(value->c_msisdn.header.length >= 0)) {
		encoded += encode_gtpv1_c_msisdn_ie(&(value->c_msisdn),
				buf + encoded);
	}

	if ((value->ext_ranap_cause.header.type == GTPV1_IE_EXTENDED_RANAP_CAUSE) &&
			(value->ext_ranap_cause.header.length >= 0)) {
		encoded += encode_gtpv1_extended_ranap_cause_ie(&(value->ext_ranap_cause),
				buf + encoded);
	}

	if ((value->enodeb_id.header.type == GTPV1_IE_ENODEB_ID) &&
			(value->enodeb_id.header.length >= 0)) {
		encoded += encode_gtpv1_enodeb_id_ie(&(value->enodeb_id),
				buf + encoded);
	}

	if ((value->selection_mode_with_nsapi.header.type == GTPV1_IE_SELECTION_MODE_WITH_NSAPI) &&
			(value->selection_mode_with_nsapi.header.length >= 0)) {
		encoded += encode_gtpv1_selection_mode_with_nsapi_ie(&(value->selection_mode_with_nsapi),
				buf + encoded);
	}

	if ((value->ue_usage_type.header.type == GTPV1_IE_UE_USAGE_TYPE) &&
			(value->ue_usage_type.header.length >= 0)) {
		encoded += encode_gtpv1_ue_usage_type_ie(&(value->ue_usage_type),
				buf + encoded);
	}

	if ((value->extended_common_flag_2.header.type == GTPV1_IE_EXTENDED_COMMON_FLAGS_II) &&
			(value->extended_common_flag_2.header.length >= 0)) {
		encoded += encode_gtpv1_extended_common_flag_2_ie(&(value->extended_common_flag_2), buf + encoded);
	}

	if ((value->ue_scef_pdn_connection.header.type == GTPV1_IE_UE_SCEF_PDN_CONNTECTION) &&
			(value->ue_scef_pdn_connection.header.length >= 0)) {
		encoded += encode_gtpv1_ue_scef_pdn_connection_ie(&(value->ue_scef_pdn_connection),
				buf + encoded);
	}

	if ((value->gsn_addr_2.header.type == GTPV1_IE_GSN_ADDR) &&
			(value->gsn_addr_2.header.length >= 0)) {
		encoded += encode_gtpv1_gsn_address_ie(&(value->gsn_addr_2),
				buf + encoded);
	}

	if ((value->gsn_addr_3.header.type == GTPV1_IE_GSN_ADDR) &&
			(value->gsn_addr_3.header.length >= 0)) {
		encoded += encode_gtpv1_gsn_address_ie(&(value->gsn_addr_3),
				buf + encoded);
	}

	if ((value->private_extension.header.type == GTPV1_IE_PRIVATE_EXTENSION) &&
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension),
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;
}

int encode_gtpv1_forward_relocation_rsp(gtpv1_forward_relocation_rsp_t *value, uint8_t *buf){

	uint16_t encoded = 0;
	
	if(value == NULL || buf == NULL) {
		return -1;
	}
	
	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if (value->cause.header.type == GTPV1_IE_CAUSE) {
		encoded += encode_gtpv1_cause_ie(&(value->cause),
				buf + encoded);
	}

	if (value->teid_control_plane.header.type == GTPV1_IE_TEID_CONTROL_PLANE) {
		encoded += encode_gtpv1_teid_ie(&(value->teid_control_plane),
				buf + encoded);
	}

	if (value->teid_2.header.type == GTPV1_IE_TEID_DATA_2) {
		encoded += encode_gtpv1_teid_data_2_ie(&(value->teid_2),
				buf + encoded);
	}

	if (value->ranap_cause.header.type == GTPV1_IE_RANAP_CAUSE) {
		encoded += encode_gtpv1_ranap_cause_ie(&(value->ranap_cause),
				buf + encoded);
	}

	if ((value->sgsn_addr_control_plane.header.type == GTPV1_IE_GSN_ADDR) &&
			(value->sgsn_addr_control_plane.header.length >= 0)) {
		encoded += encode_gtpv1_gsn_address_ie(&(value->sgsn_addr_control_plane),
				buf + encoded);
	}

	if ((value->sgsn_addr_user_traffic.header.type == GTPV1_IE_GSN_ADDR) &&
			(value->sgsn_addr_user_traffic.header.length >= 0)) {
		encoded += encode_gtpv1_gsn_address_ie(&(value->sgsn_addr_user_traffic),
				buf + encoded);
	}

	if ((value->utran_container.header.type == GTPV1_IE_UTRAN_TRANSPARENT_CONTAINER) &&
			(value->utran_container.header.length >= 0)) {
		encoded += encode_gtpv1_utran_transparent_container_ie(&(value->utran_container),
				buf + encoded);
	}

	if ((value->rab_setup_info.header.type == GTPV1_IE_RAB_SETUP_INFO) &&
			(value->rab_setup_info.header.length >= 0)) {
		encoded += encode_gtpv1_rab_setup_info_ie(&(value->rab_setup_info),
				buf + encoded);
	}

	if ((value->add_rab_setup_info.header.type == GTPV1_IE_ADDITIONAL_RAB_SETUP_INFO) &&
			(value->add_rab_setup_info.header.length >= 0)) {
		encoded += encode_gtpv1_rab_setup_info_ie(&(value->add_rab_setup_info),
				buf + encoded);
	}

	if ((value->sgsn_number.header.type == GTPV1_IE_SGSN_NUMBER) &&
			(value->sgsn_number.header.length >= 0)) {
		encoded += encode_gtpv1_sgsn_number_ie(&(value->sgsn_number),
				buf + encoded);
	}

	if ((value->bss_container.header.type == GTPV1_IE_BSS_CONTAINER) &&
			(value->bss_container.header.length >= 0)) {
		encoded += encode_gtpv1_bss_container_ie(&(value->bss_container),
				buf + encoded);
	}

	if ((value->bssgp_cause.header.type == GTPV1_IE_BSSGP_CAUSE) &&
			(value->bssgp_cause.header.length >= 0)) {
		encoded += encode_gtpv1_bssgp_cause_ie(&(value->bssgp_cause),
				buf + encoded);
	}

	if ((value->list_pfcs.header.type == GTPV1_IE_LIST_OF_SET_UP_PFCS) &&
			(value->list_pfcs.header.length >= 0)) {
		encoded += encode_gtpv1_list_of_setup_pfcs_ie(&(value->list_pfcs),
				buf + encoded);
	}

	if ((value->ext_ranap_cause.header.type == GTPV1_IE_EXTENDED_RANAP_CAUSE) &&
			(value->ext_ranap_cause.header.length >= 0)) {
		encoded += encode_gtpv1_extended_ranap_cause_ie(&(value->ext_ranap_cause),
				buf + encoded);
	}

	if ((value->node_id.header.type == GTPV1_IE_NODE_IDENTIFIER) &&
			(value->node_id.header.length >= 0)) {
		encoded += encode_gtpv1_node_identifier_ie(&(value->node_id),
				buf + encoded);
	}

	if ((value->private_extension.header.type == GTPV1_IE_PRIVATE_EXTENSION) &&
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension),
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;
}


int encode_gtpv1_ms_info_change_notification_req(gtpv1_ms_info_change_notification_req_t *value, uint8_t *buf) {

	uint16_t encoded = 0;
	
	if(value == NULL || buf == NULL) {
		return -1;
	}
	
	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if (value->imsi.header.type == GTPV1_IE_IMSI) {
		encoded += encode_gtpv1_imsi_ie(&(value->imsi), 
				buf + encoded);
	}

	if (value->linked_nsapi.header.type == GTPV1_IE_NSAPI) {
		encoded += encode_gtpv1_nsapi_ie(&(value->linked_nsapi), 
				buf + encoded);
	}

	if ((value->rat_type.header.type == GTPV1_IE_RAT_TYPE) && 
			(value->rat_type.header.length >= 0)) {
		encoded += encode_gtpv1_rat_type_ie(&(value->rat_type), 
				buf + encoded);
	}

	if ((value->user_location_information.header.type == 
				GTPV1_IE_USER_LOCATION_INFORMATION) && 
			(value->user_location_information.header.length >= 0)) {
		encoded += encode_gtpv1_user_location_information_ie(
				&(value->user_location_information ), buf + encoded);
	}

	if ((value->imei_sv.header.type == GTPV1_IE_IMEI_SV) && 
			(value->imei_sv.header.length >= 0)) {
		encoded += encode_gtpv1_imei_ie(&(value->imei_sv), 
				buf + encoded);
	}

	if ((value->extended_common_flag.header.type == GTPV1_IE_EXTENDED_COMMON_FLAG) && 
			(value->extended_common_flag.header.length >= 0)) {
		encoded += encode_gtpv1_extended_common_flags_ie(&(value->extended_common_flag), 
				buf + encoded);
	}
	
	if ((value->user_csg_information.header.type == GTPV1_IE_USER_CSG_INFORMATION) && 
			(value->user_csg_information.header.length >= 0)) {
		encoded += encode_gtpv1_user_csg_information_ie(&(value->user_csg_information), 
				buf + encoded);
	}
	
	if ((value->private_extension.header.type == GTPV1_IE_PRIVATE_EXTENSION) &&
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension),
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;
}

int encode_gtpv1_ms_info_change_notification_rsp(gtpv1_ms_info_change_notification_rsp_t *value, uint8_t *buf) {
	
	
	uint16_t encoded = 0;
	
	if(value == NULL || buf == NULL) {
		return -1;
	}
	
	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if (value->cause.header.type == GTPV1_IE_CAUSE) {
		encoded += encode_gtpv1_cause_ie(&(value->cause),
				buf + encoded);
	}

	if (value->imsi.header.type == GTPV1_IE_IMSI) {
		encoded += encode_gtpv1_imsi_ie(&(value->imsi), 
				buf + encoded);
	}

	if (value->linked_nsapi.header.type == GTPV1_IE_NSAPI) {
		encoded += encode_gtpv1_nsapi_ie(&(value->linked_nsapi), 
				buf + encoded);
	}

	if ((value->imei_sv.header.type == GTPV1_IE_IMEI_SV) && 
			(value->imei_sv.header.length >= 0)) {
		encoded += encode_gtpv1_imei_ie(&(value->imei_sv), 
				buf + encoded);
	}

	if ((value->ms_info_change_reporting_action.header.type == 
				GTPV1_IE_MS_INFO_CHANGE_REPORTING_ACTION) && 
			(value->ms_info_change_reporting_action.header.length >= 0)) {
		encoded += encode_gtpv1_ms_info_change_reporting_action_ie(
				&(value->ms_info_change_reporting_action), buf + encoded);
	}
	
	if ((value->csg_information_reporting_action.header.type == 
				GTPV1_IE_CSG_INFORMATION_REPORTING_ACTION) && 
			(value->csg_information_reporting_action.header.length >= 0)) {
		encoded += encode_gtpv1_csg_information_reporting_action_ie(
				&(value->csg_information_reporting_action), buf + encoded);
	}

	if ((value->private_extension.header.type == GTPV1_IE_PRIVATE_EXTENSION) &&
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension),
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;
}

int encode_gtpv1_identification_req(gtpv1_identification_req_t *value, uint8_t *buf){

	uint16_t encoded = 0;
	
	if(value == NULL || buf == NULL) {
		return -1;
	}

	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if (value->routing_area_identity.header.type == GTPV1_IE_ROUTEING_AREA_IDENTITY) {
		encoded += encode_gtpv1_routing_area_identity_ie(&(value->routing_area_identity),
				buf + encoded);
	}

	if (value->packet_tmsi.header.type == GTPV1_IE_PACKET_TMSI) {
		encoded += encode_gtpv1_packet_tmsi_ie(&(value->packet_tmsi),
				buf + encoded);
	}

	if (value->p_tmsi_signature.header.type == GTPV1_IE_P_TMSI_SIGNATURE) {
		encoded += encode_gtpv1_p_tmsi_signature_ie(&(value->p_tmsi_signature),
				buf + encoded);
	}

	if ((value->sgsn_addr_control_plane.header.type == GTPV1_IE_GSN_ADDR) &&
			(value->sgsn_addr_control_plane.header.length >= 0)) {
		encoded += encode_gtpv1_gsn_address_ie(&(value->sgsn_addr_control_plane),
				buf + encoded);
	}

	if ((value->hop_counter.header.type == GTPV1_IE_HOP_COUNTER) &&
			(value->hop_counter.header.length >= 0)) {
		encoded += encode_gtpv1_hop_counter_ie(&(value->hop_counter),
				buf + encoded);
	}

	if ((value->private_extension.header.type == GTPV1_IE_PRIVATE_EXTENSION) &&
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension),
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;
}

int encode_gtpv1_identification_rsp(gtpv1_identification_rsp_t *value, uint8_t *buf){

	uint16_t encoded = 0;

	if(value == NULL || buf == NULL) {
		return -1;
	}

	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if (value->cause.header.type == GTPV1_IE_CAUSE) {
		encoded += encode_gtpv1_cause_ie(&(value->cause),
				buf + encoded);
	}

	if (value->imsi.header.type == GTPV1_IE_IMSI) {
		encoded += encode_gtpv1_imsi_ie(&(value->imsi),
				buf + encoded);
	}

	if (value->auth_triplet.header.type == GTPV1_IE_AUTH_TRIPLET) {
		encoded += encode_gtpv1_auth_triplet_ie(&(value->auth_triplet),
				buf + encoded);
	}

	if ((value->auth_quintuplet.header.type == GTPV1_IE_AUTH_QUINTUPLET) &&
			(value->auth_quintuplet.header.length >= 0)) {
		encoded += encode_gtpv1_auth_quintuplet_ie(&(value->auth_quintuplet),
				buf + encoded);
	}

	if ((value->ue_usage_type.header.type == GTPV1_IE_UE_USAGE_TYPE) &&
			(value->ue_usage_type.header.length >= 0)) {
		encoded += encode_gtpv1_ue_usage_type_ie(&(value->ue_usage_type),
				buf + encoded);
	}

	if ((value->iov_updates_counter.header.type == GTPV1_IE_IOV_UPDATES_COUNTER) &&
			(value->iov_updates_counter.header.length >= 0)) {
		encoded += encode_gtpv1_iov_updates_counter_ie(&(value->iov_updates_counter),
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;
}

int encode_gtpv1_relocation_cancel_req(gtpv1_relocation_cancel_req_t *value, uint8_t *buf) {

	uint16_t encoded = 0;
	
	if(value == NULL || buf == NULL) {
		return -1;
	}
	
	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if (value->imsi.header.type == GTPV1_IE_IMSI) {
		encoded += encode_gtpv1_imsi_ie(&(value->imsi),
				buf + encoded);
	}

	if ((value->imei_sv.header.type == GTPV1_IE_IMEI_SV) &&
			(value->imei_sv.header.length >= 0)) {
		encoded += encode_gtpv1_imei_ie(&(value->imei_sv),
				buf + encoded);
	}

	if ((value->extended_common_flag.header.type == GTPV1_IE_EXTENDED_COMMON_FLAG) &&
			(value->extended_common_flag.header.length >= 0)) {
		encoded += encode_gtpv1_extended_common_flags_ie(&(value->extended_common_flag),
				buf + encoded);
	}

	if ((value->ext_ranap_cause.header.type == GTPV1_IE_EXTENDED_RANAP_CAUSE) &&
			(value->ext_ranap_cause.header.length >= 0)) {
		encoded += encode_gtpv1_extended_ranap_cause_ie(&(value->ext_ranap_cause),
				buf + encoded);
	}

	if ((value->private_extension.header.type == GTPV1_IE_PRIVATE_EXTENSION) &&
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension),
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;
}

int encode_gtpv1_relocation_cancel_rsp(gtpv1_relocation_cancel_rsp_t *value, uint8_t *buf) {

	uint16_t encoded = 0;
	
	if(value == NULL || buf == NULL) {
		return -1;
	}
	
	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if (value->cause.header.type == GTPV1_IE_CAUSE) {
		encoded += encode_gtpv1_cause_ie(&(value->cause),
				buf + encoded);
	}

	if ((value->private_extension.header.type == GTPV1_IE_PRIVATE_EXTENSION) &&
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension),
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;
}

int encode_gtpv1_forward_relocation_complete_ack(gtpv1_forward_relocation_complete_ack_t *value, uint8_t *buf) {
	
	uint16_t encoded = 0;
	
	if (value == NULL || buf == NULL) {
		return -1;
	}
	
	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if (value->cause.header.type == GTPV1_IE_CAUSE) {
		encoded += encode_gtpv1_cause_ie(&(value->cause),
				buf + encoded);
	}

	if ((value->private_extension.header.type == GTPV1_IE_PRIVATE_EXTENSION) &&
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension),
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;
}

int encode_gtpv1_forward_relocation_complete(gtpv1_forward_relocation_complete_t *value, uint8_t *buf) {
	
	uint16_t encoded = 0;
	
	if (value == NULL || buf == NULL) {
		return -1;
	}
	
	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if ((value->private_extension.header.type == GTPV1_IE_PRIVATE_EXTENSION) &&
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension),
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;
}


int encode_gtpv1_forward_srns_context_ack(gtpv1_forward_srns_context_ack_t *value, uint8_t *buf) {
	
	uint16_t encoded = 0;

	if (value == NULL || buf == NULL) {
		return -1;
	}

	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if (value->cause.header.type == GTPV1_IE_CAUSE) {
		encoded += encode_gtpv1_cause_ie(&(value->cause),
				buf + encoded);
	}

	if ((value->private_extension.header.type == GTPV1_IE_PRIVATE_EXTENSION) &&
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension),
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;
}

int encode_gtpv1_forward_srns_ctxt(gtpv1_forward_srns_ctxt_t *value, uint8_t *buf) {

	uint16_t encoded = 0;
	
	if (value == NULL || buf == NULL) {
		return -1;
	}
	
	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if (value->rab_context.header.type == GTPV1_IE_RAB_CONTEXT) {
		encoded += encode_gtpv1_rab_context_ie(&(value->rab_context),
				buf + encoded);
	}

	if ((value->pdcp_ctxt.header.type == GTPV1_IE_SRC_RNC_PDCP_CTXT_INFO) &&
			(value->pdcp_ctxt.header.length >= 0)) {
		encoded += encode_gtpv1_src_rnc_pdcp_ctxt_info_ie(&(value->pdcp_ctxt),
				buf + encoded);
	}

	if ((value->pdu_num.header.type == GTPV1_IE_PDU_NUMBERS) &&
			(value->pdu_num.header.length >= 0)) {
		encoded += encode_gtpv1_pdu_numbers_ie(&(value->pdu_num),
				buf + encoded);
	}

	if ((value->private_extension.header.type == GTPV1_IE_PRIVATE_EXTENSION) &&
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension),
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;
}

int encode_gtpv1_sgsn_context_ack(gtpv1_sgsn_context_ack_t *value, uint8_t *buf) {

	uint16_t encoded = 0;
	
	if (value == NULL || buf == NULL) {
		return -1;
	}
	
	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if (value->cause.header.type == GTPV1_IE_CAUSE) {
		encoded += encode_gtpv1_cause_ie(&(value->cause),
				buf + encoded);
	}

	if (value->teid_2.header.type == GTPV1_IE_TEID_DATA_2) {
		encoded += encode_gtpv1_teid_data_2_ie(&(value->teid_2),
				buf + encoded);
	}

	if ((value->sgsn_addr_user_traffic.header.type == GTPV1_IE_GSN_ADDR) &&
			(value->sgsn_addr_user_traffic.header.length >= 0)) {
		encoded += encode_gtpv1_gsn_address_ie(&(value->sgsn_addr_user_traffic),
				buf + encoded);
	}

	if ((value->sgsn_number.header.type == GTPV1_IE_SGSN_NUMBER) &&
			(value->sgsn_number.header.length >= 0)) {
		encoded += encode_gtpv1_sgsn_number_ie(&(value->sgsn_number),
				buf + encoded);
	}

	if ((value->node_id.header.type == GTPV1_IE_NODE_IDENTIFIER) &&
			(value->node_id.header.length >= 0)) {
		encoded += encode_gtpv1_node_identifier_ie(&(value->node_id),
				buf + encoded);
	}

	if ((value->private_extension.header.type == GTPV1_IE_PRIVATE_EXTENSION) &&
			(value->private_extension.header.length >= 0)) {
		encoded += encode_gtpv1_private_extension_ie(&(value->private_extension),
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;
}

int encode_gtpv1_supported_extension_headers_notification(gtpv1_supported_extension_headers_notification_t *value, uint8_t *buf) {

	uint16_t encoded = 0;
	
	if (value == NULL || buf == NULL) {
		return -1;
	}
	
	encoded += encode_gtpv1_header(&value->header, buf +encoded);

	if ((value->ext_header_list.type == GTPV1_IE_EXTENSION_HEADER_TYPE_LIST) &&
			(value->ext_header_list.length >= 0)) {
		encoded += encode_gtpv1_extension_header_type_list_ie(&(value->ext_header_list),
				buf + encoded);
	}

	((gtpv1_header_t *) buf)->message_len = htons(encoded - 8);

	return encoded;
}
