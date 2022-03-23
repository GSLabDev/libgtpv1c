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

#include "fill_gtpv1_ies.h"

void fill_gtpv1_echo_req(gtpv1_echo_req_t *echo_request) {
	
	echo_request->header.version = 1;
	echo_request->header.protocol_type = 1;
	echo_request->header.spare = 0;
	echo_request->header.extension_header = 0;
	echo_request->header.seq_num_flag = 0;
	echo_request->header.n_pdu_flag = 0;

	echo_request->header.message_type = GTPV1_ECHO_REQUEST;
	echo_request->header.message_len = 9;
	echo_request->header.teid = 0;
	echo_request->header.seq = 0x00fe;
	echo_request->header.n_pdu_number = 4;
	echo_request->header.next_extension_header_type = 0;

	echo_request->private_extension.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	echo_request->private_extension.header.length = 6;
	echo_request->private_extension.extension_identifier = 12;
	strncpy((char *)&echo_request->private_extension.extension_value, "2021", 4);

	return;
}

void fill_gtpv1_echo_rsp(gtpv1_echo_rsp_t *echo_rsp){

	echo_rsp->header.version = 1;
	echo_rsp->header.protocol_type = 1;
	echo_rsp->header.spare = 0;
	echo_rsp->header.extension_header = 0;
	echo_rsp->header.seq_num_flag = 0;
	echo_rsp->header.n_pdu_flag = 0;

	echo_rsp->header.message_type = GTPV1_ECHO_RESPONSE;
	echo_rsp->header.message_len = 11;
	echo_rsp->header.teid = 0x372f0000;
	echo_rsp->header.seq = 0x00fe;
	echo_rsp->header.n_pdu_number = 4;
	echo_rsp->header.next_extension_header_type = 0;

	echo_rsp->recovery.header.type = GTPV1_IE_RECOVERY;
	echo_rsp->recovery.restart_counter = 2;

	echo_rsp->private_extension.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	echo_rsp->private_extension.header.length = 6;
	echo_rsp->private_extension.extension_identifier = 12;
	strncpy((char *)&echo_rsp->private_extension.extension_value, "2021", 4);

	return;
}

void fill_gtpv1_version_not_supported(gtpv1_version_not_supported_t *version_not_supported){

	version_not_supported->header.version = 1;
	version_not_supported->header.protocol_type = 1;
	version_not_supported->header.spare = 0;
	version_not_supported->header.extension_header = 0;
	version_not_supported->header.seq_num_flag = 0;
	version_not_supported->header.n_pdu_flag = 0;

	version_not_supported->header.message_type = GTPV1_VERSION_NOT_SUPPORTED;
	version_not_supported->header.message_len = 0 ;
	version_not_supported->header.teid = 0;
	version_not_supported->header.seq = 0;
	version_not_supported->header.n_pdu_number = 0;
	version_not_supported->header.next_extension_header_type = 0;

	return;
}

void fill_gtpv1_supported_extension_headers_notification(gtpv1_supported_extension_headers_notification_t *supported_extension_headers_notification){

	supported_extension_headers_notification->header.version = 1;
	supported_extension_headers_notification->header.protocol_type = 1;
	supported_extension_headers_notification->header.spare = 0;
	supported_extension_headers_notification->header.extension_header = 0;
	supported_extension_headers_notification->header.seq_num_flag = 0;
	supported_extension_headers_notification->header.n_pdu_flag = 0;

	supported_extension_headers_notification->header.message_type = GTPV1_SUPPORTED_EXTENSION_HEADERS_NOTIFICATION;
	supported_extension_headers_notification->header.message_len = 4;
	supported_extension_headers_notification->header.teid = 0x372f0000;
	supported_extension_headers_notification->header.seq = 0x00fe;
	supported_extension_headers_notification->header.n_pdu_number = 4;
	supported_extension_headers_notification->header.next_extension_header_type = 0;

	supported_extension_headers_notification->ext_header_list.type = GTPV1_IE_EXTENSION_HEADER_TYPE_LIST;
	supported_extension_headers_notification->ext_header_list.length = 2;
	supported_extension_headers_notification->ext_header_list.extension_type_list[0] = 1;
	supported_extension_headers_notification->ext_header_list.extension_type_list[1] = 0;

	return;
}

void fill_gtpv1_create_pdp_ctxt_req(gtpv1_create_pdp_ctxt_req_t *create_pdp_ctxt_req) {

	create_pdp_ctxt_req->header.version = 1;
	create_pdp_ctxt_req->header.protocol_type = 1;
	create_pdp_ctxt_req->header.spare = 0;
	create_pdp_ctxt_req->header.extension_header = 0;
	create_pdp_ctxt_req->header.seq_num_flag = 0;
	create_pdp_ctxt_req->header.n_pdu_flag = 0;

	create_pdp_ctxt_req->header.message_type = GTPV1_CREATE_PDP_CTXT_REQ;
	create_pdp_ctxt_req->header.message_len = 290;
	create_pdp_ctxt_req->header.teid = 0;
	create_pdp_ctxt_req->header.seq = 0;
	create_pdp_ctxt_req->header.n_pdu_number = 0;
	create_pdp_ctxt_req->header.next_extension_header_type = 0;

	create_pdp_ctxt_req->imsi.header.type = GTPV1_IE_IMSI;
	create_pdp_ctxt_req->imsi.imsi_number_digits = 272031000000000;

	create_pdp_ctxt_req->routing_area_identity.header.type = GTPV1_IE_ROUTEING_AREA_IDENTITY;
	create_pdp_ctxt_req->routing_area_identity.rai_value.mcc_digit_2 = 0x0;
	create_pdp_ctxt_req->routing_area_identity.rai_value.mcc_digit_1 = 0x4;
	create_pdp_ctxt_req->routing_area_identity.rai_value.mnc_digit_3 = 0x8;
	create_pdp_ctxt_req->routing_area_identity.rai_value.mcc_digit_3 = 0x4;
	create_pdp_ctxt_req->routing_area_identity.rai_value.mnc_digit_2 = 0x7;
	create_pdp_ctxt_req->routing_area_identity.rai_value.mnc_digit_1 = 0x0;
	create_pdp_ctxt_req->routing_area_identity.rai_value.lac = 0x14;
	create_pdp_ctxt_req->routing_area_identity.rai_value.rac = 0x14;

	create_pdp_ctxt_req->recovery.header.type = GTPV1_IE_RECOVERY;
	create_pdp_ctxt_req->recovery.restart_counter = 2;

	create_pdp_ctxt_req->selection_mode.header.type = GTPV1_IE_SELECTION_MODE;
	create_pdp_ctxt_req->selection_mode.spare2 = 0;
	create_pdp_ctxt_req->selection_mode.selec_mode = 1;

	create_pdp_ctxt_req->tunn_endpt_idnt_data_1.header.type = GTPV1_IE_TEID_DATA_1;
	create_pdp_ctxt_req->tunn_endpt_idnt_data_1.teid = 0x0fffeee;

	create_pdp_ctxt_req->tunn_endpt_idnt_control_plane.header.type = GTPV1_IE_TEID_CONTROL_PLANE;
	create_pdp_ctxt_req->tunn_endpt_idnt_control_plane.teid = 0x00ab;
	
	create_pdp_ctxt_req->nsapi.header.type = GTPV1_IE_NSAPI;
	create_pdp_ctxt_req->nsapi.spare = 0;
	create_pdp_ctxt_req->nsapi.nsapi_value = 5;
	
	create_pdp_ctxt_req->linked_nsapi.header.type = GTPV1_IE_NSAPI;
	create_pdp_ctxt_req->linked_nsapi.spare = 0;
	create_pdp_ctxt_req->linked_nsapi.nsapi_value = 9;
	
	create_pdp_ctxt_req->chrgng_char.header.type = GTPV1_IE_CHRGNG_CHAR;
	create_pdp_ctxt_req->chrgng_char.chrgng_char_val = 1;
		
	create_pdp_ctxt_req->trace_reference.header.type = GTPV1_IE_TRACE_REFERENCE;
	create_pdp_ctxt_req->trace_reference.trace_reference = 9;

	create_pdp_ctxt_req->trace_type.header.type = GTPV1_IE_TRACE_TYPE;
	create_pdp_ctxt_req->trace_type.trace_type = 9;
		
	create_pdp_ctxt_req->end_user_address.header.type = GTPV1_IE_END_USER_ADDR;
	create_pdp_ctxt_req->end_user_address.header.length = 6;
	create_pdp_ctxt_req->end_user_address.spare = 0xf;
	create_pdp_ctxt_req->end_user_address.pdp_type_org = 1;
	create_pdp_ctxt_req->end_user_address.pdp_type_number = 0x21;
	create_pdp_ctxt_req->end_user_address.pdp_address.ipv4 = 3232235564;
	
	create_pdp_ctxt_req->apn.header.type = GTPV1_IE_APN;
	create_pdp_ctxt_req->apn.header.length = 13;
	strncpy((char *)&create_pdp_ctxt_req->apn.apn_value,"nextphones.co",13);

	create_pdp_ctxt_req->protocol_config_options.header.type = GTPV1_IE_PROTOCOL_CONFIG_OPTIONS;
	create_pdp_ctxt_req->protocol_config_options.header.length = 25;
	create_pdp_ctxt_req->protocol_config_options.pco.pco_flag_ext  = 1;
	create_pdp_ctxt_req->protocol_config_options.pco.pco_flag_spare  = 0;
	create_pdp_ctxt_req->protocol_config_options.pco.pco_cfg_proto  = 1;
	create_pdp_ctxt_req->protocol_config_options.pco.pco_content_count  = 2;
	create_pdp_ctxt_req->protocol_config_options.pco.pco_content[0].prot_or_cont_id  = 2;
	create_pdp_ctxt_req->protocol_config_options.pco.pco_content[0].length  = 9;
	strncpy((char *)&create_pdp_ctxt_req->protocol_config_options.pco.pco_content[0].content,"355240599",9);
	create_pdp_ctxt_req->protocol_config_options.pco.pco_content[1].prot_or_cont_id  = 2;
	create_pdp_ctxt_req->protocol_config_options.pco.pco_content[1].length  = 9;
	strncpy((char *)&create_pdp_ctxt_req->protocol_config_options.pco.pco_content[1].content,"355240589",9);

	create_pdp_ctxt_req->sgsn_address_for_signalling.header.type = GTPV1_IE_GSN_ADDR;
	create_pdp_ctxt_req->sgsn_address_for_signalling.header.length = 4;
	create_pdp_ctxt_req->sgsn_address_for_signalling.gsn_address.ipv4 = 3232235564;

	create_pdp_ctxt_req->sgsn_address_for_user_traffic.header.type = GTPV1_IE_GSN_ADDR;
	create_pdp_ctxt_req->sgsn_address_for_user_traffic.header.length = 4;
	create_pdp_ctxt_req->sgsn_address_for_user_traffic.gsn_address.ipv4 = 3232235564;	

	create_pdp_ctxt_req->msisdn.header.type = GTPV1_IE_MSISDN;
	create_pdp_ctxt_req->msisdn.header.length = 2;
	strncpy((char *)&create_pdp_ctxt_req->msisdn.msisdn_number_digits, "22",2);
	
	create_pdp_ctxt_req->qos_profile.header.type = GTPV1_IE_QOS;
	create_pdp_ctxt_req->qos_profile.header.length = 21;
	create_pdp_ctxt_req->qos_profile.qos.allocation_retention_priority = 2;
	create_pdp_ctxt_req->qos_profile.qos.spare1 = 0;
	create_pdp_ctxt_req->qos_profile.qos.delay_class = 2;
	create_pdp_ctxt_req->qos_profile.qos.reliablity_class = 2;
	create_pdp_ctxt_req->qos_profile.qos.peak_throughput = 3;
	create_pdp_ctxt_req->qos_profile.qos.spare2 = 0;
	create_pdp_ctxt_req->qos_profile.qos.precedence_class = 1;
	create_pdp_ctxt_req->qos_profile.qos.spare3 = 0;
	create_pdp_ctxt_req->qos_profile.qos.mean_throughput = 4;
	create_pdp_ctxt_req->qos_profile.qos.traffic_class = 1;
	create_pdp_ctxt_req->qos_profile.qos.delivery_order = 1;
	create_pdp_ctxt_req->qos_profile.qos.delivery_erroneous_sdu = 2;
	create_pdp_ctxt_req->qos_profile.qos.max_sdu_size = 3;
	create_pdp_ctxt_req->qos_profile.qos.max_bitrate_uplink = 123;
	create_pdp_ctxt_req->qos_profile.qos.max_bitrate_downlink = 254;
	create_pdp_ctxt_req->qos_profile.qos.residual_ber = 1;
	create_pdp_ctxt_req->qos_profile.qos.sdu_error_ratio = 1; 
	create_pdp_ctxt_req->qos_profile.qos.transfer_delay = 1; 
	create_pdp_ctxt_req->qos_profile.qos.traffic_handling_priority = 2;
	create_pdp_ctxt_req->qos_profile.qos.guaranteed_bitrate_uplink = 122;
	create_pdp_ctxt_req->qos_profile.qos.guaranteed_bitrate_downlink = 222;
	create_pdp_ctxt_req->qos_profile.qos.spare4 = 0; 
	create_pdp_ctxt_req->qos_profile.qos.signalling_indication = 1;
	create_pdp_ctxt_req->qos_profile.qos.source_statistics_descriptor = 1;
	create_pdp_ctxt_req->qos_profile.qos.max_bitrate_downlink_ext1 = 250;
	create_pdp_ctxt_req->qos_profile.qos.guaranteed_bitrate_downlink_ext1 = 11;
	create_pdp_ctxt_req->qos_profile.qos.max_bitrate_uplink_ext1 = 33;
	create_pdp_ctxt_req->qos_profile.qos.guaranteed_bitrate_uplink_ext1 = 22;
	create_pdp_ctxt_req->qos_profile.qos.max_bitrate_downlink_ext2 = 44;
	create_pdp_ctxt_req->qos_profile.qos.guaranteed_bitrate_downlink_ext2 = 33;
	create_pdp_ctxt_req->qos_profile.qos.max_bitrate_uplink_ext2 = 34;
	create_pdp_ctxt_req->qos_profile.qos.guaranteed_bitrate_uplink_ext2 = 23;	
	
	create_pdp_ctxt_req->tft.header.type = GTPV1_IE_TFT;
	create_pdp_ctxt_req->tft.header.length = 19;
	create_pdp_ctxt_req->tft.tft_op_code = 1;
	create_pdp_ctxt_req->tft.e_bit = 1;
	create_pdp_ctxt_req->tft.no_packet_filters = 2;
	create_pdp_ctxt_req->tft.packet_filter_list_del[0].spare = 0;
	create_pdp_ctxt_req->tft.packet_filter_list_del[0].filter_id = 1;
	create_pdp_ctxt_req->tft.packet_filter_list_del[1].spare = 0;
	create_pdp_ctxt_req->tft.packet_filter_list_del[1].filter_id = 2;
	create_pdp_ctxt_req->tft.packet_filter_list_new[0].spare = 0;
	create_pdp_ctxt_req->tft.packet_filter_list_new[0].filter_direction = 1;
	create_pdp_ctxt_req->tft.packet_filter_list_new[0].filter_id = 5;
	create_pdp_ctxt_req->tft.packet_filter_list_new[0].filter_eval_precedence = 1;
	create_pdp_ctxt_req->tft.packet_filter_list_new[0].filter_content_length = 1;
	create_pdp_ctxt_req->tft.packet_filter_list_new[0].filter_content[0] = 1;
	create_pdp_ctxt_req->tft.packet_filter_list_new[1].spare = 0;
	create_pdp_ctxt_req->tft.packet_filter_list_new[1].filter_direction = 2;
	create_pdp_ctxt_req->tft.packet_filter_list_new[1].filter_id = 5;
	create_pdp_ctxt_req->tft.packet_filter_list_new[1].filter_eval_precedence = 1;
	create_pdp_ctxt_req->tft.packet_filter_list_new[1].filter_content_length = 2;
	create_pdp_ctxt_req->tft.packet_filter_list_new[1].filter_content[0] = 1;
	create_pdp_ctxt_req->tft.packet_filter_list_new[1].filter_content[1] = 0;
	create_pdp_ctxt_req->tft.parameters_list[0].parameter_id = 1;
	create_pdp_ctxt_req->tft.parameters_list[0].parameter_content_length = 2;
	create_pdp_ctxt_req->tft.parameters_list[0].parameter_content[0] = 1;
	create_pdp_ctxt_req->tft.parameters_list[0].parameter_content[1] = 2;
	create_pdp_ctxt_req->tft.parameters_list[1].parameter_id = 1;
	create_pdp_ctxt_req->tft.parameters_list[1].parameter_content_length = 3;
	create_pdp_ctxt_req->tft.parameters_list[1].parameter_content[0] = 3;
	create_pdp_ctxt_req->tft.parameters_list[1].parameter_content[1] = 2;
	create_pdp_ctxt_req->tft.parameters_list[1].parameter_content[2] = 0;

	create_pdp_ctxt_req->trigger_id.header.type = GTPV1_IE_TRIGGER_ID;
	create_pdp_ctxt_req->trigger_id.header.length = 5;
	memset(&create_pdp_ctxt_req->trigger_id.trigger_id,'2',5);

	create_pdp_ctxt_req->omc_identity.header.type = GTPV1_IE_OMC_IDENTITY;
	create_pdp_ctxt_req->omc_identity.header.length = 7;
	strncpy((char *)&create_pdp_ctxt_req->omc_identity.omc_identity,"abc.com",7);
	
	create_pdp_ctxt_req->common_flag.header.type = GTPV1_IE_COMMON_FLAG;
	create_pdp_ctxt_req->common_flag.header.length = 1;
	create_pdp_ctxt_req->common_flag.dual_addr_bearer_flag = 1;
	create_pdp_ctxt_req->common_flag.upgrade_qos_supported = 1;
	create_pdp_ctxt_req->common_flag.nrsn = 1;
	create_pdp_ctxt_req->common_flag.no_qos_negotiation = 1;
	create_pdp_ctxt_req->common_flag.mbms_counting_information = 1;
	create_pdp_ctxt_req->common_flag.ran_procedures_ready = 1;
	create_pdp_ctxt_req->common_flag.mbms_service_type = 1;
	create_pdp_ctxt_req->common_flag.prohibit_payload_compression = 1;
	
	create_pdp_ctxt_req->apn_restriction.header.type = GTPV1_IE_APN_RESTRICTION;
	create_pdp_ctxt_req->apn_restriction.header.length = 1;
	create_pdp_ctxt_req->apn_restriction.restriction_type_value = 12;
	
	create_pdp_ctxt_req->rat_type.header.type = GTPV1_IE_RAT_TYPE;
	create_pdp_ctxt_req->rat_type.header.length = 1;
	create_pdp_ctxt_req->rat_type.rat_type = 2;
	
	create_pdp_ctxt_req->user_location_information.header.type = GTPV1_IE_USER_LOCATION_INFORMATION;
	create_pdp_ctxt_req->user_location_information.header.length = 8;
	create_pdp_ctxt_req->user_location_information.geographic_location_type = 1;
	create_pdp_ctxt_req->user_location_information.mcc_digit_2 = 0x0;
	create_pdp_ctxt_req->user_location_information.mcc_digit_1 = 0x4;
	create_pdp_ctxt_req->user_location_information.mnc_digit_3 = 0x8;
	create_pdp_ctxt_req->user_location_information.mcc_digit_3 = 0x4;
	create_pdp_ctxt_req->user_location_information.mnc_digit_2 = 0x7;
	create_pdp_ctxt_req->user_location_information.mnc_digit_1 = 0x0;
	create_pdp_ctxt_req->user_location_information.lac = 0x1;
	create_pdp_ctxt_req->user_location_information.ci_sac_rac = 0x1;

	create_pdp_ctxt_req->ms_time_zone.header.type = GTPV1_IE_MS_TIME_ZONE;
	create_pdp_ctxt_req->ms_time_zone.header.length = 2;
	create_pdp_ctxt_req->ms_time_zone.time_zone = 1;
	create_pdp_ctxt_req->ms_time_zone.spare = 0;
	create_pdp_ctxt_req->ms_time_zone.daylight_saving_time = 1;

	create_pdp_ctxt_req->imei_sv.header.type = GTPV1_IE_IMEI_SV;
	create_pdp_ctxt_req->imei_sv.header.length = 8;
	create_pdp_ctxt_req->imei_sv.imei_sv = 0b0001000100010001000100010001000100100010001000100010001000010001;
	/*
	create_pdp_ctxt_req->camel_charging_information_container.header.type = GTPV1_IE_CAMEL_CHARGING_INFORMATION_CONTAINER;
	create_pdp_ctxt_req->camel_charging_information_container.header.length = 4;
	strncpy((char *)&create_pdp_ctxt_req->camel_charging_information_container.camel_information_pdp_ie,"abcd",4);
	*/

	create_pdp_ctxt_req->additional_trace_information.header.type = GTPV1_IE_ADDITIONAL_TRACE_INFORMATION;
	create_pdp_ctxt_req->additional_trace_information.header.length = 9;
	create_pdp_ctxt_req->additional_trace_information.trace_reference_2 = 1;
	create_pdp_ctxt_req->additional_trace_information.trace_recording_session_reference = 1;
	create_pdp_ctxt_req->additional_trace_information.spare1 = 0;
	create_pdp_ctxt_req->additional_trace_information.triggering_events_in_ggsn_mbms_ctxt = 0;
	create_pdp_ctxt_req->additional_trace_information.triggering_events_in_ggsn_pdp_ctxt = 1;
	create_pdp_ctxt_req->additional_trace_information.trace_depth = 1;
	create_pdp_ctxt_req->additional_trace_information.spare2 = 0;
	create_pdp_ctxt_req->additional_trace_information.list_of_interfaces_in_ggsn_gmb = 0;
	create_pdp_ctxt_req->additional_trace_information.list_of_interfaces_in_ggsn_gi = 0;
	create_pdp_ctxt_req->additional_trace_information.list_of_interfaces_in_ggsn_gn = 1;
	create_pdp_ctxt_req->additional_trace_information.trace_activity_control = 1;

	create_pdp_ctxt_req->correlation_id.header.type = GTPV1_IE_CORRELATION_ID;
	create_pdp_ctxt_req->correlation_id.header.length = 1;
	create_pdp_ctxt_req->correlation_id.correlation_id = 5;
	
	create_pdp_ctxt_req->evolved_allocation_retention_priority_1.header.type = GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_I;
	create_pdp_ctxt_req->evolved_allocation_retention_priority_1.header.length = 1;
	create_pdp_ctxt_req->evolved_allocation_retention_priority_1.spare = 0;
	create_pdp_ctxt_req->evolved_allocation_retention_priority_1.pci = 1;
	create_pdp_ctxt_req->evolved_allocation_retention_priority_1.pl = 12;
	create_pdp_ctxt_req->evolved_allocation_retention_priority_1.spare2 = 0;
	create_pdp_ctxt_req->evolved_allocation_retention_priority_1.pvi = 1;
	
	create_pdp_ctxt_req->extended_common_flag.header.type = GTPV1_IE_EXTENDED_COMMON_FLAG;
	create_pdp_ctxt_req->extended_common_flag.header.length = 1;
	create_pdp_ctxt_req->extended_common_flag.uasi = 1;
	create_pdp_ctxt_req->extended_common_flag.bdwi = 1;
	create_pdp_ctxt_req->extended_common_flag.pcri = 1;
	create_pdp_ctxt_req->extended_common_flag.vb = 1;
	create_pdp_ctxt_req->extended_common_flag.retloc = 1;
	create_pdp_ctxt_req->extended_common_flag.cpsr = 1;
	create_pdp_ctxt_req->extended_common_flag.ccrsi = 1;
	create_pdp_ctxt_req->extended_common_flag.unauthenticated_imsi = 1;

	create_pdp_ctxt_req->user_csg_information.header.type = GTPV1_IE_USER_CSG_INFORMATION;
	create_pdp_ctxt_req->user_csg_information.header.length = 8;
	create_pdp_ctxt_req->user_csg_information.mcc_digit_2 = 0x0;
	create_pdp_ctxt_req->user_csg_information.mcc_digit_1 = 0x4;
	create_pdp_ctxt_req->user_csg_information.mnc_digit_3 = 0x8;
	create_pdp_ctxt_req->user_csg_information.mcc_digit_3 = 0x4;
	create_pdp_ctxt_req->user_csg_information.mnc_digit_2 = 0x7;
	create_pdp_ctxt_req->user_csg_information.mnc_digit_1 = 0x0;
	create_pdp_ctxt_req->user_csg_information.spare = 0;
	create_pdp_ctxt_req->user_csg_information.csg_id = 1;
	create_pdp_ctxt_req->user_csg_information.csg_id_II = 1;
	create_pdp_ctxt_req->user_csg_information.access_mode = 1;
	create_pdp_ctxt_req->user_csg_information.spare2 = 0;
	create_pdp_ctxt_req->user_csg_information.cmi = 1;

	create_pdp_ctxt_req->apn_ambr.header.type = GTPV1_IE_APN_AMBR;
	create_pdp_ctxt_req->apn_ambr.header.length = 8;
	create_pdp_ctxt_req->apn_ambr.apn_ambr_uplink = 10;
	create_pdp_ctxt_req->apn_ambr.apn_ambr_downlink = 7;

	create_pdp_ctxt_req->signalling_priority_indication.header.type = GTPV1_IE_SIGNALLING_PRIORITY_INDICATION;
	create_pdp_ctxt_req->signalling_priority_indication.header.length = 1;
	create_pdp_ctxt_req->signalling_priority_indication.spare = 0;
	create_pdp_ctxt_req->signalling_priority_indication.lapi = 1;
		
	create_pdp_ctxt_req->cn_operator_selection_entity.header.type = GTPV1_IE_CN_OPERATOR_SELECTION_ENTITY;
	create_pdp_ctxt_req->cn_operator_selection_entity.header.length = 1;
	create_pdp_ctxt_req->cn_operator_selection_entity.spare = 0;
	create_pdp_ctxt_req->cn_operator_selection_entity.selection_entity = 2;

	create_pdp_ctxt_req->mapped_ue_usage_type.header.type = GTPV1_IE_MAPPED_UE_USAGE_TYPE;
	create_pdp_ctxt_req->mapped_ue_usage_type.header.length = 2;
	create_pdp_ctxt_req->mapped_ue_usage_type.mapped_ue_usage_type = 2;

	create_pdp_ctxt_req->up_function_selection_indication.header.type = GTPV1_IE_UP_FUNCTION_SELECTION_INDICATION;
	create_pdp_ctxt_req->up_function_selection_indication.header.length = 1;
	create_pdp_ctxt_req->up_function_selection_indication.spare = 0;
	create_pdp_ctxt_req->up_function_selection_indication.dcnr = 1;

	create_pdp_ctxt_req->private_extension.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	create_pdp_ctxt_req->private_extension.header.length = 6;
	create_pdp_ctxt_req->private_extension.extension_identifier = 12;
	strncpy((char *)&create_pdp_ctxt_req->private_extension.extension_value, "2021", 4);

	return;
}

void fill_gtpv1_create_pdp_ctxt_rsp(gtpv1_create_pdp_ctxt_rsp_t *create_pdp_ctxt_rsp) {

	create_pdp_ctxt_rsp->header.version = 1;
	create_pdp_ctxt_rsp->header.protocol_type = 1;
	create_pdp_ctxt_rsp->header.spare = 0;
	create_pdp_ctxt_rsp->header.extension_header = 0;
	create_pdp_ctxt_rsp->header.seq_num_flag = 0;
	create_pdp_ctxt_rsp->header.n_pdu_flag = 0;
	
	create_pdp_ctxt_rsp->header.message_type = GTPV1_CREATE_PDP_CTXT_RSP;
	create_pdp_ctxt_rsp->header.message_len = 234;
	create_pdp_ctxt_rsp->header.teid = 0x372f0000;
	create_pdp_ctxt_rsp->header.seq = 0x00fe;
	create_pdp_ctxt_rsp->header.n_pdu_number = 4;
	create_pdp_ctxt_rsp->header.next_extension_header_type = 0;

	create_pdp_ctxt_rsp->cause.header.type = GTPV1_IE_CAUSE;
	create_pdp_ctxt_rsp->cause.cause_value = 128;

	create_pdp_ctxt_rsp->reordering_req.header.type = GTPV1_IE_REORDERING_REQ;
	create_pdp_ctxt_rsp->reordering_req.spare = 0;
	create_pdp_ctxt_rsp->reordering_req.reord_req = 0;

	create_pdp_ctxt_rsp->recovery.header.type = GTPV1_IE_RECOVERY;
	create_pdp_ctxt_rsp->recovery.restart_counter = 2;

	create_pdp_ctxt_rsp->tunn_endpt_idnt_data_1.header.type = GTPV1_IE_TEID_DATA_1;
	create_pdp_ctxt_rsp->tunn_endpt_idnt_data_1.teid = 0x08020000;

	create_pdp_ctxt_rsp->tunn_endpt_idnt_control_plane.header.type = GTPV1_IE_TEID_CONTROL_PLANE;
	create_pdp_ctxt_rsp->tunn_endpt_idnt_control_plane.teid = 0x08010000;

	create_pdp_ctxt_rsp->nsapi.header.type = GTPV1_IE_NSAPI;
	create_pdp_ctxt_rsp->nsapi.spare = 0;
	create_pdp_ctxt_rsp->nsapi.nsapi_value = 8;

	create_pdp_ctxt_rsp->charging_id.header.type = GTPV1_IE_CHARGING_ID;
	create_pdp_ctxt_rsp->charging_id.chrgng_id_val = 0x0330410b;

	create_pdp_ctxt_rsp->end_user_address.header.type = GTPV1_IE_END_USER_ADDR;
	create_pdp_ctxt_rsp->end_user_address.header.length = 22;
	create_pdp_ctxt_rsp->end_user_address.spare = 0xf;
	create_pdp_ctxt_rsp->end_user_address.pdp_type_org = 1;
	create_pdp_ctxt_rsp->end_user_address.pdp_type_number = 0x8D;
	create_pdp_ctxt_rsp->end_user_address.pdp_address.ipv4 = 3232235564;
	char *str1 = "2001:db80:3333:4444:5555:6666:7777:8888";
	inet_pton(AF_INET6, str1, create_pdp_ctxt_rsp->end_user_address.pdp_address.ipv6);

	create_pdp_ctxt_rsp->protocol_config_options.header.type = GTPV1_IE_PROTOCOL_CONFIG_OPTIONS;
	create_pdp_ctxt_rsp->protocol_config_options.header.length = 25;
	create_pdp_ctxt_rsp->protocol_config_options.pco.pco_flag_ext  = 1;
	create_pdp_ctxt_rsp->protocol_config_options.pco.pco_flag_spare  = 0;
	create_pdp_ctxt_rsp->protocol_config_options.pco.pco_cfg_proto  = 1;
	create_pdp_ctxt_rsp->protocol_config_options.pco.pco_content_count  = 2;
	create_pdp_ctxt_rsp->protocol_config_options.pco.pco_content[0].prot_or_cont_id  = 2;
	create_pdp_ctxt_rsp->protocol_config_options.pco.pco_content[0].length  = 9;
	strncpy((char *)&create_pdp_ctxt_rsp->protocol_config_options.pco.pco_content[0].content,"355240599",9);
	create_pdp_ctxt_rsp->protocol_config_options.pco.pco_content[1].prot_or_cont_id  = 2;
	create_pdp_ctxt_rsp->protocol_config_options.pco.pco_content[1].length  = 9;
	strncpy((char *)&create_pdp_ctxt_rsp->protocol_config_options.pco.pco_content[1].content,"355240589",9);

	create_pdp_ctxt_rsp->gsn_addr_1.header.type = GTPV1_IE_GSN_ADDR;
	create_pdp_ctxt_rsp->gsn_addr_1.header.length = 4;
	create_pdp_ctxt_rsp->gsn_addr_1.gsn_address.ipv4 = 3232235564;

	create_pdp_ctxt_rsp->gsn_addr_2.header.type = GTPV1_IE_GSN_ADDR;
	create_pdp_ctxt_rsp->gsn_addr_2.header.length = 4;
	create_pdp_ctxt_rsp->gsn_addr_2.gsn_address.ipv4 = 3232235563;

	create_pdp_ctxt_rsp->gsn_addr_3.header.type = GTPV1_IE_GSN_ADDR;
	create_pdp_ctxt_rsp->gsn_addr_3.header.length = 16;	
	char *str2 = "2001:db80:3333:4444:5555:6666:7777:8888";
	inet_pton(AF_INET6, str2, create_pdp_ctxt_rsp->gsn_addr_3.gsn_address.ipv6);

	create_pdp_ctxt_rsp->gsn_addr_4.header.type = GTPV1_IE_GSN_ADDR;
	create_pdp_ctxt_rsp->gsn_addr_4.header.length = 16;
	char *str3 = "2001:db80:3333:4444:5555:6666:7777:8885";
	inet_pton(AF_INET6, str3, create_pdp_ctxt_rsp->gsn_addr_4.gsn_address.ipv6);

	create_pdp_ctxt_rsp->qos_profile.header.type = GTPV1_IE_QOS;
	create_pdp_ctxt_rsp->qos_profile.header.length = 21;
	create_pdp_ctxt_rsp->qos_profile.qos.allocation_retention_priority = 2;
	create_pdp_ctxt_rsp->qos_profile.qos.spare1 = 0;
	create_pdp_ctxt_rsp->qos_profile.qos.delay_class = 2;
	create_pdp_ctxt_rsp->qos_profile.qos.reliablity_class = 2;
	create_pdp_ctxt_rsp->qos_profile.qos.peak_throughput = 3;
	create_pdp_ctxt_rsp->qos_profile.qos.spare2 = 0;
	create_pdp_ctxt_rsp->qos_profile.qos.precedence_class = 1;
	create_pdp_ctxt_rsp->qos_profile.qos.spare3 = 0;
	create_pdp_ctxt_rsp->qos_profile.qos.mean_throughput = 4;
	create_pdp_ctxt_rsp->qos_profile.qos.traffic_class = 1;
	create_pdp_ctxt_rsp->qos_profile.qos.delivery_order = 1;
	create_pdp_ctxt_rsp->qos_profile.qos.delivery_erroneous_sdu = 2;
	create_pdp_ctxt_rsp->qos_profile.qos.max_sdu_size = 3;
	create_pdp_ctxt_rsp->qos_profile.qos.max_bitrate_uplink = 123;
	create_pdp_ctxt_rsp->qos_profile.qos.max_bitrate_downlink = 234;
	create_pdp_ctxt_rsp->qos_profile.qos.residual_ber = 1;
	create_pdp_ctxt_rsp->qos_profile.qos.sdu_error_ratio = 1; 
	create_pdp_ctxt_rsp->qos_profile.qos.transfer_delay = 1; 
	create_pdp_ctxt_rsp->qos_profile.qos.traffic_handling_priority = 2;
	create_pdp_ctxt_rsp->qos_profile.qos.guaranteed_bitrate_uplink = 122;
	create_pdp_ctxt_rsp->qos_profile.qos.guaranteed_bitrate_downlink = 222;
	create_pdp_ctxt_rsp->qos_profile.qos.spare4 = 0; 
	create_pdp_ctxt_rsp->qos_profile.qos.signalling_indication = 1;
	create_pdp_ctxt_rsp->qos_profile.qos.source_statistics_descriptor = 1;
	create_pdp_ctxt_rsp->qos_profile.qos.max_bitrate_downlink_ext1 = 22;
	create_pdp_ctxt_rsp->qos_profile.qos.guaranteed_bitrate_downlink_ext1 = 11;
	create_pdp_ctxt_rsp->qos_profile.qos.max_bitrate_uplink_ext1 = 33;
	create_pdp_ctxt_rsp->qos_profile.qos.guaranteed_bitrate_uplink_ext1 = 22;
	create_pdp_ctxt_rsp->qos_profile.qos.max_bitrate_downlink_ext2 = 44;
	create_pdp_ctxt_rsp->qos_profile.qos.guaranteed_bitrate_downlink_ext2 = 33;
	create_pdp_ctxt_rsp->qos_profile.qos.max_bitrate_uplink_ext2 = 34;
	create_pdp_ctxt_rsp->qos_profile.qos.guaranteed_bitrate_uplink_ext2 = 23;

	create_pdp_ctxt_rsp->charging_gateway_addr.header.type = GTPV1_IE_CHARGING_GATEWAY_ADDR;
	create_pdp_ctxt_rsp->charging_gateway_addr.header.length = 4;
	create_pdp_ctxt_rsp->charging_gateway_addr.ipv4_addr = 3232235564;

	create_pdp_ctxt_rsp->alt_charging_gateway_addr.header.type = GTPV1_IE_CHARGING_GATEWAY_ADDR;
	create_pdp_ctxt_rsp->alt_charging_gateway_addr.header.length = 16;
	char *str4 = "2001:db80:3133:4444:5555:6666:7777:8885";
	inet_pton(AF_INET6, str4, create_pdp_ctxt_rsp->alt_charging_gateway_addr.ipv6_addr);

	create_pdp_ctxt_rsp->common_flag.header.type = GTPV1_IE_COMMON_FLAG;
	create_pdp_ctxt_rsp->common_flag.header.length = 1;
	create_pdp_ctxt_rsp->common_flag.dual_addr_bearer_flag = 1;
	create_pdp_ctxt_rsp->common_flag.upgrade_qos_supported = 1;
	create_pdp_ctxt_rsp->common_flag.nrsn = 1;
	create_pdp_ctxt_rsp->common_flag.no_qos_negotiation = 1;
	create_pdp_ctxt_rsp->common_flag.mbms_counting_information = 1;
	create_pdp_ctxt_rsp->common_flag.ran_procedures_ready = 1;
	create_pdp_ctxt_rsp->common_flag.mbms_service_type = 1;
	create_pdp_ctxt_rsp->common_flag.prohibit_payload_compression = 1;

	create_pdp_ctxt_rsp->apn_restriction.header.type = GTPV1_IE_APN_RESTRICTION;
	create_pdp_ctxt_rsp->apn_restriction.header.length = 1;
	create_pdp_ctxt_rsp->apn_restriction.restriction_type_value = 12;

	create_pdp_ctxt_rsp->ms_info_change_reporting_action.header.type = GTPV1_IE_MS_INFO_CHANGE_REPORTING_ACTION;
	create_pdp_ctxt_rsp->ms_info_change_reporting_action.header.length = 1;
	create_pdp_ctxt_rsp->ms_info_change_reporting_action.action = 4;

	create_pdp_ctxt_rsp->bearer_control.header.type = GTPV1_IE_BEARER_CONTROL_MODE;
	create_pdp_ctxt_rsp->bearer_control.header.length = 1;
	create_pdp_ctxt_rsp->bearer_control.bearer_control_mode = 3;

	create_pdp_ctxt_rsp->evolved_allocation_retention_priority_1.header.type = GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_I;
	create_pdp_ctxt_rsp->evolved_allocation_retention_priority_1.header.length = 1;
	create_pdp_ctxt_rsp->evolved_allocation_retention_priority_1.spare = 0;
	create_pdp_ctxt_rsp->evolved_allocation_retention_priority_1.pci = 1;
	create_pdp_ctxt_rsp->evolved_allocation_retention_priority_1.pl = 12;
	create_pdp_ctxt_rsp->evolved_allocation_retention_priority_1.spare2 = 0; 
	create_pdp_ctxt_rsp->evolved_allocation_retention_priority_1.pvi = 1;

	create_pdp_ctxt_rsp->extended_common_flag.header.type = GTPV1_IE_EXTENDED_COMMON_FLAG;
	create_pdp_ctxt_rsp->extended_common_flag.header.length = 1;
	create_pdp_ctxt_rsp->extended_common_flag.uasi = 1;
	create_pdp_ctxt_rsp->extended_common_flag.bdwi = 0;
	create_pdp_ctxt_rsp->extended_common_flag.pcri = 1;
	create_pdp_ctxt_rsp->extended_common_flag.vb = 0;
	create_pdp_ctxt_rsp->extended_common_flag.retloc = 1;
	create_pdp_ctxt_rsp->extended_common_flag.cpsr = 0;
	create_pdp_ctxt_rsp->extended_common_flag.ccrsi = 1;
	create_pdp_ctxt_rsp->extended_common_flag.unauthenticated_imsi = 0;

	create_pdp_ctxt_rsp->csg_information_reporting_action.header.type = GTPV1_IE_CSG_INFORMATION_REPORTING_ACTION;
	create_pdp_ctxt_rsp->csg_information_reporting_action.header.length = 1;
	create_pdp_ctxt_rsp->csg_information_reporting_action.spare = 0;
	create_pdp_ctxt_rsp->csg_information_reporting_action.ucuhc = 1;
	create_pdp_ctxt_rsp->csg_information_reporting_action.ucshc = 1;
	create_pdp_ctxt_rsp->csg_information_reporting_action.uccsg = 1;

	create_pdp_ctxt_rsp->apn_ambr.header.type = GTPV1_IE_APN_AMBR;
	create_pdp_ctxt_rsp->apn_ambr.header.length = 8;
	create_pdp_ctxt_rsp->apn_ambr.apn_ambr_uplink = 10;
	create_pdp_ctxt_rsp->apn_ambr.apn_ambr_downlink = 7;

	create_pdp_ctxt_rsp->ggsn_back_off_time.header.type = GTPV1_IE_GGSN_BACK_OFF_TIME;
	create_pdp_ctxt_rsp->ggsn_back_off_time.header.length = 1;
	create_pdp_ctxt_rsp->ggsn_back_off_time.timer_unit = 0;
	create_pdp_ctxt_rsp->ggsn_back_off_time.timer_value = 8;

	create_pdp_ctxt_rsp->extended_common_flag_2.header.type = GTPV1_IE_EXTENDED_COMMON_FLAGS_II;
	create_pdp_ctxt_rsp->extended_common_flag_2.header.length = 1;
	create_pdp_ctxt_rsp->extended_common_flag_2.spare = 0;
	create_pdp_ctxt_rsp->extended_common_flag_2.pmts_mi = 1;
	create_pdp_ctxt_rsp->extended_common_flag_2.dtci = 1;
	create_pdp_ctxt_rsp->extended_common_flag_2.pnsi = 1;

	create_pdp_ctxt_rsp->private_extension.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	create_pdp_ctxt_rsp->private_extension.header.length = 6;
	create_pdp_ctxt_rsp->private_extension.extension_identifier = 12;
	strncpy((char*)&create_pdp_ctxt_rsp->private_extension.extension_value, "2021", 4);

	return;
}

void fill_gtpv1_update_pdp_ctxt_req_sgsn(gtpv1_update_pdp_ctxt_req_sgsn_t *update_pdp_ctxt_req_sgsn) {

	update_pdp_ctxt_req_sgsn->header.version = 1;
	update_pdp_ctxt_req_sgsn->header.protocol_type = 1;
	update_pdp_ctxt_req_sgsn->header.spare = 0;
	update_pdp_ctxt_req_sgsn->header.extension_header = 0;
	update_pdp_ctxt_req_sgsn->header.seq_num_flag = 0;
	update_pdp_ctxt_req_sgsn->header.n_pdu_flag = 0;
	update_pdp_ctxt_req_sgsn->header.message_type = GTPV1_UPDATE_PDP_CTXT_REQ; 
	update_pdp_ctxt_req_sgsn->header.message_len = 278;
	update_pdp_ctxt_req_sgsn->header.teid = 0x372f0000; 
	update_pdp_ctxt_req_sgsn->header.seq = 0x00fe;
	update_pdp_ctxt_req_sgsn->header.n_pdu_number = 4;
	update_pdp_ctxt_req_sgsn->header.next_extension_header_type = 0;

	update_pdp_ctxt_req_sgsn->imsi.header.type = GTPV1_IE_IMSI;
	update_pdp_ctxt_req_sgsn->imsi.imsi_number_digits = 272031000000000;

	update_pdp_ctxt_req_sgsn->routing_area_identity.header.type = GTPV1_IE_ROUTEING_AREA_IDENTITY;
	update_pdp_ctxt_req_sgsn->routing_area_identity.rai_value.mcc_digit_2 = 0x0;
	update_pdp_ctxt_req_sgsn->routing_area_identity.rai_value.mcc_digit_1 = 0x4;
	update_pdp_ctxt_req_sgsn->routing_area_identity.rai_value.mnc_digit_3 = 0x8;
	update_pdp_ctxt_req_sgsn->routing_area_identity.rai_value.mcc_digit_3 = 0x4;
	update_pdp_ctxt_req_sgsn->routing_area_identity.rai_value.mnc_digit_2 = 0x7;
	update_pdp_ctxt_req_sgsn->routing_area_identity.rai_value.mnc_digit_1 = 0x0;
	update_pdp_ctxt_req_sgsn->routing_area_identity.rai_value.lac = 0x14;
	update_pdp_ctxt_req_sgsn->routing_area_identity.rai_value.rac = 0x14;

	update_pdp_ctxt_req_sgsn->recovery.header.type = GTPV1_IE_RECOVERY;
	update_pdp_ctxt_req_sgsn->recovery.restart_counter = 2;

	update_pdp_ctxt_req_sgsn->tunn_endpt_idnt_data_1.header.type = GTPV1_IE_TEID_DATA_1;
	update_pdp_ctxt_req_sgsn->tunn_endpt_idnt_data_1.teid = 0x0fffeee;

	update_pdp_ctxt_req_sgsn->tunn_endpt_idnt_control_plane.header.type = GTPV1_IE_TEID_CONTROL_PLANE;
	update_pdp_ctxt_req_sgsn->tunn_endpt_idnt_control_plane.teid = 0x00ab;

	update_pdp_ctxt_req_sgsn->nsapi.header.type = GTPV1_IE_NSAPI;
	update_pdp_ctxt_req_sgsn->nsapi.spare = 0;
	update_pdp_ctxt_req_sgsn->nsapi.nsapi_value = 5;

	update_pdp_ctxt_req_sgsn->trace_reference.header.type = GTPV1_IE_TRACE_REFERENCE;
	update_pdp_ctxt_req_sgsn->trace_reference.trace_reference = 9;

	update_pdp_ctxt_req_sgsn->trace_type.header.type = GTPV1_IE_TRACE_TYPE;
	update_pdp_ctxt_req_sgsn->trace_type.trace_type = 9;

	update_pdp_ctxt_req_sgsn->protocol_config_options.header.type = GTPV1_IE_PROTOCOL_CONFIG_OPTIONS;
	update_pdp_ctxt_req_sgsn->protocol_config_options.header.length = 25;
	update_pdp_ctxt_req_sgsn->protocol_config_options.pco.pco_flag_ext  = 1;
	update_pdp_ctxt_req_sgsn->protocol_config_options.pco.pco_flag_spare  = 0;
	update_pdp_ctxt_req_sgsn->protocol_config_options.pco.pco_cfg_proto  = 1;
	update_pdp_ctxt_req_sgsn->protocol_config_options.pco.pco_content_count  = 2;
	update_pdp_ctxt_req_sgsn->protocol_config_options.pco.pco_content[0].prot_or_cont_id  = 2;
	update_pdp_ctxt_req_sgsn->protocol_config_options.pco.pco_content[0].length  = 9;
	strncpy((char *)&update_pdp_ctxt_req_sgsn->protocol_config_options.pco.pco_content[0].content,"355240599",9);
	update_pdp_ctxt_req_sgsn->protocol_config_options.pco.pco_content[1].prot_or_cont_id  = 2;
	update_pdp_ctxt_req_sgsn->protocol_config_options.pco.pco_content[1].length  = 9;
	strncpy((char *)&update_pdp_ctxt_req_sgsn->protocol_config_options.pco.pco_content[1].content,"355240589",9);

	update_pdp_ctxt_req_sgsn->gsn_addr_1.header.type = GTPV1_IE_GSN_ADDR;
	update_pdp_ctxt_req_sgsn->gsn_addr_1.header.length = 4;
	update_pdp_ctxt_req_sgsn->gsn_addr_1.gsn_address.ipv4 = 3232235564; 

	update_pdp_ctxt_req_sgsn->gsn_addr_2.header.type = GTPV1_IE_GSN_ADDR;
	update_pdp_ctxt_req_sgsn->gsn_addr_2.header.length = 4;
	update_pdp_ctxt_req_sgsn->gsn_addr_2.gsn_address.ipv4 = 3232235564;

	update_pdp_ctxt_req_sgsn->gsn_addr_3.header.type = GTPV1_IE_GSN_ADDR;
	update_pdp_ctxt_req_sgsn->gsn_addr_3.header.length = 16;
	char *str21 = "2001:db80:3333:4444:5555:6666:7777:8888";
	inet_pton(AF_INET6, str21, update_pdp_ctxt_req_sgsn->gsn_addr_3.gsn_address.ipv6);

	update_pdp_ctxt_req_sgsn->gsn_addr_4.header.type = GTPV1_IE_GSN_ADDR;
	update_pdp_ctxt_req_sgsn->gsn_addr_4.header.length = 16;
	char *str31 = "2001:db80:3333:4444:5555:6666:7777:8885";
	inet_pton(AF_INET6, str31, update_pdp_ctxt_req_sgsn->gsn_addr_4.gsn_address.ipv6);

	update_pdp_ctxt_req_sgsn->qos_profile.header.type = GTPV1_IE_QOS;
	update_pdp_ctxt_req_sgsn->qos_profile.header.length = 21;
	update_pdp_ctxt_req_sgsn->qos_profile.qos.allocation_retention_priority = 2;
	update_pdp_ctxt_req_sgsn->qos_profile.qos.spare1 = 0;
	update_pdp_ctxt_req_sgsn->qos_profile.qos.delay_class = 2;
	update_pdp_ctxt_req_sgsn->qos_profile.qos.reliablity_class = 2;
	update_pdp_ctxt_req_sgsn->qos_profile.qos.peak_throughput = 3;
	update_pdp_ctxt_req_sgsn->qos_profile.qos.spare2 = 0;
	update_pdp_ctxt_req_sgsn->qos_profile.qos.precedence_class = 1;
	update_pdp_ctxt_req_sgsn->qos_profile.qos.spare3 = 0;
	update_pdp_ctxt_req_sgsn->qos_profile.qos.mean_throughput = 4;
	update_pdp_ctxt_req_sgsn->qos_profile.qos.traffic_class = 1;
	update_pdp_ctxt_req_sgsn->qos_profile.qos.delivery_order = 1;
	update_pdp_ctxt_req_sgsn->qos_profile.qos.delivery_erroneous_sdu = 2;
	update_pdp_ctxt_req_sgsn->qos_profile.qos.max_sdu_size = 3;
	update_pdp_ctxt_req_sgsn->qos_profile.qos.max_bitrate_uplink = 123;
	update_pdp_ctxt_req_sgsn->qos_profile.qos.max_bitrate_downlink = 234;
	update_pdp_ctxt_req_sgsn->qos_profile.qos.residual_ber = 1;
	update_pdp_ctxt_req_sgsn->qos_profile.qos.sdu_error_ratio = 1; 
	update_pdp_ctxt_req_sgsn->qos_profile.qos.transfer_delay = 1; 
	update_pdp_ctxt_req_sgsn->qos_profile.qos.traffic_handling_priority = 2;
	update_pdp_ctxt_req_sgsn->qos_profile.qos.guaranteed_bitrate_uplink = 122;
	update_pdp_ctxt_req_sgsn->qos_profile.qos.guaranteed_bitrate_downlink = 222;
	update_pdp_ctxt_req_sgsn->qos_profile.qos.spare4 = 0; 
	update_pdp_ctxt_req_sgsn->qos_profile.qos.signalling_indication = 1;
	update_pdp_ctxt_req_sgsn->qos_profile.qos.source_statistics_descriptor = 1;
	update_pdp_ctxt_req_sgsn->qos_profile.qos.max_bitrate_downlink_ext1 = 22;
	update_pdp_ctxt_req_sgsn->qos_profile.qos.guaranteed_bitrate_downlink_ext1 = 11;
	update_pdp_ctxt_req_sgsn->qos_profile.qos.max_bitrate_uplink_ext1 = 33;
	update_pdp_ctxt_req_sgsn->qos_profile.qos.guaranteed_bitrate_uplink_ext1 = 22;
	update_pdp_ctxt_req_sgsn->qos_profile.qos.max_bitrate_downlink_ext2 = 44;
	update_pdp_ctxt_req_sgsn->qos_profile.qos.guaranteed_bitrate_downlink_ext2 = 33;
	update_pdp_ctxt_req_sgsn->qos_profile.qos.max_bitrate_uplink_ext2 = 34;
	update_pdp_ctxt_req_sgsn->qos_profile.qos.guaranteed_bitrate_uplink_ext2 = 23;

	update_pdp_ctxt_req_sgsn->tft.header.type = GTPV1_IE_TFT;
	update_pdp_ctxt_req_sgsn->tft.header.length = 19;
	update_pdp_ctxt_req_sgsn->tft.tft_op_code = 1;
	update_pdp_ctxt_req_sgsn->tft.e_bit = 1;
	update_pdp_ctxt_req_sgsn->tft.no_packet_filters = 2;
	update_pdp_ctxt_req_sgsn->tft.packet_filter_list_del[0].spare = 0;
	update_pdp_ctxt_req_sgsn->tft.packet_filter_list_del[0].filter_id = 1;
	update_pdp_ctxt_req_sgsn->tft.packet_filter_list_del[1].spare = 0;
	update_pdp_ctxt_req_sgsn->tft.packet_filter_list_del[1].filter_id = 2;
	update_pdp_ctxt_req_sgsn->tft.packet_filter_list_new[0].spare = 0;
	update_pdp_ctxt_req_sgsn->tft.packet_filter_list_new[0].filter_direction = 1;
	update_pdp_ctxt_req_sgsn->tft.packet_filter_list_new[0].filter_id = 5;
	update_pdp_ctxt_req_sgsn->tft.packet_filter_list_new[0].filter_eval_precedence = 1;
	update_pdp_ctxt_req_sgsn->tft.packet_filter_list_new[0].filter_content_length = 1;
	update_pdp_ctxt_req_sgsn->tft.packet_filter_list_new[0].filter_content[0] = 1;
	update_pdp_ctxt_req_sgsn->tft.packet_filter_list_new[1].spare = 0;
	update_pdp_ctxt_req_sgsn->tft.packet_filter_list_new[1].filter_direction = 2;
	update_pdp_ctxt_req_sgsn->tft.packet_filter_list_new[1].filter_id = 5;
	update_pdp_ctxt_req_sgsn->tft.packet_filter_list_new[1].filter_eval_precedence = 1;
	update_pdp_ctxt_req_sgsn->tft.packet_filter_list_new[1].filter_content_length = 2;
	update_pdp_ctxt_req_sgsn->tft.packet_filter_list_new[1].filter_content[0] = 1;
	update_pdp_ctxt_req_sgsn->tft.packet_filter_list_new[1].filter_content[1] = 0;
	update_pdp_ctxt_req_sgsn->tft.parameters_list[0].parameter_id = 1;
	update_pdp_ctxt_req_sgsn->tft.parameters_list[0].parameter_content_length = 2;
	update_pdp_ctxt_req_sgsn->tft.parameters_list[0].parameter_content[0] = 1;
	update_pdp_ctxt_req_sgsn->tft.parameters_list[0].parameter_content[1] = 2;
	update_pdp_ctxt_req_sgsn->tft.parameters_list[1].parameter_id = 1;
	update_pdp_ctxt_req_sgsn->tft.parameters_list[1].parameter_content_length = 3;
	update_pdp_ctxt_req_sgsn->tft.parameters_list[1].parameter_content[0] = 3;
	update_pdp_ctxt_req_sgsn->tft.parameters_list[1].parameter_content[1] = 2;
	update_pdp_ctxt_req_sgsn->tft.parameters_list[1].parameter_content[2] = 0;

	update_pdp_ctxt_req_sgsn->trigger_id.header.type = GTPV1_IE_TRIGGER_ID;    
	update_pdp_ctxt_req_sgsn->trigger_id.header.length = 5;    
	memset(&update_pdp_ctxt_req_sgsn->trigger_id.trigger_id,'2',5);

	update_pdp_ctxt_req_sgsn->omc_identity.header.type = GTPV1_IE_OMC_IDENTITY;    
	update_pdp_ctxt_req_sgsn->omc_identity.header.length = 7;    
	strncpy((char *)&update_pdp_ctxt_req_sgsn->omc_identity.omc_identity,"abc.com",7);

	update_pdp_ctxt_req_sgsn->common_flag.header.type = GTPV1_IE_COMMON_FLAG;
	update_pdp_ctxt_req_sgsn->common_flag.header.length = 1;
	update_pdp_ctxt_req_sgsn->common_flag.dual_addr_bearer_flag = 1;
	update_pdp_ctxt_req_sgsn->common_flag.upgrade_qos_supported = 1;
	update_pdp_ctxt_req_sgsn->common_flag.nrsn = 1;
	update_pdp_ctxt_req_sgsn->common_flag.no_qos_negotiation = 1;
	update_pdp_ctxt_req_sgsn->common_flag.mbms_counting_information = 1;
	update_pdp_ctxt_req_sgsn->common_flag.ran_procedures_ready = 1;
	update_pdp_ctxt_req_sgsn->common_flag.mbms_service_type = 1;
	update_pdp_ctxt_req_sgsn->common_flag.prohibit_payload_compression = 1;

	update_pdp_ctxt_req_sgsn->rat_type.header.type = GTPV1_IE_RAT_TYPE;
	update_pdp_ctxt_req_sgsn->rat_type.header.length = 1;
	update_pdp_ctxt_req_sgsn->rat_type.rat_type = 2;

	update_pdp_ctxt_req_sgsn->user_location_information.header.type = GTPV1_IE_USER_LOCATION_INFORMATION;
	update_pdp_ctxt_req_sgsn->user_location_information.header.length = 8;
	update_pdp_ctxt_req_sgsn->user_location_information.geographic_location_type = 1;
	update_pdp_ctxt_req_sgsn->user_location_information.mcc_digit_2 = 0x0;
	update_pdp_ctxt_req_sgsn->user_location_information.mcc_digit_1 = 0x4;
	update_pdp_ctxt_req_sgsn->user_location_information.mnc_digit_3 = 0x8;
	update_pdp_ctxt_req_sgsn->user_location_information.mcc_digit_3 = 0x4;
	update_pdp_ctxt_req_sgsn->user_location_information.mnc_digit_2 = 0x7;
	update_pdp_ctxt_req_sgsn->user_location_information.mnc_digit_1 = 0x0;
	update_pdp_ctxt_req_sgsn->user_location_information.lac = 0x1;
	update_pdp_ctxt_req_sgsn->user_location_information.ci_sac_rac = 0x1;

	update_pdp_ctxt_req_sgsn->ms_time_zone.header.type = GTPV1_IE_MS_TIME_ZONE;    
	update_pdp_ctxt_req_sgsn->ms_time_zone.header.length = 2;
	update_pdp_ctxt_req_sgsn->ms_time_zone.time_zone = 1;    
	update_pdp_ctxt_req_sgsn->ms_time_zone.spare = 0;    
	update_pdp_ctxt_req_sgsn->ms_time_zone.daylight_saving_time = 1;

	update_pdp_ctxt_req_sgsn->additional_trace_information.header.type = GTPV1_IE_ADDITIONAL_TRACE_INFORMATION;
	update_pdp_ctxt_req_sgsn->additional_trace_information.header.length = 9;
	update_pdp_ctxt_req_sgsn->additional_trace_information.trace_reference_2 = 1;
	update_pdp_ctxt_req_sgsn->additional_trace_information.trace_recording_session_reference = 1;
	update_pdp_ctxt_req_sgsn->additional_trace_information.spare1 = 0;
	update_pdp_ctxt_req_sgsn->additional_trace_information.triggering_events_in_ggsn_mbms_ctxt = 0;
	update_pdp_ctxt_req_sgsn->additional_trace_information.triggering_events_in_ggsn_pdp_ctxt = 1;
	update_pdp_ctxt_req_sgsn->additional_trace_information.trace_depth = 1;
	update_pdp_ctxt_req_sgsn->additional_trace_information.spare2 = 0;
	update_pdp_ctxt_req_sgsn->additional_trace_information.list_of_interfaces_in_ggsn_gmb = 0;
	update_pdp_ctxt_req_sgsn->additional_trace_information.list_of_interfaces_in_ggsn_gi = 0;
	update_pdp_ctxt_req_sgsn->additional_trace_information.list_of_interfaces_in_ggsn_gn = 1;
	update_pdp_ctxt_req_sgsn->additional_trace_information.trace_activity_control = 1;

	update_pdp_ctxt_req_sgsn->direct_tunnel_flag.header.type = GTPV1_IE_DIRECT_TUNNEL_FLAG;
	update_pdp_ctxt_req_sgsn->direct_tunnel_flag.header.length = 1;
	update_pdp_ctxt_req_sgsn->direct_tunnel_flag.spare = 0;
	update_pdp_ctxt_req_sgsn->direct_tunnel_flag.ei = 1;
	update_pdp_ctxt_req_sgsn->direct_tunnel_flag.gcsi = 1;
	update_pdp_ctxt_req_sgsn->direct_tunnel_flag.dti = 1;

	update_pdp_ctxt_req_sgsn->evolved_allocation_retention_priority_1.header.type = GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_I;
	update_pdp_ctxt_req_sgsn->evolved_allocation_retention_priority_1.header.length = 1;
	update_pdp_ctxt_req_sgsn->evolved_allocation_retention_priority_1.spare =0;
	update_pdp_ctxt_req_sgsn->evolved_allocation_retention_priority_1.pci =1;
	update_pdp_ctxt_req_sgsn->evolved_allocation_retention_priority_1.pl = 12;
	update_pdp_ctxt_req_sgsn->evolved_allocation_retention_priority_1.spare2 =0;
	update_pdp_ctxt_req_sgsn->evolved_allocation_retention_priority_1.pvi = 1;

	update_pdp_ctxt_req_sgsn->extended_common_flag.header.type = GTPV1_IE_EXTENDED_COMMON_FLAG;
	update_pdp_ctxt_req_sgsn->extended_common_flag.header.length = 1;
	update_pdp_ctxt_req_sgsn->extended_common_flag.uasi = 0;
	update_pdp_ctxt_req_sgsn->extended_common_flag.bdwi = 0;
	update_pdp_ctxt_req_sgsn->extended_common_flag.pcri = 0;
	update_pdp_ctxt_req_sgsn->extended_common_flag.vb = 0;
	update_pdp_ctxt_req_sgsn->extended_common_flag.retloc = 0;
	update_pdp_ctxt_req_sgsn->extended_common_flag.cpsr = 0;

	update_pdp_ctxt_req_sgsn->user_csg_information.header.type = GTPV1_IE_USER_CSG_INFORMATION;
	update_pdp_ctxt_req_sgsn->user_csg_information.header.length = 8;
	update_pdp_ctxt_req_sgsn->user_csg_information.mcc_digit_2 = 0x0;
	update_pdp_ctxt_req_sgsn->user_csg_information.mcc_digit_1 = 0x4;
	update_pdp_ctxt_req_sgsn->user_csg_information.mnc_digit_3 = 0x8;
	update_pdp_ctxt_req_sgsn->user_csg_information.mcc_digit_3 = 0x4;
	update_pdp_ctxt_req_sgsn->user_csg_information.mnc_digit_2 = 0x7;
	update_pdp_ctxt_req_sgsn->user_csg_information.mnc_digit_1 = 0x0;
	update_pdp_ctxt_req_sgsn->user_csg_information.spare = 0;
	update_pdp_ctxt_req_sgsn->user_csg_information.csg_id = 1;
	update_pdp_ctxt_req_sgsn->user_csg_information.csg_id_II = 1;
	update_pdp_ctxt_req_sgsn->user_csg_information.access_mode = 1;
	update_pdp_ctxt_req_sgsn->user_csg_information.spare2 = 0;
	update_pdp_ctxt_req_sgsn->user_csg_information.cmi = 1;

	update_pdp_ctxt_req_sgsn->apn_ambr.header.type = GTPV1_IE_APN_AMBR;
	update_pdp_ctxt_req_sgsn->apn_ambr.header.length = 8;
	update_pdp_ctxt_req_sgsn->apn_ambr.apn_ambr_uplink = 0;
	update_pdp_ctxt_req_sgsn->apn_ambr.apn_ambr_downlink = 7;

	update_pdp_ctxt_req_sgsn->signalling_priority_indication.header.type = GTPV1_IE_SIGNALLING_PRIORITY_INDICATION;
	update_pdp_ctxt_req_sgsn->signalling_priority_indication.header.length = 1;
	update_pdp_ctxt_req_sgsn->signalling_priority_indication.spare = 0;
	update_pdp_ctxt_req_sgsn->signalling_priority_indication.lapi = 1;
		
	update_pdp_ctxt_req_sgsn->cn_operator_selection_entity.header.type = GTPV1_IE_CN_OPERATOR_SELECTION_ENTITY;
	update_pdp_ctxt_req_sgsn->cn_operator_selection_entity.header.length = 1;
	update_pdp_ctxt_req_sgsn->cn_operator_selection_entity.spare = 0;
	update_pdp_ctxt_req_sgsn->cn_operator_selection_entity.selection_entity = 1;	
	
	update_pdp_ctxt_req_sgsn->imei_sv.header.type = GTPV1_IE_IMEI_SV;
	update_pdp_ctxt_req_sgsn->imei_sv.header.length = 8;
	update_pdp_ctxt_req_sgsn->imei_sv.imei_sv = 0b0001000100010001000100010001000100100010001000100010001000010001;

	update_pdp_ctxt_req_sgsn->private_extension.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	update_pdp_ctxt_req_sgsn->private_extension.header.length = 6;
	update_pdp_ctxt_req_sgsn->private_extension.extension_identifier = 12;
	strncpy((char *)&update_pdp_ctxt_req_sgsn->private_extension.extension_value, "2021", 4);

	return;
}

void fill_gtpv1_update_pdp_ctxt_req_ggsn(gtpv1_update_pdp_ctxt_req_ggsn_t *update_pdp_ctxt_req_ggsn) {

	update_pdp_ctxt_req_ggsn->header.version = 1;
	update_pdp_ctxt_req_ggsn->header.protocol_type = 1;
	update_pdp_ctxt_req_ggsn->header.spare = 0;
	update_pdp_ctxt_req_ggsn->header.extension_header = 0;
	update_pdp_ctxt_req_ggsn->header.seq_num_flag = 0;
	update_pdp_ctxt_req_ggsn->header.n_pdu_flag = 0;
	update_pdp_ctxt_req_ggsn->header.message_type = GTPV1_UPDATE_PDP_CTXT_REQ; 
	update_pdp_ctxt_req_ggsn->header.message_len = 148;
	update_pdp_ctxt_req_ggsn->header.teid = 0x372f0000; 
	update_pdp_ctxt_req_ggsn->header.seq = 0x00fe;
	update_pdp_ctxt_req_ggsn->header.n_pdu_number = 4;
	update_pdp_ctxt_req_ggsn->header.next_extension_header_type = 0;

	update_pdp_ctxt_req_ggsn->imsi.header.type = GTPV1_IE_IMSI;
	update_pdp_ctxt_req_ggsn->imsi.imsi_number_digits = 272031000000000;

	update_pdp_ctxt_req_ggsn->recovery.header.type = GTPV1_IE_RECOVERY;
	update_pdp_ctxt_req_ggsn->recovery.restart_counter = 2;

	update_pdp_ctxt_req_ggsn->nsapi.header.type = GTPV1_IE_NSAPI;
	update_pdp_ctxt_req_ggsn->nsapi.spare = 0;
	update_pdp_ctxt_req_ggsn->nsapi.nsapi_value = 5;

	update_pdp_ctxt_req_ggsn->end_user_address.header.type = GTPV1_IE_END_USER_ADDR;
	update_pdp_ctxt_req_ggsn->end_user_address.header.length = 6;
	update_pdp_ctxt_req_ggsn->end_user_address.spare = 0xf;
	update_pdp_ctxt_req_ggsn->end_user_address.pdp_type_org =1;
	update_pdp_ctxt_req_ggsn->end_user_address.pdp_type_number = 0x21;
	update_pdp_ctxt_req_ggsn->end_user_address.pdp_address.ipv4 = 355240599;

	update_pdp_ctxt_req_ggsn->protocol_config_options.header.type = GTPV1_IE_PROTOCOL_CONFIG_OPTIONS;
	update_pdp_ctxt_req_ggsn->protocol_config_options.header.length = 25;
	update_pdp_ctxt_req_ggsn->protocol_config_options.pco.pco_flag_ext  = 1;
	update_pdp_ctxt_req_ggsn->protocol_config_options.pco.pco_flag_spare  = 0;
	update_pdp_ctxt_req_ggsn->protocol_config_options.pco.pco_cfg_proto  = 1;
	update_pdp_ctxt_req_ggsn->protocol_config_options.pco.pco_content_count  = 2;
	update_pdp_ctxt_req_ggsn->protocol_config_options.pco.pco_content[0].prot_or_cont_id  = 2;
	update_pdp_ctxt_req_ggsn->protocol_config_options.pco.pco_content[0].length  = 9;
	strncpy((char *)&update_pdp_ctxt_req_ggsn->protocol_config_options.pco.pco_content[0].content,"355240599",9);
	update_pdp_ctxt_req_ggsn->protocol_config_options.pco.pco_content[1].prot_or_cont_id  = 2;
	update_pdp_ctxt_req_ggsn->protocol_config_options.pco.pco_content[1].length  = 9;
	strncpy((char *)&update_pdp_ctxt_req_ggsn->protocol_config_options.pco.pco_content[1].content,"355240589",9);

	update_pdp_ctxt_req_ggsn->qos_profile.header.type = GTPV1_IE_QOS;
	update_pdp_ctxt_req_ggsn->qos_profile.header.length = 21;
	update_pdp_ctxt_req_ggsn->qos_profile.qos.allocation_retention_priority = 2;
	update_pdp_ctxt_req_ggsn->qos_profile.qos.spare1 = 0;
	update_pdp_ctxt_req_ggsn->qos_profile.qos.delay_class = 2;
	update_pdp_ctxt_req_ggsn->qos_profile.qos.reliablity_class = 2;
	update_pdp_ctxt_req_ggsn->qos_profile.qos.peak_throughput = 3;
	update_pdp_ctxt_req_ggsn->qos_profile.qos.spare2 = 0;
	update_pdp_ctxt_req_ggsn->qos_profile.qos.precedence_class = 1;
	update_pdp_ctxt_req_ggsn->qos_profile.qos.spare3 = 0;
	update_pdp_ctxt_req_ggsn->qos_profile.qos.mean_throughput = 4;
	update_pdp_ctxt_req_ggsn->qos_profile.qos.traffic_class = 1;
	update_pdp_ctxt_req_ggsn->qos_profile.qos.delivery_order = 1;
	update_pdp_ctxt_req_ggsn->qos_profile.qos.delivery_erroneous_sdu = 2;
	update_pdp_ctxt_req_ggsn->qos_profile.qos.max_sdu_size = 3;
	update_pdp_ctxt_req_ggsn->qos_profile.qos.max_bitrate_uplink = 123;
	update_pdp_ctxt_req_ggsn->qos_profile.qos.max_bitrate_downlink = 234;
	update_pdp_ctxt_req_ggsn->qos_profile.qos.residual_ber = 1;
	update_pdp_ctxt_req_ggsn->qos_profile.qos.sdu_error_ratio = 1; 
	update_pdp_ctxt_req_ggsn->qos_profile.qos.transfer_delay = 1; 
	update_pdp_ctxt_req_ggsn->qos_profile.qos.traffic_handling_priority = 2;
	update_pdp_ctxt_req_ggsn->qos_profile.qos.guaranteed_bitrate_uplink = 122;
	update_pdp_ctxt_req_ggsn->qos_profile.qos.guaranteed_bitrate_downlink = 222;
	update_pdp_ctxt_req_ggsn->qos_profile.qos.spare4 = 0; 
	update_pdp_ctxt_req_ggsn->qos_profile.qos.signalling_indication = 1;
	update_pdp_ctxt_req_ggsn->qos_profile.qos.source_statistics_descriptor = 1;
	update_pdp_ctxt_req_ggsn->qos_profile.qos.max_bitrate_downlink_ext1 = 22;
	update_pdp_ctxt_req_ggsn->qos_profile.qos.guaranteed_bitrate_downlink_ext1 = 11;
	update_pdp_ctxt_req_ggsn->qos_profile.qos.max_bitrate_uplink_ext1 = 33;
	update_pdp_ctxt_req_ggsn->qos_profile.qos.guaranteed_bitrate_uplink_ext1 = 22;
	update_pdp_ctxt_req_ggsn->qos_profile.qos.max_bitrate_downlink_ext2 = 44;
	update_pdp_ctxt_req_ggsn->qos_profile.qos.guaranteed_bitrate_downlink_ext2 = 33;
	update_pdp_ctxt_req_ggsn->qos_profile.qos.max_bitrate_uplink_ext2 = 34;
	update_pdp_ctxt_req_ggsn->qos_profile.qos.guaranteed_bitrate_uplink_ext2 = 23;	

	update_pdp_ctxt_req_ggsn->tft.header.type = GTPV1_IE_TFT;
	update_pdp_ctxt_req_ggsn->tft.header.length = 19;
	update_pdp_ctxt_req_ggsn->tft.tft_op_code = 1;
	update_pdp_ctxt_req_ggsn->tft.e_bit = 1;
	update_pdp_ctxt_req_ggsn->tft.no_packet_filters = 2;
	update_pdp_ctxt_req_ggsn->tft.packet_filter_list_del[0].spare = 0;
	update_pdp_ctxt_req_ggsn->tft.packet_filter_list_del[0].filter_id = 1;
	update_pdp_ctxt_req_ggsn->tft.packet_filter_list_del[1].spare = 0;
	update_pdp_ctxt_req_ggsn->tft.packet_filter_list_del[1].filter_id = 2;
	update_pdp_ctxt_req_ggsn->tft.packet_filter_list_new[0].spare = 0;
	update_pdp_ctxt_req_ggsn->tft.packet_filter_list_new[0].filter_direction = 1;
	update_pdp_ctxt_req_ggsn->tft.packet_filter_list_new[0].filter_id = 5;
	update_pdp_ctxt_req_ggsn->tft.packet_filter_list_new[0].filter_eval_precedence = 1;
	update_pdp_ctxt_req_ggsn->tft.packet_filter_list_new[0].filter_content_length = 1;
	update_pdp_ctxt_req_ggsn->tft.packet_filter_list_new[0].filter_content[0] = 1;
	update_pdp_ctxt_req_ggsn->tft.packet_filter_list_new[1].spare = 0;
	update_pdp_ctxt_req_ggsn->tft.packet_filter_list_new[1].filter_direction = 2;
	update_pdp_ctxt_req_ggsn->tft.packet_filter_list_new[1].filter_id = 5;
	update_pdp_ctxt_req_ggsn->tft.packet_filter_list_new[1].filter_eval_precedence = 1;
	update_pdp_ctxt_req_ggsn->tft.packet_filter_list_new[1].filter_content_length = 2;
	update_pdp_ctxt_req_ggsn->tft.packet_filter_list_new[1].filter_content[0] = 1;
	update_pdp_ctxt_req_ggsn->tft.packet_filter_list_new[1].filter_content[1] = 0;
	update_pdp_ctxt_req_ggsn->tft.parameters_list[0].parameter_id = 1;
	update_pdp_ctxt_req_ggsn->tft.parameters_list[0].parameter_content_length = 2;
	update_pdp_ctxt_req_ggsn->tft.parameters_list[0].parameter_content[0] = 1;
	update_pdp_ctxt_req_ggsn->tft.parameters_list[0].parameter_content[1] = 2;
	update_pdp_ctxt_req_ggsn->tft.parameters_list[1].parameter_id = 1;
	update_pdp_ctxt_req_ggsn->tft.parameters_list[1].parameter_content_length = 3;
	update_pdp_ctxt_req_ggsn->tft.parameters_list[1].parameter_content[0] = 3;
	update_pdp_ctxt_req_ggsn->tft.parameters_list[1].parameter_content[1] = 2;
	update_pdp_ctxt_req_ggsn->tft.parameters_list[1].parameter_content[2] = 0;

	update_pdp_ctxt_req_ggsn->common_flag.header.type = GTPV1_IE_COMMON_FLAG;
	update_pdp_ctxt_req_ggsn->common_flag.header.length = 1;
	update_pdp_ctxt_req_ggsn->common_flag.dual_addr_bearer_flag = 1;
	update_pdp_ctxt_req_ggsn->common_flag.upgrade_qos_supported = 1;
	update_pdp_ctxt_req_ggsn->common_flag.nrsn = 1;
	update_pdp_ctxt_req_ggsn->common_flag.no_qos_negotiation = 1;
	update_pdp_ctxt_req_ggsn->common_flag.mbms_counting_information = 1;
	update_pdp_ctxt_req_ggsn->common_flag.ran_procedures_ready = 1;
	update_pdp_ctxt_req_ggsn->common_flag.mbms_service_type = 1;
	update_pdp_ctxt_req_ggsn->common_flag.prohibit_payload_compression = 1;

	update_pdp_ctxt_req_ggsn->apn_restriction.header.type = GTPV1_IE_APN_RESTRICTION;
	update_pdp_ctxt_req_ggsn->apn_restriction.header.length =1;
	update_pdp_ctxt_req_ggsn->apn_restriction.restriction_type_value = 12;

	update_pdp_ctxt_req_ggsn->ms_info_change_reporting_action.header.type = GTPV1_IE_MS_INFO_CHANGE_REPORTING_ACTION;
	update_pdp_ctxt_req_ggsn->ms_info_change_reporting_action.header.length = 1;
	update_pdp_ctxt_req_ggsn->ms_info_change_reporting_action.action = 4;

	update_pdp_ctxt_req_ggsn->direct_tunnel_flag.header.type = GTPV1_IE_DIRECT_TUNNEL_FLAG;
	update_pdp_ctxt_req_ggsn->direct_tunnel_flag.header.length = 1;
	update_pdp_ctxt_req_ggsn->direct_tunnel_flag.spare = 0;
	update_pdp_ctxt_req_ggsn->direct_tunnel_flag.ei = 1;
	update_pdp_ctxt_req_ggsn->direct_tunnel_flag.gcsi = 1;
	update_pdp_ctxt_req_ggsn->direct_tunnel_flag.dti = 1;

	update_pdp_ctxt_req_ggsn->bearer_control.header.type = GTPV1_IE_BEARER_CONTROL_MODE;
	update_pdp_ctxt_req_ggsn->bearer_control.header.length = 1;
	update_pdp_ctxt_req_ggsn->bearer_control.bearer_control_mode = 3;

	update_pdp_ctxt_req_ggsn->evolved_allocation_retention_priority_1.header.type = GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_I;
	update_pdp_ctxt_req_ggsn->evolved_allocation_retention_priority_1.header.length = 1;
	update_pdp_ctxt_req_ggsn->evolved_allocation_retention_priority_1.spare =0;
	update_pdp_ctxt_req_ggsn->evolved_allocation_retention_priority_1.pci =1;
	update_pdp_ctxt_req_ggsn->evolved_allocation_retention_priority_1.pl = 12;
	update_pdp_ctxt_req_ggsn->evolved_allocation_retention_priority_1.spare2 =0;
	update_pdp_ctxt_req_ggsn->evolved_allocation_retention_priority_1.pvi = 1;

	update_pdp_ctxt_req_ggsn->extended_common_flag.header.type = GTPV1_IE_EXTENDED_COMMON_FLAG;
	update_pdp_ctxt_req_ggsn->extended_common_flag.header.length = 1;
	update_pdp_ctxt_req_ggsn->extended_common_flag.uasi = 0;
	update_pdp_ctxt_req_ggsn->extended_common_flag.bdwi = 0;
	update_pdp_ctxt_req_ggsn->extended_common_flag.pcri = 0;
	update_pdp_ctxt_req_ggsn->extended_common_flag.vb = 0;
	update_pdp_ctxt_req_ggsn->extended_common_flag.retloc = 0;
	update_pdp_ctxt_req_ggsn->extended_common_flag.cpsr = 0;

	update_pdp_ctxt_req_ggsn->csg_information_reporting_action.header.type = GTPV1_IE_CSG_INFORMATION_REPORTING_ACTION;
	update_pdp_ctxt_req_ggsn->csg_information_reporting_action.header.length = 1;
	update_pdp_ctxt_req_ggsn->csg_information_reporting_action.spare = 0;
	update_pdp_ctxt_req_ggsn->csg_information_reporting_action.ucuhc = 1;
	update_pdp_ctxt_req_ggsn->csg_information_reporting_action.ucshc = 1;
	update_pdp_ctxt_req_ggsn->csg_information_reporting_action.uccsg = 1;

	update_pdp_ctxt_req_ggsn->apn_ambr.header.type = GTPV1_IE_APN_AMBR;
	update_pdp_ctxt_req_ggsn->apn_ambr.header.length = 8;
	update_pdp_ctxt_req_ggsn->apn_ambr.apn_ambr_uplink = 0;
	update_pdp_ctxt_req_ggsn->apn_ambr.apn_ambr_downlink = 7;

	update_pdp_ctxt_req_ggsn->private_extension.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	update_pdp_ctxt_req_ggsn->private_extension.header.length = 6;
	update_pdp_ctxt_req_ggsn->private_extension.extension_identifier = 12;
	strncpy((char *)&update_pdp_ctxt_req_ggsn->private_extension.extension_value, "2021", 4);

	return;
}

void fill_gtpv1_update_pdp_ctxt_rsp_ggsn(gtpv1_update_pdp_ctxt_rsp_ggsn_t *update_pdp_ctxt_rsp_ggsn){

	update_pdp_ctxt_rsp_ggsn->header.version = 1;
	update_pdp_ctxt_rsp_ggsn->header.protocol_type = 1;
	update_pdp_ctxt_rsp_ggsn->header.spare = 0;
	update_pdp_ctxt_rsp_ggsn->header.extension_header = 0;
	update_pdp_ctxt_rsp_ggsn->header.seq_num_flag = 0;
	update_pdp_ctxt_rsp_ggsn->header.n_pdu_flag = 0;

	update_pdp_ctxt_rsp_ggsn->header.message_type = GTPV1_UPDATE_PDP_CTXT_RSP;
	update_pdp_ctxt_rsp_ggsn->header.message_len = 193;
	update_pdp_ctxt_rsp_ggsn->header.teid = 0x372f0000;
	update_pdp_ctxt_rsp_ggsn->header.seq = 0x00fe;
	update_pdp_ctxt_rsp_ggsn->header.n_pdu_number = 4;
	update_pdp_ctxt_rsp_ggsn->header.next_extension_header_type = 0;

	update_pdp_ctxt_rsp_ggsn->cause.header.type = GTPV1_IE_CAUSE;
	update_pdp_ctxt_rsp_ggsn->cause.cause_value = 128;

	update_pdp_ctxt_rsp_ggsn->recovery.header.type = GTPV1_IE_RECOVERY;
	update_pdp_ctxt_rsp_ggsn->recovery.restart_counter = 2;

	update_pdp_ctxt_rsp_ggsn->tunn_endpt_idnt_data_1.header.type = GTPV1_IE_TEID_DATA_1;
	update_pdp_ctxt_rsp_ggsn->tunn_endpt_idnt_data_1.teid = 0x0fffeee;

	update_pdp_ctxt_rsp_ggsn->tunn_endpt_idnt_control_plane.header.type = GTPV1_IE_TEID_CONTROL_PLANE;
	update_pdp_ctxt_rsp_ggsn->tunn_endpt_idnt_control_plane.teid = 0x00ab;

	update_pdp_ctxt_rsp_ggsn->charging_id.header.type = GTPV1_IE_CHARGING_ID;
	update_pdp_ctxt_rsp_ggsn->charging_id.chrgng_id_val = 0x0330410b;

	update_pdp_ctxt_rsp_ggsn->protocol_config_options.header.type = GTPV1_IE_PROTOCOL_CONFIG_OPTIONS;
	update_pdp_ctxt_rsp_ggsn->protocol_config_options.header.length = 25;
	update_pdp_ctxt_rsp_ggsn->protocol_config_options.pco.pco_flag_ext  = 1;
	update_pdp_ctxt_rsp_ggsn->protocol_config_options.pco.pco_flag_spare  = 0;
	update_pdp_ctxt_rsp_ggsn->protocol_config_options.pco.pco_cfg_proto  = 1;
	update_pdp_ctxt_rsp_ggsn->protocol_config_options.pco.pco_content_count  = 2;
	update_pdp_ctxt_rsp_ggsn->protocol_config_options.pco.pco_content[0].prot_or_cont_id  = 2;
	update_pdp_ctxt_rsp_ggsn->protocol_config_options.pco.pco_content[0].length  = 9;
	strncpy((char *)&update_pdp_ctxt_rsp_ggsn->protocol_config_options.pco.pco_content[0].content,"355240599",9);
	update_pdp_ctxt_rsp_ggsn->protocol_config_options.pco.pco_content[1].prot_or_cont_id  = 2;
	update_pdp_ctxt_rsp_ggsn->protocol_config_options.pco.pco_content[1].length  = 9;
	strncpy((char *)&update_pdp_ctxt_rsp_ggsn->protocol_config_options.pco.pco_content[1].content,"355240589",9);

	update_pdp_ctxt_rsp_ggsn->gsn_addr_1.header.type = GTPV1_IE_GSN_ADDR;
	update_pdp_ctxt_rsp_ggsn->gsn_addr_1.header.length = 4;
	update_pdp_ctxt_rsp_ggsn->gsn_addr_1.gsn_address.ipv4 = 3232235564;

	update_pdp_ctxt_rsp_ggsn->gsn_addr_2.header.type = GTPV1_IE_GSN_ADDR;
	update_pdp_ctxt_rsp_ggsn->gsn_addr_2.header.length = 4;
	update_pdp_ctxt_rsp_ggsn->gsn_addr_2.gsn_address.ipv4 = 3232235563;

	update_pdp_ctxt_rsp_ggsn->gsn_addr_3.header.type = GTPV1_IE_GSN_ADDR;
	update_pdp_ctxt_rsp_ggsn->gsn_addr_3.header.length = 16;
	char *src2 = "1111:2222:3333:4444:5555:6666:7777:8888";
	inet_pton(AF_INET6, src2, update_pdp_ctxt_rsp_ggsn->gsn_addr_3.gsn_address.ipv6);

	update_pdp_ctxt_rsp_ggsn->gsn_addr_4.header.type = GTPV1_IE_GSN_ADDR;
	update_pdp_ctxt_rsp_ggsn->gsn_addr_4.header.length = 16;
	char *src3 = "2001:db80:3333:4444:5555:6666:7777:8885";
	inet_pton(AF_INET6, src3, update_pdp_ctxt_rsp_ggsn->gsn_addr_4.gsn_address.ipv6);

	update_pdp_ctxt_rsp_ggsn->qos_profile.header.type = GTPV1_IE_QOS;
	update_pdp_ctxt_rsp_ggsn->qos_profile.header.length = 21;
	update_pdp_ctxt_rsp_ggsn->qos_profile.qos.allocation_retention_priority = 2;
	update_pdp_ctxt_rsp_ggsn->qos_profile.qos.spare1 = 0;
	update_pdp_ctxt_rsp_ggsn->qos_profile.qos.delay_class = 2;
	update_pdp_ctxt_rsp_ggsn->qos_profile.qos.reliablity_class = 2;
	update_pdp_ctxt_rsp_ggsn->qos_profile.qos.peak_throughput = 3;
	update_pdp_ctxt_rsp_ggsn->qos_profile.qos.spare2 = 0;
	update_pdp_ctxt_rsp_ggsn->qos_profile.qos.precedence_class = 1;
	update_pdp_ctxt_rsp_ggsn->qos_profile.qos.spare3 = 0;
	update_pdp_ctxt_rsp_ggsn->qos_profile.qos.mean_throughput = 4;
	update_pdp_ctxt_rsp_ggsn->qos_profile.qos.traffic_class = 1;
	update_pdp_ctxt_rsp_ggsn->qos_profile.qos.delivery_order = 1;
	update_pdp_ctxt_rsp_ggsn->qos_profile.qos.delivery_erroneous_sdu = 2;
	update_pdp_ctxt_rsp_ggsn->qos_profile.qos.max_sdu_size = 3;
	update_pdp_ctxt_rsp_ggsn->qos_profile.qos.max_bitrate_uplink = 123;
	update_pdp_ctxt_rsp_ggsn->qos_profile.qos.max_bitrate_downlink = 234;
	update_pdp_ctxt_rsp_ggsn->qos_profile.qos.residual_ber = 1;
	update_pdp_ctxt_rsp_ggsn->qos_profile.qos.sdu_error_ratio = 1; 
	update_pdp_ctxt_rsp_ggsn->qos_profile.qos.transfer_delay = 1; 
	update_pdp_ctxt_rsp_ggsn->qos_profile.qos.traffic_handling_priority = 2;
	update_pdp_ctxt_rsp_ggsn->qos_profile.qos.guaranteed_bitrate_uplink = 122;
	update_pdp_ctxt_rsp_ggsn->qos_profile.qos.guaranteed_bitrate_downlink = 222;
	update_pdp_ctxt_rsp_ggsn->qos_profile.qos.spare4 = 0; 
	update_pdp_ctxt_rsp_ggsn->qos_profile.qos.signalling_indication = 1;
	update_pdp_ctxt_rsp_ggsn->qos_profile.qos.source_statistics_descriptor = 1;
	update_pdp_ctxt_rsp_ggsn->qos_profile.qos.max_bitrate_downlink_ext1 = 22;
	update_pdp_ctxt_rsp_ggsn->qos_profile.qos.guaranteed_bitrate_downlink_ext1 = 11;
	update_pdp_ctxt_rsp_ggsn->qos_profile.qos.max_bitrate_uplink_ext1 = 33;
	update_pdp_ctxt_rsp_ggsn->qos_profile.qos.guaranteed_bitrate_uplink_ext1 = 22;
	update_pdp_ctxt_rsp_ggsn->qos_profile.qos.max_bitrate_downlink_ext2 = 44;
	update_pdp_ctxt_rsp_ggsn->qos_profile.qos.guaranteed_bitrate_downlink_ext2 = 33;
	update_pdp_ctxt_rsp_ggsn->qos_profile.qos.max_bitrate_uplink_ext2 = 34;
	update_pdp_ctxt_rsp_ggsn->qos_profile.qos.guaranteed_bitrate_uplink_ext2 = 23;

	update_pdp_ctxt_rsp_ggsn->charging_gateway_addr.header.type = GTPV1_IE_CHARGING_GATEWAY_ADDR;
	update_pdp_ctxt_rsp_ggsn->charging_gateway_addr.header.length = 4;
	update_pdp_ctxt_rsp_ggsn->charging_gateway_addr.ipv4_addr = 3232235564;

	update_pdp_ctxt_rsp_ggsn->alt_charging_gateway_addr.header.type = GTPV1_IE_CHARGING_GATEWAY_ADDR;
	update_pdp_ctxt_rsp_ggsn->alt_charging_gateway_addr.header.length = 16;
	char *src4 = "2001:db80:3133:4444:5555:6666:7777:8885";
	inet_pton(AF_INET6, src4, update_pdp_ctxt_rsp_ggsn->alt_charging_gateway_addr.ipv6_addr);

	update_pdp_ctxt_rsp_ggsn->common_flag.header.type = GTPV1_IE_COMMON_FLAG;
	update_pdp_ctxt_rsp_ggsn->common_flag.header.length =1;
	update_pdp_ctxt_rsp_ggsn->common_flag.dual_addr_bearer_flag = 1;
	update_pdp_ctxt_rsp_ggsn->common_flag.upgrade_qos_supported =1;
	update_pdp_ctxt_rsp_ggsn->common_flag.nrsn =1;
	update_pdp_ctxt_rsp_ggsn->common_flag.no_qos_negotiation =1;
	update_pdp_ctxt_rsp_ggsn->common_flag.mbms_counting_information = 1;
	update_pdp_ctxt_rsp_ggsn->common_flag.ran_procedures_ready =1;
	update_pdp_ctxt_rsp_ggsn->common_flag.mbms_service_type = 1;
	update_pdp_ctxt_rsp_ggsn->common_flag.prohibit_payload_compression = 1;

	update_pdp_ctxt_rsp_ggsn->apn_restriction.header.type = GTPV1_IE_APN_RESTRICTION;
	update_pdp_ctxt_rsp_ggsn->apn_restriction.header.length =1;
	update_pdp_ctxt_rsp_ggsn->apn_restriction.restriction_type_value = 12;

	update_pdp_ctxt_rsp_ggsn->bearer_control.header.type = GTPV1_IE_BEARER_CONTROL_MODE;
	update_pdp_ctxt_rsp_ggsn->bearer_control.header.length = 1;
	update_pdp_ctxt_rsp_ggsn->bearer_control.bearer_control_mode = 3;

	update_pdp_ctxt_rsp_ggsn->ms_info_change_reporting_action.header.type = GTPV1_IE_MS_INFO_CHANGE_REPORTING_ACTION;
	update_pdp_ctxt_rsp_ggsn->ms_info_change_reporting_action.header.length = 1;
	update_pdp_ctxt_rsp_ggsn->ms_info_change_reporting_action.action = 4;

	update_pdp_ctxt_rsp_ggsn->evolved_allocation_retention_priority_1.header.type = GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_I;
	update_pdp_ctxt_rsp_ggsn->evolved_allocation_retention_priority_1.header.length = 1;
	update_pdp_ctxt_rsp_ggsn->evolved_allocation_retention_priority_1.spare =0;
	update_pdp_ctxt_rsp_ggsn->evolved_allocation_retention_priority_1.pci =1;
	update_pdp_ctxt_rsp_ggsn->evolved_allocation_retention_priority_1.pl = 12;
	update_pdp_ctxt_rsp_ggsn->evolved_allocation_retention_priority_1.spare2 =0;
	update_pdp_ctxt_rsp_ggsn->evolved_allocation_retention_priority_1.pvi = 1;

	update_pdp_ctxt_rsp_ggsn->csg_information_reporting_action.header.type = GTPV1_IE_CSG_INFORMATION_REPORTING_ACTION;
	update_pdp_ctxt_rsp_ggsn->csg_information_reporting_action.header.length = 1;
	update_pdp_ctxt_rsp_ggsn->csg_information_reporting_action.spare = 0;
	update_pdp_ctxt_rsp_ggsn->csg_information_reporting_action.ucuhc = 1;
	update_pdp_ctxt_rsp_ggsn->csg_information_reporting_action.ucshc = 1;
	update_pdp_ctxt_rsp_ggsn->csg_information_reporting_action.uccsg = 1;

	update_pdp_ctxt_rsp_ggsn->apn_ambr.header.type = GTPV1_IE_APN_AMBR;
	update_pdp_ctxt_rsp_ggsn->apn_ambr.header.length = 8;
	update_pdp_ctxt_rsp_ggsn->apn_ambr.apn_ambr_uplink = 0;
	update_pdp_ctxt_rsp_ggsn->apn_ambr.apn_ambr_downlink = 7;

	update_pdp_ctxt_rsp_ggsn->private_extension.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	update_pdp_ctxt_rsp_ggsn->private_extension.header.length = 6;
	update_pdp_ctxt_rsp_ggsn->private_extension.extension_identifier = 12;
	strncpy((char *)&update_pdp_ctxt_rsp_ggsn->private_extension.extension_value, "2021", 4);

	return;
}

void fill_gtpv1_update_pdp_ctxt_rsp_sgsn(gtpv1_update_pdp_ctxt_rsp_sgsn_t *update_pdp_ctxt_rsp_sgsn){

	update_pdp_ctxt_rsp_sgsn->header.version = 1;
	update_pdp_ctxt_rsp_sgsn->header.protocol_type = 1;
	update_pdp_ctxt_rsp_sgsn->header.spare = 0;
	update_pdp_ctxt_rsp_sgsn->header.extension_header = 0;
	update_pdp_ctxt_rsp_sgsn->header.seq_num_flag = 0;
	update_pdp_ctxt_rsp_sgsn->header.n_pdu_flag = 0;

	update_pdp_ctxt_rsp_sgsn->header.message_type = GTPV1_UPDATE_PDP_CTXT_RSP;
	update_pdp_ctxt_rsp_sgsn->header.message_len = 112;
	update_pdp_ctxt_rsp_sgsn->header.teid = 0x372f0000;
	update_pdp_ctxt_rsp_sgsn->header.seq = 0x00fe;
	update_pdp_ctxt_rsp_sgsn->header.n_pdu_number = 4;
	update_pdp_ctxt_rsp_sgsn->header.next_extension_header_type = 0;

	update_pdp_ctxt_rsp_sgsn->cause.header.type = GTPV1_IE_CAUSE;
	update_pdp_ctxt_rsp_sgsn->cause.cause_value = 128;

	update_pdp_ctxt_rsp_sgsn->recovery.header.type = GTPV1_IE_RECOVERY;
	update_pdp_ctxt_rsp_sgsn->recovery.restart_counter = 2;

	update_pdp_ctxt_rsp_sgsn->tunn_endpt_idnt_data_1.header.type = GTPV1_IE_TEID_DATA_1;
	update_pdp_ctxt_rsp_sgsn->tunn_endpt_idnt_data_1.teid = 0x0fffeee;

	update_pdp_ctxt_rsp_sgsn->protocol_config_options.header.type = GTPV1_IE_PROTOCOL_CONFIG_OPTIONS;
	update_pdp_ctxt_rsp_sgsn->protocol_config_options.header.length = 25;
	update_pdp_ctxt_rsp_sgsn->protocol_config_options.pco.pco_flag_ext  = 1;
	update_pdp_ctxt_rsp_sgsn->protocol_config_options.pco.pco_flag_spare  = 0;
	update_pdp_ctxt_rsp_sgsn->protocol_config_options.pco.pco_cfg_proto  = 1;
	update_pdp_ctxt_rsp_sgsn->protocol_config_options.pco.pco_content_count  = 2;
	update_pdp_ctxt_rsp_sgsn->protocol_config_options.pco.pco_content[0].prot_or_cont_id  = 2;
	update_pdp_ctxt_rsp_sgsn->protocol_config_options.pco.pco_content[0].length  = 9;
	strncpy((char *)&update_pdp_ctxt_rsp_sgsn->protocol_config_options.pco.pco_content[0].content,"355240599",9);
	update_pdp_ctxt_rsp_sgsn->protocol_config_options.pco.pco_content[1].prot_or_cont_id  = 2;
	update_pdp_ctxt_rsp_sgsn->protocol_config_options.pco.pco_content[1].length  = 9;
	strncpy((char *)&update_pdp_ctxt_rsp_sgsn->protocol_config_options.pco.pco_content[1].content,"355240589",9);

	update_pdp_ctxt_rsp_sgsn->sgsn_address_for_user_traffic.header.type = GTPV1_IE_GSN_ADDR;
	update_pdp_ctxt_rsp_sgsn->sgsn_address_for_user_traffic.header.length = 4;
	update_pdp_ctxt_rsp_sgsn->sgsn_address_for_user_traffic.gsn_address.ipv4 = 3232235563;

	update_pdp_ctxt_rsp_sgsn->qos_profile.header.type = GTPV1_IE_QOS;
	update_pdp_ctxt_rsp_sgsn->qos_profile.header.length = 21;
	update_pdp_ctxt_rsp_sgsn->qos_profile.qos.allocation_retention_priority = 0;
	update_pdp_ctxt_rsp_sgsn->qos_profile.qos.spare1 = 0;
	update_pdp_ctxt_rsp_sgsn->qos_profile.qos.delay_class = 2;
	update_pdp_ctxt_rsp_sgsn->qos_profile.qos.reliablity_class = 2;
	update_pdp_ctxt_rsp_sgsn->qos_profile.qos.peak_throughput = 3;
	update_pdp_ctxt_rsp_sgsn->qos_profile.qos.spare2 = 0;
	update_pdp_ctxt_rsp_sgsn->qos_profile.qos.precedence_class = 1;
	update_pdp_ctxt_rsp_sgsn->qos_profile.qos.spare3 = 0;
	update_pdp_ctxt_rsp_sgsn->qos_profile.qos.mean_throughput = 4;
	update_pdp_ctxt_rsp_sgsn->qos_profile.qos.traffic_class = 1;
	update_pdp_ctxt_rsp_sgsn->qos_profile.qos.delivery_order = 1;
	update_pdp_ctxt_rsp_sgsn->qos_profile.qos.delivery_erroneous_sdu = 2;
	update_pdp_ctxt_rsp_sgsn->qos_profile.qos.max_sdu_size = 3;
	update_pdp_ctxt_rsp_sgsn->qos_profile.qos.max_bitrate_uplink = 123;
	update_pdp_ctxt_rsp_sgsn->qos_profile.qos.max_bitrate_downlink = 234;
	update_pdp_ctxt_rsp_sgsn->qos_profile.qos.residual_ber = 1;
	update_pdp_ctxt_rsp_sgsn->qos_profile.qos.sdu_error_ratio = 1; 
	update_pdp_ctxt_rsp_sgsn->qos_profile.qos.transfer_delay = 1; 
	update_pdp_ctxt_rsp_sgsn->qos_profile.qos.traffic_handling_priority = 2;
	update_pdp_ctxt_rsp_sgsn->qos_profile.qos.guaranteed_bitrate_uplink = 122;
	update_pdp_ctxt_rsp_sgsn->qos_profile.qos.guaranteed_bitrate_downlink = 222;
	update_pdp_ctxt_rsp_sgsn->qos_profile.qos.spare4 = 0; 
	update_pdp_ctxt_rsp_sgsn->qos_profile.qos.signalling_indication = 1;
	update_pdp_ctxt_rsp_sgsn->qos_profile.qos.source_statistics_descriptor = 1;
	update_pdp_ctxt_rsp_sgsn->qos_profile.qos.max_bitrate_downlink_ext1 = 22;
	update_pdp_ctxt_rsp_sgsn->qos_profile.qos.guaranteed_bitrate_downlink_ext1 = 11;
	update_pdp_ctxt_rsp_sgsn->qos_profile.qos.max_bitrate_uplink_ext1 = 33;
	update_pdp_ctxt_rsp_sgsn->qos_profile.qos.guaranteed_bitrate_uplink_ext1 = 22;
	update_pdp_ctxt_rsp_sgsn->qos_profile.qos.max_bitrate_downlink_ext2 = 44;
	update_pdp_ctxt_rsp_sgsn->qos_profile.qos.guaranteed_bitrate_downlink_ext2 = 33;
	update_pdp_ctxt_rsp_sgsn->qos_profile.qos.max_bitrate_uplink_ext2 = 34;
	update_pdp_ctxt_rsp_sgsn->qos_profile.qos.guaranteed_bitrate_uplink_ext2 = 23;

	update_pdp_ctxt_rsp_sgsn->user_location_information.header.type = GTPV1_IE_USER_LOCATION_INFORMATION;
	update_pdp_ctxt_rsp_sgsn->user_location_information.header.length = 8;
	update_pdp_ctxt_rsp_sgsn->user_location_information.geographic_location_type = 1;
	update_pdp_ctxt_rsp_sgsn->user_location_information.mcc_digit_2 = 0x0;
	update_pdp_ctxt_rsp_sgsn->user_location_information.mcc_digit_1 = 0x4;
	update_pdp_ctxt_rsp_sgsn->user_location_information.mnc_digit_3 = 0x8;
	update_pdp_ctxt_rsp_sgsn->user_location_information.mcc_digit_3 = 0x4;
	update_pdp_ctxt_rsp_sgsn->user_location_information.mnc_digit_2 = 0x7;
	update_pdp_ctxt_rsp_sgsn->user_location_information.mnc_digit_1 = 0x0;
	update_pdp_ctxt_rsp_sgsn->user_location_information.lac = 0x1;
	update_pdp_ctxt_rsp_sgsn->user_location_information.ci_sac_rac = 0x1;

	update_pdp_ctxt_rsp_sgsn->ms_time_zone.header.type = GTPV1_IE_MS_TIME_ZONE;
	update_pdp_ctxt_rsp_sgsn->ms_time_zone.header.length = 2;
	update_pdp_ctxt_rsp_sgsn->ms_time_zone.time_zone = 1;
	update_pdp_ctxt_rsp_sgsn->ms_time_zone.spare = 0;
	update_pdp_ctxt_rsp_sgsn->ms_time_zone.daylight_saving_time = 1;

	update_pdp_ctxt_rsp_sgsn->direct_tunnel_flag.header.type = GTPV1_IE_DIRECT_TUNNEL_FLAG;
	update_pdp_ctxt_rsp_sgsn->direct_tunnel_flag.header.length = 1;
	update_pdp_ctxt_rsp_sgsn->direct_tunnel_flag.spare = 0;
	update_pdp_ctxt_rsp_sgsn->direct_tunnel_flag.ei = 1;
	update_pdp_ctxt_rsp_sgsn->direct_tunnel_flag.gcsi = 1;
	update_pdp_ctxt_rsp_sgsn->direct_tunnel_flag.dti = 1;

	update_pdp_ctxt_rsp_sgsn->evolved_allocation_retention_priority_1.header.type = GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_I;
	update_pdp_ctxt_rsp_sgsn->evolved_allocation_retention_priority_1.header.length = 1;
	update_pdp_ctxt_rsp_sgsn->evolved_allocation_retention_priority_1.spare =0;
	update_pdp_ctxt_rsp_sgsn->evolved_allocation_retention_priority_1.pci =1;
	update_pdp_ctxt_rsp_sgsn->evolved_allocation_retention_priority_1.pl = 12;
	update_pdp_ctxt_rsp_sgsn->evolved_allocation_retention_priority_1.spare2 =0;
	update_pdp_ctxt_rsp_sgsn->evolved_allocation_retention_priority_1.pvi = 1;

	update_pdp_ctxt_rsp_sgsn->apn_ambr.header.type = GTPV1_IE_APN_AMBR;
	update_pdp_ctxt_rsp_sgsn->apn_ambr.header.length = 8;
	update_pdp_ctxt_rsp_sgsn->apn_ambr.apn_ambr_uplink = 0;
	update_pdp_ctxt_rsp_sgsn->apn_ambr.apn_ambr_downlink = 7;

	update_pdp_ctxt_rsp_sgsn->private_extension.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	update_pdp_ctxt_rsp_sgsn->private_extension.header.length = 6;
	update_pdp_ctxt_rsp_sgsn->private_extension.extension_identifier = 12;
	strncpy((char *)&update_pdp_ctxt_rsp_sgsn->private_extension.extension_value, "2021", 4);

	return;
}

void fill_gtpv1_delete_pdp_ctxt_req(gtpv1_delete_pdp_ctxt_req_t *delete_pdp_ctxt_req) {

	delete_pdp_ctxt_req->header.version = 1;
	delete_pdp_ctxt_req->header.protocol_type = 1;
	delete_pdp_ctxt_req->header.spare = 0;
	delete_pdp_ctxt_req->header.extension_header = 0;
	delete_pdp_ctxt_req->header.seq_num_flag = 0;
	delete_pdp_ctxt_req->header.n_pdu_flag = 0;

	delete_pdp_ctxt_req->header.message_type = GTPV1_DELETE_PDP_CTXT_REQ;
	delete_pdp_ctxt_req->header.message_len = 70;
	delete_pdp_ctxt_req->header.teid = 0x372f0000;
	delete_pdp_ctxt_req->header.seq = 0x00fe;
	delete_pdp_ctxt_req->header.n_pdu_number = 4;
	delete_pdp_ctxt_req->header.next_extension_header_type = 0;

	delete_pdp_ctxt_req->cause.header.type = GTPV1_IE_CAUSE;
	delete_pdp_ctxt_req->cause.cause_value = 128;

	delete_pdp_ctxt_req->teardown_ind.header.type = GTPV1_IE_TEARDOWN_IND;
	delete_pdp_ctxt_req->teardown_ind.spare = 0;
	delete_pdp_ctxt_req->teardown_ind.teardown_ind = 1;

	delete_pdp_ctxt_req->nsapi.header.type = GTPV1_IE_NSAPI;
	delete_pdp_ctxt_req->nsapi.spare = 0;
	delete_pdp_ctxt_req->nsapi.nsapi_value = 8;

	delete_pdp_ctxt_req->protocol_config_options.header.type = GTPV1_IE_PROTOCOL_CONFIG_OPTIONS;
	delete_pdp_ctxt_req->protocol_config_options.header.length = 25;
	delete_pdp_ctxt_req->protocol_config_options.pco.pco_flag_ext  = 1;
	delete_pdp_ctxt_req->protocol_config_options.pco.pco_flag_spare  = 0;
	delete_pdp_ctxt_req->protocol_config_options.pco.pco_cfg_proto  = 1;
	delete_pdp_ctxt_req->protocol_config_options.pco.pco_content_count  = 2;
	delete_pdp_ctxt_req->protocol_config_options.pco.pco_content[0].prot_or_cont_id  = 2;
	delete_pdp_ctxt_req->protocol_config_options.pco.pco_content[0].length  = 9;
	strncpy((char *)&delete_pdp_ctxt_req->protocol_config_options.pco.pco_content[0].content,"355240599",9);
	delete_pdp_ctxt_req->protocol_config_options.pco.pco_content[1].prot_or_cont_id  = 2;
	delete_pdp_ctxt_req->protocol_config_options.pco.pco_content[1].length  = 9;
	strncpy((char *)&delete_pdp_ctxt_req->protocol_config_options.pco.pco_content[1].content,"355240589",9);

	delete_pdp_ctxt_req->user_location_information.header.type = GTPV1_IE_USER_LOCATION_INFORMATION;
	delete_pdp_ctxt_req->user_location_information.header.length = 8;
	delete_pdp_ctxt_req->user_location_information.geographic_location_type = 1;
	delete_pdp_ctxt_req->user_location_information.mcc_digit_2 = 0x0;
	delete_pdp_ctxt_req->user_location_information.mcc_digit_1 = 0x4;
	delete_pdp_ctxt_req->user_location_information.mnc_digit_3 = 0x8;
	delete_pdp_ctxt_req->user_location_information.mcc_digit_3 = 0x4;
	delete_pdp_ctxt_req->user_location_information.mnc_digit_2 = 0x7;
	delete_pdp_ctxt_req->user_location_information.mnc_digit_1 = 0x0;
	delete_pdp_ctxt_req->user_location_information.lac = 0x1;
	delete_pdp_ctxt_req->user_location_information.ci_sac_rac = 0x1;

	delete_pdp_ctxt_req->ms_time_zone.header.type = GTPV1_IE_MS_TIME_ZONE;
	delete_pdp_ctxt_req->ms_time_zone.header.length = 2;
	delete_pdp_ctxt_req->ms_time_zone.time_zone = 1;
	delete_pdp_ctxt_req->ms_time_zone.spare = 0;
	delete_pdp_ctxt_req->ms_time_zone.daylight_saving_time = 1;

	delete_pdp_ctxt_req->extended_common_flag.header.type = GTPV1_IE_EXTENDED_COMMON_FLAG;
	delete_pdp_ctxt_req->extended_common_flag.header.length = 1;
	delete_pdp_ctxt_req->extended_common_flag.uasi = 1;
	delete_pdp_ctxt_req->extended_common_flag.bdwi = 1;
	delete_pdp_ctxt_req->extended_common_flag.pcri = 1;
	delete_pdp_ctxt_req->extended_common_flag.vb = 1;
	delete_pdp_ctxt_req->extended_common_flag.retloc = 1;
	delete_pdp_ctxt_req->extended_common_flag.cpsr = 1;
	delete_pdp_ctxt_req->extended_common_flag.ccrsi = 1;
	delete_pdp_ctxt_req->extended_common_flag.unauthenticated_imsi = 1;

	delete_pdp_ctxt_req->uli_timestamp.header.type = GTPV1_IE_ULI_TIMESTAMP;
	delete_pdp_ctxt_req->uli_timestamp.header.length = 4;
	delete_pdp_ctxt_req->uli_timestamp.timestamp_value = 3;

	delete_pdp_ctxt_req->private_extension.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	delete_pdp_ctxt_req->private_extension.header.length = 6;
	delete_pdp_ctxt_req->private_extension.extension_identifier = 12;
	strncpy((char*)&delete_pdp_ctxt_req->private_extension.extension_value, "2021", 4);

	return;
}

void fill_gtpv1_delete_pdp_ctxt_rsp(gtpv1_delete_pdp_ctxt_rsp_t *delete_pdp_ctxt_rsp){

	delete_pdp_ctxt_rsp->header.version = 1;
	delete_pdp_ctxt_rsp->header.protocol_type = 1;
	delete_pdp_ctxt_rsp->header.spare = 0;
	delete_pdp_ctxt_rsp->header.extension_header = 0;
	delete_pdp_ctxt_rsp->header.seq_num_flag = 0;
	delete_pdp_ctxt_rsp->header.n_pdu_flag = 0;

	delete_pdp_ctxt_rsp->header.message_type = GTPV1_DELETE_PDP_CTXT_RSP;
	delete_pdp_ctxt_rsp->header.message_len = 62;
	delete_pdp_ctxt_rsp->header.teid = 0x372f0000;
	delete_pdp_ctxt_rsp->header.seq = 0x00fe;
	delete_pdp_ctxt_rsp->header.n_pdu_number = 4;
	delete_pdp_ctxt_rsp->header.next_extension_header_type = 0;

	delete_pdp_ctxt_rsp->cause.header.type = GTPV1_IE_CAUSE;
	delete_pdp_ctxt_rsp->cause.cause_value = 128;

	delete_pdp_ctxt_rsp->protocol_config_options.header.type = GTPV1_IE_PROTOCOL_CONFIG_OPTIONS;
	delete_pdp_ctxt_rsp->protocol_config_options.header.length = 25;
	delete_pdp_ctxt_rsp->protocol_config_options.pco.pco_flag_ext  = 1;
	delete_pdp_ctxt_rsp->protocol_config_options.pco.pco_flag_spare  = 0;
	delete_pdp_ctxt_rsp->protocol_config_options.pco.pco_cfg_proto  = 1;
	delete_pdp_ctxt_rsp->protocol_config_options.pco.pco_content_count  = 2;
	delete_pdp_ctxt_rsp->protocol_config_options.pco.pco_content[0].prot_or_cont_id  = 2;
	delete_pdp_ctxt_rsp->protocol_config_options.pco.pco_content[0].length  = 9;
	strncpy((char *)&delete_pdp_ctxt_rsp->protocol_config_options.pco.pco_content[0].content,"355240599",9);
	delete_pdp_ctxt_rsp->protocol_config_options.pco.pco_content[1].prot_or_cont_id  = 2;
	delete_pdp_ctxt_rsp->protocol_config_options.pco.pco_content[1].length  = 9;
	strncpy((char *)&delete_pdp_ctxt_rsp->protocol_config_options.pco.pco_content[1].content,"355240589",9);

	delete_pdp_ctxt_rsp->user_location_information.header.type = GTPV1_IE_USER_LOCATION_INFORMATION;
	delete_pdp_ctxt_rsp->user_location_information.header.length = 8;
	delete_pdp_ctxt_rsp->user_location_information.geographic_location_type = 1;
	delete_pdp_ctxt_rsp->user_location_information.mcc_digit_2 = 0x0;
	delete_pdp_ctxt_rsp->user_location_information.mcc_digit_1 = 0x4;
	delete_pdp_ctxt_rsp->user_location_information.mnc_digit_3 = 0x8;
	delete_pdp_ctxt_rsp->user_location_information.mcc_digit_3 = 0x4;
	delete_pdp_ctxt_rsp->user_location_information.mnc_digit_2 = 0x7;
	delete_pdp_ctxt_rsp->user_location_information.mnc_digit_1 = 0x0;
	delete_pdp_ctxt_rsp->user_location_information.lac = 0x1;
	delete_pdp_ctxt_rsp->user_location_information.ci_sac_rac = 0x1;

	delete_pdp_ctxt_rsp->ms_time_zone.header.type = GTPV1_IE_MS_TIME_ZONE;
	delete_pdp_ctxt_rsp->ms_time_zone.header.length = 2;
	delete_pdp_ctxt_rsp->ms_time_zone.time_zone = 1;
	delete_pdp_ctxt_rsp->ms_time_zone.spare = 0;
	delete_pdp_ctxt_rsp->ms_time_zone.daylight_saving_time = 1;

	delete_pdp_ctxt_rsp->uli_timestamp.header.type = GTPV1_IE_ULI_TIMESTAMP;
	delete_pdp_ctxt_rsp->uli_timestamp.header.length = 4;
	delete_pdp_ctxt_rsp->uli_timestamp.timestamp_value = 3;

	delete_pdp_ctxt_rsp->private_extension.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	delete_pdp_ctxt_rsp->private_extension.header.length = 6;
	delete_pdp_ctxt_rsp->private_extension.extension_identifier = 12;
	strncpy((char*)&delete_pdp_ctxt_rsp->private_extension.extension_value, "2021", 4);

	return;
}

void fill_gtpv1_pdu_notification_req(gtpv1_pdu_notification_req_t *pdu_notification_req) {

	pdu_notification_req->header.version = 1;
	pdu_notification_req->header.protocol_type = 1;
	pdu_notification_req->header.spare = 0;
	pdu_notification_req->header.extension_header = 0;
	pdu_notification_req->header.seq_num_flag = 0;
	pdu_notification_req->header.n_pdu_flag = 0;

	pdu_notification_req->header.message_type = GTPV1_PDU_NOTIFICATION_REQ;
	pdu_notification_req->header.message_len = 83;
	pdu_notification_req->header.teid = 0x372f0000;
	pdu_notification_req->header.seq = 0x00fe;
	pdu_notification_req->header.n_pdu_number = 4;
	pdu_notification_req->header.next_extension_header_type = 0;

	pdu_notification_req->imsi.header.type = GTPV1_IE_IMSI;
	pdu_notification_req->imsi.imsi_number_digits = 272031000000000;

	pdu_notification_req->tunn_endpt_idnt_control_plane.header.type = GTPV1_IE_TEID_CONTROL_PLANE;
	pdu_notification_req->tunn_endpt_idnt_control_plane.teid = 0x00ab;

	pdu_notification_req->end_user_address.header.type = GTPV1_IE_END_USER_ADDR;
	pdu_notification_req->end_user_address.header.length = 6;
	pdu_notification_req->end_user_address.spare = 0xf;
	pdu_notification_req->end_user_address.pdp_type_org = 1;
	pdu_notification_req->end_user_address.pdp_type_number = 0x21;
	pdu_notification_req->end_user_address.pdp_address.ipv4 = 3232235564; 

	pdu_notification_req->apn.header.type = GTPV1_IE_APN;
	pdu_notification_req->apn.header.length = 13;
	strncpy((char *)&pdu_notification_req->apn.apn_value,"nextphones.co",13);

	pdu_notification_req->protocol_config_options.header.type = GTPV1_IE_PROTOCOL_CONFIG_OPTIONS;
	pdu_notification_req->protocol_config_options.header.length = 25;
	pdu_notification_req->protocol_config_options.pco.pco_flag_ext  = 1;
	pdu_notification_req->protocol_config_options.pco.pco_flag_spare  = 0;
	pdu_notification_req->protocol_config_options.pco.pco_cfg_proto  = 1;
	pdu_notification_req->protocol_config_options.pco.pco_content_count  = 2;
	pdu_notification_req->protocol_config_options.pco.pco_content[0].prot_or_cont_id  = 2;
	pdu_notification_req->protocol_config_options.pco.pco_content[0].length  = 9;
	strncpy((char *)&pdu_notification_req->protocol_config_options.pco.pco_content[0].content,"355240599",9);
	pdu_notification_req->protocol_config_options.pco.pco_content[1].prot_or_cont_id  = 2;
	pdu_notification_req->protocol_config_options.pco.pco_content[1].length  = 9;
	strncpy((char *)&pdu_notification_req->protocol_config_options.pco.pco_content[1].content,"355240589",9);

	pdu_notification_req->ggsn_addr_control_plane.header.type = GTPV1_IE_GSN_ADDR;
	pdu_notification_req->ggsn_addr_control_plane.header.length = 4;
	pdu_notification_req->ggsn_addr_control_plane.gsn_address.ipv4 = 3232235564; 

	pdu_notification_req->private_extension.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	pdu_notification_req->private_extension.header.length = 6;
	pdu_notification_req->private_extension.extension_identifier = 12;
	strncpy((char *)&pdu_notification_req->private_extension.extension_value, "2021", 4);

	return;
}

void fill_gtpv1_pdu_notification_rsp(gtpv1_pdu_notification_rsp_t *pdu_notification_rsp){

	pdu_notification_rsp->header.version = 1;
	pdu_notification_rsp->header.protocol_type = 1;
	pdu_notification_rsp->header.spare = 0;
	pdu_notification_rsp->header.extension_header = 0;
	pdu_notification_rsp->header.seq_num_flag = 0;
	pdu_notification_rsp->header.n_pdu_flag = 0;

	pdu_notification_rsp->header.message_type = GTPV1_PDU_NOTIFICATION_RSP;
	pdu_notification_rsp->header.message_len = 11;
	pdu_notification_rsp->header.teid = 0x372f0000;
	pdu_notification_rsp->header.seq = 0x00fe;
	pdu_notification_rsp->header.n_pdu_number = 4;
	pdu_notification_rsp->header.next_extension_header_type = 0;

	pdu_notification_rsp->cause.header.type = GTPV1_IE_CAUSE;
	pdu_notification_rsp->cause.cause_value = 128;

	pdu_notification_rsp->private_extension.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	pdu_notification_rsp->private_extension.header.length = 6;
	pdu_notification_rsp->private_extension.extension_identifier = 12;
	strncpy((char *)&pdu_notification_rsp->private_extension.extension_value, "2021", 4);

	return;
}

void fill_gtpv1_pdu_notification_reject_req(gtpv1_pdu_notification_reject_req_t *pdu_notification_reject_req) {

	pdu_notification_reject_req->header.version = 1;
	pdu_notification_reject_req->header.protocol_type = 1;
	pdu_notification_reject_req->header.spare = 0;
	pdu_notification_reject_req->header.extension_header = 0;
	pdu_notification_reject_req->header.seq_num_flag = 0;
	pdu_notification_reject_req->header.n_pdu_flag = 0;

	pdu_notification_reject_req->header.message_type = GTPV1_PDU_NOTIFICATION_REJECT_REQ;
	pdu_notification_reject_req->header.message_len = 69;
	pdu_notification_reject_req->header.teid = 0x372f0000;
	pdu_notification_reject_req->header.seq = 0x00fe;
	pdu_notification_reject_req->header.n_pdu_number = 4;
	pdu_notification_reject_req->header.next_extension_header_type = 0;

	pdu_notification_reject_req->cause.header.type = GTPV1_IE_CAUSE;
	pdu_notification_reject_req->cause.cause_value = 128;

	pdu_notification_reject_req->tunn_endpt_idnt_control_plane.header.type = GTPV1_IE_TEID_CONTROL_PLANE;
	pdu_notification_reject_req->tunn_endpt_idnt_control_plane.teid = 0x00ab;

	pdu_notification_reject_req->end_user_address.header.type = GTPV1_IE_END_USER_ADDR;
	pdu_notification_reject_req->end_user_address.header.length = 6;
	pdu_notification_reject_req->end_user_address.spare = 0xf;
	pdu_notification_reject_req->end_user_address.pdp_type_org = 1;
	pdu_notification_reject_req->end_user_address.pdp_type_number = 0x21;
	pdu_notification_reject_req->end_user_address.pdp_address.ipv4 = 3232235564;

	pdu_notification_reject_req->apn.header.type = GTPV1_IE_APN;
	pdu_notification_reject_req->apn.header.length = 13;
	strncpy((char *)&pdu_notification_reject_req->apn.apn_value,"nextphones.co",13);

	pdu_notification_reject_req->protocol_config_options.header.type = GTPV1_IE_PROTOCOL_CONFIG_OPTIONS;
	pdu_notification_reject_req->protocol_config_options.header.length = 25;
	pdu_notification_reject_req->protocol_config_options.pco.pco_flag_ext  = 1;
	pdu_notification_reject_req->protocol_config_options.pco.pco_flag_spare  = 0;
	pdu_notification_reject_req->protocol_config_options.pco.pco_cfg_proto  = 1;
	pdu_notification_reject_req->protocol_config_options.pco.pco_content_count  = 2;
	pdu_notification_reject_req->protocol_config_options.pco.pco_content[0].prot_or_cont_id  = 2;
	pdu_notification_reject_req->protocol_config_options.pco.pco_content[0].length  = 9;
	strncpy((char *)&pdu_notification_reject_req->protocol_config_options.pco.pco_content[0].content,"355240599",9);
	pdu_notification_reject_req->protocol_config_options.pco.pco_content[1].prot_or_cont_id  = 2;
	pdu_notification_reject_req->protocol_config_options.pco.pco_content[1].length  = 9;
	strncpy((char *)&pdu_notification_reject_req->protocol_config_options.pco.pco_content[1].content,"355240589",9);

	pdu_notification_reject_req->private_extension.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	pdu_notification_reject_req->private_extension.header.length = 6;
	pdu_notification_reject_req->private_extension.extension_identifier = 12;
	strncpy((char *)&pdu_notification_reject_req->private_extension.extension_value, "2021", 4);

	return;
}

void fill_gtpv1_pdu_notification_reject_rsp(gtpv1_pdu_notification_reject_rsp_t *pdu_notification_reject_rsp){

	pdu_notification_reject_rsp->header.version = 1;
	pdu_notification_reject_rsp->header.protocol_type = 1;
	pdu_notification_reject_rsp->header.spare = 0;
	pdu_notification_reject_rsp->header.extension_header = 0;
	pdu_notification_reject_rsp->header.seq_num_flag = 0;
	pdu_notification_reject_rsp->header.n_pdu_flag = 0;

	pdu_notification_reject_rsp->header.message_type = GTPV1_PDU_NOTIFICATION_REJECT_RSP;
	pdu_notification_reject_rsp->header.message_len = 11;
	pdu_notification_reject_rsp->header.teid = 0x372f0000;
	pdu_notification_reject_rsp->header.seq = 0x00fe;
	pdu_notification_reject_rsp->header.n_pdu_number = 4;
	pdu_notification_reject_rsp->header.next_extension_header_type = 0;

	pdu_notification_reject_rsp->cause.header.type = GTPV1_IE_CAUSE;
	pdu_notification_reject_rsp->cause.cause_value = 128;

	pdu_notification_reject_rsp->private_extension.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	pdu_notification_reject_rsp->private_extension.header.length = 6;
	pdu_notification_reject_rsp->private_extension.extension_identifier = 12;
	strncpy((char *)&pdu_notification_reject_rsp->private_extension.extension_value, "2021", 4);

	return;
}

void fill_gtpv1_initiate_pdp_ctxt_active_req(gtpv1_initiate_pdp_ctxt_active_req_t *initiate_pdp_ctxt_active_req) {

	initiate_pdp_ctxt_active_req->header.version = 1;
	initiate_pdp_ctxt_active_req->header.protocol_type = 1;
	initiate_pdp_ctxt_active_req->header.spare = 0;
	initiate_pdp_ctxt_active_req->header.extension_header = 0;
	initiate_pdp_ctxt_active_req->header.seq_num_flag = 0;
	initiate_pdp_ctxt_active_req->header.n_pdu_flag = 0;

	initiate_pdp_ctxt_active_req->header.message_type = GTPV1_INITIATE_PDP_CTXT_ACTIVATION_REQ;
	initiate_pdp_ctxt_active_req->header.message_len = 93;
	initiate_pdp_ctxt_active_req->header.teid = 0;
	initiate_pdp_ctxt_active_req->header.seq = 0x00fe;
	initiate_pdp_ctxt_active_req->header.n_pdu_number = 4;
	initiate_pdp_ctxt_active_req->header.next_extension_header_type = 0;

	initiate_pdp_ctxt_active_req->linked_nsapi.header.type = GTPV1_IE_NSAPI;
	initiate_pdp_ctxt_active_req->linked_nsapi.spare = 0;
	initiate_pdp_ctxt_active_req->linked_nsapi.nsapi_value = 9;

	initiate_pdp_ctxt_active_req->protocol_config_options.header.type = GTPV1_IE_PROTOCOL_CONFIG_OPTIONS;
	initiate_pdp_ctxt_active_req->protocol_config_options.header.length = 25;
	initiate_pdp_ctxt_active_req->protocol_config_options.pco.pco_flag_ext  = 1;
	initiate_pdp_ctxt_active_req->protocol_config_options.pco.pco_flag_spare  = 0;
	initiate_pdp_ctxt_active_req->protocol_config_options.pco.pco_cfg_proto  = 1;
	initiate_pdp_ctxt_active_req->protocol_config_options.pco.pco_content_count  = 2;
	initiate_pdp_ctxt_active_req->protocol_config_options.pco.pco_content[0].prot_or_cont_id  = 2;
	initiate_pdp_ctxt_active_req->protocol_config_options.pco.pco_content[0].length  = 9;
	strncpy((char *)&initiate_pdp_ctxt_active_req->protocol_config_options.pco.pco_content[0].content,"355240599",9);
	initiate_pdp_ctxt_active_req->protocol_config_options.pco.pco_content[1].prot_or_cont_id  = 2;
	initiate_pdp_ctxt_active_req->protocol_config_options.pco.pco_content[1].length  = 9;
	strncpy((char *)&initiate_pdp_ctxt_active_req->protocol_config_options.pco.pco_content[1].content,"355240589",9);

	initiate_pdp_ctxt_active_req->qos_profile.header.type = GTPV1_IE_QOS;
	initiate_pdp_ctxt_active_req->qos_profile.header.length = 21;
	initiate_pdp_ctxt_active_req->qos_profile.qos.allocation_retention_priority = 2;
	initiate_pdp_ctxt_active_req->qos_profile.qos.spare1 = 0;
	initiate_pdp_ctxt_active_req->qos_profile.qos.delay_class = 2;
	initiate_pdp_ctxt_active_req->qos_profile.qos.reliablity_class = 2;
	initiate_pdp_ctxt_active_req->qos_profile.qos.peak_throughput = 3;
	initiate_pdp_ctxt_active_req->qos_profile.qos.spare2 = 0;
	initiate_pdp_ctxt_active_req->qos_profile.qos.precedence_class = 1;
	initiate_pdp_ctxt_active_req->qos_profile.qos.spare3 = 0;
	initiate_pdp_ctxt_active_req->qos_profile.qos.mean_throughput = 4;
	initiate_pdp_ctxt_active_req->qos_profile.qos.traffic_class = 1;
	initiate_pdp_ctxt_active_req->qos_profile.qos.delivery_order = 1;
	initiate_pdp_ctxt_active_req->qos_profile.qos.delivery_erroneous_sdu = 2;
	initiate_pdp_ctxt_active_req->qos_profile.qos.max_sdu_size = 3;
	initiate_pdp_ctxt_active_req->qos_profile.qos.max_bitrate_uplink = 123;
	initiate_pdp_ctxt_active_req->qos_profile.qos.max_bitrate_downlink = 234;
	initiate_pdp_ctxt_active_req->qos_profile.qos.residual_ber = 1;
	initiate_pdp_ctxt_active_req->qos_profile.qos.sdu_error_ratio = 1; 
	initiate_pdp_ctxt_active_req->qos_profile.qos.transfer_delay = 1; 
	initiate_pdp_ctxt_active_req->qos_profile.qos.traffic_handling_priority = 2;
	initiate_pdp_ctxt_active_req->qos_profile.qos.guaranteed_bitrate_uplink = 122;
	initiate_pdp_ctxt_active_req->qos_profile.qos.guaranteed_bitrate_downlink = 222;
	initiate_pdp_ctxt_active_req->qos_profile.qos.spare4 = 0; 
	initiate_pdp_ctxt_active_req->qos_profile.qos.signalling_indication = 1;
	initiate_pdp_ctxt_active_req->qos_profile.qos.source_statistics_descriptor = 1;
	initiate_pdp_ctxt_active_req->qos_profile.qos.max_bitrate_downlink_ext1 = 22;
	initiate_pdp_ctxt_active_req->qos_profile.qos.guaranteed_bitrate_downlink_ext1 = 11;
	initiate_pdp_ctxt_active_req->qos_profile.qos.max_bitrate_uplink_ext1 = 33;
	initiate_pdp_ctxt_active_req->qos_profile.qos.guaranteed_bitrate_uplink_ext1 = 22;
	initiate_pdp_ctxt_active_req->qos_profile.qos.max_bitrate_downlink_ext2 = 44;
	initiate_pdp_ctxt_active_req->qos_profile.qos.guaranteed_bitrate_downlink_ext2 = 33;
	initiate_pdp_ctxt_active_req->qos_profile.qos.max_bitrate_uplink_ext2 = 34;
	initiate_pdp_ctxt_active_req->qos_profile.qos.guaranteed_bitrate_uplink_ext2 = 23;

	initiate_pdp_ctxt_active_req->tft.header.type = GTPV1_IE_TFT;
	initiate_pdp_ctxt_active_req->tft.header.length = 19;
	initiate_pdp_ctxt_active_req->tft.tft_op_code = 1;
	initiate_pdp_ctxt_active_req->tft.e_bit = 1;
	initiate_pdp_ctxt_active_req->tft.no_packet_filters = 2;
	initiate_pdp_ctxt_active_req->tft.packet_filter_list_del[0].spare = 0;
	initiate_pdp_ctxt_active_req->tft.packet_filter_list_del[0].filter_id = 1;
	initiate_pdp_ctxt_active_req->tft.packet_filter_list_del[1].spare = 0;
	initiate_pdp_ctxt_active_req->tft.packet_filter_list_del[1].filter_id = 2;
	initiate_pdp_ctxt_active_req->tft.packet_filter_list_new[0].spare = 0;
	initiate_pdp_ctxt_active_req->tft.packet_filter_list_new[0].filter_direction = 1;
	initiate_pdp_ctxt_active_req->tft.packet_filter_list_new[0].filter_id = 5;
	initiate_pdp_ctxt_active_req->tft.packet_filter_list_new[0].filter_eval_precedence = 1;
	initiate_pdp_ctxt_active_req->tft.packet_filter_list_new[0].filter_content_length = 1;
	initiate_pdp_ctxt_active_req->tft.packet_filter_list_new[0].filter_content[0] = 1;
	initiate_pdp_ctxt_active_req->tft.packet_filter_list_new[1].spare = 0;
	initiate_pdp_ctxt_active_req->tft.packet_filter_list_new[1].filter_direction = 2;
	initiate_pdp_ctxt_active_req->tft.packet_filter_list_new[1].filter_id = 5;
	initiate_pdp_ctxt_active_req->tft.packet_filter_list_new[1].filter_eval_precedence = 1;
	initiate_pdp_ctxt_active_req->tft.packet_filter_list_new[1].filter_content_length = 2;
	initiate_pdp_ctxt_active_req->tft.packet_filter_list_new[1].filter_content[0] = 1;
	initiate_pdp_ctxt_active_req->tft.packet_filter_list_new[1].filter_content[1] = 0;
	initiate_pdp_ctxt_active_req->tft.parameters_list[0].parameter_id = 1;
	initiate_pdp_ctxt_active_req->tft.parameters_list[0].parameter_content_length = 2;
	initiate_pdp_ctxt_active_req->tft.parameters_list[0].parameter_content[0] = 1;
	initiate_pdp_ctxt_active_req->tft.parameters_list[0].parameter_content[1] = 2;
	initiate_pdp_ctxt_active_req->tft.parameters_list[1].parameter_id = 1;
	initiate_pdp_ctxt_active_req->tft.parameters_list[1].parameter_content_length = 3;
	initiate_pdp_ctxt_active_req->tft.parameters_list[1].parameter_content[0] = 3;
	initiate_pdp_ctxt_active_req->tft.parameters_list[1].parameter_content[1] = 2;
	initiate_pdp_ctxt_active_req->tft.parameters_list[1].parameter_content[2] = 0;

	initiate_pdp_ctxt_active_req->correlation_id.header.type = GTPV1_IE_CORRELATION_ID;
	initiate_pdp_ctxt_active_req->correlation_id.header.length = 1;
	initiate_pdp_ctxt_active_req->correlation_id.correlation_id = 5;

	initiate_pdp_ctxt_active_req->evolved_allocation_retention_priority_1.header.type = GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_I;
	initiate_pdp_ctxt_active_req->evolved_allocation_retention_priority_1.header.length = 1;
	initiate_pdp_ctxt_active_req->evolved_allocation_retention_priority_1.spare =0;
	initiate_pdp_ctxt_active_req->evolved_allocation_retention_priority_1.pci =1;
	initiate_pdp_ctxt_active_req->evolved_allocation_retention_priority_1.pl = 12;
	initiate_pdp_ctxt_active_req->evolved_allocation_retention_priority_1.spare2 =0;
	initiate_pdp_ctxt_active_req->evolved_allocation_retention_priority_1.pvi = 1;

	initiate_pdp_ctxt_active_req->private_extension.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	initiate_pdp_ctxt_active_req->private_extension.header.length = 6;
	initiate_pdp_ctxt_active_req->private_extension.extension_identifier = 12;
	strncpy((char *)&initiate_pdp_ctxt_active_req->private_extension.extension_value, "2021", 4);

	return;
}

void fill_gtpv1_initiate_pdp_ctxt_active_rsp(gtpv1_initiate_pdp_ctxt_active_rsp_t *initiate_pdp_ctxt_active_rsp){

	initiate_pdp_ctxt_active_rsp->header.version = 1;
	initiate_pdp_ctxt_active_rsp->header.protocol_type = 1;
	initiate_pdp_ctxt_active_rsp->header.spare = 0;
	initiate_pdp_ctxt_active_rsp->header.extension_header = 0;
	initiate_pdp_ctxt_active_rsp->header.seq_num_flag = 0;
	initiate_pdp_ctxt_active_rsp->header.n_pdu_flag = 0;

	initiate_pdp_ctxt_active_rsp->header.message_type = GTPV1_INITIATE_PDP_CTXT_ACTIVATION_RSP;
	initiate_pdp_ctxt_active_rsp->header.message_len = 39;
	initiate_pdp_ctxt_active_rsp->header.teid = 0x372f0000;
	initiate_pdp_ctxt_active_rsp->header.seq = 0x00fe;
	initiate_pdp_ctxt_active_rsp->header.n_pdu_number = 4;
	initiate_pdp_ctxt_active_rsp->header.next_extension_header_type = 0;

	initiate_pdp_ctxt_active_rsp->cause.header.type = GTPV1_IE_CAUSE;
	initiate_pdp_ctxt_active_rsp->cause.cause_value = 128;

	initiate_pdp_ctxt_active_rsp->protocol_config_options.header.type = GTPV1_IE_PROTOCOL_CONFIG_OPTIONS;
	initiate_pdp_ctxt_active_rsp->protocol_config_options.header.length = 25;
	initiate_pdp_ctxt_active_rsp->protocol_config_options.pco.pco_flag_ext  = 1;
	initiate_pdp_ctxt_active_rsp->protocol_config_options.pco.pco_flag_spare  = 0;
	initiate_pdp_ctxt_active_rsp->protocol_config_options.pco.pco_cfg_proto  = 1;
	initiate_pdp_ctxt_active_rsp->protocol_config_options.pco.pco_content_count  = 2;
	initiate_pdp_ctxt_active_rsp->protocol_config_options.pco.pco_content[0].prot_or_cont_id  = 2;
	initiate_pdp_ctxt_active_rsp->protocol_config_options.pco.pco_content[0].length  = 9;
	strncpy((char *)&initiate_pdp_ctxt_active_rsp->protocol_config_options.pco.pco_content[0].content,"355240599",9);
	initiate_pdp_ctxt_active_rsp->protocol_config_options.pco.pco_content[1].prot_or_cont_id  = 2;
	initiate_pdp_ctxt_active_rsp->protocol_config_options.pco.pco_content[1].length  = 9;
	strncpy((char *)&initiate_pdp_ctxt_active_rsp->protocol_config_options.pco.pco_content[1].content,"355240589",9);

	initiate_pdp_ctxt_active_rsp->private_extension.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	initiate_pdp_ctxt_active_rsp->private_extension.header.length = 6;
	initiate_pdp_ctxt_active_rsp->private_extension.extension_identifier = 12;
	strncpy((char *)&initiate_pdp_ctxt_active_rsp->private_extension.extension_value, "2021", 4);

	return;
}

void fill_gtpv1_send_routeing_info_for_gprs_req(gtpv1_send_routeing_info_for_gprs_req_t *send_routeing_info_for_gprs_req) {

	send_routeing_info_for_gprs_req->header.version = 1;
	send_routeing_info_for_gprs_req->header.protocol_type = 1;
	send_routeing_info_for_gprs_req->header.spare = 0;
	send_routeing_info_for_gprs_req->header.extension_header = 0;
	send_routeing_info_for_gprs_req->header.seq_num_flag = 0;
	send_routeing_info_for_gprs_req->header.n_pdu_flag = 0;

	send_routeing_info_for_gprs_req->header.message_type = GTPV1_SEND_ROUTEING_INFO_FOR_GPRS_REQ;
	send_routeing_info_for_gprs_req->header.message_len = 18;
	send_routeing_info_for_gprs_req->header.teid = 0x372f0000;
	send_routeing_info_for_gprs_req->header.seq = 0x00fe;
	send_routeing_info_for_gprs_req->header.n_pdu_number = 4;
	send_routeing_info_for_gprs_req->header.next_extension_header_type = 0;

	send_routeing_info_for_gprs_req->imsi.header.type = GTPV1_IE_IMSI;
	send_routeing_info_for_gprs_req->imsi.imsi_number_digits = 272031000000000;

	send_routeing_info_for_gprs_req->private_extension.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	send_routeing_info_for_gprs_req->private_extension.header.length = 6;
	send_routeing_info_for_gprs_req->private_extension.extension_identifier = 12;
	strncpy((char *)&send_routeing_info_for_gprs_req->private_extension.extension_value, "2021", 4);

	return;
};

void fill_gtpv1_send_routeing_info_for_gprs_rsp(gtpv1_send_routeing_info_for_gprs_rsp_t *send_routeing_info_for_gprs_rsp){

	send_routeing_info_for_gprs_rsp->header.version = 1;
	send_routeing_info_for_gprs_rsp->header.protocol_type = 1;
	send_routeing_info_for_gprs_rsp->header.spare = 0;
	send_routeing_info_for_gprs_rsp->header.extension_header = 0;
	send_routeing_info_for_gprs_rsp->header.seq_num_flag = 0;
	send_routeing_info_for_gprs_rsp->header.n_pdu_flag = 0;

	send_routeing_info_for_gprs_rsp->header.message_type = GTPV1_SEND_ROUTEING_INFO_FOR_GPRS_RSP;
	send_routeing_info_for_gprs_rsp->header.message_len = 31 ;
	send_routeing_info_for_gprs_rsp->header.teid = 0x372f0000;
	send_routeing_info_for_gprs_rsp->header.seq = 0x00fe;
	send_routeing_info_for_gprs_rsp->header.n_pdu_number = 4;
	send_routeing_info_for_gprs_rsp->header.next_extension_header_type = 0;

	send_routeing_info_for_gprs_rsp->cause.header.type = GTPV1_IE_CAUSE;
	send_routeing_info_for_gprs_rsp->cause.cause_value = 128;

	send_routeing_info_for_gprs_rsp->imsi.header.type = GTPV1_IE_IMSI;
	send_routeing_info_for_gprs_rsp->imsi.imsi_number_digits = 272031000000000;

	send_routeing_info_for_gprs_rsp->map_cause.header.type = GTPV1_IE_MAP_CAUSE;
	send_routeing_info_for_gprs_rsp->map_cause.map_cause_value = 1;

	send_routeing_info_for_gprs_rsp->ms_not_rechable_reason.header.type = GTPV1_IE_MS_NOT_RECHABLE_REASON;
	send_routeing_info_for_gprs_rsp->ms_not_rechable_reason.reason_for_absence = 2;

	send_routeing_info_for_gprs_rsp->gsn_addr.header.type = GTPV1_IE_GSN_ADDR;
	send_routeing_info_for_gprs_rsp->gsn_addr.header.length = 4;
	send_routeing_info_for_gprs_rsp->gsn_addr.gsn_address.ipv4 = 3232235564;

	send_routeing_info_for_gprs_rsp->private_extension.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	send_routeing_info_for_gprs_rsp->private_extension.header.length = 6;
	send_routeing_info_for_gprs_rsp->private_extension.extension_identifier = 12;
	strncpy((char *)&send_routeing_info_for_gprs_rsp->private_extension.extension_value, "2021", 4);

	return;
}

void fill_gtpv1_failure_report_req(gtpv1_failure_report_req_t *failure_report_req) {

	failure_report_req->header.version = 1;
	failure_report_req->header.protocol_type = 1;
	failure_report_req->header.spare = 0;
	failure_report_req->header.extension_header = 0;
	failure_report_req->header.seq_num_flag = 0;
	failure_report_req->header.n_pdu_flag = 0;

	failure_report_req->header.message_type = GTPV1_FAILURE_REPORT_REQ;
	failure_report_req->header.message_len = 18;
	failure_report_req->header.teid = 0x372f0000;
	failure_report_req->header.seq = 0x00fe;
	failure_report_req->header.n_pdu_number = 4;
	failure_report_req->header.next_extension_header_type = 0;

	failure_report_req->imsi.header.type = GTPV1_IE_IMSI;
	failure_report_req->imsi.imsi_number_digits = 272031000000000;

	failure_report_req->private_extension.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	failure_report_req->private_extension.header.length = 6;
	failure_report_req->private_extension.extension_identifier = 12;
	strncpy((char *)&failure_report_req->private_extension.extension_value, "2021", 4);

	return;
}

void fill_gtpv1_failure_report_rsp(gtpv1_failure_report_rsp_t *failure_report_rsp){

	failure_report_rsp->header.version = 1;
	failure_report_rsp->header.protocol_type = 1;
	failure_report_rsp->header.spare = 0;
	failure_report_rsp->header.extension_header = 0;
	failure_report_rsp->header.seq_num_flag = 0;
	failure_report_rsp->header.n_pdu_flag = 0;

	failure_report_rsp->header.message_type = GTPV1_FAILURE_REPORT_RSP;
	failure_report_rsp->header.message_len = 13;
	failure_report_rsp->header.teid = 0x372f0000;
	failure_report_rsp->header.seq = 0x00fe;
	failure_report_rsp->header.n_pdu_number = 4;
	failure_report_rsp->header.next_extension_header_type = 0;

	failure_report_rsp->cause.header.type = GTPV1_IE_CAUSE;
	failure_report_rsp->cause.cause_value = 128;

	failure_report_rsp->map_cause.header.type = GTPV1_IE_MAP_CAUSE;
	failure_report_rsp->map_cause.map_cause_value = 1;

	failure_report_rsp->private_extension.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	failure_report_rsp->private_extension.header.length = 6;
	failure_report_rsp->private_extension.extension_identifier = 12;
	strncpy((char *)&failure_report_rsp->private_extension.extension_value, "2021", 4);

	return;
}

void fill_gtpv1_note_ms_gprs_present_req(gtpv1_note_ms_gprs_present_req_t *note_ms_gprs_present_req) {

	note_ms_gprs_present_req->header.version = 1;
	note_ms_gprs_present_req->header.protocol_type = 1;
	note_ms_gprs_present_req->header.spare = 0;
	note_ms_gprs_present_req->header.extension_header = 0;
	note_ms_gprs_present_req->header.seq_num_flag = 0;
	note_ms_gprs_present_req->header.n_pdu_flag = 0;

	note_ms_gprs_present_req->header.message_type = GTPV1_NOTE_MS_GPRS_PRESENT_REQ;
	note_ms_gprs_present_req->header.message_len = 25;
	note_ms_gprs_present_req->header.teid = 0x372f0000;
	note_ms_gprs_present_req->header.seq = 0x00fe;
	note_ms_gprs_present_req->header.n_pdu_number = 4;
	note_ms_gprs_present_req->header.next_extension_header_type = 0;

	note_ms_gprs_present_req->imsi.header.type = GTPV1_IE_IMSI;
	note_ms_gprs_present_req->imsi.imsi_number_digits = 272031000000000;

	note_ms_gprs_present_req->gsn_addr.header.type = GTPV1_IE_GSN_ADDR;
	note_ms_gprs_present_req->gsn_addr.header.length = 4;
	note_ms_gprs_present_req->gsn_addr.gsn_address.ipv4 = 3232235564;

	note_ms_gprs_present_req->private_extension.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	note_ms_gprs_present_req->private_extension.header.length = 6;
	note_ms_gprs_present_req->private_extension.extension_identifier = 12;
	strncpy((char *)&note_ms_gprs_present_req->private_extension.extension_value, "2021", 4);

	return;
}

void fill_gtpv1_note_ms_gprs_present_rsp(gtpv1_note_ms_gprs_present_rsp_t *note_ms_gprs_present_rsp){

	note_ms_gprs_present_rsp->header.version = 1;
	note_ms_gprs_present_rsp->header.protocol_type = 1;
	note_ms_gprs_present_rsp->header.spare = 0;
	note_ms_gprs_present_rsp->header.extension_header = 0;
	note_ms_gprs_present_rsp->header.seq_num_flag = 0;
	note_ms_gprs_present_rsp->header.n_pdu_flag = 0;

	note_ms_gprs_present_rsp->header.message_type = GTPV1_NOTE_MS_GPRS_PRESENT_RSP;
	note_ms_gprs_present_rsp->header.message_len = 11;
	note_ms_gprs_present_rsp->header.teid = 0x372f0000;
	note_ms_gprs_present_rsp->header.seq = 0x00fe;
	note_ms_gprs_present_rsp->header.n_pdu_number = 4;
	note_ms_gprs_present_rsp->header.next_extension_header_type = 0;

	note_ms_gprs_present_rsp->cause.header.type = GTPV1_IE_CAUSE;
	note_ms_gprs_present_rsp->cause.cause_value = 128;

	note_ms_gprs_present_rsp->private_extension.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	note_ms_gprs_present_rsp->private_extension.header.length = 6;
	note_ms_gprs_present_rsp->private_extension.extension_identifier = 12;
	strncpy((char *)&note_ms_gprs_present_rsp->private_extension.extension_value, "2021", 4);

	return;
}

void fill_gtpv1_identification_req(gtpv1_identification_req_t *identification_req) {

	identification_req->header.version = 1;
	identification_req->header.protocol_type = 1;
	identification_req->header.spare = 0;
	identification_req->header.extension_header = 0;
	identification_req->header.seq_num_flag = 0;
	identification_req->header.n_pdu_flag = 0;

	identification_req->header.message_type = GTPV1_IDENTIFICATION_REQ;
	identification_req->header.message_len = 36;
	identification_req->header.teid = 0x372f0000;
	identification_req->header.seq = 0x00fe;
	identification_req->header.n_pdu_number = 4;
	identification_req->header.next_extension_header_type = 0;

	identification_req->routing_area_identity.header.type = GTPV1_IE_ROUTEING_AREA_IDENTITY;
	identification_req->routing_area_identity.rai_value.mcc_digit_2 = 0x0;
	identification_req->routing_area_identity.rai_value.mcc_digit_1 = 0x4;
	identification_req->routing_area_identity.rai_value.mnc_digit_3 = 0x8;
	identification_req->routing_area_identity.rai_value.mcc_digit_3 = 0x4;
	identification_req->routing_area_identity.rai_value.mnc_digit_2 = 0x7;
	identification_req->routing_area_identity.rai_value.mnc_digit_1 = 0x0;
	identification_req->routing_area_identity.rai_value.lac = 0x14;
	identification_req->routing_area_identity.rai_value.rac = 0x14;

	identification_req->packet_tmsi.header.type = GTPV1_IE_PACKET_TMSI;
	identification_req->packet_tmsi.p_tmsi = 1;

	identification_req->p_tmsi_signature.header.type = GTPV1_IE_P_TMSI_SIGNATURE;
	identification_req->p_tmsi_signature.p_tmsi_signature = 1;

	identification_req->sgsn_addr_control_plane.header.type = GTPV1_IE_GSN_ADDR;
	identification_req->sgsn_addr_control_plane.header.length = 4;
	identification_req->sgsn_addr_control_plane.gsn_address.ipv4 = 3232235564;
	
	identification_req->hop_counter.header.type = GTPV1_IE_HOP_COUNTER;
	identification_req->hop_counter.header.length = 1;
	identification_req->hop_counter.hop_counter = 3;

	identification_req->private_extension.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	identification_req->private_extension.header.length = 6;
	identification_req->private_extension.extension_identifier = 12;
	strncpy((char *)&identification_req->private_extension.extension_value, "2021", 4);
	
	return ;
}

void fill_gtpv1_identification_rsp(gtpv1_identification_rsp_t *identification_rsp){

	identification_rsp->header.version = 1;
	identification_rsp->header.protocol_type = 1;
	identification_rsp->header.spare = 0;
	identification_rsp->header.extension_header = 0;
	identification_rsp->header.seq_num_flag = 0;
	identification_rsp->header.n_pdu_flag = 0;

	identification_rsp->header.message_type = GTPV1_IDENTIFICATION_RSP;
	identification_rsp->header.message_len = 106;
	identification_rsp->header.teid = 0x372f0000;
	identification_rsp->header.seq = 0x00fe;
	identification_rsp->header.n_pdu_number = 4;
	identification_rsp->header.next_extension_header_type = 0;

	identification_rsp->cause.header.type = GTPV1_IE_CAUSE;
	identification_rsp->cause.cause_value = 128;

	identification_rsp->imsi.header.type = GTPV1_IE_IMSI;
	identification_rsp->imsi.imsi_number_digits = 272031000000000;

	identification_rsp->auth_triplet.header.type = GTPV1_IE_AUTH_TRIPLET;
	identification_rsp->auth_triplet.header.length = 28;
	strncpy((char *)&identification_rsp->auth_triplet.auth_triplet_value.rand,"1111111111111111",16);	
	identification_rsp->auth_triplet.auth_triplet_value.sres = 2;
	identification_rsp->auth_triplet.auth_triplet_value.kc = 2;

	identification_rsp->auth_quintuplet.header.type = GTPV1_IE_AUTH_QUINTUPLET;
	identification_rsp->auth_quintuplet.header.length = 52;
	strncpy((char *)&identification_rsp->auth_quintuplet.auth_quintuplet_value.rand,"1111111111111111",16);
	identification_rsp->auth_quintuplet.auth_quintuplet_value.xres_length = 1;
	strncpy((char *)&identification_rsp->auth_quintuplet.auth_quintuplet_value.xres,"1",1);
	strncpy((char *)&identification_rsp->auth_quintuplet.auth_quintuplet_value.ck,"1111111111111111",16);
	strncpy((char *)&identification_rsp->auth_quintuplet.auth_quintuplet_value.ik,"1111111111111111",16);
	identification_rsp->auth_quintuplet.auth_quintuplet_value.autn_length = 1;
	strncpy((char *)&identification_rsp->auth_quintuplet.auth_quintuplet_value.autn,"1",1);

	identification_rsp->ue_usage_type.header.type = GTPV1_IE_UE_USAGE_TYPE;
	identification_rsp->ue_usage_type.header.length = 4;
	identification_rsp->ue_usage_type.ue_usage_type_value = 15;

	identification_rsp->iov_updates_counter.header.type = GTPV1_IE_IOV_UPDATES_COUNTER;
	identification_rsp->iov_updates_counter.header.length = 1;
	identification_rsp->iov_updates_counter.iov_updates_counter = 10;

	return;
}

void fill_gtpv1_sgsn_ctxt_req(gtpv1_sgsn_ctxt_req_t *sgsn_ctxt_req) {

	sgsn_ctxt_req->header.version = 1;
	sgsn_ctxt_req->header.protocol_type = 1;
	sgsn_ctxt_req->header.spare = 0;
	sgsn_ctxt_req->header.extension_header = 0;
	sgsn_ctxt_req->header.seq_num_flag = 0;
	sgsn_ctxt_req->header.n_pdu_flag = 0;
	sgsn_ctxt_req->header.message_type = GTPV1_SGSN_CONTEXT_REQ;
	sgsn_ctxt_req->header.message_len = 81;
	sgsn_ctxt_req->header.teid = 0x372f0000;
	sgsn_ctxt_req->header.seq = 0x00fe;
	sgsn_ctxt_req->header.n_pdu_number = 4;
	sgsn_ctxt_req->header.next_extension_header_type = 0;

	sgsn_ctxt_req->imsi.header.type = GTPV1_IE_IMSI;
	sgsn_ctxt_req->imsi.imsi_number_digits = 272031000000000;

	sgsn_ctxt_req->routing_area_identity.header.type = GTPV1_IE_ROUTEING_AREA_IDENTITY;
	sgsn_ctxt_req->routing_area_identity.rai_value.mcc_digit_2 = 0x0;
	sgsn_ctxt_req->routing_area_identity.rai_value.mcc_digit_1 = 0x4;
	sgsn_ctxt_req->routing_area_identity.rai_value.mnc_digit_3 = 0x8;
	sgsn_ctxt_req->routing_area_identity.rai_value.mcc_digit_3 = 0x4;
	sgsn_ctxt_req->routing_area_identity.rai_value.mnc_digit_2 = 0x7;
	sgsn_ctxt_req->routing_area_identity.rai_value.mnc_digit_1 = 0x0;
	sgsn_ctxt_req->routing_area_identity.rai_value.lac = 0x14;
	sgsn_ctxt_req->routing_area_identity.rai_value.rac = 0x14;

	sgsn_ctxt_req->temporary_logical_link_identifier.header.type = GTPV1_IE_TEMPORARY_LOGICAL_LINK_IDENTIFIER;
	sgsn_ctxt_req->temporary_logical_link_identifier.tlli = 1;

	sgsn_ctxt_req->packet_tmsi.header.type = GTPV1_IE_PACKET_TMSI;
	sgsn_ctxt_req->packet_tmsi.p_tmsi = 1;

	sgsn_ctxt_req->p_tmsi_signature.header.type = GTPV1_IE_P_TMSI_SIGNATURE;
	sgsn_ctxt_req->p_tmsi_signature.p_tmsi_signature = 1;

	sgsn_ctxt_req->ms_validated.header.type = GTPV1_IE_MS_VALIDATED;
	sgsn_ctxt_req->ms_validated.spare = 0;
	sgsn_ctxt_req->ms_validated.ms_validated = 1;

	sgsn_ctxt_req->tunn_endpt_idnt_control_plane.header.type = GTPV1_IE_TEID_CONTROL_PLANE;
	sgsn_ctxt_req->tunn_endpt_idnt_control_plane.teid = 0x0fffeee;

	sgsn_ctxt_req->sgsn_address_for_control_plane.header.type = GTPV1_IE_GSN_ADDR;
	sgsn_ctxt_req->sgsn_address_for_control_plane.header.length = 4;
	sgsn_ctxt_req->sgsn_address_for_control_plane.gsn_address.ipv4 = 3232235564;

	sgsn_ctxt_req->alternative_sgsn_address_for_control_plane.header.type = GTPV1_IE_GSN_ADDR;
	sgsn_ctxt_req->alternative_sgsn_address_for_control_plane.header.length = 16;
	char *str6 = "2001:db80:3333:4444:5555:6666:7777:8888";
	inet_pton(AF_INET6, str6, sgsn_ctxt_req->alternative_sgsn_address_for_control_plane.gsn_address.ipv6);

	sgsn_ctxt_req->sgsn_number.header.type = GTPV1_IE_SGSN_NUMBER;
	sgsn_ctxt_req->sgsn_number.header.length = 2;
	strncpy((char *)&sgsn_ctxt_req->sgsn_number.sgsn_number,"11",2);

	sgsn_ctxt_req->rat_type.header.type = GTPV1_IE_RAT_TYPE;
	sgsn_ctxt_req->rat_type.header.length = 1;
	sgsn_ctxt_req->rat_type.rat_type = 2;
	
	sgsn_ctxt_req->private_extension.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	sgsn_ctxt_req->private_extension.header.length = 6;
	sgsn_ctxt_req->private_extension.extension_identifier = 12;
	strncpy((char *)&sgsn_ctxt_req->private_extension.extension_value, "2021", 4);

	return;
}

void fill_gtpv1_ms_network_capability_value(gtpv1_ms_network_capability_value_t *ms_network_capability_value) {
	ms_network_capability_value->GEA_1 = 0;
	ms_network_capability_value->sm_capabilities_via_dedicated_channels = 0;
	ms_network_capability_value->sm_capabilities_via_gprs_channels = 0;
	ms_network_capability_value->ucs2_support = 0;
	ms_network_capability_value->ss_screening_indicator = 0;
	ms_network_capability_value->solsa_capability = 0;
	ms_network_capability_value->revision_level_indicator = 0;
	ms_network_capability_value->pfc_feature_mode = 0;
	ms_network_capability_value->GEA_2 = 0;
	ms_network_capability_value->GEA_3 = 0;
	ms_network_capability_value->GEA_4 = 0;
	ms_network_capability_value->GEA_5 = 0;
	ms_network_capability_value->GEA_6 = 0;
	ms_network_capability_value->GEA_7 = 0;
	ms_network_capability_value->lcs_va_capability = 0;
	ms_network_capability_value->ps_ge_ut_iu_mode_capability = 0;
	ms_network_capability_value->ps_ge_ut_s1_mode_capability = 0;
	ms_network_capability_value->emm_combined_procedure_capability = 0;
	ms_network_capability_value->isr_support = 0;
	ms_network_capability_value->srvcc_to_ge_ut_capability = 0;
	ms_network_capability_value->epc_capability = 0;
	ms_network_capability_value->nf_capability = 0;
	ms_network_capability_value->ge_network_sharing_capability = 0;
	ms_network_capability_value->user_plane_integrity_protection_support = 0;
	ms_network_capability_value->GIA_4 = 0;
	ms_network_capability_value->GIA_5 = 0;
	ms_network_capability_value->GIA_6 = 0;
	ms_network_capability_value->GIA_7 = 0;
	ms_network_capability_value->ePCO_ie_indicator = 0;
	ms_network_capability_value->restriction_on_use_of_enhanced_coverage_capability = 0;
	ms_network_capability_value->dual_connectivity_of_e_ut_with_nr_capability = 0;
	return;
}

void fill_gtpv1_sgsn_ctxt_rsp(gtpv1_sgsn_ctxt_rsp_t *sgsn_ctxt_rsp){

	sgsn_ctxt_rsp->header.version = 1;
	sgsn_ctxt_rsp->header.protocol_type = 1;
	sgsn_ctxt_rsp->header.spare = 0;
	sgsn_ctxt_rsp->header.extension_header = 0;
	sgsn_ctxt_rsp->header.seq_num_flag = 0;
	sgsn_ctxt_rsp->header.n_pdu_flag = 0;

	sgsn_ctxt_rsp->header.message_type = GTPV1_SGSN_CONTEXT_RSP;
	sgsn_ctxt_rsp->header.message_len = 410;
	sgsn_ctxt_rsp->header.teid = 0x372f0000;
	sgsn_ctxt_rsp->header.seq = 0x00fe;
	sgsn_ctxt_rsp->header.n_pdu_number = 4;
	sgsn_ctxt_rsp->header.next_extension_header_type = 0;

	sgsn_ctxt_rsp->cause.header.type = GTPV1_IE_CAUSE;
	sgsn_ctxt_rsp->cause.cause_value = 128;

	sgsn_ctxt_rsp->imsi.header.type = GTPV1_IE_IMSI;
	sgsn_ctxt_rsp->imsi.imsi_number_digits = 272031000000000;

	sgsn_ctxt_rsp->tunn_endpt_idnt_control_plane.header.type = GTPV1_IE_TEID_CONTROL_PLANE;
	sgsn_ctxt_rsp->tunn_endpt_idnt_control_plane.teid = 0x0fffeee;

	sgsn_ctxt_rsp->rab_context.header.type = GTPV1_IE_RAB_CONTEXT;
	sgsn_ctxt_rsp->rab_context.spare = 0;
	sgsn_ctxt_rsp->rab_context.nsapi = 1;
	sgsn_ctxt_rsp->rab_context.dl_gtp_u_sequence_number = 1;
	sgsn_ctxt_rsp->rab_context.ul_gtp_u_sequence_number = 2;
	sgsn_ctxt_rsp->rab_context.dl_pdcp_sequence_number = 1;
	sgsn_ctxt_rsp->rab_context.ul_pdcp_sequence_number = 2;

	sgsn_ctxt_rsp->radio_priority_sms.header.type = GTPV1_IE_RADIO_PRIORITY_SMS;
	sgsn_ctxt_rsp->radio_priority_sms.spare = 0;
	sgsn_ctxt_rsp->radio_priority_sms.radio_priority_sms = 2;

	sgsn_ctxt_rsp->radio_priority.header.type = GTPV1_IE_RADIO_PRIORITY;
	sgsn_ctxt_rsp->radio_priority.nsapi = 1;
	sgsn_ctxt_rsp->radio_priority.spare = 0;
	sgsn_ctxt_rsp->radio_priority.radio_priority = 2;

	sgsn_ctxt_rsp->packet_flow_id.header.type = GTPV1_IE_PACKET_FLOW_ID;
	sgsn_ctxt_rsp->packet_flow_id.spare = 0;
	sgsn_ctxt_rsp->packet_flow_id.nsapi = 1;
	sgsn_ctxt_rsp->packet_flow_id.packet_flow_id = 4;

	sgsn_ctxt_rsp->chrgng_char.header.type = GTPV1_IE_CHRGNG_CHAR;
	sgsn_ctxt_rsp->chrgng_char.chrgng_char_val = 1;

	sgsn_ctxt_rsp->radio_priority_lcs.header.type = GTPV1_IE_RADIO_PRIORITY_LCS;
	sgsn_ctxt_rsp->radio_priority_lcs.header.length = 1;
	sgsn_ctxt_rsp->radio_priority_lcs.spare = 0;
	sgsn_ctxt_rsp->radio_priority_lcs.radio_priority_lcs = 1;

	sgsn_ctxt_rsp->mm_context.header.type = GTPV1_IE_MM_CONTEXT;
	sgsn_ctxt_rsp->mm_context.header.length = 47;
	sgsn_ctxt_rsp->mm_context.mm_context.gsm_keys_and_triplet.spare = 15;
	sgsn_ctxt_rsp->mm_context.mm_context.gsm_keys_and_triplet.cksn = 1;
	sgsn_ctxt_rsp->mm_context.security_mode = 1;
	sgsn_ctxt_rsp->mm_context.mm_context.gsm_keys_and_triplet.no_of_vectors = 1;
	sgsn_ctxt_rsp->mm_context.mm_context.gsm_keys_and_triplet.used_cipher = 1;
	sgsn_ctxt_rsp->mm_context.mm_context.gsm_keys_and_triplet.kc = 1;
	strncpy((char *)&sgsn_ctxt_rsp->mm_context.mm_context.gsm_keys_and_triplet.triplet[0].rand,"1111111111111111",16);
	sgsn_ctxt_rsp->mm_context.mm_context.gsm_keys_and_triplet.triplet[0].sres = 2;
	sgsn_ctxt_rsp->mm_context.mm_context.gsm_keys_and_triplet.triplet[0].kc = 2;

	sgsn_ctxt_rsp->mm_context.drx_parameter.split_pg_cycle_code = 1;
	sgsn_ctxt_rsp->mm_context.drx_parameter.cycle_length = 1;
	sgsn_ctxt_rsp->mm_context.drx_parameter.ccch = 1;
	sgsn_ctxt_rsp->mm_context.drx_parameter.timer = 1;
	sgsn_ctxt_rsp->mm_context.ms_network_capability_length = 4;
	
	fill_gtpv1_ms_network_capability_value(&(sgsn_ctxt_rsp->mm_context.ms_network_capability));

	sgsn_ctxt_rsp->mm_context.container_length = 0;

	sgsn_ctxt_rsp->pdp_context.header.type = GTPV1_IE_PDP_CONTEXT;
	sgsn_ctxt_rsp->pdp_context.header.length = 116;
	sgsn_ctxt_rsp->pdp_context.ea = 0;
	sgsn_ctxt_rsp->pdp_context.vaa = 1;
	sgsn_ctxt_rsp->pdp_context.asi = 1;
	sgsn_ctxt_rsp->pdp_context.order = 0;
	sgsn_ctxt_rsp->pdp_context.nsapi = 5;
	sgsn_ctxt_rsp->pdp_context.spare = 0;
	sgsn_ctxt_rsp->pdp_context.sapi = 1;
	sgsn_ctxt_rsp->pdp_context.qos_sub_length = 21;
	sgsn_ctxt_rsp->pdp_context.qos_sub.allocation_retention_priority = 2;
	sgsn_ctxt_rsp->pdp_context.qos_sub.spare1 = 0;
	sgsn_ctxt_rsp->pdp_context.qos_sub.delay_class = 2;
	sgsn_ctxt_rsp->pdp_context.qos_sub.reliablity_class = 2;
	sgsn_ctxt_rsp->pdp_context.qos_sub.peak_throughput = 3;
	sgsn_ctxt_rsp->pdp_context.qos_sub.spare2 = 0;
	sgsn_ctxt_rsp->pdp_context.qos_sub.precedence_class = 1;
	sgsn_ctxt_rsp->pdp_context.qos_sub.spare3 = 0;
	sgsn_ctxt_rsp->pdp_context.qos_sub.mean_throughput = 4;
	sgsn_ctxt_rsp->pdp_context.qos_sub.traffic_class = 1;
	sgsn_ctxt_rsp->pdp_context.qos_sub.delivery_order = 1;
	sgsn_ctxt_rsp->pdp_context.qos_sub.delivery_erroneous_sdu = 2;
	sgsn_ctxt_rsp->pdp_context.qos_sub.max_sdu_size = 3;
	sgsn_ctxt_rsp->pdp_context.qos_sub.max_bitrate_uplink = 123;
	sgsn_ctxt_rsp->pdp_context.qos_sub.max_bitrate_downlink = 234;
	sgsn_ctxt_rsp->pdp_context.qos_sub.residual_ber = 1;
	sgsn_ctxt_rsp->pdp_context.qos_sub.sdu_error_ratio = 1; 
	sgsn_ctxt_rsp->pdp_context.qos_sub.transfer_delay = 1; 
	sgsn_ctxt_rsp->pdp_context.qos_sub.traffic_handling_priority = 2;
	sgsn_ctxt_rsp->pdp_context.qos_sub.guaranteed_bitrate_uplink = 122;
	sgsn_ctxt_rsp->pdp_context.qos_sub.guaranteed_bitrate_downlink = 222;
	sgsn_ctxt_rsp->pdp_context.qos_sub.spare4 = 0; 
	sgsn_ctxt_rsp->pdp_context.qos_sub.signalling_indication = 1;
	sgsn_ctxt_rsp->pdp_context.qos_sub.source_statistics_descriptor = 1;
	sgsn_ctxt_rsp->pdp_context.qos_sub.max_bitrate_downlink_ext1 = 22;
	sgsn_ctxt_rsp->pdp_context.qos_sub.guaranteed_bitrate_downlink_ext1 = 11;
	sgsn_ctxt_rsp->pdp_context.qos_sub.max_bitrate_uplink_ext1 = 33;
	sgsn_ctxt_rsp->pdp_context.qos_sub.guaranteed_bitrate_uplink_ext1 = 22;
	sgsn_ctxt_rsp->pdp_context.qos_sub.max_bitrate_downlink_ext2 = 44;
	sgsn_ctxt_rsp->pdp_context.qos_sub.guaranteed_bitrate_downlink_ext2 = 33;
	sgsn_ctxt_rsp->pdp_context.qos_sub.max_bitrate_uplink_ext2 = 34;
	sgsn_ctxt_rsp->pdp_context.qos_sub.guaranteed_bitrate_uplink_ext2 = 23;
	sgsn_ctxt_rsp->pdp_context.qos_req_length = 21;
	sgsn_ctxt_rsp->pdp_context.qos_req.allocation_retention_priority = 2;
	sgsn_ctxt_rsp->pdp_context.qos_req.spare1 = 0;
	sgsn_ctxt_rsp->pdp_context.qos_req.delay_class = 2;
	sgsn_ctxt_rsp->pdp_context.qos_req.reliablity_class = 2;
	sgsn_ctxt_rsp->pdp_context.qos_req.peak_throughput = 3;
	sgsn_ctxt_rsp->pdp_context.qos_req.spare2 = 0;
	sgsn_ctxt_rsp->pdp_context.qos_req.precedence_class = 1;
	sgsn_ctxt_rsp->pdp_context.qos_req.spare3 = 0;
	sgsn_ctxt_rsp->pdp_context.qos_req.mean_throughput = 4;
	sgsn_ctxt_rsp->pdp_context.qos_req.traffic_class = 1;
	sgsn_ctxt_rsp->pdp_context.qos_req.delivery_order = 1;
	sgsn_ctxt_rsp->pdp_context.qos_req.delivery_erroneous_sdu = 2;
	sgsn_ctxt_rsp->pdp_context.qos_req.max_sdu_size = 3;
	sgsn_ctxt_rsp->pdp_context.qos_req.max_bitrate_uplink = 123;
	sgsn_ctxt_rsp->pdp_context.qos_req.max_bitrate_downlink = 234;
	sgsn_ctxt_rsp->pdp_context.qos_req.residual_ber = 1;
	sgsn_ctxt_rsp->pdp_context.qos_req.sdu_error_ratio = 1;
	sgsn_ctxt_rsp->pdp_context.qos_req.transfer_delay = 1;
	sgsn_ctxt_rsp->pdp_context.qos_req.traffic_handling_priority = 2;
	sgsn_ctxt_rsp->pdp_context.qos_req.guaranteed_bitrate_uplink = 122;
	sgsn_ctxt_rsp->pdp_context.qos_req.guaranteed_bitrate_downlink = 222;
	sgsn_ctxt_rsp->pdp_context.qos_req.spare4 = 0;
	sgsn_ctxt_rsp->pdp_context.qos_req.signalling_indication = 1;
	sgsn_ctxt_rsp->pdp_context.qos_req.source_statistics_descriptor = 1;
	sgsn_ctxt_rsp->pdp_context.qos_req.max_bitrate_downlink_ext1 = 22;
	sgsn_ctxt_rsp->pdp_context.qos_req.guaranteed_bitrate_downlink_ext1 = 11;
	sgsn_ctxt_rsp->pdp_context.qos_req.max_bitrate_uplink_ext1 = 33;
	sgsn_ctxt_rsp->pdp_context.qos_req.guaranteed_bitrate_uplink_ext1 = 22;
	sgsn_ctxt_rsp->pdp_context.qos_req.max_bitrate_downlink_ext2 = 44;
	sgsn_ctxt_rsp->pdp_context.qos_req.guaranteed_bitrate_downlink_ext2 = 33;
	sgsn_ctxt_rsp->pdp_context.qos_req.max_bitrate_uplink_ext2 = 34;
	sgsn_ctxt_rsp->pdp_context.qos_req.guaranteed_bitrate_uplink_ext2 = 23;
	sgsn_ctxt_rsp->pdp_context.qos_neg_length = 21;
	sgsn_ctxt_rsp->pdp_context.qos_neg.allocation_retention_priority = 2;
	sgsn_ctxt_rsp->pdp_context.qos_neg.spare1 = 0;
	sgsn_ctxt_rsp->pdp_context.qos_neg.delay_class = 2;
	sgsn_ctxt_rsp->pdp_context.qos_neg.reliablity_class = 2;
	sgsn_ctxt_rsp->pdp_context.qos_neg.peak_throughput = 3;
	sgsn_ctxt_rsp->pdp_context.qos_neg.spare2 = 0;
	sgsn_ctxt_rsp->pdp_context.qos_neg.precedence_class = 1;
	sgsn_ctxt_rsp->pdp_context.qos_neg.spare3 = 0;
	sgsn_ctxt_rsp->pdp_context.qos_neg.mean_throughput = 4;
	sgsn_ctxt_rsp->pdp_context.qos_neg.traffic_class = 1;
	sgsn_ctxt_rsp->pdp_context.qos_neg.delivery_order = 1;
	sgsn_ctxt_rsp->pdp_context.qos_neg.delivery_erroneous_sdu = 2;
	sgsn_ctxt_rsp->pdp_context.qos_neg.max_sdu_size = 3;
	sgsn_ctxt_rsp->pdp_context.qos_neg.max_bitrate_uplink = 123;
	sgsn_ctxt_rsp->pdp_context.qos_neg.max_bitrate_downlink = 234;
	sgsn_ctxt_rsp->pdp_context.qos_neg.residual_ber = 1;
	sgsn_ctxt_rsp->pdp_context.qos_neg.sdu_error_ratio = 1;
	sgsn_ctxt_rsp->pdp_context.qos_neg.transfer_delay = 1;
	sgsn_ctxt_rsp->pdp_context.qos_neg.traffic_handling_priority = 2;
	sgsn_ctxt_rsp->pdp_context.qos_neg.guaranteed_bitrate_uplink = 122;
	sgsn_ctxt_rsp->pdp_context.qos_neg.guaranteed_bitrate_downlink = 222;
	sgsn_ctxt_rsp->pdp_context.qos_neg.spare4 = 0;
	sgsn_ctxt_rsp->pdp_context.qos_neg.signalling_indication = 1;
	sgsn_ctxt_rsp->pdp_context.qos_neg.source_statistics_descriptor = 1;
	sgsn_ctxt_rsp->pdp_context.qos_neg.max_bitrate_downlink_ext1 = 22;
	sgsn_ctxt_rsp->pdp_context.qos_neg.guaranteed_bitrate_downlink_ext1 = 11;
	sgsn_ctxt_rsp->pdp_context.qos_neg.max_bitrate_uplink_ext1 = 33;
	sgsn_ctxt_rsp->pdp_context.qos_neg.guaranteed_bitrate_uplink_ext1 = 22;
	sgsn_ctxt_rsp->pdp_context.qos_neg.max_bitrate_downlink_ext2 = 44;
	sgsn_ctxt_rsp->pdp_context.qos_neg.guaranteed_bitrate_downlink_ext2 = 33;
	sgsn_ctxt_rsp->pdp_context.qos_neg.max_bitrate_uplink_ext2 = 34;
	sgsn_ctxt_rsp->pdp_context.qos_neg.guaranteed_bitrate_uplink_ext2 = 23;
	sgsn_ctxt_rsp->pdp_context.sequence_number_down = 1;
	sgsn_ctxt_rsp->pdp_context.sequence_number_up = 2;
	sgsn_ctxt_rsp->pdp_context.send_npdu_number = 255;
	sgsn_ctxt_rsp->pdp_context.rcv_npdu_number = 255;
	sgsn_ctxt_rsp->pdp_context.uplink_teid_cp = 0x372f0000;
	sgsn_ctxt_rsp->pdp_context.uplink_teid_data1 = 0x37300000;
	sgsn_ctxt_rsp->pdp_context.pdp_ctxt_identifier = 0;
	sgsn_ctxt_rsp->pdp_context.spare2 = 15;
	sgsn_ctxt_rsp->pdp_context.pdp_type_org = 1;
	sgsn_ctxt_rsp->pdp_context.pdp_type_number1 = 0x21;
	sgsn_ctxt_rsp->pdp_context.pdp_address_length1 = 4;
	sgsn_ctxt_rsp->pdp_context.pdp_address1.ipv4 = 355240599;
	sgsn_ctxt_rsp->pdp_context.ggsn_addr_cp_length = 4;
	sgsn_ctxt_rsp->pdp_context.ggsn_addr_cp.ipv4 = 355240589;
	sgsn_ctxt_rsp->pdp_context.ggsn_addr_ut_length = 4;
	sgsn_ctxt_rsp->pdp_context.ggsn_addr_ut.ipv4 = 355240599;
	sgsn_ctxt_rsp->pdp_context.apn_length = 13;
	strncpy((char *)&sgsn_ctxt_rsp->pdp_context.apn,"nextphones.co",13);
	sgsn_ctxt_rsp->pdp_context.spare3 = 0;
	sgsn_ctxt_rsp->pdp_context.transaction_identifier1 = 10;
	sgsn_ctxt_rsp->pdp_context.transaction_identifier2 = 55;

	sgsn_ctxt_rsp->gsn_addr_1.header.type = GTPV1_IE_GSN_ADDR;
	sgsn_ctxt_rsp->gsn_addr_1.header.length = 4;
	sgsn_ctxt_rsp->gsn_addr_1.gsn_address.ipv4 = 3232235564;	

	sgsn_ctxt_rsp->gsn_addr_2.header.type = GTPV1_IE_GSN_ADDR;
	sgsn_ctxt_rsp->gsn_addr_2.header.length = 16;
	char *str6 = "2001:db80:3333:4444:5555:6666:7777:8888";
	inet_pton(AF_INET6, str6, sgsn_ctxt_rsp->gsn_addr_2.gsn_address.ipv6);
	
	sgsn_ctxt_rsp->gsn_addr_3.header.type = GTPV1_IE_GSN_ADDR;
	sgsn_ctxt_rsp->gsn_addr_3.header.length = 16;
	char *str7 = "2001:db80:3333:4444:5555:6666:7777:8888";
	inet_pton(AF_INET6, str7, sgsn_ctxt_rsp->gsn_addr_3.gsn_address.ipv6);

	sgsn_ctxt_rsp->pdp_context_prioritization.header.type = GTPV1_IE_PDP_CONTEXT_PRIORITIZATION;

	sgsn_ctxt_rsp->mbms_ue_context.header.type = GTPV1_IE_MBMS_UE_CONTEXT;
	sgsn_ctxt_rsp->mbms_ue_context.header.length = 34;
	sgsn_ctxt_rsp->mbms_ue_context.linked_nsapi = 2;
	sgsn_ctxt_rsp->mbms_ue_context.spare1 = 0;
	sgsn_ctxt_rsp->mbms_ue_context.uplink_teid_cp = 0x372f0000;
	sgsn_ctxt_rsp->mbms_ue_context.enhanced_nsapi = 129;
	sgsn_ctxt_rsp->mbms_ue_context.spare2 = 15;
	sgsn_ctxt_rsp->mbms_ue_context.pdp_type_org = 1;
	sgsn_ctxt_rsp->mbms_ue_context.pdp_type_number = 0x21;
	sgsn_ctxt_rsp->mbms_ue_context.pdp_address_length = 4;
	sgsn_ctxt_rsp->mbms_ue_context.pdp_address.ipv4 = 355240599;
	sgsn_ctxt_rsp->mbms_ue_context.ggsn_addr_cp_length = 4;
	sgsn_ctxt_rsp->mbms_ue_context.ggsn_addr_cp.ipv4 = 355240589;
	sgsn_ctxt_rsp->mbms_ue_context.apn_length = 13;
	strncpy((char *)&sgsn_ctxt_rsp->mbms_ue_context.apn,"nextphones.co",13);
	sgsn_ctxt_rsp->mbms_ue_context.spare3 = 0;
	sgsn_ctxt_rsp->mbms_ue_context.transaction_identifier1 = 1;
	sgsn_ctxt_rsp->mbms_ue_context.transaction_identifier2 = 5;

	sgsn_ctxt_rsp->subscribed_rfsp_index.header.type = GTPV1_IE_RFSP_INDEX;
	sgsn_ctxt_rsp->subscribed_rfsp_index.header.length = 2;
	sgsn_ctxt_rsp->subscribed_rfsp_index.rfsp_index = 1;

	sgsn_ctxt_rsp->rfsp_index_in_use.header.type = GTPV1_IE_RFSP_INDEX;
	sgsn_ctxt_rsp->rfsp_index_in_use.header.length = 2;
	sgsn_ctxt_rsp->rfsp_index_in_use.rfsp_index = 1;

	sgsn_ctxt_rsp->co_located_ggsn_pgw_fqdn.header.type = GTPV1_IE_FQDN;
	sgsn_ctxt_rsp->co_located_ggsn_pgw_fqdn.header.length = 5;
	strncpy((char *)&sgsn_ctxt_rsp->co_located_ggsn_pgw_fqdn.fqdn,"gslab",5);

	sgsn_ctxt_rsp->evolved_allocation_retention_priority_II.header.type = GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_II;
	sgsn_ctxt_rsp->evolved_allocation_retention_priority_II.header.length = 2;
	sgsn_ctxt_rsp->evolved_allocation_retention_priority_II.spare = 0;
	sgsn_ctxt_rsp->evolved_allocation_retention_priority_II.nsapi = 1;
	sgsn_ctxt_rsp->evolved_allocation_retention_priority_II.spare2 = 0;
	sgsn_ctxt_rsp->evolved_allocation_retention_priority_II.pci = 1;
	sgsn_ctxt_rsp->evolved_allocation_retention_priority_II.pl = 1;
	sgsn_ctxt_rsp->evolved_allocation_retention_priority_II.spare3 = 0;
	sgsn_ctxt_rsp->evolved_allocation_retention_priority_II.pvi = 1;

	sgsn_ctxt_rsp->extended_common_flag.header.type = GTPV1_IE_EXTENDED_COMMON_FLAG;
	sgsn_ctxt_rsp->extended_common_flag.header.length = 1;
	sgsn_ctxt_rsp->extended_common_flag.uasi = 0;
	sgsn_ctxt_rsp->extended_common_flag.bdwi = 0;
	sgsn_ctxt_rsp->extended_common_flag.pcri = 1;
	sgsn_ctxt_rsp->extended_common_flag.vb = 0;
	sgsn_ctxt_rsp->extended_common_flag.retloc = 0;
	sgsn_ctxt_rsp->extended_common_flag.cpsr = 1;
	sgsn_ctxt_rsp->extended_common_flag.ccrsi = 0;
	sgsn_ctxt_rsp->extended_common_flag.unauthenticated_imsi = 1;

	sgsn_ctxt_rsp->ue_network_capability.header.type = GTPV1_IE_UE_NETWORK_CAPABILITY;
	sgsn_ctxt_rsp->ue_network_capability.header.length = 8;
	sgsn_ctxt_rsp->ue_network_capability.eea0 = 1;
	sgsn_ctxt_rsp->ue_network_capability.eea1_128 = 1;
	sgsn_ctxt_rsp->ue_network_capability.eea2_128 = 0;
	sgsn_ctxt_rsp->ue_network_capability.eea3_128 = 1;
	sgsn_ctxt_rsp->ue_network_capability.eea4 = 0;
	sgsn_ctxt_rsp->ue_network_capability.eea5 = 1;
	sgsn_ctxt_rsp->ue_network_capability.eea6 = 1;
	sgsn_ctxt_rsp->ue_network_capability.eea7 = 0;
	sgsn_ctxt_rsp->ue_network_capability.eia0 = 1;
	sgsn_ctxt_rsp->ue_network_capability.eia1_128 = 0;
	sgsn_ctxt_rsp->ue_network_capability.eia2_128 = 1;
	sgsn_ctxt_rsp->ue_network_capability.eia3_128 = 0;
	sgsn_ctxt_rsp->ue_network_capability.eia4 = 1;
	sgsn_ctxt_rsp->ue_network_capability.eia5 = 0;
	sgsn_ctxt_rsp->ue_network_capability.eia6 = 1;
	sgsn_ctxt_rsp->ue_network_capability.eia7 = 1;
	sgsn_ctxt_rsp->ue_network_capability.uea0 = 0;
	sgsn_ctxt_rsp->ue_network_capability.uea1 = 1;
	sgsn_ctxt_rsp->ue_network_capability.uea2 = 0;
	sgsn_ctxt_rsp->ue_network_capability.uea3 = 1;
	sgsn_ctxt_rsp->ue_network_capability.uea4 = 0;
	sgsn_ctxt_rsp->ue_network_capability.uea5 = 1;
	sgsn_ctxt_rsp->ue_network_capability.uea6 = 0;
	sgsn_ctxt_rsp->ue_network_capability.uea7 = 1;
	sgsn_ctxt_rsp->ue_network_capability.ucs2 = 1;
	sgsn_ctxt_rsp->ue_network_capability.uia1 = 0;
	sgsn_ctxt_rsp->ue_network_capability.uia2 = 1;
	sgsn_ctxt_rsp->ue_network_capability.uia3 = 1;
	sgsn_ctxt_rsp->ue_network_capability.uia4 = 0;
	sgsn_ctxt_rsp->ue_network_capability.uia5 = 1;
	sgsn_ctxt_rsp->ue_network_capability.uia6 = 0;
	sgsn_ctxt_rsp->ue_network_capability.uia7 = 1;
	sgsn_ctxt_rsp->ue_network_capability.prose_dd = 1;
	sgsn_ctxt_rsp->ue_network_capability.prose = 0;
	sgsn_ctxt_rsp->ue_network_capability.h245_ash = 1;
	sgsn_ctxt_rsp->ue_network_capability.acc_csfb = 1;
	sgsn_ctxt_rsp->ue_network_capability.lpp = 0;
	sgsn_ctxt_rsp->ue_network_capability.lcs = 1;
	sgsn_ctxt_rsp->ue_network_capability.srvcc1x = 1;
	sgsn_ctxt_rsp->ue_network_capability.nf = 0;
	sgsn_ctxt_rsp->ue_network_capability.epco = 1;
	sgsn_ctxt_rsp->ue_network_capability.hc_cp_ciot = 0;
	sgsn_ctxt_rsp->ue_network_capability.erw_opdn = 1;
	sgsn_ctxt_rsp->ue_network_capability.s1_udata = 1;
	sgsn_ctxt_rsp->ue_network_capability.up_ciot = 1;
	sgsn_ctxt_rsp->ue_network_capability.cp_ciot = 0;
	sgsn_ctxt_rsp->ue_network_capability.prose_relay = 1;
	sgsn_ctxt_rsp->ue_network_capability.prose_dc = 1;
	sgsn_ctxt_rsp->ue_network_capability.bearers_15 = 0;
	sgsn_ctxt_rsp->ue_network_capability.sgc = 1;
	sgsn_ctxt_rsp->ue_network_capability.n1mode = 0;
	sgsn_ctxt_rsp->ue_network_capability.dcnr = 1;
	sgsn_ctxt_rsp->ue_network_capability.cp_backoff = 0;
	sgsn_ctxt_rsp->ue_network_capability.restrict_ec = 0;
	sgsn_ctxt_rsp->ue_network_capability.v2x_pc5 = 1;
	sgsn_ctxt_rsp->ue_network_capability.multiple_drb = 0;
	sgsn_ctxt_rsp->ue_network_capability.spare1 = 0;
	sgsn_ctxt_rsp->ue_network_capability.v2xnr_pcf = 1;
	sgsn_ctxt_rsp->ue_network_capability.up_mt_edt = 0;
	sgsn_ctxt_rsp->ue_network_capability.cp_mt_edt = 0;
	sgsn_ctxt_rsp->ue_network_capability.wusa = 1;
	sgsn_ctxt_rsp->ue_network_capability.racs = 1;

	sgsn_ctxt_rsp->ue_ambr.header.type = GTPV1_IE_UE_AMBR;
	sgsn_ctxt_rsp->ue_ambr.header.length = 16;
	sgsn_ctxt_rsp->ue_ambr.subscribed_ue_ambr_for_uplink = 8;
	sgsn_ctxt_rsp->ue_ambr.subscribed_ue_ambr_for_downlink = 16;
	sgsn_ctxt_rsp->ue_ambr.authorized_ue_ambr_for_uplink = 32;
	sgsn_ctxt_rsp->ue_ambr.authorized_ue_ambr_for_downlink = 64;
	
	sgsn_ctxt_rsp->apn_ambr_with_nsapi.header.type = GTPV1_IE_APN_AMBR_WITH_NSAPI;
	sgsn_ctxt_rsp->apn_ambr_with_nsapi.header.length = 9;
	sgsn_ctxt_rsp->apn_ambr_with_nsapi.spare = 0;
	sgsn_ctxt_rsp->apn_ambr_with_nsapi.nsapi = 1;
	sgsn_ctxt_rsp->apn_ambr_with_nsapi.authorized_apn_ambr_for_uplink = 1;
	sgsn_ctxt_rsp->apn_ambr_with_nsapi.authorized_apn_ambr_for_downlink = 1;

	sgsn_ctxt_rsp->signalling_priority_indication_with_nsapi.header.type = GTPV1_IE_SIGNALLING_PRIORITY_INDICATION_WITH_NSAPI;
	sgsn_ctxt_rsp->signalling_priority_indication_with_nsapi.header.length = 2;
	sgsn_ctxt_rsp->signalling_priority_indication_with_nsapi.spare = 0;
	sgsn_ctxt_rsp->signalling_priority_indication_with_nsapi.nsapi = 1;
	sgsn_ctxt_rsp->signalling_priority_indication_with_nsapi.spare2 = 0;
	sgsn_ctxt_rsp->signalling_priority_indication_with_nsapi.lapi = 1;

	sgsn_ctxt_rsp->higher_bitrates_than_16_mbps_flag.header.type = GTPV1_IE_HIGER_BITRATES_THAN_16_MBPS_FLAG;
	sgsn_ctxt_rsp->higher_bitrates_than_16_mbps_flag.header.length = 1;
	sgsn_ctxt_rsp->higher_bitrates_than_16_mbps_flag.higher_bitrates_than_16_mbps_flag = 1;

	sgsn_ctxt_rsp->selection_mode_with_nsapi.header.type = GTPV1_IE_SELECTION_MODE_WITH_NSAPI;
	sgsn_ctxt_rsp->selection_mode_with_nsapi.header.length = 2;
	sgsn_ctxt_rsp->selection_mode_with_nsapi.spare = 0;
	sgsn_ctxt_rsp->selection_mode_with_nsapi.nsapi = 1;
	sgsn_ctxt_rsp->selection_mode_with_nsapi.spare2 = 0;
	sgsn_ctxt_rsp->selection_mode_with_nsapi.selection_mode_value = 1;

	sgsn_ctxt_rsp->local_home_network_id_with_nsapi.header.type = GTPV1_IE_LOCAL_HOME_NETWORK_ID_WITH_NSAPI;
	sgsn_ctxt_rsp->local_home_network_id_with_nsapi.header.length = 6;
	sgsn_ctxt_rsp->local_home_network_id_with_nsapi.spare = 0;
	sgsn_ctxt_rsp->local_home_network_id_with_nsapi.nsapi = 1;
	strncpy((char *)&sgsn_ctxt_rsp->local_home_network_id_with_nsapi.local_home_network_id_with_nsapi, "gslab",5);

	sgsn_ctxt_rsp->ue_usage_type.header.type = GTPV1_IE_UE_USAGE_TYPE;
	sgsn_ctxt_rsp->ue_usage_type.header.length = 4;
	sgsn_ctxt_rsp->ue_usage_type.ue_usage_type_value = 15;

	sgsn_ctxt_rsp->extended_common_flag_2.header.type = GTPV1_IE_EXTENDED_COMMON_FLAGS_II;
	sgsn_ctxt_rsp->extended_common_flag_2.header.length = 1;
	sgsn_ctxt_rsp->extended_common_flag_2.spare = 0;
	sgsn_ctxt_rsp->extended_common_flag_2.pmts_mi = 1;
	sgsn_ctxt_rsp->extended_common_flag_2.dtci = 1;
	sgsn_ctxt_rsp->extended_common_flag_2.pnsi = 1;
	
	/*data not decoded
	sgsn_ctxt_rsp->ue_scef_pdn_connection.header.type = GTPV1_IE_UE_SCEF_PDN_CONNTECTION;
	sgsn_ctxt_rsp->ue_scef_pdn_connection.header.length = 19;
	sgsn_ctxt_rsp->ue_scef_pdn_connection.apn_length = 13;
	strncpy((char *)&sgsn_ctxt_rsp->ue_scef_pdn_connection.apn, "nextphones.co", 13);
	sgsn_ctxt_rsp->ue_scef_pdn_connection.spare = 0;
	sgsn_ctxt_rsp->ue_scef_pdn_connection.nsapi = 5;
	sgsn_ctxt_rsp->ue_scef_pdn_connection.scef_id_length = 3;
	strncpy((char *)&sgsn_ctxt_rsp->ue_scef_pdn_connection.scef_id, "111", 3);
	*/
	sgsn_ctxt_rsp->iov_updates_counter.header.type = GTPV1_IE_IOV_UPDATES_COUNTER;
	sgsn_ctxt_rsp->iov_updates_counter.header.length = 1;
	sgsn_ctxt_rsp->iov_updates_counter.iov_updates_counter = 10;
	
	sgsn_ctxt_rsp->private_extension.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	sgsn_ctxt_rsp->private_extension.header.length = 6;
	sgsn_ctxt_rsp->private_extension.extension_identifier = 12;
	strncpy((char *)&sgsn_ctxt_rsp->private_extension.extension_value, "2021", 4);

	return;
}

void fill_gtpv1_sgsn_context_ack(gtpv1_sgsn_context_ack_t *sgsn_context_ack){

	sgsn_context_ack->header.version = 1;
	sgsn_context_ack->header.protocol_type = 1;
	sgsn_context_ack->header.spare = 0;
	sgsn_context_ack->header.extension_header = 0;
	sgsn_context_ack->header.seq_num_flag = 0;
	sgsn_context_ack->header.n_pdu_flag = 0;
	sgsn_context_ack->header.message_type = GTPV1_SGSN_CONTEXT_ACK;
	sgsn_context_ack->header.message_len = 40;
	sgsn_context_ack->header.teid = 0x372f0000;
	sgsn_context_ack->header.seq = 0x00fe;
	sgsn_context_ack->header.n_pdu_number = 4;
	sgsn_context_ack->header.next_extension_header_type = 0;

	sgsn_context_ack->cause.header.type = GTPV1_IE_CAUSE;
	sgsn_context_ack->cause.cause_value = 128;

	sgsn_context_ack->teid_2.header.type = GTPV1_IE_TEID_DATA_2;
	sgsn_context_ack->teid_2.nsapi = 5;
	sgsn_context_ack->teid_2.teid = 0x0fffeee;

	sgsn_context_ack->sgsn_addr_user_traffic.header.type = GTPV1_IE_GSN_ADDR;
	sgsn_context_ack->sgsn_addr_user_traffic.header.length = 4;
	sgsn_context_ack->sgsn_addr_user_traffic.gsn_address.ipv4 = 3232235564;

	sgsn_context_ack->sgsn_number.header.type = GTPV1_IE_SGSN_NUMBER;
	sgsn_context_ack->sgsn_number.header.length = 2;
	strncpy((char *)&sgsn_context_ack->sgsn_number.sgsn_number,"11",2);

	sgsn_context_ack->node_id.header.type = GTPV1_IE_NODE_IDENTIFIER;
	sgsn_context_ack->node_id.header.length = 8;
	sgsn_context_ack->node_id.len_of_node_name = 3;
	strncpy((char *)&sgsn_context_ack->node_id.node_name,"mme",3);
	sgsn_context_ack->node_id.len_of_node_realm = 3;
	strncpy((char *)&sgsn_context_ack->node_id.node_realm,"aaa",3);

	sgsn_context_ack->private_extension.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	sgsn_context_ack->private_extension.header.length = 6;
	sgsn_context_ack->private_extension.extension_identifier = 12;
	strncpy((char *)&sgsn_context_ack->private_extension.extension_value, "2021", 4);

	return;
}

void fill_gtpv1_forward_relocation_req(gtpv1_forward_relocation_req_t *forward_relocation_req) {

	forward_relocation_req->header.version = 1;
	forward_relocation_req->header.protocol_type = 1;
	forward_relocation_req->header.spare = 0;
	forward_relocation_req->header.extension_header = 0;
	forward_relocation_req->header.seq_num_flag = 0;
	forward_relocation_req->header.n_pdu_flag = 0;

	forward_relocation_req->header.message_type = GTPV1_FORWARD_RELOCATION_REQUEST;
	forward_relocation_req->header.message_len = 493;
	forward_relocation_req->header.teid = 0x372f0000;
	forward_relocation_req->header.seq = 0x00fe;
	forward_relocation_req->header.n_pdu_number = 4;
	forward_relocation_req->header.next_extension_header_type = 0;

	forward_relocation_req->imsi.header.type = GTPV1_IE_IMSI;
	forward_relocation_req->imsi.imsi_number_digits = 272031000000000;

	forward_relocation_req->tunn_endpt_idnt_control_plane.header.type = GTPV1_IE_TEID_CONTROL_PLANE;
	forward_relocation_req->tunn_endpt_idnt_control_plane.teid = 0x0fffeee;

	forward_relocation_req->ranap_cause.header.type = GTPV1_IE_RANAP_CAUSE;
	forward_relocation_req->ranap_cause.ranap_cause = 7;

	forward_relocation_req->packet_flow_id.header.type = GTPV1_IE_PACKET_FLOW_ID;
	forward_relocation_req->packet_flow_id.spare = 0;
	forward_relocation_req->packet_flow_id.nsapi = 1;	
	forward_relocation_req->packet_flow_id.packet_flow_id = 4;

	forward_relocation_req->chrgng_char.header.type = GTPV1_IE_CHRGNG_CHAR;
	forward_relocation_req->chrgng_char.chrgng_char_val = 1;

	forward_relocation_req->mm_context.header.type = GTPV1_IE_MM_CONTEXT;
	forward_relocation_req->mm_context.header.length = 47;
	forward_relocation_req->mm_context.mm_context.gsm_keys_and_triplet.spare = 15;
	forward_relocation_req->mm_context.mm_context.gsm_keys_and_triplet.cksn = 1;
	forward_relocation_req->mm_context.security_mode = 1;
	forward_relocation_req->mm_context.mm_context.gsm_keys_and_triplet.no_of_vectors = 1;
	forward_relocation_req->mm_context.mm_context.gsm_keys_and_triplet.used_cipher = 1;
	forward_relocation_req->mm_context.mm_context.gsm_keys_and_triplet.kc = 1;
	strncpy((char *)&forward_relocation_req->mm_context.mm_context.gsm_keys_and_triplet.triplet[0].rand,"1111111111111111",16);
	forward_relocation_req->mm_context.mm_context.gsm_keys_and_triplet.triplet[0].sres = 2;
	forward_relocation_req->mm_context.mm_context.gsm_keys_and_triplet.triplet[0].kc = 2;

	forward_relocation_req->mm_context.drx_parameter.split_pg_cycle_code = 1;
	forward_relocation_req->mm_context.drx_parameter.cycle_length = 1;
	forward_relocation_req->mm_context.drx_parameter.ccch = 1;
	forward_relocation_req->mm_context.drx_parameter.timer = 1;
	
	forward_relocation_req->mm_context.ms_network_capability_length = 4;
	fill_gtpv1_ms_network_capability_value(&(forward_relocation_req->mm_context.ms_network_capability));
	
	forward_relocation_req->mm_context.container_length = 0;	

	forward_relocation_req->pdp_context.header.type = GTPV1_IE_PDP_CONTEXT;
	forward_relocation_req->pdp_context.header.length = 116;
	forward_relocation_req->pdp_context.ea = 0;
	forward_relocation_req->pdp_context.vaa = 1;
	forward_relocation_req->pdp_context.asi = 1;
	forward_relocation_req->pdp_context.order = 0;
	forward_relocation_req->pdp_context.nsapi = 5;
	forward_relocation_req->pdp_context.spare = 0;
	forward_relocation_req->pdp_context.sapi = 1;
	forward_relocation_req->pdp_context.qos_sub_length = 21;
	forward_relocation_req->pdp_context.qos_sub.allocation_retention_priority = 2;
	forward_relocation_req->pdp_context.qos_sub.spare1 = 0;
	forward_relocation_req->pdp_context.qos_sub.delay_class = 2;
	forward_relocation_req->pdp_context.qos_sub.reliablity_class = 2;
	forward_relocation_req->pdp_context.qos_sub.peak_throughput = 3;
	forward_relocation_req->pdp_context.qos_sub.spare2 = 0;
	forward_relocation_req->pdp_context.qos_sub.precedence_class = 1;
	forward_relocation_req->pdp_context.qos_sub.spare3 = 0;
	forward_relocation_req->pdp_context.qos_sub.mean_throughput = 4;
	forward_relocation_req->pdp_context.qos_sub.traffic_class = 1;
	forward_relocation_req->pdp_context.qos_sub.delivery_order = 1;
	forward_relocation_req->pdp_context.qos_sub.delivery_erroneous_sdu = 2;
	forward_relocation_req->pdp_context.qos_sub.max_sdu_size = 3;
	forward_relocation_req->pdp_context.qos_sub.max_bitrate_uplink = 123;
	forward_relocation_req->pdp_context.qos_sub.max_bitrate_downlink = 234;
	forward_relocation_req->pdp_context.qos_sub.residual_ber = 1;
	forward_relocation_req->pdp_context.qos_sub.sdu_error_ratio = 1; 
	forward_relocation_req->pdp_context.qos_sub.transfer_delay = 1; 
	forward_relocation_req->pdp_context.qos_sub.traffic_handling_priority = 2;
	forward_relocation_req->pdp_context.qos_sub.guaranteed_bitrate_uplink = 122;
	forward_relocation_req->pdp_context.qos_sub.guaranteed_bitrate_downlink = 222;
	forward_relocation_req->pdp_context.qos_sub.spare4 = 0; 
	forward_relocation_req->pdp_context.qos_sub.signalling_indication = 1;
	forward_relocation_req->pdp_context.qos_sub.source_statistics_descriptor = 1;
	forward_relocation_req->pdp_context.qos_sub.max_bitrate_downlink_ext1 = 22;
	forward_relocation_req->pdp_context.qos_sub.guaranteed_bitrate_downlink_ext1 = 11;
	forward_relocation_req->pdp_context.qos_sub.max_bitrate_uplink_ext1 = 33;
	forward_relocation_req->pdp_context.qos_sub.guaranteed_bitrate_uplink_ext1 = 22;
	forward_relocation_req->pdp_context.qos_sub.max_bitrate_downlink_ext2 = 44;
	forward_relocation_req->pdp_context.qos_sub.guaranteed_bitrate_downlink_ext2 = 33;
	forward_relocation_req->pdp_context.qos_sub.max_bitrate_uplink_ext2 = 34;
	forward_relocation_req->pdp_context.qos_sub.guaranteed_bitrate_uplink_ext2 = 23;
	forward_relocation_req->pdp_context.qos_req_length = 21;
	forward_relocation_req->pdp_context.qos_req.allocation_retention_priority = 2;
	forward_relocation_req->pdp_context.qos_req.spare1 = 0;
	forward_relocation_req->pdp_context.qos_req.delay_class = 2;
	forward_relocation_req->pdp_context.qos_req.reliablity_class = 2;
	forward_relocation_req->pdp_context.qos_req.peak_throughput = 3;
	forward_relocation_req->pdp_context.qos_req.spare2 = 0;
	forward_relocation_req->pdp_context.qos_req.precedence_class = 1;
	forward_relocation_req->pdp_context.qos_req.spare3 = 0;
	forward_relocation_req->pdp_context.qos_req.mean_throughput = 4;
	forward_relocation_req->pdp_context.qos_req.traffic_class = 1;
	forward_relocation_req->pdp_context.qos_req.delivery_order = 1;
	forward_relocation_req->pdp_context.qos_req.delivery_erroneous_sdu = 2;
	forward_relocation_req->pdp_context.qos_req.max_sdu_size = 3;
	forward_relocation_req->pdp_context.qos_req.max_bitrate_uplink = 123;
	forward_relocation_req->pdp_context.qos_req.max_bitrate_downlink = 234;
	forward_relocation_req->pdp_context.qos_req.residual_ber = 1;
	forward_relocation_req->pdp_context.qos_req.sdu_error_ratio = 1;
	forward_relocation_req->pdp_context.qos_req.transfer_delay = 1;
	forward_relocation_req->pdp_context.qos_req.traffic_handling_priority = 2;
	forward_relocation_req->pdp_context.qos_req.guaranteed_bitrate_uplink = 122;
	forward_relocation_req->pdp_context.qos_req.guaranteed_bitrate_downlink = 222;
	forward_relocation_req->pdp_context.qos_req.spare4 = 0;
	forward_relocation_req->pdp_context.qos_req.signalling_indication = 1;
	forward_relocation_req->pdp_context.qos_req.source_statistics_descriptor = 1;
	forward_relocation_req->pdp_context.qos_req.max_bitrate_downlink_ext1 = 22;
	forward_relocation_req->pdp_context.qos_req.guaranteed_bitrate_downlink_ext1 = 11;
	forward_relocation_req->pdp_context.qos_req.max_bitrate_uplink_ext1 = 33;
	forward_relocation_req->pdp_context.qos_req.guaranteed_bitrate_uplink_ext1 = 22;
	forward_relocation_req->pdp_context.qos_req.max_bitrate_downlink_ext2 = 44;
	forward_relocation_req->pdp_context.qos_req.guaranteed_bitrate_downlink_ext2 = 33;
	forward_relocation_req->pdp_context.qos_req.max_bitrate_uplink_ext2 = 34;
	forward_relocation_req->pdp_context.qos_req.guaranteed_bitrate_uplink_ext2 = 23;
	forward_relocation_req->pdp_context.qos_neg_length = 21;
	forward_relocation_req->pdp_context.qos_neg.allocation_retention_priority = 2;
	forward_relocation_req->pdp_context.qos_neg.spare1 = 0;
	forward_relocation_req->pdp_context.qos_neg.delay_class = 2;
	forward_relocation_req->pdp_context.qos_neg.reliablity_class = 2;
	forward_relocation_req->pdp_context.qos_neg.peak_throughput = 3;
	forward_relocation_req->pdp_context.qos_neg.spare2 = 0;
	forward_relocation_req->pdp_context.qos_neg.precedence_class = 1;
	forward_relocation_req->pdp_context.qos_neg.spare3 = 0;
	forward_relocation_req->pdp_context.qos_neg.mean_throughput = 4;
	forward_relocation_req->pdp_context.qos_neg.traffic_class = 1;
	forward_relocation_req->pdp_context.qos_neg.delivery_order = 1;
	forward_relocation_req->pdp_context.qos_neg.delivery_erroneous_sdu = 2;
	forward_relocation_req->pdp_context.qos_neg.max_sdu_size = 3;
	forward_relocation_req->pdp_context.qos_neg.max_bitrate_uplink = 123;
	forward_relocation_req->pdp_context.qos_neg.max_bitrate_downlink = 234;
	forward_relocation_req->pdp_context.qos_neg.residual_ber = 1;
	forward_relocation_req->pdp_context.qos_neg.sdu_error_ratio = 1;
	forward_relocation_req->pdp_context.qos_neg.transfer_delay = 1;
	forward_relocation_req->pdp_context.qos_neg.traffic_handling_priority = 2;
	forward_relocation_req->pdp_context.qos_neg.guaranteed_bitrate_uplink = 122;
	forward_relocation_req->pdp_context.qos_neg.guaranteed_bitrate_downlink = 222;
	forward_relocation_req->pdp_context.qos_neg.spare4 = 0;
	forward_relocation_req->pdp_context.qos_neg.signalling_indication = 1;
	forward_relocation_req->pdp_context.qos_neg.source_statistics_descriptor = 1;
	forward_relocation_req->pdp_context.qos_neg.max_bitrate_downlink_ext1 = 22;
	forward_relocation_req->pdp_context.qos_neg.guaranteed_bitrate_downlink_ext1 = 11;
	forward_relocation_req->pdp_context.qos_neg.max_bitrate_uplink_ext1 = 33;
	forward_relocation_req->pdp_context.qos_neg.guaranteed_bitrate_uplink_ext1 = 22;
	forward_relocation_req->pdp_context.qos_neg.max_bitrate_downlink_ext2 = 44;
	forward_relocation_req->pdp_context.qos_neg.guaranteed_bitrate_downlink_ext2 = 33;
	forward_relocation_req->pdp_context.qos_neg.max_bitrate_uplink_ext2 = 34;
	forward_relocation_req->pdp_context.qos_neg.guaranteed_bitrate_uplink_ext2 = 23;
	forward_relocation_req->pdp_context.sequence_number_down = 1;
	forward_relocation_req->pdp_context.sequence_number_up = 2;
	forward_relocation_req->pdp_context.send_npdu_number = 255;
	forward_relocation_req->pdp_context.rcv_npdu_number = 255;
	forward_relocation_req->pdp_context.uplink_teid_cp = 0x372f0000;
	forward_relocation_req->pdp_context.uplink_teid_data1 = 0x37300000;
	forward_relocation_req->pdp_context.pdp_ctxt_identifier = 0;
	forward_relocation_req->pdp_context.spare2 = 15;
	forward_relocation_req->pdp_context.pdp_type_org = 1;
	forward_relocation_req->pdp_context.pdp_type_number1 = 0x21;
	forward_relocation_req->pdp_context.pdp_address_length1 = 4;
	forward_relocation_req->pdp_context.pdp_address1.ipv4 = 355240599;
	forward_relocation_req->pdp_context.ggsn_addr_cp_length = 4;
	forward_relocation_req->pdp_context.ggsn_addr_cp.ipv4 = 355240589;
	forward_relocation_req->pdp_context.ggsn_addr_ut_length = 4;
	forward_relocation_req->pdp_context.ggsn_addr_ut.ipv4 = 355240599;
	forward_relocation_req->pdp_context.apn_length = 13;
	strncpy((char *)&forward_relocation_req->pdp_context.apn,"nextphones.co",13);
	forward_relocation_req->pdp_context.spare3 = 0;
	forward_relocation_req->pdp_context.transaction_identifier1 = 10;
	forward_relocation_req->pdp_context.transaction_identifier2 = 55;

	forward_relocation_req->gsn_addr_1.header.type = GTPV1_IE_GSN_ADDR;
	forward_relocation_req->gsn_addr_1.header.length = 4;
	forward_relocation_req->gsn_addr_1.gsn_address.ipv4 = 3232235564;

	forward_relocation_req->gsn_addr_2.header.type = GTPV1_IE_GSN_ADDR;
	forward_relocation_req->gsn_addr_2.header.length = 16;
	char *str6 = "2001:db80:3333:4444:5555:6666:7777:8888";
	inet_pton(AF_INET6, str6, forward_relocation_req->gsn_addr_2.gsn_address.ipv6);

	forward_relocation_req->gsn_addr_3.header.type = GTPV1_IE_GSN_ADDR;
	forward_relocation_req->gsn_addr_3.header.length = 16;
	char *str7 = "2001:db80:3333:4444:5555:6666:7777:8888";
	inet_pton(AF_INET6, str7, forward_relocation_req->gsn_addr_3.gsn_address.ipv6);	

	forward_relocation_req->target_id.header.type = GTPV1_IE_TARGET_IDENTIFICATION;
	forward_relocation_req->target_id.header.length = 10;
	forward_relocation_req->target_id.mcc_digit_2 = 0x0;
	forward_relocation_req->target_id.mcc_digit_1 = 0x4;
	forward_relocation_req->target_id.mnc_digit_3 = 0x8;
	forward_relocation_req->target_id.mcc_digit_3 = 0x4;
	forward_relocation_req->target_id.mnc_digit_1 = 0x0;
	forward_relocation_req->target_id.mnc_digit_2 = 0x7;
	forward_relocation_req->target_id.lac = 0x2;
	forward_relocation_req->target_id.rac = 0x2;
	forward_relocation_req->target_id.rnc_id = 2;
	forward_relocation_req->target_id.extended_rnc_id = 0;

	/*not supported
	forward_relocation_req->utran_container.header.type = GTPV1_IE_UTRAN_TRANSPARENT_CONTAINER;
	forward_relocation_req->utran_container.header.length = 4;
	strncpy((char *)&forward_relocation_req->utran_container.utran_transparent_field, "2124", 4);
	*/

	forward_relocation_req->pdp_context_prioritization.header.type = GTPV1_IE_PDP_CONTEXT_PRIORITIZATION;

	forward_relocation_req->mbms_ue_context.header.type = GTPV1_IE_MBMS_UE_CONTEXT;
	forward_relocation_req->mbms_ue_context.header.length = 34;
	forward_relocation_req->mbms_ue_context.linked_nsapi = 2;
	forward_relocation_req->mbms_ue_context.spare1 = 0;
	forward_relocation_req->mbms_ue_context.uplink_teid_cp = 0x372f0000;
	forward_relocation_req->mbms_ue_context.enhanced_nsapi = 129;
	forward_relocation_req->mbms_ue_context.spare2 = 15;
	forward_relocation_req->mbms_ue_context.pdp_type_org = 1;
	forward_relocation_req->mbms_ue_context.pdp_type_number = 0x21;
	forward_relocation_req->mbms_ue_context.pdp_address_length = 4;
	forward_relocation_req->mbms_ue_context.pdp_address.ipv4 = 355240599;
	forward_relocation_req->mbms_ue_context.ggsn_addr_cp_length = 4;
	forward_relocation_req->mbms_ue_context.ggsn_addr_cp.ipv4 = 355240589;
	forward_relocation_req->mbms_ue_context.apn_length = 13;
	strncpy((char *)&forward_relocation_req->mbms_ue_context.apn,"nextphones.co",13);
	forward_relocation_req->mbms_ue_context.spare3 = 0;
	forward_relocation_req->mbms_ue_context.transaction_identifier1 = 1;
	forward_relocation_req->mbms_ue_context.transaction_identifier2 = 5;

	forward_relocation_req->plmn_id.header.type = GTPV1_IE_SELECTED_PLMN_ID;
	forward_relocation_req->plmn_id.header.length = 3;
	forward_relocation_req->plmn_id.mcc_digit_2 = 0x0;
	forward_relocation_req->plmn_id.mcc_digit_1 = 0x4;
	forward_relocation_req->plmn_id.mnc_digit_3 = 0x8;
	forward_relocation_req->plmn_id.mcc_digit_3 = 0x4;
	forward_relocation_req->plmn_id.mnc_digit_1 = 0x0;
	forward_relocation_req->plmn_id.mnc_digit_2 = 0x7;

	//not suppported
	/*
	forward_relocation_req->bss_container.header.type = GTPV1_IE_BSS_CONTAINER;
	forward_relocation_req->bss_container.header.length = 23;
	strncpy((char *)&forward_relocation_req->bss_container.bss_container, "NM-FLOW-CONTROL-BVC.cnf", 23);
	*/

	forward_relocation_req->cell_id.header.type = GTPV1_IE_CELL_IDENTIFICATION;
	forward_relocation_req->cell_id.header.length = 17;
	forward_relocation_req->cell_id.target_cell_id.rai_value.mcc_digit_2 = 0x0;
	forward_relocation_req->cell_id.target_cell_id.rai_value.mcc_digit_1 = 0x4;
	forward_relocation_req->cell_id.target_cell_id.rai_value.mnc_digit_3 = 0x8;
	forward_relocation_req->cell_id.target_cell_id.rai_value.mcc_digit_3 = 0x4;
	forward_relocation_req->cell_id.target_cell_id.rai_value.mnc_digit_2 = 0x7;
	forward_relocation_req->cell_id.target_cell_id.rai_value.mnc_digit_1 = 0x0;
	forward_relocation_req->cell_id.target_cell_id.rai_value.lac = 0x14;
	forward_relocation_req->cell_id.target_cell_id.rai_value.rac = 0x14;
	forward_relocation_req->cell_id.target_cell_id.cell_identity = 1;
	forward_relocation_req->cell_id.source_type = 0;
	forward_relocation_req->cell_id.ID.source_cell_id.rai_value.mcc_digit_2 = 0x0;
	forward_relocation_req->cell_id.ID.source_cell_id.rai_value.mcc_digit_1 = 0x4;
	forward_relocation_req->cell_id.ID.source_cell_id.rai_value.mnc_digit_3 = 0x8;
	forward_relocation_req->cell_id.ID.source_cell_id.rai_value.mcc_digit_3 = 0x4;
	forward_relocation_req->cell_id.ID.source_cell_id.rai_value.mnc_digit_2 = 0x7;
	forward_relocation_req->cell_id.ID.source_cell_id.rai_value.mnc_digit_1 = 0x0;
	forward_relocation_req->cell_id.ID.source_cell_id.rai_value.lac = 0x14;
	forward_relocation_req->cell_id.ID.source_cell_id.rai_value.rac = 0x14;
	forward_relocation_req->cell_id.ID.source_cell_id.cell_identity = 1;	

	forward_relocation_req->bssgp_cause.header.type = GTPV1_IE_BSSGP_CAUSE;
	forward_relocation_req->bssgp_cause.header.length = 1;
	forward_relocation_req->bssgp_cause.bssgp_cause = 2;

	/* not supported
	forward_relocation_req->xid_param.header.type = GTPV1_IE_PS_HANDOVER_XID_PARAM;
	forward_relocation_req->xid_param.header.length = 4;
	forward_relocation_req->xid_param.spare = 0;
	forward_relocation_req->xid_param.sapi = 2;
	forward_relocation_req->xid_param.xid_param_length = 2;
	strncpy((char *)&forward_relocation_req->xid_param.xid_param, "11", 2);
	*/

	forward_relocation_req->direct_tunnel_flag.header.type = GTPV1_IE_DIRECT_TUNNEL_FLAG;
	forward_relocation_req->direct_tunnel_flag.header.length = 1;
	forward_relocation_req->direct_tunnel_flag.spare = 0;
	forward_relocation_req->direct_tunnel_flag.ei = 1;
	forward_relocation_req->direct_tunnel_flag.gcsi = 1;
	forward_relocation_req->direct_tunnel_flag.dti = 1;
	
	/*data not decoded
	forward_relocation_req->inter_rat_handover.header.type = GTPV1_IE_RELIABLE_INTER_RAT_HANDOVER_INFO;
	forward_relocation_req->inter_rat_handover.header.length = 1;
	forward_relocation_req->inter_rat_handover.handover_info = 2;
	*/
	forward_relocation_req->subscribed_rfsp_index.header.type = GTPV1_IE_RFSP_INDEX;
	forward_relocation_req->subscribed_rfsp_index.header.length = 2;
	forward_relocation_req->subscribed_rfsp_index.rfsp_index = 3;

	forward_relocation_req->rfsp_index_in_use.header.type = GTPV1_IE_RFSP_INDEX;
	forward_relocation_req->rfsp_index_in_use.header.length = 2;
	forward_relocation_req->rfsp_index_in_use.rfsp_index = 2;

	forward_relocation_req->co_located_ggsn_pgw_fqdn.header.type = GTPV1_IE_FQDN;
	forward_relocation_req->co_located_ggsn_pgw_fqdn.header.length = 5;
	strncpy((char *)&forward_relocation_req->co_located_ggsn_pgw_fqdn.fqdn,"gslab",5);

	forward_relocation_req->evolved_allocation_retention_priority_II.header.type = GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_II;
	forward_relocation_req->evolved_allocation_retention_priority_II.header.length = 2;
	forward_relocation_req->evolved_allocation_retention_priority_II.spare = 0;
	forward_relocation_req->evolved_allocation_retention_priority_II.nsapi = 1;
	forward_relocation_req->evolved_allocation_retention_priority_II.spare2 = 0;
	forward_relocation_req->evolved_allocation_retention_priority_II.pci = 1;
	forward_relocation_req->evolved_allocation_retention_priority_II.pl = 1;
	forward_relocation_req->evolved_allocation_retention_priority_II.spare3 = 0;
	forward_relocation_req->evolved_allocation_retention_priority_II.pvi = 1;

	forward_relocation_req->extended_common_flag.header.type = GTPV1_IE_EXTENDED_COMMON_FLAG;
	forward_relocation_req->extended_common_flag.header.length = 1;
	forward_relocation_req->extended_common_flag.uasi = 0;
	forward_relocation_req->extended_common_flag.bdwi = 0;
	forward_relocation_req->extended_common_flag.pcri = 0;
	forward_relocation_req->extended_common_flag.vb = 0;
	forward_relocation_req->extended_common_flag.retloc = 0;
	forward_relocation_req->extended_common_flag.cpsr = 0;

	//data not decoded
	/*
	forward_relocation_req->csg_id.header.type = GTPV1_IE_CSG_ID;
	forward_relocation_req->csg_id.header.length = 4;
	forward_relocation_req->csg_id.spare = 0;
	forward_relocation_req->csg_id.csg_id = 1;
	forward_relocation_req->csg_id.csg_id2 = 2;
	*/

	forward_relocation_req->csg_member.header.type = GTPV1_IE_CSG_MEMB_INDCTN;
	forward_relocation_req->csg_member.header.length = 1;
	forward_relocation_req->csg_member.spare = 0;
	forward_relocation_req->csg_member.cmi = 1;	

	forward_relocation_req->ue_network_capability.header.type = GTPV1_IE_UE_NETWORK_CAPABILITY;
	forward_relocation_req->ue_network_capability.header.length = 5;
	forward_relocation_req->ue_network_capability.eea0 = 1;
	forward_relocation_req->ue_network_capability.eea1_128 = 1;
	forward_relocation_req->ue_network_capability.eea2_128 = 0;
	forward_relocation_req->ue_network_capability.eea3_128 = 1;
	forward_relocation_req->ue_network_capability.eea4 = 0;
	forward_relocation_req->ue_network_capability.eea5 = 1;
	forward_relocation_req->ue_network_capability.eea6 = 1;
	forward_relocation_req->ue_network_capability.eea7 = 0;
	forward_relocation_req->ue_network_capability.eia0 = 1;
	forward_relocation_req->ue_network_capability.eia1_128 = 0;
	forward_relocation_req->ue_network_capability.eia2_128 = 1;
	forward_relocation_req->ue_network_capability.eia3_128 = 0;
	forward_relocation_req->ue_network_capability.eia4 = 1;
	forward_relocation_req->ue_network_capability.eia5 = 0;
	forward_relocation_req->ue_network_capability.eia6 = 1;
	forward_relocation_req->ue_network_capability.eia7 = 1;
	forward_relocation_req->ue_network_capability.uea0 = 0;
	forward_relocation_req->ue_network_capability.uea1 = 1;
	forward_relocation_req->ue_network_capability.uea2 = 0;
	forward_relocation_req->ue_network_capability.uea3 = 1;
	forward_relocation_req->ue_network_capability.uea4 = 0;
	forward_relocation_req->ue_network_capability.uea5 = 1;
	forward_relocation_req->ue_network_capability.uea6 = 0;
	forward_relocation_req->ue_network_capability.uea7 = 1;
	forward_relocation_req->ue_network_capability.ucs2 = 1;
	forward_relocation_req->ue_network_capability.uia1 = 0;
	forward_relocation_req->ue_network_capability.uia2 = 1;
	forward_relocation_req->ue_network_capability.uia3 = 1;
	forward_relocation_req->ue_network_capability.uia4 = 0;
	forward_relocation_req->ue_network_capability.uia5 = 1;
	forward_relocation_req->ue_network_capability.uia6 = 0;
	forward_relocation_req->ue_network_capability.uia7 = 1;
	forward_relocation_req->ue_network_capability.prose_dd = 1;
	forward_relocation_req->ue_network_capability.prose = 0;
	forward_relocation_req->ue_network_capability.h245_ash = 1;
	forward_relocation_req->ue_network_capability.acc_csfb = 1;
	forward_relocation_req->ue_network_capability.lpp = 0;
	forward_relocation_req->ue_network_capability.lcs = 1;
	forward_relocation_req->ue_network_capability.srvcc1x = 1;
	forward_relocation_req->ue_network_capability.nf = 0;

	forward_relocation_req->ue_ambr.header.type = GTPV1_IE_UE_AMBR;
	forward_relocation_req->ue_ambr.header.length = 16;
	forward_relocation_req->ue_ambr.subscribed_ue_ambr_for_uplink = 8;
	forward_relocation_req->ue_ambr.subscribed_ue_ambr_for_downlink = 16;
	forward_relocation_req->ue_ambr.authorized_ue_ambr_for_uplink = 32;
	forward_relocation_req->ue_ambr.authorized_ue_ambr_for_downlink = 64;

	forward_relocation_req->apn_ambr_with_nsapi.header.type = GTPV1_IE_APN_AMBR_WITH_NSAPI;
	forward_relocation_req->apn_ambr_with_nsapi.header.length = 9;
	forward_relocation_req->apn_ambr_with_nsapi.spare = 0;
	forward_relocation_req->apn_ambr_with_nsapi.nsapi = 1;
	forward_relocation_req->apn_ambr_with_nsapi.authorized_apn_ambr_for_uplink = 1;
	forward_relocation_req->apn_ambr_with_nsapi.authorized_apn_ambr_for_downlink = 1;

	forward_relocation_req->signalling_priority_indication_with_nsapi.header.type = GTPV1_IE_SIGNALLING_PRIORITY_INDICATION_WITH_NSAPI;
	forward_relocation_req->signalling_priority_indication_with_nsapi.header.length = 2;
	forward_relocation_req->signalling_priority_indication_with_nsapi.spare = 0;
	forward_relocation_req->signalling_priority_indication_with_nsapi.nsapi = 1;
	forward_relocation_req->signalling_priority_indication_with_nsapi.spare2 = 0;
	forward_relocation_req->signalling_priority_indication_with_nsapi.lapi = 1;

	forward_relocation_req->higher_bitrates_than_16_mbps_flag.header.type = GTPV1_IE_HIGER_BITRATES_THAN_16_MBPS_FLAG;
	forward_relocation_req->higher_bitrates_than_16_mbps_flag.header.length = 1;
	forward_relocation_req->higher_bitrates_than_16_mbps_flag.higher_bitrates_than_16_mbps_flag = 1;

	forward_relocation_req->add_mm_ctxt.header.type = GTPV1_IE_ADDTL_MM_CTXT_SRVCC;
	forward_relocation_req->add_mm_ctxt.header.length = 34;
	forward_relocation_req->add_mm_ctxt.ms_classmark_2.ms_classmark_2_len = 3;
	forward_relocation_req->add_mm_ctxt.ms_classmark_2.spare1 = 0;
	forward_relocation_req->add_mm_ctxt.ms_classmark_2.rev_level = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_2.es_ind = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_2.a5_1 = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_2.rf_power_cap = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_2.spare2 = 0;
	forward_relocation_req->add_mm_ctxt.ms_classmark_2.ps_cap = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_2.ss_screen_ind = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_2.sm_cap = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_2.vbs = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_2.vgcs = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_2.fc = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_2.cm3 = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_2.spare3 = 0;
	forward_relocation_req->add_mm_ctxt.ms_classmark_2.lcsvacap = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_2.ucs2 = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_2.solsa = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_2.cmsp = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_2.a5_3 = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_2.a5_2 = 1;

	forward_relocation_req->add_mm_ctxt.ms_classmark_3.ms_classmark_3_len = 21;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.spare1 = 0;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.mult_band_supp = 5;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.a5_bits = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.assoc_radio_cap_1 = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.assoc_radio_cap_2 = 2;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.r_support = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.r_gsm_assoc_radio_cap = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.hscsd_mult_slot_cap = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.hscsd_mult_slot_class = 4;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.ucs2_treatment = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.extended_meas_cap = 0;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.ms_meas_cap = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.sms_value = 3;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.sm_value = 5;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.ms_pos_method_cap = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.ms_pos_method = 3;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.ecsd_multislot_cap = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.ecsd_multislot_class = 6;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.psk8_struct = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.mod_cap = 0;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.rf_pwr_cap_1 = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.rf_pwr_cap_1_val = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.rf_pwr_cap_2 = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.rf_pwr_cap_2_val = 0;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.gsm_400_bands_supp = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.gsm_400_bands_val = 0;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.gsm_400_assoc_radio_cap = 4;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.gsm_850_assoc_radio_cap = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.gsm_850_assoc_radio_cap_val = 3;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.gsm_1900_assoc_radio_cap = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.gsm_1900_assoc_radio_cap_val = 5;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.umts_fdd_rat_cap = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.umts_tdd_rat_cap = 0;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.cdma2000_rat_cap = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.dtm_gprs_multislot_class = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.dtm_gprs_multislot_val = 0;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.single_slot_dtm = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.dtm_egprs_multislot_class = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.dtm_egprs_multislot_val = 2;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.single_band_supp = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.single_band_supp_val = 7;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.gsm_750_assoc_radio_cap = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.gsm_750_assoc_radio_cap_val = 14;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.umts_1_28_mcps_tdd_rat_cap = 0;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.geran_feature_package = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.ext_dtm_gprs_multislot_class = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.ext_dtm_gprs_multislot_val = 3;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.ext_dtm_egprs_multislot_val = 2;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.high_multislot_cap = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.high_multislot_val = 2;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.geran_iu_mode_supp = 0;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.geran_feature_package_2 = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.gmsk_multislot_power_prof = 2;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.psk8_multislot_power_prof = 3;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.t_gsm_400_bands_supp = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.t_gsm_400_bands_val = 2;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.t_gsm_400_assoc_radio_cap = 6;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.t_gsm_900_assoc_radio_cap = 0;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.dl_advanced_rx_perf = 3;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.dtm_enhancements_cap = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.dtm_gprs_high_multislot_cap = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.dtm_gprs_high_multislot_val = 2;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.offset_required = 0;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.dtm_egprs_high_multislot_cap = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.dtm_egprs_high_multislot_val = 2;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.repeated_acch_capability = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.gsm_710_assoc_radio_cap = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.gsm_710_assoc_radio_val = 5;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.t_gsm_810_assoc_radio_cap = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.t_gsm_810_assoc_radio_val = 7;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.ciphering_mode_setting_cap = 0;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.add_pos_cap = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.e_utra_fdd_supp = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.e_utra_tdd_supp = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.e_utra_meas_rep_supp = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.prio_resel_supp = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.utra_csg_cells_rep = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.vamos_level = 2;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.tighter_capability = 3;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.sel_ciph_dl_sacch = 0;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.cs_ps_srvcc_geran_utra = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.cs_ps_srvcc_geran_eutra = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.geran_net_sharing = 0;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.e_utra_wb_rsrq_meas_supp = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.er_band_support = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.utra_mult_band_ind_supp = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.e_utra_mult_band_ind_supp = 0;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.extended_tsc_set_cap_supp = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.extended_earfcn_val_range = 1;
	forward_relocation_req->add_mm_ctxt.ms_classmark_3.spare3 = 0;
	forward_relocation_req->add_mm_ctxt.sup_codec_list_len = 7;
	forward_relocation_req->add_mm_ctxt.sup_codec_list[0].sysid = 2;
	forward_relocation_req->add_mm_ctxt.sup_codec_list[0].len_bitmap_sysid = 2;
	forward_relocation_req->add_mm_ctxt.sup_codec_list[0].codec_bitmap_1_8 = 6;
	forward_relocation_req->add_mm_ctxt.sup_codec_list[0].codec_bitmap_9_16 = 5;
	forward_relocation_req->add_mm_ctxt.sup_codec_list[1].sysid = 1;
	forward_relocation_req->add_mm_ctxt.sup_codec_list[1].len_bitmap_sysid = 1;
	forward_relocation_req->add_mm_ctxt.sup_codec_list[1].codec_bitmap_1_8 = 3;

	forward_relocation_req->add_flag_srvcc.header.type = GTPV1_IE_ADDTL_FLGS_SRVCC;
	forward_relocation_req->add_flag_srvcc.header.length = 1;
	forward_relocation_req->add_flag_srvcc.spare = 0;
	forward_relocation_req->add_flag_srvcc.ics = 0;

	//data not decoded
	/*
	forward_relocation_req->stn_sr.header.type = GTPV1_IE_STN_SR;
	forward_relocation_req->stn_sr.header.length = 3;
	forward_relocation_req->stn_sr.nanpi = 1;
	forward_relocation_req->stn_sr.digits[0].digit1 = 0;
	forward_relocation_req->stn_sr.digits[0].digit2 = 1;
	forward_relocation_req->stn_sr.digits[1].digit1 = 2;
	forward_relocation_req->stn_sr.digits[1].digit2 = 1;
	*/

	forward_relocation_req->c_msisdn.header.type = GTPV1_IE_C_MSISDN;
	forward_relocation_req->c_msisdn.header.length = 5;
	strncpy((char *)&forward_relocation_req->c_msisdn.msisdn, "23456", 5);

	forward_relocation_req->ext_ranap_cause.header.type = GTPV1_IE_EXTENDED_RANAP_CAUSE;
	forward_relocation_req->ext_ranap_cause.header.length = 2;
	forward_relocation_req->ext_ranap_cause.extended_ranap_cause = 2;

	forward_relocation_req->enodeb_id.header.type = GTPV1_IE_ENODEB_ID;
	forward_relocation_req->enodeb_id.header.length = 9;
	forward_relocation_req->enodeb_id.enodeb_type = 0x0;
	forward_relocation_req->enodeb_id.mcc_digit_2 = 0x0;
	forward_relocation_req->enodeb_id.mcc_digit_1 = 0x4;
	forward_relocation_req->enodeb_id.mnc_digit_3 = 0x8;
	forward_relocation_req->enodeb_id.mcc_digit_3 = 0x4;
	forward_relocation_req->enodeb_id.mnc_digit_1 = 0x0;
	forward_relocation_req->enodeb_id.mnc_digit_2 = 0x7;
	forward_relocation_req->enodeb_id.spare = 0;
	forward_relocation_req->enodeb_id.macro_enodeb_id = 2;
	forward_relocation_req->enodeb_id.macro_enodeb_id2 = 3;
	forward_relocation_req->enodeb_id.home_enodeb_id = 0;
	forward_relocation_req->enodeb_id.home_enodeb_id2 = 0;
	forward_relocation_req->enodeb_id.tac = 20;

	forward_relocation_req->selection_mode_with_nsapi.header.type = GTPV1_IE_SELECTION_MODE_WITH_NSAPI;
	forward_relocation_req->selection_mode_with_nsapi.header.length = 2;
	forward_relocation_req->selection_mode_with_nsapi.spare = 0;
	forward_relocation_req->selection_mode_with_nsapi.nsapi = 1;
	forward_relocation_req->selection_mode_with_nsapi.spare2 = 0;
	forward_relocation_req->selection_mode_with_nsapi.selection_mode_value = 1;

	forward_relocation_req->ue_usage_type.header.type = GTPV1_IE_UE_USAGE_TYPE;
	forward_relocation_req->ue_usage_type.header.length = 4;
	forward_relocation_req->ue_usage_type.ue_usage_type_value = 15;

	forward_relocation_req->extended_common_flag_2.header.type = GTPV1_IE_EXTENDED_COMMON_FLAGS_II;
	forward_relocation_req->extended_common_flag_2.header.length = 1;
	forward_relocation_req->extended_common_flag_2.spare = 0;
	forward_relocation_req->extended_common_flag_2.pmts_mi = 1;
	forward_relocation_req->extended_common_flag_2.dtci = 1;
	forward_relocation_req->extended_common_flag_2.pnsi = 1;
	
	/*data not decoded
	forward_relocation_req->ue_scef_pdn_connection.header.type = GTPV1_IE_UE_SCEF_PDN_CONNTECTION;
	forward_relocation_req->ue_scef_pdn_connection.header.length = 19;
	forward_relocation_req->ue_scef_pdn_connection.apn_length = 13;
	strncpy((char *)&forward_relocation_req->ue_scef_pdn_connection.apn, "nextphones.co", 13);
	forward_relocation_req->ue_scef_pdn_connection.spare = 0;
	forward_relocation_req->ue_scef_pdn_connection.nsapi = 5;
	forward_relocation_req->ue_scef_pdn_connection.scef_id_length = 3;
	strncpy((char *)&forward_relocation_req->ue_scef_pdn_connection.scef_id, "111", 3);
	*/

	forward_relocation_req->private_extension.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	forward_relocation_req->private_extension.header.length = 6;
	forward_relocation_req->private_extension.extension_identifier = 12;
	strncpy((char *)&forward_relocation_req->private_extension.extension_value, "2021", 4);

	return;
}

void fill_gtpv1_forward_relocation_rsp(gtpv1_forward_relocation_rsp_t *forward_relocation_rsp){

	forward_relocation_rsp->header.version = 1;
	forward_relocation_rsp->header.protocol_type = 1;
	forward_relocation_rsp->header.spare = 0;
	forward_relocation_rsp->header.extension_header = 0;
	forward_relocation_rsp->header.seq_num_flag = 0;
	forward_relocation_rsp->header.n_pdu_flag = 0;

	forward_relocation_rsp->header.message_type = GTPV1_FORWARD_RELOCATION_RESPONSE;
	forward_relocation_rsp->header.message_len = 106;
	forward_relocation_rsp->header.teid = 0x372f0000;
	forward_relocation_rsp->header.seq = 0x00fe;
	forward_relocation_rsp->header.n_pdu_number = 4;
	forward_relocation_rsp->header.next_extension_header_type = 0;

	forward_relocation_rsp->cause.header.type = GTPV1_IE_CAUSE;
	forward_relocation_rsp->cause.cause_value = 128;

	forward_relocation_rsp->teid_control_plane.header.type = GTPV1_IE_TEID_CONTROL_PLANE;
	forward_relocation_rsp->teid_control_plane.teid = 0x00ab;

	forward_relocation_rsp->teid_2.header.type = GTPV1_IE_TEID_DATA_2;
	forward_relocation_rsp->teid_2.nsapi = 5;
	forward_relocation_rsp->teid_2.teid = 0x0fffeee;

	forward_relocation_rsp->ranap_cause.header.type = GTPV1_IE_RANAP_CAUSE;
	forward_relocation_rsp->ranap_cause.ranap_cause = 7;

	forward_relocation_rsp->sgsn_addr_control_plane.header.type = GTPV1_IE_GSN_ADDR;
	forward_relocation_rsp->sgsn_addr_control_plane.header.length = 4;
	forward_relocation_rsp->sgsn_addr_control_plane.gsn_address.ipv4 = 3232235564;
	
	forward_relocation_rsp->sgsn_addr_user_traffic.header.type = GTPV1_IE_GSN_ADDR;
	forward_relocation_rsp->sgsn_addr_user_traffic.header.length = 4;
	forward_relocation_rsp->sgsn_addr_user_traffic.gsn_address.ipv4 = 3232235564;

	/*not supported
	forward_relocation_rsp->utran_container.header.type = GTPV1_IE_UTRAN_TRANSPARENT_CONTAINER;
	forward_relocation_rsp->utran_container.header.length = 4;
	strncpy((char *)&forward_relocation_rsp->utran_container.utran_transparent_field, "2124", 4);
	*/

	forward_relocation_rsp->rab_setup_info.header.type = GTPV1_IE_RAB_SETUP_INFO;
	forward_relocation_rsp->rab_setup_info.header.length = 9;
	forward_relocation_rsp->rab_setup_info.spare = 0;
	forward_relocation_rsp->rab_setup_info.nsapi = 2;
	forward_relocation_rsp->rab_setup_info.teid = 0x0fffeee;
	forward_relocation_rsp->rab_setup_info.rnc_ip_addr.ipv4 = 3565240599;

	forward_relocation_rsp->add_rab_setup_info.header.type = GTPV1_IE_ADDITIONAL_RAB_SETUP_INFO;
	forward_relocation_rsp->add_rab_setup_info.header.length = 21;
	forward_relocation_rsp->add_rab_setup_info.spare = 0;
	forward_relocation_rsp->add_rab_setup_info.nsapi = 2;
	forward_relocation_rsp->add_rab_setup_info.teid = 0x0fffeee;
	char *str3 = "2001:db80:3333:4444:5555:6666:7777:8885";
	inet_pton(AF_INET6, str3, forward_relocation_rsp->add_rab_setup_info.rnc_ip_addr.ipv6);

	forward_relocation_rsp->sgsn_number.header.type = GTPV1_IE_SGSN_NUMBER;
	forward_relocation_rsp->sgsn_number.header.length = 2;
	strncpy((char *)&forward_relocation_rsp->sgsn_number.sgsn_number,"11",2);

	//not supported
	/*
	forward_relocation_rsp->bss_container.header.type = GTPV1_IE_BSS_CONTAINER;
	forward_relocation_rsp->bss_container.header.length = 23;
	strncpy((char *)&forward_relocation_rsp->bss_container.bss_container, "NM-FLOW-CONTROL-BVC.cnf", 23);
	*/

	forward_relocation_rsp->bssgp_cause.header.type = GTPV1_IE_BSSGP_CAUSE;
	forward_relocation_rsp->bssgp_cause.header.length = 1;
	forward_relocation_rsp->bssgp_cause.bssgp_cause = 2;

	forward_relocation_rsp->list_pfcs.header.type = GTPV1_IE_LIST_OF_SET_UP_PFCS;
	forward_relocation_rsp->list_pfcs.header.length = 4;
	forward_relocation_rsp->list_pfcs.list.no_of_pfcs = 3;
	forward_relocation_rsp->list_pfcs.list.pfi_list[0].spare = 0;
	forward_relocation_rsp->list_pfcs.list.pfi_list[0].pfi_value = 1;
	forward_relocation_rsp->list_pfcs.list.pfi_list[1].spare = 0;
	forward_relocation_rsp->list_pfcs.list.pfi_list[1].pfi_value = 0;
	forward_relocation_rsp->list_pfcs.list.pfi_list[2].spare = 0;
	forward_relocation_rsp->list_pfcs.list.pfi_list[2].pfi_value = 3;

	forward_relocation_rsp->ext_ranap_cause.header.type = GTPV1_IE_EXTENDED_RANAP_CAUSE;
	forward_relocation_rsp->ext_ranap_cause.header.length = 2;
	forward_relocation_rsp->ext_ranap_cause.extended_ranap_cause = 2;

	forward_relocation_rsp->node_id.header.type = GTPV1_IE_NODE_IDENTIFIER;
	forward_relocation_rsp->node_id.header.length = 8;
	forward_relocation_rsp->node_id.len_of_node_name = 3;
	strncpy((char *)&forward_relocation_rsp->node_id.node_name,"mme",3);
	forward_relocation_rsp->node_id.len_of_node_realm = 3;
	strncpy((char *)&forward_relocation_rsp->node_id.node_realm,"aaa",3);

	forward_relocation_rsp->private_extension.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	forward_relocation_rsp->private_extension.header.length = 6;
	forward_relocation_rsp->private_extension.extension_identifier = 12;
	strncpy((char *)&forward_relocation_rsp->private_extension.extension_value, "2021", 4);

	return;
}

void fill_gtpv1_forward_relocation_complete(gtpv1_forward_relocation_complete_t *forward_relocation_complete){

	forward_relocation_complete->header.version = 1;
	forward_relocation_complete->header.protocol_type = 1;
	forward_relocation_complete->header.spare = 0;
	forward_relocation_complete->header.extension_header = 0;
	forward_relocation_complete->header.seq_num_flag = 0;
	forward_relocation_complete->header.n_pdu_flag = 0;
	forward_relocation_complete->header.message_type = GTPV1_FORWARD_RELOCATION_COMPLETE;
	forward_relocation_complete->header.message_len = 9;
	forward_relocation_complete->header.teid = 0x372f0000;
	forward_relocation_complete->header.seq = 0x00fe;
	forward_relocation_complete->header.n_pdu_number = 4;
	forward_relocation_complete->header.next_extension_header_type = 0;

	forward_relocation_complete->private_extension.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	forward_relocation_complete->private_extension.header.length = 6;
	forward_relocation_complete->private_extension.extension_identifier = 12;
	strncpy((char *)&forward_relocation_complete->private_extension.extension_value, "2021", 4);

	return;
}

void fill_gtpv1_relocation_cancel_req(gtpv1_relocation_cancel_req_t *relocation_cancel_req) {

	relocation_cancel_req->header.version = 1;
	relocation_cancel_req->header.protocol_type = 1;
	relocation_cancel_req->header.spare = 0;
	relocation_cancel_req->header.extension_header = 0;
	relocation_cancel_req->header.seq_num_flag = 0;
	relocation_cancel_req->header.n_pdu_flag = 0;

	relocation_cancel_req->header.message_type = GTPV1_RELOCATION_CANCEL_REQ;
	relocation_cancel_req->header.message_len = 38;
	relocation_cancel_req->header.teid = 0x372f0000;
	relocation_cancel_req->header.seq = 0x00fe;
	relocation_cancel_req->header.n_pdu_number = 4;
	relocation_cancel_req->header.next_extension_header_type = 0;

	relocation_cancel_req->imsi.header.type = GTPV1_IE_IMSI;
	relocation_cancel_req->imsi.imsi_number_digits = 272031000000000;
	
	relocation_cancel_req->imei_sv.header.type = GTPV1_IE_IMEI_SV;
	relocation_cancel_req->imei_sv.header.length = 8;
	relocation_cancel_req->imei_sv.imei_sv = 0b0001000100010001000100010001000100100010001000100010001000010001;

	relocation_cancel_req->extended_common_flag.header.type = GTPV1_IE_EXTENDED_COMMON_FLAG;
	relocation_cancel_req->extended_common_flag.header.length = 1;
	relocation_cancel_req->extended_common_flag.uasi = 0;
	relocation_cancel_req->extended_common_flag.bdwi = 0;
	relocation_cancel_req->extended_common_flag.pcri = 0;
	relocation_cancel_req->extended_common_flag.vb = 0;
	relocation_cancel_req->extended_common_flag.retloc = 0;
	relocation_cancel_req->extended_common_flag.cpsr = 0;
	relocation_cancel_req->extended_common_flag.ccrsi = 0;
	relocation_cancel_req->extended_common_flag.unauthenticated_imsi = 0;

	relocation_cancel_req->ext_ranap_cause.header.type = GTPV1_IE_EXTENDED_RANAP_CAUSE;
	relocation_cancel_req->ext_ranap_cause.header.length = 2;
	relocation_cancel_req->ext_ranap_cause.extended_ranap_cause = 2;

	relocation_cancel_req->private_extension.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	relocation_cancel_req->private_extension.header.length = 6;
	relocation_cancel_req->private_extension.extension_identifier = 12;
	strncpy((char *)&relocation_cancel_req->private_extension.extension_value, "2021", 4);

	return;
}

void fill_gtpv1_relocation_cancel_rsp(gtpv1_relocation_cancel_rsp_t *relocation_cancel_rsp){

	relocation_cancel_rsp->header.version = 1;
	relocation_cancel_rsp->header.protocol_type = 1;
	relocation_cancel_rsp->header.spare = 0;
	relocation_cancel_rsp->header.extension_header = 0;
	relocation_cancel_rsp->header.seq_num_flag = 0;
	relocation_cancel_rsp->header.n_pdu_flag = 0;

	relocation_cancel_rsp->header.message_type = GTPV1_RELOCATION_CANCEL_RSP;
	relocation_cancel_rsp->header.message_len = 11;
	relocation_cancel_rsp->header.teid = 0x372f0000;
	relocation_cancel_rsp->header.seq = 0x00fe;
	relocation_cancel_rsp->header.n_pdu_number = 4;
	relocation_cancel_rsp->header.next_extension_header_type = 0;

	relocation_cancel_rsp->cause.header.type = GTPV1_IE_CAUSE;
	relocation_cancel_rsp->cause.cause_value = 128;

	relocation_cancel_rsp->private_extension.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	relocation_cancel_rsp->private_extension.header.length = 6;
	relocation_cancel_rsp->private_extension.extension_identifier = 12;
	strncpy((char *)&relocation_cancel_rsp->private_extension.extension_value, "2021", 4);

	return;
}

void fill_gtpv1_forward_relocation_complete_ack(gtpv1_forward_relocation_complete_ack_t *forward_relocation_complete_ack){

	forward_relocation_complete_ack->header.version = 1;
	forward_relocation_complete_ack->header.protocol_type = 1;
	forward_relocation_complete_ack->header.spare = 0;
	forward_relocation_complete_ack->header.extension_header = 0;
	forward_relocation_complete_ack->header.seq_num_flag = 0;
	forward_relocation_complete_ack->header.n_pdu_flag = 0;
	forward_relocation_complete_ack->header.message_type = GTPV1_FORWARD_RELOCATION_COMPLETE_ACK;
	forward_relocation_complete_ack->header.message_len = 11;
	forward_relocation_complete_ack->header.teid = 0x372f0000;
	forward_relocation_complete_ack->header.seq = 0x00fe;
	forward_relocation_complete_ack->header.n_pdu_number = 4;
	forward_relocation_complete_ack->header.next_extension_header_type = 0;

	forward_relocation_complete_ack->cause.header.type = GTPV1_IE_CAUSE;
	forward_relocation_complete_ack->cause.cause_value = 128;

	forward_relocation_complete_ack->private_extension.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	forward_relocation_complete_ack->private_extension.header.length = 6;
	forward_relocation_complete_ack->private_extension.extension_identifier = 12;
	strncpy((char *)&forward_relocation_complete_ack->private_extension.extension_value, "2021", 4);

	return;
}

void fill_gtpv1_forward_srns_context_ack(gtpv1_forward_srns_context_ack_t *forward_srns_context_ack){

	forward_srns_context_ack->header.version = 1;
	forward_srns_context_ack->header.protocol_type = 1;
	forward_srns_context_ack->header.spare = 0;
	forward_srns_context_ack->header.extension_header = 0;
	forward_srns_context_ack->header.seq_num_flag = 0;
	forward_srns_context_ack->header.n_pdu_flag = 0;
	forward_srns_context_ack->header.message_type = GTPV1_FORWARD_SRNS_CONTEXT_ACK;
	forward_srns_context_ack->header.message_len = 11;
	forward_srns_context_ack->header.teid = 0x372f0000;
	forward_srns_context_ack->header.seq = 0x00fe;
	forward_srns_context_ack->header.n_pdu_number = 4;
	forward_srns_context_ack->header.next_extension_header_type = 0;

	forward_srns_context_ack->cause.header.type = GTPV1_IE_CAUSE;
	forward_srns_context_ack->cause.cause_value = 128;

	forward_srns_context_ack->private_extension.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	forward_srns_context_ack->private_extension.header.length = 6;
	forward_srns_context_ack->private_extension.extension_identifier = 12;
	strncpy((char *)&forward_srns_context_ack->private_extension.extension_value, "2021", 4);

	return;
}

void fill_gtpv1_forward_srns_ctxt(gtpv1_forward_srns_ctxt_t *forward_srns_ctxt){

	forward_srns_ctxt->header.version = 1;
	forward_srns_ctxt->header.protocol_type = 1;
	forward_srns_ctxt->header.spare = 0;
	forward_srns_ctxt->header.extension_header = 0;
	forward_srns_ctxt->header.seq_num_flag = 0;
	forward_srns_ctxt->header.n_pdu_flag = 0;

	forward_srns_ctxt->header.message_type = GTPV1_FORWARD_SRNS_CONTEXT;
	forward_srns_ctxt->header.message_len = 36;
	forward_srns_ctxt->header.teid = 0x372f0000;
	forward_srns_ctxt->header.seq = 0x00fe;
	forward_srns_ctxt->header.n_pdu_number = 4;
	forward_srns_ctxt->header.next_extension_header_type = 0;

	forward_srns_ctxt->rab_context.header.type = GTPV1_IE_RAB_CONTEXT;
	forward_srns_ctxt->rab_context.spare = 0;
	forward_srns_ctxt->rab_context.nsapi = 1;
	forward_srns_ctxt->rab_context.dl_gtp_u_sequence_number = 1;
	forward_srns_ctxt->rab_context.ul_gtp_u_sequence_number = 2;
	forward_srns_ctxt->rab_context.dl_pdcp_sequence_number = 1;
	forward_srns_ctxt->rab_context.ul_pdcp_sequence_number = 2;

	forward_srns_ctxt->pdcp_ctxt.header.type = GTPV1_IE_SRC_RNC_PDCP_CTXT_INFO;
	forward_srns_ctxt->pdcp_ctxt.header.length = 2;
	strncpy((char *)&forward_srns_ctxt->pdcp_ctxt.rrc_container,"11",2);

	forward_srns_ctxt->pdu_num.header.type = GTPV1_IE_PDU_NUMBERS;
	forward_srns_ctxt->pdu_num.header.length = 9;
	forward_srns_ctxt->pdu_num.spare = 0;
	forward_srns_ctxt->pdu_num.nsapi = 1;
	forward_srns_ctxt->pdu_num.dl_gtpu_seqn_nbr = 1;
	forward_srns_ctxt->pdu_num.ul_gtpu_seqn_nbr = 2;
	forward_srns_ctxt->pdu_num.snd_npdu_nbr = 1;
	forward_srns_ctxt->pdu_num.rcv_npdu_nbr = 2;

	forward_srns_ctxt->private_extension.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	forward_srns_ctxt->private_extension.header.length = 6;
	forward_srns_ctxt->private_extension.extension_identifier = 12;
	strncpy((char *)&forward_srns_ctxt->private_extension.extension_value, "2021", 4);

	return;
}

void fill_gtpv1_ran_info_relay(gtpv1_ran_info_relay_t *ran_info_relay){

	ran_info_relay->header.version = 1;
	ran_info_relay->header.protocol_type = 1;
	ran_info_relay->header.spare = 0;
	ran_info_relay->header.extension_header = 0;
	ran_info_relay->header.seq_num_flag = 0;
	ran_info_relay->header.n_pdu_flag = 0;
	ran_info_relay->header.message_type = GTPV1_RAN_INFO_RELAY;
	ran_info_relay->header.message_len = 23;
	ran_info_relay->header.teid = 0x372f0000;
	ran_info_relay->header.seq = 0x00fe;
	ran_info_relay->header.n_pdu_number = 4;
	ran_info_relay->header.next_extension_header_type = 0;

	ran_info_relay->ran_transparent_container.header.type = GTPV1_IE_RAN_TRANSPARENT_CONTAINER;
	ran_info_relay->ran_transparent_container.header.length = 2;
	strncpy((char *)&ran_info_relay->ran_transparent_container.rtc_field,"11",2);

	ran_info_relay->rim_addr.header.type = GTPV1_IE_RIM_ROUTING_ADDR;
	ran_info_relay->rim_addr.header.length = 2;
	strncpy((char *)&ran_info_relay->rim_addr.rim_routing_addr,"11",2);

	ran_info_relay->rim_addr_disc.header.type = GTPV1_IE_RIM_ROUTING_ADDR_DISCRIMINATOR;
	ran_info_relay->rim_addr_disc.header.length = 1;
	ran_info_relay->rim_addr_disc.spare = 0;
	ran_info_relay->rim_addr_disc.discriminator = 2;

	ran_info_relay->private_extension.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	ran_info_relay->private_extension.header.length = 6;
	ran_info_relay->private_extension.extension_identifier = 12;
	strncpy((char *)&ran_info_relay->private_extension.extension_value, "2021", 4);

	return;
}

void fill_gtpv1_mbms_notification_req(gtpv1_mbms_notification_req_t *mbms_notification_req) {

	mbms_notification_req->header.version = 1;
	mbms_notification_req->header.protocol_type = 1;
	mbms_notification_req->header.spare = 0;
	mbms_notification_req->header.extension_header = 0;
	mbms_notification_req->header.seq_num_flag = 0;
	mbms_notification_req->header.n_pdu_flag = 0;

	mbms_notification_req->header.message_type = GTPV1_MBMS_NOTIFICATION_REQ;
	mbms_notification_req->header.message_len = 57;
	mbms_notification_req->header.teid = 0x372f0000;
	mbms_notification_req->header.seq = 0x00fe;
	mbms_notification_req->header.n_pdu_number = 4;
	mbms_notification_req->header.next_extension_header_type = 0;

	mbms_notification_req->imsi.header.type = GTPV1_IE_IMSI;
	mbms_notification_req->imsi.imsi_number_digits = 272031000000000;

	mbms_notification_req->tunn_endpt_idnt_control_plane.header.type = GTPV1_IE_TEID_CONTROL_PLANE;
	mbms_notification_req->tunn_endpt_idnt_control_plane.teid = 0x00ab;

	mbms_notification_req->nsapi.header.type = GTPV1_IE_NSAPI;
	mbms_notification_req->nsapi.spare = 0;
	mbms_notification_req->nsapi.nsapi_value = 5;

	mbms_notification_req->end_user_address.header.type = GTPV1_IE_END_USER_ADDR;
	mbms_notification_req->end_user_address.header.length =6;
	mbms_notification_req->end_user_address.spare = 0xf;
	mbms_notification_req->end_user_address.pdp_type_org =1;
	mbms_notification_req->end_user_address.pdp_type_number = 0x21;
	mbms_notification_req->end_user_address.pdp_address.ipv4 = 355240599;

	mbms_notification_req->apn.header.type = GTPV1_IE_APN;
	mbms_notification_req->apn.header.length = 13;
	strncpy((char *)&mbms_notification_req->apn.apn_value,"nextphones.co",13);

	mbms_notification_req->ggsn_addr_control_plane.header.type = GTPV1_IE_GSN_ADDR;
	mbms_notification_req->ggsn_addr_control_plane.header.length = 4;
	mbms_notification_req->ggsn_addr_control_plane.gsn_address.ipv4 = 3232235564;

	/* DATA NOT DECODED
	mbms_notification_req->mbms_protocol.header.type = GTPV1_IE_MBMS_PROTOCOL_CONFIG_OPTIONS;
	mbms_notification_req->mbms_protocol.header.length = 2;
	strncpy((char *)&mbms_notification_req->mbms_protocol.mbms_protocol_configuration,"11",2);
	*/

	mbms_notification_req->private_extension.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	mbms_notification_req->private_extension.header.length = 6;
	mbms_notification_req->private_extension.extension_identifier = 12;
	strncpy((char *)&mbms_notification_req->private_extension.extension_value, "2021", 4);

	return;
}

void fill_gtpv1_mbms_notification_rsp(gtpv1_mbms_notification_rsp_t *mbms_notification_rsp){

	mbms_notification_rsp->header.version = 1;
	mbms_notification_rsp->header.protocol_type = 1;
	mbms_notification_rsp->header.spare = 0;
	mbms_notification_rsp->header.extension_header = 0;
	mbms_notification_rsp->header.seq_num_flag = 0;
	mbms_notification_rsp->header.n_pdu_flag = 0;

	mbms_notification_rsp->header.message_type = GTPV1_MBMS_NOTIFICATION_RSP;
	mbms_notification_rsp->header.message_len = 11;
	mbms_notification_rsp->header.teid = 0x372f0000;
	mbms_notification_rsp->header.seq = 0x00fe;
	mbms_notification_rsp->header.n_pdu_number = 4;
	mbms_notification_rsp->header.next_extension_header_type = 0;

	mbms_notification_rsp->cause.header.type = GTPV1_IE_CAUSE;
	mbms_notification_rsp->cause.cause_value = 128;

	mbms_notification_rsp->private_extension.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	mbms_notification_rsp->private_extension.header.length = 6;
	mbms_notification_rsp->private_extension.extension_identifier = 12;
	strncpy((char *)&mbms_notification_rsp->private_extension.extension_value, "2021", 4);

	return;
}

void fill_gtpv1_ms_info_change_notification_req(gtpv1_ms_info_change_notification_req_t *ms_info_change_notification_req) {

	ms_info_change_notification_req->header.version = 1;
	ms_info_change_notification_req->header.protocol_type = 1;
	ms_info_change_notification_req->header.spare = 0;
	ms_info_change_notification_req->header.extension_header = 0;
	ms_info_change_notification_req->header.seq_num_flag = 0;
	ms_info_change_notification_req->header.n_pdu_flag = 0;
	ms_info_change_notification_req->header.message_type = GTPV1_MS_INFO_CHANGE_NOTIFICATION_REQ;
	ms_info_change_notification_req->header.message_len = 61;
	ms_info_change_notification_req->header.teid = 0x372f0000;
	ms_info_change_notification_req->header.seq = 0x00fe;
	ms_info_change_notification_req->header.n_pdu_number = 4;
	ms_info_change_notification_req->header.next_extension_header_type = 0;

	ms_info_change_notification_req->imsi.header.type = GTPV1_IE_IMSI;
	ms_info_change_notification_req->imsi.imsi_number_digits = 272031000000000;

	ms_info_change_notification_req->linked_nsapi.header.type = GTPV1_IE_NSAPI;
	ms_info_change_notification_req->linked_nsapi.spare = 0;
	ms_info_change_notification_req->linked_nsapi.nsapi_value = 9;

	ms_info_change_notification_req->rat_type.header.type = GTPV1_IE_RAT_TYPE;
	ms_info_change_notification_req->rat_type.header.length = 1;
	ms_info_change_notification_req->rat_type.rat_type = 2;

	ms_info_change_notification_req->user_location_information.header.type = GTPV1_IE_USER_LOCATION_INFORMATION;
	ms_info_change_notification_req->user_location_information.header.length = 8;
	ms_info_change_notification_req->user_location_information.geographic_location_type = 1;
	ms_info_change_notification_req->user_location_information.mcc_digit_2 = 0x0;
	ms_info_change_notification_req->user_location_information.mcc_digit_1 = 0x4;
	ms_info_change_notification_req->user_location_information.mnc_digit_3 = 0x8;
	ms_info_change_notification_req->user_location_information.mcc_digit_3 = 0x4;
	ms_info_change_notification_req->user_location_information.mnc_digit_2 = 0x7;
	ms_info_change_notification_req->user_location_information.mnc_digit_1 = 0x0;
	ms_info_change_notification_req->user_location_information.lac = 0x1;
	ms_info_change_notification_req->user_location_information.ci_sac_rac = 0x1;

	ms_info_change_notification_req->imei_sv.header.type = GTPV1_IE_IMEI_SV;
	ms_info_change_notification_req->imei_sv.header.length = 8;
	ms_info_change_notification_req->imei_sv.imei_sv = 0b0001000100010001000100010001000100100010001000100010001000010001;

	ms_info_change_notification_req->extended_common_flag.header.type = GTPV1_IE_EXTENDED_COMMON_FLAG;
	ms_info_change_notification_req->extended_common_flag.header.length = 1;
	ms_info_change_notification_req->extended_common_flag.uasi = 0;
	ms_info_change_notification_req->extended_common_flag.bdwi = 0;
	ms_info_change_notification_req->extended_common_flag.pcri = 0;
	ms_info_change_notification_req->extended_common_flag.vb = 0;
	ms_info_change_notification_req->extended_common_flag.retloc = 0;
	ms_info_change_notification_req->extended_common_flag.cpsr = 0;
	ms_info_change_notification_req->extended_common_flag.ccrsi = 0;

	ms_info_change_notification_req->user_csg_information.header.type = GTPV1_IE_USER_CSG_INFORMATION;
	ms_info_change_notification_req->user_csg_information.header.length = 8;
	ms_info_change_notification_req->user_csg_information.mcc_digit_2 = 0x0;
	ms_info_change_notification_req->user_csg_information.mcc_digit_1 = 0x4;
	ms_info_change_notification_req->user_csg_information.mnc_digit_3 = 0x8;
	ms_info_change_notification_req->user_csg_information.mcc_digit_3 = 0x4;
	ms_info_change_notification_req->user_csg_information.mnc_digit_2 = 0x7;
	ms_info_change_notification_req->user_csg_information.mnc_digit_1 = 0x0;	
	ms_info_change_notification_req->user_csg_information.spare = 0;
	ms_info_change_notification_req->user_csg_information.csg_id = 1;
	ms_info_change_notification_req->user_csg_information.csg_id_II = 1;
	ms_info_change_notification_req->user_csg_information.access_mode = 1;
	ms_info_change_notification_req->user_csg_information.spare2 = 0;
	ms_info_change_notification_req->user_csg_information.cmi = 1;

	ms_info_change_notification_req->private_extension.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	ms_info_change_notification_req->private_extension.header.length = 6;
	ms_info_change_notification_req->private_extension.extension_identifier = 12;
	strncpy((char *)&ms_info_change_notification_req->private_extension.extension_value, "2021", 4);

	return;
}

void fill_gtpv1_ms_info_change_notification_rsp(gtpv1_ms_info_change_notification_rsp_t *ms_info_change_notification_rsp){

	ms_info_change_notification_rsp->header.version = 1;
	ms_info_change_notification_rsp->header.protocol_type = 1;
	ms_info_change_notification_rsp->header.spare = 0;
	ms_info_change_notification_rsp->header.extension_header = 0;
	ms_info_change_notification_rsp->header.seq_num_flag = 0;
	ms_info_change_notification_rsp->header.n_pdu_flag = 0;
	ms_info_change_notification_rsp->header.message_type = GTPV1_MS_INFO_CHANGE_NOTIFICATION_RSP;
	ms_info_change_notification_rsp->header.message_len = 41;
	ms_info_change_notification_rsp->header.teid = 0x372f0000;
	ms_info_change_notification_rsp->header.seq = 0x00fe;
	ms_info_change_notification_rsp->header.n_pdu_number = 4;
	ms_info_change_notification_rsp->header.next_extension_header_type = 0;

	ms_info_change_notification_rsp->cause.header.type = GTPV1_IE_CAUSE;
	ms_info_change_notification_rsp->cause.cause_value = 128;

	ms_info_change_notification_rsp->imsi.header.type = GTPV1_IE_IMSI;
	ms_info_change_notification_rsp->imsi.imsi_number_digits = 272031000000000;

	ms_info_change_notification_rsp->linked_nsapi.header.type = GTPV1_IE_NSAPI;
	ms_info_change_notification_rsp->linked_nsapi.spare = 0;
	ms_info_change_notification_rsp->linked_nsapi.nsapi_value = 9;

	ms_info_change_notification_rsp->imei_sv.header.type = GTPV1_IE_IMEI_SV;
	ms_info_change_notification_rsp->imei_sv.header.length = 8;
	ms_info_change_notification_rsp->imei_sv.imei_sv = 0b0001000100010001000100010001000100100010001000100010001000010001;

	ms_info_change_notification_rsp->ms_info_change_reporting_action.header.type = GTPV1_IE_MS_INFO_CHANGE_REPORTING_ACTION;
	ms_info_change_notification_rsp->ms_info_change_reporting_action.header.length = 1;
	ms_info_change_notification_rsp->ms_info_change_reporting_action.action = 4;

	ms_info_change_notification_rsp->csg_information_reporting_action.header.type = GTPV1_IE_CSG_INFORMATION_REPORTING_ACTION;
	ms_info_change_notification_rsp->csg_information_reporting_action.header.length = 1;
	ms_info_change_notification_rsp->csg_information_reporting_action.spare = 0;
	ms_info_change_notification_rsp->csg_information_reporting_action.ucuhc = 1;
	ms_info_change_notification_rsp->csg_information_reporting_action.ucshc = 1;
	ms_info_change_notification_rsp->csg_information_reporting_action.uccsg = 1;

	ms_info_change_notification_rsp->private_extension.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	ms_info_change_notification_rsp->private_extension.header.length = 6;
	ms_info_change_notification_rsp->private_extension.extension_identifier = 12;
	strncpy((char *)&ms_info_change_notification_rsp->private_extension.extension_value, "2021", 4);

	return;
}
