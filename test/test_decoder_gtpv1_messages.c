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

#include "test_decoder_gtpv1_messages.h"

void test_decode_gtpv1_echo_req(void)
{
	gtpv1_echo_req_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x01, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00,
		0xff, 0x00, 0x06, 0x00, 0x0c, 0x32, 0x30, 0x32, 0x31};

	CU_ASSERT(decode_gtpv1_echo_req(buf, &decode) == 17);
	CU_ASSERT(decode_gtpv1_echo_req(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_echo_req(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_echo_req(buf, NULL) == -1);

	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);

	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_ECHO_REQUEST);
	CU_ASSERT_EQUAL(decode.header.message_len, 9);
	CU_ASSERT_EQUAL(decode.header.teid, 0);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.private_extension.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.private_extension.header.length, 6);
	CU_ASSERT_EQUAL(decode.private_extension.extension_identifier, 12);
	CU_ASSERT_NSTRING_EQUAL(decode.private_extension.extension_value, "2021",4);
}

void test_decode_gtpv1_echo_rsp(void)
{
	gtpv1_echo_rsp_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x02, 0x00, 0x0b, 0x37, 0x2f, 0x00, 0x00,
		0x0e, 0x02, 0xff, 0x00, 0x06, 0x00, 0x0c, 0x32, 0x30, 0x32,
		0x31};

	CU_ASSERT(decode_gtpv1_echo_rsp(buf, &decode) == 19);
	CU_ASSERT(decode_gtpv1_echo_rsp(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_echo_rsp(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_echo_rsp(buf, NULL) == -1);

	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);

	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_ECHO_RESPONSE);
	CU_ASSERT_EQUAL(decode.header.message_len, 11);
	CU_ASSERT_EQUAL(decode.header.teid, 0x372f0000);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.recovery.header.type, GTPV1_IE_RECOVERY);
	CU_ASSERT_EQUAL(decode.recovery.restart_counter, 2);

	CU_ASSERT_EQUAL(decode.private_extension.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.private_extension.header.length, 6);
	CU_ASSERT_EQUAL(decode.private_extension.extension_identifier, 12);
	CU_ASSERT_NSTRING_EQUAL(decode.private_extension.extension_value, "2021", 4);
}

void test_decode_gtpv1_version_not_supported(void)
{
	gtpv1_version_not_supported_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	CU_ASSERT(decode_gtpv1_version_not_supported(buf, &decode) == 8);
	CU_ASSERT(decode_gtpv1_version_not_supported(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_version_not_supported(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_version_not_supported(buf, NULL) == -1);

	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);

	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_VERSION_NOT_SUPPORTED);
	CU_ASSERT_EQUAL(decode.header.message_len, 0);
	CU_ASSERT_EQUAL(decode.header.teid, 0);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);
}

void test_decode_gtpv1_supported_extension_headers_notification(void)
{
	gtpv1_supported_extension_headers_notification_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x1f, 0x00, 0x04, 0x37, 0x2f, 0x00, 0x00,
		0x8d, 0x02, 0x01, 0x00};

	CU_ASSERT(decode_gtpv1_supported_extension_headers_notification(buf, &decode) == 12);
	CU_ASSERT(decode_gtpv1_supported_extension_headers_notification(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_supported_extension_headers_notification(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_supported_extension_headers_notification(buf, NULL) == -1);

	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);

	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_SUPPORTED_EXTENSION_HEADERS_NOTIFICATION);
	CU_ASSERT_EQUAL(decode.header.message_len, 4);
	CU_ASSERT_EQUAL(decode.header.teid, 0x372f0000);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.ext_header_list.type, GTPV1_IE_EXTENSION_HEADER_TYPE_LIST);
	CU_ASSERT_EQUAL(decode.ext_header_list.length, 2);
	CU_ASSERT_EQUAL(decode.ext_header_list.extension_type_list[0], 1);
	CU_ASSERT_EQUAL(decode.ext_header_list.extension_type_list[1], 0);
}

void test_decode_gtpv1_create_pdp_ctxt_req(void)
{
	gtpv1_create_pdp_ctxt_req_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x10, 0x01, 0x22, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x72, 0x02, 0x13, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x0f,
		0x01, 0x14, 0x05, 0x10, 0x00, 0xff, 0xfe, 0xee, 0x11, 0x00,
		0x00, 0x00, 0xab, 0x14, 0x09, 0x1a, 0x00, 0x01, 0x80, 0x00,
		0x06, 0xf1, 0x21, 0xc0, 0xa8, 0x00, 0x2c, 0x84, 0x00, 0x19,
		0x81, 0x00, 0x02, 0x09, 0x33, 0x35, 0x35, 0x32, 0x34, 0x30,
		0x35, 0x39, 0x39, 0x00, 0x02, 0x09, 0x33, 0x35, 0x35, 0x32,
		0x34, 0x30, 0x35, 0x38, 0x39, 0x83, 0x00, 0x0d, 0x6e, 0x65,
		0x78, 0x74, 0x70, 0x68, 0x6f, 0x6e, 0x65, 0x73, 0x2e, 0x63,
		0x6f, 0x85, 0x00, 0x04, 0xc0, 0xa8, 0x00, 0x2c, 0x85, 0x00,
		0x04, 0xc0, 0xa8, 0x00, 0x2c, 0x86, 0x00, 0x02, 0x32, 0x32,
		0x87, 0x00, 0x15, 0x02,	0x12, 0x31, 0x04, 0x2a, 0x03, 0x7b,
		0xfe, 0x11, 0x06, 0x7a, 0xde, 0x11, 0xfa, 0x0b, 0x21, 0x16,
		0x2c, 0x21, 0x22, 0x17, 0x89, 0x00, 0x13, 0x32, 0x15, 0x01,
		0x01, 0x01, 0x25, 0x01, 0x02, 0x01, 0x00, 0x01, 0x02, 0x01,
		0x02, 0x01, 0x03, 0x03, 0x02, 0x00, 0x9a, 0x00, 0x08, 0x11,
		0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x11, 0x97, 0x00, 0x01,
		0x02, 0x03, 0x04, 0xf4, 0x87, 0x00, 0x14, 0x14, 0x1b, 0x00,
		0x09, 0x1c, 0x00, 0x09, 0x8e, 0x00, 0x05, 0x32, 0x32, 0x32,
		0x32, 0x32, 0x8f, 0x00, 0x07, 0x61, 0x62, 0x63, 0x2e, 0x63,
		0x6f, 0x6d, 0x98, 0x00, 0x08, 0x01, 0x04, 0xf4, 0x87, 0x00,
		0x01, 0x00, 0x01, 0x99, 0x00, 0x02, 0x01, 0x01, 0xa2, 0x00,
		0x09, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01,
		0xb7, 0x00, 0x01, 0x05, 0xc2, 0x00, 0x08, 0x04, 0xf4, 0x87,
		0x01, 0x00, 0x00, 0x01, 0x41, 0xcb, 0x00, 0x01, 0x01, 0xd8,
		0x00, 0x01, 0x02, 0xdf, 0x00, 0x02, 0x00, 0x02, 0xe0, 0x00,
		0x01, 0x01, 0x0e, 0x02, 0x94, 0x00, 0x01, 0xff, 0x95, 0x00,
		0x01, 0x0c, 0xbf, 0x00, 0x01, 0x71, 0xc1, 0x00, 0x01, 0xff,
		0xc6, 0x00, 0x08, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00,
		0x07, 0xff, 0x00, 0x06, 0x00, 0x0c, 0x32, 0x30, 0x32, 0x31};

	CU_ASSERT(decode_gtpv1_create_pdp_ctxt_req(buf, &decode) == 298);
	CU_ASSERT(decode_gtpv1_create_pdp_ctxt_req(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_create_pdp_ctxt_req(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_create_pdp_ctxt_req(buf, NULL) == -1);
	
	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);

	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_CREATE_PDP_CTXT_REQ);
	CU_ASSERT_EQUAL(decode.header.message_len, 290);
	CU_ASSERT_EQUAL(decode.header.teid, 0);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.imsi.header.type, GTPV1_IE_IMSI);
	CU_ASSERT_EQUAL(decode.imsi.imsi_number_digits, 272031000000000);

	CU_ASSERT_EQUAL(decode.routing_area_identity.header.type, GTPV1_IE_ROUTEING_AREA_IDENTITY);
	CU_ASSERT_EQUAL(decode.routing_area_identity.rai_value.mcc_digit_2, 0x0);
	CU_ASSERT_EQUAL(decode.routing_area_identity.rai_value.mcc_digit_1, 0x4);
	CU_ASSERT_EQUAL(decode.routing_area_identity.rai_value.mnc_digit_3, 0x8);
	CU_ASSERT_EQUAL(decode.routing_area_identity.rai_value.mcc_digit_3, 0x4);
	CU_ASSERT_EQUAL(decode.routing_area_identity.rai_value.mnc_digit_2, 0x7);
	CU_ASSERT_EQUAL(decode.routing_area_identity.rai_value.mnc_digit_1, 0x0);
	CU_ASSERT_EQUAL(decode.routing_area_identity.rai_value.lac, 0x14);
	CU_ASSERT_EQUAL(decode.routing_area_identity.rai_value.rac, 0x14);

	CU_ASSERT_EQUAL(decode.recovery.header.type, GTPV1_IE_RECOVERY);
	CU_ASSERT_EQUAL(decode.recovery.restart_counter, 2);

	CU_ASSERT_EQUAL(decode.selection_mode.header.type, GTPV1_IE_SELECTION_MODE);
	CU_ASSERT_EQUAL(decode.selection_mode.spare2, 0);
	CU_ASSERT_EQUAL(decode.selection_mode.selec_mode, 1);

	CU_ASSERT_EQUAL(decode.tunn_endpt_idnt_data_1.header.type, GTPV1_IE_TEID_DATA_1);
	CU_ASSERT_EQUAL(decode.tunn_endpt_idnt_data_1.teid, 0x0fffeee);

	CU_ASSERT_EQUAL(decode.tunn_endpt_idnt_control_plane.header.type, GTPV1_IE_TEID_CONTROL_PLANE);
	CU_ASSERT_EQUAL(decode.tunn_endpt_idnt_control_plane.teid, 0x00ab);
	
	CU_ASSERT_EQUAL(decode.nsapi.header.type, GTPV1_IE_NSAPI);
	CU_ASSERT_EQUAL(decode.nsapi.spare, 0);
	CU_ASSERT_EQUAL(decode.nsapi.nsapi_value, 5);
	
	CU_ASSERT_EQUAL(decode.linked_nsapi.header.type, GTPV1_IE_NSAPI);
	CU_ASSERT_EQUAL(decode.linked_nsapi.spare, 0);
	CU_ASSERT_EQUAL(decode.linked_nsapi.nsapi_value, 9);
	
	CU_ASSERT_EQUAL(decode.chrgng_char.header.type, GTPV1_IE_CHRGNG_CHAR);
	CU_ASSERT_EQUAL(decode.chrgng_char.chrgng_char_val, 1);
		
	CU_ASSERT_EQUAL(decode.trace_reference.header.type, GTPV1_IE_TRACE_REFERENCE);
	CU_ASSERT_EQUAL(decode.trace_reference.trace_reference, 9);

	CU_ASSERT_EQUAL(decode.trace_type.header.type, GTPV1_IE_TRACE_TYPE);
	CU_ASSERT_EQUAL(decode.trace_type.trace_type, 9);
		
	CU_ASSERT_EQUAL(decode.end_user_address.header.type, GTPV1_IE_END_USER_ADDR);
	CU_ASSERT_EQUAL(decode.end_user_address.header.length, 6);
	CU_ASSERT_EQUAL(decode.end_user_address.spare, 0xf);
	CU_ASSERT_EQUAL(decode.end_user_address.pdp_type_org, 1);
	CU_ASSERT_EQUAL(decode.end_user_address.pdp_type_number, 0x21);
	CU_ASSERT_EQUAL(decode.end_user_address.pdp_address.ipv4, 3232235564);
	
	CU_ASSERT_EQUAL(decode.apn.header.type, GTPV1_IE_APN);
	CU_ASSERT_EQUAL(decode.apn.header.length, 13);
	CU_ASSERT_NSTRING_EQUAL(decode.apn.apn_value,"nextphones.co", 13);

	CU_ASSERT_EQUAL(decode.protocol_config_options.header.type, GTPV1_IE_PROTOCOL_CONFIG_OPTIONS);
	CU_ASSERT_EQUAL(decode.protocol_config_options.header.length, 25);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_flag_ext , 1);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_flag_spare , 0);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_cfg_proto , 1);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content_count , 2);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[0].prot_or_cont_id , 2);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[0].length , 9);
	CU_ASSERT_STRING_EQUAL(decode.protocol_config_options.pco.pco_content[0].content,"355240599");
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[1].prot_or_cont_id , 2);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[1].length , 9);
	CU_ASSERT_STRING_EQUAL(decode.protocol_config_options.pco.pco_content[1].content,"355240589");

	CU_ASSERT_EQUAL(decode.sgsn_address_for_signalling.header.type, GTPV1_IE_GSN_ADDR);
	CU_ASSERT_EQUAL(decode.sgsn_address_for_signalling.header.length, 4);
	CU_ASSERT_EQUAL(decode.sgsn_address_for_signalling.gsn_address.ipv4, 3232235564);

	CU_ASSERT_EQUAL(decode.sgsn_address_for_user_traffic.header.type, GTPV1_IE_GSN_ADDR);
	CU_ASSERT_EQUAL(decode.sgsn_address_for_user_traffic.header.length, 4);
	CU_ASSERT_EQUAL(decode.sgsn_address_for_user_traffic.gsn_address.ipv4, 3232235564);

	CU_ASSERT_EQUAL(decode.msisdn.header.type, GTPV1_IE_MSISDN);
	CU_ASSERT_EQUAL(decode.msisdn.header.length, 2);
	CU_ASSERT_NSTRING_EQUAL(decode.msisdn.msisdn_number_digits, "22", 2);
	
	CU_ASSERT_EQUAL(decode.qos_profile.header.type, GTPV1_IE_QOS);
	CU_ASSERT_EQUAL(decode.qos_profile.header.length, 21);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.allocation_retention_priority, 2);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.spare1, 0);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.delay_class, 2);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.reliablity_class, 2);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.peak_throughput, 3);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.spare2, 0);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.precedence_class, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.spare3, 0);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.mean_throughput, 4);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.traffic_class, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.delivery_order, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.delivery_erroneous_sdu, 2);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_sdu_size, 3);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_uplink, 123);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_downlink, 254);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.residual_ber, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.sdu_error_ratio, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.transfer_delay, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.traffic_handling_priority, 2);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_uplink, 122);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_downlink, 222);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.spare4, 0);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.signalling_indication, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.source_statistics_descriptor, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_downlink_ext1, 250);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_downlink_ext1, 11);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_uplink_ext1, 33);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_uplink_ext1, 22);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_downlink_ext2, 44);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_downlink_ext2, 33);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_uplink_ext2, 34);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_uplink_ext2, 23);	

	CU_ASSERT_EQUAL(decode.tft.header.type, GTPV1_IE_TFT);
	CU_ASSERT_EQUAL(decode.tft.header.length, 19);
	CU_ASSERT_EQUAL(decode.tft.tft_op_code, 1);
	CU_ASSERT_EQUAL(decode.tft.e_bit, 1);
	CU_ASSERT_EQUAL(decode.tft.no_packet_filters, 2);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_del[0].spare, 0);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_del[0].filter_id, 0);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_del[1].spare, 0);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_del[1].filter_id, 0);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[0].spare, 0);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[0].filter_direction, 1);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[0].filter_id, 5);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[0].filter_eval_precedence, 1);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[0].filter_content_length, 1);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[0].filter_content[0], 1);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[1].spare, 0);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[1].filter_direction, 2);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[1].filter_id, 5);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[1].filter_eval_precedence, 1);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[1].filter_content_length, 2);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[1].filter_content[0], 1);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[1].filter_content[1], 0);
	CU_ASSERT_EQUAL(decode.tft.parameters_list[0].parameter_id, 1);
	CU_ASSERT_EQUAL(decode.tft.parameters_list[0].parameter_content_length, 2);
	CU_ASSERT_EQUAL(decode.tft.parameters_list[0].parameter_content[0], 1);
	CU_ASSERT_EQUAL(decode.tft.parameters_list[0].parameter_content[1], 2);
	CU_ASSERT_EQUAL(decode.tft.parameters_list[1].parameter_id, 1);
	CU_ASSERT_EQUAL(decode.tft.parameters_list[1].parameter_content_length, 3);
	CU_ASSERT_EQUAL(decode.tft.parameters_list[1].parameter_content[0], 3);
	CU_ASSERT_EQUAL(decode.tft.parameters_list[1].parameter_content[1], 2);
	CU_ASSERT_EQUAL(decode.tft.parameters_list[1].parameter_content[2], 0);

	CU_ASSERT_EQUAL(decode.trigger_id.header.type, GTPV1_IE_TRIGGER_ID);
	CU_ASSERT_EQUAL(decode.trigger_id.header.length, 5);
	CU_ASSERT_NSTRING_EQUAL(decode.trigger_id.trigger_id,"22222", 5);

	CU_ASSERT_EQUAL(decode.omc_identity.header.type, GTPV1_IE_OMC_IDENTITY);
	CU_ASSERT_EQUAL(decode.omc_identity.header.length, 7);
	CU_ASSERT_NSTRING_EQUAL(decode.omc_identity.omc_identity,"abc.com", 7);
	
	CU_ASSERT_EQUAL(decode.common_flag.header.type, GTPV1_IE_COMMON_FLAG);
	CU_ASSERT_EQUAL(decode.common_flag.header.length, 1);
	CU_ASSERT_EQUAL(decode.common_flag.dual_addr_bearer_flag, 1);
	CU_ASSERT_EQUAL(decode.common_flag.upgrade_qos_supported, 1);
	CU_ASSERT_EQUAL(decode.common_flag.nrsn, 1);
	CU_ASSERT_EQUAL(decode.common_flag.no_qos_negotiation, 1);
	CU_ASSERT_EQUAL(decode.common_flag.mbms_counting_information, 1);
	CU_ASSERT_EQUAL(decode.common_flag.ran_procedures_ready, 1);
	CU_ASSERT_EQUAL(decode.common_flag.mbms_service_type, 1);
	CU_ASSERT_EQUAL(decode.common_flag.prohibit_payload_compression, 1);
	
	CU_ASSERT_EQUAL(decode.apn_restriction.header.type, GTPV1_IE_APN_RESTRICTION);
	CU_ASSERT_EQUAL(decode.apn_restriction.header.length, 1);
	CU_ASSERT_EQUAL(decode.apn_restriction.restriction_type_value, 12);
	
	CU_ASSERT_EQUAL(decode.rat_type.header.type, GTPV1_IE_RAT_TYPE);
	CU_ASSERT_EQUAL(decode.rat_type.header.length, 1);
	CU_ASSERT_EQUAL(decode.rat_type.rat_type, 2);
	
	CU_ASSERT_EQUAL(decode.user_location_information.header.type, GTPV1_IE_USER_LOCATION_INFORMATION);
	CU_ASSERT_EQUAL(decode.user_location_information.header.length, 8);
	CU_ASSERT_EQUAL(decode.user_location_information.geographic_location_type, 1);
	CU_ASSERT_EQUAL(decode.user_location_information.mcc_digit_2, 0x0);
	CU_ASSERT_EQUAL(decode.user_location_information.mcc_digit_1, 0x4);
	CU_ASSERT_EQUAL(decode.user_location_information.mnc_digit_3, 0x8);
	CU_ASSERT_EQUAL(decode.user_location_information.mcc_digit_3, 0x4);
	CU_ASSERT_EQUAL(decode.user_location_information.mnc_digit_2, 0x7);
	CU_ASSERT_EQUAL(decode.user_location_information.mnc_digit_1, 0x0);
	CU_ASSERT_EQUAL(decode.user_location_information.lac, 0x1);
	CU_ASSERT_EQUAL(decode.user_location_information.ci_sac_rac, 0x1);

	CU_ASSERT_EQUAL(decode.ms_time_zone.header.type, GTPV1_IE_MS_TIME_ZONE);
	CU_ASSERT_EQUAL(decode.ms_time_zone.header.length, 2);
	CU_ASSERT_EQUAL(decode.ms_time_zone.time_zone, 1);
	CU_ASSERT_EQUAL(decode.ms_time_zone.spare, 0);
	CU_ASSERT_EQUAL(decode.ms_time_zone.daylight_saving_time, 1);

	CU_ASSERT_EQUAL(decode.imei_sv.header.type, GTPV1_IE_IMEI_SV);
	CU_ASSERT_EQUAL(decode.imei_sv.header.length, 8);
	CU_ASSERT_EQUAL(decode.imei_sv.imei_sv, 0b0001000100010001000100010001000100100010001000100010001000010001);

	CU_ASSERT_EQUAL(decode.additional_trace_information.header.type, GTPV1_IE_ADDITIONAL_TRACE_INFORMATION);
	CU_ASSERT_EQUAL(decode.additional_trace_information.header.length, 9);
	CU_ASSERT_EQUAL(decode.additional_trace_information.trace_reference_2, 1);
	CU_ASSERT_EQUAL(decode.additional_trace_information.trace_recording_session_reference, 1);
	CU_ASSERT_EQUAL(decode.additional_trace_information.spare1, 0);
	CU_ASSERT_EQUAL(decode.additional_trace_information.triggering_events_in_ggsn_mbms_ctxt, 0);
	CU_ASSERT_EQUAL(decode.additional_trace_information.triggering_events_in_ggsn_pdp_ctxt, 1);
	CU_ASSERT_EQUAL(decode.additional_trace_information.trace_depth, 1);
	CU_ASSERT_EQUAL(decode.additional_trace_information.spare2, 0);
	CU_ASSERT_EQUAL(decode.additional_trace_information.list_of_interfaces_in_ggsn_gmb, 0);
	CU_ASSERT_EQUAL(decode.additional_trace_information.list_of_interfaces_in_ggsn_gi, 0);
	CU_ASSERT_EQUAL(decode.additional_trace_information.list_of_interfaces_in_ggsn_gn, 1);
	CU_ASSERT_EQUAL(decode.additional_trace_information.trace_activity_control, 1);

	CU_ASSERT_EQUAL(decode.correlation_id.header.type, GTPV1_IE_CORRELATION_ID);
	CU_ASSERT_EQUAL(decode.correlation_id.header.length, 1);
	CU_ASSERT_EQUAL(decode.correlation_id.correlation_id, 5);
	
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.header.type, GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_I);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.header.length, 1);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.spare, 0);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.pci, 1);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.pl, 12);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.spare2, 0);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.pvi, 1);
	
	CU_ASSERT_EQUAL(decode.extended_common_flag.header.type, GTPV1_IE_EXTENDED_COMMON_FLAG);
	CU_ASSERT_EQUAL(decode.extended_common_flag.header.length, 1);
	CU_ASSERT_EQUAL(decode.extended_common_flag.uasi, 1);
	CU_ASSERT_EQUAL(decode.extended_common_flag.bdwi, 1);
	CU_ASSERT_EQUAL(decode.extended_common_flag.pcri, 1);
	CU_ASSERT_EQUAL(decode.extended_common_flag.vb, 1);
	CU_ASSERT_EQUAL(decode.extended_common_flag.retloc, 1);
	CU_ASSERT_EQUAL(decode.extended_common_flag.cpsr, 1);
	CU_ASSERT_EQUAL(decode.extended_common_flag.ccrsi, 1);
	CU_ASSERT_EQUAL(decode.extended_common_flag.unauthenticated_imsi, 1);
		
	CU_ASSERT_EQUAL(decode.user_csg_information.header.type, GTPV1_IE_USER_CSG_INFORMATION);
	CU_ASSERT_EQUAL(decode.user_csg_information.header.length, 8);
	CU_ASSERT_EQUAL(decode.user_csg_information.mcc_digit_2, 0x0);
	CU_ASSERT_EQUAL(decode.user_csg_information.mcc_digit_1, 0x4);
	CU_ASSERT_EQUAL(decode.user_csg_information.mnc_digit_3, 0x8);
	CU_ASSERT_EQUAL(decode.user_csg_information.mcc_digit_3, 0x4);
	CU_ASSERT_EQUAL(decode.user_csg_information.mnc_digit_2, 0x7);
	CU_ASSERT_EQUAL(decode.user_csg_information.mnc_digit_1, 0x0);
	CU_ASSERT_EQUAL(decode.user_csg_information.spare, 0);
	CU_ASSERT_EQUAL(decode.user_csg_information.csg_id, 1);
	CU_ASSERT_EQUAL(decode.user_csg_information.csg_id_II, 1);
	CU_ASSERT_EQUAL(decode.user_csg_information.access_mode, 1);
	CU_ASSERT_EQUAL(decode.user_csg_information.spare2, 0);
	CU_ASSERT_EQUAL(decode.user_csg_information.cmi, 1);

	CU_ASSERT_EQUAL(decode.apn_ambr.header.type, GTPV1_IE_APN_AMBR);
	CU_ASSERT_EQUAL(decode.apn_ambr.header.length, 8);
	CU_ASSERT_EQUAL(decode.apn_ambr.apn_ambr_uplink, 10);
	CU_ASSERT_EQUAL(decode.apn_ambr.apn_ambr_downlink, 7);

	CU_ASSERT_EQUAL(decode.signalling_priority_indication.header.type, GTPV1_IE_SIGNALLING_PRIORITY_INDICATION);
	CU_ASSERT_EQUAL(decode.signalling_priority_indication.header.length, 1);
	CU_ASSERT_EQUAL(decode.signalling_priority_indication.spare, 0);
	CU_ASSERT_EQUAL(decode.signalling_priority_indication.lapi, 1);
		
	CU_ASSERT_EQUAL(decode.cn_operator_selection_entity.header.type, GTPV1_IE_CN_OPERATOR_SELECTION_ENTITY);
	CU_ASSERT_EQUAL(decode.cn_operator_selection_entity.header.length, 1);
	CU_ASSERT_EQUAL(decode.cn_operator_selection_entity.spare, 0);
	CU_ASSERT_EQUAL(decode.cn_operator_selection_entity.selection_entity, 2);

	CU_ASSERT_EQUAL(decode.mapped_ue_usage_type.header.type, GTPV1_IE_MAPPED_UE_USAGE_TYPE);
	CU_ASSERT_EQUAL(decode.mapped_ue_usage_type.header.length, 2);
	CU_ASSERT_EQUAL(decode.mapped_ue_usage_type.mapped_ue_usage_type, 2);

	CU_ASSERT_EQUAL(decode.up_function_selection_indication.header.type, GTPV1_IE_UP_FUNCTION_SELECTION_INDICATION);
	CU_ASSERT_EQUAL(decode.up_function_selection_indication.header.length, 1);
	CU_ASSERT_EQUAL(decode.up_function_selection_indication.spare, 0);
	CU_ASSERT_EQUAL(decode.up_function_selection_indication.dcnr, 1);

	CU_ASSERT_EQUAL(decode.private_extension.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.private_extension.header.length, 6);
	CU_ASSERT_EQUAL(decode.private_extension.extension_identifier, 12);
	CU_ASSERT_NSTRING_EQUAL(decode.private_extension.extension_value,"2021", 4);
}

void test_decode_gtpv1_create_pdp_ctxt_rsp(void)
{
	gtpv1_create_pdp_ctxt_rsp_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x11, 0x00, 0xea, 0x37, 0x2f, 0x00, 0x00,
		0x01, 0x80, 0x08, 0x00, 0x0e, 0x02, 0x10, 0x08, 0x02, 0x00, 
		0x00, 0x11, 0x08, 0x01, 0x00, 0x00, 0x14, 0x08, 0x7f, 0x03,
		0x30, 0x41, 0x0b, 0x80, 0x00, 0x16, 0xf1, 0x8d, 0xc0, 0xa8,
		0x00, 0x2c, 0x20, 0x01, 0xdb, 0x80, 0x33, 0x33, 0x44, 0x44,
		0x55, 0x55, 0x66, 0x66, 0x77, 0x77, 0x88, 0x88, 0x84, 0x00,
		0x19, 0x81, 0x00, 0x02, 0x09, 0x33, 0x35, 0x35, 0x32, 0x34,
		0x30, 0x35, 0x39, 0x39, 0x00, 0x02, 0x09, 0x33, 0x35, 0x35,
		0x32, 0x34, 0x30, 0x35, 0x38, 0x39, 0x85, 0x00, 0x04, 0xc0,
		0xa8, 0x00, 0x2c, 0x85, 0x00, 0x04, 0xc0, 0xa8, 0x00, 0x2b,
		0x85, 0x00, 0x10, 0x20, 0x01, 0xdb, 0x80, 0x33, 0x33, 0x44,
		0x44, 0x55, 0x55, 0x66, 0x66, 0x77, 0x77, 0x88, 0x88, 0x85,
		0x00, 0x10, 0x20, 0x01, 0xdb, 0x80, 0x33, 0x33, 0x44, 0x44,
		0x55, 0x55, 0x66, 0x66, 0x77, 0x77, 0x88, 0x85, 0x87, 0x00,
		0x15, 0x02, 0x12, 0x31, 0x04, 0x2a, 0x03, 0x7b, 0xea, 0x11,
		0x06, 0x7a, 0xde, 0x11, 0x16, 0x0b, 0x21, 0x16, 0x2c, 0x21,
		0x22, 0x17, 0xfb, 0x00, 0x04, 0xc0, 0xa8, 0x00, 0x2c, 0xfb,
		0x00, 0x10, 0x20, 0x01, 0xdb, 0x80, 0x31, 0x33, 0x44, 0x44,
		0x55, 0x55, 0x66, 0x66, 0x77, 0x77, 0x88, 0x85, 0x94, 0x00,
		0x01, 0xff, 0x95, 0x00, 0x01, 0x0c, 0xb5, 0x00, 0x01, 0x04,
		0xb8, 0x00, 0x01, 0x03, 0xbf, 0x00, 0x01, 0x71, 0xc1, 0x00,
		0x01, 0xaa, 0xc3, 0x00, 0x01, 0x57, 0xc6, 0x00, 0x08, 0x00,
		0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x07, 0xca, 0x00, 0x01,
		0x08, 0xda, 0x00, 0x01, 0x07, 0xff, 0x00, 0x06, 0x00, 0x0c,
		0x32, 0x30, 0x32, 0x31};

	CU_ASSERT(decode_gtpv1_create_pdp_ctxt_rsp(buf, &decode) == 242);
	CU_ASSERT(decode_gtpv1_create_pdp_ctxt_rsp(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_create_pdp_ctxt_rsp(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_create_pdp_ctxt_rsp(buf, NULL) == -1);

	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);
	
	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_CREATE_PDP_CTXT_RSP);
	CU_ASSERT_EQUAL(decode.header.message_len, 234);
	CU_ASSERT_EQUAL(decode.header.teid, 0x372f0000);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.cause.header.type, GTPV1_IE_CAUSE);
	CU_ASSERT_EQUAL(decode.cause.cause_value, 128);

	CU_ASSERT_EQUAL(decode.reordering_req.header.type, GTPV1_IE_REORDERING_REQ);
	CU_ASSERT_EQUAL(decode.reordering_req.spare, 0);
	CU_ASSERT_EQUAL(decode.reordering_req.reord_req, 0);

	CU_ASSERT_EQUAL(decode.recovery.header.type, GTPV1_IE_RECOVERY);
	CU_ASSERT_EQUAL(decode.recovery.restart_counter, 2);

	CU_ASSERT_EQUAL(decode.tunn_endpt_idnt_data_1.header.type, GTPV1_IE_TEID_DATA_1);
	CU_ASSERT_EQUAL(decode.tunn_endpt_idnt_data_1.teid, 0x08020000);

	CU_ASSERT_EQUAL(decode.tunn_endpt_idnt_control_plane.header.type, GTPV1_IE_TEID_CONTROL_PLANE);
	CU_ASSERT_EQUAL(decode.tunn_endpt_idnt_control_plane.teid, 0x08010000);

	CU_ASSERT_EQUAL(decode.nsapi.header.type, GTPV1_IE_NSAPI);
	CU_ASSERT_EQUAL(decode.nsapi.spare, 0);
	CU_ASSERT_EQUAL(decode.nsapi.nsapi_value, 8);

	CU_ASSERT_EQUAL(decode.charging_id.header.type, GTPV1_IE_CHARGING_ID);
	CU_ASSERT_EQUAL(decode.charging_id.chrgng_id_val, 0x0330410b);

	CU_ASSERT_EQUAL(decode.end_user_address.header.type, GTPV1_IE_END_USER_ADDR);
	CU_ASSERT_EQUAL(decode.end_user_address.header.length, 22);
	CU_ASSERT_EQUAL(decode.end_user_address.spare, 0xf);
	CU_ASSERT_EQUAL(decode.end_user_address.pdp_type_org, 1);
	CU_ASSERT_EQUAL(decode.end_user_address.pdp_type_number, 0x8D);
	CU_ASSERT_EQUAL(decode.end_user_address.pdp_address.ipv4, 3232235564);
	char addr[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &decode.end_user_address.pdp_address.ipv6, addr, INET6_ADDRSTRLEN);
	CU_ASSERT_NSTRING_EQUAL(addr, "2001:db80:3333:4444:5555:6666:7777:8888",39);

	CU_ASSERT_EQUAL(decode.protocol_config_options.header.type, GTPV1_IE_PROTOCOL_CONFIG_OPTIONS);
	CU_ASSERT_EQUAL(decode.protocol_config_options.header.length, 25);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_flag_ext, 1);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_flag_spare, 0);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_cfg_proto, 1);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content_count, 2);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[0].prot_or_cont_id, 2);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[0].length, 9);
	CU_ASSERT_NSTRING_EQUAL(decode.protocol_config_options.pco.pco_content[0].content,"355240599", 9);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[1].prot_or_cont_id , 2);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[1].length , 9);
	CU_ASSERT_NSTRING_EQUAL(decode.protocol_config_options.pco.pco_content[1].content,"355240589", 9);
	
	CU_ASSERT_EQUAL(decode.gsn_addr_1.header.type, GTPV1_IE_GSN_ADDR);
	CU_ASSERT_EQUAL(decode.gsn_addr_1.header.length, 4);
	CU_ASSERT_EQUAL(decode.gsn_addr_1.gsn_address.ipv4, 3232235564);

	CU_ASSERT_EQUAL(decode.gsn_addr_2.header.type, GTPV1_IE_GSN_ADDR);
	CU_ASSERT_EQUAL(decode.gsn_addr_2.header.length, 4);
	CU_ASSERT_EQUAL(decode.gsn_addr_2.gsn_address.ipv4, 3232235563);

	CU_ASSERT_EQUAL(decode.gsn_addr_3.header.type, GTPV1_IE_GSN_ADDR);
	CU_ASSERT_EQUAL(decode.gsn_addr_3.header.length, 16);
	char addr1[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &decode.gsn_addr_3.gsn_address.ipv6, addr1, INET6_ADDRSTRLEN);
	CU_ASSERT_NSTRING_EQUAL(addr1, "2001:db80:3333:4444:5555:6666:7777:8888",39);

	CU_ASSERT_EQUAL(decode.gsn_addr_4.header.type, GTPV1_IE_GSN_ADDR);
	CU_ASSERT_EQUAL(decode.gsn_addr_4.header.length, 16);
	char addr2[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &decode.gsn_addr_4.gsn_address.ipv6, addr2, INET6_ADDRSTRLEN);
	CU_ASSERT_NSTRING_EQUAL(addr2, "2001:db80:3333:4444:5555:6666:7777:8885",39);

	CU_ASSERT_EQUAL(decode.qos_profile.header.type, GTPV1_IE_QOS);
	CU_ASSERT_EQUAL(decode.qos_profile.header.length, 21);	
	CU_ASSERT_EQUAL(decode.qos_profile.qos.allocation_retention_priority, 2);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.spare1, 0);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.delay_class, 2);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.reliablity_class, 2);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.peak_throughput, 3);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.spare2, 0);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.precedence_class, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.spare3, 0);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.mean_throughput, 4);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.traffic_class, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.delivery_order, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.delivery_erroneous_sdu, 2);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_sdu_size, 3);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_uplink, 123);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_downlink, 234);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.residual_ber, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.sdu_error_ratio, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.transfer_delay, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.traffic_handling_priority, 2);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_uplink, 122);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_downlink, 222);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.spare4, 0);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.signalling_indication, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.source_statistics_descriptor, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_downlink_ext1, 22);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_downlink_ext1, 11);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_uplink_ext1, 33);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_uplink_ext1, 22);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_downlink_ext2, 44);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_downlink_ext2, 33);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_uplink_ext2, 34);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_uplink_ext2, 23);

	CU_ASSERT_EQUAL(decode.charging_gateway_addr.header.type, GTPV1_IE_CHARGING_GATEWAY_ADDR);
	CU_ASSERT_EQUAL(decode.charging_gateway_addr.header.length, 4);
	CU_ASSERT_EQUAL(decode.charging_gateway_addr.ipv4_addr, 3232235564);

	CU_ASSERT_EQUAL(decode.alt_charging_gateway_addr.header.type, GTPV1_IE_CHARGING_GATEWAY_ADDR);
	CU_ASSERT_EQUAL(decode.alt_charging_gateway_addr.header.length, 16);
	char addr3[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &decode.alt_charging_gateway_addr.ipv6_addr, addr3, INET6_ADDRSTRLEN);
	CU_ASSERT_NSTRING_EQUAL(addr3, "2001:db80:3133:4444:5555:6666:7777:8885",39);

	CU_ASSERT_EQUAL(decode.common_flag.header.type, GTPV1_IE_COMMON_FLAG);
	CU_ASSERT_EQUAL(decode.common_flag.header.length, 1);
	CU_ASSERT_EQUAL(decode.common_flag.dual_addr_bearer_flag, 1);
	CU_ASSERT_EQUAL(decode.common_flag.upgrade_qos_supported, 1);
	CU_ASSERT_EQUAL(decode.common_flag.nrsn, 1);
	CU_ASSERT_EQUAL(decode.common_flag.no_qos_negotiation, 1);
	CU_ASSERT_EQUAL(decode.common_flag.mbms_counting_information, 1);
	CU_ASSERT_EQUAL(decode.common_flag.ran_procedures_ready, 1);
	CU_ASSERT_EQUAL(decode.common_flag.mbms_service_type, 1);
	CU_ASSERT_EQUAL(decode.common_flag.prohibit_payload_compression, 1);

	CU_ASSERT_EQUAL(decode.apn_restriction.header.type, GTPV1_IE_APN_RESTRICTION);
	CU_ASSERT_EQUAL(decode.apn_restriction.header.length, 1);
	CU_ASSERT_EQUAL(decode.apn_restriction.restriction_type_value, 12);

	CU_ASSERT_EQUAL(decode.ms_info_change_reporting_action.header.type, GTPV1_IE_MS_INFO_CHANGE_REPORTING_ACTION);
	CU_ASSERT_EQUAL(decode.ms_info_change_reporting_action.header.length, 1);
	CU_ASSERT_EQUAL(decode.ms_info_change_reporting_action.action, 4);

	CU_ASSERT_EQUAL(decode.bearer_control.header.type, GTPV1_IE_BEARER_CONTROL_MODE);
	CU_ASSERT_EQUAL(decode.bearer_control.header.length, 1);
	CU_ASSERT_EQUAL(decode.bearer_control.bearer_control_mode, 3);

	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.header.type, GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_I);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.header.length, 1);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.spare, 0);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.pci, 1);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.pl, 12);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.spare2, 0); 
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.pvi, 1);

	CU_ASSERT_EQUAL(decode.extended_common_flag.header.type, GTPV1_IE_EXTENDED_COMMON_FLAG);
	CU_ASSERT_EQUAL(decode.extended_common_flag.header.length, 1);
	CU_ASSERT_EQUAL(decode.extended_common_flag.uasi, 1);
	CU_ASSERT_EQUAL(decode.extended_common_flag.bdwi, 0);
	CU_ASSERT_EQUAL(decode.extended_common_flag.pcri, 1);
	CU_ASSERT_EQUAL(decode.extended_common_flag.vb, 0);
	CU_ASSERT_EQUAL(decode.extended_common_flag.retloc, 1);
	CU_ASSERT_EQUAL(decode.extended_common_flag.cpsr, 0);
	CU_ASSERT_EQUAL(decode.extended_common_flag.ccrsi, 1);
	CU_ASSERT_EQUAL(decode.extended_common_flag.unauthenticated_imsi, 0);
	
	CU_ASSERT_EQUAL(decode.apn_ambr.header.type, GTPV1_IE_APN_AMBR);
	CU_ASSERT_EQUAL(decode.apn_ambr.header.length, 8);
	CU_ASSERT_EQUAL(decode.apn_ambr.apn_ambr_uplink, 10);
	CU_ASSERT_EQUAL(decode.apn_ambr.apn_ambr_downlink, 7);

	CU_ASSERT_EQUAL(decode.ggsn_back_off_time.header.type, GTPV1_IE_GGSN_BACK_OFF_TIME);
	CU_ASSERT_EQUAL(decode.ggsn_back_off_time.header.length, 1);
	CU_ASSERT_EQUAL(decode.ggsn_back_off_time.timer_unit, 0);
	CU_ASSERT_EQUAL(decode.ggsn_back_off_time.timer_value, 8);
	
	CU_ASSERT_EQUAL(decode.extended_common_flag_2.header.type, GTPV1_IE_EXTENDED_COMMON_FLAGS_II);
	CU_ASSERT_EQUAL(decode.extended_common_flag_2.header.length, 1);
	CU_ASSERT_EQUAL(decode.extended_common_flag_2.spare, 0);
	CU_ASSERT_EQUAL(decode.extended_common_flag_2.pmts_mi, 1);
	CU_ASSERT_EQUAL(decode.extended_common_flag_2.dtci, 1);
	CU_ASSERT_EQUAL(decode.extended_common_flag_2.pnsi, 1);

	CU_ASSERT_EQUAL(decode.private_extension.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.private_extension.header.length, 6);
	CU_ASSERT_EQUAL(decode.private_extension.extension_identifier, 12);
	CU_ASSERT_NSTRING_EQUAL(decode.private_extension.extension_value,"2021", 4);
}

void test_decode_gtpv1_update_pdp_ctxt_req_sgsn(void)
{
	gtpv1_update_pdp_ctxt_req_sgsn_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x12, 0x01, 0x16, 0x37, 0x2f, 0x00, 0x00,
		0x02, 0x72, 0x02, 0x13, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x03,
		0x04, 0xf4, 0x87, 0x00, 0x14, 0x14, 0x0e, 0x02, 0x10, 0x00,
		0xff, 0xfe, 0xee, 0x11, 0x00, 0x00, 0x00, 0xab, 0x14, 0x05,
		0x1b, 0x00, 0x09, 0x1c, 0x00, 0x09, 0x84, 0x00, 0x19, 0x81,
		0x00, 0x02, 0x09, 0x33, 0x35, 0x35, 0x32, 0x34, 0x30, 0x35,
		0x39, 0x39, 0x00, 0x02, 0x09, 0x33, 0x35, 0x35, 0x32, 0x34,
		0x30, 0x35, 0x38, 0x39, 0x85, 0x00, 0x04, 0xc0, 0xa8, 0x00,
		0x2c, 0x85, 0x00, 0x04, 0xc0, 0xa8, 0x00, 0x2c, 0x85, 0x00,
		0x10, 0x20, 0x01, 0xdb, 0x80, 0x33, 0x33, 0x44, 0x44, 0x55,
		0x55, 0x66, 0x66, 0x77, 0x77, 0x88, 0x88, 0x85, 0x00, 0x10,
		0x20, 0x01, 0xdb, 0x80, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55,
		0x66, 0x66, 0x77, 0x77, 0x88, 0x85, 0x87, 0x00, 0x15, 0x02,
		0x12, 0x31, 0x04, 0x2a, 0x03, 0x7b, 0xea, 0x11, 0x06, 0x7a,
		0xde, 0x11, 0x16, 0x0b, 0x21, 0x16, 0x2c, 0x21, 0x22, 0x17,
		0x89, 0x00, 0x13, 0x32, 0x15, 0x01, 0x01, 0x01, 0x25, 0x01,
		0x02, 0x01, 0x00, 0x01, 0x02, 0x01, 0x02, 0x01, 0x03, 0x03,
		0x02, 0x00, 0x8e, 0x00, 0x05, 0x32, 0x32, 0x32, 0x32, 0x32,
		0x8f, 0x00, 0x07, 0x61, 0x62, 0x63, 0x2e, 0x63, 0x6f, 0x6d,
		0x94, 0x00, 0x01, 0xff, 0x97, 0x00, 0x01, 0x02, 0x98, 0x00,
		0x08, 0x01, 0x04, 0xf4, 0x87, 0x00, 0x01, 0x00, 0x01, 0x99,
		0x00, 0x02, 0x01, 0x01, 0xa2, 0x00, 0x09, 0x00, 0x00, 0x01,
		0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0xb6, 0x00, 0x01, 0x07,
		0xbf, 0x00, 0x01, 0x71, 0xc1, 0x00, 0x01, 0x00, 0xc2, 0x00,
		0x08, 0x04, 0xf4, 0x87, 0x01, 0x00, 0x00, 0x01, 0x41, 0xc6,
		0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
		0xcb, 0x00, 0x01, 0x01, 0xd8, 0x00, 0x01, 0x01, 0x9a, 0x00,
		0x08, 0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x11, 0xff, 
		0x00, 0x06, 0x00, 0x0c, 0x32, 0x30, 0x32, 0x31};

	CU_ASSERT(decode_gtpv1_update_pdp_ctxt_req_sgsn(buf, &decode) == 286);
	CU_ASSERT(decode_gtpv1_update_pdp_ctxt_req_sgsn(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_update_pdp_ctxt_req_sgsn(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_update_pdp_ctxt_req_sgsn(buf, NULL) == -1);

	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);
	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_UPDATE_PDP_CTXT_REQ); 
	CU_ASSERT_EQUAL(decode.header.message_len, 278);
	CU_ASSERT_EQUAL(decode.header.teid, 0x372f0000); 
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.imsi.header.type, GTPV1_IE_IMSI);
	CU_ASSERT_EQUAL(decode.imsi.imsi_number_digits, 272031000000000);

	CU_ASSERT_EQUAL(decode.routing_area_identity.header.type, GTPV1_IE_ROUTEING_AREA_IDENTITY);
	CU_ASSERT_EQUAL(decode.routing_area_identity.rai_value.mcc_digit_2, 0x0);
	CU_ASSERT_EQUAL(decode.routing_area_identity.rai_value.mcc_digit_1, 0x4);
	CU_ASSERT_EQUAL(decode.routing_area_identity.rai_value.mnc_digit_3, 0x8);
	CU_ASSERT_EQUAL(decode.routing_area_identity.rai_value.mcc_digit_3, 0x4);
	CU_ASSERT_EQUAL(decode.routing_area_identity.rai_value.mnc_digit_2, 0x7);
	CU_ASSERT_EQUAL(decode.routing_area_identity.rai_value.mnc_digit_1, 0x0);
	CU_ASSERT_EQUAL(decode.routing_area_identity.rai_value.lac, 0x14);
	CU_ASSERT_EQUAL(decode.routing_area_identity.rai_value.rac, 0x14);

	CU_ASSERT_EQUAL(decode.recovery.header.type, GTPV1_IE_RECOVERY);
	CU_ASSERT_EQUAL(decode.recovery.restart_counter, 2);

	CU_ASSERT_EQUAL(decode.tunn_endpt_idnt_data_1.header.type, GTPV1_IE_TEID_DATA_1);
	CU_ASSERT_EQUAL(decode.tunn_endpt_idnt_data_1.teid, 0x0fffeee);

	CU_ASSERT_EQUAL(decode.tunn_endpt_idnt_control_plane.header.type, GTPV1_IE_TEID_CONTROL_PLANE);
	CU_ASSERT_EQUAL(decode.tunn_endpt_idnt_control_plane.teid, 0x00ab);

	CU_ASSERT_EQUAL(decode.nsapi.header.type, GTPV1_IE_NSAPI);
	CU_ASSERT_EQUAL(decode.nsapi.spare, 0);
	CU_ASSERT_EQUAL(decode.nsapi.nsapi_value, 5);

	CU_ASSERT_EQUAL(decode.trace_reference.header.type, GTPV1_IE_TRACE_REFERENCE);
	CU_ASSERT_EQUAL(decode.trace_reference.trace_reference, 9);

	CU_ASSERT_EQUAL(decode.trace_type.header.type, GTPV1_IE_TRACE_TYPE);
	CU_ASSERT_EQUAL(decode.trace_type.trace_type, 9);

	CU_ASSERT_EQUAL(decode.protocol_config_options.header.type, GTPV1_IE_PROTOCOL_CONFIG_OPTIONS);
	CU_ASSERT_EQUAL(decode.protocol_config_options.header.length, 25);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_flag_ext , 1);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_flag_spare , 0);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_cfg_proto , 1);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content_count , 2);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[0].prot_or_cont_id , 2);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[0].length , 9);
	CU_ASSERT_NSTRING_EQUAL(decode.protocol_config_options.pco.pco_content[0].content,"355240599", 9);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[1].prot_or_cont_id , 2);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[1].length , 9);
	CU_ASSERT_NSTRING_EQUAL(decode.protocol_config_options.pco.pco_content[1].content,"355240589", 9);

	CU_ASSERT_EQUAL(decode.gsn_addr_1.header.type, GTPV1_IE_GSN_ADDR);
	CU_ASSERT_EQUAL(decode.gsn_addr_1.header.length, 4);
	CU_ASSERT_EQUAL(decode.gsn_addr_1.gsn_address.ipv4, 3232235564); 

	CU_ASSERT_EQUAL(decode.gsn_addr_2.header.type, GTPV1_IE_GSN_ADDR);
	CU_ASSERT_EQUAL(decode.gsn_addr_2.header.length, 4);
	CU_ASSERT_EQUAL(decode.gsn_addr_2.gsn_address.ipv4, 3232235564);

	CU_ASSERT_EQUAL(decode.gsn_addr_3.header.type, GTPV1_IE_GSN_ADDR);
	CU_ASSERT_EQUAL(decode.gsn_addr_3.header.length, 16);
	char addr4[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &decode.gsn_addr_3.gsn_address.ipv6, addr4, INET6_ADDRSTRLEN);
	CU_ASSERT_NSTRING_EQUAL(addr4, "2001:db80:3333:4444:5555:6666:7777:8888",39);

	CU_ASSERT_EQUAL(decode.gsn_addr_4.header.type, GTPV1_IE_GSN_ADDR);
	CU_ASSERT_EQUAL(decode.gsn_addr_4.header.length, 16);
	char addr5[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &decode.gsn_addr_4.gsn_address.ipv6, addr5, INET6_ADDRSTRLEN);
	CU_ASSERT_NSTRING_EQUAL(addr5, "2001:db80:3333:4444:5555:6666:7777:8885",39);

	CU_ASSERT_EQUAL(decode.qos_profile.header.type, GTPV1_IE_QOS);
	CU_ASSERT_EQUAL(decode.qos_profile.header.length, 21);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.allocation_retention_priority, 2);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.spare1, 0);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.delay_class, 2);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.reliablity_class, 2);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.peak_throughput, 3);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.spare2, 0);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.precedence_class, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.spare3, 0);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.mean_throughput, 4);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.traffic_class, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.delivery_order, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.delivery_erroneous_sdu, 2);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_sdu_size, 3);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_uplink, 123);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_downlink, 234);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.residual_ber, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.sdu_error_ratio, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.transfer_delay, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.traffic_handling_priority, 2);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_uplink, 122);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_downlink, 222);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.spare4, 0);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.signalling_indication, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.source_statistics_descriptor, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_downlink_ext1, 22);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_downlink_ext1, 11);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_uplink_ext1, 33);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_uplink_ext1, 22);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_downlink_ext2, 44);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_downlink_ext2, 33);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_uplink_ext2, 34);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_uplink_ext2, 23);

	CU_ASSERT_EQUAL(decode.tft.header.type, GTPV1_IE_TFT);
	CU_ASSERT_EQUAL(decode.tft.header.length, 19);
	CU_ASSERT_EQUAL(decode.tft.tft_op_code, 1);
	CU_ASSERT_EQUAL(decode.tft.e_bit, 1);
	CU_ASSERT_EQUAL(decode.tft.no_packet_filters, 2);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[0].spare, 0);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[0].filter_direction, 1);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[0].filter_id, 5);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[0].filter_eval_precedence, 1);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[0].filter_content_length, 1);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[0].filter_content[0], 1);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[1].spare, 0);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[1].filter_direction, 2);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[1].filter_id, 5);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[1].filter_eval_precedence, 1);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[1].filter_content_length, 2);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[1].filter_content[0], 1);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[1].filter_content[1], 0);
	CU_ASSERT_EQUAL(decode.tft.parameters_list[0].parameter_id, 1);
	CU_ASSERT_EQUAL(decode.tft.parameters_list[0].parameter_content_length, 2);
	CU_ASSERT_EQUAL(decode.tft.parameters_list[0].parameter_content[0], 1);
	CU_ASSERT_EQUAL(decode.tft.parameters_list[0].parameter_content[1], 2);
	CU_ASSERT_EQUAL(decode.tft.parameters_list[1].parameter_id, 1);
	CU_ASSERT_EQUAL(decode.tft.parameters_list[1].parameter_content_length, 3);
	CU_ASSERT_EQUAL(decode.tft.parameters_list[1].parameter_content[0], 3);
	CU_ASSERT_EQUAL(decode.tft.parameters_list[1].parameter_content[1], 2);
	CU_ASSERT_EQUAL(decode.tft.parameters_list[1].parameter_content[2], 0);

	CU_ASSERT_EQUAL(decode.trigger_id.header.type, GTPV1_IE_TRIGGER_ID);    
	CU_ASSERT_EQUAL(decode.trigger_id.header.length, 5);    
	CU_ASSERT_STRING_EQUAL(decode.trigger_id.trigger_id,"22222");

	CU_ASSERT_EQUAL(decode.omc_identity.header.type, GTPV1_IE_OMC_IDENTITY);    
	CU_ASSERT_EQUAL(decode.omc_identity.header.length, 7);    
	CU_ASSERT_NSTRING_EQUAL(decode.omc_identity.omc_identity,"abc.com", 7);

	CU_ASSERT_EQUAL(decode.common_flag.header.type, GTPV1_IE_COMMON_FLAG);
	CU_ASSERT_EQUAL(decode.common_flag.header.length, 1);
	CU_ASSERT_EQUAL(decode.common_flag.dual_addr_bearer_flag, 1);
	CU_ASSERT_EQUAL(decode.common_flag.upgrade_qos_supported, 1);
	CU_ASSERT_EQUAL(decode.common_flag.nrsn, 1);
	CU_ASSERT_EQUAL(decode.common_flag.no_qos_negotiation, 1);
	CU_ASSERT_EQUAL(decode.common_flag.mbms_counting_information, 1);
	CU_ASSERT_EQUAL(decode.common_flag.ran_procedures_ready, 1);
	CU_ASSERT_EQUAL(decode.common_flag.mbms_service_type, 1);
	CU_ASSERT_EQUAL(decode.common_flag.prohibit_payload_compression, 1);

	CU_ASSERT_EQUAL(decode.rat_type.header.type, GTPV1_IE_RAT_TYPE);
	CU_ASSERT_EQUAL(decode.rat_type.header.length, 1);
	CU_ASSERT_EQUAL(decode.rat_type.rat_type, 2);

	CU_ASSERT_EQUAL(decode.user_location_information.header.type, GTPV1_IE_USER_LOCATION_INFORMATION);
	CU_ASSERT_EQUAL(decode.user_location_information.header.length, 8);
	CU_ASSERT_EQUAL(decode.user_location_information.geographic_location_type, 1);
	CU_ASSERT_EQUAL(decode.user_location_information.mcc_digit_2, 0x0);
	CU_ASSERT_EQUAL(decode.user_location_information.mcc_digit_1, 0x4);
	CU_ASSERT_EQUAL(decode.user_location_information.mnc_digit_3, 0x8);
	CU_ASSERT_EQUAL(decode.user_location_information.mcc_digit_3, 0x4);
	CU_ASSERT_EQUAL(decode.user_location_information.mnc_digit_2, 0x7);
	CU_ASSERT_EQUAL(decode.user_location_information.mnc_digit_1, 0x0);
	CU_ASSERT_EQUAL(decode.user_location_information.lac, 0x1);
	CU_ASSERT_EQUAL(decode.user_location_information.ci_sac_rac, 0x1);

	CU_ASSERT_EQUAL(decode.ms_time_zone.header.type, GTPV1_IE_MS_TIME_ZONE);    
	CU_ASSERT_EQUAL(decode.ms_time_zone.header.length, 2);
	CU_ASSERT_EQUAL(decode.ms_time_zone.time_zone, 1);    
	CU_ASSERT_EQUAL(decode.ms_time_zone.spare, 0);    
	CU_ASSERT_EQUAL(decode.ms_time_zone.daylight_saving_time, 1);

	CU_ASSERT_EQUAL(decode.additional_trace_information.header.type, GTPV1_IE_ADDITIONAL_TRACE_INFORMATION);
	CU_ASSERT_EQUAL(decode.additional_trace_information.header.length, 9);
	CU_ASSERT_EQUAL(decode.additional_trace_information.trace_reference_2, 1);
	CU_ASSERT_EQUAL(decode.additional_trace_information.trace_recording_session_reference, 1);
	CU_ASSERT_EQUAL(decode.additional_trace_information.spare1, 0);
	CU_ASSERT_EQUAL(decode.additional_trace_information.triggering_events_in_ggsn_mbms_ctxt, 0);
	CU_ASSERT_EQUAL(decode.additional_trace_information.triggering_events_in_ggsn_pdp_ctxt, 1);
	CU_ASSERT_EQUAL(decode.additional_trace_information.trace_depth, 1);
	CU_ASSERT_EQUAL(decode.additional_trace_information.spare2, 0);
	CU_ASSERT_EQUAL(decode.additional_trace_information.list_of_interfaces_in_ggsn_gmb, 0);
	CU_ASSERT_EQUAL(decode.additional_trace_information.list_of_interfaces_in_ggsn_gi, 0);
	CU_ASSERT_EQUAL(decode.additional_trace_information.list_of_interfaces_in_ggsn_gn, 1);
	CU_ASSERT_EQUAL(decode.additional_trace_information.trace_activity_control, 1);

	CU_ASSERT_EQUAL(decode.direct_tunnel_flag.header.type, GTPV1_IE_DIRECT_TUNNEL_FLAG);
	CU_ASSERT_EQUAL(decode.direct_tunnel_flag.header.length, 1);
	CU_ASSERT_EQUAL(decode.direct_tunnel_flag.spare, 0);
	CU_ASSERT_EQUAL(decode.direct_tunnel_flag.ei, 1);
	CU_ASSERT_EQUAL(decode.direct_tunnel_flag.gcsi, 1);
	CU_ASSERT_EQUAL(decode.direct_tunnel_flag.dti, 1);

	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.header.type, GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_I);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.header.length, 1);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.spare,0);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.pci,1);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.pl, 12);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.spare2,0);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.pvi, 1);

	CU_ASSERT_EQUAL(decode.extended_common_flag.header.type, GTPV1_IE_EXTENDED_COMMON_FLAG);
	CU_ASSERT_EQUAL(decode.extended_common_flag.header.length, 1);
	CU_ASSERT_EQUAL(decode.extended_common_flag.uasi, 0);
	CU_ASSERT_EQUAL(decode.extended_common_flag.bdwi, 0);
	CU_ASSERT_EQUAL(decode.extended_common_flag.pcri, 0);
	CU_ASSERT_EQUAL(decode.extended_common_flag.vb, 0);
	CU_ASSERT_EQUAL(decode.extended_common_flag.retloc, 0);
	CU_ASSERT_EQUAL(decode.extended_common_flag.cpsr, 0);

	CU_ASSERT_EQUAL(decode.user_csg_information.header.type, GTPV1_IE_USER_CSG_INFORMATION);
	CU_ASSERT_EQUAL(decode.user_csg_information.header.length, 8);
	CU_ASSERT_EQUAL(decode.user_csg_information.mcc_digit_2, 0x0);
	CU_ASSERT_EQUAL(decode.user_csg_information.mcc_digit_1, 0x4);
	CU_ASSERT_EQUAL(decode.user_csg_information.mnc_digit_3, 0x8);
	CU_ASSERT_EQUAL(decode.user_csg_information.mcc_digit_3, 0x4);
	CU_ASSERT_EQUAL(decode.user_csg_information.mnc_digit_2, 0x7);
	CU_ASSERT_EQUAL(decode.user_csg_information.mnc_digit_1, 0x0);
	CU_ASSERT_EQUAL(decode.user_csg_information.spare, 0);
	CU_ASSERT_EQUAL(decode.user_csg_information.csg_id, 1);
	CU_ASSERT_EQUAL(decode.user_csg_information.csg_id_II, 1);
	CU_ASSERT_EQUAL(decode.user_csg_information.access_mode, 1);
	CU_ASSERT_EQUAL(decode.user_csg_information.spare2, 0);
	CU_ASSERT_EQUAL(decode.user_csg_information.cmi, 1);

	CU_ASSERT_EQUAL(decode.apn_ambr.header.type, GTPV1_IE_APN_AMBR);
	CU_ASSERT_EQUAL(decode.apn_ambr.header.length, 8);
	CU_ASSERT_EQUAL(decode.apn_ambr.apn_ambr_uplink, 0);
	CU_ASSERT_EQUAL(decode.apn_ambr.apn_ambr_downlink, 7);

	CU_ASSERT_EQUAL(decode.signalling_priority_indication.header.type, GTPV1_IE_SIGNALLING_PRIORITY_INDICATION);
	CU_ASSERT_EQUAL(decode.signalling_priority_indication.header.length, 1);
	CU_ASSERT_EQUAL(decode.signalling_priority_indication.spare, 0);
	CU_ASSERT_EQUAL(decode.signalling_priority_indication.lapi, 1);
		
	CU_ASSERT_EQUAL(decode.cn_operator_selection_entity.header.type, GTPV1_IE_CN_OPERATOR_SELECTION_ENTITY);
	CU_ASSERT_EQUAL(decode.cn_operator_selection_entity.header.length, 1);
	CU_ASSERT_EQUAL(decode.cn_operator_selection_entity.spare, 0);
	CU_ASSERT_EQUAL(decode.cn_operator_selection_entity.selection_entity, 1);	

	CU_ASSERT_EQUAL(decode.imei_sv.header.type, GTPV1_IE_IMEI_SV);
	CU_ASSERT_EQUAL(decode.imei_sv.header.length, 8);
	CU_ASSERT_EQUAL(decode.imei_sv.imei_sv, 0b0001000100010001000100010001000100100010001000100010001000010001);

	CU_ASSERT_EQUAL(decode.private_extension.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.private_extension.header.length, 6);
	CU_ASSERT_EQUAL(decode.private_extension.extension_identifier, 12);
	CU_ASSERT_NSTRING_EQUAL(decode.private_extension.extension_value,"2021", 4);
}

void test_decode_gtpv1_update_pdp_ctxt_req_ggsn(void)
{
	gtpv1_update_pdp_ctxt_req_ggsn_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x12, 0x00, 0x94, 0x37, 0x2f, 0x00, 0x00, 
		0x02, 0x72, 0x02, 0x13, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x0e,
		0x02, 0x14, 0x05, 0x80, 0x00, 0x06, 0xf1, 0x21, 0x15, 0x2c,
		0x8a, 0x97, 0x84, 0x00, 0x19, 0x81, 0x00, 0x02, 0x09, 0x33,
		0x35, 0x35, 0x32, 0x34, 0x30, 0x35, 0x39, 0x39, 0x00, 0x02,
		0x09, 0x33, 0x35, 0x35, 0x32, 0x34, 0x30, 0x35, 0x38, 0x39,
		0x87, 0x00, 0x15, 0x02, 0x12, 0x31, 0x04, 0x2a, 0x03, 0x7b,
		0xea, 0x11, 0x06, 0x7a, 0xde, 0x11, 0x16, 0x0b, 0x21, 0x16, 
		0x2c, 0x21, 0x22, 0x17, 0x89, 0x00, 0x13, 0x32, 0x15, 0x01,
		0x01, 0x01, 0x25, 0x01, 0x02, 0x01, 0x00, 0x01, 0x02, 0x01,
		0x02, 0x01, 0x03, 0x03, 0x02, 0x00, 0x94, 0x00, 0x01, 0xff,
		0x95, 0x00, 0x01, 0x0c, 0xb5, 0x00, 0x01, 0x04, 0xb6, 0x00,
		0x01, 0x07, 0xb8, 0x00, 0x01, 0x03, 0xbf, 0x00, 0x01, 0x71,
		0xc1, 0x00, 0x01, 0x00, 0xc3, 0x00, 0x01, 0x07, 0xc6, 0x00,
		0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xff,
		0x00, 0x06, 0x00, 0x0c, 0x32, 0x30, 0x32, 0x31};

	CU_ASSERT(decode_gtpv1_update_pdp_ctxt_req_ggsn(buf, &decode) == 156);
	CU_ASSERT(decode_gtpv1_update_pdp_ctxt_req_ggsn(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_update_pdp_ctxt_req_ggsn(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_update_pdp_ctxt_req_ggsn(buf, NULL) == -1);

	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);
	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_UPDATE_PDP_CTXT_REQ); 
	CU_ASSERT_EQUAL(decode.header.message_len, 148);
	CU_ASSERT_EQUAL(decode.header.teid, 0x372f0000); 
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.imsi.header.type, GTPV1_IE_IMSI);
	CU_ASSERT_EQUAL(decode.imsi.imsi_number_digits, 272031000000000);

	CU_ASSERT_EQUAL(decode.recovery.header.type, GTPV1_IE_RECOVERY);
	CU_ASSERT_EQUAL(decode.recovery.restart_counter, 2);

	CU_ASSERT_EQUAL(decode.nsapi.header.type, GTPV1_IE_NSAPI);
	CU_ASSERT_EQUAL(decode.nsapi.spare, 0);
	CU_ASSERT_EQUAL(decode.nsapi.nsapi_value, 5);

	CU_ASSERT_EQUAL(decode.end_user_address.header.type, GTPV1_IE_END_USER_ADDR);
	CU_ASSERT_EQUAL(decode.end_user_address.header.length, 6);
	CU_ASSERT_EQUAL(decode.end_user_address.spare, 0xf);
	CU_ASSERT_EQUAL(decode.end_user_address.pdp_type_org, 1);
	CU_ASSERT_EQUAL(decode.end_user_address.pdp_type_number, 0x21);
	CU_ASSERT_EQUAL(decode.end_user_address.pdp_address.ipv4, 355240599);

	CU_ASSERT_EQUAL(decode.protocol_config_options.header.type, GTPV1_IE_PROTOCOL_CONFIG_OPTIONS);
	CU_ASSERT_EQUAL(decode.protocol_config_options.header.length, 25);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_flag_ext , 1);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_flag_spare , 0);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_cfg_proto , 1);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content_count , 2);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[0].prot_or_cont_id , 2);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[0].length , 9);
	CU_ASSERT_NSTRING_EQUAL(decode.protocol_config_options.pco.pco_content[0].content,"355240599", 9);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[1].prot_or_cont_id , 2);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[1].length , 9);
	CU_ASSERT_NSTRING_EQUAL(decode.protocol_config_options.pco.pco_content[1].content,"355240589", 9);

	CU_ASSERT_EQUAL(decode.qos_profile.header.type, GTPV1_IE_QOS);
	CU_ASSERT_EQUAL(decode.qos_profile.header.length, 21);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.allocation_retention_priority, 2);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.spare1, 0);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.delay_class, 2);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.reliablity_class, 2);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.peak_throughput, 3);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.spare2, 0);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.precedence_class, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.spare3, 0);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.mean_throughput, 4);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.traffic_class, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.delivery_order, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.delivery_erroneous_sdu, 2);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_sdu_size, 3);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_uplink, 123);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_downlink, 234);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.residual_ber, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.sdu_error_ratio, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.transfer_delay, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.traffic_handling_priority, 2);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_uplink, 122);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_downlink, 222);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.spare4, 0);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.signalling_indication, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.source_statistics_descriptor, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_downlink_ext1, 22);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_downlink_ext1, 11);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_uplink_ext1, 33);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_uplink_ext1, 22);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_downlink_ext2, 44);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_downlink_ext2, 33);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_uplink_ext2, 34);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_uplink_ext2, 23);

	CU_ASSERT_EQUAL(decode.tft.header.type, GTPV1_IE_TFT);
	CU_ASSERT_EQUAL(decode.tft.header.length, 19);
	CU_ASSERT_EQUAL(decode.tft.tft_op_code, 1);
	CU_ASSERT_EQUAL(decode.tft.e_bit, 1);
	CU_ASSERT_EQUAL(decode.tft.no_packet_filters, 2);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[0].spare, 0);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[0].filter_direction, 1);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[0].filter_id, 5);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[0].filter_eval_precedence, 1);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[0].filter_content_length, 1);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[0].filter_content[0], 1);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[1].spare, 0);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[1].filter_direction, 2);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[1].filter_id, 5);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[1].filter_eval_precedence, 1);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[1].filter_content_length, 2);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[1].filter_content[0], 1);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[1].filter_content[1], 0);
	CU_ASSERT_EQUAL(decode.tft.parameters_list[0].parameter_id, 1);
	CU_ASSERT_EQUAL(decode.tft.parameters_list[0].parameter_content_length, 2);
	CU_ASSERT_EQUAL(decode.tft.parameters_list[0].parameter_content[0], 1);
	CU_ASSERT_EQUAL(decode.tft.parameters_list[0].parameter_content[1], 2);
	CU_ASSERT_EQUAL(decode.tft.parameters_list[1].parameter_id, 1);
	CU_ASSERT_EQUAL(decode.tft.parameters_list[1].parameter_content_length, 3);
	CU_ASSERT_EQUAL(decode.tft.parameters_list[1].parameter_content[0], 3);
	CU_ASSERT_EQUAL(decode.tft.parameters_list[1].parameter_content[1], 2);
	CU_ASSERT_EQUAL(decode.tft.parameters_list[1].parameter_content[2], 0);

	CU_ASSERT_EQUAL(decode.common_flag.header.type, GTPV1_IE_COMMON_FLAG);
	CU_ASSERT_EQUAL(decode.common_flag.header.length, 1);
	CU_ASSERT_EQUAL(decode.common_flag.dual_addr_bearer_flag, 1);
	CU_ASSERT_EQUAL(decode.common_flag.upgrade_qos_supported, 1);
	CU_ASSERT_EQUAL(decode.common_flag.nrsn, 1);
	CU_ASSERT_EQUAL(decode.common_flag.no_qos_negotiation, 1);
	CU_ASSERT_EQUAL(decode.common_flag.mbms_counting_information, 1);
	CU_ASSERT_EQUAL(decode.common_flag.ran_procedures_ready, 1);
	CU_ASSERT_EQUAL(decode.common_flag.mbms_service_type, 1);
	CU_ASSERT_EQUAL(decode.common_flag.prohibit_payload_compression, 1);

	CU_ASSERT_EQUAL(decode.apn_restriction.header.type, GTPV1_IE_APN_RESTRICTION);
	CU_ASSERT_EQUAL(decode.apn_restriction.header.length,1);
	CU_ASSERT_EQUAL(decode.apn_restriction.restriction_type_value, 12);

	CU_ASSERT_EQUAL(decode.ms_info_change_reporting_action.header.type, GTPV1_IE_MS_INFO_CHANGE_REPORTING_ACTION);
	CU_ASSERT_EQUAL(decode.ms_info_change_reporting_action.header.length, 1);
	CU_ASSERT_EQUAL(decode.ms_info_change_reporting_action.action, 4);

	CU_ASSERT_EQUAL(decode.direct_tunnel_flag.header.type, GTPV1_IE_DIRECT_TUNNEL_FLAG);
	CU_ASSERT_EQUAL(decode.direct_tunnel_flag.header.length, 1);
	CU_ASSERT_EQUAL(decode.direct_tunnel_flag.spare, 0);
	CU_ASSERT_EQUAL(decode.direct_tunnel_flag.ei, 1);
	CU_ASSERT_EQUAL(decode.direct_tunnel_flag.gcsi, 1);
	CU_ASSERT_EQUAL(decode.direct_tunnel_flag.dti, 1);

	CU_ASSERT_EQUAL(decode.bearer_control.header.type, GTPV1_IE_BEARER_CONTROL_MODE);
	CU_ASSERT_EQUAL(decode.bearer_control.header.length, 1);
	CU_ASSERT_EQUAL(decode.bearer_control.bearer_control_mode, 3);

	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.header.type, GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_I);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.header.length, 1);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.spare,0);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.pci,1);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.pl, 12);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.spare2,0);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.pvi, 1);

	CU_ASSERT_EQUAL(decode.extended_common_flag.header.type, GTPV1_IE_EXTENDED_COMMON_FLAG);
	CU_ASSERT_EQUAL(decode.extended_common_flag.header.length, 1);
	CU_ASSERT_EQUAL(decode.extended_common_flag.uasi, 0);
	CU_ASSERT_EQUAL(decode.extended_common_flag.bdwi, 0);
	CU_ASSERT_EQUAL(decode.extended_common_flag.pcri, 0);
	CU_ASSERT_EQUAL(decode.extended_common_flag.vb, 0);
	CU_ASSERT_EQUAL(decode.extended_common_flag.retloc, 0);
	CU_ASSERT_EQUAL(decode.extended_common_flag.cpsr, 0);

	CU_ASSERT_EQUAL(decode.csg_information_reporting_action.header.type, GTPV1_IE_CSG_INFORMATION_REPORTING_ACTION);
	CU_ASSERT_EQUAL(decode.csg_information_reporting_action.header.length, 1);
	CU_ASSERT_EQUAL(decode.csg_information_reporting_action.spare, 0);
	CU_ASSERT_EQUAL(decode.csg_information_reporting_action.ucuhc, 1);
	CU_ASSERT_EQUAL(decode.csg_information_reporting_action.ucshc, 1);
	CU_ASSERT_EQUAL(decode.csg_information_reporting_action.uccsg, 1);

	CU_ASSERT_EQUAL(decode.apn_ambr.header.type, GTPV1_IE_APN_AMBR);
	CU_ASSERT_EQUAL(decode.apn_ambr.header.length, 8);
	CU_ASSERT_EQUAL(decode.apn_ambr.apn_ambr_uplink, 0);
	CU_ASSERT_EQUAL(decode.apn_ambr.apn_ambr_downlink, 7);

	CU_ASSERT_EQUAL(decode.private_extension.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.private_extension.header.length, 6);
	CU_ASSERT_EQUAL(decode.private_extension.extension_identifier, 12);
	CU_ASSERT_NSTRING_EQUAL(decode.private_extension.extension_value,"2021", 4);
}

void test_decode_gtpv1_update_pdp_ctxt_rsp_ggsn(void)
{
	gtpv1_update_pdp_ctxt_rsp_ggsn_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x13, 0x00, 0xc1, 0x37, 0x2f, 0x00, 0x00,
		0x01, 0x80, 0x0e, 0x02, 0x10, 0x00, 0xff, 0xfe, 0xee, 0x11,
		0x00, 0x00, 0x00, 0xab, 0x7f, 0x03, 0x30, 0x41, 0x0b, 0x84,
		0x00, 0x19, 0x81, 0x00, 0x02, 0x09, 0x33, 0x35, 0x35, 0x32,
		0x34, 0x30, 0x35, 0x39, 0x39, 0x00, 0x02, 0x09, 0x33, 0x35,
		0x35, 0x32, 0x34, 0x30, 0x35, 0x38, 0x39, 0x85, 0x00, 0x04,
		0xc0, 0xa8, 0x00, 0x2c, 0x85, 0x00, 0x04, 0xc0, 0xa8, 0x00,
		0x2b, 0x85, 0x00, 0x10, 0x11, 0x11, 0x22, 0x22, 0x33, 0x33,
		0x44, 0x44, 0x55, 0x55, 0x66, 0x66, 0x77, 0x77, 0x88, 0x88,
		0x85, 0x00, 0x10, 0x20, 0x01, 0xdb, 0x80, 0x33, 0x33, 0x44,
		0x44, 0x55, 0x55, 0x66, 0x66, 0x77, 0x77, 0x88, 0x85, 0x87,
		0x00, 0x15, 0x02, 0x12, 0x31, 0x04, 0x2a, 0x03, 0x7b, 0xea,
		0x11, 0x06, 0x7a, 0xde, 0x11, 0x16, 0x0b, 0x21, 0x16, 0x2c,
		0x21, 0x22, 0x17, 0xfb, 0x00, 0x04, 0xc0, 0xa8, 0x00, 0x2c,
		0xfb, 0x00, 0x10, 0x20, 0x01, 0xdb, 0x80, 0x31, 0x33, 0x44,
		0x44, 0x55, 0x55, 0x66, 0x66, 0x77, 0x77, 0x88, 0x85, 0x94,
		0x00, 0x01, 0xff, 0x95, 0x00, 0x01, 0x0c, 0xb8, 0x00, 0x01,
		0x03, 0xb5, 0x00, 0x01, 0x04, 0xbf, 0x00, 0x01, 0x71, 0xc3,
		0x00, 0x01, 0x07, 0xc6, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x07, 0xff, 0x00, 0x06, 0x00, 0x0c, 0x32,
		0x30, 0x32, 0x31};

	CU_ASSERT(decode_gtpv1_update_pdp_ctxt_rsp_ggsn(buf, &decode) == 201);
	CU_ASSERT(decode_gtpv1_update_pdp_ctxt_rsp_ggsn(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_update_pdp_ctxt_rsp_ggsn(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_update_pdp_ctxt_rsp_ggsn(buf, NULL) == -1);

	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);

	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_UPDATE_PDP_CTXT_RSP);
	CU_ASSERT_EQUAL(decode.header.message_len, 193);
	CU_ASSERT_EQUAL(decode.header.teid, 0x372f0000);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.cause.header.type, GTPV1_IE_CAUSE);
	CU_ASSERT_EQUAL(decode.cause.cause_value, 128);

	CU_ASSERT_EQUAL(decode.recovery.header.type, GTPV1_IE_RECOVERY);
	CU_ASSERT_EQUAL(decode.recovery.restart_counter, 2);

	CU_ASSERT_EQUAL(decode.tunn_endpt_idnt_data_1.header.type, GTPV1_IE_TEID_DATA_1);
	CU_ASSERT_EQUAL(decode.tunn_endpt_idnt_data_1.teid, 0x0fffeee);

	CU_ASSERT_EQUAL(decode.tunn_endpt_idnt_control_plane.header.type, GTPV1_IE_TEID_CONTROL_PLANE);
	CU_ASSERT_EQUAL(decode.tunn_endpt_idnt_control_plane.teid, 0x00ab);

	CU_ASSERT_EQUAL(decode.charging_id.header.type, GTPV1_IE_CHARGING_ID);
	CU_ASSERT_EQUAL(decode.charging_id.chrgng_id_val, 0x0330410b);

	CU_ASSERT_EQUAL(decode.protocol_config_options.header.type, GTPV1_IE_PROTOCOL_CONFIG_OPTIONS);
	CU_ASSERT_EQUAL(decode.protocol_config_options.header.length, 25);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_flag_ext , 1);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_flag_spare , 0);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_cfg_proto , 1);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content_count , 2);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[0].prot_or_cont_id , 2);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[0].length , 9);
	CU_ASSERT_NSTRING_EQUAL(decode.protocol_config_options.pco.pco_content[0].content,"355240599",9);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[1].prot_or_cont_id , 2);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[1].length , 9);
	CU_ASSERT_NSTRING_EQUAL(decode.protocol_config_options.pco.pco_content[1].content,"355240589",9);

	CU_ASSERT_EQUAL(decode.gsn_addr_1.header.type, GTPV1_IE_GSN_ADDR);
	CU_ASSERT_EQUAL(decode.gsn_addr_1.header.length, 4);
	CU_ASSERT_EQUAL(decode.gsn_addr_1.gsn_address.ipv4, 3232235564);

	CU_ASSERT_EQUAL(decode.gsn_addr_2.header.type, GTPV1_IE_GSN_ADDR);
	CU_ASSERT_EQUAL(decode.gsn_addr_2.header.length, 4);
	CU_ASSERT_EQUAL(decode.gsn_addr_2.gsn_address.ipv4, 3232235563);

	CU_ASSERT_EQUAL(decode.gsn_addr_3.header.type, GTPV1_IE_GSN_ADDR);
	CU_ASSERT_EQUAL(decode.gsn_addr_3.header.length, 16);
	char addr6[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &decode.gsn_addr_3.gsn_address.ipv6, addr6, INET6_ADDRSTRLEN);
	CU_ASSERT_NSTRING_EQUAL(addr6, "1111:2222:3333:4444:5555:6666:7777:8888",39);

	CU_ASSERT_EQUAL(decode.gsn_addr_4.header.type, GTPV1_IE_GSN_ADDR);
	CU_ASSERT_EQUAL(decode.gsn_addr_4.header.length, 16);
	char addr7[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &decode.gsn_addr_4.gsn_address.ipv6, addr7, INET6_ADDRSTRLEN);
	CU_ASSERT_NSTRING_EQUAL(addr7, "2001:db80:3333:4444:5555:6666:7777:8885",39);

	CU_ASSERT_EQUAL(decode.qos_profile.header.type, GTPV1_IE_QOS);
	CU_ASSERT_EQUAL(decode.qos_profile.header.length, 21);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.allocation_retention_priority, 2);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.spare1, 0);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.delay_class, 2);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.reliablity_class, 2);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.peak_throughput, 3);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.spare2, 0);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.precedence_class, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.spare3, 0);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.mean_throughput, 4);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.traffic_class, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.delivery_order, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.delivery_erroneous_sdu, 2);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_sdu_size, 3);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_uplink, 123);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_downlink, 234);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.residual_ber, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.sdu_error_ratio, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.transfer_delay, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.traffic_handling_priority, 2);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_uplink, 122);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_downlink, 222);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.spare4, 0);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.signalling_indication, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.source_statistics_descriptor, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_downlink_ext1, 22);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_downlink_ext1, 11);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_uplink_ext1, 33);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_uplink_ext1, 22);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_downlink_ext2, 44);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_downlink_ext2, 33);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_uplink_ext2, 34);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_uplink_ext2, 23);

	CU_ASSERT_EQUAL(decode.charging_gateway_addr.header.type, GTPV1_IE_CHARGING_GATEWAY_ADDR);
	CU_ASSERT_EQUAL(decode.charging_gateway_addr.header.length, 4);
	CU_ASSERT_EQUAL(decode.charging_gateway_addr.ipv4_addr, 3232235564);

	CU_ASSERT_EQUAL(decode.alt_charging_gateway_addr.header.type, GTPV1_IE_CHARGING_GATEWAY_ADDR);
	CU_ASSERT_EQUAL(decode.alt_charging_gateway_addr.header.length, 16);
	char addr8[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &decode.alt_charging_gateway_addr.ipv6_addr, addr8, INET6_ADDRSTRLEN);
	CU_ASSERT_NSTRING_EQUAL(addr8, "2001:db80:3133:4444:5555:6666:7777:8885",39);

	CU_ASSERT_EQUAL(decode.common_flag.header.type, GTPV1_IE_COMMON_FLAG);
	CU_ASSERT_EQUAL(decode.common_flag.header.length,1);
	CU_ASSERT_EQUAL(decode.common_flag.dual_addr_bearer_flag, 1);
	CU_ASSERT_EQUAL(decode.common_flag.upgrade_qos_supported,1);
	CU_ASSERT_EQUAL(decode.common_flag.nrsn,1);
	CU_ASSERT_EQUAL(decode.common_flag.no_qos_negotiation,1);
	CU_ASSERT_EQUAL(decode.common_flag.mbms_counting_information, 1);
	CU_ASSERT_EQUAL(decode.common_flag.ran_procedures_ready,1);
	CU_ASSERT_EQUAL(decode.common_flag.mbms_service_type, 1);
	CU_ASSERT_EQUAL(decode.common_flag.prohibit_payload_compression, 1);

	CU_ASSERT_EQUAL(decode.apn_restriction.header.type, GTPV1_IE_APN_RESTRICTION);
	CU_ASSERT_EQUAL(decode.apn_restriction.header.length,1);
	CU_ASSERT_EQUAL(decode.apn_restriction.restriction_type_value, 12);

	CU_ASSERT_EQUAL(decode.bearer_control.header.type, GTPV1_IE_BEARER_CONTROL_MODE);
	CU_ASSERT_EQUAL(decode.bearer_control.header.length, 1);
	CU_ASSERT_EQUAL(decode.bearer_control.bearer_control_mode, 3);

	CU_ASSERT_EQUAL(decode.ms_info_change_reporting_action.header.type, GTPV1_IE_MS_INFO_CHANGE_REPORTING_ACTION);
	CU_ASSERT_EQUAL(decode.ms_info_change_reporting_action.header.length, 1);
	CU_ASSERT_EQUAL(decode.ms_info_change_reporting_action.action, 4);

	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.header.type, GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_I);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.header.length, 1);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.spare,0);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.pci,1);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.pl, 12);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.spare2,0);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.pvi, 1);

	CU_ASSERT_EQUAL(decode.csg_information_reporting_action.header.type, GTPV1_IE_CSG_INFORMATION_REPORTING_ACTION);
	CU_ASSERT_EQUAL(decode.csg_information_reporting_action.header.length, 1);
	CU_ASSERT_EQUAL(decode.csg_information_reporting_action.spare, 0);
	CU_ASSERT_EQUAL(decode.csg_information_reporting_action.ucuhc, 1);
	CU_ASSERT_EQUAL(decode.csg_information_reporting_action.ucshc, 1);
	CU_ASSERT_EQUAL(decode.csg_information_reporting_action.uccsg, 1);

	CU_ASSERT_EQUAL(decode.apn_ambr.header.type, GTPV1_IE_APN_AMBR);
	CU_ASSERT_EQUAL(decode.apn_ambr.header.length, 8);
	CU_ASSERT_EQUAL(decode.apn_ambr.apn_ambr_uplink, 0);
	CU_ASSERT_EQUAL(decode.apn_ambr.apn_ambr_downlink, 7);

	CU_ASSERT_EQUAL(decode.private_extension.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.private_extension.header.length, 6);
	CU_ASSERT_EQUAL(decode.private_extension.extension_identifier, 12);
	CU_ASSERT_NSTRING_EQUAL(decode.private_extension.extension_value,"2021", 4);
}

void test_decode_gtpv1_update_pdp_ctxt_rsp_sgsn(void)
{
	gtpv1_update_pdp_ctxt_rsp_sgsn_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x13, 0x00, 0x70, 0x37, 0x2f, 0x00, 0x00,
		0x01, 0x80, 0x0e, 0x02, 0x10, 0x00, 0xff, 0xfe, 0xee, 0x84,
		0x00, 0x19, 0x81, 0x00, 0x02, 0x09, 0x33, 0x35, 0x35, 0x32,
		0x34, 0x30, 0x35, 0x39, 0x39, 0x00, 0x02, 0x09, 0x33, 0x35,
		0x35, 0x32, 0x34, 0x30, 0x35, 0x38, 0x39, 0x85, 0x00, 0x04,
		0xc0, 0xa8, 0x00, 0x2b, 0x87, 0x00, 0x15, 0x00, 0x12, 0x31,
		0x04, 0x2a, 0x03, 0x7b, 0xea, 0x11, 0x06, 0x7a, 0xde, 0x11,
		0x16, 0x0b, 0x21, 0x16, 0x2c, 0x21, 0x22, 0x17, 0x98, 0x00,
		0x08, 0x01, 0x04, 0xf4, 0x87, 0x00, 0x01, 0x00, 0x01, 0x99,
		0x00, 0x02, 0x01, 0x01, 0xb6, 0x00, 0x01, 0x07, 0xbf, 0x00,
		0x01, 0x71, 0xc6, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x07, 0xff, 0x00, 0x06, 0x00, 0x0c, 0x32, 0x30,
		0x32, 0x31};

	CU_ASSERT(decode_gtpv1_update_pdp_ctxt_rsp_sgsn(buf, &decode) == 120);
	CU_ASSERT(decode_gtpv1_update_pdp_ctxt_rsp_sgsn(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_update_pdp_ctxt_rsp_sgsn(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_update_pdp_ctxt_rsp_sgsn(buf, NULL) == -1);

	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);

	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_UPDATE_PDP_CTXT_RSP);
	CU_ASSERT_EQUAL(decode.header.message_len, 112);
	CU_ASSERT_EQUAL(decode.header.teid, 0x372f0000);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.cause.header.type, GTPV1_IE_CAUSE);
	CU_ASSERT_EQUAL(decode.cause.cause_value, 128);

	CU_ASSERT_EQUAL(decode.recovery.header.type, GTPV1_IE_RECOVERY);
	CU_ASSERT_EQUAL(decode.recovery.restart_counter, 2);

	CU_ASSERT_EQUAL(decode.tunn_endpt_idnt_data_1.header.type, GTPV1_IE_TEID_DATA_1);
	CU_ASSERT_EQUAL(decode.tunn_endpt_idnt_data_1.teid, 0x0fffeee);

	CU_ASSERT_EQUAL(decode.protocol_config_options.header.type, GTPV1_IE_PROTOCOL_CONFIG_OPTIONS);
	CU_ASSERT_EQUAL(decode.protocol_config_options.header.length, 25);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_flag_ext , 1);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_flag_spare , 0);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_cfg_proto , 1);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content_count , 2);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[0].prot_or_cont_id , 2);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[0].length , 9);
	CU_ASSERT_NSTRING_EQUAL(decode.protocol_config_options.pco.pco_content[0].content,"355240599",9);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[1].prot_or_cont_id , 2);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[1].length , 9);
	CU_ASSERT_NSTRING_EQUAL(decode.protocol_config_options.pco.pco_content[1].content,"355240589",9);

	CU_ASSERT_EQUAL(decode.sgsn_address_for_user_traffic.header.type, GTPV1_IE_GSN_ADDR);
	CU_ASSERT_EQUAL(decode.sgsn_address_for_user_traffic.header.length, 4);
	CU_ASSERT_EQUAL(decode.sgsn_address_for_user_traffic.gsn_address.ipv4, 3232235563);

	CU_ASSERT_EQUAL(decode.qos_profile.header.type, GTPV1_IE_QOS);
	CU_ASSERT_EQUAL(decode.qos_profile.header.length, 21);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.allocation_retention_priority, 0);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.spare1, 0);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.delay_class, 2);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.reliablity_class, 2);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.peak_throughput, 3);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.spare2, 0);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.precedence_class, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.spare3, 0);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.mean_throughput, 4);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.traffic_class, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.delivery_order, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.delivery_erroneous_sdu, 2);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_sdu_size, 3);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_uplink, 123);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_downlink, 234);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.residual_ber, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.sdu_error_ratio, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.transfer_delay, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.traffic_handling_priority, 2);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_uplink, 122);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_downlink, 222);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.spare4, 0);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.signalling_indication, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.source_statistics_descriptor, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_downlink_ext1, 22);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_downlink_ext1, 11);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_uplink_ext1, 33);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_uplink_ext1, 22);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_downlink_ext2, 44);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_downlink_ext2, 33);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_uplink_ext2, 34);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_uplink_ext2, 23);

	CU_ASSERT_EQUAL(decode.user_location_information.header.type, GTPV1_IE_USER_LOCATION_INFORMATION);
	CU_ASSERT_EQUAL(decode.user_location_information.header.length, 8);
	CU_ASSERT_EQUAL(decode.user_location_information.geographic_location_type, 1);
	CU_ASSERT_EQUAL(decode.user_location_information.mcc_digit_2, 0x0);
	CU_ASSERT_EQUAL(decode.user_location_information.mcc_digit_1, 0x4);
	CU_ASSERT_EQUAL(decode.user_location_information.mnc_digit_3, 0x8);
	CU_ASSERT_EQUAL(decode.user_location_information.mcc_digit_3, 0x4);
	CU_ASSERT_EQUAL(decode.user_location_information.mnc_digit_2, 0x7);
	CU_ASSERT_EQUAL(decode.user_location_information.mnc_digit_1, 0x0);
	CU_ASSERT_EQUAL(decode.user_location_information.lac, 0x1);
	CU_ASSERT_EQUAL(decode.user_location_information.ci_sac_rac, 0x1);

	CU_ASSERT_EQUAL(decode.ms_time_zone.header.type, GTPV1_IE_MS_TIME_ZONE);
	CU_ASSERT_EQUAL(decode.ms_time_zone.header.length, 2);
	CU_ASSERT_EQUAL(decode.ms_time_zone.time_zone, 1);
	CU_ASSERT_EQUAL(decode.ms_time_zone.spare, 0);
	CU_ASSERT_EQUAL(decode.ms_time_zone.daylight_saving_time, 1);

	CU_ASSERT_EQUAL(decode.direct_tunnel_flag.header.type, GTPV1_IE_DIRECT_TUNNEL_FLAG);
	CU_ASSERT_EQUAL(decode.direct_tunnel_flag.header.length, 1);
	CU_ASSERT_EQUAL(decode.direct_tunnel_flag.spare, 0);
	CU_ASSERT_EQUAL(decode.direct_tunnel_flag.ei, 1);
	CU_ASSERT_EQUAL(decode.direct_tunnel_flag.gcsi, 1);
	CU_ASSERT_EQUAL(decode.direct_tunnel_flag.dti, 1);

	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.header.type, GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_I);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.header.length, 1);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.spare,0);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.pci,1);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.pl, 12);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.spare2,0);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.pvi, 1);

	CU_ASSERT_EQUAL(decode.apn_ambr.header.type, GTPV1_IE_APN_AMBR);
	CU_ASSERT_EQUAL(decode.apn_ambr.header.length, 8);
	CU_ASSERT_EQUAL(decode.apn_ambr.apn_ambr_uplink, 0);
	CU_ASSERT_EQUAL(decode.apn_ambr.apn_ambr_downlink, 7);

	CU_ASSERT_EQUAL(decode.private_extension.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.private_extension.header.length, 6);
	CU_ASSERT_EQUAL(decode.private_extension.extension_identifier, 12);
	CU_ASSERT_NSTRING_EQUAL(decode.private_extension.extension_value,"2021", 4);
}

void test_decode_gtpv1_delete_pdp_ctxt_req(void)
{
	gtpv1_delete_pdp_ctxt_req_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x14, 0x00, 0x46, 0x37, 0x2f, 0x00, 0x00,
		0x01, 0x80, 0x13, 0x01, 0x14, 0x08, 0x84, 0x00, 0x19, 0x81,
		0x00, 0x02, 0x09, 0x33, 0x35, 0x35, 0x32, 0x34, 0x30, 0x35,
		0x39, 0x39, 0x00, 0x02, 0x09, 0x33, 0x35, 0x35, 0x32, 0x34,
		0x30, 0x35, 0x38, 0x39, 0x98, 0x00, 0x08, 0x01, 0x04, 0xf4,
		0x87, 0x00, 0x01, 0x00, 0x01, 0x99, 0x00, 0x02, 0x01, 0x01,
		0xc1, 0x00, 0x01, 0xff, 0xd6, 0x00, 0x04, 0x00, 0x00, 0x00,
		0x03, 0xff, 0x00, 0x06, 0x00, 0x0c, 0x32, 0x30, 0x32, 0x31};

	CU_ASSERT(decode_gtpv1_delete_pdp_ctxt_req(buf, &decode) == 78);
	CU_ASSERT(decode_gtpv1_delete_pdp_ctxt_req(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_delete_pdp_ctxt_req(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_delete_pdp_ctxt_req(buf, NULL) == -1);

	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);

	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_DELETE_PDP_CTXT_REQ);
	CU_ASSERT_EQUAL(decode.header.message_len, 70);
	CU_ASSERT_EQUAL(decode.header.teid, 0x372f0000);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.cause.header.type, GTPV1_IE_CAUSE);
	CU_ASSERT_EQUAL(decode.cause.cause_value, 128);

	CU_ASSERT_EQUAL(decode.teardown_ind.header.type, GTPV1_IE_TEARDOWN_IND);
	CU_ASSERT_EQUAL(decode.teardown_ind.spare, 0);
	CU_ASSERT_EQUAL(decode.teardown_ind.teardown_ind, 1);

	CU_ASSERT_EQUAL(decode.nsapi.header.type, GTPV1_IE_NSAPI);
	CU_ASSERT_EQUAL(decode.nsapi.spare, 0);
	CU_ASSERT_EQUAL(decode.nsapi.nsapi_value, 8);

	CU_ASSERT_EQUAL(decode.protocol_config_options.header.type, GTPV1_IE_PROTOCOL_CONFIG_OPTIONS);
	CU_ASSERT_EQUAL(decode.protocol_config_options.header.length, 25);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_flag_ext , 1);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_flag_spare , 0);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_cfg_proto , 1);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content_count , 2);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[0].prot_or_cont_id , 2);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[0].length , 9);
	CU_ASSERT_NSTRING_EQUAL(decode.protocol_config_options.pco.pco_content[0].content,"355240599",9);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[1].prot_or_cont_id , 2);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[1].length , 9);
	CU_ASSERT_NSTRING_EQUAL(decode.protocol_config_options.pco.pco_content[1].content,"355240589",9);

	CU_ASSERT_EQUAL(decode.user_location_information.header.type, GTPV1_IE_USER_LOCATION_INFORMATION);
	CU_ASSERT_EQUAL(decode.user_location_information.header.length, 8);
	CU_ASSERT_EQUAL(decode.user_location_information.geographic_location_type, 1);
	CU_ASSERT_EQUAL(decode.user_location_information.mcc_digit_2, 0x0);
	CU_ASSERT_EQUAL(decode.user_location_information.mcc_digit_1, 0x4);
	CU_ASSERT_EQUAL(decode.user_location_information.mnc_digit_3, 0x8);
	CU_ASSERT_EQUAL(decode.user_location_information.mcc_digit_3, 0x4);
	CU_ASSERT_EQUAL(decode.user_location_information.mnc_digit_2, 0x7);
	CU_ASSERT_EQUAL(decode.user_location_information.mnc_digit_1, 0x0);
	CU_ASSERT_EQUAL(decode.user_location_information.lac, 0x1);
	CU_ASSERT_EQUAL(decode.user_location_information.ci_sac_rac, 0x1);

	CU_ASSERT_EQUAL(decode.ms_time_zone.header.type, GTPV1_IE_MS_TIME_ZONE);
	CU_ASSERT_EQUAL(decode.ms_time_zone.header.length, 2);
	CU_ASSERT_EQUAL(decode.ms_time_zone.time_zone, 1);
	CU_ASSERT_EQUAL(decode.ms_time_zone.spare, 0);
	CU_ASSERT_EQUAL(decode.ms_time_zone.daylight_saving_time, 1);

	CU_ASSERT_EQUAL(decode.extended_common_flag.header.type, GTPV1_IE_EXTENDED_COMMON_FLAG);
	CU_ASSERT_EQUAL(decode.extended_common_flag.header.length, 1);
	CU_ASSERT_EQUAL(decode.extended_common_flag.uasi, 1);
	CU_ASSERT_EQUAL(decode.extended_common_flag.bdwi, 1);
	CU_ASSERT_EQUAL(decode.extended_common_flag.pcri, 1);
	CU_ASSERT_EQUAL(decode.extended_common_flag.vb, 1);
	CU_ASSERT_EQUAL(decode.extended_common_flag.retloc, 1);
	CU_ASSERT_EQUAL(decode.extended_common_flag.cpsr, 1);
	CU_ASSERT_EQUAL(decode.extended_common_flag.ccrsi, 1);
	CU_ASSERT_EQUAL(decode.extended_common_flag.unauthenticated_imsi, 1);

	CU_ASSERT_EQUAL(decode.uli_timestamp.header.type, GTPV1_IE_ULI_TIMESTAMP);
	CU_ASSERT_EQUAL(decode.uli_timestamp.header.length, 4);
	CU_ASSERT_EQUAL(decode.uli_timestamp.timestamp_value, 3);

	CU_ASSERT_EQUAL(decode.private_extension.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.private_extension.header.length, 6);
	CU_ASSERT_EQUAL(decode.private_extension.extension_identifier, 12);
	CU_ASSERT_NSTRING_EQUAL(decode.private_extension.extension_value,"2021", 4);
}

void test_decode_gtpv1_delete_pdp_ctxt_rsp(void)
{
	gtpv1_delete_pdp_ctxt_rsp_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x15, 0x00, 0x3e, 0x37, 0x2f, 0x00, 0x00,
		0x01, 0x80, 0x84, 0x00, 0x19, 0x81, 0x00, 0x02, 0x09, 0x33,
		0x35, 0x35, 0x32, 0x34, 0x30, 0x35, 0x39, 0x39, 0x00, 0x02,
		0x09, 0x33, 0x35, 0x35, 0x32, 0x34, 0x30, 0x35, 0x38, 0x39,
		0x98, 0x00, 0x08, 0x01, 0x04, 0xf4, 0x97, 0x00, 0x01, 0x00,
		0x01, 0x99, 0x00, 0x02, 0x01, 0x01, 0xd6, 0x00, 0x04, 0x00,
		0x00, 0x00, 0x03, 0xff, 0x00, 0x06, 0x00, 0x0c, 0x32, 0x30,
		0x32, 0x31};

	CU_ASSERT(decode_gtpv1_delete_pdp_ctxt_rsp(buf, &decode) == 70);
	CU_ASSERT(decode_gtpv1_delete_pdp_ctxt_rsp(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_delete_pdp_ctxt_rsp(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_delete_pdp_ctxt_rsp(buf, NULL) == -1);
	
	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);

	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_DELETE_PDP_CTXT_RSP);
	CU_ASSERT_EQUAL(decode.header.message_len, 62);
	CU_ASSERT_EQUAL(decode.header.teid, 0x372f0000);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.cause.header.type, GTPV1_IE_CAUSE);
	CU_ASSERT_EQUAL(decode.cause.cause_value, 128);

	CU_ASSERT_EQUAL(decode.protocol_config_options.header.type, GTPV1_IE_PROTOCOL_CONFIG_OPTIONS);
	CU_ASSERT_EQUAL(decode.protocol_config_options.header.length, 25);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_flag_ext , 1);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_flag_spare , 0);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_cfg_proto , 1);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content_count , 2);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[0].prot_or_cont_id , 2);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[0].length , 9);
	CU_ASSERT_NSTRING_EQUAL(decode.protocol_config_options.pco.pco_content[0].content,"355240599",9);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[1].prot_or_cont_id , 2);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[1].length , 9);
	CU_ASSERT_NSTRING_EQUAL(decode.protocol_config_options.pco.pco_content[1].content,"355240589",9);

	CU_ASSERT_EQUAL(decode.user_location_information.header.type, GTPV1_IE_USER_LOCATION_INFORMATION);
	CU_ASSERT_EQUAL(decode.user_location_information.header.length, 8);
	CU_ASSERT_EQUAL(decode.user_location_information.geographic_location_type, 1);
	CU_ASSERT_EQUAL(decode.user_location_information.mcc_digit_2, 0x0);
	CU_ASSERT_EQUAL(decode.user_location_information.mcc_digit_1, 0x4);
	CU_ASSERT_EQUAL(decode.user_location_information.mnc_digit_3, 0x9);
	CU_ASSERT_EQUAL(decode.user_location_information.mcc_digit_3, 0x4);
	CU_ASSERT_EQUAL(decode.user_location_information.mnc_digit_2, 0x7);
	CU_ASSERT_EQUAL(decode.user_location_information.mnc_digit_1, 0x0);
	CU_ASSERT_EQUAL(decode.user_location_information.lac, 0x1);
	CU_ASSERT_EQUAL(decode.user_location_information.ci_sac_rac, 0x1);

	CU_ASSERT_EQUAL(decode.ms_time_zone.header.type, GTPV1_IE_MS_TIME_ZONE);
	CU_ASSERT_EQUAL(decode.ms_time_zone.header.length, 2);
	CU_ASSERT_EQUAL(decode.ms_time_zone.time_zone, 1);
	CU_ASSERT_EQUAL(decode.ms_time_zone.spare, 0);
	CU_ASSERT_EQUAL(decode.ms_time_zone.daylight_saving_time, 1);

	CU_ASSERT_EQUAL(decode.uli_timestamp.header.type, GTPV1_IE_ULI_TIMESTAMP);
	CU_ASSERT_EQUAL(decode.uli_timestamp.header.length, 4);
	CU_ASSERT_EQUAL(decode.uli_timestamp.timestamp_value, 3);

	CU_ASSERT_EQUAL(decode.private_extension.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.private_extension.header.length, 6);
	CU_ASSERT_EQUAL(decode.private_extension.extension_identifier, 12);
	CU_ASSERT_NSTRING_EQUAL(decode.private_extension.extension_value,"2021", 4);
}

void test_decode_gtpv1_pdu_notification_req(void)
{
	gtpv1_pdu_notification_req_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x1b, 0x00, 0x53, 0x37, 0x2f, 0x00, 0x00,
		0x02, 0x72, 0x02, 0x13, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x11,
		0x00, 0x00, 0x00, 0xab, 0x80, 0x00, 0x06, 0xf1, 0x21, 0xc0,
		0xa8, 0x00, 0x2c, 0x83, 0x00, 0x0d, 0x6e, 0x65, 0x78, 0x74,
		0x70, 0x68, 0x6f, 0x6e, 0x65, 0x73, 0x2e, 0x63, 0x6f, 0x84,
		0x00, 0x19, 0x81, 0x00, 0x02, 0x09, 0x33, 0x35, 0x35, 0x32,
		0x34, 0x30, 0x35, 0x39, 0x39, 0x00, 0x02, 0x09, 0x33, 0x35,
		0x35, 0x32, 0x34, 0x30, 0x35, 0x38, 0x39, 0x85, 0x00, 0x04,
		0xc0, 0xa8, 0x00, 0x2c, 0xff, 0x00, 0x06, 0x00, 0x0c, 0x32,
		0x30, 0x32, 0x31};

	CU_ASSERT(decode_gtpv1_pdu_notification_req(buf, &decode) == 91);
	CU_ASSERT(decode_gtpv1_pdu_notification_req(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_pdu_notification_req(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_pdu_notification_req(buf, NULL) == -1);

	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);

	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_PDU_NOTIFICATION_REQ);
	CU_ASSERT_EQUAL(decode.header.message_len, 83);
	CU_ASSERT_EQUAL(decode.header.teid, 0x372f0000);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.imsi.header.type, GTPV1_IE_IMSI);
	CU_ASSERT_EQUAL(decode.imsi.imsi_number_digits, 272031000000000);

	CU_ASSERT_EQUAL(decode.tunn_endpt_idnt_control_plane.header.type, GTPV1_IE_TEID_CONTROL_PLANE);
	CU_ASSERT_EQUAL(decode.tunn_endpt_idnt_control_plane.teid, 0x00ab);

	CU_ASSERT_EQUAL(decode.end_user_address.header.type, GTPV1_IE_END_USER_ADDR);
	CU_ASSERT_EQUAL(decode.end_user_address.header.length, 6);
	CU_ASSERT_EQUAL(decode.end_user_address.spare, 0xf);
	CU_ASSERT_EQUAL(decode.end_user_address.pdp_type_org, 1);
	CU_ASSERT_EQUAL(decode.end_user_address.pdp_type_number, 0x21);
	CU_ASSERT_EQUAL(decode.end_user_address.pdp_address.ipv4, 3232235564);

	CU_ASSERT_EQUAL(decode.apn.header.type, GTPV1_IE_APN);
	CU_ASSERT_EQUAL(decode.apn.header.length, 13);
	CU_ASSERT_NSTRING_EQUAL(decode.apn.apn_value,"nextphones.co",13);

	CU_ASSERT_EQUAL(decode.protocol_config_options.header.type, GTPV1_IE_PROTOCOL_CONFIG_OPTIONS);
	CU_ASSERT_EQUAL(decode.protocol_config_options.header.length, 25);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_flag_ext , 1);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_flag_spare , 0);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_cfg_proto , 1);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content_count , 2);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[0].prot_or_cont_id , 2);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[0].length , 9);
	CU_ASSERT_NSTRING_EQUAL(decode.protocol_config_options.pco.pco_content[0].content,"355240599",9);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[1].prot_or_cont_id , 2);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[1].length , 9);
	CU_ASSERT_NSTRING_EQUAL(decode.protocol_config_options.pco.pco_content[1].content,"355240589",9);

	CU_ASSERT_EQUAL(decode.ggsn_addr_control_plane.header.type, GTPV1_IE_GSN_ADDR);
	CU_ASSERT_EQUAL(decode.ggsn_addr_control_plane.header.length, 4);
	CU_ASSERT_EQUAL(decode.ggsn_addr_control_plane.gsn_address.ipv4, 3232235564);

	CU_ASSERT_EQUAL(decode.private_extension.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.private_extension.header.length, 6);
	CU_ASSERT_EQUAL(decode.private_extension.extension_identifier, 12);
	CU_ASSERT_NSTRING_EQUAL(decode.private_extension.extension_value,"2021", 4);
}

void test_decode_gtpv1_pdu_notification_rsp(void)
{
	gtpv1_pdu_notification_rsp_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x1c, 0x00, 0x0b, 0x37, 0x2f, 0x00, 0x00,
		0x01, 0x80, 0xff, 0x00, 0x06, 0x00, 0x0c, 0x32, 0x30, 0x32, 0x31};

	CU_ASSERT(decode_gtpv1_pdu_notification_rsp(buf, &decode) == 19);
	CU_ASSERT(decode_gtpv1_pdu_notification_rsp(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_pdu_notification_rsp(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_pdu_notification_rsp(buf, NULL) == -1);

	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);

	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_PDU_NOTIFICATION_RSP);
	CU_ASSERT_EQUAL(decode.header.message_len, 11);
	CU_ASSERT_EQUAL(decode.header.teid, 0x372f0000);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.cause.header.type, GTPV1_IE_CAUSE);
	CU_ASSERT_EQUAL(decode.cause.cause_value, 128);

	CU_ASSERT_EQUAL(decode.private_extension.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.private_extension.header.length, 6);
	CU_ASSERT_EQUAL(decode.private_extension.extension_identifier, 12);
	CU_ASSERT_NSTRING_EQUAL(decode.private_extension.extension_value,"2021", 4);
}

void test_decode_gtpv1_pdu_notification_reject_req(void)
{
	gtpv1_pdu_notification_reject_req_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x1d, 0x00, 0x45, 0x37, 0x2f, 0x00, 0x00,
		0x01, 0x80, 0x11, 0x00, 0x00, 0x00, 0xab, 0x80, 0x00, 0x06,
		0xf1, 0x21, 0xc0, 0xa8, 0x00, 0x2c, 0x83, 0x00, 0x0d, 0x6e,
		0x65, 0x78, 0x74, 0x70, 0x68, 0x6f, 0x6e, 0x65, 0x73, 0x2e,
		0x63, 0x6f, 0x84, 0x00, 0x19, 0x81, 0x00, 0x02, 0x09, 0x33,
		0x35, 0x35, 0x32, 0x34, 0x30, 0x35, 0x39, 0x39, 0x00, 0x02,
		0x09, 0x33, 0x35, 0x35, 0x32, 0x34, 0x30, 0x35, 0x38, 0x39,
		0xff, 0x00, 0x06, 0x00, 0x0c, 0x32, 0x30, 0x32, 0x31};

	CU_ASSERT(decode_gtpv1_pdu_notification_reject_req(buf, &decode) == 77);
	CU_ASSERT(decode_gtpv1_pdu_notification_reject_req(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_pdu_notification_reject_req(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_pdu_notification_reject_req(buf, NULL) == -1);

	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);

	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_PDU_NOTIFICATION_REJECT_REQ);
	CU_ASSERT_EQUAL(decode.header.message_len, 69);
	CU_ASSERT_EQUAL(decode.header.teid, 0x372f0000);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.cause.header.type, GTPV1_IE_CAUSE);
	CU_ASSERT_EQUAL(decode.cause.cause_value, 128);

	CU_ASSERT_EQUAL(decode.tunn_endpt_idnt_control_plane.header.type, GTPV1_IE_TEID_CONTROL_PLANE);
	CU_ASSERT_EQUAL(decode.tunn_endpt_idnt_control_plane.teid, 0x00ab);

	CU_ASSERT_EQUAL(decode.end_user_address.header.type, GTPV1_IE_END_USER_ADDR);
	CU_ASSERT_EQUAL(decode.end_user_address.header.length, 6);
	CU_ASSERT_EQUAL(decode.end_user_address.spare, 0xf);
	CU_ASSERT_EQUAL(decode.end_user_address.pdp_type_org, 1);
	CU_ASSERT_EQUAL(decode.end_user_address.pdp_type_number, 0x21);
	CU_ASSERT_EQUAL(decode.end_user_address.pdp_address.ipv4, 3232235564);

	CU_ASSERT_EQUAL(decode.apn.header.type, GTPV1_IE_APN);
	CU_ASSERT_EQUAL(decode.apn.header.length, 13);
	CU_ASSERT_NSTRING_EQUAL(decode.apn.apn_value,"nextphones.co",13);

	CU_ASSERT_EQUAL(decode.protocol_config_options.header.type, GTPV1_IE_PROTOCOL_CONFIG_OPTIONS);
	CU_ASSERT_EQUAL(decode.protocol_config_options.header.length, 25);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_flag_ext , 1);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_flag_spare , 0);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_cfg_proto , 1);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content_count , 2);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[0].prot_or_cont_id , 2);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[0].length , 9);
	CU_ASSERT_NSTRING_EQUAL(decode.protocol_config_options.pco.pco_content[0].content,"355240599",9);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[1].prot_or_cont_id , 2);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[1].length , 9);
	CU_ASSERT_NSTRING_EQUAL(decode.protocol_config_options.pco.pco_content[1].content,"355240589",9);

	CU_ASSERT_EQUAL(decode.private_extension.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.private_extension.header.length, 6);
	CU_ASSERT_EQUAL(decode.private_extension.extension_identifier, 12);
	CU_ASSERT_NSTRING_EQUAL(decode.private_extension.extension_value,"2021", 4);
}

void test_decode_gtpv1_pdu_notification_reject_rsp(void)
{
	gtpv1_pdu_notification_reject_rsp_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x1e, 0x00, 0x0b, 0x37, 0x2f, 0x00, 0x00,
		0x01, 0x80, 0xff, 0x00, 0x06, 0x00, 0x0c, 0x32, 0x30, 0x32, 0x31};

	CU_ASSERT(decode_gtpv1_pdu_notification_reject_rsp(buf, &decode) == 19);
	CU_ASSERT(decode_gtpv1_pdu_notification_reject_rsp(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_pdu_notification_reject_rsp(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_pdu_notification_reject_rsp(buf, NULL) == -1);

	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);

	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_PDU_NOTIFICATION_REJECT_RSP);
	CU_ASSERT_EQUAL(decode.header.message_len, 11);
	CU_ASSERT_EQUAL(decode.header.teid, 0x372f0000);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.cause.header.type, GTPV1_IE_CAUSE);
	CU_ASSERT_EQUAL(decode.cause.cause_value, 128);

	CU_ASSERT_EQUAL(decode.private_extension.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.private_extension.header.length, 6);
	CU_ASSERT_EQUAL(decode.private_extension.extension_identifier, 12);
	CU_ASSERT_NSTRING_EQUAL(decode.private_extension.extension_value,"2021", 4);
}

void test_decode_gtpv1_initiate_pdp_ctxt_active_req(void)
{
	gtpv1_initiate_pdp_ctxt_active_req_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x16, 0x00, 0x5d, 0x00, 0x00, 0x00, 0x00,
		0x14, 0x09, 0x84, 0x00, 0x19, 0x81, 0x00, 0x02, 0x09, 0x33,
		0x35, 0x35, 0x32, 0x34, 0x30, 0x35, 0x39, 0x39, 0x00, 0x02,
		0x09, 0x33, 0x35, 0x35, 0x32, 0x34, 0x30, 0x35, 0x38, 0x39,
		0x87, 0x00, 0x15, 0x02, 0x12, 0x31, 0x04, 0x2a, 0x03, 0x7b,
		0xea, 0x11, 0x06, 0x7a, 0xde, 0x11, 0x16, 0x0b, 0x21, 0x16,
		0x2c, 0x21, 0x22, 0x17, 0x89, 0x00, 0x13, 0x32, 0x15, 0x01,
		0x01, 0x01, 0x25, 0x01, 0x02, 0x01, 0x00, 0x01, 0x02, 0x01,
		0x02, 0x01, 0x03, 0x03, 0x02, 0x00, 0xb7, 0x00, 0x01, 0x05,
		0xbf, 0x00, 0x01, 0x71, 0xff, 0x00, 0x06, 0x00, 0x0c, 0x32,
		0x30, 0x32, 0x31};

	CU_ASSERT(decode_gtpv1_initiate_pdp_ctxt_active_req(buf, &decode) == 101);
	CU_ASSERT(decode_gtpv1_initiate_pdp_ctxt_active_req(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_initiate_pdp_ctxt_active_req(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_initiate_pdp_ctxt_active_req(buf, NULL) == -1);

	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);

	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_INITIATE_PDP_CTXT_ACTIVATION_REQ);
	CU_ASSERT_EQUAL(decode.header.message_len, 93);
	CU_ASSERT_EQUAL(decode.header.teid, 0);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.linked_nsapi.header.type, GTPV1_IE_NSAPI);
	CU_ASSERT_EQUAL(decode.linked_nsapi.spare, 0);
	CU_ASSERT_EQUAL(decode.linked_nsapi.nsapi_value, 9);

	CU_ASSERT_EQUAL(decode.protocol_config_options.header.type, GTPV1_IE_PROTOCOL_CONFIG_OPTIONS);
	CU_ASSERT_EQUAL(decode.protocol_config_options.header.length, 25);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_flag_ext , 1);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_flag_spare , 0);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_cfg_proto , 1);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content_count , 2);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[0].prot_or_cont_id , 2);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[0].length , 9);
	CU_ASSERT_NSTRING_EQUAL(decode.protocol_config_options.pco.pco_content[0].content,"355240599",9);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[1].prot_or_cont_id , 2);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[1].length , 9);
	CU_ASSERT_NSTRING_EQUAL(decode.protocol_config_options.pco.pco_content[1].content,"355240589",9);

	CU_ASSERT_EQUAL(decode.qos_profile.header.type, GTPV1_IE_QOS);
	CU_ASSERT_EQUAL(decode.qos_profile.header.length, 21);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.allocation_retention_priority, 2);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.spare1, 0);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.delay_class, 2);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.reliablity_class, 2);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.peak_throughput, 3);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.spare2, 0);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.precedence_class, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.spare3, 0);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.mean_throughput, 4);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.traffic_class, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.delivery_order, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.delivery_erroneous_sdu, 2);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_sdu_size, 3);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_uplink, 123);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_downlink, 234);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.residual_ber, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.sdu_error_ratio, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.transfer_delay, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.traffic_handling_priority, 2);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_uplink, 122);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_downlink, 222);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.spare4, 0);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.signalling_indication, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.source_statistics_descriptor, 1);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_downlink_ext1, 22);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_downlink_ext1, 11);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_uplink_ext1, 33);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_uplink_ext1, 22);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_downlink_ext2, 44);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_downlink_ext2, 33);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.max_bitrate_uplink_ext2, 34);
	CU_ASSERT_EQUAL(decode.qos_profile.qos.guaranteed_bitrate_uplink_ext2, 23);

	CU_ASSERT_EQUAL(decode.tft.header.type, GTPV1_IE_TFT);
	CU_ASSERT_EQUAL(decode.tft.header.length, 19);
	CU_ASSERT_EQUAL(decode.tft.tft_op_code, 1);
	CU_ASSERT_EQUAL(decode.tft.e_bit, 1);
	CU_ASSERT_EQUAL(decode.tft.no_packet_filters, 2);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[0].spare, 0);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[0].filter_direction, 1);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[0].filter_id, 5);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[0].filter_eval_precedence, 1);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[0].filter_content_length, 1);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[0].filter_content[0], 1);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[1].spare, 0);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[1].filter_direction, 2);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[1].filter_id, 5);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[1].filter_eval_precedence, 1);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[1].filter_content_length, 2);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[1].filter_content[0], 1);
	CU_ASSERT_EQUAL(decode.tft.packet_filter_list_new[1].filter_content[1], 0);
	CU_ASSERT_EQUAL(decode.tft.parameters_list[0].parameter_id, 1);
	CU_ASSERT_EQUAL(decode.tft.parameters_list[0].parameter_content_length, 2);
	CU_ASSERT_EQUAL(decode.tft.parameters_list[0].parameter_content[0], 1);
	CU_ASSERT_EQUAL(decode.tft.parameters_list[0].parameter_content[1], 2);
	CU_ASSERT_EQUAL(decode.tft.parameters_list[1].parameter_id, 1);
	CU_ASSERT_EQUAL(decode.tft.parameters_list[1].parameter_content_length, 3);
	CU_ASSERT_EQUAL(decode.tft.parameters_list[1].parameter_content[0], 3);
	CU_ASSERT_EQUAL(decode.tft.parameters_list[1].parameter_content[1], 2);
	CU_ASSERT_EQUAL(decode.tft.parameters_list[1].parameter_content[2], 0);

	CU_ASSERT_EQUAL(decode.correlation_id.header.type, GTPV1_IE_CORRELATION_ID);
	CU_ASSERT_EQUAL(decode.correlation_id.header.length, 1);
	CU_ASSERT_EQUAL(decode.correlation_id.correlation_id, 5);

	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.header.type, GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_I);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.header.length, 1);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.spare,0);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.pci,1);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.pl, 12);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.spare2,0);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_1.pvi, 1);

	CU_ASSERT_EQUAL(decode.private_extension.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.private_extension.header.length, 6);
	CU_ASSERT_EQUAL(decode.private_extension.extension_identifier, 12);
	CU_ASSERT_NSTRING_EQUAL(decode.private_extension.extension_value,"2021", 4);
}

void test_decode_gtpv1_initiate_pdp_ctxt_active_rsp(void)
{
	gtpv1_initiate_pdp_ctxt_active_rsp_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x17, 0x00, 0x27, 0x37, 0x2f, 0x00, 0x00,
		0x01, 0x80, 0xff, 0x00, 0x06, 0x00, 0x0c, 0x32, 0x30, 0x32,
		0x31, 0x84, 0x00, 0x19, 0x81, 0x00, 0x02, 0x09, 0x33, 0x35,
		0x35, 0x32, 0x34, 0x30, 0x35, 0x39, 0x39, 0x00, 0x02, 0x09,
		0x33, 0x35, 0x35, 0x32, 0x34, 0x30, 0x35, 0x38, 0x39};

	CU_ASSERT(decode_gtpv1_initiate_pdp_ctxt_active_rsp(buf, &decode) == 47);
	CU_ASSERT(decode_gtpv1_initiate_pdp_ctxt_active_rsp(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_initiate_pdp_ctxt_active_rsp(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_initiate_pdp_ctxt_active_rsp(buf, NULL) == -1);

	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);

	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_INITIATE_PDP_CTXT_ACTIVATION_RSP);
	CU_ASSERT_EQUAL(decode.header.message_len, 39);
	CU_ASSERT_EQUAL(decode.header.teid, 0x372f0000);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.cause.header.type, GTPV1_IE_CAUSE);
	CU_ASSERT_EQUAL(decode.cause.cause_value, 128);

	CU_ASSERT_EQUAL(decode.protocol_config_options.header.type, GTPV1_IE_PROTOCOL_CONFIG_OPTIONS);
	CU_ASSERT_EQUAL(decode.protocol_config_options.header.length, 25);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_flag_ext , 1);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_flag_spare , 0);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_cfg_proto , 1);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content_count , 2);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[0].prot_or_cont_id , 2);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[0].length , 9);
	CU_ASSERT_NSTRING_EQUAL(decode.protocol_config_options.pco.pco_content[0].content,"355240599",9);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[1].prot_or_cont_id , 2);
	CU_ASSERT_EQUAL(decode.protocol_config_options.pco.pco_content[1].length , 9);
	CU_ASSERT_NSTRING_EQUAL(decode.protocol_config_options.pco.pco_content[1].content,"355240589",9);

	CU_ASSERT_EQUAL(decode.private_extension.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.private_extension.header.length, 6);
	CU_ASSERT_EQUAL(decode.private_extension.extension_identifier, 12);
	CU_ASSERT_NSTRING_EQUAL(decode.private_extension.extension_value,"2021", 4);
}

void test_decode_gtpv1_send_routeing_info_for_gprs_req(void)
{
	gtpv1_send_routeing_info_for_gprs_req_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x20, 0x00, 0x12, 0x37, 0x2f, 0x00, 0x00,
		0x02, 0x72, 0x02, 0x13, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff,
		0x00, 0x06, 0x00, 0x0c, 0x32, 0x30, 0x32, 0x31};

	CU_ASSERT(decode_gtpv1_send_routeing_info_for_gprs_req(buf, &decode) == 26);
	CU_ASSERT(decode_gtpv1_send_routeing_info_for_gprs_req(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_send_routeing_info_for_gprs_req(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_send_routeing_info_for_gprs_req(buf, NULL) == -1);

	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);

	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_SEND_ROUTEING_INFO_FOR_GPRS_REQ);
	CU_ASSERT_EQUAL(decode.header.message_len, 18);
	CU_ASSERT_EQUAL(decode.header.teid, 0x372f0000);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.imsi.header.type, GTPV1_IE_IMSI);
	CU_ASSERT_EQUAL(decode.imsi.imsi_number_digits, 272031000000000);

	CU_ASSERT_EQUAL(decode.private_extension.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.private_extension.header.length, 6);
	CU_ASSERT_EQUAL(decode.private_extension.extension_identifier, 12);
	CU_ASSERT_NSTRING_EQUAL(decode.private_extension.extension_value,"2021", 4);
}

void test_decode_gtpv1_send_routeing_info_for_gprs_rsp(void)
{
	gtpv1_send_routeing_info_for_gprs_rsp_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x21, 0x00, 0x1f, 0x37, 0x2f, 0x00, 0x00,
		0x01, 0x80, 0x02, 0x72, 0x02, 0x13, 0x00, 0x00, 0x00, 0x00,
		0xf0, 0x0b, 0x01, 0x1d, 0x02, 0x85, 0x00, 0x04, 0xc0, 0xa8,
		0x00, 0x2c, 0xff, 0x00, 0x06, 0x00, 0x0c, 0x32, 0x30, 0x32, 0x31};

	CU_ASSERT(decode_gtpv1_send_routeing_info_for_gprs_rsp(buf, &decode) == 39);
	CU_ASSERT(decode_gtpv1_send_routeing_info_for_gprs_rsp(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_send_routeing_info_for_gprs_rsp(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_send_routeing_info_for_gprs_rsp(buf, NULL) == -1);

	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);

	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_SEND_ROUTEING_INFO_FOR_GPRS_RSP);
	CU_ASSERT_EQUAL(decode.header.message_len, 31);
	CU_ASSERT_EQUAL(decode.header.teid, 0x372f0000);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.cause.header.type, GTPV1_IE_CAUSE);
	CU_ASSERT_EQUAL(decode.cause.cause_value, 128);

	CU_ASSERT_EQUAL(decode.imsi.header.type, GTPV1_IE_IMSI);
	CU_ASSERT_EQUAL(decode.imsi.imsi_number_digits, 272031000000000);

	CU_ASSERT_EQUAL(decode.map_cause.header.type, GTPV1_IE_MAP_CAUSE);
	CU_ASSERT_EQUAL(decode.map_cause.map_cause_value, 1);

	CU_ASSERT_EQUAL(decode.ms_not_rechable_reason.header.type, GTPV1_IE_MS_NOT_RECHABLE_REASON);
	CU_ASSERT_EQUAL(decode.ms_not_rechable_reason.reason_for_absence, 2);

	CU_ASSERT_EQUAL(decode.gsn_addr.header.type, GTPV1_IE_GSN_ADDR);
	CU_ASSERT_EQUAL(decode.gsn_addr.header.length, 4);
	CU_ASSERT_EQUAL(decode.gsn_addr.gsn_address.ipv4, 3232235564);

	CU_ASSERT_EQUAL(decode.private_extension.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.private_extension.header.length, 6);
	CU_ASSERT_EQUAL(decode.private_extension.extension_identifier, 12);
	CU_ASSERT_NSTRING_EQUAL(decode.private_extension.extension_value,"2021", 4);
}

void test_decode_gtpv1_failure_report_req(void)
{
	gtpv1_failure_report_req_t decode = {0};
	uint8_t buf[SIZE]  = {0x30, 0x22, 0x00, 0x12, 0x37, 0x2f, 0x00, 0x00,
		0x02, 0x72, 0x02, 0x13, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff,
		0x00, 0x06, 0x00, 0x0c, 0x32, 0x30, 0x32, 0x31};

	CU_ASSERT(decode_gtpv1_failure_report_req(buf, &decode) == 26);
	CU_ASSERT(decode_gtpv1_failure_report_req(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_failure_report_req(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_failure_report_req(buf, NULL) == -1);

	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);

	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_FAILURE_REPORT_REQ);
	CU_ASSERT_EQUAL(decode.header.message_len, 18);
	CU_ASSERT_EQUAL(decode.header.teid, 0x372f0000);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.imsi.header.type, GTPV1_IE_IMSI);
	CU_ASSERT_EQUAL(decode.imsi.imsi_number_digits, 272031000000000);

	CU_ASSERT_EQUAL(decode.private_extension.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.private_extension.header.length, 6);
	CU_ASSERT_EQUAL(decode.private_extension.extension_identifier, 12);
	CU_ASSERT_NSTRING_EQUAL(decode.private_extension.extension_value,"2021", 4);
}

void test_decode_gtpv1_failure_report_rsp(void)
{
	gtpv1_failure_report_rsp_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x23, 0x00, 0x0d, 0x37, 0x2f, 0x00, 0x00,
		0x01, 0x80, 0x0b, 0x01, 0xff, 0x00, 0x06, 0x00, 0x0c, 0x32,
		0x30, 0x32, 0x31};

	CU_ASSERT(decode_gtpv1_failure_report_rsp(buf, &decode) == 21);
	CU_ASSERT(decode_gtpv1_failure_report_rsp(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_failure_report_rsp(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_failure_report_rsp(buf, NULL) == -1);

	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);

	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_FAILURE_REPORT_RSP);
	CU_ASSERT_EQUAL(decode.header.message_len, 13);
	CU_ASSERT_EQUAL(decode.header.teid, 0x372f0000);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.cause.header.type, GTPV1_IE_CAUSE);
	CU_ASSERT_EQUAL(decode.cause.cause_value, 128);

	CU_ASSERT_EQUAL(decode.map_cause.header.type, GTPV1_IE_MAP_CAUSE);
	CU_ASSERT_EQUAL(decode.map_cause.map_cause_value, 1);

	CU_ASSERT_EQUAL(decode.private_extension.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.private_extension.header.length, 6);
	CU_ASSERT_EQUAL(decode.private_extension.extension_identifier, 12);
	CU_ASSERT_NSTRING_EQUAL(decode.private_extension.extension_value,"2021", 4);
}

void test_decode_gtpv1_note_ms_gprs_present_req(void)
{
	gtpv1_note_ms_gprs_present_req_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x24, 0x00, 0x19, 0x37, 0x2f, 0x00, 0x00,
		0x02, 0x72, 0x02, 0x13, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x85,
		0x00, 0x04, 0xc0, 0xa8, 0x00, 0x2c, 0xff, 0x00, 0x06, 0x00,
		0x0c, 0x32, 0x30, 0x32, 0x31};

	CU_ASSERT(decode_gtpv1_note_ms_gprs_present_req(buf, &decode) == 33);
	CU_ASSERT(decode_gtpv1_note_ms_gprs_present_req(NULL, NULL) ==  -1);
	CU_ASSERT(decode_gtpv1_note_ms_gprs_present_req(NULL, &decode)== -1);
	CU_ASSERT(decode_gtpv1_note_ms_gprs_present_req(buf, NULL) == -1);
	
	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);
	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_NOTE_MS_GPRS_PRESENT_REQ);
	CU_ASSERT_EQUAL(decode.header.message_len, 25);
	CU_ASSERT_EQUAL(decode.header.teid, 0x372f0000);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.imsi.header.type, GTPV1_IE_IMSI);
	CU_ASSERT_EQUAL(decode.imsi.imsi_number_digits, 272031000000000);

	CU_ASSERT_EQUAL(decode.gsn_addr.header.type, GTPV1_IE_GSN_ADDR);
	CU_ASSERT_EQUAL(decode.gsn_addr.header.length, 4);
	CU_ASSERT_EQUAL(decode.gsn_addr.gsn_address.ipv4, 3232235564);

	CU_ASSERT_EQUAL(decode.private_extension.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.private_extension.header.length, 6);
	CU_ASSERT_EQUAL(decode.private_extension.extension_identifier, 12);
	CU_ASSERT_NSTRING_EQUAL(decode.private_extension.extension_value,"2021", 4);
}

void test_decode_gtpv1_note_ms_gprs_present_rsp(void)
{
	gtpv1_note_ms_gprs_present_rsp_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x25, 0x00, 0x0b, 0x37, 0x2f, 0x00, 0x00,
		0x01, 0x80, 0xff, 0x00, 0x06, 0x00, 0x0c, 0x32, 0x30, 0x32, 0x31};

	CU_ASSERT(decode_gtpv1_note_ms_gprs_present_rsp(buf, &decode) == 19);
	CU_ASSERT(decode_gtpv1_note_ms_gprs_present_rsp(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_note_ms_gprs_present_rsp(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_note_ms_gprs_present_rsp(buf, NULL) == -1);
	
	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);
	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_NOTE_MS_GPRS_PRESENT_RSP);
	CU_ASSERT_EQUAL(decode.header.message_len, 11);
	CU_ASSERT_EQUAL(decode.header.teid, 0x372f0000);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.cause.header.type, GTPV1_IE_CAUSE);
	CU_ASSERT_EQUAL(decode.cause.cause_value, 128);

	CU_ASSERT_EQUAL(decode.private_extension.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.private_extension.header.length, 6);
	CU_ASSERT_EQUAL(decode.private_extension.extension_identifier, 12);
	CU_ASSERT_NSTRING_EQUAL(decode.private_extension.extension_value,"2021", 4);
}

void test_decode_gtpv1_identification_req(void)
{
	gtpv1_identification_req_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x30, 0x00, 0x24, 0x37, 0x2f, 0x00, 0x00, 
		0x03, 0x04, 0xf4, 0x87, 0x00, 0x14, 0x14, 0x05, 0x00, 0x00,
		0x00, 0x01, 0x0c, 0x00, 0x00, 0x01, 0x85, 0x00, 0x04, 0xc0,
		0xa8, 0x00, 0x2c, 0xa3, 0x00, 0x01, 0x03, 0xff, 0x00, 0x06,
		0x00, 0x0c, 0x32, 0x30, 0x32, 0x31};

	CU_ASSERT(decode_gtpv1_identification_req(buf, &decode) == 44);
	CU_ASSERT(decode_gtpv1_identification_req(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_identification_req(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_identification_req(buf, NULL) == -1);

	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);
	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_IDENTIFICATION_REQ);
	CU_ASSERT_EQUAL(decode.header.message_len, 36);
	CU_ASSERT_EQUAL(decode.header.teid, 0x372f0000);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.routing_area_identity.header.type, GTPV1_IE_ROUTEING_AREA_IDENTITY);
	CU_ASSERT_EQUAL(decode.routing_area_identity.rai_value.mcc_digit_2, 0x0);
	CU_ASSERT_EQUAL(decode.routing_area_identity.rai_value.mcc_digit_1, 0x4);
	CU_ASSERT_EQUAL(decode.routing_area_identity.rai_value.mnc_digit_3, 0x8);
	CU_ASSERT_EQUAL(decode.routing_area_identity.rai_value.mcc_digit_3, 0x4);
	CU_ASSERT_EQUAL(decode.routing_area_identity.rai_value.mnc_digit_2, 0x7);
	CU_ASSERT_EQUAL(decode.routing_area_identity.rai_value.mnc_digit_1, 0x0);
	CU_ASSERT_EQUAL(decode.routing_area_identity.rai_value.lac, 0x14);
	CU_ASSERT_EQUAL(decode.routing_area_identity.rai_value.rac, 0x14);

	CU_ASSERT_EQUAL(decode.packet_tmsi.header.type, GTPV1_IE_PACKET_TMSI);
	CU_ASSERT_EQUAL(decode.packet_tmsi.p_tmsi, 1);

	CU_ASSERT_EQUAL(decode.p_tmsi_signature.header.type, GTPV1_IE_P_TMSI_SIGNATURE);
	CU_ASSERT_EQUAL(decode.p_tmsi_signature.p_tmsi_signature, 1);

	CU_ASSERT_EQUAL(decode.sgsn_addr_control_plane.header.type, GTPV1_IE_GSN_ADDR);
	CU_ASSERT_EQUAL(decode.sgsn_addr_control_plane.header.length, 4);
	CU_ASSERT_EQUAL(decode.sgsn_addr_control_plane.gsn_address.ipv4, 3232235564);

	CU_ASSERT_EQUAL(decode.hop_counter.header.type, GTPV1_IE_HOP_COUNTER);
	CU_ASSERT_EQUAL(decode.hop_counter.header.length, 1);
	CU_ASSERT_EQUAL(decode.hop_counter.hop_counter, 3);

	CU_ASSERT_EQUAL(decode.private_extension.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.private_extension.header.length, 6);
	CU_ASSERT_EQUAL(decode.private_extension.extension_identifier, 12);
	CU_ASSERT_NSTRING_EQUAL(decode.private_extension.extension_value,"2021", 4);
}

void test_decode_gtpv1_identification_rsp(void)
{
	gtpv1_identification_rsp_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x31, 0x00, 0x6a, 0x37, 0x2f, 0x00, 0x00,
		0x01, 0x80, 0x02, 0x72, 0x02, 0x13, 0x00, 0x00, 0x00, 0x00,
		0xf0, 0x09, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
		0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x00, 0x00,
		0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		0x88, 0x00, 0x34, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
		0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x01,
		0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
		0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
		0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
		0x31, 0x31, 0x31, 0x01, 0x31, 0xd9, 0x00, 0x04, 0x00, 0x00,
		0x00, 0x0f, 0xde, 0x00, 0x01, 0x0a};

	CU_ASSERT(decode_gtpv1_identification_rsp(buf, &decode) == 114)
	CU_ASSERT(decode_gtpv1_identification_rsp(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_identification_rsp(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_identification_rsp(buf, NULL) == -1);
	
	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);
	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_IDENTIFICATION_RSP);
	CU_ASSERT_EQUAL(decode.header.message_len, 106);
	CU_ASSERT_EQUAL(decode.header.teid, 0x372f0000);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.cause.header.type, GTPV1_IE_CAUSE);
	CU_ASSERT_EQUAL(decode.cause.cause_value, 128);

	CU_ASSERT_EQUAL(decode.imsi.header.type, GTPV1_IE_IMSI);
	CU_ASSERT_EQUAL(decode.imsi.imsi_number_digits, 272031000000000);

	CU_ASSERT_EQUAL(decode.auth_triplet.header.type, GTPV1_IE_AUTH_TRIPLET);
	CU_ASSERT_NSTRING_EQUAL(decode.auth_triplet.auth_triplet_value.rand, "1111111111111111", 16);
	CU_ASSERT_EQUAL(decode.auth_triplet.auth_triplet_value.sres, 2);
	CU_ASSERT_EQUAL(decode.auth_triplet.auth_triplet_value.kc, 2);

	CU_ASSERT_EQUAL(decode.auth_quintuplet.header.type, GTPV1_IE_AUTH_QUINTUPLET);
	CU_ASSERT_EQUAL(decode.auth_quintuplet.header.length, 52);
	CU_ASSERT_NSTRING_EQUAL(decode.auth_quintuplet.auth_quintuplet_value.rand, "1111111111111111", 16);
	CU_ASSERT_EQUAL(decode.auth_quintuplet.auth_quintuplet_value.xres_length, 1);
	CU_ASSERT_STRING_EQUAL(decode.auth_quintuplet.auth_quintuplet_value.xres, "1");
	CU_ASSERT_NSTRING_EQUAL(decode.auth_quintuplet.auth_quintuplet_value.ck, "1111111111111111", 16);
	CU_ASSERT_NSTRING_EQUAL(decode.auth_quintuplet.auth_quintuplet_value.ik, "1111111111111111", 16);
	CU_ASSERT_EQUAL(decode.auth_quintuplet.auth_quintuplet_value.autn_length, 1);
	CU_ASSERT_STRING_EQUAL(decode.auth_quintuplet.auth_quintuplet_value.autn, "1");

	CU_ASSERT_EQUAL(decode.ue_usage_type.header.type, GTPV1_IE_UE_USAGE_TYPE);
	CU_ASSERT_EQUAL(decode.ue_usage_type.header.length, 4);
	CU_ASSERT_EQUAL(decode.ue_usage_type.ue_usage_type_value, 15);

	CU_ASSERT_EQUAL(decode.iov_updates_counter.header.type, GTPV1_IE_IOV_UPDATES_COUNTER);
	CU_ASSERT_EQUAL(decode.iov_updates_counter.header.length, 1);
	CU_ASSERT_EQUAL(decode.iov_updates_counter.iov_updates_counter, 10);
}

void test_decode_gtpv1_sgsn_ctxt_req(void)
{
	gtpv1_sgsn_ctxt_req_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x32, 0x00, 0x51, 0x37, 0x2f, 0x00, 0x00,
		0x02, 0x72, 0x02, 0x13, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x03,
		0x04, 0xf4, 0x87, 0x00, 0x14, 0x14, 0x04, 0x00, 0x00, 0x00,
		0x01, 0x05, 0x00, 0x00, 0x00, 0x01, 0x0c, 0x00, 0x00, 0x01,
		0x0d, 0x01, 0x11, 0x00, 0xff, 0xfe, 0xee, 0x85, 0x00, 0x04,
		0xc0, 0xa8, 0x00, 0x2c, 0x85, 0x00, 0x10, 0x20, 0x01, 0xdb,
		0x80, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x66, 0x66, 0x77,
		0x77, 0x88, 0x88, 0x93, 0x00, 0x02, 0x31, 0x31, 0x97, 0x00,
		0x01, 0x02, 0xff, 0x00, 0x06, 0x00, 0x0c, 0x32, 0x30, 0x32,
		0x31};
	
	CU_ASSERT(decode_gtpv1_sgsn_context_req(buf, &decode) == 89);
	CU_ASSERT(decode_gtpv1_sgsn_context_req(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_sgsn_context_req(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_sgsn_context_req(buf, NULL) == -1);
	
	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);
	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_SGSN_CONTEXT_REQ);
	CU_ASSERT_EQUAL(decode.header.message_len, 81);
	CU_ASSERT_EQUAL(decode.header.teid, 0x372f0000);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.imsi.header.type, GTPV1_IE_IMSI);
	CU_ASSERT_EQUAL(decode.imsi.imsi_number_digits, 272031000000000);

	CU_ASSERT_EQUAL(decode.routing_area_identity.header.type, GTPV1_IE_ROUTEING_AREA_IDENTITY);
	CU_ASSERT_EQUAL(decode.routing_area_identity.rai_value.mcc_digit_2, 0x0);
	CU_ASSERT_EQUAL(decode.routing_area_identity.rai_value.mcc_digit_1, 0x4);
	CU_ASSERT_EQUAL(decode.routing_area_identity.rai_value.mnc_digit_3, 0x8);
	CU_ASSERT_EQUAL(decode.routing_area_identity.rai_value.mcc_digit_3, 0x4);
	CU_ASSERT_EQUAL(decode.routing_area_identity.rai_value.mnc_digit_2, 0x7);
	CU_ASSERT_EQUAL(decode.routing_area_identity.rai_value.mnc_digit_1, 0x0);
	CU_ASSERT_EQUAL(decode.routing_area_identity.rai_value.lac, 0x14);
	CU_ASSERT_EQUAL(decode.routing_area_identity.rai_value.rac, 0x14);

	CU_ASSERT_EQUAL(decode.temporary_logical_link_identifier.header.type, GTPV1_IE_TEMPORARY_LOGICAL_LINK_IDENTIFIER);
	CU_ASSERT_EQUAL(decode.temporary_logical_link_identifier.tlli, 1);

	CU_ASSERT_EQUAL(decode.packet_tmsi.header.type, GTPV1_IE_PACKET_TMSI);
	CU_ASSERT_EQUAL(decode.packet_tmsi.p_tmsi, 1);

	CU_ASSERT_EQUAL(decode.p_tmsi_signature.header.type, GTPV1_IE_P_TMSI_SIGNATURE);
	CU_ASSERT_EQUAL(decode.p_tmsi_signature.p_tmsi_signature, 1);

	CU_ASSERT_EQUAL(decode.ms_validated.header.type, GTPV1_IE_MS_VALIDATED);
	CU_ASSERT_EQUAL(decode.ms_validated.spare, 0);
	CU_ASSERT_EQUAL(decode.ms_validated.ms_validated, 1);

	CU_ASSERT_EQUAL(decode.tunn_endpt_idnt_control_plane.header.type, GTPV1_IE_TEID_CONTROL_PLANE);
	CU_ASSERT_EQUAL(decode.tunn_endpt_idnt_control_plane.teid, 0x0fffeee);

	CU_ASSERT_EQUAL(decode.sgsn_address_for_control_plane.header.type, GTPV1_IE_GSN_ADDR);
	CU_ASSERT_EQUAL(decode.sgsn_address_for_control_plane.header.length, 4);
	CU_ASSERT_EQUAL(decode.sgsn_address_for_control_plane.gsn_address.ipv4, 3232235564);

	CU_ASSERT_EQUAL(decode.alternative_sgsn_address_for_control_plane.header.type, GTPV1_IE_GSN_ADDR);
	CU_ASSERT_EQUAL(decode.alternative_sgsn_address_for_control_plane.header.length, 16);
	char addr9[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &decode.alternative_sgsn_address_for_control_plane.gsn_address.ipv6, addr9, INET6_ADDRSTRLEN);
	CU_ASSERT_NSTRING_EQUAL(addr9, "2001:db80:3333:4444:5555:6666:7777:8888",39);

	CU_ASSERT_EQUAL(decode.sgsn_number.header.type, GTPV1_IE_SGSN_NUMBER);
	CU_ASSERT_EQUAL(decode.sgsn_number.header.length, 2);
	CU_ASSERT_STRING_EQUAL(decode.sgsn_number.sgsn_number,"11");

	CU_ASSERT_EQUAL(decode.rat_type.header.type, GTPV1_IE_RAT_TYPE);
	CU_ASSERT_EQUAL(decode.rat_type.header.length, 1);
	CU_ASSERT_EQUAL(decode.rat_type.rat_type, 2);

	CU_ASSERT_EQUAL(decode.private_extension.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.private_extension.header.length, 6);
	CU_ASSERT_EQUAL(decode.private_extension.extension_identifier, 12);
	CU_ASSERT_NSTRING_EQUAL(decode.private_extension.extension_value,"2021", 4);
}

void test_decode_gtpv1_sgsn_ctxt_rsp(void)
{
	gtpv1_sgsn_ctxt_rsp_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x33, 0x01, 0x9a, 0x37, 0x2f, 0x00, 0x00,
		0x01, 0x80, 0x02, 0x72, 0x02, 0x13, 0x00, 0x00, 0x00, 0x00,
		0xf0, 0x11, 0x00, 0xff, 0xfe, 0xee, 0x16, 0x01, 0x00, 0x01,
		0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0x17, 0x02, 0x18, 0x12,
		0x19, 0x01, 0x04, 0x1a, 0x00, 0x01, 0x96, 0x00, 0x01, 0x01,
		0x81, 0x00, 0x2f, 0x79, 0x49, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x01, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
		0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x00,
		0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x01, 0x19, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x82, 0x00, 0x74, 0x65, 0x01, 0x15, 0x02, 0x12, 0x31, 0x04,
		0x2a, 0x03, 0x7b, 0xea, 0x11, 0x06, 0x7a, 0xde, 0x11, 0x16,
		0x0b, 0x21, 0x16, 0x2c, 0x21, 0x22, 0x17, 0x15, 0x02, 0x12,
		0x31, 0x04, 0x2a, 0x03, 0x7b, 0xea, 0x11, 0x06, 0x7a, 0xde,
		0x51, 0x16, 0x0b, 0x21, 0x16, 0x2c, 0x21, 0x22, 0x17, 0x15,
		0x02, 0x52, 0x31, 0x04, 0x2a, 0x03, 0x7b, 0xea, 0x11, 0x06,
		0x7a, 0xde, 0x11, 0x16, 0x0b, 0x21, 0x16, 0x2c, 0x21, 0x22,
		0x17, 0x00, 0x01, 0x00, 0x02, 0xff, 0xff, 0x37, 0x2f, 0x00,
		0x00, 0x37, 0x30, 0x00, 0x00, 0x00, 0xf1, 0x21, 0x04, 0x15,
		0x2c, 0x8a, 0x97, 0x04, 0x15, 0x2c, 0x8a, 0x8d, 0x04, 0x15,
		0x2c, 0x8a, 0x97, 0x0d, 0x6e, 0x65, 0x78, 0x74, 0x70, 0x68,
		0x6f, 0x6e, 0x65, 0x73, 0x2e, 0x63, 0x6f, 0x0a, 0x37, 0x85,
		0x00, 0x04, 0xc0, 0xa8, 0x00, 0x2c, 0x91, 0x00, 0x00, 0x9c,
		0x00, 0x22, 0x20, 0x37, 0x2f, 0x00, 0x00, 0x81, 0xf1, 0x21,
		0x04, 0x15, 0x2c, 0x8a, 0x97, 0x04, 0x15, 0x2c, 0x8a, 0x8d,
		0x0d, 0x6e, 0x65, 0x78, 0x74, 0x70, 0x68, 0x6f, 0x6e, 0x65,
		0x73, 0x2e, 0x63, 0x6f, 0x01, 0x05, 0xbd, 0x00, 0x02, 0x00,
		0x01, 0xbd, 0x00, 0x02, 0x00, 0x01, 0xbe, 0x00, 0x05, 0x67,
		0x73, 0x6c, 0x61, 0x62, 0xc0, 0x00, 0x02, 0x01, 0x45, 0xc1,
		0x00, 0x01, 0x25, 0xc7, 0x00, 0x08, 0xd6, 0xab, 0x55, 0xb5,
		0xb6, 0xbb, 0x52, 0x53, 0xc8, 0x00, 0x10, 0x00, 0x00, 0x00,
		0x08, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x20, 0x00,
		0x00, 0x00, 0x40, 0xc9, 0x00, 0x09, 0x01, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x01, 0xcc, 0x00, 0x02, 0x01, 0x01,
		0xcd, 0x00, 0x01, 0x01, 0xd5, 0x00, 0x02, 0x01, 0x01, 0xd7,
		0x00, 0x06, 0x01, 0x67, 0x73, 0x6c, 0x61, 0x62, 0xd9, 0x00,
		0x04, 0x00, 0x00, 0x00, 0x0f, 0xda, 0x00, 0x01, 0x07, 0x85,
		0x00, 0x10, 0x20, 0x01, 0xdb, 0x80, 0x33, 0x33, 0x44, 0x44,
		0x55, 0x55, 0x66, 0x66, 0x77, 0x77, 0x88, 0x88, 0x85, 0x00,
		0x10, 0x20, 0x01, 0xdb, 0x80, 0x33, 0x33, 0x44, 0x44, 0x55,
		0x55, 0x66, 0x66, 0x77, 0x77, 0x88, 0x88, 0xde, 0x00, 0x01,
		0x0a, 0xff, 0x00, 0x06, 0x00, 0x0c, 0x32, 0x30, 0x32, 0x31};

	CU_ASSERT(decode_gtpv1_sgsn_context_rsp(buf, &decode) == 418);
	CU_ASSERT(decode_gtpv1_sgsn_context_rsp(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_sgsn_context_rsp(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_sgsn_context_rsp(buf, NULL) == -1);
	
	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);
	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_SGSN_CONTEXT_RSP);
	CU_ASSERT_EQUAL(decode.header.message_len, 410);
	CU_ASSERT_EQUAL(decode.header.teid, 0x372f0000);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.cause.header.type, GTPV1_IE_CAUSE);
	CU_ASSERT_EQUAL(decode.cause.cause_value, 128);

	CU_ASSERT_EQUAL(decode.imsi.header.type, GTPV1_IE_IMSI);
	CU_ASSERT_EQUAL(decode.imsi.imsi_number_digits, 272031000000000);

	CU_ASSERT_EQUAL(decode.tunn_endpt_idnt_control_plane.header.type, GTPV1_IE_TEID_CONTROL_PLANE);
	CU_ASSERT_EQUAL(decode.tunn_endpt_idnt_control_plane.teid, 0x0fffeee);

	CU_ASSERT_EQUAL(decode.rab_context.header.type, GTPV1_IE_RAB_CONTEXT);
	CU_ASSERT_EQUAL(decode.rab_context.spare, 0);
	CU_ASSERT_EQUAL(decode.rab_context.nsapi, 1);
	CU_ASSERT_EQUAL(decode.rab_context.dl_gtp_u_sequence_number, 1);
	CU_ASSERT_EQUAL(decode.rab_context.ul_gtp_u_sequence_number, 2);
	CU_ASSERT_EQUAL(decode.rab_context.dl_pdcp_sequence_number, 1);
	CU_ASSERT_EQUAL(decode.rab_context.ul_pdcp_sequence_number, 2);

	CU_ASSERT_EQUAL(decode.radio_priority_sms.header.type, GTPV1_IE_RADIO_PRIORITY_SMS);
	CU_ASSERT_EQUAL(decode.radio_priority_sms.spare, 0);
	CU_ASSERT_EQUAL(decode.radio_priority_sms.radio_priority_sms, 2);

	CU_ASSERT_EQUAL(decode.radio_priority.header.type, GTPV1_IE_RADIO_PRIORITY);
	CU_ASSERT_EQUAL(decode.radio_priority.nsapi, 1);
	CU_ASSERT_EQUAL(decode.radio_priority.spare, 0);
	CU_ASSERT_EQUAL(decode.radio_priority.radio_priority, 2);

	CU_ASSERT_EQUAL(decode.packet_flow_id.header.type, GTPV1_IE_PACKET_FLOW_ID);
	CU_ASSERT_EQUAL(decode.packet_flow_id.spare, 0);
	CU_ASSERT_EQUAL(decode.packet_flow_id.nsapi, 1);
	CU_ASSERT_EQUAL(decode.packet_flow_id.packet_flow_id, 4);

	CU_ASSERT_EQUAL(decode.chrgng_char.header.type, GTPV1_IE_CHRGNG_CHAR);
	CU_ASSERT_EQUAL(decode.chrgng_char.chrgng_char_val, 1);

	CU_ASSERT_EQUAL(decode.radio_priority_lcs.header.type, GTPV1_IE_RADIO_PRIORITY_LCS);
	CU_ASSERT_EQUAL(decode.radio_priority_lcs.header.length, 1);
	CU_ASSERT_EQUAL(decode.radio_priority_lcs.spare, 0);
	CU_ASSERT_EQUAL(decode.radio_priority_lcs.radio_priority_lcs, 1);

	CU_ASSERT_EQUAL(decode.mm_context.header.type, GTPV1_IE_MM_CONTEXT);
	CU_ASSERT_EQUAL(decode.mm_context.header.length, 47);
	CU_ASSERT_EQUAL(decode.mm_context.mm_context.gsm_keys_and_triplet.spare, 15);
	CU_ASSERT_EQUAL(decode.mm_context.mm_context.gsm_keys_and_triplet.cksn, 1);
	CU_ASSERT_EQUAL(decode.mm_context.security_mode, 1);
	CU_ASSERT_EQUAL(decode.mm_context.mm_context.gsm_keys_and_triplet.no_of_vectors, 1);
	CU_ASSERT_EQUAL(decode.mm_context.mm_context.gsm_keys_and_triplet.used_cipher, 1);
	CU_ASSERT_EQUAL(decode.mm_context.mm_context.gsm_keys_and_triplet.kc, 1);
	CU_ASSERT_NSTRING_EQUAL(decode.mm_context.mm_context.gsm_keys_and_triplet.triplet[0].rand,"1111111111111111",16);
	CU_ASSERT_EQUAL(decode.mm_context.mm_context.gsm_keys_and_triplet.triplet[0].sres, 2);
	CU_ASSERT_EQUAL(decode.mm_context.mm_context.gsm_keys_and_triplet.triplet[0].kc, 2);
	CU_ASSERT_EQUAL(decode.mm_context.drx_parameter.split_pg_cycle_code, 1);
	CU_ASSERT_EQUAL(decode.mm_context.drx_parameter.cycle_length, 1);
	CU_ASSERT_EQUAL(decode.mm_context.drx_parameter.ccch, 1);
	CU_ASSERT_EQUAL(decode.mm_context.drx_parameter.timer, 1);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability_length, 4);

	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.GEA_1, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.sm_capabilities_via_dedicated_channels, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.sm_capabilities_via_gprs_channels, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.ucs2_support, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.ss_screening_indicator, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.solsa_capability, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.revision_level_indicator, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.pfc_feature_mode, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.GEA_2, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.GEA_3, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.GEA_4, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.GEA_5, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.GEA_6, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.GEA_7, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.lcs_va_capability, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.ps_ge_ut_iu_mode_capability, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.ps_ge_ut_s1_mode_capability, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.emm_combined_procedure_capability, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.isr_support, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.srvcc_to_ge_ut_capability, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.epc_capability, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.nf_capability, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.ge_network_sharing_capability, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.user_plane_integrity_protection_support, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.GIA_4, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.GIA_5, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.GIA_6, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.GIA_7, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.ePCO_ie_indicator, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.restriction_on_use_of_enhanced_coverage_capability, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.dual_connectivity_of_e_ut_with_nr_capability, 0);
	CU_ASSERT_EQUAL(decode.mm_context.container_length, 0);

	CU_ASSERT_EQUAL(decode.pdp_context.header.type, GTPV1_IE_PDP_CONTEXT);
	CU_ASSERT_EQUAL(decode.pdp_context.header.length, 116);
	CU_ASSERT_EQUAL(decode.pdp_context.ea, 0);
	CU_ASSERT_EQUAL(decode.pdp_context.vaa, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.asi, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.order, 0);
	CU_ASSERT_EQUAL(decode.pdp_context.nsapi, 5);
	CU_ASSERT_EQUAL(decode.pdp_context.spare, 0);
	CU_ASSERT_EQUAL(decode.pdp_context.sapi, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub_length, 21);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.allocation_retention_priority, 2);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.spare1, 0);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.delay_class, 2);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.reliablity_class, 2);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.peak_throughput, 3);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.spare2, 0);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.precedence_class, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.spare3, 0);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.mean_throughput, 4);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.traffic_class, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.delivery_order, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.delivery_erroneous_sdu, 2);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.max_sdu_size, 3);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.max_bitrate_uplink, 123);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.max_bitrate_downlink, 234);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.residual_ber, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.sdu_error_ratio, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.transfer_delay, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.traffic_handling_priority, 2);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.guaranteed_bitrate_uplink, 122);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.guaranteed_bitrate_downlink, 222);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.spare4, 0);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.signalling_indication, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.source_statistics_descriptor, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.max_bitrate_downlink_ext1, 22);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.guaranteed_bitrate_downlink_ext1, 11);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.max_bitrate_uplink_ext1, 33);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.guaranteed_bitrate_uplink_ext1, 22);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.max_bitrate_downlink_ext2, 44);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.guaranteed_bitrate_downlink_ext2, 33);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.max_bitrate_uplink_ext2, 34);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.guaranteed_bitrate_uplink_ext2, 23);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req_length, 21);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.allocation_retention_priority, 2);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.spare1, 0);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.delay_class, 2);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.reliablity_class, 2);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.peak_throughput, 3);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.spare2, 0);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.precedence_class, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.spare3, 0);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.mean_throughput, 4);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.traffic_class, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.delivery_order, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.delivery_erroneous_sdu, 2);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.max_sdu_size, 3);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.max_bitrate_uplink, 123);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.max_bitrate_downlink, 234);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.residual_ber, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.sdu_error_ratio, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.transfer_delay, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.traffic_handling_priority, 2);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.guaranteed_bitrate_uplink, 122);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.guaranteed_bitrate_downlink, 222);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.spare4, 0);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.signalling_indication, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.source_statistics_descriptor, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.max_bitrate_downlink_ext1, 22);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.guaranteed_bitrate_downlink_ext1, 11);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.max_bitrate_uplink_ext1, 33);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.guaranteed_bitrate_uplink_ext1, 22);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.max_bitrate_downlink_ext2, 44);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.guaranteed_bitrate_downlink_ext2, 33);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.max_bitrate_uplink_ext2, 34);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.guaranteed_bitrate_uplink_ext2, 23);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg_length, 21);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.allocation_retention_priority, 2);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.spare1, 0);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.delay_class, 2);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.reliablity_class, 2);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.peak_throughput, 3);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.spare2, 0);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.precedence_class, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.spare3, 0);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.mean_throughput, 4);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.traffic_class, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.delivery_order, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.delivery_erroneous_sdu, 2);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.max_sdu_size, 3);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.max_bitrate_uplink, 123);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.max_bitrate_downlink, 234);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.residual_ber, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.sdu_error_ratio, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.transfer_delay, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.traffic_handling_priority, 2);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.guaranteed_bitrate_uplink, 122);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.guaranteed_bitrate_downlink, 222);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.spare4, 0);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.signalling_indication, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.source_statistics_descriptor, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.max_bitrate_downlink_ext1, 22);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.guaranteed_bitrate_downlink_ext1, 11);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.max_bitrate_uplink_ext1, 33);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.guaranteed_bitrate_uplink_ext1, 22);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.max_bitrate_downlink_ext2, 44);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.guaranteed_bitrate_downlink_ext2, 33);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.max_bitrate_uplink_ext2, 34);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.guaranteed_bitrate_uplink_ext2, 23);
	CU_ASSERT_EQUAL(decode.pdp_context.sequence_number_down, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.sequence_number_up, 2);
	CU_ASSERT_EQUAL(decode.pdp_context.send_npdu_number, 255);
	CU_ASSERT_EQUAL(decode.pdp_context.rcv_npdu_number, 255);
	CU_ASSERT_EQUAL(decode.pdp_context.uplink_teid_cp, 0x372f0000);
	CU_ASSERT_EQUAL(decode.pdp_context.uplink_teid_data1, 0x37300000);
	CU_ASSERT_EQUAL(decode.pdp_context.pdp_ctxt_identifier, 0);
	CU_ASSERT_EQUAL(decode.pdp_context.spare2, 15);
	CU_ASSERT_EQUAL(decode.pdp_context.pdp_type_org, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.pdp_type_number1, 0x21);
	CU_ASSERT_EQUAL(decode.pdp_context.pdp_address_length1, 4);
	CU_ASSERT_EQUAL(decode.pdp_context.pdp_address1.ipv4, 355240599);
	CU_ASSERT_EQUAL(decode.pdp_context.ggsn_addr_cp_length, 4);
	CU_ASSERT_EQUAL(decode.pdp_context.ggsn_addr_cp.ipv4, 355240589);
	CU_ASSERT_EQUAL(decode.pdp_context.ggsn_addr_ut_length, 4);
	CU_ASSERT_EQUAL(decode.pdp_context.ggsn_addr_ut.ipv4, 355240599);

	CU_ASSERT_EQUAL(decode.gsn_addr_1.header.type, GTPV1_IE_GSN_ADDR);
	CU_ASSERT_EQUAL(decode.gsn_addr_1.header.length, 4);
	CU_ASSERT_EQUAL(decode.gsn_addr_1.gsn_address.ipv4, 3232235564);

	CU_ASSERT_EQUAL(decode.pdp_context_prioritization.header.type, GTPV1_IE_PDP_CONTEXT_PRIORITIZATION);

	CU_ASSERT_EQUAL(decode.mbms_ue_context.header.type, GTPV1_IE_MBMS_UE_CONTEXT);
	CU_ASSERT_EQUAL(decode.mbms_ue_context.header.length, 34);
	CU_ASSERT_EQUAL(decode.mbms_ue_context.linked_nsapi, 2);
	CU_ASSERT_EQUAL(decode.mbms_ue_context.spare1, 0);
	CU_ASSERT_EQUAL(decode.mbms_ue_context.uplink_teid_cp, 0x372f0000);
	CU_ASSERT_EQUAL(decode.mbms_ue_context.enhanced_nsapi, 129);
	CU_ASSERT_EQUAL(decode.mbms_ue_context.spare2, 15);
	CU_ASSERT_EQUAL(decode.mbms_ue_context.pdp_type_org, 1);
	CU_ASSERT_EQUAL(decode.mbms_ue_context.pdp_type_number, 0x21);
	CU_ASSERT_EQUAL(decode.mbms_ue_context.pdp_address_length, 4);
	CU_ASSERT_EQUAL(decode.mbms_ue_context.pdp_address.ipv4, 355240599);
	CU_ASSERT_EQUAL(decode.mbms_ue_context.ggsn_addr_cp_length, 4);
	CU_ASSERT_EQUAL(decode.mbms_ue_context.ggsn_addr_cp.ipv4, 355240589);
	CU_ASSERT_EQUAL(decode.mbms_ue_context.apn_length, 13);
	CU_ASSERT_STRING_EQUAL(decode.mbms_ue_context.apn,"nextphones.co");
	CU_ASSERT_EQUAL(decode.mbms_ue_context.spare3, 0);
	CU_ASSERT_EQUAL(decode.mbms_ue_context.transaction_identifier1, 1);
	CU_ASSERT_EQUAL(decode.mbms_ue_context.transaction_identifier2, 5);

	CU_ASSERT_EQUAL(decode.subscribed_rfsp_index.header.type, GTPV1_IE_RFSP_INDEX);
	CU_ASSERT_EQUAL(decode.subscribed_rfsp_index.header.length, 2);
	CU_ASSERT_EQUAL(decode.subscribed_rfsp_index.rfsp_index, 1);

	CU_ASSERT_EQUAL(decode.rfsp_index_in_use.header.type, GTPV1_IE_RFSP_INDEX);
	CU_ASSERT_EQUAL(decode.rfsp_index_in_use.header.length, 2);
	CU_ASSERT_EQUAL(decode.rfsp_index_in_use.rfsp_index, 1);

	CU_ASSERT_EQUAL(decode.co_located_ggsn_pgw_fqdn.header.type, GTPV1_IE_FQDN);
	CU_ASSERT_EQUAL(decode.co_located_ggsn_pgw_fqdn.header.length, 5);
	CU_ASSERT_STRING_EQUAL(decode.co_located_ggsn_pgw_fqdn.fqdn,"gslab");

	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_II.header.type, GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_II);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_II.header.length, 2);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_II.spare, 0);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_II.nsapi, 1);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_II.spare2, 0);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_II.pci, 1);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_II.pl, 1);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_II.spare3, 0);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_II.pvi, 1);

	CU_ASSERT_EQUAL(decode.extended_common_flag.header.type, GTPV1_IE_EXTENDED_COMMON_FLAG);
	CU_ASSERT_EQUAL(decode.extended_common_flag.header.length, 1);
	CU_ASSERT_EQUAL(decode.extended_common_flag.uasi, 0);
	CU_ASSERT_EQUAL(decode.extended_common_flag.bdwi, 0);
	CU_ASSERT_EQUAL(decode.extended_common_flag.pcri, 1);
	CU_ASSERT_EQUAL(decode.extended_common_flag.vb, 0);
	CU_ASSERT_EQUAL(decode.extended_common_flag.retloc, 0);
	CU_ASSERT_EQUAL(decode.extended_common_flag.cpsr, 1);
	CU_ASSERT_EQUAL(decode.extended_common_flag.ccrsi, 0);

	CU_ASSERT_EQUAL(decode.ue_network_capability.header.type, GTPV1_IE_UE_NETWORK_CAPABILITY);
	CU_ASSERT_EQUAL(decode.ue_network_capability.header.length, 8);
	CU_ASSERT_EQUAL(decode.ue_network_capability.eea0, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.eea1_128, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.eea2_128, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.eea3_128, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.eea4, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.eea5, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.eea6, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.eea7, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.eia0, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.eia1_128, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.eia2_128, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.eia3_128, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.eia4, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.eia5, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.eia6, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.eia7, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.uea0, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.uea1, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.uea2, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.uea3, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.uea4, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.uea5, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.uea6, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.uea7, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.ucs2, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.uia1, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.uia2, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.uia3, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.uia4, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.uia5, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.uia6, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.uia7, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.prose_dd, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.prose, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.h245_ash, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.acc_csfb, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.lpp, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.lcs, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.srvcc1x, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.nf, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.epco, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.hc_cp_ciot, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.erw_opdn, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.s1_udata, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.up_ciot, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.cp_ciot, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.prose_relay, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.prose_dc, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.bearers_15, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.sgc, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.n1mode, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.dcnr, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.cp_backoff, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.restrict_ec, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.v2x_pc5, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.multiple_drb, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.spare1, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.v2xnr_pcf, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.up_mt_edt, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.cp_mt_edt, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.wusa, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.racs, 1);

	CU_ASSERT_EQUAL(decode.ue_ambr.header.type, GTPV1_IE_UE_AMBR);
	CU_ASSERT_EQUAL(decode.ue_ambr.header.length, 16);
	CU_ASSERT_EQUAL(decode.ue_ambr.subscribed_ue_ambr_for_uplink, 8);
	CU_ASSERT_EQUAL(decode.ue_ambr.subscribed_ue_ambr_for_downlink, 16);
	CU_ASSERT_EQUAL(decode.ue_ambr.authorized_ue_ambr_for_uplink, 32);
	CU_ASSERT_EQUAL(decode.ue_ambr.authorized_ue_ambr_for_downlink, 64);

	CU_ASSERT_EQUAL(decode.apn_ambr_with_nsapi.header.type, GTPV1_IE_APN_AMBR_WITH_NSAPI);
	CU_ASSERT_EQUAL(decode.apn_ambr_with_nsapi.header.length, 9);
	CU_ASSERT_EQUAL(decode.apn_ambr_with_nsapi.spare, 0);
	CU_ASSERT_EQUAL(decode.apn_ambr_with_nsapi.nsapi, 1);
	CU_ASSERT_EQUAL(decode.apn_ambr_with_nsapi.authorized_apn_ambr_for_uplink, 1);
	CU_ASSERT_EQUAL(decode.apn_ambr_with_nsapi.authorized_apn_ambr_for_downlink, 1);

	CU_ASSERT_EQUAL(decode.signalling_priority_indication_with_nsapi.header.type, GTPV1_IE_SIGNALLING_PRIORITY_INDICATION_WITH_NSAPI);
	CU_ASSERT_EQUAL(decode.signalling_priority_indication_with_nsapi.header.length, 2);
	CU_ASSERT_EQUAL(decode.signalling_priority_indication_with_nsapi.spare, 0);
	CU_ASSERT_EQUAL(decode.signalling_priority_indication_with_nsapi.nsapi, 1);
	CU_ASSERT_EQUAL(decode.signalling_priority_indication_with_nsapi.spare2, 0);
	CU_ASSERT_EQUAL(decode.signalling_priority_indication_with_nsapi.lapi, 1);

	CU_ASSERT_EQUAL(decode.higher_bitrates_than_16_mbps_flag.header.type, GTPV1_IE_HIGER_BITRATES_THAN_16_MBPS_FLAG);
	CU_ASSERT_EQUAL(decode.higher_bitrates_than_16_mbps_flag.header.length, 1);
	CU_ASSERT_EQUAL(decode.higher_bitrates_than_16_mbps_flag.higher_bitrates_than_16_mbps_flag, 1);

	CU_ASSERT_EQUAL(decode.selection_mode_with_nsapi.header.type, GTPV1_IE_SELECTION_MODE_WITH_NSAPI);
	CU_ASSERT_EQUAL(decode.selection_mode_with_nsapi.header.length, 2);
	CU_ASSERT_EQUAL(decode.selection_mode_with_nsapi.spare, 0);
	CU_ASSERT_EQUAL(decode.selection_mode_with_nsapi.nsapi, 1);
	CU_ASSERT_EQUAL(decode.selection_mode_with_nsapi.spare2, 0);
	CU_ASSERT_EQUAL(decode.selection_mode_with_nsapi.selection_mode_value, 1);

	CU_ASSERT_EQUAL(decode.local_home_network_id_with_nsapi.header.type, GTPV1_IE_LOCAL_HOME_NETWORK_ID_WITH_NSAPI);
	CU_ASSERT_EQUAL(decode.local_home_network_id_with_nsapi.header.length, 6);
	CU_ASSERT_EQUAL(decode.local_home_network_id_with_nsapi.spare, 0);
	CU_ASSERT_EQUAL(decode.local_home_network_id_with_nsapi.nsapi, 1);
	CU_ASSERT_STRING_EQUAL(decode.local_home_network_id_with_nsapi.local_home_network_id_with_nsapi,"gslab");

	CU_ASSERT_EQUAL(decode.ue_usage_type.header.type, GTPV1_IE_UE_USAGE_TYPE);
	CU_ASSERT_EQUAL(decode.ue_usage_type.header.length, 4);
	CU_ASSERT_EQUAL(decode.ue_usage_type.ue_usage_type_value, 15);

	CU_ASSERT_EQUAL(decode.extended_common_flag_2.header.type, GTPV1_IE_EXTENDED_COMMON_FLAGS_II);
	CU_ASSERT_EQUAL(decode.extended_common_flag_2.header.length, 1);
	CU_ASSERT_EQUAL(decode.extended_common_flag_2.spare, 0);
	CU_ASSERT_EQUAL(decode.extended_common_flag_2.pmts_mi, 1);
	CU_ASSERT_EQUAL(decode.extended_common_flag_2.dtci, 1);
	CU_ASSERT_EQUAL(decode.extended_common_flag_2.pnsi, 1);

	CU_ASSERT_EQUAL(decode.gsn_addr_2.header.type, GTPV1_IE_GSN_ADDR);
	CU_ASSERT_EQUAL(decode.gsn_addr_2.header.length, 16);
	char addr10[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &decode.gsn_addr_2.gsn_address.ipv6, addr10, INET6_ADDRSTRLEN);
	CU_ASSERT_NSTRING_EQUAL(addr10, "2001:db80:3333:4444:5555:6666:7777:8888",39);

	CU_ASSERT_EQUAL(decode.gsn_addr_3.header.type, GTPV1_IE_GSN_ADDR);
	CU_ASSERT_EQUAL(decode.gsn_addr_3.header.length, 16);
	char addr11[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &decode.gsn_addr_3.gsn_address.ipv6, addr11, INET6_ADDRSTRLEN);
	CU_ASSERT_NSTRING_EQUAL(addr11, "2001:db80:3333:4444:5555:6666:7777:8888",39);

	CU_ASSERT_EQUAL(decode.iov_updates_counter.header.type, GTPV1_IE_IOV_UPDATES_COUNTER);
	CU_ASSERT_EQUAL(decode.iov_updates_counter.header.length, 1);
	CU_ASSERT_EQUAL(decode.iov_updates_counter.iov_updates_counter, 10);

	CU_ASSERT_EQUAL(decode.private_extension.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.private_extension.header.length, 6);
	CU_ASSERT_EQUAL(decode.private_extension.extension_identifier, 12);
	CU_ASSERT_NSTRING_EQUAL(decode.private_extension.extension_value,"2021", 4);
}

void test_decode_gtpv1_sgsn_context_ack(void)
{
	gtpv1_sgsn_context_ack_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x34, 0x00, 0x28, 0x37, 0x2f, 0x00, 0x00,
		0x01, 0x80, 0x12, 0x05, 0x00, 0xff, 0xfe, 0xee, 0x85, 0x00,
		0x04, 0xc0, 0xa8, 0x00, 0x2c, 0x93, 0x00, 0x02, 0x31, 0x31,
		0xdb, 0x00, 0x08, 0x03, 0x6d, 0x6d, 0x65, 0x03, 0x61, 0x61,
		0x61, 0xff, 0x00, 0x06, 0x00, 0x0c, 0x32, 0x30, 0x32, 0x31};

	CU_ASSERT(decode_gtpv1_sgsn_context_ack(buf, &decode) == 48);
	CU_ASSERT(decode_gtpv1_sgsn_context_ack(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_sgsn_context_ack(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_sgsn_context_ack(buf, NULL) == -1);
	
	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);
	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_SGSN_CONTEXT_ACK);
	CU_ASSERT_EQUAL(decode.header.message_len, 40);
	CU_ASSERT_EQUAL(decode.header.teid, 0x372f0000);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.cause.header.type, GTPV1_IE_CAUSE);
	CU_ASSERT_EQUAL(decode.cause.cause_value, 128);

	CU_ASSERT_EQUAL(decode.teid_2.header.type, GTPV1_IE_TEID_DATA_2);
	CU_ASSERT_EQUAL(decode.teid_2.nsapi, 5);
	CU_ASSERT_EQUAL(decode.teid_2.teid, 0x0fffeee);

	CU_ASSERT_EQUAL(decode.sgsn_addr_user_traffic.header.type, GTPV1_IE_GSN_ADDR);
	CU_ASSERT_EQUAL(decode.sgsn_addr_user_traffic.header.length, 4);
	CU_ASSERT_EQUAL(decode.sgsn_addr_user_traffic.gsn_address.ipv4, 3232235564);

	CU_ASSERT_EQUAL(decode.sgsn_number.header.type, GTPV1_IE_SGSN_NUMBER);
	CU_ASSERT_EQUAL(decode.sgsn_number.header.length, 2);
	CU_ASSERT_STRING_EQUAL(decode.sgsn_number.sgsn_number,"11");

	CU_ASSERT_EQUAL(decode.node_id.header.type, GTPV1_IE_NODE_IDENTIFIER);
	CU_ASSERT_EQUAL(decode.node_id.header.length, 8);
	CU_ASSERT_EQUAL(decode.node_id.len_of_node_name, 3);
	CU_ASSERT_STRING_EQUAL(decode.node_id.node_name, "mme");
	CU_ASSERT_EQUAL(decode.node_id.len_of_node_realm, 3);
	CU_ASSERT_STRING_EQUAL(decode.node_id.node_realm, "aaa");

	CU_ASSERT_EQUAL(decode.private_extension.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.private_extension.header.length, 6);
	CU_ASSERT_EQUAL(decode.private_extension.extension_identifier, 12);
	CU_ASSERT_NSTRING_EQUAL(decode.private_extension.extension_value,"2021", 4);
}

void test_decode_gtpv1_forward_relocation_req(void)
{
	gtpv1_forward_relocation_req_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x35, 0x01, 0xed, 0x37, 0x2f, 0x00, 0x00,
		0x02, 0x72, 0x02, 0x13, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x11,
		0x00, 0xff, 0xfe, 0xee, 0x15, 0x07, 0x19, 0x01, 0x04, 0x1a,
		0x00, 0x01, 0x81, 0x00, 0x2f, 0x79, 0x49, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x01, 0x31, 0x31, 0x31, 0x31, 0x31,
		0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
		0x31, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x02, 0x01, 0x19, 0x04, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x82, 0x00, 0x74, 0x65, 0x01, 0x15, 0x02, 0x12,
		0x31, 0x04, 0x2a, 0x03, 0x7b, 0xea, 0x11, 0x06, 0x7a, 0xde,
		0x11, 0x16, 0x0b, 0x21, 0x16, 0x2c, 0x21, 0x22, 0x17, 0x15,
		0x02, 0x12, 0x31, 0x04, 0x2a, 0x03, 0x7b, 0xea, 0x11, 0x06,
		0x7a, 0xde, 0x11, 0x16, 0x0b, 0x21, 0x16, 0x2c, 0x21, 0x22,
		0x17, 0x15, 0x02, 0x12, 0x31, 0x04, 0x2a, 0x03, 0x7b, 0xea,
		0x11, 0x06, 0x7a, 0xde, 0x11, 0x16, 0x0b, 0x21, 0x16, 0x2c,
		0x21, 0x22, 0x17, 0x00, 0x01, 0x00, 0x02, 0xff, 0xff, 0x37,
		0x2f, 0x00, 0x00, 0x37, 0x30, 0x00, 0x00, 0x00, 0xf1, 0x21,
		0x04, 0x15, 0x2c, 0x8a, 0x97, 0x04, 0x15, 0x2c, 0x8a, 0x8d,
		0x04, 0x15, 0x2c, 0x8a, 0x97, 0x0d, 0x6e, 0x65, 0x78, 0x74,
		0x70, 0x68, 0x6f, 0x6e, 0x65, 0x73, 0x2e, 0x63, 0x6f, 0x0a,
		0x37, 0x85, 0x00, 0x04, 0xc0, 0xa8, 0x00, 0x2c, 0x8a, 0x00,
		0x0a, 0x04, 0xf4, 0x87, 0x00, 0x02, 0x02, 0x00, 0x02, 0x00,
		0x00, 0x91, 0x00, 0x00, 0x9c, 0x00, 0x22, 0x20, 0x37, 0x2f,
		0x00, 0x00, 0x81, 0xf1, 0x21, 0x04, 0x15, 0x2c, 0x8a, 0x97,
		0x04, 0x15, 0x2c, 0x8a, 0x8d, 0x0d, 0x6e, 0x65, 0x78, 0x74,
		0x70, 0x68, 0x6f, 0x6e, 0x65, 0x73, 0x2e, 0x63, 0x6f, 0x01,
		0x05, 0xa4, 0x00, 0x03, 0x04, 0xf4, 0x87, 0xae, 0x00, 0x11,
		0x04, 0xf4, 0x87, 0x00, 0x14, 0x14, 0x00, 0x01, 0x00, 0x04,
		0xf4, 0x87, 0x00, 0x14, 0x14, 0x00, 0x01, 0xb0, 0x00, 0x01,
		0x02, 0xb6, 0x00, 0x01, 0x07, 0xbd, 0x00, 0x02, 0x00, 0x03,
		0xbd, 0x00, 0x02, 0x00, 0x02, 0xbe, 0x00, 0x05, 0x67, 0x73,
		0x6c, 0x61, 0x62, 0xc0, 0x00, 0x02, 0x01, 0x45, 0xc1, 0x00,
		0x01, 0x00, 0xc5, 0x00, 0x01, 0x01, 0xc7, 0x00, 0x05, 0xd6,
		0xab, 0x55, 0xb5, 0xb6, 0xc8, 0x00, 0x10, 0x00, 0x00, 0x00,
		0x08, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x20, 0x00,
		0x00, 0x00, 0x40, 0xc9, 0x00, 0x09, 0x01, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x01, 0xcc, 0x00, 0x02, 0x01, 0x01,
		0xcd, 0x00, 0x01, 0x01, 0xcf, 0x00, 0x22, 0x03, 0x39, 0x5f,
		0xbf, 0x15, 0x51, 0x21, 0x99, 0x29, 0xac, 0x73, 0x56, 0x44,
		0x9d, 0x6c, 0xeb, 0xf9, 0xf6, 0x6f, 0x33, 0xd2, 0xb5, 0xbb,
		0xfb, 0x2b, 0xb0, 0x07, 0x02, 0x02, 0x06, 0x05, 0x01, 0x01,
		0x03, 0xd0, 0x00, 0x01, 0x00, 0xd2, 0x00, 0x05, 0x32, 0x33,
		0x34, 0x35, 0x36, 0xd3, 0x00, 0x02, 0x00, 0x02, 0xd4, 0x00,
		0x09, 0x00, 0x04, 0xf4, 0x87, 0x02, 0x00, 0x03, 0x00, 0x14,
		0xd5, 0x00, 0x02, 0x01, 0x01, 0xd9, 0x00, 0x04, 0x00, 0x00,
		0x00, 0x0f, 0xda, 0x00, 0x01, 0x07, 0x85, 0x00, 0x10, 0x20,
		0x01, 0xdb, 0x80, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x66,
		0x66, 0x77, 0x77, 0x88, 0x88, 0x85, 0x00, 0x10, 0x20, 0x01,
		0xdb, 0x80, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x66, 0x66,
		0x77, 0x77, 0x88, 0x88, 0xff, 0x00, 0x06, 0x00, 0x0c, 0x32,
		0x30, 0x32, 0x31};

	CU_ASSERT(decode_gtpv1_forward_relocation_req(buf, &decode) == 501);
	CU_ASSERT(decode_gtpv1_forward_relocation_req(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_forward_relocation_req(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_forward_relocation_req(buf, NULL) == -1);

	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);
	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_FORWARD_RELOCATION_REQUEST);
	CU_ASSERT_EQUAL(decode.header.message_len, 493);
	CU_ASSERT_EQUAL(decode.header.teid, 0x372f0000);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.imsi.header.type, GTPV1_IE_IMSI);
	CU_ASSERT_EQUAL(decode.imsi.imsi_number_digits, 272031000000000);

	CU_ASSERT_EQUAL(decode.tunn_endpt_idnt_control_plane.header.type, GTPV1_IE_TEID_CONTROL_PLANE);
	CU_ASSERT_EQUAL(decode.tunn_endpt_idnt_control_plane.teid, 0x0fffeee);

	CU_ASSERT_EQUAL(decode.ranap_cause.header.type, GTPV1_IE_RANAP_CAUSE);
	CU_ASSERT_EQUAL(decode.ranap_cause.ranap_cause, 7);

	CU_ASSERT_EQUAL(decode.packet_flow_id.header.type, GTPV1_IE_PACKET_FLOW_ID);
	CU_ASSERT_EQUAL(decode.packet_flow_id.spare, 0);
	CU_ASSERT_EQUAL(decode.packet_flow_id.nsapi, 1);
	CU_ASSERT_EQUAL(decode.packet_flow_id.packet_flow_id, 4);

	CU_ASSERT_EQUAL(decode.chrgng_char.header.type, GTPV1_IE_CHRGNG_CHAR);
	CU_ASSERT_EQUAL(decode.chrgng_char.chrgng_char_val, 1);

	CU_ASSERT_EQUAL(decode.mm_context.header.type, GTPV1_IE_MM_CONTEXT);
	CU_ASSERT_EQUAL(decode.mm_context.header.length, 47);
	CU_ASSERT_EQUAL(decode.mm_context.mm_context.gsm_keys_and_triplet.spare, 15);
	CU_ASSERT_EQUAL(decode.mm_context.mm_context.gsm_keys_and_triplet.cksn, 1);
	CU_ASSERT_EQUAL(decode.mm_context.security_mode, 1);
	CU_ASSERT_EQUAL(decode.mm_context.mm_context.gsm_keys_and_triplet.no_of_vectors, 1);
	CU_ASSERT_EQUAL(decode.mm_context.mm_context.gsm_keys_and_triplet.used_cipher, 1);
	CU_ASSERT_EQUAL(decode.mm_context.mm_context.gsm_keys_and_triplet.kc, 1);
	CU_ASSERT_NSTRING_EQUAL(decode.mm_context.mm_context.gsm_keys_and_triplet.triplet[0].rand,"1111111111111111",16);
	CU_ASSERT_EQUAL(decode.mm_context.mm_context.gsm_keys_and_triplet.triplet[0].sres, 2);
	CU_ASSERT_EQUAL(decode.mm_context.mm_context.gsm_keys_and_triplet.triplet[0].kc, 2);
	CU_ASSERT_EQUAL(decode.mm_context.drx_parameter.split_pg_cycle_code, 1);
	CU_ASSERT_EQUAL(decode.mm_context.drx_parameter.cycle_length, 1);
	CU_ASSERT_EQUAL(decode.mm_context.drx_parameter.ccch, 1);
	CU_ASSERT_EQUAL(decode.mm_context.drx_parameter.timer, 1);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability_length, 4);

	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.GEA_1, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.sm_capabilities_via_dedicated_channels, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.sm_capabilities_via_gprs_channels, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.ucs2_support, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.ss_screening_indicator, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.solsa_capability, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.revision_level_indicator, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.pfc_feature_mode, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.GEA_2, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.GEA_3, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.GEA_4, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.GEA_5, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.GEA_6, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.GEA_7, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.lcs_va_capability, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.ps_ge_ut_iu_mode_capability, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.ps_ge_ut_s1_mode_capability, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.emm_combined_procedure_capability, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.isr_support, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.srvcc_to_ge_ut_capability, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.epc_capability, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.nf_capability, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.ge_network_sharing_capability, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.user_plane_integrity_protection_support, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.GIA_4, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.GIA_5, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.GIA_6, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.GIA_7, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.ePCO_ie_indicator, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.restriction_on_use_of_enhanced_coverage_capability, 0);
	CU_ASSERT_EQUAL(decode.mm_context.ms_network_capability.dual_connectivity_of_e_ut_with_nr_capability, 0);
	CU_ASSERT_EQUAL(decode.mm_context.container_length, 0);

	CU_ASSERT_EQUAL(decode.pdp_context.header.type, GTPV1_IE_PDP_CONTEXT);
	CU_ASSERT_EQUAL(decode.pdp_context.header.length, 116);
	CU_ASSERT_EQUAL(decode.pdp_context.ea, 0);
	CU_ASSERT_EQUAL(decode.pdp_context.vaa, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.asi, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.order, 0);
	CU_ASSERT_EQUAL(decode.pdp_context.nsapi, 5);
	CU_ASSERT_EQUAL(decode.pdp_context.spare, 0);
	CU_ASSERT_EQUAL(decode.pdp_context.sapi, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub_length, 21);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.allocation_retention_priority, 2);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.spare1, 0);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.delay_class, 2);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.reliablity_class, 2);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.peak_throughput, 3);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.spare2, 0);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.precedence_class, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.spare3, 0);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.mean_throughput, 4);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.traffic_class, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.delivery_order, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.delivery_erroneous_sdu, 2);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.max_sdu_size, 3);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.max_bitrate_uplink, 123);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.max_bitrate_downlink, 234);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.residual_ber, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.sdu_error_ratio, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.transfer_delay, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.traffic_handling_priority, 2);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.guaranteed_bitrate_uplink, 122);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.guaranteed_bitrate_downlink, 222);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.spare4, 0);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.signalling_indication, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.source_statistics_descriptor, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.max_bitrate_downlink_ext1, 22);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.guaranteed_bitrate_downlink_ext1, 11);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.max_bitrate_uplink_ext1, 33);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.guaranteed_bitrate_uplink_ext1, 22);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.max_bitrate_downlink_ext2, 44);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.guaranteed_bitrate_downlink_ext2, 33);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.max_bitrate_uplink_ext2, 34);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_sub.guaranteed_bitrate_uplink_ext2, 23);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req_length, 21);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.allocation_retention_priority, 2);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.spare1, 0);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.delay_class, 2);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.reliablity_class, 2);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.peak_throughput, 3);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.spare2, 0);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.precedence_class, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.spare3, 0);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.mean_throughput, 4);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.traffic_class, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.delivery_order, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.delivery_erroneous_sdu, 2);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.max_sdu_size, 3);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.max_bitrate_uplink, 123);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.max_bitrate_downlink, 234);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.residual_ber, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.sdu_error_ratio, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.transfer_delay, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.traffic_handling_priority, 2);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.guaranteed_bitrate_uplink, 122);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.guaranteed_bitrate_downlink, 222);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.spare4, 0);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.signalling_indication, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.source_statistics_descriptor, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.max_bitrate_downlink_ext1, 22);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.guaranteed_bitrate_downlink_ext1, 11);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.max_bitrate_uplink_ext1, 33);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.guaranteed_bitrate_uplink_ext1, 22);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.max_bitrate_downlink_ext2, 44);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.guaranteed_bitrate_downlink_ext2, 33);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.max_bitrate_uplink_ext2, 34);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_req.guaranteed_bitrate_uplink_ext2, 23);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg_length, 21);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.allocation_retention_priority, 2);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.spare1, 0);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.delay_class, 2);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.reliablity_class, 2);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.peak_throughput, 3);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.spare2, 0);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.precedence_class, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.spare3, 0);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.mean_throughput, 4);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.traffic_class, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.delivery_order, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.delivery_erroneous_sdu, 2);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.max_sdu_size, 3);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.max_bitrate_uplink, 123);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.max_bitrate_downlink, 234);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.residual_ber, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.sdu_error_ratio, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.transfer_delay, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.traffic_handling_priority, 2);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.guaranteed_bitrate_uplink, 122);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.guaranteed_bitrate_downlink, 222);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.spare4, 0);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.signalling_indication, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.source_statistics_descriptor, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.max_bitrate_downlink_ext1, 22);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.guaranteed_bitrate_downlink_ext1, 11);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.max_bitrate_uplink_ext1, 33);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.guaranteed_bitrate_uplink_ext1, 22);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.max_bitrate_downlink_ext2, 44);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.guaranteed_bitrate_downlink_ext2, 33);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.max_bitrate_uplink_ext2, 34);
	CU_ASSERT_EQUAL(decode.pdp_context.qos_neg.guaranteed_bitrate_uplink_ext2, 23);
	CU_ASSERT_EQUAL(decode.pdp_context.sequence_number_down, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.sequence_number_up, 2);
	CU_ASSERT_EQUAL(decode.pdp_context.send_npdu_number, 255);
	CU_ASSERT_EQUAL(decode.pdp_context.rcv_npdu_number, 255);
	CU_ASSERT_EQUAL(decode.pdp_context.uplink_teid_cp, 0x372f0000);
	CU_ASSERT_EQUAL(decode.pdp_context.uplink_teid_data1, 0x37300000);
	CU_ASSERT_EQUAL(decode.pdp_context.pdp_ctxt_identifier, 0);
	CU_ASSERT_EQUAL(decode.pdp_context.spare2, 15);
	CU_ASSERT_EQUAL(decode.pdp_context.pdp_type_org, 1);
	CU_ASSERT_EQUAL(decode.pdp_context.pdp_type_number1, 0x21);
	CU_ASSERT_EQUAL(decode.pdp_context.pdp_address_length1, 4);
	CU_ASSERT_EQUAL(decode.pdp_context.pdp_address1.ipv4, 355240599);
	CU_ASSERT_EQUAL(decode.pdp_context.ggsn_addr_cp_length, 4);
	CU_ASSERT_EQUAL(decode.pdp_context.ggsn_addr_cp.ipv4, 355240589);
	CU_ASSERT_EQUAL(decode.pdp_context.ggsn_addr_ut_length, 4);
	CU_ASSERT_EQUAL(decode.pdp_context.ggsn_addr_ut.ipv4, 355240599);

	CU_ASSERT_EQUAL(decode.gsn_addr_1.header.type, GTPV1_IE_GSN_ADDR);
	CU_ASSERT_EQUAL(decode.gsn_addr_1.header.length, 4);
	CU_ASSERT_EQUAL(decode.gsn_addr_1.gsn_address.ipv4, 3232235564);

	CU_ASSERT_EQUAL(decode.target_id.header.type, GTPV1_IE_TARGET_IDENTIFICATION);
	CU_ASSERT_EQUAL(decode.target_id.header.length, 10);
	CU_ASSERT_EQUAL(decode.target_id.mcc_digit_2, 0x0);
	CU_ASSERT_EQUAL(decode.target_id.mcc_digit_1, 0x4);
	CU_ASSERT_EQUAL(decode.target_id.mnc_digit_3, 0x8);
	CU_ASSERT_EQUAL(decode.target_id.mcc_digit_3, 0x4);
	CU_ASSERT_EQUAL(decode.target_id.mnc_digit_1, 0x0);
	CU_ASSERT_EQUAL(decode.target_id.mnc_digit_2, 0x7);
	CU_ASSERT_EQUAL(decode.target_id.lac, 0x2);
	CU_ASSERT_EQUAL(decode.target_id.rac, 0x2);
	CU_ASSERT_EQUAL(decode.target_id.rnc_id, 0x2);
	CU_ASSERT_EQUAL(decode.target_id.extended_rnc_id, 0);

	CU_ASSERT_EQUAL(decode.pdp_context_prioritization.header.type, GTPV1_IE_PDP_CONTEXT_PRIORITIZATION);

	CU_ASSERT_EQUAL(decode.mbms_ue_context.header.type, GTPV1_IE_MBMS_UE_CONTEXT);
	CU_ASSERT_EQUAL(decode.mbms_ue_context.header.length, 34);
	CU_ASSERT_EQUAL(decode.mbms_ue_context.linked_nsapi, 2);
	CU_ASSERT_EQUAL(decode.mbms_ue_context.spare1, 0);
	CU_ASSERT_EQUAL(decode.mbms_ue_context.uplink_teid_cp, 0x372f0000);
	CU_ASSERT_EQUAL(decode.mbms_ue_context.enhanced_nsapi, 129);
	CU_ASSERT_EQUAL(decode.mbms_ue_context.spare2, 15);
	CU_ASSERT_EQUAL(decode.mbms_ue_context.pdp_type_org, 1);
	CU_ASSERT_EQUAL(decode.mbms_ue_context.pdp_type_number, 0x21);
	CU_ASSERT_EQUAL(decode.mbms_ue_context.pdp_address_length, 4);
	CU_ASSERT_EQUAL(decode.mbms_ue_context.pdp_address.ipv4, 355240599);
	CU_ASSERT_EQUAL(decode.mbms_ue_context.ggsn_addr_cp_length, 4);
	CU_ASSERT_EQUAL(decode.mbms_ue_context.ggsn_addr_cp.ipv4, 355240589);
	CU_ASSERT_EQUAL(decode.mbms_ue_context.apn_length, 13);
	CU_ASSERT_STRING_EQUAL(decode.mbms_ue_context.apn,"nextphones.co");
	CU_ASSERT_EQUAL(decode.mbms_ue_context.spare3, 0);
	CU_ASSERT_EQUAL(decode.mbms_ue_context.transaction_identifier1, 1);
	CU_ASSERT_EQUAL(decode.mbms_ue_context.transaction_identifier2, 5);

	CU_ASSERT_EQUAL(decode.plmn_id.header.type, GTPV1_IE_SELECTED_PLMN_ID);
	CU_ASSERT_EQUAL(decode.plmn_id.header.length, 3);
	CU_ASSERT_EQUAL(decode.plmn_id.mcc_digit_2, 0x0);
	CU_ASSERT_EQUAL(decode.plmn_id.mcc_digit_1, 0x4);
	CU_ASSERT_EQUAL(decode.plmn_id.mnc_digit_3, 0xf);
	CU_ASSERT_EQUAL(decode.plmn_id.mcc_digit_3, 0x4);
	CU_ASSERT_EQUAL(decode.plmn_id.mnc_digit_1, 0x7);
	CU_ASSERT_EQUAL(decode.plmn_id.mnc_digit_2, 0x8);

	CU_ASSERT_EQUAL(decode.cell_id.header.type, GTPV1_IE_CELL_IDENTIFICATION);
	CU_ASSERT_EQUAL(decode.cell_id.header.length, 17);
	CU_ASSERT_EQUAL(decode.cell_id.target_cell_id.rai_value.mcc_digit_2, 0x0);
	CU_ASSERT_EQUAL(decode.cell_id.target_cell_id.rai_value.mcc_digit_1, 0x4);
	CU_ASSERT_EQUAL(decode.cell_id.target_cell_id.rai_value.mnc_digit_3, 0x8);
	CU_ASSERT_EQUAL(decode.cell_id.target_cell_id.rai_value.mcc_digit_3, 0x4);
	CU_ASSERT_EQUAL(decode.cell_id.target_cell_id.rai_value.mnc_digit_1, 0x0);
	CU_ASSERT_EQUAL(decode.cell_id.target_cell_id.rai_value.mnc_digit_2, 0x7);
	CU_ASSERT_EQUAL(decode.cell_id.target_cell_id.rai_value.lac, 20);
	CU_ASSERT_EQUAL(decode.cell_id.target_cell_id.rai_value.rac, 20);
	CU_ASSERT_EQUAL(decode.cell_id.target_cell_id.cell_identity, 1);
	CU_ASSERT_EQUAL(decode.cell_id.source_type, 0);
	CU_ASSERT_EQUAL(decode.cell_id.ID.source_cell_id.rai_value.mcc_digit_2, 0x0);
	CU_ASSERT_EQUAL(decode.cell_id.ID.source_cell_id.rai_value.mcc_digit_1, 0x4);
	CU_ASSERT_EQUAL(decode.cell_id.ID.source_cell_id.rai_value.mnc_digit_3, 0x8);
	CU_ASSERT_EQUAL(decode.cell_id.ID.source_cell_id.rai_value.mcc_digit_3, 0x4);
	CU_ASSERT_EQUAL(decode.cell_id.ID.source_cell_id.rai_value.mnc_digit_1, 0x0);
	CU_ASSERT_EQUAL(decode.cell_id.ID.source_cell_id.rai_value.mnc_digit_2, 0x7);
	CU_ASSERT_EQUAL(decode.cell_id.ID.source_cell_id.rai_value.lac, 20);
	CU_ASSERT_EQUAL(decode.cell_id.ID.source_cell_id.rai_value.rac, 20);
	CU_ASSERT_EQUAL(decode.cell_id.ID.source_cell_id.cell_identity, 1);

	CU_ASSERT_EQUAL(decode.bssgp_cause.header.type, GTPV1_IE_BSSGP_CAUSE);
	CU_ASSERT_EQUAL(decode.bssgp_cause.header.length, 1);
	CU_ASSERT_EQUAL(decode.bssgp_cause.bssgp_cause, 2);

	CU_ASSERT_EQUAL(decode.direct_tunnel_flag.header.type, GTPV1_IE_DIRECT_TUNNEL_FLAG);
	CU_ASSERT_EQUAL(decode.direct_tunnel_flag.header.length, 1);
	CU_ASSERT_EQUAL(decode.direct_tunnel_flag.spare, 0);
	CU_ASSERT_EQUAL(decode.direct_tunnel_flag.ei, 1);
	CU_ASSERT_EQUAL(decode.direct_tunnel_flag.gcsi, 1);
	CU_ASSERT_EQUAL(decode.direct_tunnel_flag.dti, 1);

	CU_ASSERT_EQUAL(decode.subscribed_rfsp_index.header.type, GTPV1_IE_RFSP_INDEX);
	CU_ASSERT_EQUAL(decode.subscribed_rfsp_index.header.length, 2);
	CU_ASSERT_EQUAL(decode.subscribed_rfsp_index.rfsp_index, 3);

	CU_ASSERT_EQUAL(decode.rfsp_index_in_use.header.type, GTPV1_IE_RFSP_INDEX);
	CU_ASSERT_EQUAL(decode.rfsp_index_in_use.header.length, 2);
	CU_ASSERT_EQUAL(decode.rfsp_index_in_use.rfsp_index, 2);

	CU_ASSERT_EQUAL(decode.co_located_ggsn_pgw_fqdn.header.type, GTPV1_IE_FQDN);
	CU_ASSERT_EQUAL(decode.co_located_ggsn_pgw_fqdn.header.length, 5);
	CU_ASSERT_STRING_EQUAL(decode.co_located_ggsn_pgw_fqdn.fqdn,"gslab");

	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_II.header.type, GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_II);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_II.header.length, 2);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_II.spare, 0);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_II.nsapi, 1);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_II.spare2, 0);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_II.pci, 1);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_II.pl, 1);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_II.spare3, 0);
	CU_ASSERT_EQUAL(decode.evolved_allocation_retention_priority_II.pvi, 1);

	CU_ASSERT_EQUAL(decode.extended_common_flag.header.type, GTPV1_IE_EXTENDED_COMMON_FLAG);
	CU_ASSERT_EQUAL(decode.extended_common_flag.header.length, 1);
	CU_ASSERT_EQUAL(decode.extended_common_flag.uasi, 0);
	CU_ASSERT_EQUAL(decode.extended_common_flag.bdwi, 0);
	CU_ASSERT_EQUAL(decode.extended_common_flag.pcri, 0);
	CU_ASSERT_EQUAL(decode.extended_common_flag.vb, 0);
	CU_ASSERT_EQUAL(decode.extended_common_flag.retloc, 0);
	CU_ASSERT_EQUAL(decode.extended_common_flag.cpsr, 0);
	CU_ASSERT_EQUAL(decode.extended_common_flag.ccrsi, 0);

	CU_ASSERT_EQUAL(decode.csg_member.header.type, GTPV1_IE_CSG_MEMB_INDCTN);
	CU_ASSERT_EQUAL(decode.csg_member.header.length, 1);
	CU_ASSERT_EQUAL(decode.csg_member.spare, 0);
	CU_ASSERT_EQUAL(decode.csg_member.cmi, 1);

	CU_ASSERT_EQUAL(decode.ue_network_capability.header.type, GTPV1_IE_UE_NETWORK_CAPABILITY);
	CU_ASSERT_EQUAL(decode.ue_network_capability.header.length, 5);
	CU_ASSERT_EQUAL(decode.ue_network_capability.eea0, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.eea1_128, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.eea2_128, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.eea3_128, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.eea4, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.eea5, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.eea6, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.eea7, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.eia0, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.eia1_128, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.eia2_128, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.eia3_128, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.eia4, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.eia5, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.eia6, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.eia7, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.uea0, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.uea1, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.uea2, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.uea3, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.uea4, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.uea5, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.uea6, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.uea7, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.ucs2, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.uia1, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.uia2, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.uia3, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.uia4, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.uia5, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.uia6, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.uia7, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.prose_dd, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.prose, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.h245_ash, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.acc_csfb, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.lpp, 0);
	CU_ASSERT_EQUAL(decode.ue_network_capability.lcs, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.srvcc1x, 1);
	CU_ASSERT_EQUAL(decode.ue_network_capability.nf, 0);

	CU_ASSERT_EQUAL(decode.ue_ambr.header.type, GTPV1_IE_UE_AMBR);
	CU_ASSERT_EQUAL(decode.ue_ambr.header.length, 16);
	CU_ASSERT_EQUAL(decode.ue_ambr.subscribed_ue_ambr_for_uplink, 8);
	CU_ASSERT_EQUAL(decode.ue_ambr.subscribed_ue_ambr_for_downlink, 16);
	CU_ASSERT_EQUAL(decode.ue_ambr.authorized_ue_ambr_for_uplink, 32);
	CU_ASSERT_EQUAL(decode.ue_ambr.authorized_ue_ambr_for_downlink, 64);

	CU_ASSERT_EQUAL(decode.apn_ambr_with_nsapi.header.type, GTPV1_IE_APN_AMBR_WITH_NSAPI);
	CU_ASSERT_EQUAL(decode.apn_ambr_with_nsapi.header.length, 9);
	CU_ASSERT_EQUAL(decode.apn_ambr_with_nsapi.spare, 0);
	CU_ASSERT_EQUAL(decode.apn_ambr_with_nsapi.nsapi, 1);
	CU_ASSERT_EQUAL(decode.apn_ambr_with_nsapi.authorized_apn_ambr_for_uplink, 1);
	CU_ASSERT_EQUAL(decode.apn_ambr_with_nsapi.authorized_apn_ambr_for_downlink, 1);

	CU_ASSERT_EQUAL(decode.signalling_priority_indication_with_nsapi.header.type, GTPV1_IE_SIGNALLING_PRIORITY_INDICATION_WITH_NSAPI);
	CU_ASSERT_EQUAL(decode.signalling_priority_indication_with_nsapi.header.length, 2);
	CU_ASSERT_EQUAL(decode.signalling_priority_indication_with_nsapi.spare, 0);
	CU_ASSERT_EQUAL(decode.signalling_priority_indication_with_nsapi.nsapi, 1);
	CU_ASSERT_EQUAL(decode.signalling_priority_indication_with_nsapi.spare2, 0);
	CU_ASSERT_EQUAL(decode.signalling_priority_indication_with_nsapi.lapi, 1);

	CU_ASSERT_EQUAL(decode.higher_bitrates_than_16_mbps_flag.header.type, GTPV1_IE_HIGER_BITRATES_THAN_16_MBPS_FLAG);
	CU_ASSERT_EQUAL(decode.higher_bitrates_than_16_mbps_flag.header.length, 1);
	CU_ASSERT_EQUAL(decode.higher_bitrates_than_16_mbps_flag.higher_bitrates_than_16_mbps_flag, 1);

	CU_ASSERT_EQUAL(decode.add_mm_ctxt.header.type, GTPV1_IE_ADDTL_MM_CTXT_SRVCC);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.header.length, 34);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_2.ms_classmark_2_len, 3);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_2.spare1, 0);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_2.rev_level, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_2.es_ind, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_2.a5_1, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_2.rf_power_cap, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_2.spare2, 0);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_2.ps_cap, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_2.ss_screen_ind, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_2.sm_cap, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_2.vbs, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_2.vgcs, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_2.fc, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_2.cm3, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_2.spare3, 0);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_2.lcsvacap, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_2.ucs2, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_2.solsa, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_2.cmsp, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_2.a5_3, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_2.a5_2, 1);

	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.ms_classmark_3_len, 21);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.spare1, 0);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.mult_band_supp, 5);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.a5_bits, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.assoc_radio_cap_1, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.assoc_radio_cap_2, 2);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.r_support, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.r_gsm_assoc_radio_cap, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.hscsd_mult_slot_cap, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.hscsd_mult_slot_class, 4);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.ucs2_treatment, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.extended_meas_cap, 0);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.ms_meas_cap, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.sms_value, 3);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.sm_value, 5);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.ms_pos_method_cap, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.ms_pos_method, 3);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.ecsd_multislot_cap, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.ecsd_multislot_class, 6);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.psk8_struct, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.mod_cap, 0);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.rf_pwr_cap_1, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.rf_pwr_cap_1_val, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.rf_pwr_cap_2, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.rf_pwr_cap_2_val, 0);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.gsm_400_bands_supp, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.gsm_400_bands_val, 0);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.gsm_400_assoc_radio_cap, 4);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.gsm_850_assoc_radio_cap, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.gsm_850_assoc_radio_cap_val, 3);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.gsm_1900_assoc_radio_cap, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.gsm_1900_assoc_radio_cap_val, 5);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.umts_fdd_rat_cap, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.umts_tdd_rat_cap, 0);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.cdma2000_rat_cap, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.dtm_gprs_multislot_class, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.dtm_gprs_multislot_val, 0);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.single_slot_dtm, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.dtm_egprs_multislot_class, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.dtm_egprs_multislot_val, 2);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.single_band_supp, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.single_band_supp_val, 7);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.gsm_750_assoc_radio_cap, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.gsm_750_assoc_radio_cap_val, 14);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.umts_1_28_mcps_tdd_rat_cap, 0);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.geran_feature_package, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.ext_dtm_gprs_multislot_class, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.ext_dtm_gprs_multislot_val, 3);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.ext_dtm_egprs_multislot_val, 2);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.high_multislot_cap, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.high_multislot_val, 2);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.geran_iu_mode_supp, 0);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.geran_feature_package_2, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.gmsk_multislot_power_prof, 2);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.psk8_multislot_power_prof, 3);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.t_gsm_400_bands_supp, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.t_gsm_400_bands_val, 2);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.t_gsm_400_assoc_radio_cap, 6);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.t_gsm_900_assoc_radio_cap, 0);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.dl_advanced_rx_perf, 3);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.dtm_enhancements_cap, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.dtm_gprs_high_multislot_cap, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.dtm_gprs_high_multislot_val, 2);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.offset_required, 0);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.dtm_egprs_high_multislot_cap, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.dtm_egprs_high_multislot_val, 2);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.repeated_acch_capability, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.gsm_710_assoc_radio_cap, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.gsm_710_assoc_radio_val, 5);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.t_gsm_810_assoc_radio_cap, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.t_gsm_810_assoc_radio_val, 7);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.ciphering_mode_setting_cap, 0);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.add_pos_cap, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.e_utra_fdd_supp, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.e_utra_tdd_supp, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.e_utra_meas_rep_supp, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.prio_resel_supp, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.utra_csg_cells_rep, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.vamos_level, 2);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.tighter_capability, 3);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.sel_ciph_dl_sacch, 0);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.cs_ps_srvcc_geran_utra, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.cs_ps_srvcc_geran_eutra, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.geran_net_sharing, 0);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.e_utra_wb_rsrq_meas_supp, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.er_band_support, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.utra_mult_band_ind_supp, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.e_utra_mult_band_ind_supp, 0);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.extended_tsc_set_cap_supp, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.extended_earfcn_val_range, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.ms_classmark_3.spare3, 0);

	CU_ASSERT_EQUAL(decode.add_mm_ctxt.sup_codec_list_len, 7);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.sup_codec_list[0].sysid, 2);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.sup_codec_list[0].len_bitmap_sysid, 2);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.sup_codec_list[0].codec_bitmap_1_8, 6);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.sup_codec_list[0].codec_bitmap_9_16, 5);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.sup_codec_list[1].sysid, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.sup_codec_list[1].len_bitmap_sysid, 1);
	CU_ASSERT_EQUAL(decode.add_mm_ctxt.sup_codec_list[1].codec_bitmap_1_8, 3);

	CU_ASSERT_EQUAL(decode.add_flag_srvcc.header.type, GTPV1_IE_ADDTL_FLGS_SRVCC);
	CU_ASSERT_EQUAL(decode.add_flag_srvcc.header.length, 1);
	CU_ASSERT_EQUAL(decode.add_flag_srvcc.spare, 0);
	CU_ASSERT_EQUAL(decode.add_flag_srvcc.ics, 0);

	CU_ASSERT_EQUAL(decode.c_msisdn.header.type, GTPV1_IE_C_MSISDN);
	CU_ASSERT_EQUAL(decode.c_msisdn.header.length, 5);
	CU_ASSERT_STRING_EQUAL(decode.c_msisdn.msisdn, "23456");

	CU_ASSERT_EQUAL(decode.ext_ranap_cause.header.type, GTPV1_IE_EXTENDED_RANAP_CAUSE);
	CU_ASSERT_EQUAL(decode.ext_ranap_cause.header.length, 2);
	CU_ASSERT_EQUAL(decode.ext_ranap_cause.extended_ranap_cause, 2);

	CU_ASSERT_EQUAL(decode.enodeb_id.header.type, GTPV1_IE_ENODEB_ID);
	CU_ASSERT_EQUAL(decode.enodeb_id.header.length, 9);
	CU_ASSERT_EQUAL(decode.enodeb_id.enodeb_type, 0);
	CU_ASSERT_EQUAL(decode.enodeb_id.mcc_digit_2, 0x0);
	CU_ASSERT_EQUAL(decode.enodeb_id.mcc_digit_1, 0x4);
	CU_ASSERT_EQUAL(decode.enodeb_id.mnc_digit_3, 0x8);
	CU_ASSERT_EQUAL(decode.enodeb_id.mcc_digit_3, 0x4);
	CU_ASSERT_EQUAL(decode.enodeb_id.mnc_digit_1, 0x0);
	CU_ASSERT_EQUAL(decode.enodeb_id.mnc_digit_2, 0x7);
	CU_ASSERT_EQUAL(decode.enodeb_id.spare, 0);
	CU_ASSERT_EQUAL(decode.enodeb_id.macro_enodeb_id, 2);
	CU_ASSERT_EQUAL(decode.enodeb_id.macro_enodeb_id2, 3);
	CU_ASSERT_EQUAL(decode.enodeb_id.home_enodeb_id, 0);
	CU_ASSERT_EQUAL(decode.enodeb_id.home_enodeb_id2, 0);
	CU_ASSERT_EQUAL(decode.enodeb_id.tac, 20);

	CU_ASSERT_EQUAL(decode.selection_mode_with_nsapi.header.type, GTPV1_IE_SELECTION_MODE_WITH_NSAPI);
	CU_ASSERT_EQUAL(decode.selection_mode_with_nsapi.header.length, 2);
	CU_ASSERT_EQUAL(decode.selection_mode_with_nsapi.spare, 0);
	CU_ASSERT_EQUAL(decode.selection_mode_with_nsapi.nsapi, 1);
	CU_ASSERT_EQUAL(decode.selection_mode_with_nsapi.spare2, 0);
	CU_ASSERT_EQUAL(decode.selection_mode_with_nsapi.selection_mode_value, 1);

	CU_ASSERT_EQUAL(decode.ue_usage_type.header.type, GTPV1_IE_UE_USAGE_TYPE);
	CU_ASSERT_EQUAL(decode.ue_usage_type.header.length, 4);
	CU_ASSERT_EQUAL(decode.ue_usage_type.ue_usage_type_value, 15);

	CU_ASSERT_EQUAL(decode.extended_common_flag_2.header.type, GTPV1_IE_EXTENDED_COMMON_FLAGS_II);
	CU_ASSERT_EQUAL(decode.extended_common_flag_2.header.length, 1);
	CU_ASSERT_EQUAL(decode.extended_common_flag_2.spare, 0);
	CU_ASSERT_EQUAL(decode.extended_common_flag_2.pmts_mi, 1);
	CU_ASSERT_EQUAL(decode.extended_common_flag_2.dtci, 1);
	CU_ASSERT_EQUAL(decode.extended_common_flag_2.pnsi, 1);

	CU_ASSERT_EQUAL(decode.gsn_addr_2.header.type, GTPV1_IE_GSN_ADDR);
	CU_ASSERT_EQUAL(decode.gsn_addr_2.header.length, 16);
	char addr12[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &decode.gsn_addr_2.gsn_address.ipv6, addr12, INET6_ADDRSTRLEN);
	CU_ASSERT_NSTRING_EQUAL(addr12, "2001:db80:3333:4444:5555:6666:7777:8888",39);

	CU_ASSERT_EQUAL(decode.gsn_addr_3.header.type, GTPV1_IE_GSN_ADDR);
	CU_ASSERT_EQUAL(decode.gsn_addr_3.header.length, 16);
	char addr13[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &decode.gsn_addr_3.gsn_address.ipv6, addr13, INET6_ADDRSTRLEN);
	CU_ASSERT_NSTRING_EQUAL(addr13, "2001:db80:3333:4444:5555:6666:7777:8888",39);

	CU_ASSERT_EQUAL(decode.private_extension.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.private_extension.header.length, 6);
	CU_ASSERT_EQUAL(decode.private_extension.extension_identifier, 12);
	CU_ASSERT_NSTRING_EQUAL(decode.private_extension.extension_value,"2021", 4);
}

void test_decode_gtpv1_forward_relocation_rsp(void)
{
	gtpv1_forward_relocation_rsp_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x36, 0x00, 0x6a, 0x37, 0x2f, 0x00, 0x00,
		0x01, 0x80, 0x11, 0x00, 0x00, 0x00, 0xab, 0x12, 0x45, 0x00,
		0xff, 0xfe, 0xee, 0x15, 0x07, 0x85, 0x00, 0x04, 0xc0, 0xa8,
		0x00, 0x2c, 0x85, 0x00, 0x04, 0xc0, 0xa8, 0x00, 0x2c, 0x8c,
		0x00, 0x09, 0x02, 0x00, 0xff, 0xfe, 0xee, 0xd4, 0x81, 0x41,
		0x17, 0x92, 0x00, 0x15, 0x02, 0x00, 0xff, 0xfe, 0xee, 0x20,
		0x01, 0xdb, 0x80, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x66,
		0x66, 0x77, 0x77, 0x88, 0x85, 0x93, 0x00, 0x02, 0x31, 0x31,
		0xb0, 0x00, 0x01, 0x02, 0xb3, 0x00, 0x04, 0x03, 0x01, 0x00,
		0x03, 0xd3, 0x00, 0x02, 0x00, 0x02, 0xdb, 0x00, 0x08, 0x03,
		0x6d, 0x6d, 0x65, 0x03, 0x61, 0x61, 0x61, 0xff, 0x00, 0x06,
		0x00, 0x0c, 0x32, 0x30, 0x32, 0x31};

	CU_ASSERT(decode_gtpv1_forward_relocation_rsp(buf, &decode) == 114);
	CU_ASSERT(decode_gtpv1_forward_relocation_rsp(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_forward_relocation_rsp(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_forward_relocation_rsp(buf, NULL) == -1);
	
	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);
	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_FORWARD_RELOCATION_RESPONSE);
	CU_ASSERT_EQUAL(decode.header.message_len, 106);
	CU_ASSERT_EQUAL(decode.header.teid, 0x372f0000);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);
	
	CU_ASSERT_EQUAL(decode.cause.header.type, GTPV1_IE_CAUSE);
	CU_ASSERT_EQUAL(decode.cause.cause_value, 128);

	CU_ASSERT_EQUAL(decode.teid_control_plane.header.type, GTPV1_IE_TEID_CONTROL_PLANE);
	CU_ASSERT_EQUAL(decode.teid_control_plane.teid, 0x00ab);

	CU_ASSERT_EQUAL(decode.teid_2.header.type, GTPV1_IE_TEID_DATA_2);
	CU_ASSERT_EQUAL(decode.teid_2.nsapi, 5);
	CU_ASSERT_EQUAL(decode.teid_2.teid, 0x0fffeee);

	CU_ASSERT_EQUAL(decode.ranap_cause.header.type, GTPV1_IE_RANAP_CAUSE);
	CU_ASSERT_EQUAL(decode.ranap_cause.ranap_cause, 7);

	CU_ASSERT_EQUAL(decode.sgsn_addr_control_plane.header.type, GTPV1_IE_GSN_ADDR);
	CU_ASSERT_EQUAL(decode.sgsn_addr_control_plane.header.length, 4);
	CU_ASSERT_EQUAL(decode.sgsn_addr_control_plane.gsn_address.ipv4, 3232235564);

	CU_ASSERT_EQUAL(decode.sgsn_addr_user_traffic.header.type, GTPV1_IE_GSN_ADDR);
	CU_ASSERT_EQUAL(decode.sgsn_addr_user_traffic.header.length, 4);
	CU_ASSERT_EQUAL(decode.sgsn_addr_user_traffic.gsn_address.ipv4, 3232235564);

	CU_ASSERT_EQUAL(decode.rab_setup_info.header.type, GTPV1_IE_RAB_SETUP_INFO);
	CU_ASSERT_EQUAL(decode.rab_setup_info.header.length, 9);
	CU_ASSERT_EQUAL(decode.rab_setup_info.spare, 0);
	CU_ASSERT_EQUAL(decode.rab_setup_info.nsapi, 2);
	CU_ASSERT_EQUAL(decode.rab_setup_info.teid, 0x0fffeee);
	CU_ASSERT_EQUAL(decode.rab_setup_info.rnc_ip_addr.ipv4, 3565240599);

	CU_ASSERT_EQUAL(decode.add_rab_setup_info.header.type, GTPV1_IE_ADDITIONAL_RAB_SETUP_INFO);
	CU_ASSERT_EQUAL(decode.add_rab_setup_info.header.length, 21);
	CU_ASSERT_EQUAL(decode.add_rab_setup_info.spare, 0);
	CU_ASSERT_EQUAL(decode.add_rab_setup_info.nsapi, 2);
	CU_ASSERT_EQUAL(decode.add_rab_setup_info.teid, 0x0fffeee);
	char addr[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &decode.add_rab_setup_info.rnc_ip_addr.ipv6, addr, INET6_ADDRSTRLEN);
	CU_ASSERT_NSTRING_EQUAL(addr, "2001:db80:3333:4444:5555:6666:7777:8885",39);

	CU_ASSERT_EQUAL(decode.sgsn_number.header.type, GTPV1_IE_SGSN_NUMBER);
	CU_ASSERT_EQUAL(decode.sgsn_number.header.length, 2);
	CU_ASSERT_STRING_EQUAL(decode.sgsn_number.sgsn_number,"11");

	CU_ASSERT_EQUAL(decode.bssgp_cause.header.type, GTPV1_IE_BSSGP_CAUSE);
	CU_ASSERT_EQUAL(decode.bssgp_cause.header.length, 1);
	CU_ASSERT_EQUAL(decode.bssgp_cause.bssgp_cause, 2);

	CU_ASSERT_EQUAL(decode.list_pfcs.header.type, GTPV1_IE_LIST_OF_SET_UP_PFCS);
	CU_ASSERT_EQUAL(decode.list_pfcs.header.length, 4);
	CU_ASSERT_EQUAL(decode.list_pfcs.list.no_of_pfcs, 3);
	CU_ASSERT_EQUAL(decode.list_pfcs.list.pfi_list[0].spare, 0);
	CU_ASSERT_EQUAL(decode.list_pfcs.list.pfi_list[0].pfi_value, 1);
	CU_ASSERT_EQUAL(decode.list_pfcs.list.pfi_list[1].spare, 0);
	CU_ASSERT_EQUAL(decode.list_pfcs.list.pfi_list[1].pfi_value, 0);
	CU_ASSERT_EQUAL(decode.list_pfcs.list.pfi_list[2].spare, 0);
	CU_ASSERT_EQUAL(decode.list_pfcs.list.pfi_list[2].pfi_value, 3);

	CU_ASSERT_EQUAL(decode.ext_ranap_cause.header.type, GTPV1_IE_EXTENDED_RANAP_CAUSE);
	CU_ASSERT_EQUAL(decode.ext_ranap_cause.header.length, 2);
	CU_ASSERT_EQUAL(decode.ext_ranap_cause.extended_ranap_cause, 2);

	CU_ASSERT_EQUAL(decode.node_id.header.type, GTPV1_IE_NODE_IDENTIFIER);
	CU_ASSERT_EQUAL(decode.node_id.header.length, 8);
	CU_ASSERT_EQUAL(decode.node_id.len_of_node_name, 3);
	CU_ASSERT_STRING_EQUAL(decode.node_id.node_name, "mme");
	CU_ASSERT_EQUAL(decode.node_id.len_of_node_realm, 3);
	CU_ASSERT_STRING_EQUAL(decode.node_id.node_realm, "aaa");

	CU_ASSERT_EQUAL(decode.private_extension.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.private_extension.header.length, 6);
	CU_ASSERT_EQUAL(decode.private_extension.extension_identifier, 12);
	CU_ASSERT_NSTRING_EQUAL(decode.private_extension.extension_value,"2021", 4);
}

void test_decode_gtpv1_forward_relocation_complete(void)
{
	gtpv1_forward_relocation_complete_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x37, 0x00, 0x09, 0x37, 0x2f, 0x00, 0x00,
		0xff, 0x00, 0x06, 0x00, 0x0c, 0x32, 0x30, 0x32, 0x31};

	CU_ASSERT(decode_gtpv1_forward_relocation_complete(buf, &decode) == 17);
	CU_ASSERT(decode_gtpv1_forward_relocation_complete(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_forward_relocation_complete(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_forward_relocation_complete(buf, NULL) == -1);
	
	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);
	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_FORWARD_RELOCATION_COMPLETE);
	CU_ASSERT_EQUAL(decode.header.message_len, 9);
	CU_ASSERT_EQUAL(decode.header.teid, 0x372f0000);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.private_extension.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.private_extension.header.length, 6);
	CU_ASSERT_EQUAL(decode.private_extension.extension_identifier, 12);
	CU_ASSERT_NSTRING_EQUAL(decode.private_extension.extension_value,"2021", 4);
}

void test_decode_gtpv1_relocation_cancel_req(void)
{
	gtpv1_relocation_cancel_req_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x38, 0x00, 0x26, 0x37, 0x2f, 0x00, 0x00,
		0x02, 0x72, 0x02, 0x13, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x9a,
		0x00, 0x08, 0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x11,
		0xc1, 0x00, 0x01, 0x00, 0xd3, 0x00, 0x02, 0x00, 0x02, 0xff,
		0x00, 0x06, 0x00, 0x0c, 0x32, 0x30, 0x32, 0x31};

	CU_ASSERT(decode_gtpv1_relocation_cancel_req(buf, &decode) == 46);
	CU_ASSERT(decode_gtpv1_relocation_cancel_req(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_relocation_cancel_req(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_relocation_cancel_req(buf, NULL) == -1);
	
	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);
	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_RELOCATION_CANCEL_REQ);
	CU_ASSERT_EQUAL(decode.header.message_len, 38);
	CU_ASSERT_EQUAL(decode.header.teid, 0x372f0000);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.imsi.header.type, GTPV1_IE_IMSI);
	CU_ASSERT_EQUAL(decode.imsi.imsi_number_digits, 272031000000000);

	CU_ASSERT_EQUAL(decode.imei_sv.header.type, GTPV1_IE_IMEI_SV);
	CU_ASSERT_EQUAL(decode.imei_sv.header.length, 8);
	CU_ASSERT_EQUAL(decode.imei_sv.imei_sv, 0b0001000100010001000100010001000100100010001000100010001000010001);

	CU_ASSERT_EQUAL(decode.extended_common_flag.header.type, GTPV1_IE_EXTENDED_COMMON_FLAG);
	CU_ASSERT_EQUAL(decode.extended_common_flag.header.length, 1);
	CU_ASSERT_EQUAL(decode.extended_common_flag.uasi, 0);
	CU_ASSERT_EQUAL(decode.extended_common_flag.bdwi, 0);
	CU_ASSERT_EQUAL(decode.extended_common_flag.pcri, 0);
	CU_ASSERT_EQUAL(decode.extended_common_flag.vb, 0);
	CU_ASSERT_EQUAL(decode.extended_common_flag.retloc, 0);
	CU_ASSERT_EQUAL(decode.extended_common_flag.cpsr, 0);
	CU_ASSERT_EQUAL(decode.extended_common_flag.ccrsi, 0);

	CU_ASSERT_EQUAL(decode.ext_ranap_cause.header.type, GTPV1_IE_EXTENDED_RANAP_CAUSE);
	CU_ASSERT_EQUAL(decode.ext_ranap_cause.header.length, 2);
	CU_ASSERT_EQUAL(decode.ext_ranap_cause.extended_ranap_cause, 2);

	CU_ASSERT_EQUAL(decode.private_extension.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.private_extension.header.length, 6);
	CU_ASSERT_EQUAL(decode.private_extension.extension_identifier, 12);
	CU_ASSERT_NSTRING_EQUAL(decode.private_extension.extension_value,"2021", 4);
}

void test_decode_gtpv1_relocation_cancel_rsp(void)
{
	gtpv1_relocation_cancel_rsp_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x39, 0x00, 0x0b, 0x37, 0x2f, 0x00, 0x00,
		0x01, 0x80, 0xff, 0x00, 0x06, 0x00, 0x0c, 0x32, 0x30, 0x32, 0x31};

	CU_ASSERT(decode_gtpv1_relocation_cancel_rsp(buf, &decode) == 19);
	CU_ASSERT(decode_gtpv1_relocation_cancel_rsp(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_relocation_cancel_rsp(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_relocation_cancel_rsp(buf, NULL) == -1);
	
	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);
	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_RELOCATION_CANCEL_RSP);
	CU_ASSERT_EQUAL(decode.header.message_len, 11);
	CU_ASSERT_EQUAL(decode.header.teid, 0x372f0000);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.cause.header.type, GTPV1_IE_CAUSE);
	CU_ASSERT_EQUAL(decode.cause.cause_value, 128);	

	CU_ASSERT_EQUAL(decode.private_extension.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.private_extension.header.length, 6);
	CU_ASSERT_EQUAL(decode.private_extension.extension_identifier, 12);
	CU_ASSERT_NSTRING_EQUAL(decode.private_extension.extension_value,"2021", 4);
}

void test_decode_gtpv1_forward_relocation_complete_ack(void)
{
	gtpv1_forward_relocation_complete_ack_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x3b, 0x00, 0x0b, 0x37, 0x2f, 0x00, 0x00,
		0x01, 0x80, 0xff, 0x00, 0x06, 0x00, 0x0c, 0x32, 0x30, 0x32, 0x31};

	CU_ASSERT(decode_gtpv1_forward_relocation_complete_ack(buf, &decode) == 19);
	CU_ASSERT(decode_gtpv1_forward_relocation_complete_ack(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_forward_relocation_complete_ack(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_forward_relocation_complete_ack(buf, NULL) == -1);
	
	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);
	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_FORWARD_RELOCATION_COMPLETE_ACK);
	CU_ASSERT_EQUAL(decode.header.message_len, 11);
	CU_ASSERT_EQUAL(decode.header.teid, 0x372f0000);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.cause.header.type, GTPV1_IE_CAUSE);
	CU_ASSERT_EQUAL(decode.cause.cause_value, 128);	

	CU_ASSERT_EQUAL(decode.private_extension.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.private_extension.header.length, 6);
	CU_ASSERT_EQUAL(decode.private_extension.extension_identifier, 12);
	CU_ASSERT_NSTRING_EQUAL(decode.private_extension.extension_value,"2021", 4);;
}

void test_decode_gtpv1_forward_srns_context_ack(void)
{
	gtpv1_forward_srns_context_ack_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x3c, 0x00, 0x0b, 0x37, 0x2f, 0x00, 0x00,
		0x01, 0x80, 0xff, 0x00, 0x06, 0x00, 0x0c, 0x32, 0x30, 0x32, 0x31};

	CU_ASSERT(decode_gtpv1_forward_srns_context_ack(buf, &decode) == 19);
	CU_ASSERT(decode_gtpv1_forward_srns_context_ack(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_forward_srns_context_ack(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_forward_srns_context_ack(buf, NULL) == -1);
	
	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);
	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_FORWARD_SRNS_CONTEXT_ACK);
	CU_ASSERT_EQUAL(decode.header.message_len, 11);
	CU_ASSERT_EQUAL(decode.header.teid, 0x372f0000);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.cause.header.type, GTPV1_IE_CAUSE);
	CU_ASSERT_EQUAL(decode.cause.cause_value, 128);	

	CU_ASSERT_EQUAL(decode.private_extension.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.private_extension.header.length, 6);
	CU_ASSERT_EQUAL(decode.private_extension.extension_identifier, 12);
	CU_ASSERT_NSTRING_EQUAL(decode.private_extension.extension_value,"2021", 4);
}

void test_decode_gtpv1_forward_srns_ctxt(void)
{
	gtpv1_forward_srns_ctxt_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x3a, 0x00, 0x24, 0x37, 0x2f, 0x00, 0x00,
		0x16, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02,
		0xa1, 0x00, 0x02, 0x31, 0x31, 0xaf, 0x00, 0x09, 0x01, 0x00,
		0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0xff, 0x00, 0x06,
		0x00, 0x0c, 0x32, 0x30, 0x32, 0x31};

	CU_ASSERT(decode_gtpv1_forward_srns_ctxt(buf, &decode) == 44);
	CU_ASSERT(decode_gtpv1_forward_srns_ctxt(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_forward_srns_ctxt(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_forward_srns_ctxt(buf, NULL) == -1);
	
	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);
	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_FORWARD_SRNS_CONTEXT);
	CU_ASSERT_EQUAL(decode.header.message_len, 36);
	CU_ASSERT_EQUAL(decode.header.teid, 0x372f0000);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.rab_context.header.type, GTPV1_IE_RAB_CONTEXT);
	CU_ASSERT_EQUAL(decode.rab_context.spare, 0);
	CU_ASSERT_EQUAL(decode.rab_context.nsapi, 1);
	CU_ASSERT_EQUAL(decode.rab_context.dl_gtp_u_sequence_number, 1);
	CU_ASSERT_EQUAL(decode.rab_context.ul_gtp_u_sequence_number, 2);
	CU_ASSERT_EQUAL(decode.rab_context.dl_pdcp_sequence_number, 1);
	CU_ASSERT_EQUAL(decode.rab_context.ul_pdcp_sequence_number, 2);

	CU_ASSERT_EQUAL(decode.pdcp_ctxt.header.type, GTPV1_IE_SRC_RNC_PDCP_CTXT_INFO);
	CU_ASSERT_EQUAL(decode.pdcp_ctxt.header.length, 2);
	CU_ASSERT_STRING_EQUAL(decode.pdcp_ctxt.rrc_container, "11");

	CU_ASSERT_EQUAL(decode.pdu_num.header.type, GTPV1_IE_PDU_NUMBERS);
	CU_ASSERT_EQUAL(decode.pdu_num.header.length, 9);
	CU_ASSERT_EQUAL(decode.pdu_num.spare, 0);
	CU_ASSERT_EQUAL(decode.pdu_num.nsapi, 1);
	CU_ASSERT_EQUAL(decode.pdu_num.dl_gtpu_seqn_nbr, 1);
	CU_ASSERT_EQUAL(decode.pdu_num.ul_gtpu_seqn_nbr, 2);
	CU_ASSERT_EQUAL(decode.pdu_num.snd_npdu_nbr, 1);
	CU_ASSERT_EQUAL(decode.pdu_num.rcv_npdu_nbr, 2);

	CU_ASSERT_EQUAL(decode.private_extension.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.private_extension.header.length, 6);
	CU_ASSERT_EQUAL(decode.private_extension.extension_identifier, 12);
	CU_ASSERT_NSTRING_EQUAL(decode.private_extension.extension_value,"2021", 4);
}

void test_decode_gtpv1_ran_info_relay(void)
{
	gtpv1_ran_info_relay_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x46, 0x00, 0x17, 0x37, 0x2f, 0x00, 0x00,
		0x90, 0x00, 0x02, 0x31, 0x31, 0x9e, 0x00, 0x02, 0x31, 0x31,
		0xb2, 0x00, 0x01, 0x02, 0xff, 0x00, 0x06, 0x00, 0x0c, 0x32,
		0x30, 0x32, 0x31};

	CU_ASSERT(decode_gtpv1_ran_info_relay(buf, &decode) == 31);
	CU_ASSERT(decode_gtpv1_ran_info_relay(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_ran_info_relay(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_ran_info_relay(buf, NULL) == -1);
	
	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);
	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_RAN_INFO_RELAY);
	CU_ASSERT_EQUAL(decode.header.message_len, 23);
	CU_ASSERT_EQUAL(decode.header.teid, 0x372f0000);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.ran_transparent_container.header.type, GTPV1_IE_RAN_TRANSPARENT_CONTAINER);
	CU_ASSERT_EQUAL(decode.ran_transparent_container.header.length, 2);
	CU_ASSERT_STRING_EQUAL(decode.ran_transparent_container.rtc_field, "11");

	CU_ASSERT_EQUAL(decode.rim_addr.header.type, GTPV1_IE_RIM_ROUTING_ADDR);
	CU_ASSERT_EQUAL(decode.rim_addr.header.length, 2);
	CU_ASSERT_STRING_EQUAL(decode.rim_addr.rim_routing_addr, "11");

	CU_ASSERT_EQUAL(decode.rim_addr_disc.header.type, GTPV1_IE_RIM_ROUTING_ADDR_DISCRIMINATOR);
	CU_ASSERT_EQUAL(decode.rim_addr_disc.header.length, 1);
	CU_ASSERT_EQUAL(decode.rim_addr_disc.spare, 0);
	CU_ASSERT_EQUAL(decode.rim_addr_disc.discriminator, 2);

	CU_ASSERT_EQUAL(decode.private_extension.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.private_extension.header.length, 6);
	CU_ASSERT_EQUAL(decode.private_extension.extension_identifier, 12);
	CU_ASSERT_NSTRING_EQUAL(decode.private_extension.extension_value,"2021", 4);
}

void test_decode_gtpv1_mbms_notification_req(void)
{
	gtpv1_mbms_notification_req_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x60, 0x00, 0x39, 0x37, 0x2f, 0x00, 0x00,
		0x02, 0x72, 0x02, 0x13, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x11,
		0x00, 0x00, 0x00, 0xab, 0x14, 0x05, 0x80, 0x00, 0x06, 0xf1,
		0x21, 0x15, 0x2c, 0x8a, 0x97, 0x83, 0x00, 0x0d, 0x6e, 0x65,
		0x78, 0x74, 0x70, 0x68, 0x6f, 0x6e, 0x65, 0x73, 0x2e, 0x63,
		0x6f, 0x85, 0x00, 0x04, 0xc0, 0xa8, 0x00, 0x2c, 0xff, 0x00,
		0x06, 0x00, 0x0c, 0x32, 0x30, 0x32, 0x31};

	CU_ASSERT(decode_gtpv1_mbms_notification_req(buf, &decode) == 65);
	CU_ASSERT(decode_gtpv1_mbms_notification_req(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_mbms_notification_req(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_mbms_notification_req(buf, NULL) == -1);
	
	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);
	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_MBMS_NOTIFICATION_REQ);
	CU_ASSERT_EQUAL(decode.header.message_len, 57);
	CU_ASSERT_EQUAL(decode.header.teid, 0x372f0000);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.imsi.header.type, GTPV1_IE_IMSI);
	CU_ASSERT_EQUAL(decode.imsi.imsi_number_digits, 272031000000000);

	CU_ASSERT_EQUAL(decode.tunn_endpt_idnt_control_plane.header.type, GTPV1_IE_TEID_CONTROL_PLANE);
	CU_ASSERT_EQUAL(decode.tunn_endpt_idnt_control_plane.teid, 0x00ab);

	CU_ASSERT_EQUAL(decode.nsapi.header.type, GTPV1_IE_NSAPI);
	CU_ASSERT_EQUAL(decode.nsapi.spare, 0);
	CU_ASSERT_EQUAL(decode.nsapi.nsapi_value, 5);

	CU_ASSERT_EQUAL(decode.end_user_address.header.type, GTPV1_IE_END_USER_ADDR);
	CU_ASSERT_EQUAL(decode.end_user_address.header.length, 6);
	CU_ASSERT_EQUAL(decode.end_user_address.spare, 0xf);
	CU_ASSERT_EQUAL(decode.end_user_address.pdp_type_org, 1);
	CU_ASSERT_EQUAL(decode.end_user_address.pdp_type_number, 0x21);
	CU_ASSERT_EQUAL(decode.end_user_address.pdp_address.ipv4, 355240599);

	CU_ASSERT_EQUAL(decode.apn.header.type, GTPV1_IE_APN);
	CU_ASSERT_EQUAL(decode.apn.header.length, 13);
	CU_ASSERT_NSTRING_EQUAL(decode.apn.apn_value,"nextphones.co",13);

	CU_ASSERT_EQUAL(decode.ggsn_addr_control_plane.header.type, GTPV1_IE_GSN_ADDR);
	CU_ASSERT_EQUAL(decode.ggsn_addr_control_plane.header.length, 4);
	CU_ASSERT_EQUAL(decode.ggsn_addr_control_plane.gsn_address.ipv4, 3232235564);

	CU_ASSERT_EQUAL(decode.private_extension.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.private_extension.header.length, 6);
	CU_ASSERT_EQUAL(decode.private_extension.extension_identifier, 12);
	CU_ASSERT_NSTRING_EQUAL(decode.private_extension.extension_value,"2021", 4);
}

void test_decode_gtpv1_mbms_notification_rsp(void)
{
	gtpv1_mbms_notification_rsp_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x61, 0x00, 0x0b, 0x37, 0x2f, 0x00, 0x00,
		0x01, 0x80, 0xff, 0x00, 0x06, 0x00, 0x0c, 0x32, 0x30, 0x32, 0x31};

	CU_ASSERT(decode_gtpv1_mbms_notification_rsp(buf, &decode) == 19);
	CU_ASSERT(decode_gtpv1_mbms_notification_rsp(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_mbms_notification_rsp(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_mbms_notification_rsp(buf, NULL) == -1);
	
	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);
	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_MBMS_NOTIFICATION_RSP);
	CU_ASSERT_EQUAL(decode.header.message_len, 11);
	CU_ASSERT_EQUAL(decode.header.teid, 0x372f0000);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.cause.header.type, GTPV1_IE_CAUSE);
	CU_ASSERT_EQUAL(decode.cause.cause_value, 128);	

	CU_ASSERT_EQUAL(decode.private_extension.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.private_extension.header.length, 6);
	CU_ASSERT_EQUAL(decode.private_extension.extension_identifier, 12);
	CU_ASSERT_NSTRING_EQUAL(decode.private_extension.extension_value,"2021", 4);
}

void test_decode_gtpv1_ms_info_change_notification_req(void)
{
	gtpv1_ms_info_change_notification_req_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x80, 0x00, 0x3d, 0x37, 0x2f, 0x00, 0x00,
		0x02, 0x72, 0x02, 0x13, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x14,
		0x09, 0x97, 0x00, 0x01, 0x02, 0x98, 0x00, 0x08, 0x01, 0x04,
		0xf4, 0x87, 0x00, 0x01, 0x00, 0x01, 0x9a, 0x00, 0x08, 0x11,
		0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x11, 0xc1, 0x00, 0x01,
		0x00, 0xc2, 0x00, 0x08, 0x04, 0xf4, 0x87, 0x01, 0x00, 0x00,
		0x01, 0x41, 0xff, 0x00, 0x06, 0x00, 0x0c, 0x32, 0x30, 0x32, 0x31};

	CU_ASSERT(decode_gtpv1_ms_info_change_notification_req(buf, &decode) == 69);
	CU_ASSERT(decode_gtpv1_ms_info_change_notification_req(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_ms_info_change_notification_req(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_ms_info_change_notification_req(buf, NULL) == -1);
	
	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);
	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_MS_INFO_CHANGE_NOTIFICATION_REQ);
	CU_ASSERT_EQUAL(decode.header.message_len, 61);
	CU_ASSERT_EQUAL(decode.header.teid, 0x372f0000);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.imsi.header.type, GTPV1_IE_IMSI);
	CU_ASSERT_EQUAL(decode.imsi.imsi_number_digits, 272031000000000);

	CU_ASSERT_EQUAL(decode.linked_nsapi.header.type, GTPV1_IE_NSAPI);
	CU_ASSERT_EQUAL(decode.linked_nsapi.spare, 0);
	CU_ASSERT_EQUAL(decode.linked_nsapi.nsapi_value, 9);

	CU_ASSERT_EQUAL(decode.rat_type.header.type, GTPV1_IE_RAT_TYPE);
	CU_ASSERT_EQUAL(decode.rat_type.header.length, 1);
	CU_ASSERT_EQUAL(decode.rat_type.rat_type, 2);

	CU_ASSERT_EQUAL(decode.user_location_information.header.type, GTPV1_IE_USER_LOCATION_INFORMATION);
	CU_ASSERT_EQUAL(decode.user_location_information.header.length, 8);
	CU_ASSERT_EQUAL(decode.user_location_information.geographic_location_type, 1);
	CU_ASSERT_EQUAL(decode.user_location_information.mcc_digit_2, 0x0);
	CU_ASSERT_EQUAL(decode.user_location_information.mcc_digit_1, 0x4);
	CU_ASSERT_EQUAL(decode.user_location_information.mnc_digit_3, 0x8);
	CU_ASSERT_EQUAL(decode.user_location_information.mcc_digit_3, 0x4);
	CU_ASSERT_EQUAL(decode.user_location_information.mnc_digit_2, 0x7);
	CU_ASSERT_EQUAL(decode.user_location_information.mnc_digit_1, 0x0);
	CU_ASSERT_EQUAL(decode.user_location_information.lac, 0x1);
	CU_ASSERT_EQUAL(decode.user_location_information.ci_sac_rac, 0x1);

	CU_ASSERT_EQUAL(decode.imei_sv.header.type, GTPV1_IE_IMEI_SV);
	CU_ASSERT_EQUAL(decode.imei_sv.header.length, 8);
	CU_ASSERT_EQUAL(decode.imei_sv.imei_sv, 0b0001000100010001000100010001000100100010001000100010001000010001);

	CU_ASSERT_EQUAL(decode.extended_common_flag.header.type, GTPV1_IE_EXTENDED_COMMON_FLAG);
	CU_ASSERT_EQUAL(decode.extended_common_flag.header.length, 1);
	CU_ASSERT_EQUAL(decode.extended_common_flag.uasi, 0);
	CU_ASSERT_EQUAL(decode.extended_common_flag.bdwi, 0);
	CU_ASSERT_EQUAL(decode.extended_common_flag.pcri, 0);
	CU_ASSERT_EQUAL(decode.extended_common_flag.vb, 0);
	CU_ASSERT_EQUAL(decode.extended_common_flag.retloc, 0);
	CU_ASSERT_EQUAL(decode.extended_common_flag.cpsr, 0);
	CU_ASSERT_EQUAL(decode.extended_common_flag.ccrsi, 0);

	CU_ASSERT_EQUAL(decode.user_csg_information.header.type, GTPV1_IE_USER_CSG_INFORMATION);
	CU_ASSERT_EQUAL(decode.user_csg_information.header.length, 8);
	CU_ASSERT_EQUAL(decode.user_csg_information.mcc_digit_2, 0x0);
	CU_ASSERT_EQUAL(decode.user_csg_information.mcc_digit_1, 0x4);
	CU_ASSERT_EQUAL(decode.user_csg_information.mnc_digit_3, 0x8);
	CU_ASSERT_EQUAL(decode.user_csg_information.mcc_digit_3, 0x4);
	CU_ASSERT_EQUAL(decode.user_csg_information.mnc_digit_2, 0x7);
	CU_ASSERT_EQUAL(decode.user_csg_information.mnc_digit_1, 0x0);
	CU_ASSERT_EQUAL(decode.user_csg_information.spare, 0);
	CU_ASSERT_EQUAL(decode.user_csg_information.csg_id, 1);
	CU_ASSERT_EQUAL(decode.user_csg_information.csg_id_II, 1);
	CU_ASSERT_EQUAL(decode.user_csg_information.access_mode, 1);
	CU_ASSERT_EQUAL(decode.user_csg_information.spare2, 0);
	CU_ASSERT_EQUAL(decode.user_csg_information.cmi, 1);

	CU_ASSERT_EQUAL(decode.private_extension.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.private_extension.header.length, 6);
	CU_ASSERT_EQUAL(decode.private_extension.extension_identifier, 12);
	CU_ASSERT_NSTRING_EQUAL(decode.private_extension.extension_value,"2021", 4);
}

void test_decode_gtpv1_ms_info_change_notification_rsp(void)
{
	gtpv1_ms_info_change_notification_rsp_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x81, 0x00, 0x29, 0x37, 0x2f, 0x00, 0x00,
		0x01, 0x80, 0x02, 0x72, 0x02, 0x13, 0x00, 0x00, 0x00, 0x00,
		0xf0, 0x14, 0x09, 0x9a, 0x00, 0x08, 0x11, 0x11, 0x11, 0x11,
		0x22, 0x22, 0x22, 0x11, 0xb5, 0x00, 0x01, 0x04, 0xc3, 0x00,
		0x01, 0x07, 0xff, 0x00, 0x06, 0x00, 0x0c, 0x32, 0x30, 0x32, 0x31};

	CU_ASSERT(decode_gtpv1_ms_info_change_notification_rsp(buf, &decode) == 49);
	CU_ASSERT(decode_gtpv1_ms_info_change_notification_rsp(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_ms_info_change_notification_rsp(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_ms_info_change_notification_rsp(buf, NULL) == -1);
	
	CU_ASSERT_EQUAL(decode.header.version, 1);
	CU_ASSERT_EQUAL(decode.header.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.header.spare, 0);
	CU_ASSERT_EQUAL(decode.header.extension_header, 0);
	CU_ASSERT_EQUAL(decode.header.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_flag, 0);
	CU_ASSERT_EQUAL(decode.header.message_type, GTPV1_MS_INFO_CHANGE_NOTIFICATION_RSP);
	CU_ASSERT_EQUAL(decode.header.message_len, 41);
	CU_ASSERT_EQUAL(decode.header.teid, 0x372f0000);
	CU_ASSERT_EQUAL(decode.header.seq, 0);
	CU_ASSERT_EQUAL(decode.header.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.header.next_extension_header_type, 0);

	CU_ASSERT_EQUAL(decode.cause.header.type, GTPV1_IE_CAUSE);
	CU_ASSERT_EQUAL(decode.cause.cause_value, 128);	

	CU_ASSERT_EQUAL(decode.imsi.header.type, GTPV1_IE_IMSI);
	CU_ASSERT_EQUAL(decode.imsi.imsi_number_digits, 272031000000000);

	CU_ASSERT_EQUAL(decode.linked_nsapi.header.type, GTPV1_IE_NSAPI);
	CU_ASSERT_EQUAL(decode.linked_nsapi.spare, 0);
	CU_ASSERT_EQUAL(decode.linked_nsapi.nsapi_value, 9);

	CU_ASSERT_EQUAL(decode.imei_sv.header.type, GTPV1_IE_IMEI_SV);
	CU_ASSERT_EQUAL(decode.imei_sv.header.length, 8);
	CU_ASSERT_EQUAL(decode.imei_sv.imei_sv, 0b0001000100010001000100010001000100100010001000100010001000010001);

	CU_ASSERT_EQUAL(decode.ms_info_change_reporting_action.header.type, GTPV1_IE_MS_INFO_CHANGE_REPORTING_ACTION);
	CU_ASSERT_EQUAL(decode.ms_info_change_reporting_action.header.length, 1);
	CU_ASSERT_EQUAL(decode.ms_info_change_reporting_action.action, 4);

	CU_ASSERT_EQUAL(decode.private_extension.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.private_extension.header.length, 6);
	CU_ASSERT_EQUAL(decode.private_extension.extension_identifier, 12);
	CU_ASSERT_NSTRING_EQUAL(decode.private_extension.extension_value,"2021", 4);
}
