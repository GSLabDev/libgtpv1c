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

#include "test_decoder_gtpv1_ies.h"

void test_decode_gtpv1_header(void)
{
	gtpv1_header_t decode = {0};
	uint8_t buf[SIZE] = {0x30, 0x10, 0x00, 0xc2, 0x00, 0x00, 0x00, 0x00};

	CU_ASSERT(decode_gtpv1_header(buf, &decode) == 8);
	CU_ASSERT(decode_gtpv1_header(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_header(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_header(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.version, 1);
	CU_ASSERT_EQUAL(decode.protocol_type, 1);
	CU_ASSERT_EQUAL(decode.spare, 0);
	CU_ASSERT_EQUAL(decode.extension_header, 0);
	CU_ASSERT_EQUAL(decode.seq_num_flag, 0);
	CU_ASSERT_EQUAL(decode.n_pdu_flag, 0);
	CU_ASSERT_EQUAL(decode.message_type, 16);
	CU_ASSERT_EQUAL(decode.message_len, 194);
	CU_ASSERT_EQUAL(decode.teid, 0);
	CU_ASSERT_EQUAL(decode.seq, 0);
	CU_ASSERT_EQUAL(decode.n_pdu_number, 0);
	CU_ASSERT_EQUAL(decode.next_extension_header_type, 0);
}

void test_decode_gtpv1_cause_ie(void)
{
	gtpv1_cause_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x01, 0x80};

	CU_ASSERT(decode_gtpv1_cause_ie(buf, &decode) == 2);
	CU_ASSERT(decode_gtpv1_cause_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_cause_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_cause_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_CAUSE);
	CU_ASSERT_EQUAL(decode.cause_value, 128);
}

void test_decode_gtpv1_imsi_ie(void)
{
	gtpv1_imsi_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x02, 0x72, 0x02, 0x13, 0x00, 0x00, 0x00, 0x00, 0xf0};

	CU_ASSERT(decode_gtpv1_imsi_ie(buf, &decode) == 9);
	CU_ASSERT(decode_gtpv1_imsi_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_imsi_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_imsi_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_IMSI);
	CU_ASSERT_EQUAL(decode.imsi_number_digits, 272031000000000);
}

void test_decode_gtpv1_routing_area_identity_ie(void)
{
	gtpv1_routing_area_identity_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x03, 0x04, 0xf4, 0x87, 0x00, 0x14, 0x14};

	CU_ASSERT(decode_gtpv1_routing_area_identity_ie(buf, &decode) == 7);
	CU_ASSERT(decode_gtpv1_routing_area_identity_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_routing_area_identity_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_routing_area_identity_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_ROUTEING_AREA_IDENTITY);
	CU_ASSERT_EQUAL(decode.rai_value.mcc_digit_2, 0x0);
	CU_ASSERT_EQUAL(decode.rai_value.mcc_digit_1, 0x4);
	CU_ASSERT_EQUAL(decode.rai_value.mnc_digit_3, 0x8);
	CU_ASSERT_EQUAL(decode.rai_value.mcc_digit_3, 0x4);
	CU_ASSERT_EQUAL(decode.rai_value.mnc_digit_2, 0x7);
	CU_ASSERT_EQUAL(decode.rai_value.mnc_digit_1, 0x0);
	CU_ASSERT_EQUAL(decode.rai_value.lac, 0x14);
	CU_ASSERT_EQUAL(decode.rai_value.rac, 0x14);

	gtpv1_routing_area_identity_ie_t decode_1 = {0};
	uint8_t buf_1[SIZE] = {0x03, 0x25, 0x83, 0x81, 0x00, 0x14, 0x14};

	CU_ASSERT(decode_gtpv1_routing_area_identity_ie(buf_1, &decode_1) == 7);
	CU_ASSERT_EQUAL(decode_1.header.type, GTPV1_IE_ROUTEING_AREA_IDENTITY);
	CU_ASSERT_EQUAL(decode_1.rai_value.mcc_digit_2, 2);
	CU_ASSERT_EQUAL(decode_1.rai_value.mcc_digit_1, 5);
	CU_ASSERT_EQUAL(decode_1.rai_value.mnc_digit_3, 8);
	CU_ASSERT_EQUAL(decode_1.rai_value.mcc_digit_3, 3);
	CU_ASSERT_EQUAL(decode_1.rai_value.mnc_digit_1, 1);
	CU_ASSERT_EQUAL(decode_1.rai_value.mnc_digit_2, 8);
	CU_ASSERT_EQUAL(decode_1.rai_value.lac, 20);
	CU_ASSERT_EQUAL(decode_1.rai_value.rac, 20);

}

void test_decode_gtpv1_reordering_req_ie(void)
{
	gtpv1_reordering_req_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x08, 0x00};

	CU_ASSERT(decode_gtpv1_reordering_req_ie(buf, &decode) == 2);
	CU_ASSERT(decode_gtpv1_reordering_req_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_reordering_req_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_reordering_req_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_REORDERING_REQ);
	CU_ASSERT_EQUAL(decode.spare, 0);
	CU_ASSERT_EQUAL(decode.reord_req, 0);
}

void test_decode_gtpv1_recovery_ie(void)
{
	gtpv1_recovery_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x0e, 0x02};

	CU_ASSERT(decode_gtpv1_recovery_ie(buf, &decode) == 2);
	CU_ASSERT(decode_gtpv1_recovery_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_recovery_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_recovery_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_RECOVERY);
	CU_ASSERT_EQUAL(decode.restart_counter, 2);
}

void test_decode_gtpv1_selection_mode_ie(void)
{
	gtpv1_selection_mode_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x0f, 0x01};

	CU_ASSERT(decode_gtpv1_selection_mode_ie(buf, &decode) == 2);
	CU_ASSERT(decode_gtpv1_selection_mode_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_selection_mode_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_selection_mode_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_SELECTION_MODE);
	CU_ASSERT_EQUAL(decode.spare2, 0);
	CU_ASSERT_EQUAL(decode.selec_mode, 1);
}

void test_decode_gtpv1_teid_ie(void)
{
	gtpv1_teid_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x10, 0x00, 0xff, 0xfe, 0xee};

	CU_ASSERT(decode_gtpv1_teid_ie(buf, &decode) == 5);
	CU_ASSERT(decode_gtpv1_teid_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_teid_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_teid_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_TEID_DATA_1);
	CU_ASSERT_EQUAL(decode.teid, 0x0fffeee);
}

void test_decode_gtpv1_teardown_ind_ie(void)
{
	gtpv1_teardown_ind_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x13, 0x01};

	CU_ASSERT(decode_gtpv1_teardown_ind_ie(buf, &decode) == 2);
	CU_ASSERT(decode_gtpv1_teardown_ind_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_teardown_ind_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_teardown_ind_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_TEARDOWN_IND);
	CU_ASSERT_EQUAL(decode.spare, 0);
	CU_ASSERT_EQUAL(decode.teardown_ind, 1);
}

void test_decode_gtpv1_nsapi_ie(void)
{
	gtpv1_nsapi_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x14, 0x05};

	CU_ASSERT(decode_gtpv1_nsapi_ie(buf, &decode) == 2);
	CU_ASSERT(decode_gtpv1_nsapi_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_nsapi_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_nsapi_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_NSAPI);
	CU_ASSERT_EQUAL(decode.spare, 0);
	CU_ASSERT_EQUAL(decode.nsapi_value, 5);
}

void test_decode_gtpv1_chrgng_char_ie(void)
{
	gtpv1_chrgng_char_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x1a, 0x00, 0x01};

	CU_ASSERT(decode_gtpv1_chrgng_char_ie(buf, &decode) == 3);
	CU_ASSERT(decode_gtpv1_chrgng_char_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_chrgng_char_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_chrgng_char_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_CHRGNG_CHAR);
	CU_ASSERT_EQUAL(decode.chrgng_char_val, 1);
}

void test_decode_gtpv1_trace_reference_ie(void)
{
	gtpv1_trace_reference_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x1b, 0x00, 0x09};

	CU_ASSERT(decode_gtpv1_trace_reference_ie(buf, &decode) == 3);
	CU_ASSERT(decode_gtpv1_trace_reference_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_trace_reference_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_trace_reference_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_TRACE_REFERENCE);
	CU_ASSERT_EQUAL(decode.trace_reference, 9);
}

void test_decode_gtpv1_trace_type_ie(void)
{
	gtpv1_trace_type_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x1c, 0x00, 0x09};

	CU_ASSERT(decode_gtpv1_trace_type_ie(buf, &decode) == 3);
	CU_ASSERT(decode_gtpv1_trace_type_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_trace_type_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_trace_type_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_TRACE_TYPE);
	CU_ASSERT_EQUAL(decode.trace_type, 9);
}

void test_decode_gtpv1_charging_id_ie(void)
{
	gtpv1_charging_id_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x7f, 0x03, 0x30, 0x41, 0x0b};

	CU_ASSERT(decode_gtpv1_charging_id_ie(buf, &decode) == 5);
	CU_ASSERT(decode_gtpv1_charging_id_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_charging_id_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_charging_id_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_CHARGING_ID);
	CU_ASSERT_EQUAL(decode.chrgng_id_val, 0x0330410b);
}

void test_decode_gtpv1_end_user_address_ie(void)
{
	gtpv1_end_user_address_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x80, 0x00, 0x06, 0xf1, 0x21, 0xd4, 0x81, 0x41, 0x17};

	CU_ASSERT(decode_gtpv1_end_user_address_ie(buf, &decode) == 9);
	CU_ASSERT(decode_gtpv1_end_user_address_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_end_user_address_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_end_user_address_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_END_USER_ADDR);
	CU_ASSERT_EQUAL(decode.header.length, 6);
	CU_ASSERT_EQUAL(decode.spare, 0xf);
	CU_ASSERT_EQUAL(decode.pdp_type_org, 1);
	CU_ASSERT_EQUAL(decode.pdp_type_number, 0x21);
	CU_ASSERT_EQUAL(decode.pdp_address.ipv4, 3565240599);

	gtpv1_end_user_address_ie_t decode1 = {0};
	uint8_t buf1[SIZE] = {0x80, 0x00, 0x16, 0xf1, 0x8d, 0xc0, 0xa8, 0x00,
		0x2c, 0x20, 0x01, 0xdb, 0x80, 0x33, 0x33, 0x44, 0x44, 0x55,
		0x55, 0x66, 0x66, 0x77, 0x77, 0x88, 0x88};

	CU_ASSERT(decode_gtpv1_end_user_address_ie(buf1, &decode1) == 25);
	CU_ASSERT(decode_gtpv1_end_user_address_ie(NULL, &decode1) == -1);
	CU_ASSERT(decode_gtpv1_end_user_address_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_end_user_address_ie(buf1, NULL) == -1);
	CU_ASSERT_EQUAL(decode1.header.type, GTPV1_IE_END_USER_ADDR);
	CU_ASSERT_EQUAL(decode1.header.length, 22);
	CU_ASSERT_EQUAL(decode1.spare, 0xf);
	CU_ASSERT_EQUAL(decode1.pdp_type_org, 1);
	CU_ASSERT_EQUAL(decode1.pdp_type_number, 0x8D);
	CU_ASSERT_EQUAL(decode1.pdp_address.ipv4, 3232235564);
	char addr[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &decode1.pdp_address.ipv6, addr, INET6_ADDRSTRLEN);
	CU_ASSERT_NSTRING_EQUAL(addr, "2001:db80:3333:4444:5555:6666:7777:8888",39);

	gtpv1_end_user_address_ie_t decode2 = {0};
	uint8_t buf2[SIZE] = {0x80, 0x00, 0x02, 0xf0, 0x21};

	CU_ASSERT(decode_gtpv1_end_user_address_ie(buf2, &decode2) == 5);
	CU_ASSERT(decode_gtpv1_end_user_address_ie(NULL, &decode2) == -1);
	CU_ASSERT(decode_gtpv1_end_user_address_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_end_user_address_ie(buf2, NULL) == -1);
	CU_ASSERT_EQUAL(decode2.header.type, GTPV1_IE_END_USER_ADDR);
	CU_ASSERT_EQUAL(decode2.header.length, 2);
	CU_ASSERT_EQUAL(decode2.spare, 0xf);
	CU_ASSERT_EQUAL(decode2.pdp_type_org, 0);
	CU_ASSERT_EQUAL(decode2.pdp_type_number, 0x21);
}

void test_decode_gtpv1_apn_ie(void)
{
	gtpv1_apn_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x83, 0x00, 0x0d, 0x6e, 0x65, 0x78, 0x74, 0x70, 0x68,
		0x6f, 0x6e, 0x65, 0x73, 0x2e, 0x63, 0x6f};

	CU_ASSERT(decode_gtpv1_apn_ie(buf, &decode) == 16);
	CU_ASSERT(decode_gtpv1_apn_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_apn_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_apn_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_APN);
	CU_ASSERT_EQUAL(decode.header.length, 13);
	CU_ASSERT_STRING_EQUAL(decode.apn_value,"nextphones.co");
}

void test_decode_gtpv1_protocol_config_options_ie(void)
{
	gtpv1_protocol_config_options_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x84, 0x00, 0x19, 0x81, 0x00, 0x02, 0x09, 0x33,
		0x35, 0x35, 0x32, 0x34, 0x30, 0x35, 0x39, 0x39, 0x00, 0x02,
		0x09, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31};
	
	CU_ASSERT(decode_gtpv1_protocol_config_options_ie(buf, &decode) == 28);
	CU_ASSERT(decode_gtpv1_protocol_config_options_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_protocol_config_options_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_protocol_config_options_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_PROTOCOL_CONFIG_OPTIONS);
	CU_ASSERT_EQUAL(decode.header.length, 25);
	CU_ASSERT_EQUAL(decode.pco.pco_flag_ext, 1);
	CU_ASSERT_EQUAL(decode.pco.pco_flag_spare, 0);
	CU_ASSERT_EQUAL(decode.pco.pco_cfg_proto, 1);
	CU_ASSERT_EQUAL(decode.pco.pco_content[0].prot_or_cont_id, 2);
	CU_ASSERT_EQUAL(decode.pco.pco_content[0].length, 9);
	CU_ASSERT_STRING_EQUAL(decode.pco.pco_content[0].content,"355240599");
	CU_ASSERT_EQUAL(decode.pco.pco_content[1].prot_or_cont_id, 2);
	CU_ASSERT_EQUAL(decode.pco.pco_content[1].length, 9);
	CU_ASSERT_STRING_EQUAL(decode.pco.pco_content[1].content,"111111111");
}

void test_decode_gtpv1_gsn_addr_ie(void)
{
	gtpv1_gsn_addr_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x85, 0x00, 0x04, 0xd4, 0x81, 0x41, 0x0d};

	CU_ASSERT(decode_gtpv1_gsn_address_ie(buf, &decode) == 7);
	CU_ASSERT(decode_gtpv1_gsn_address_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_gsn_address_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_gsn_address_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_GSN_ADDR);
	CU_ASSERT_EQUAL(decode.header.length, 4);
	CU_ASSERT_EQUAL(decode.gsn_address.ipv4, 3565240589);

	gtpv1_gsn_addr_ie_t decode1 = {0};
	uint8_t buf1[SIZE] = {0x85, 0x00, 0x10, 0x20, 0x01, 0xdb, 0x80, 0x33,
		0x33, 0x44, 0x44, 0x55, 0x55, 0x66, 0x66, 0x77, 0x77, 0x88,
		0x88 };

	CU_ASSERT(decode_gtpv1_gsn_address_ie(buf1, &decode1) == 19);
	CU_ASSERT(decode_gtpv1_gsn_address_ie(NULL, &decode1) == -1);
	CU_ASSERT(decode_gtpv1_gsn_address_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_gsn_address_ie(buf1, NULL) == -1);
	CU_ASSERT_EQUAL(decode1.header.type, GTPV1_IE_GSN_ADDR);
	CU_ASSERT_EQUAL(decode1.header.length, 16);
	char addr[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &decode1.gsn_address.ipv6, addr, INET6_ADDRSTRLEN);
	CU_ASSERT_NSTRING_EQUAL(addr, "2001:db80:3333:4444:5555:6666:7777:8888",39);
}

void test_decode_gtpv1_msisdn_ie(void)
{
	gtpv1_msisdn_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x86, 0x00, 0x02, 0x32, 0x32};

	CU_ASSERT(decode_gtpv1_msisdn_ie(buf, &decode) == 5);
	CU_ASSERT(decode_gtpv1_msisdn_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_msisdn_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_msisdn_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_MSISDN);
	CU_ASSERT_EQUAL(decode.header.length, 2);
	CU_ASSERT_STRING_EQUAL(decode.msisdn_number_digits,"22");
}

void test_decode_gtpv1_qos_ie(void)
{
	gtpv1_qos_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x87, 0x00, 0x15, 0x02, 0x12, 0x31, 0x04, 0x2a,
		0x03, 0x7b, 0xea, 0x11, 0x06, 0x7a, 0xde, 0x11, 0x16, 0x0b,
		0x21, 0x16, 0x2c, 0x21, 0x22, 0x17};

	CU_ASSERT(decode_gtpv1_qos_ie(buf, &decode) == 24);
	CU_ASSERT(decode_gtpv1_qos_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_qos_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_qos_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_QOS);
	CU_ASSERT_EQUAL(decode.header.length, 21);
	CU_ASSERT_EQUAL(decode.qos.allocation_retention_priority, 2);
	CU_ASSERT_EQUAL(decode.qos.spare1, 0);
	CU_ASSERT_EQUAL(decode.qos.delay_class, 2);
	CU_ASSERT_EQUAL(decode.qos.reliablity_class, 2);
	CU_ASSERT_EQUAL(decode.qos.peak_throughput, 3);
	CU_ASSERT_EQUAL(decode.qos.spare2, 0);
	CU_ASSERT_EQUAL(decode.qos.precedence_class, 1);
	CU_ASSERT_EQUAL(decode.qos.spare3, 0);
	CU_ASSERT_EQUAL(decode.qos.mean_throughput, 4);
	CU_ASSERT_EQUAL(decode.qos.traffic_class, 1);
	CU_ASSERT_EQUAL(decode.qos.delivery_order, 1);
	CU_ASSERT_EQUAL(decode.qos.delivery_erroneous_sdu, 2);
	CU_ASSERT_EQUAL(decode.qos.max_sdu_size, 3);
	CU_ASSERT_EQUAL(decode.qos.max_bitrate_uplink, 123);
	CU_ASSERT_EQUAL(decode.qos.max_bitrate_downlink, 234);
	CU_ASSERT_EQUAL(decode.qos.residual_ber, 1);
	CU_ASSERT_EQUAL(decode.qos.sdu_error_ratio, 1);
	CU_ASSERT_EQUAL(decode.qos.transfer_delay, 1);
	CU_ASSERT_EQUAL(decode.qos.traffic_handling_priority, 2);
	CU_ASSERT_EQUAL(decode.qos.guaranteed_bitrate_uplink, 122);
	CU_ASSERT_EQUAL(decode.qos.guaranteed_bitrate_downlink, 222);
	CU_ASSERT_EQUAL(decode.qos.spare4, 0);
	CU_ASSERT_EQUAL(decode.qos.signalling_indication, 1);
	CU_ASSERT_EQUAL(decode.qos.source_statistics_descriptor, 1);
	CU_ASSERT_EQUAL(decode.qos.max_bitrate_downlink_ext1, 22);
	CU_ASSERT_EQUAL(decode.qos.guaranteed_bitrate_downlink_ext1, 11);
	CU_ASSERT_EQUAL(decode.qos.max_bitrate_uplink_ext1, 33);
	CU_ASSERT_EQUAL(decode.qos.guaranteed_bitrate_uplink_ext1, 22);
	CU_ASSERT_EQUAL(decode.qos.max_bitrate_downlink_ext2, 44);
	CU_ASSERT_EQUAL(decode.qos.guaranteed_bitrate_downlink_ext2, 33);
	CU_ASSERT_EQUAL(decode.qos.max_bitrate_uplink_ext2, 34);
	CU_ASSERT_EQUAL(decode.qos.guaranteed_bitrate_uplink_ext2, 23);
}

void test_decode_gtpv1_traffic_flow_tmpl_ie(void)
{
	gtpv1_traffic_flow_tmpl_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x89, 0x00, 0x13, 0x32, 0x15, 0x01, 0x01, 0x01,
		0x25, 0x01, 0x02, 0x01, 0x00, 0x01, 0x02, 0x01, 0x02, 0x01,
		0x03, 0x03, 0x02, 0x00};

	CU_ASSERT(decode_gtpv1_traffic_flow_tmpl_ie(buf, &decode) == 22);
	CU_ASSERT(decode_gtpv1_traffic_flow_tmpl_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_traffic_flow_tmpl_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_traffic_flow_tmpl_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_TFT);
	CU_ASSERT_EQUAL(decode.header.length, 19);
	CU_ASSERT_EQUAL(decode.tft_op_code, 1);
	CU_ASSERT_EQUAL(decode.e_bit, 1);
	CU_ASSERT_EQUAL(decode.no_packet_filters, 2);
	CU_ASSERT_EQUAL(decode.packet_filter_list_new[0].spare, 0);
	CU_ASSERT_EQUAL(decode.packet_filter_list_new[0].filter_direction, 1);
	CU_ASSERT_EQUAL(decode.packet_filter_list_new[0].filter_id, 5);
	CU_ASSERT_EQUAL(decode.packet_filter_list_new[0].filter_eval_precedence, 1);
	CU_ASSERT_EQUAL(decode.packet_filter_list_new[0].filter_content_length, 1);
	CU_ASSERT_EQUAL(decode.packet_filter_list_new[0].filter_content[0], 1);
	CU_ASSERT_EQUAL(decode.packet_filter_list_new[1].spare, 0);
	CU_ASSERT_EQUAL(decode.packet_filter_list_new[1].filter_direction, 2);
	CU_ASSERT_EQUAL(decode.packet_filter_list_new[1].filter_id, 5);
	CU_ASSERT_EQUAL(decode.packet_filter_list_new[1].filter_eval_precedence, 1);
	CU_ASSERT_EQUAL(decode.packet_filter_list_new[1].filter_content_length, 2);
	CU_ASSERT_EQUAL(decode.packet_filter_list_new[1].filter_content[0], 1);
	CU_ASSERT_EQUAL(decode.packet_filter_list_new[1].filter_content[1], 0);
	CU_ASSERT_EQUAL(decode.parameters_list[0].parameter_id, 1);
	CU_ASSERT_EQUAL(decode.parameters_list[0].parameter_content_length, 2);
	CU_ASSERT_EQUAL(decode.parameters_list[0].parameter_content[0], 1);
	CU_ASSERT_EQUAL(decode.parameters_list[0].parameter_content[1], 2);
	CU_ASSERT_EQUAL(decode.parameters_list[1].parameter_id, 1);
	CU_ASSERT_EQUAL(decode.parameters_list[1].parameter_content_length, 3);
	CU_ASSERT_EQUAL(decode.parameters_list[1].parameter_content[0], 3);
	CU_ASSERT_EQUAL(decode.parameters_list[1].parameter_content[1], 2);
	CU_ASSERT_EQUAL(decode.parameters_list[1].parameter_content[2], 0);
}

void test_decode_gtpv1_trigger_id_ie(void)
{
	gtpv1_trigger_id_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x8e, 0x00, 0x05, 0x32, 0x32, 0x32, 0x32, 0x32};

	CU_ASSERT(decode_gtpv1_trigger_id_ie(buf, &decode) == 8);
	CU_ASSERT(decode_gtpv1_trigger_id_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_trigger_id_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_trigger_id_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_TRIGGER_ID);
	CU_ASSERT_EQUAL(decode.header.length, 5);
	CU_ASSERT_STRING_EQUAL(decode.trigger_id,"22222");
}

void test_decode_gtpv1_omc_identity_ie(void)
{
	gtpv1_omc_identity_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x8f, 0x00, 0x07, 0x61, 0x62, 0x63, 0x2e, 0x63,
		0x6f, 0x6d};

	CU_ASSERT(decode_gtpv1_omc_identity_ie(buf, &decode) == 10);
	CU_ASSERT(decode_gtpv1_omc_identity_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_omc_identity_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_omc_identity_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_OMC_IDENTITY);
	CU_ASSERT_EQUAL(decode.header.length, 7);
	CU_ASSERT_STRING_EQUAL(decode.omc_identity,"abc.com");
}

void test_decode_gtpv1_common_flag_ie(void)
{
	gtpv1_common_flag_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x94, 0x00, 0x01, 0xff};

	CU_ASSERT(decode_gtpv1_common_flag_ie(buf, &decode) == 4);
	CU_ASSERT(decode_gtpv1_common_flag_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_common_flag_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_common_flag_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_COMMON_FLAG);
	CU_ASSERT_EQUAL(decode.header.length, 1);
	CU_ASSERT_EQUAL(decode.dual_addr_bearer_flag, 1);
	CU_ASSERT_EQUAL(decode.upgrade_qos_supported, 1);
	CU_ASSERT_EQUAL(decode.nrsn, 1);
	CU_ASSERT_EQUAL(decode.no_qos_negotiation, 1);
	CU_ASSERT_EQUAL(decode.mbms_counting_information, 1);
	CU_ASSERT_EQUAL(decode.ran_procedures_ready, 1);
	CU_ASSERT_EQUAL(decode.mbms_service_type, 1);
	CU_ASSERT_EQUAL(decode.prohibit_payload_compression, 1);
}

void test_decode_gtpv1_apn_restriction_ie(void)
{
	gtpv1_apn_restriction_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x95, 0x00, 0x01, 0x0c};

	CU_ASSERT(decode_gtpv1_apn_restriction_ie(buf, &decode) == 4);
	CU_ASSERT(decode_gtpv1_apn_restriction_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_apn_restriction_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_apn_restriction_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_APN_RESTRICTION);
	CU_ASSERT_EQUAL(decode.header.length, 1);
	CU_ASSERT_EQUAL(decode.restriction_type_value, 12);
}

void test_decode_gtpv1_rat_type_ie(void)
{
	gtpv1_rat_type_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x97, 0x00 ,0x01, 0x02} ;
	
	CU_ASSERT(decode_gtpv1_rat_type_ie(buf, &decode) == 4);
	CU_ASSERT(decode_gtpv1_rat_type_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_rat_type_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_rat_type_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_RAT_TYPE);
	CU_ASSERT_EQUAL(decode.header.length, 1);
	CU_ASSERT_EQUAL(decode.rat_type, 2);
}

void test_decode_gtpv1_user_location_information_ie(void)
{
	gtpv1_user_location_information_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x98, 0x00, 0x08, 0x01, 0x63, 0xf8, 0x94, 0x00, 0x01, 0x00, 0x01};

	CU_ASSERT(decode_gtpv1_user_location_information_ie(buf, &decode) == 11);
	CU_ASSERT(decode_gtpv1_user_location_information_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_user_location_information_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_user_location_information_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_USER_LOCATION_INFORMATION);
	CU_ASSERT_EQUAL(decode.header.length, 8);
	CU_ASSERT_EQUAL(decode.geographic_location_type, 1);
	CU_ASSERT_EQUAL(decode.mcc_digit_2, 6);
	CU_ASSERT_EQUAL(decode.mcc_digit_1, 3);
	CU_ASSERT_EQUAL(decode.mnc_digit_3, 9);
	CU_ASSERT_EQUAL(decode.mcc_digit_3, 8);
	CU_ASSERT_EQUAL(decode.mnc_digit_2, 4);
	CU_ASSERT_EQUAL(decode.mnc_digit_1, 0);
	CU_ASSERT_EQUAL(decode.lac, 1);
	CU_ASSERT_EQUAL(decode.ci_sac_rac, 1);
	
	gtpv1_user_location_information_ie_t decode_1 = {0};
	uint8_t buf_1[SIZE] = {0x98, 0x00, 0x08, 0x01, 0x63, 0x98, 0x41, 0x00, 0x01, 0x00, 0x01};

	CU_ASSERT(decode_gtpv1_user_location_information_ie(buf_1, &decode_1) == 11);
	CU_ASSERT_EQUAL(decode_1.header.type, GTPV1_IE_USER_LOCATION_INFORMATION);
	CU_ASSERT_EQUAL(decode_1.header.length, 8);
	CU_ASSERT_EQUAL(decode_1.geographic_location_type, 1);
	CU_ASSERT_EQUAL(decode_1.mcc_digit_2, 6);
	CU_ASSERT_EQUAL(decode_1.mcc_digit_1, 3);
	CU_ASSERT_EQUAL(decode_1.mnc_digit_3, 9);
	CU_ASSERT_EQUAL(decode_1.mcc_digit_3, 8);
	CU_ASSERT_EQUAL(decode_1.mnc_digit_2, 4);
	CU_ASSERT_EQUAL(decode_1.mnc_digit_1, 1);
	CU_ASSERT_EQUAL(decode_1.lac, 1);
	CU_ASSERT_EQUAL(decode_1.ci_sac_rac, 1);
}

void test_decode_gtpv1_ms_time_zone_ie(void)
{
	gtpv1_ms_time_zone_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x99, 0x00, 0x02, 0x01, 0x01};

	CU_ASSERT(decode_gtpv1_ms_time_zone_ie(buf, &decode) == 5);
	CU_ASSERT(decode_gtpv1_ms_time_zone_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_ms_time_zone_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_ms_time_zone_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_MS_TIME_ZONE);
	CU_ASSERT_EQUAL(decode.header.length, 2);
	CU_ASSERT_EQUAL(decode.time_zone, 1);
	CU_ASSERT_EQUAL(decode.spare, 0);
	CU_ASSERT_EQUAL(decode.daylight_saving_time, 1);
}

void test_decode_gtpv1_imei_ie(void)
{
	gtpv1_imei_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x9a, 0x00, 0x08, 0x11, 0x11, 0x11, 0x11, 0x22,
		0x22, 0x22, 0x11};

	CU_ASSERT(decode_gtpv1_imei_ie(buf, &decode) == 11);
	CU_ASSERT(decode_gtpv1_imei_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_imei_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_imei_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_IMEI_SV);
	CU_ASSERT_EQUAL(decode.header.length, 8);
	CU_ASSERT_EQUAL(decode.imei_sv, 0b0001000100010001000100010001000100100010001000100010001000010001);
}

void test_decode_gtpv1_camel_charging_information_container_ie(void)
{
	gtpv1_camel_charging_information_container_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x9b, 0x00, 0x02, 0x31, 0x31};

	CU_ASSERT(decode_gtpv1_camel_charging_information_container_ie(buf, &decode) == 5);
	CU_ASSERT(decode_gtpv1_camel_charging_information_container_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_camel_charging_information_container_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_camel_charging_information_container_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_CAMEL_CHARGING_INFORMATION_CONTAINER);
	CU_ASSERT_EQUAL(decode.header.length, 2);
	CU_ASSERT_STRING_EQUAL(decode.camel_information_pdp_ie, "11");
}

void test_decode_gtpv1_additional_trace_information_ie(void)
{
	gtpv1_additional_trace_information_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xa2, 0x00, 0x09, 0x00, 0x00, 0x01, 0x00, 0x01,
		0x01, 0x01, 0x01, 0x01};

	CU_ASSERT(decode_gtpv1_additional_trace_information_ie(buf, &decode) == 12);
	CU_ASSERT(decode_gtpv1_additional_trace_information_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_additional_trace_information_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_additional_trace_information_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_ADDITIONAL_TRACE_INFORMATION);
	CU_ASSERT_EQUAL(decode.header.length, 9);
	CU_ASSERT_EQUAL(decode.trace_reference_2, 1);
	CU_ASSERT_EQUAL(decode.trace_recording_session_reference, 1);
	CU_ASSERT_EQUAL(decode.spare1, 0);
	CU_ASSERT_EQUAL(decode.triggering_events_in_ggsn_mbms_ctxt, 0);
	CU_ASSERT_EQUAL(decode.triggering_events_in_ggsn_pdp_ctxt, 1);
	CU_ASSERT_EQUAL(decode.trace_depth, 1);
	CU_ASSERT_EQUAL(decode.spare2, 0);
	CU_ASSERT_EQUAL(decode.list_of_interfaces_in_ggsn_gmb, 0);
	CU_ASSERT_EQUAL(decode.list_of_interfaces_in_ggsn_gi, 0);
	CU_ASSERT_EQUAL(decode.list_of_interfaces_in_ggsn_gn, 1);
	CU_ASSERT_EQUAL(decode.trace_activity_control, 1);
}

void test_decode_gtpv1_ms_info_change_reporting_action_ie(void)
{
	gtpv1_ms_info_change_reporting_action_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xb5, 0x00, 0x01, 0x01};
	
	CU_ASSERT(decode_gtpv1_ms_info_change_reporting_action_ie(buf, &decode) == 4);
	CU_ASSERT(decode_gtpv1_ms_info_change_reporting_action_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_ms_info_change_reporting_action_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_ms_info_change_reporting_action_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_MS_INFO_CHANGE_REPORTING_ACTION);
	CU_ASSERT_EQUAL(decode.header.length, 1);
	CU_ASSERT_EQUAL(decode.action, 1);
}

void test_decode_gtpv1_direct_tunnel_flag_ie(void)
{
	gtpv1_direct_tunnel_flag_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xb6, 0x00, 0x01, 0x07};

	CU_ASSERT(decode_gtpv1_direct_tunnel_flag_ie(buf, &decode) == 4);
	CU_ASSERT(decode_gtpv1_direct_tunnel_flag_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_direct_tunnel_flag_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_direct_tunnel_flag_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_DIRECT_TUNNEL_FLAG);
	CU_ASSERT_EQUAL(decode.header.length, 1);
	CU_ASSERT_EQUAL(decode.spare, 0);
	CU_ASSERT_EQUAL(decode.ei, 1);
	CU_ASSERT_EQUAL(decode.gcsi, 1);
	CU_ASSERT_EQUAL(decode.dti, 1);
}

void test_decode_gtpv1_correlation_id_ie(void)
{
	gtpv1_correlation_id_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xb7, 0x00, 0x01, 0x05};

	CU_ASSERT(decode_gtpv1_correlation_id_ie(buf, &decode) == 4);
	CU_ASSERT(decode_gtpv1_correlation_id_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_correlation_id_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_correlation_id_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_CORRELATION_ID);
	CU_ASSERT_EQUAL(decode.header.length, 1);
	CU_ASSERT_EQUAL(decode.correlation_id, 5);
}

void test_decode_gtpv1_bearer_control_mode_ie(void)
{
	gtpv1_bearer_control_mode_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xb8, 0x00, 0x01, 0x01};

	CU_ASSERT(decode_gtpv1_bearer_control_mode_ie(buf, &decode) == 4);
	CU_ASSERT(decode_gtpv1_bearer_control_mode_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_bearer_control_mode_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_bearer_control_mode_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_BEARER_CONTROL_MODE);
	CU_ASSERT_EQUAL(decode.header.length, 1);
	CU_ASSERT_EQUAL(decode.bearer_control_mode, 1);
}

void test_decode_gtpv1_evolved_allocation_retention_priority_1_ie(void)
{
	gtpv1_evolved_allocation_retention_priority_1_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xbf, 0x00, 0x01, 0x71};
	
	CU_ASSERT(decode_gtpv1_evolved_allocation_retention_priority_1_ie(buf, &decode) == 4);
	CU_ASSERT(decode_gtpv1_evolved_allocation_retention_priority_1_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_evolved_allocation_retention_priority_1_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_evolved_allocation_retention_priority_1_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_I);
	CU_ASSERT_EQUAL(decode.header.length, 1);
	CU_ASSERT_EQUAL(decode.spare, 0);
	CU_ASSERT_EQUAL(decode.pci, 1);
	CU_ASSERT_EQUAL(decode.pl, 12);
	CU_ASSERT_EQUAL(decode.spare2, 0);
	CU_ASSERT_EQUAL(decode.pvi, 1);
}

void test_decode_gtpv1_extended_common_flag_ie(void)
{
	gtpv1_extended_common_flag_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xc1, 0x00, 0x01, 0xff};

	CU_ASSERT(decode_gtpv1_extended_common_flag_ie(buf, &decode) == 4);
	CU_ASSERT(decode_gtpv1_extended_common_flag_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_extended_common_flag_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_extended_common_flag_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_EXTENDED_COMMON_FLAG);
	CU_ASSERT_EQUAL(decode.header.length, 1);
	CU_ASSERT_EQUAL(decode.uasi, 1);
	CU_ASSERT_EQUAL(decode.bdwi, 1);
	CU_ASSERT_EQUAL(decode.pcri, 1);
	CU_ASSERT_EQUAL(decode.vb, 1);
	CU_ASSERT_EQUAL(decode.retloc, 1);
	CU_ASSERT_EQUAL(decode.cpsr, 1);
	CU_ASSERT_EQUAL(decode.ccrsi, 1);
}

void test_decode_gtpv1_user_csg_information_ie(void)
{
	gtpv1_user_csg_information_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xc2, 0x00, 0x08, 0x51, 0xf1, 0x83, 0x01, 0x00, 0x00, 0x01, 0x41};

	CU_ASSERT(decode_gtpv1_user_csg_information_ie(buf, &decode) == 11);
	CU_ASSERT(decode_gtpv1_user_csg_information_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_user_csg_information_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_user_csg_information_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_USER_CSG_INFORMATION);
	CU_ASSERT_EQUAL(decode.header.length, 8);
	CU_ASSERT_EQUAL(decode.mcc_digit_2, 5);
	CU_ASSERT_EQUAL(decode.mcc_digit_1, 1);
	CU_ASSERT_EQUAL(decode.mnc_digit_3, 8);
	CU_ASSERT_EQUAL(decode.mcc_digit_3, 1);
	CU_ASSERT_EQUAL(decode.mnc_digit_2, 3);
	CU_ASSERT_EQUAL(decode.mnc_digit_1, 0);
	CU_ASSERT_EQUAL(decode.spare, 0);
	CU_ASSERT_EQUAL(decode.csg_id, 1);
	CU_ASSERT_EQUAL(decode.csg_id_II, 1);
	CU_ASSERT_EQUAL(decode.access_mode, 1);
	CU_ASSERT_EQUAL(decode.spare2, 0);
	CU_ASSERT_EQUAL(decode.cmi, 1);
	
	gtpv1_user_csg_information_ie_t decode_1 = {0};
	uint8_t buf_1[SIZE] = {0xc2, 0x00, 0x08, 0x51, 0x81, 0x31, 0x01, 0x00, 0x00, 0x01, 0x41};

	CU_ASSERT(decode_gtpv1_user_csg_information_ie(buf_1, &decode_1) == 11);
	CU_ASSERT_EQUAL(decode_1.header.type, GTPV1_IE_USER_CSG_INFORMATION);
	CU_ASSERT_EQUAL(decode_1.header.length, 8);
	CU_ASSERT_EQUAL(decode_1.mcc_digit_2, 5);
	CU_ASSERT_EQUAL(decode_1.mcc_digit_1, 1);
	CU_ASSERT_EQUAL(decode_1.mnc_digit_3, 8);
	CU_ASSERT_EQUAL(decode_1.mcc_digit_3, 1);
	CU_ASSERT_EQUAL(decode_1.mnc_digit_2, 3);
	CU_ASSERT_EQUAL(decode_1.mnc_digit_1, 1);
	CU_ASSERT_EQUAL(decode_1.spare, 0);
	CU_ASSERT_EQUAL(decode_1.csg_id, 1);
	CU_ASSERT_EQUAL(decode_1.csg_id_II, 1);
	CU_ASSERT_EQUAL(decode_1.access_mode, 1);
	CU_ASSERT_EQUAL(decode_1.spare2, 0);
	CU_ASSERT_EQUAL(decode_1.cmi, 1);

}

void test_decode_gtpv1_csg_information_reporting_action_ie(void)
{
	gtpv1_csg_information_reporting_action_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xc3, 0x00, 0x01, 0x07};

	CU_ASSERT(decode_gtpv1_csg_information_reporting_action_ie(buf, &decode) == 4);
	CU_ASSERT(decode_gtpv1_csg_information_reporting_action_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_csg_information_reporting_action_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_csg_information_reporting_action_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_CSG_INFORMATION_REPORTING_ACTION);
	CU_ASSERT_EQUAL(decode.header.length, 1);
	CU_ASSERT_EQUAL(decode.spare, 0);
	CU_ASSERT_EQUAL(decode.ucuhc, 1);
	CU_ASSERT_EQUAL(decode.ucshc, 1);
	CU_ASSERT_EQUAL(decode.uccsg, 1);
}

void test_decode_gtpv1_apn_ambr_ie(void)
{
	gtpv1_apn_ambr_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xc6, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x07};

	CU_ASSERT(decode_gtpv1_apn_ambr_ie(buf, &decode) == 11);
	CU_ASSERT(decode_gtpv1_apn_ambr_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_apn_ambr_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_apn_ambr_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_APN_AMBR);
	CU_ASSERT_EQUAL(decode.header.length, 8);
	CU_ASSERT_EQUAL(decode.apn_ambr_uplink, 0);
	CU_ASSERT_EQUAL(decode.apn_ambr_downlink, 7);
}

void test_decode_gtpv1_ggsn_back_off_time_ie(void)
{
	gtpv1_ggsn_back_off_time_ie_t decode = {0};
	uint8_t buf[SIZE]  = {0xca, 0x00, 0x01, 0x08};

	CU_ASSERT(decode_gtpv1_ggsn_back_off_time_ie(buf, &decode) == 4);
	CU_ASSERT(decode_gtpv1_ggsn_back_off_time_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_ggsn_back_off_time_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_ggsn_back_off_time_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_GGSN_BACK_OFF_TIME);
	CU_ASSERT_EQUAL(decode.header.length, 1);
	CU_ASSERT_EQUAL(decode.timer_unit, 0);
	CU_ASSERT_EQUAL(decode.timer_value, 8);
} 

void test_decode_gtpv1_signalling_priority_indication_ie(void)
{
	gtpv1_signalling_priority_indication_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xcb, 0x00, 0x01, 0x01};

	CU_ASSERT(decode_gtpv1_signalling_priority_indication_ie(buf, &decode) == 4);
	CU_ASSERT(decode_gtpv1_signalling_priority_indication_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_signalling_priority_indication_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_signalling_priority_indication_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_SIGNALLING_PRIORITY_INDICATION);
	CU_ASSERT_EQUAL(decode.header.length, 1);
	CU_ASSERT_EQUAL(decode.spare, 0);
	CU_ASSERT_EQUAL(decode.lapi, 1);
}

void test_decode_gtpv1_uli_timestamp_ie(void)
{
	gtpv1_uli_timestamp_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xd6, 0x00, 0x04, 0x00, 0x00, 0x00, 0x20};

	CU_ASSERT(decode_gtpv1_uli_timestamp_ie(buf, &decode) == 7);
	CU_ASSERT(decode_gtpv1_uli_timestamp_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_uli_timestamp_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_uli_timestamp_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_ULI_TIMESTAMP);
	CU_ASSERT_EQUAL(decode.header.length, 4);
	CU_ASSERT_EQUAL(decode.timestamp_value, 32);
}

void test_decode_gtpv1_cn_operator_selection_entity_ie(void)
{
	gtpv1_cn_operator_selection_entity_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xd8, 0x00, 0x01, 0x01};

	CU_ASSERT(decode_gtpv1_cn_operator_selection_entity_ie(buf, &decode) == 4);
	CU_ASSERT(decode_gtpv1_cn_operator_selection_entity_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_cn_operator_selection_entity_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_cn_operator_selection_entity_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_CN_OPERATOR_SELECTION_ENTITY);
	CU_ASSERT_EQUAL(decode.header.length, 1);
	CU_ASSERT_EQUAL(decode.spare, 0);
	CU_ASSERT_EQUAL(decode.selection_entity, 1);
}

void test_decode_gtpv1_extended_common_flags_2_ie(void)
{
	gtpv1_extended_common_flag_2_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xda, 0x00, 0x01, 0x07};
	
	CU_ASSERT(decode_gtpv1_extended_common_flag_2_ie(buf, &decode) == 4);
	CU_ASSERT(decode_gtpv1_extended_common_flag_2_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_extended_common_flag_2_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_extended_common_flag_2_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_EXTENDED_COMMON_FLAGS_II);
	CU_ASSERT_EQUAL(decode.header.length, 1);
	CU_ASSERT_EQUAL(decode.spare, 0);
	CU_ASSERT_EQUAL(decode.pmts_mi, 1);
	CU_ASSERT_EQUAL(decode.dtci, 1);
	CU_ASSERT_EQUAL(decode.pnsi, 1);
}

void test_decode_gtpv1_mapped_ue_usage_type_ie(void)
{
	gtpv1_mapped_ue_usage_type_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xdf, 0x00, 0x03, 0x00, 0x01};

	CU_ASSERT(decode_gtpv1_mapped_ue_usage_type_ie(buf, &decode) == 5);
	CU_ASSERT(decode_gtpv1_mapped_ue_usage_type_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_mapped_ue_usage_type_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_mapped_ue_usage_type_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_MAPPED_UE_USAGE_TYPE);
	CU_ASSERT_EQUAL(decode.header.length, 3);
	CU_ASSERT_EQUAL(decode.mapped_ue_usage_type, 1);
}

void test_decode_gtpv1_up_function_selection_indication_ie(void)
{
	gtpv1_up_function_selection_indication_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xe0, 0x00, 0x01, 0x01};

	CU_ASSERT(decode_gtpv1_up_function_selection_indication_ie(buf, &decode) == 4);
	CU_ASSERT(decode_gtpv1_up_function_selection_indication_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_up_function_selection_indication_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_up_function_selection_indication_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_UP_FUNCTION_SELECTION_INDICATION);
	CU_ASSERT_EQUAL(decode.header.length, 1);
	CU_ASSERT_EQUAL(decode.spare, 0);
	CU_ASSERT_EQUAL(decode.dcnr, 1);
}

void test_decode_gtpv1_charging_gateway_addr_ie(void)
{
	gtpv1_charging_gateway_addr_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xfb, 0x00, 0x04, 0xc0, 0xa8, 0x00, 0x2c};

	CU_ASSERT(decode_gtpv1_charging_gateway_addr_ie(buf, &decode) == 7);
	CU_ASSERT(decode_gtpv1_charging_gateway_addr_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_charging_gateway_addr_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_charging_gateway_addr_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_CHARGING_GATEWAY_ADDR);
	CU_ASSERT_EQUAL(decode.header.length, 4);
	CU_ASSERT_EQUAL(decode.ipv4_addr, 3232235564);
}

void test_decode_gtpv1_private_extension_ie(void)
{
	gtpv1_private_extension_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xff, 0x00, 0x04, 0x00, 0x0c, 0x31, 0x31};
	
	CU_ASSERT(decode_gtpv1_private_extension_ie(buf, &decode) == 7);
	CU_ASSERT(decode_gtpv1_private_extension_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_private_extension_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_private_extension_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_PRIVATE_EXTENSION);
	CU_ASSERT_EQUAL(decode.header.length, 4);
	CU_ASSERT_EQUAL(decode.extension_identifier, 12);
	CU_ASSERT_STRING_EQUAL(decode.extension_value, "11");
}

void test_decode_gtpv1_map_cause_ie(void)
{
	gtpv1_map_cause_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x0b, 0x01};

	CU_ASSERT(decode_gtpv1_map_cause_ie(buf, &decode) == 2);
	CU_ASSERT(decode_gtpv1_map_cause_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_map_cause_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_map_cause_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_MAP_CAUSE);
	CU_ASSERT_EQUAL(decode.map_cause_value, 1);
}

void test_decode_gtpv1_ms_not_rechable_reason_ie(void)
{
	gtpv1_ms_not_rechable_reason_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x1d, 0x02};

	CU_ASSERT(decode_gtpv1_ms_not_rechable_reason_ie(buf, &decode) == 2);
	CU_ASSERT(decode_gtpv1_ms_not_rechable_reason_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_ms_not_rechable_reason_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_ms_not_rechable_reason_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_MS_NOT_RECHABLE_REASON);
	CU_ASSERT_EQUAL(decode.reason_for_absence, 2);
}


void test_decode_gtpv1_temporary_logical_link_identifier_ie(void)
{
	gtpv1_temporary_logical_link_identifier_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x04, 0x00, 0x00, 0x00, 0x01};

	CU_ASSERT(decode_gtpv1_temporary_logical_link_identifier_ie(buf, &decode) == 5);
	CU_ASSERT(decode_gtpv1_temporary_logical_link_identifier_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_temporary_logical_link_identifier_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_temporary_logical_link_identifier_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_TEMPORARY_LOGICAL_LINK_IDENTIFIER);
	CU_ASSERT_EQUAL(decode.tlli, 1);
}

void test_decode_gtpv1_packet_tmsi_ie(void)
{
	gtpv1_packet_tmsi_ie_t decode ={0};
	uint8_t buf[SIZE] = {0x05, 0x00, 0x00, 0x00, 0x01};

	CU_ASSERT(decode_gtpv1_packet_tmsi_ie(buf, &decode) == 5);
	CU_ASSERT(decode_gtpv1_packet_tmsi_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_packet_tmsi_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_packet_tmsi_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_PACKET_TMSI);
	CU_ASSERT_EQUAL(decode.p_tmsi, 1);
}

void test_decode_gtpv1_p_tmsi_signature_ie(void)
{
	gtpv1_p_tmsi_signature_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x0c, 0x00, 0x00, 0x01};

	CU_ASSERT(decode_gtpv1_p_tmsi_signature_ie(buf, &decode) == 4);
	CU_ASSERT(decode_gtpv1_p_tmsi_signature_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_p_tmsi_signature_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_p_tmsi_signature_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_P_TMSI_SIGNATURE);
	CU_ASSERT_EQUAL(decode.p_tmsi_signature, 1);
}

void test_decode_gtpv1_ms_validated_ie(void)
{
	gtpv1_ms_validated_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x0d, 0x01};

	CU_ASSERT(decode_gtpv1_ms_validated_ie(buf, &decode) == 2);
	CU_ASSERT(decode_gtpv1_ms_validated_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_ms_validated_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_ms_validated_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_MS_VALIDATED);
	CU_ASSERT_EQUAL(decode.spare, 0);
	CU_ASSERT_EQUAL(decode.ms_validated, 1);
}

void test_decode_gtpv1_sgsn_number_ie(void)
{
	gtpv1_sgsn_number_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x93, 0x00, 0x02, 0x31, 0x31};

	CU_ASSERT(decode_gtpv1_sgsn_number_ie(buf, &decode) == 5);
	CU_ASSERT(decode_gtpv1_sgsn_number_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_sgsn_number_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_sgsn_number_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_SGSN_NUMBER);
	CU_ASSERT_EQUAL(decode.header.length, 2);
	CU_ASSERT_STRING_EQUAL(decode.sgsn_number,"11");
}

void test_decode_gtpv1_hop_counter_ie(void)
{
	gtpv1_hop_counter_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xa3, 0x00, 0x01, 0x01};

	CU_ASSERT(decode_gtpv1_hop_counter_ie(buf, &decode) == 4);
	CU_ASSERT(decode_gtpv1_hop_counter_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_hop_counter_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_hop_counter_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_HOP_COUNTER);
	CU_ASSERT_EQUAL(decode.header.length, 1);
	CU_ASSERT_EQUAL(decode.hop_counter, 1);
}

void test_decode_gtpv1_rab_context_ie(void)
{
	gtpv1_rab_context_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x16, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01,
		0x00, 0x01};

	CU_ASSERT(decode_gtpv1_rab_context_ie(buf, &decode) == 10);
	CU_ASSERT(decode_gtpv1_rab_context_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_rab_context_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_rab_context_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_RAB_CONTEXT);
	CU_ASSERT_EQUAL(decode.spare, 0);
	CU_ASSERT_EQUAL(decode.nsapi, 1);
	CU_ASSERT_EQUAL(decode.dl_gtp_u_sequence_number, 1);
	CU_ASSERT_EQUAL(decode.ul_gtp_u_sequence_number, 1);
	CU_ASSERT_EQUAL(decode.dl_pdcp_sequence_number, 1);
	CU_ASSERT_EQUAL(decode.ul_pdcp_sequence_number, 1);
}

void test_decode_gtpv1_radio_priority_sms_ie(void)
{
	gtpv1_radio_priority_sms_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x17, 0x01};

	CU_ASSERT(decode_gtpv1_radio_priority_sms_ie(buf, &decode) == 2);
	CU_ASSERT(decode_gtpv1_radio_priority_sms_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_radio_priority_sms_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_radio_priority_sms_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_RADIO_PRIORITY_SMS);
	CU_ASSERT_EQUAL(decode.spare, 0);
	CU_ASSERT_EQUAL(decode.radio_priority_sms, 1);
}

void test_decode_gtpv1_radio_priority_ie(void)
{
	gtpv1_radio_priority_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x18, 0x11};

	CU_ASSERT(decode_gtpv1_radio_priority_ie(buf, &decode) == 2);
	CU_ASSERT(decode_gtpv1_radio_priority_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_radio_priority_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_radio_priority_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_RADIO_PRIORITY);
	CU_ASSERT_EQUAL(decode.nsapi, 1);
	CU_ASSERT_EQUAL(decode.spare, 0);
	CU_ASSERT_EQUAL(decode.radio_priority, 1);
}

void test_decode_gtpv1_packet_flow_id_ie(void)
{
	gtpv1_packet_flow_id_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x19, 0x01, 0x01};

	CU_ASSERT(decode_gtpv1_packet_flow_id_ie(buf, &decode) == 3);
	CU_ASSERT(decode_gtpv1_packet_flow_id_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_packet_flow_id_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_packet_flow_id_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_PACKET_FLOW_ID);
	CU_ASSERT_EQUAL(decode.spare, 0);
	CU_ASSERT_EQUAL(decode.nsapi, 1);
	CU_ASSERT_EQUAL(decode.packet_flow_id, 1);
}

void test_decode_gtpv1_radio_priority_lcs_ie(void)
{
	gtpv1_radio_priority_lcs_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x96, 0x00, 0x01, 0x01};

	CU_ASSERT(decode_gtpv1_radio_priority_lcs_ie(buf, &decode) == 4);
	CU_ASSERT(decode_gtpv1_radio_priority_lcs_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_radio_priority_lcs_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_radio_priority_lcs_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_RADIO_PRIORITY_LCS);
	CU_ASSERT_EQUAL(decode.header.length, 1);
	CU_ASSERT_EQUAL(decode.spare, 0);
	CU_ASSERT_EQUAL(decode.radio_priority_lcs, 1);
}

void test_decode_gtpv1_pdp_context_prioritization_ie(void)
{
	gtpv1_pdp_context_prioritization_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x91, 0x00, 0x00};

	CU_ASSERT(decode_gtpv1_pdp_context_prioritization_ie(buf, &decode) == 3);
	CU_ASSERT(decode_gtpv1_pdp_context_prioritization_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_pdp_context_prioritization_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_pdp_context_prioritization_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_PDP_CONTEXT_PRIORITIZATION);
}

void test_decode_gtpv1_rfsp_index_ie(void)
{
	gtpv1_rfsp_index_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xbd, 0x00, 0x02, 0x00, 0x01};

	CU_ASSERT(decode_gtpv1_rfsp_index_ie(buf, &decode) == 5);
	CU_ASSERT(decode_gtpv1_rfsp_index_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_rfsp_index_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_rfsp_index_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_RFSP_INDEX);
	CU_ASSERT_EQUAL(decode.header.length, 2);
	CU_ASSERT_EQUAL(decode.rfsp_index, 1);
}

void test_decode_gtpv1_fqdn_ie(void)
{
	gtpv1_fqdn_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xbe, 0x00, 0x05, 0x67, 0x73, 0x6c,0x61, 0x62};

	CU_ASSERT(decode_gtpv1_fqdn_ie(buf, &decode) == 8);
	CU_ASSERT(decode_gtpv1_fqdn_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_fqdn_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_fqdn_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_FQDN);
	CU_ASSERT_EQUAL(decode.header.length, 5);
	CU_ASSERT_STRING_EQUAL(decode.fqdn,"gslab");
}

void test_decode_gtpv1_evolved_allocation_retention_priority_II_ie(void)
{
	gtpv1_evolved_allocation_retention_priority_II_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xc0, 0x00, 0x02, 0x01, 0x45};

	CU_ASSERT(decode_gtpv1_evolved_allocation_retention_priority_II_ie(buf, &decode) == 5);
	CU_ASSERT(decode_gtpv1_evolved_allocation_retention_priority_II_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_evolved_allocation_retention_priority_II_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_evolved_allocation_retention_priority_II_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_II);
	CU_ASSERT_EQUAL(decode.header.length, 2);
	CU_ASSERT_EQUAL(decode.spare, 0);
	CU_ASSERT_EQUAL(decode.nsapi, 1);
	CU_ASSERT_EQUAL(decode.spare2, 0);
	CU_ASSERT_EQUAL(decode.pci, 1);
	CU_ASSERT_EQUAL(decode.pl, 1);
	CU_ASSERT_EQUAL(decode.spare3, 0);
	CU_ASSERT_EQUAL(decode.pvi, 1);
}

void test_decode_gtpv1_ue_network_capability_ie(void)
{
	gtpv1_ue_network_capability_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xc7, 0x00, 0x08, 0xd6, 0xab, 0x55, 0xb5, 0xb6,
		0xbb, 0x52, 0x13};

	CU_ASSERT(decode_gtpv1_ue_network_capability_ie(buf, &decode) == 11);
	CU_ASSERT(decode_gtpv1_ue_network_capability_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_ue_network_capability_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_ue_network_capability_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_UE_NETWORK_CAPABILITY);
	CU_ASSERT_EQUAL(decode.header.length, 8);
	CU_ASSERT_EQUAL(decode.eea0, 1);
	CU_ASSERT_EQUAL(decode.eea1_128, 1);
	CU_ASSERT_EQUAL(decode.eea2_128, 0);
	CU_ASSERT_EQUAL(decode.eea3_128, 1);
	CU_ASSERT_EQUAL(decode.eea4, 0);
	CU_ASSERT_EQUAL(decode.eea5, 1);
	CU_ASSERT_EQUAL(decode.eea6, 1);
	CU_ASSERT_EQUAL(decode.eea7, 0);
	CU_ASSERT_EQUAL(decode.eia0, 1);
	CU_ASSERT_EQUAL(decode.eia1_128, 0);
	CU_ASSERT_EQUAL(decode.eia2_128, 1);
	CU_ASSERT_EQUAL(decode.eia3_128, 0);
	CU_ASSERT_EQUAL(decode.eia4, 1);
	CU_ASSERT_EQUAL(decode.eia5, 0);
	CU_ASSERT_EQUAL(decode.eia6, 1);
	CU_ASSERT_EQUAL(decode.eia7, 1);
	CU_ASSERT_EQUAL(decode.uea0, 0);
	CU_ASSERT_EQUAL(decode.uea1, 1);
	CU_ASSERT_EQUAL(decode.uea2, 0);
	CU_ASSERT_EQUAL(decode.uea3, 1);
	CU_ASSERT_EQUAL(decode.uea4, 0);
	CU_ASSERT_EQUAL(decode.uea5, 1);
	CU_ASSERT_EQUAL(decode.uea6, 0);
	CU_ASSERT_EQUAL(decode.uea7, 1);
	CU_ASSERT_EQUAL(decode.ucs2, 1);
	CU_ASSERT_EQUAL(decode.uia1, 0);
	CU_ASSERT_EQUAL(decode.uia2, 1);
	CU_ASSERT_EQUAL(decode.uia3, 1);
	CU_ASSERT_EQUAL(decode.uia4, 0);
	CU_ASSERT_EQUAL(decode.uia5, 1);
	CU_ASSERT_EQUAL(decode.uia6, 0);
	CU_ASSERT_EQUAL(decode.uia7, 1);
	CU_ASSERT_EQUAL(decode.prose_dd, 1);
	CU_ASSERT_EQUAL(decode.prose, 0);
	CU_ASSERT_EQUAL(decode.h245_ash, 1);
	CU_ASSERT_EQUAL(decode.acc_csfb, 1);
	CU_ASSERT_EQUAL(decode.lpp, 0);
	CU_ASSERT_EQUAL(decode.lcs, 1);
	CU_ASSERT_EQUAL(decode.srvcc1x, 1);
	CU_ASSERT_EQUAL(decode.nf, 0);
	CU_ASSERT_EQUAL(decode.epco, 1);
	CU_ASSERT_EQUAL(decode.hc_cp_ciot, 0);
	CU_ASSERT_EQUAL(decode.erw_opdn, 1);
	CU_ASSERT_EQUAL(decode.s1_udata, 1);
	CU_ASSERT_EQUAL(decode.up_ciot, 1);
	CU_ASSERT_EQUAL(decode.cp_ciot, 0);
	CU_ASSERT_EQUAL(decode.prose_relay, 1);
	CU_ASSERT_EQUAL(decode.prose_dc, 1);
	CU_ASSERT_EQUAL(decode.bearers_15, 0);
	CU_ASSERT_EQUAL(decode.sgc, 1);
	CU_ASSERT_EQUAL(decode.n1mode, 0);
	CU_ASSERT_EQUAL(decode.dcnr, 1);
	CU_ASSERT_EQUAL(decode.cp_backoff, 0);
	CU_ASSERT_EQUAL(decode.restrict_ec, 0);
	CU_ASSERT_EQUAL(decode.v2x_pc5, 1);
	CU_ASSERT_EQUAL(decode.multiple_drb, 0);
	CU_ASSERT_EQUAL(decode.spare1, 0);
	CU_ASSERT_EQUAL(decode.v2xnr_pcf, 1);
	CU_ASSERT_EQUAL(decode.up_mt_edt, 0);
	CU_ASSERT_EQUAL(decode.cp_mt_edt, 0);
	CU_ASSERT_EQUAL(decode.wusa, 1);
	CU_ASSERT_EQUAL(decode.racs, 1);
}

void test_decode_gtpv1_apn_ambr_with_nsapi_ie(void)
{
	gtpv1_apn_ambr_with_nsapi_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xc9, 0x00, 0x09, 0x01, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x01};

	CU_ASSERT(decode_gtpv1_apn_ambr_with_nsapi_ie(buf, &decode) == 12);
	CU_ASSERT(decode_gtpv1_apn_ambr_with_nsapi_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_apn_ambr_with_nsapi_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_apn_ambr_with_nsapi_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_APN_AMBR_WITH_NSAPI);
	CU_ASSERT_EQUAL(decode.header.length, 9);
	CU_ASSERT_EQUAL(decode.spare, 0);
	CU_ASSERT_EQUAL(decode.nsapi, 1);
	CU_ASSERT_EQUAL(decode.authorized_apn_ambr_for_uplink, 1);
	CU_ASSERT_EQUAL(decode.authorized_apn_ambr_for_downlink, 1);
}

void test_decode_gtpv1_signalling_priority_indication_with_nsapi_ie(void)
{
	gtpv1_signalling_priority_indication_with_nsapi_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xcc, 0x00, 0x02, 0x01, 0x01};

	CU_ASSERT(decode_gtpv1_signalling_priority_indication_with_nsapi_ie(buf, &decode) == 5);
	CU_ASSERT(decode_gtpv1_signalling_priority_indication_with_nsapi_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_signalling_priority_indication_with_nsapi_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_signalling_priority_indication_with_nsapi_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_SIGNALLING_PRIORITY_INDICATION_WITH_NSAPI);
	CU_ASSERT_EQUAL(decode.header.length, 2);
	CU_ASSERT_EQUAL(decode.spare, 0);
	CU_ASSERT_EQUAL(decode.nsapi, 1);
	CU_ASSERT_EQUAL(decode.spare2, 0);
	CU_ASSERT_EQUAL(decode.lapi, 1);
}

void test_decode_gtpv1_higher_bitrates_than_16_mbps_flag_ie(void)
{
	gtpv1_higher_bitrates_than_16_mbps_flag_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xcd, 0x00, 0x01, 0x01};

	CU_ASSERT(decode_gtpv1_higher_bitrates_than_16_mbps_flag_ie(buf, &decode) == 4);
	CU_ASSERT(decode_gtpv1_higher_bitrates_than_16_mbps_flag_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_higher_bitrates_than_16_mbps_flag_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_higher_bitrates_than_16_mbps_flag_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_HIGER_BITRATES_THAN_16_MBPS_FLAG);
	CU_ASSERT_EQUAL(decode.header.length, 1);
	CU_ASSERT_EQUAL(decode.higher_bitrates_than_16_mbps_flag, 1);
}

void test_decode_gtpv1_selection_mode_with_nsapi_ie(void)
{
	gtpv1_selection_mode_with_nsapi_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xd5, 0x00, 0x02, 0x01, 0x01};

	CU_ASSERT(decode_gtpv1_selection_mode_with_nsapi_ie(buf, &decode) == 5);
	CU_ASSERT(decode_gtpv1_selection_mode_with_nsapi_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_selection_mode_with_nsapi_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_selection_mode_with_nsapi_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_SELECTION_MODE_WITH_NSAPI);
	CU_ASSERT_EQUAL(decode.header.length, 2);
	CU_ASSERT_EQUAL(decode.spare, 0);
	CU_ASSERT_EQUAL(decode.nsapi, 1);
	CU_ASSERT_EQUAL(decode.spare2, 0);
	CU_ASSERT_EQUAL(decode.selection_mode_value, 1);
}

void test_decode_gtpv1_local_home_network_id_with_nsapi_ie(void)
{
	gtpv1_local_home_network_id_with_nsapi_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xd7, 0x00, 0x06, 0x01, 0x67, 0x73, 0x6c, 0x61, 0x62};

	CU_ASSERT(decode_gtpv1_local_home_network_id_with_nsapi_ie(buf, &decode) == 9);
	CU_ASSERT(decode_gtpv1_local_home_network_id_with_nsapi_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_local_home_network_id_with_nsapi_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_local_home_network_id_with_nsapi_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_LOCAL_HOME_NETWORK_ID_WITH_NSAPI);
	CU_ASSERT_EQUAL(decode.header.length, 6);
	CU_ASSERT_EQUAL(decode.spare, 0);
	CU_ASSERT_EQUAL(decode.nsapi, 1);
	CU_ASSERT_STRING_EQUAL(decode.local_home_network_id_with_nsapi,"gslab");
}

void test_decode_gtpv1_ran_transparent_container_ie(void)
{
	gtpv1_ran_transparent_container_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x90, 0x00, 0x02, 0x32, 0x32};

	CU_ASSERT(decode_gtpv1_ran_transparent_container_ie(buf, &decode) == 5);
	CU_ASSERT(decode_gtpv1_ran_transparent_container_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_ran_transparent_container_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_ran_transparent_container_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_RAN_TRANSPARENT_CONTAINER);
	CU_ASSERT_EQUAL(decode.header.length, 2);
	CU_ASSERT_STRING_EQUAL(decode.rtc_field, "22");
}

void test_decode_gtpv1_rim_routing_addr_ie(void)
{
	gtpv1_rim_routing_addr_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x9e, 0x00, 0x02, 0x31, 0x31};

	CU_ASSERT(decode_gtpv1_rim_routing_addr_ie(buf, &decode) == 5);
	CU_ASSERT(decode_gtpv1_rim_routing_addr_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_rim_routing_addr_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_rim_routing_addr_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_RIM_ROUTING_ADDR);
	CU_ASSERT_EQUAL(decode.header.length, 2);
	CU_ASSERT_STRING_EQUAL(decode.rim_routing_addr, "11");
}

void test_decode_gtpv1_rim_routing_addr_disc_ie(void)
{
	gtpv1_rim_routing_addr_disc_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xb2, 0x00, 0x01, 0x02};

	CU_ASSERT(decode_gtpv1_rim_routing_addr_disc_ie(buf, &decode) == 4);
	CU_ASSERT(decode_gtpv1_rim_routing_addr_disc_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_rim_routing_addr_disc_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_rim_routing_addr_disc_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_RIM_ROUTING_ADDR_DISCRIMINATOR);
	CU_ASSERT_EQUAL(decode.header.length, 1);
	CU_ASSERT_EQUAL(decode.spare, 0);
	CU_ASSERT_EQUAL(decode.discriminator, 2);
}

void test_decode_gtpv1_selected_plmn_id_ie(void)
{
	gtpv1_selected_plmn_id_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xa4, 0x00, 0x03, 0x30, 0x15, 0x08};

	CU_ASSERT(decode_gtpv1_selected_plmn_id_ie(buf, &decode) == 6);
	CU_ASSERT(decode_gtpv1_selected_plmn_id_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_selected_plmn_id_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_selected_plmn_id_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_SELECTED_PLMN_ID);
	CU_ASSERT_EQUAL(decode.header.length, 3);
	CU_ASSERT_EQUAL(decode.mcc_digit_2, 3);
	CU_ASSERT_EQUAL(decode.mcc_digit_1, 0);
	CU_ASSERT_EQUAL(decode.mnc_digit_3, 0);
	CU_ASSERT_EQUAL(decode.mcc_digit_3, 5);
	CU_ASSERT_EQUAL(decode.mnc_digit_1, 1);
	CU_ASSERT_EQUAL(decode.mnc_digit_2, 8);

	gtpv1_selected_plmn_id_ie_t decode_1 = {0};
	uint8_t buf_1[SIZE] = {0xa4, 0x00, 0x03, 0x30, 0xf5, 0x08};

	CU_ASSERT(decode_gtpv1_selected_plmn_id_ie(buf_1, &decode_1) == 6);
	CU_ASSERT_EQUAL(decode_1.header.type, GTPV1_IE_SELECTED_PLMN_ID);
	CU_ASSERT_EQUAL(decode_1.header.length, 3);
	CU_ASSERT_EQUAL(decode_1.mcc_digit_2, 3);
	CU_ASSERT_EQUAL(decode_1.mcc_digit_1, 0);
	CU_ASSERT_EQUAL(decode_1.mnc_digit_3, 0xf);
	CU_ASSERT_EQUAL(decode_1.mcc_digit_3, 5);
	CU_ASSERT_EQUAL(decode_1.mnc_digit_1, 8);
	CU_ASSERT_EQUAL(decode_1.mnc_digit_2, 0);
}

void test_decode_gtpv1_mbms_protocol_config_options_ie(void)
{
	gtpv1_mbms_protocol_config_options_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x9f, 0x00, 0x02, 0x31, 0x31};

	CU_ASSERT(decode_gtpv1_mbms_protocol_config_options_ie(buf, &decode) == 5);
	CU_ASSERT(decode_gtpv1_mbms_protocol_config_options_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_mbms_protocol_config_options_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_mbms_protocol_config_options_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_MBMS_PROTOCOL_CONFIG_OPTIONS);
	CU_ASSERT_EQUAL(decode.header.length, 2);
	CU_ASSERT_STRING_EQUAL(decode.mbms_protocol_configuration, "11");
}

void test_decode_gtpv1_teid_data_2_ie(void)
{
	gtpv1_teid_data_2_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x12, 0x05, 0x00, 0xff, 0xfe, 0xee};

	CU_ASSERT(decode_gtpv1_teid_data_2_ie(buf, &decode) == 6);
	CU_ASSERT(decode_gtpv1_teid_data_2_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_teid_data_2_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_teid_data_2_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_TEID_DATA_2);
	CU_ASSERT_EQUAL(decode.nsapi, 5);
	CU_ASSERT_EQUAL(decode.teid, 0x0fffeee);
}

void test_decode_gtpv1_ranap_cause_ie(void)
{
	gtpv1_ranap_cause_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x15, 0x07};

	CU_ASSERT(decode_gtpv1_ranap_cause_ie(buf, &decode) == 2);
	CU_ASSERT(decode_gtpv1_ranap_cause_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_ranap_cause_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_ranap_cause_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_RANAP_CAUSE);
	CU_ASSERT_EQUAL(decode.ranap_cause, 7);
}

void test_decode_gtpv1_target_identification_ie(void)
{
	gtpv1_target_identification_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x8a, 0x00, 0x0a, 0x22, 0x71, 0x31, 0x00, 0x02, 0x02, 0x00, 0x02, 0x00, 0x01};

	CU_ASSERT(decode_gtpv1_target_identification_ie(buf, &decode) == 13);
	CU_ASSERT(decode_gtpv1_target_identification_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_target_identification_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_target_identification_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_TARGET_IDENTIFICATION);
	CU_ASSERT_EQUAL(decode.header.length, 10);
	CU_ASSERT_EQUAL(decode.mcc_digit_2, 2);
	CU_ASSERT_EQUAL(decode.mcc_digit_1, 2);
	CU_ASSERT_EQUAL(decode.mnc_digit_3, 7);
	CU_ASSERT_EQUAL(decode.mcc_digit_3, 1);
	CU_ASSERT_EQUAL(decode.mnc_digit_1, 1);
	CU_ASSERT_EQUAL(decode.mnc_digit_2, 3);
	CU_ASSERT_EQUAL(decode.lac, 0x2);
	CU_ASSERT_EQUAL(decode.rac, 0x2);
	CU_ASSERT_EQUAL(decode.rnc_id, 0x2);
	CU_ASSERT_EQUAL(decode.extended_rnc_id, 0x1);


	gtpv1_target_identification_ie_t decode_1 = {0};
	uint8_t buf_1[SIZE] = {0x8a, 0x00, 0x08, 0x22, 0xf1, 0x73, 0x00, 0x02, 0x02, 0x00, 0x02};

	CU_ASSERT(decode_gtpv1_target_identification_ie(buf_1, &decode_1) == 11);
	CU_ASSERT_EQUAL(decode_1.header.type, GTPV1_IE_TARGET_IDENTIFICATION);
	CU_ASSERT_EQUAL(decode_1.header.length, 8);
	CU_ASSERT_EQUAL(decode_1.mcc_digit_2, 2);
	CU_ASSERT_EQUAL(decode_1.mcc_digit_1, 2);
	CU_ASSERT_EQUAL(decode_1.mnc_digit_3, 7);
	CU_ASSERT_EQUAL(decode_1.mcc_digit_3, 1);
	CU_ASSERT_EQUAL(decode_1.mnc_digit_1, 0);
	CU_ASSERT_EQUAL(decode_1.mnc_digit_2, 3);
	CU_ASSERT_EQUAL(decode_1.lac, 0x2);
	CU_ASSERT_EQUAL(decode_1.rac, 0x2);
	CU_ASSERT_EQUAL(decode_1.rnc_id, 0x2);
}


void test_decode_gtpv1_utran_transparent_container_ie(void)
{
	gtpv1_utran_transparent_container_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x8b, 0x00, 0x04, 0x73, 0x68, 0x75, 0x62};

	CU_ASSERT(decode_gtpv1_utran_transparent_container_ie(buf, &decode) == 7);
	CU_ASSERT(decode_gtpv1_utran_transparent_container_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_utran_transparent_container_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_utran_transparent_container_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_UTRAN_TRANSPARENT_CONTAINER);
	CU_ASSERT_EQUAL(decode.header.length, 4);
	CU_ASSERT_STRING_EQUAL(decode.utran_transparent_field, "shub");
}

void test_decode_gtpv1_rab_setup_info_ie(void)
{
	gtpv1_rab_setup_info_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x8c, 0x00, 0x09, 0x02, 0x00, 0xff, 0xfe, 0xee,
		0xd4, 0x81, 0x41, 0x17};

	CU_ASSERT(decode_gtpv1_rab_setup_info_ie(buf, &decode) == 12);
	CU_ASSERT(decode_gtpv1_rab_setup_info_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_rab_setup_info_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_rab_setup_info_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_RAB_SETUP_INFO);
	CU_ASSERT_EQUAL(decode.header.length, 9);
	CU_ASSERT_EQUAL(decode.spare, 0);
	CU_ASSERT_EQUAL(decode.nsapi, 2);
	CU_ASSERT_EQUAL(decode.teid, 0x0fffeee);
	CU_ASSERT_EQUAL(decode.rnc_ip_addr.ipv4, 3565240599);

	gtpv1_rab_setup_info_ie_t decode1 = {0};
	uint8_t buf1[SIZE] = {0x8c, 0x00, 0x01, 0x02};

	CU_ASSERT(decode_gtpv1_rab_setup_info_ie(buf1, &decode1) == 4);
	CU_ASSERT(decode_gtpv1_rab_setup_info_ie(NULL, &decode1) == -1);
	CU_ASSERT(decode_gtpv1_rab_setup_info_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_rab_setup_info_ie(buf1, NULL) == -1);
	CU_ASSERT_EQUAL(decode1.header.type, GTPV1_IE_RAB_SETUP_INFO);
	CU_ASSERT_EQUAL(decode1.header.length, 1);
	CU_ASSERT_EQUAL(decode1.spare, 0);
	CU_ASSERT_EQUAL(decode1.nsapi, 2);
}

void test_decode_gtpv1_bss_container_ie(void)
{
	gtpv1_bss_container_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xad, 0x00, 0x05, 0x67, 0x73, 0x6c, 0x61, 0x62};

	CU_ASSERT(decode_gtpv1_bss_container_ie(buf, &decode) == 8);
	CU_ASSERT(decode_gtpv1_bss_container_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_bss_container_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_bss_container_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_BSS_CONTAINER);
	CU_ASSERT_EQUAL(decode.header.length, 5);
	CU_ASSERT_STRING_EQUAL(decode.bss_container, "gslab");
}

void test_decode_gtpv1_cell_identification_ie(void)
{
	gtpv1_cell_identification_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xae, 0x00, 0x11, 0x25, 0xf3, 0x88, 0x00, 0x14,
		0x14, 0x00, 0x01, 0x00, 0x25, 0xf3, 0x88, 0x00, 0x14, 0x14,
		0x00, 0x01};

	CU_ASSERT(decode_gtpv1_cell_identification_ie(buf, &decode) == 20);
	CU_ASSERT(decode_gtpv1_cell_identification_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_cell_identification_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_cell_identification_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_CELL_IDENTIFICATION);
	CU_ASSERT_EQUAL(decode.header.length, 17);
	CU_ASSERT_EQUAL(decode.target_cell_id.rai_value.mcc_digit_2, 2);
	CU_ASSERT_EQUAL(decode.target_cell_id.rai_value.mcc_digit_1, 5);
	CU_ASSERT_EQUAL(decode.target_cell_id.rai_value.mnc_digit_3, 8);
	CU_ASSERT_EQUAL(decode.target_cell_id.rai_value.mcc_digit_3, 3);
	CU_ASSERT_EQUAL(decode.target_cell_id.rai_value.mnc_digit_1, 0);
	CU_ASSERT_EQUAL(decode.target_cell_id.rai_value.mnc_digit_2, 8);
	CU_ASSERT_EQUAL(decode.target_cell_id.rai_value.lac, 20);
	CU_ASSERT_EQUAL(decode.target_cell_id.rai_value.rac, 20);
	CU_ASSERT_EQUAL(decode.target_cell_id.cell_identity, 1);
	CU_ASSERT_EQUAL(decode.source_type, 0);
	CU_ASSERT_EQUAL(decode.ID.source_cell_id.rai_value.mcc_digit_2, 2);
	CU_ASSERT_EQUAL(decode.ID.source_cell_id.rai_value.mcc_digit_1, 5);
	CU_ASSERT_EQUAL(decode.ID.source_cell_id.rai_value.mnc_digit_3, 8);
	CU_ASSERT_EQUAL(decode.ID.source_cell_id.rai_value.mcc_digit_3, 3);
	CU_ASSERT_EQUAL(decode.ID.source_cell_id.rai_value.mnc_digit_1, 0);
	CU_ASSERT_EQUAL(decode.ID.source_cell_id.rai_value.mnc_digit_2, 8);
	CU_ASSERT_EQUAL(decode.ID.source_cell_id.rai_value.lac, 20);
	CU_ASSERT_EQUAL(decode.ID.source_cell_id.rai_value.rac, 20);
	CU_ASSERT_EQUAL(decode.ID.source_cell_id.cell_identity, 1);
}

void test_decode_gtpv1_bssgp_cause_ie(void)
{
	gtpv1_bssgp_cause_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xb0, 0x00, 0x01, 0x02};

	CU_ASSERT(decode_gtpv1_bssgp_cause_ie(buf, &decode) == 4);
	CU_ASSERT(decode_gtpv1_bssgp_cause_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_bssgp_cause_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_bssgp_cause_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_BSSGP_CAUSE);
	CU_ASSERT_EQUAL(decode.header.length, 1);
	CU_ASSERT_EQUAL(decode.bssgp_cause, 2);
}

void test_decode_gtpv1_list_of_setup_pfcs_ie(void)
{
	gtpv1_list_of_setup_pfcs_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xb3, 0x00, 0x04, 0x03, 0x01, 0x00, 0x03};

	CU_ASSERT(decode_gtpv1_list_of_setup_pfcs_ie(buf, &decode) == 7);
	CU_ASSERT(decode_gtpv1_list_of_setup_pfcs_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_list_of_setup_pfcs_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_list_of_setup_pfcs_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_LIST_OF_SET_UP_PFCS);
	CU_ASSERT_EQUAL(decode.header.length, 4);
	CU_ASSERT_EQUAL(decode.list.no_of_pfcs, 3);
	CU_ASSERT_EQUAL(decode.list.pfi_list[0].spare, 0);
	CU_ASSERT_EQUAL(decode.list.pfi_list[0].pfi_value, 1);
	CU_ASSERT_EQUAL(decode.list.pfi_list[1].spare, 0);
	CU_ASSERT_EQUAL(decode.list.pfi_list[1].pfi_value, 0);
	CU_ASSERT_EQUAL(decode.list.pfi_list[2].spare, 0);
	CU_ASSERT_EQUAL(decode.list.pfi_list[2].pfi_value, 3);

	gtpv1_list_of_setup_pfcs_ie_t decode1 = {0};
	uint8_t buf1[SIZE] = {0xb3, 0x00, 0x01, 0x0d};

	CU_ASSERT(decode_gtpv1_list_of_setup_pfcs_ie(buf1, &decode1) == 4);
	CU_ASSERT(decode_gtpv1_list_of_setup_pfcs_ie(NULL, &decode1) == -1);
	CU_ASSERT(decode_gtpv1_list_of_setup_pfcs_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_list_of_setup_pfcs_ie(buf1, NULL) == -1);
	CU_ASSERT_EQUAL(decode1.header.type, GTPV1_IE_LIST_OF_SET_UP_PFCS);
	CU_ASSERT_EQUAL(decode1.header.length, 1);
	CU_ASSERT_EQUAL(decode1.list.no_of_pfcs, 13);
}

void test_decode_gtpv1_ps_handover_xid_param_ie(void)
{
	gtpv1_ps_handover_xid_param_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xb4, 0x00, 0x04, 0x02, 0x02, 0x31, 0x31};

	CU_ASSERT(decode_gtpv1_ps_handover_xid_param_ie(buf, &decode) == 7);
	CU_ASSERT(decode_gtpv1_ps_handover_xid_param_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_ps_handover_xid_param_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_ps_handover_xid_param_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_PS_HANDOVER_XID_PARAM);
	CU_ASSERT_EQUAL(decode.header.length, 4);
	CU_ASSERT_EQUAL(decode.spare, 0);
	CU_ASSERT_EQUAL(decode.sapi, 2);
	CU_ASSERT_EQUAL(decode.xid_param_length, 2);
	CU_ASSERT_STRING_EQUAL(decode.xid_param, "11");
}

void test_decode_gtpv1_reliable_inter_rat_handover_info_ie(void)
{
	gtpv1_reliable_inter_rat_handover_info_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xbc, 0x00, 0x01, 0x02};

	CU_ASSERT(decode_gtpv1_reliable_inter_rat_handover_info_ie(buf, &decode) == 4);
	CU_ASSERT(decode_gtpv1_reliable_inter_rat_handover_info_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_reliable_inter_rat_handover_info_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_reliable_inter_rat_handover_info_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_RELIABLE_INTER_RAT_HANDOVER_INFO);
	CU_ASSERT_EQUAL(decode.header.length, 1);
	CU_ASSERT_EQUAL(decode.handover_info, 2);
}

void test_decode_gtpv1_csg_id_ie(void)
{
	gtpv1_csg_id_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xc4, 0x00, 0x04, 0x01, 0x00, 0x00, 0x02};

	CU_ASSERT(decode_gtpv1_csg_id_ie(buf, &decode) == 7);
	CU_ASSERT(decode_gtpv1_csg_id_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_csg_id_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_csg_id_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_CSG_ID);
	CU_ASSERT_EQUAL(decode.header.length, 4);
	CU_ASSERT_EQUAL(decode.spare, 0);
	CU_ASSERT_EQUAL(decode.csg_id, 1);
	CU_ASSERT_EQUAL(decode.csg_id2, 2);
}

void test_decode_gtpv1_csg_membership_indication_ie(void)
{
	gtpv1_csg_membership_indication_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xc5, 0x00, 0x01, 0x01};

	CU_ASSERT(decode_gtpv1_csg_membership_indication_ie(buf, &decode) == 4);
	CU_ASSERT(decode_gtpv1_csg_membership_indication_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_csg_membership_indication_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_csg_membership_indication_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_CSG_MEMB_INDCTN);
	CU_ASSERT_EQUAL(decode.header.length, 1);
	CU_ASSERT_EQUAL(decode.spare, 0);
	CU_ASSERT_EQUAL(decode.cmi, 1);
}

void test_decode_gtpv1_additional_mm_ctxt_for_srvcc_ie(void)
{
	gtpv1_additional_mm_ctxt_for_srvcc_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xcf, 0x00, 0x22, 0x03, 0x39, 0x5f, 0xbf, 0x15,
		0x51, 0x21, 0x99, 0x29, 0xac, 0x73, 0x56, 0x44, 0x9d, 0x6c,
		0xeb, 0xf9, 0xf6, 0x6f, 0x33, 0xd2, 0xb5, 0xbb, 0xfb, 0x2b,
		0xb0, 0x07, 0x02, 0x02, 0x06, 0x05, 0x01, 0x01, 0x03 };

	CU_ASSERT(decode_gtpv1_additional_mm_ctxt_for_srvcc_ie(buf, &decode) == 37);
	CU_ASSERT(decode_gtpv1_additional_mm_ctxt_for_srvcc_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_additional_mm_ctxt_for_srvcc_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_additional_mm_ctxt_for_srvcc_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_ADDTL_MM_CTXT_SRVCC);
	CU_ASSERT_EQUAL(decode.header.length, 34);
	CU_ASSERT_EQUAL(decode.ms_classmark_2.ms_classmark_2_len, 3);
	CU_ASSERT_EQUAL(decode.ms_classmark_2.spare1, 0);
	CU_ASSERT_EQUAL(decode.ms_classmark_2.rev_level, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_2.es_ind, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_2.a5_1, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_2.rf_power_cap, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_2.spare2, 0);
	CU_ASSERT_EQUAL(decode.ms_classmark_2.ps_cap, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_2.ss_screen_ind, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_2.sm_cap, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_2.vbs, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_2.vgcs, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_2.fc, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_2.cm3, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_2.spare3, 0);
	CU_ASSERT_EQUAL(decode.ms_classmark_2.lcsvacap, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_2.ucs2, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_2.solsa, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_2.cmsp, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_2.a5_3, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_2.a5_2, 1);

	CU_ASSERT_EQUAL(decode.ms_classmark_3.ms_classmark_3_len, 21);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.spare1, 0);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.mult_band_supp, 5);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.a5_bits, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.assoc_radio_cap_1, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.assoc_radio_cap_2, 2);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.r_support, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.r_gsm_assoc_radio_cap, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.hscsd_mult_slot_cap, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.hscsd_mult_slot_class, 4);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.ucs2_treatment, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.extended_meas_cap, 0);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.ms_meas_cap, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.sms_value, 3);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.sm_value, 5);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.ms_pos_method_cap, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.ms_pos_method, 3);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.ecsd_multislot_cap, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.ecsd_multislot_class, 6);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.psk8_struct, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.mod_cap, 0);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.rf_pwr_cap_1, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.rf_pwr_cap_1_val, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.rf_pwr_cap_2, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.rf_pwr_cap_2_val, 0);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.gsm_400_bands_supp, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.gsm_400_bands_val, 0);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.gsm_400_assoc_radio_cap, 4);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.gsm_850_assoc_radio_cap, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.gsm_850_assoc_radio_cap_val, 3);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.gsm_1900_assoc_radio_cap, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.gsm_1900_assoc_radio_cap_val, 5);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.umts_fdd_rat_cap, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.umts_tdd_rat_cap, 0);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.cdma2000_rat_cap, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.dtm_gprs_multislot_class, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.dtm_gprs_multislot_val, 0);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.single_slot_dtm, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.dtm_egprs_multislot_class, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.dtm_egprs_multislot_val, 2);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.single_band_supp, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.single_band_supp_val, 7);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.gsm_750_assoc_radio_cap, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.gsm_750_assoc_radio_cap_val, 14);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.umts_1_28_mcps_tdd_rat_cap, 0);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.geran_feature_package, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.ext_dtm_gprs_multislot_class, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.ext_dtm_gprs_multislot_val, 3);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.ext_dtm_egprs_multislot_val, 2);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.high_multislot_cap, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.high_multislot_val, 2);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.geran_iu_mode_supp, 0);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.geran_feature_package_2, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.gmsk_multislot_power_prof, 2);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.psk8_multislot_power_prof, 3);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.t_gsm_400_bands_supp, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.t_gsm_400_bands_val, 2);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.t_gsm_400_assoc_radio_cap, 6);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.t_gsm_900_assoc_radio_cap, 0);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.dl_advanced_rx_perf, 3);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.dtm_enhancements_cap, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.dtm_gprs_high_multislot_cap, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.dtm_gprs_high_multislot_val, 2);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.offset_required, 0);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.dtm_egprs_high_multislot_cap, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.dtm_egprs_high_multislot_val, 2);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.repeated_acch_capability, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.gsm_710_assoc_radio_cap, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.gsm_710_assoc_radio_val, 5);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.t_gsm_810_assoc_radio_cap, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.t_gsm_810_assoc_radio_val, 7);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.ciphering_mode_setting_cap, 0);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.add_pos_cap, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.e_utra_fdd_supp, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.e_utra_tdd_supp, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.e_utra_meas_rep_supp, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.prio_resel_supp, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.utra_csg_cells_rep, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.vamos_level, 2);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.tighter_capability, 3);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.sel_ciph_dl_sacch, 0);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.cs_ps_srvcc_geran_utra, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.cs_ps_srvcc_geran_eutra, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.geran_net_sharing, 0);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.e_utra_wb_rsrq_meas_supp, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.er_band_support, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.utra_mult_band_ind_supp, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.e_utra_mult_band_ind_supp, 0);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.extended_tsc_set_cap_supp, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.extended_earfcn_val_range, 1);
	CU_ASSERT_EQUAL(decode.ms_classmark_3.spare3, 0);

	CU_ASSERT_EQUAL(decode.sup_codec_list_len, 7);
	CU_ASSERT_EQUAL(decode.sup_codec_list[0].sysid, 2);
	CU_ASSERT_EQUAL(decode.sup_codec_list[0].len_bitmap_sysid, 2);
	CU_ASSERT_EQUAL(decode.sup_codec_list[0].codec_bitmap_1_8, 6);
	CU_ASSERT_EQUAL(decode.sup_codec_list[0].codec_bitmap_9_16, 5);
	CU_ASSERT_EQUAL(decode.sup_codec_list[1].sysid, 1);
	CU_ASSERT_EQUAL(decode.sup_codec_list[1].len_bitmap_sysid, 1);
	CU_ASSERT_EQUAL(decode.sup_codec_list[1].codec_bitmap_1_8, 3);
}

void test_decode_gtpv1_additional_flags_for_srvcc_ie(void)
{
	gtpv1_additional_flags_for_srvcc_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xd0, 0x00, 0x01, 0x01};

	CU_ASSERT(decode_gtpv1_additional_flags_for_srvcc_ie(buf, &decode) == 4);
	CU_ASSERT(decode_gtpv1_additional_flags_for_srvcc_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_additional_flags_for_srvcc_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_additional_flags_for_srvcc_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_ADDTL_FLGS_SRVCC);
	CU_ASSERT_EQUAL(decode.header.length, 1);
	CU_ASSERT_EQUAL(decode.spare, 0);
	CU_ASSERT_EQUAL(decode.ics, 1);
}

void test_decode_gtpv1_stn_sr_ie(void)
{
	gtpv1_stn_sr_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xd1, 0x00, 0x03, 0x01, 0x01, 0x21};

	CU_ASSERT(decode_gtpv1_stn_sr_ie(buf, &decode) == 6);
	CU_ASSERT(decode_gtpv1_stn_sr_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_stn_sr_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_stn_sr_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_STN_SR);
	CU_ASSERT_EQUAL(decode.header.length, 3);
	CU_ASSERT_EQUAL(decode.nanpi, 1);
	CU_ASSERT_EQUAL(decode.digits[0].digit1, 0);
	CU_ASSERT_EQUAL(decode.digits[0].digit2, 1);
	CU_ASSERT_EQUAL(decode.digits[1].digit1, 2);
	CU_ASSERT_EQUAL(decode.digits[1].digit2, 1);
}

void test_decode_gtpv1_c_msisdn_ie(void)
{
	gtpv1_c_msisdn_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xd2, 0x00, 0x05, 0x32, 0x33, 0x34, 0x35, 0x36};

	CU_ASSERT(decode_gtpv1_c_msisdn_ie(buf, &decode) == 8);
	CU_ASSERT(decode_gtpv1_c_msisdn_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_c_msisdn_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_c_msisdn_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_C_MSISDN);
	CU_ASSERT_EQUAL(decode.header.length, 5);
	CU_ASSERT_STRING_EQUAL(decode.msisdn, "23456");
}

void test_decode_gtpv1_extended_ranap_cause_ie(void)
{
	gtpv1_extended_ranap_cause_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xd3, 0x00, 0x02, 0x00, 0x02};

	CU_ASSERT(decode_gtpv1_extended_ranap_cause_ie(buf, &decode) == 5);
	CU_ASSERT(decode_gtpv1_extended_ranap_cause_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_extended_ranap_cause_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_extended_ranap_cause_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_EXTENDED_RANAP_CAUSE);
	CU_ASSERT_EQUAL(decode.header.length, 2);
	CU_ASSERT_EQUAL(decode.extended_ranap_cause, 2);
}

void test_decode_gtpv1_enodeb_id_ie(void)
{
	gtpv1_enodeb_id_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xd4, 0x00, 0x09, 0x00, 0x22, 0x01, 0x11, 0x02,
		0x00, 0x03, 0x00, 0x14};

	CU_ASSERT(decode_gtpv1_enodeb_id_ie(buf, &decode) == 12);
	CU_ASSERT(decode_gtpv1_enodeb_id_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_enodeb_id_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_enodeb_id_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_ENODEB_ID);
	CU_ASSERT_EQUAL(decode.header.length, 9);
	CU_ASSERT_EQUAL(decode.enodeb_type, 0);
	CU_ASSERT_EQUAL(decode.mcc_digit_2, 2);
	CU_ASSERT_EQUAL(decode.mcc_digit_1, 2);
	CU_ASSERT_EQUAL(decode.mnc_digit_3, 0);
	CU_ASSERT_EQUAL(decode.mcc_digit_3, 1);
	CU_ASSERT_EQUAL(decode.mnc_digit_1, 1);
	CU_ASSERT_EQUAL(decode.mnc_digit_2, 1);
	CU_ASSERT_EQUAL(decode.spare, 0);
	CU_ASSERT_EQUAL(decode.macro_enodeb_id, 2);
	CU_ASSERT_EQUAL(decode.macro_enodeb_id2, 3);
	CU_ASSERT_EQUAL(decode.home_enodeb_id, 0);
	CU_ASSERT_EQUAL(decode.home_enodeb_id2, 0);
	CU_ASSERT_EQUAL(decode.tac, 20);
}

void test_decode_gtpv1_node_identifier_ie(void)
{
	gtpv1_node_identifier_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xdb, 0x00, 0x08, 0x03, 0x6d, 0x6d, 0x65, 0x03,
		0x61, 0x61, 0x61};

	CU_ASSERT(decode_gtpv1_node_identifier_ie(buf, &decode) == 11);
	CU_ASSERT(decode_gtpv1_node_identifier_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_node_identifier_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_node_identifier_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_NODE_IDENTIFIER);
	CU_ASSERT_EQUAL(decode.header.length, 8);
	CU_ASSERT_EQUAL(decode.len_of_node_name, 3);
	CU_ASSERT_STRING_EQUAL(decode.node_name, "mme");
	CU_ASSERT_EQUAL(decode.len_of_node_realm, 3);
	CU_ASSERT_STRING_EQUAL(decode.node_realm, "aaa");
}

void test_decode_gtpv1_ms_network_capability_value(gtpv1_ms_network_capability_value_t decode) {
	CU_ASSERT_EQUAL(decode.GEA_1, 0);
	CU_ASSERT_EQUAL(decode.sm_capabilities_via_dedicated_channels, 0);
	CU_ASSERT_EQUAL(decode.sm_capabilities_via_gprs_channels, 0);
	CU_ASSERT_EQUAL(decode.ucs2_support, 0);
	CU_ASSERT_EQUAL(decode.ss_screening_indicator, 0);
	CU_ASSERT_EQUAL(decode.solsa_capability, 0);
	CU_ASSERT_EQUAL(decode.revision_level_indicator, 0);
	CU_ASSERT_EQUAL(decode.pfc_feature_mode, 0);
	CU_ASSERT_EQUAL(decode.GEA_2, 0);
	CU_ASSERT_EQUAL(decode.GEA_3, 0);
	CU_ASSERT_EQUAL(decode.GEA_4, 0);
	CU_ASSERT_EQUAL(decode.GEA_5, 0);
	CU_ASSERT_EQUAL(decode.GEA_6, 0);
	CU_ASSERT_EQUAL(decode.GEA_7, 0);
	CU_ASSERT_EQUAL(decode.lcs_va_capability, 0);
	CU_ASSERT_EQUAL(decode.ps_ge_ut_iu_mode_capability, 0);
	CU_ASSERT_EQUAL(decode.ps_ge_ut_s1_mode_capability, 0);
	CU_ASSERT_EQUAL(decode.emm_combined_procedure_capability, 0);
	CU_ASSERT_EQUAL(decode.isr_support, 0);
	CU_ASSERT_EQUAL(decode.srvcc_to_ge_ut_capability, 0);
	CU_ASSERT_EQUAL(decode.epc_capability, 0);
	CU_ASSERT_EQUAL(decode.nf_capability, 0);
	CU_ASSERT_EQUAL(decode.ge_network_sharing_capability, 0);
	CU_ASSERT_EQUAL(decode.user_plane_integrity_protection_support, 0);
	CU_ASSERT_EQUAL(decode.GIA_4, 0);
	CU_ASSERT_EQUAL(decode.GIA_5, 0);
	CU_ASSERT_EQUAL(decode.GIA_6, 0);
	CU_ASSERT_EQUAL(decode.GIA_7, 0);
	CU_ASSERT_EQUAL(decode.ePCO_ie_indicator, 0);
	CU_ASSERT_EQUAL(decode.restriction_on_use_of_enhanced_coverage_capability, 0);
	CU_ASSERT_EQUAL(decode.dual_connectivity_of_e_ut_with_nr_capability, 0);
	return;
}
void test_decode_gtpv1_mm_context_ie(void)
{
	gtpv1_mm_context_ie_t decode_0 = {0};
	uint8_t buf_0[SIZE] = {0x81, 0x00, 0x61, 0xc9, 0x09, 0x31, 0x31, 0x31,
		0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
		0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
		0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x00,
		0x34, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
		0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x01, 0x31, 0x31,
		0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
		0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
		0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
		0x31, 0x01, 0x31, 0x01, 0x19, 0x04, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00};

	CU_ASSERT(decode_gtpv1_mm_context_ie(buf_0, &decode_0) == 100);
	CU_ASSERT(decode_gtpv1_mm_context_ie(NULL, &decode_0) == -1);
	CU_ASSERT(decode_gtpv1_mm_context_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_mm_context_ie(buf_0, NULL) == -1);
	CU_ASSERT_EQUAL(decode_0.header.type, GTPV1_IE_MM_CONTEXT);
	CU_ASSERT_EQUAL(decode_0.header.length, 97 );
	CU_ASSERT_EQUAL(decode_0.mm_context.used_cipher_value_umts_keys_and_quintuplets.ksi, 1);
	CU_ASSERT_EQUAL(decode_0.mm_context.used_cipher_value_umts_keys_and_quintuplets.used_gprs_integrity_protection_algo, 1);
	CU_ASSERT_EQUAL(decode_0.mm_context.used_cipher_value_umts_keys_and_quintuplets.ugipai, 1);
	CU_ASSERT_EQUAL(decode_0.mm_context.used_cipher_value_umts_keys_and_quintuplets.gupii, 1);
	CU_ASSERT_EQUAL(decode_0.mm_context.used_cipher_value_umts_keys_and_quintuplets.used_cipher, 1);
	CU_ASSERT_EQUAL(decode_0.security_mode, 0);
	CU_ASSERT_EQUAL(decode_0.mm_context.used_cipher_value_umts_keys_and_quintuplets.no_of_vectors, 1);
	CU_ASSERT_NSTRING_EQUAL(decode_0.mm_context.used_cipher_value_umts_keys_and_quintuplets.ck, "1111111111111111", 16);
	CU_ASSERT_NSTRING_EQUAL(decode_0.mm_context.used_cipher_value_umts_keys_and_quintuplets.ik, "1111111111111111", 16);
	CU_ASSERT_EQUAL(decode_0.mm_context.used_cipher_value_umts_keys_and_quintuplets.quintuplet_length, 52);
	CU_ASSERT_NSTRING_EQUAL(decode_0.mm_context.used_cipher_value_umts_keys_and_quintuplets.quintuplet[0].rand, "1111111111111111", 16);
	CU_ASSERT_EQUAL(decode_0.mm_context.used_cipher_value_umts_keys_and_quintuplets.quintuplet[0].xres_length, 1);
	CU_ASSERT_NSTRING_EQUAL(decode_0.mm_context.used_cipher_value_umts_keys_and_quintuplets.quintuplet[0].xres, "1", 1);
	CU_ASSERT_NSTRING_EQUAL(decode_0.mm_context.used_cipher_value_umts_keys_and_quintuplets.quintuplet[0].ck, "1111111111111111", 16);
	CU_ASSERT_NSTRING_EQUAL(decode_0.mm_context.used_cipher_value_umts_keys_and_quintuplets.quintuplet[0].ik, "1111111111111111", 16);
	CU_ASSERT_EQUAL(decode_0.mm_context.used_cipher_value_umts_keys_and_quintuplets.quintuplet[0].autn_length,1);
	CU_ASSERT_NSTRING_EQUAL(decode_0.mm_context.used_cipher_value_umts_keys_and_quintuplets.quintuplet[0].autn,"1",1);
	CU_ASSERT_EQUAL(decode_0.drx_parameter.split_pg_cycle_code, 1);
	CU_ASSERT_EQUAL(decode_0.drx_parameter.cycle_length, 1);
	CU_ASSERT_EQUAL(decode_0.drx_parameter.ccch, 1);
	CU_ASSERT_EQUAL(decode_0.drx_parameter.timer, 1);
	CU_ASSERT_EQUAL(decode_0.ms_network_capability_length, 4);
	
	test_decode_gtpv1_ms_network_capability_value(decode_0.ms_network_capability);	
	
	CU_ASSERT_EQUAL(decode_0.container_length, 0);

	gtpv1_mm_context_ie_t decode_1 = {0};
	uint8_t buf_1[SIZE] = {0x81, 0x00, 0x2f, 0xf9, 0x49, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x01, 0x31, 0x31, 0x31, 0x31, 0x31,
		0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
		0x31, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x02, 0x01, 0x19, 0x04, 0x00, 0x00,	0x00, 0x00,
		0x00, 0x00};
	
	CU_ASSERT(decode_gtpv1_mm_context_ie(buf_1, &decode_1) == 50);
	CU_ASSERT(decode_gtpv1_mm_context_ie(NULL, &decode_1) == -1);
	CU_ASSERT(decode_gtpv1_mm_context_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_mm_context_ie(buf_1, NULL) == -1);
	CU_ASSERT_EQUAL(decode_1.header.type, GTPV1_IE_MM_CONTEXT);
	CU_ASSERT_EQUAL(decode_1.header.length, 47);
	CU_ASSERT_EQUAL(decode_1.mm_context.gsm_keys_and_triplet.spare, 31);
	CU_ASSERT_EQUAL(decode_1.mm_context.gsm_keys_and_triplet.cksn, 1);
	CU_ASSERT_EQUAL(decode_1.security_mode, 1);
	CU_ASSERT_EQUAL(decode_1.mm_context.gsm_keys_and_triplet.no_of_vectors, 1);
	CU_ASSERT_EQUAL(decode_1.mm_context.gsm_keys_and_triplet.used_cipher, 1);
	CU_ASSERT_EQUAL(decode_1.mm_context.gsm_keys_and_triplet.kc, 1);
	CU_ASSERT_NSTRING_EQUAL(decode_1.mm_context.gsm_keys_and_triplet.triplet[0].rand,"1111111111111111",16);
	CU_ASSERT_EQUAL(decode_1.mm_context.gsm_keys_and_triplet.triplet[0].sres, 2);
	CU_ASSERT_EQUAL(decode_1.mm_context.gsm_keys_and_triplet.triplet[0].kc, 2);
	CU_ASSERT_EQUAL(decode_1.drx_parameter.split_pg_cycle_code, 1);
	CU_ASSERT_EQUAL(decode_1.drx_parameter.cycle_length, 1);
	CU_ASSERT_EQUAL(decode_1.drx_parameter.ccch, 1);
	CU_ASSERT_EQUAL(decode_1.drx_parameter.timer, 1);
	CU_ASSERT_EQUAL(decode_1.ms_network_capability_length, 4);

	test_decode_gtpv1_ms_network_capability_value(decode_1.ms_network_capability);	
	
	CU_ASSERT_EQUAL(decode_1.container_length, 0);

	gtpv1_mm_context_ie_t decode_2 = {0};
	uint8_t buf_2[SIZE] = { 0x81, 0x00, 0x61, 0xc9, 0x8f, 0x31, 0x31, 0x31,
		0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
		0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
		0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x00,
		0x34, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
		0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x01, 0x31, 0x31,
		0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
		0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
		0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
		0x31, 0x01, 0x31, 0x01, 0x19, 0x04, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00};

	CU_ASSERT(decode_gtpv1_mm_context_ie(buf_2, &decode_2) == 100);
	CU_ASSERT(decode_gtpv1_mm_context_ie(NULL, &decode_2) == -1);
	CU_ASSERT(decode_gtpv1_mm_context_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_mm_context_ie(buf_2, NULL) == -1);
	CU_ASSERT_EQUAL(decode_2.header.type, GTPV1_IE_MM_CONTEXT );
	CU_ASSERT_EQUAL(decode_2.header.length, 97 );
	CU_ASSERT_EQUAL(decode_2.mm_context.umts_keys_and_quintuplets.ksi, 1);
	CU_ASSERT_EQUAL(decode_2.mm_context.umts_keys_and_quintuplets.used_gprs_integrity_protection_algo, 1);
	CU_ASSERT_EQUAL(decode_2.mm_context.umts_keys_and_quintuplets.ugipai, 1);
	CU_ASSERT_EQUAL(decode_2.mm_context.umts_keys_and_quintuplets.gupii, 1);
	CU_ASSERT_EQUAL(decode_2.mm_context.umts_keys_and_quintuplets.spare, 7);
	CU_ASSERT_EQUAL(decode_2.security_mode, 2);
	CU_ASSERT_EQUAL(decode_2.mm_context.umts_keys_and_quintuplets.no_of_vectors, 1);
	CU_ASSERT_NSTRING_EQUAL(decode_2.mm_context.umts_keys_and_quintuplets.ck, "1111111111111111", 16);
	CU_ASSERT_NSTRING_EQUAL(decode_2.mm_context.umts_keys_and_quintuplets.ik, "1111111111111111", 16);
	CU_ASSERT_EQUAL(decode_2.mm_context.umts_keys_and_quintuplets.quintuplet_length, 52);
	CU_ASSERT_NSTRING_EQUAL(decode_2.mm_context.umts_keys_and_quintuplets.quintuplet[0].rand, "1111111111111111", 16);
	CU_ASSERT_EQUAL(decode_2.mm_context.umts_keys_and_quintuplets.quintuplet[0].xres_length, 1);
	CU_ASSERT_STRING_EQUAL(decode_2.mm_context.umts_keys_and_quintuplets.quintuplet[0].xres, "1");
	CU_ASSERT_NSTRING_EQUAL(decode_2.mm_context.umts_keys_and_quintuplets.quintuplet[0].ck, "1111111111111111", 16);
	CU_ASSERT_NSTRING_EQUAL(decode_2.mm_context.umts_keys_and_quintuplets.quintuplet[0].ik, "1111111111111111", 16);
	CU_ASSERT_EQUAL(decode_2.mm_context.umts_keys_and_quintuplets.quintuplet[0].autn_length, 1);
	CU_ASSERT_STRING_EQUAL(decode_2.mm_context.umts_keys_and_quintuplets.quintuplet[0].autn, "1");
	CU_ASSERT_EQUAL(decode_2.drx_parameter.split_pg_cycle_code, 1);
	CU_ASSERT_EQUAL(decode_2.drx_parameter.cycle_length, 1);
	CU_ASSERT_EQUAL(decode_2.drx_parameter.ccch, 1);
	CU_ASSERT_EQUAL(decode_2.drx_parameter.timer, 1);
	CU_ASSERT_EQUAL(decode_2.ms_network_capability_length, 4);

	test_decode_gtpv1_ms_network_capability_value(decode_2.ms_network_capability);	

	CU_ASSERT_EQUAL(decode_2.container_length, 0);

	gtpv1_mm_context_ie_t decode_3 = {0};
	uint8_t buf_3[SIZE] = {0x81, 0x00, 0x49, 0xf9, 0xc9, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x34, 0x31, 0x31, 0x31,
		0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
		0x31, 0x31, 0x31, 0x01, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
		0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
		0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
		0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x01, 0x031, 0x01,
		0x19, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	CU_ASSERT(decode_gtpv1_mm_context_ie(buf_3, &decode_3) == 76);
	CU_ASSERT(decode_gtpv1_mm_context_ie(NULL, &decode_3) == -1);
	CU_ASSERT(decode_gtpv1_mm_context_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_mm_context_ie(buf_3, NULL) == -1);
	CU_ASSERT_EQUAL(decode_3.header.length, 73);
	CU_ASSERT_EQUAL(decode_3.mm_context.gsm_keys_and_umts_quintuplets.spare, 31);
	CU_ASSERT_EQUAL(decode_3.mm_context.gsm_keys_and_umts_quintuplets.cksn, 1);
	CU_ASSERT_EQUAL(decode_3.security_mode, 3);
	CU_ASSERT_EQUAL(decode_3.mm_context.gsm_keys_and_umts_quintuplets.no_of_vectors, 1);
	CU_ASSERT_EQUAL(decode_3.mm_context.gsm_keys_and_umts_quintuplets.used_cipher, 1);
	CU_ASSERT_EQUAL(decode_3.mm_context.gsm_keys_and_umts_quintuplets.kc, 1);
	CU_ASSERT_EQUAL(decode_3.mm_context.gsm_keys_and_umts_quintuplets.quintuplet_length, 52);
	CU_ASSERT_NSTRING_EQUAL(decode_3.mm_context.gsm_keys_and_umts_quintuplets.quintuplet[0].rand, "1111111111111111", 16);
	CU_ASSERT_EQUAL(decode_3.mm_context.gsm_keys_and_umts_quintuplets.quintuplet[0].xres_length, 1);
	CU_ASSERT_STRING_EQUAL(decode_3.mm_context.gsm_keys_and_umts_quintuplets.quintuplet[0].xres, "1");
	CU_ASSERT_NSTRING_EQUAL(decode_3.mm_context.gsm_keys_and_umts_quintuplets.quintuplet[0].ck, "1111111111111111", 16);
	CU_ASSERT_NSTRING_EQUAL(decode_3.mm_context.gsm_keys_and_umts_quintuplets.quintuplet[0].ik, "1111111111111111", 16 );
	CU_ASSERT_EQUAL(decode_3.mm_context.gsm_keys_and_umts_quintuplets.quintuplet[0].autn_length, 1);
	CU_ASSERT_STRING_EQUAL(decode_3.mm_context.gsm_keys_and_umts_quintuplets.quintuplet[0].autn, "1");
	CU_ASSERT_EQUAL(decode_3.drx_parameter.split_pg_cycle_code, 1);
	CU_ASSERT_EQUAL(decode_3.drx_parameter.cycle_length, 1);
	CU_ASSERT_EQUAL(decode_3.drx_parameter.ccch, 1);
	CU_ASSERT_EQUAL(decode_3.drx_parameter.timer, 1);
	CU_ASSERT_EQUAL(decode_3.ms_network_capability_length, 4);

	test_decode_gtpv1_ms_network_capability_value(decode_3.ms_network_capability);	
//	CU_ASSERT_EQUAL(decode_3.ms_network_capability.iei, 1);
//	CU_ASSERT_EQUAL(decode_3.ms_network_capability.length, 1);	
//	CU_ASSERT_STRING_EQUAL(decode_3.ms_network_capability.value, "1");

	CU_ASSERT_EQUAL(decode_3.container_length, 0);
} 

void test_decode_gtpv1_pdp_context_ie(void)
{
	gtpv1_pdp_context_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x82, 0x00, 0x74, 0x65, 0x01, 0x15, 0x02, 0x12,
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
		0x37};

	CU_ASSERT(decode_gtpv1_pdp_context_ie(buf, &decode) == 119);
	CU_ASSERT(decode_gtpv1_pdp_context_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_pdp_context_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_pdp_context_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_PDP_CONTEXT);
	CU_ASSERT_EQUAL(decode.header.length, 116);
	CU_ASSERT_EQUAL(decode.ea, 0);
	CU_ASSERT_EQUAL(decode.vaa, 1);
	CU_ASSERT_EQUAL(decode.asi, 1);
	CU_ASSERT_EQUAL(decode.order, 0);
	CU_ASSERT_EQUAL(decode.nsapi, 5);
	CU_ASSERT_EQUAL(decode.spare, 0);
	CU_ASSERT_EQUAL(decode.sapi, 1);
	CU_ASSERT_EQUAL(decode.qos_sub_length, 21);
	CU_ASSERT_EQUAL(decode.qos_sub.allocation_retention_priority, 2);
	CU_ASSERT_EQUAL(decode.qos_sub.spare1, 0);
	CU_ASSERT_EQUAL(decode.qos_sub.delay_class, 2);
	CU_ASSERT_EQUAL(decode.qos_sub.reliablity_class, 2);
	CU_ASSERT_EQUAL(decode.qos_sub.peak_throughput, 3);
	CU_ASSERT_EQUAL(decode.qos_sub.spare2, 0);
	CU_ASSERT_EQUAL(decode.qos_sub.precedence_class, 1);
	CU_ASSERT_EQUAL(decode.qos_sub.spare3, 0);
	CU_ASSERT_EQUAL(decode.qos_sub.mean_throughput, 4);
	CU_ASSERT_EQUAL(decode.qos_sub.traffic_class, 1);
	CU_ASSERT_EQUAL(decode.qos_sub.delivery_order, 1);
	CU_ASSERT_EQUAL(decode.qos_sub.delivery_erroneous_sdu, 2);
	CU_ASSERT_EQUAL(decode.qos_sub.max_sdu_size, 3);
	CU_ASSERT_EQUAL(decode.qos_sub.max_bitrate_uplink, 123);
	CU_ASSERT_EQUAL(decode.qos_sub.max_bitrate_downlink, 234);
	CU_ASSERT_EQUAL(decode.qos_sub.residual_ber, 1);
	CU_ASSERT_EQUAL(decode.qos_sub.sdu_error_ratio, 1); 
	CU_ASSERT_EQUAL(decode.qos_sub.transfer_delay, 1); 
	CU_ASSERT_EQUAL(decode.qos_sub.traffic_handling_priority, 2);
	CU_ASSERT_EQUAL(decode.qos_sub.guaranteed_bitrate_uplink, 122);
	CU_ASSERT_EQUAL(decode.qos_sub.guaranteed_bitrate_downlink, 222);
	CU_ASSERT_EQUAL(decode.qos_sub.spare4, 0); 
	CU_ASSERT_EQUAL(decode.qos_sub.signalling_indication, 1);
	CU_ASSERT_EQUAL(decode.qos_sub.source_statistics_descriptor, 1);
	CU_ASSERT_EQUAL(decode.qos_sub.max_bitrate_downlink_ext1, 22);
	CU_ASSERT_EQUAL(decode.qos_sub.guaranteed_bitrate_downlink_ext1, 11);
	CU_ASSERT_EQUAL(decode.qos_sub.max_bitrate_uplink_ext1, 33);
	CU_ASSERT_EQUAL(decode.qos_sub.guaranteed_bitrate_uplink_ext1, 22);
	CU_ASSERT_EQUAL(decode.qos_sub.max_bitrate_downlink_ext2, 44);
	CU_ASSERT_EQUAL(decode.qos_sub.guaranteed_bitrate_downlink_ext2, 33);
	CU_ASSERT_EQUAL(decode.qos_sub.max_bitrate_uplink_ext2, 34);
	CU_ASSERT_EQUAL(decode.qos_sub.guaranteed_bitrate_uplink_ext2, 23);
	CU_ASSERT_EQUAL(decode.qos_req_length, 21);
	CU_ASSERT_EQUAL(decode.qos_req.allocation_retention_priority, 2);
	CU_ASSERT_EQUAL(decode.qos_req.spare1, 0);
	CU_ASSERT_EQUAL(decode.qos_req.delay_class, 2);
	CU_ASSERT_EQUAL(decode.qos_req.reliablity_class, 2);
	CU_ASSERT_EQUAL(decode.qos_req.peak_throughput, 3);
	CU_ASSERT_EQUAL(decode.qos_req.spare2, 0);
	CU_ASSERT_EQUAL(decode.qos_req.precedence_class, 1);
	CU_ASSERT_EQUAL(decode.qos_req.spare3, 0);
	CU_ASSERT_EQUAL(decode.qos_req.mean_throughput, 4);
	CU_ASSERT_EQUAL(decode.qos_req.traffic_class, 1);
	CU_ASSERT_EQUAL(decode.qos_req.delivery_order, 1);
	CU_ASSERT_EQUAL(decode.qos_req.delivery_erroneous_sdu, 2);
	CU_ASSERT_EQUAL(decode.qos_req.max_sdu_size, 3);
	CU_ASSERT_EQUAL(decode.qos_req.max_bitrate_uplink, 123);
	CU_ASSERT_EQUAL(decode.qos_req.max_bitrate_downlink, 234);
	CU_ASSERT_EQUAL(decode.qos_req.residual_ber, 1);
	CU_ASSERT_EQUAL(decode.qos_req.sdu_error_ratio, 1);
	CU_ASSERT_EQUAL(decode.qos_req.transfer_delay, 1);
	CU_ASSERT_EQUAL(decode.qos_req.traffic_handling_priority, 2);
	CU_ASSERT_EQUAL(decode.qos_req.guaranteed_bitrate_uplink, 122);
	CU_ASSERT_EQUAL(decode.qos_req.guaranteed_bitrate_downlink, 222);
	CU_ASSERT_EQUAL(decode.qos_req.spare4, 0);
	CU_ASSERT_EQUAL(decode.qos_req.signalling_indication, 1);
	CU_ASSERT_EQUAL(decode.qos_req.source_statistics_descriptor, 1);
	CU_ASSERT_EQUAL(decode.qos_req.max_bitrate_downlink_ext1, 22);
	CU_ASSERT_EQUAL(decode.qos_req.guaranteed_bitrate_downlink_ext1, 11);
	CU_ASSERT_EQUAL(decode.qos_req.max_bitrate_uplink_ext1, 33);
	CU_ASSERT_EQUAL(decode.qos_req.guaranteed_bitrate_uplink_ext1, 22);
	CU_ASSERT_EQUAL(decode.qos_req.max_bitrate_downlink_ext2, 44);
	CU_ASSERT_EQUAL(decode.qos_req.guaranteed_bitrate_downlink_ext2, 33);
	CU_ASSERT_EQUAL(decode.qos_req.max_bitrate_uplink_ext2, 34);
	CU_ASSERT_EQUAL(decode.qos_req.guaranteed_bitrate_uplink_ext2, 23);
	CU_ASSERT_EQUAL(decode.qos_neg_length, 21);
	CU_ASSERT_EQUAL(decode.qos_neg.allocation_retention_priority, 2);
	CU_ASSERT_EQUAL(decode.qos_neg.spare1, 0);
	CU_ASSERT_EQUAL(decode.qos_neg.delay_class, 2);
	CU_ASSERT_EQUAL(decode.qos_neg.reliablity_class, 2);
	CU_ASSERT_EQUAL(decode.qos_neg.peak_throughput, 3);
	CU_ASSERT_EQUAL(decode.qos_neg.spare2, 0);
	CU_ASSERT_EQUAL(decode.qos_neg.precedence_class, 1);
	CU_ASSERT_EQUAL(decode.qos_neg.spare3, 0);
	CU_ASSERT_EQUAL(decode.qos_neg.mean_throughput, 4);
	CU_ASSERT_EQUAL(decode.qos_neg.traffic_class, 1);
	CU_ASSERT_EQUAL(decode.qos_neg.delivery_order, 1);
	CU_ASSERT_EQUAL(decode.qos_neg.delivery_erroneous_sdu, 2);
	CU_ASSERT_EQUAL(decode.qos_neg.max_sdu_size, 3);
	CU_ASSERT_EQUAL(decode.qos_neg.max_bitrate_uplink, 123);
	CU_ASSERT_EQUAL(decode.qos_neg.max_bitrate_downlink, 234);
	CU_ASSERT_EQUAL(decode.qos_neg.residual_ber, 1);
	CU_ASSERT_EQUAL(decode.qos_neg.sdu_error_ratio, 1);
	CU_ASSERT_EQUAL(decode.qos_neg.transfer_delay, 1);
	CU_ASSERT_EQUAL(decode.qos_neg.traffic_handling_priority, 2);
	CU_ASSERT_EQUAL(decode.qos_neg.guaranteed_bitrate_uplink, 122);
	CU_ASSERT_EQUAL(decode.qos_neg.guaranteed_bitrate_downlink, 222);
	CU_ASSERT_EQUAL(decode.qos_neg.spare4, 0);
	CU_ASSERT_EQUAL(decode.qos_neg.signalling_indication, 1);
	CU_ASSERT_EQUAL(decode.qos_neg.source_statistics_descriptor, 1);
	CU_ASSERT_EQUAL(decode.qos_neg.max_bitrate_downlink_ext1, 22);
	CU_ASSERT_EQUAL(decode.qos_neg.guaranteed_bitrate_downlink_ext1, 11);
	CU_ASSERT_EQUAL(decode.qos_neg.max_bitrate_uplink_ext1, 33);
	CU_ASSERT_EQUAL(decode.qos_neg.guaranteed_bitrate_uplink_ext1, 22);
	CU_ASSERT_EQUAL(decode.qos_neg.max_bitrate_downlink_ext2, 44);
	CU_ASSERT_EQUAL(decode.qos_neg.guaranteed_bitrate_downlink_ext2, 33);
	CU_ASSERT_EQUAL(decode.qos_neg.max_bitrate_uplink_ext2, 34);
	CU_ASSERT_EQUAL(decode.qos_neg.guaranteed_bitrate_uplink_ext2, 23);
	CU_ASSERT_EQUAL(decode.sequence_number_down, 1);
	CU_ASSERT_EQUAL(decode.sequence_number_up, 2);
	CU_ASSERT_EQUAL(decode.send_npdu_number, 255);
	CU_ASSERT_EQUAL(decode.rcv_npdu_number, 255);
	CU_ASSERT_EQUAL(decode.uplink_teid_cp, 0x372f0000);
	CU_ASSERT_EQUAL(decode.uplink_teid_data1, 0x37300000);
	CU_ASSERT_EQUAL(decode.pdp_ctxt_identifier, 0);
	CU_ASSERT_EQUAL(decode.spare2, 15);
	CU_ASSERT_EQUAL(decode.pdp_type_org, 1);
	CU_ASSERT_EQUAL(decode.pdp_type_number1, 0x21);
	CU_ASSERT_EQUAL(decode.pdp_address_length1, 4);
	CU_ASSERT_EQUAL(decode.pdp_address1.ipv4, 355240599);
	CU_ASSERT_EQUAL(decode.ggsn_addr_cp_length, 4);
	CU_ASSERT_EQUAL(decode.ggsn_addr_cp.ipv4, 355240589);
	CU_ASSERT_EQUAL(decode.ggsn_addr_ut_length, 4);
	CU_ASSERT_EQUAL(decode.ggsn_addr_ut.ipv4, 355240599);
	CU_ASSERT_EQUAL(decode.apn_length, 13);
	CU_ASSERT_STRING_EQUAL(decode.apn, "nextphones.co");
	CU_ASSERT_EQUAL(decode.spare3, 0);
	CU_ASSERT_EQUAL(decode.transaction_identifier1, 10);
	CU_ASSERT_EQUAL(decode.transaction_identifier2, 55);
}

void test_decode_gtpv1_mbms_ue_context_ie(void)
{
	gtpv1_mbms_ue_context_ie_t decode = {0};
	uint8_t buf[SIZE]= {0x9c, 0x00, 0x22, 0x20, 0x37, 0x2f, 0x00, 0x00,
		0x81, 0xf1, 0x21, 0x04, 0x15, 0x2c, 0x8a, 0x97, 0x04, 0x15,
		0x2c, 0x8a, 0x8d, 0x0d, 0x6e, 0x65, 0x78, 0x74, 0x70, 0x68,
		0x6f, 0x6e, 0x65, 0x73, 0x2e, 0x63, 0x6f, 0x01, 0x05};

	CU_ASSERT(decode_gtpv1_mbms_ue_context_ie(buf, &decode) == 37);
	CU_ASSERT(decode_gtpv1_mbms_ue_context_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_mbms_ue_context_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_mbms_ue_context_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_MBMS_UE_CONTEXT);
	CU_ASSERT_EQUAL(decode.header.length, 34);
	CU_ASSERT_EQUAL(decode.linked_nsapi, 2);
	CU_ASSERT_EQUAL(decode.spare1, 0);
	CU_ASSERT_EQUAL(decode.uplink_teid_cp, 0x372f0000);
	CU_ASSERT_EQUAL(decode.enhanced_nsapi, 129);
	CU_ASSERT_EQUAL(decode.spare2, 15);
	CU_ASSERT_EQUAL(decode.pdp_type_org, 1);
	CU_ASSERT_EQUAL(decode.pdp_type_number, 0x21);
	CU_ASSERT_EQUAL(decode.pdp_address_length, 4);
	CU_ASSERT_EQUAL(decode.pdp_address.ipv4, 355240599);
	CU_ASSERT_EQUAL(decode.ggsn_addr_cp_length, 4);
	CU_ASSERT_EQUAL(decode.ggsn_addr_cp.ipv4, 355240589);
	CU_ASSERT_EQUAL(decode.apn_length, 13);
	CU_ASSERT_STRING_EQUAL(decode.apn,"nextphones.co");
	CU_ASSERT_EQUAL(decode.spare3, 0);
	CU_ASSERT_EQUAL(decode.transaction_identifier1, 1);
	CU_ASSERT_EQUAL(decode.transaction_identifier2, 5);
}

void test_decode_gtpv1_ue_ambr_ie(void)
{
	gtpv1_ue_ambr_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xc8, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00,
		0x00, 0x00, 0x01};

	CU_ASSERT(decode_gtpv1_ue_ambr_ie(buf, &decode) == 11);
	CU_ASSERT(decode_gtpv1_ue_ambr_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_ue_ambr_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_ue_ambr_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_UE_AMBR);
	CU_ASSERT_EQUAL(decode.header.length, 8);
	CU_ASSERT_EQUAL(decode.subscribed_ue_ambr_for_uplink, 1);
	CU_ASSERT_EQUAL(decode.subscribed_ue_ambr_for_downlink, 1);

	gtpv1_ue_ambr_ie_t decode_2 = {0};
	uint8_t buf2[SIZE] = {0xc8, 0x00, 0x10, 0x00, 0x00, 0x00, 0x08, 0x00,
		0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x40};

	CU_ASSERT(decode_gtpv1_ue_ambr_ie(buf2, &decode_2) == 19);
	CU_ASSERT(decode_gtpv1_ue_ambr_ie(NULL, &decode_2) == -1);
	CU_ASSERT(decode_gtpv1_ue_ambr_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_ue_ambr_ie(buf2, NULL) == -1);
	CU_ASSERT_EQUAL(decode_2.header.type, GTPV1_IE_UE_AMBR);
	CU_ASSERT_EQUAL(decode_2.header.length, 16);
	CU_ASSERT_EQUAL(decode_2.subscribed_ue_ambr_for_uplink, 8);
	CU_ASSERT_EQUAL(decode_2.subscribed_ue_ambr_for_downlink, 16);
	CU_ASSERT_EQUAL(decode_2.authorized_ue_ambr_for_uplink, 32);
	CU_ASSERT_EQUAL(decode_2.authorized_ue_ambr_for_downlink, 64);
}

void test_decode_gtpv1_ue_scef_pdn_connection_ie(void)
{
	gtpv1_ue_scef_pdn_connection_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xdd, 0x00, 0x13, 0x0d, 0x6e, 0x65, 0x78, 0x74, 
		0x70, 0x68, 0x6f, 0x6e, 0x65, 0x73, 0x2e, 0x63, 0x6f, 0x05,
		0x03, 0x31, 0x31, 0x31};

	CU_ASSERT(decode_gtpv1_ue_scef_pdn_connection_ie(buf, &decode) == 22);
	CU_ASSERT(decode_gtpv1_ue_scef_pdn_connection_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_ue_scef_pdn_connection_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_ue_scef_pdn_connection_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_UE_SCEF_PDN_CONNTECTION);
	CU_ASSERT_EQUAL(decode.header.length, 19);
	CU_ASSERT_EQUAL(decode.apn_length, 13);
	CU_ASSERT_STRING_EQUAL(decode.apn, "nextphones.co");
	CU_ASSERT_EQUAL(decode.spare, 0);
	CU_ASSERT_EQUAL(decode.nsapi, 5);
	CU_ASSERT_EQUAL(decode.scef_id_length, 3);
	CU_ASSERT_STRING_EQUAL(decode.scef_id, "111");
}

void test_decode_gtpv1_auth_triplet_ie(void)
{
	gtpv1_auth_triplet_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x09, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
		0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x00,
		0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};

	CU_ASSERT(decode_gtpv1_auth_triplet_ie(buf, &decode) == 29);
	CU_ASSERT(decode_gtpv1_auth_triplet_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_auth_triplet_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_auth_triplet_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_AUTH_TRIPLET);
	CU_ASSERT_NSTRING_EQUAL(decode.auth_triplet_value.rand, "1111111111111111", 16);
	CU_ASSERT_EQUAL(decode.auth_triplet_value.sres, 2);
	CU_ASSERT_EQUAL(decode.auth_triplet_value.kc, 2);
}

void test_decode_gtpv1_auth_quintuplet_ie(void)
{
	gtpv1_auth_quintuplet_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x88, 0x00, 0x34, 0x31, 0x31, 0x31, 0x31, 0x31,
		0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
		0x31, 0x01, 0x32, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
		0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
		0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
		0x31, 0x31, 0x31, 0x31, 0x31, 0x01, 0x32};

	CU_ASSERT(decode_gtpv1_auth_quintuplet_ie(buf, &decode) == 55);
	CU_ASSERT(decode_gtpv1_auth_quintuplet_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_auth_quintuplet_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_auth_quintuplet_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_AUTH_QUINTUPLET);
	CU_ASSERT_EQUAL(decode.header.length, 52);
	CU_ASSERT_NSTRING_EQUAL(decode.auth_quintuplet_value.rand, "1111111111111111", 16);
	CU_ASSERT_EQUAL(decode.auth_quintuplet_value.xres_length, 1);
	CU_ASSERT_STRING_EQUAL(decode.auth_quintuplet_value.xres, "2");
	CU_ASSERT_NSTRING_EQUAL(decode.auth_quintuplet_value.ck, "1111111111111111", 16);
	CU_ASSERT_NSTRING_EQUAL(decode.auth_quintuplet_value.ik, "1111111111111111", 16);
	CU_ASSERT_EQUAL(decode.auth_quintuplet_value.autn_length, 1);
	CU_ASSERT_STRING_EQUAL(decode.auth_quintuplet_value.autn, "2");
}

void test_decode_gtpv1_src_rnc_pdcp_ctxt_info_ie(void)
{
	gtpv1_src_rnc_pdcp_ctxt_info_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xa1, 0x00, 0x05, 0x67, 0x73, 0x6c, 0x61, 0x62};

	CU_ASSERT(decode_gtpv1_src_rnc_pdcp_ctxt_info_ie(buf, &decode) == 8);
	CU_ASSERT(decode_gtpv1_src_rnc_pdcp_ctxt_info_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_src_rnc_pdcp_ctxt_info_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_src_rnc_pdcp_ctxt_info_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_SRC_RNC_PDCP_CTXT_INFO);
	CU_ASSERT_EQUAL(decode.header.length, 5);
	CU_ASSERT_STRING_EQUAL(decode.rrc_container, "gslab");
}

void test_decode_gtpv1_pdu_numbers_ie(void)
{
	gtpv1_pdu_numbers_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xaf, 0x00, 0x09, 0x01, 0x00, 0x01, 0x00, 0x01,
		0x00, 0x01, 0x00, 0x01};

	CU_ASSERT(decode_gtpv1_pdu_numbers_ie(buf, &decode) == 12);
	CU_ASSERT(decode_gtpv1_pdu_numbers_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_pdu_numbers_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_pdu_numbers_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_PDU_NUMBERS);
	CU_ASSERT_EQUAL(decode.header.length, 9);
	CU_ASSERT_EQUAL(decode.spare, 0);
	CU_ASSERT_EQUAL(decode.nsapi, 1);
	CU_ASSERT_EQUAL(decode.dl_gtpu_seqn_nbr, 1);
	CU_ASSERT_EQUAL(decode.ul_gtpu_seqn_nbr, 1);
	CU_ASSERT_EQUAL(decode.snd_npdu_nbr, 1);
	CU_ASSERT_EQUAL(decode.rcv_npdu_nbr, 1);
}

void test_decode_gtpv1_extension_header_type_list_ie(void)
{
	gtpv1_extension_header_type_list_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x8d, 0x02, 0x01, 0x00};

	CU_ASSERT(decode_gtpv1_extension_header_type_list_ie(buf, &decode) == 4);
	CU_ASSERT(decode_gtpv1_extension_header_type_list_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_extension_header_type_list_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_extension_header_type_list_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.type, GTPV1_IE_EXTENSION_HEADER_TYPE_LIST);
	CU_ASSERT_EQUAL(decode.length, 2);
	CU_ASSERT_EQUAL(decode.extension_type_list[0], 1);
	CU_ASSERT_EQUAL(decode.extension_type_list[1], 0);
}

void test_decode_gtpv1_iov_updates_counter_ie(void)
{
	gtpv1_iov_updates_counter_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xde, 0x00, 0x01, 0x0a};

	CU_ASSERT(decode_gtpv1_iov_updates_counter_ie(buf, &decode) == 4);
	CU_ASSERT(decode_gtpv1_iov_updates_counter_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_iov_updates_counter_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_iov_updates_counter_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_IOV_UPDATES_COUNTER);
	CU_ASSERT_EQUAL(decode.header.length, 1);
	CU_ASSERT_EQUAL(decode.iov_updates_counter, 10);
}

void test_decode_gtpv1_ue_usage_type_ie(void)
{
	gtpv1_ue_usage_type_ie_t decode = {0};
	uint8_t buf[SIZE] = {0xd9, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01};

	CU_ASSERT(decode_gtpv1_ue_usage_type_ie(buf, &decode) == 7);
	CU_ASSERT(decode_gtpv1_ue_usage_type_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_ue_usage_type_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_ue_usage_type_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_UE_USAGE_TYPE);
	CU_ASSERT_EQUAL(decode.header.length, 4);
	CU_ASSERT_EQUAL(decode.ue_usage_type_value, 1);
}

void test_decode_gtpv1_teid_control_plane_ie(void)
{
	gtpv1_teid_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x11, 0x00, 0xff, 0xfe, 0xee};

	CU_ASSERT(decode_gtpv1_teid_ie(buf, &decode) == 5);
	CU_ASSERT(decode_gtpv1_teid_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_teid_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_teid_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_TEID_CONTROL_PLANE);
	CU_ASSERT_EQUAL(decode.teid, 0x0fffeee);
}

void test_decode_gtpv1_additional_rab_setup_info_ie(void)
{
	gtpv1_rab_setup_info_ie_t decode = {0};
	uint8_t buf[SIZE] = {0x92, 0x00, 0x01, 0x02};

	CU_ASSERT(decode_gtpv1_rab_setup_info_ie(buf, &decode) == 4);
	CU_ASSERT(decode_gtpv1_rab_setup_info_ie(NULL, &decode) == -1);
	CU_ASSERT(decode_gtpv1_rab_setup_info_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_rab_setup_info_ie(buf, NULL) == -1);
	CU_ASSERT_EQUAL(decode.header.type, GTPV1_IE_ADDITIONAL_RAB_SETUP_INFO);
	CU_ASSERT_EQUAL(decode.header.length, 1);
	CU_ASSERT_EQUAL(decode.spare, 0);
	CU_ASSERT_EQUAL(decode.nsapi, 2);

	gtpv1_rab_setup_info_ie_t decode1 = {0};
	uint8_t buf1[SIZE] = {0x92, 0x00, 0x15, 0x02, 0x00, 0xff, 0xfe, 0xee,
		0x20, 0x01, 0xdb, 0x80, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55,
		0x66, 0x66, 0x77, 0x77, 0x88, 0x85};

	CU_ASSERT(decode_gtpv1_rab_setup_info_ie(buf1, &decode1) == 24);
	CU_ASSERT(decode_gtpv1_rab_setup_info_ie(NULL, &decode1) == -1);
	CU_ASSERT(decode_gtpv1_rab_setup_info_ie(NULL, NULL) == -1);
	CU_ASSERT(decode_gtpv1_rab_setup_info_ie(buf1, NULL) == -1);
	CU_ASSERT_EQUAL(decode1.header.type, GTPV1_IE_ADDITIONAL_RAB_SETUP_INFO);
	CU_ASSERT_EQUAL(decode1.header.length, 21);
	CU_ASSERT_EQUAL(decode1.spare, 0);
	CU_ASSERT_EQUAL(decode1.nsapi, 2);
	CU_ASSERT_EQUAL(decode1.teid, 0x0fffeee);
	char addr[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &decode1.rnc_ip_addr.ipv6, addr, INET6_ADDRSTRLEN);
	CU_ASSERT_NSTRING_EQUAL(addr, "2001:db80:3333:4444:5555:6666:7777:8885",39);
}
