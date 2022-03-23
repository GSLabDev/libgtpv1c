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

#include "test_encoder_gtpv1_ies.h"

void remove_white_spaces(uint8_t *str)
{
	int i = 0, j = 0;
	while (str[i])
	{
		if (str[i] != ' ')
			str[j++] = str[i];
		i++;
	}
	str[j] = '\0';
	return;
}

int hexdump(void const *data, uint64_t len, uint64_t split, uint64_t line_len, char *result)
{
	uint8_t const *inptr = data;
	uint8_t *ptr;
	int rem = len;
	uint8_t buf[SIZE];

	while (rem > 0) {
		int len_rem = rem;
		int count = 0;
		ptr = buf;
		for (int itr=0; itr<line_len; itr++) {
			if (split == count++) {
				ptr += 2;
				count = 1;
			}
			if (len_rem) {
				sprintf((char *)ptr, "%02x ", *((unsigned char *) inptr + itr));
				len_rem--;
			}
			ptr += 3;
		}
		rem -= line_len;
		inptr += line_len;
		*ptr = '\0';
	}
	remove_white_spaces(buf);
	if (strcmp(result, (char*)buf) == 0)
	{
		return 0;
	}
	return -1;
}

void test_encode_gtpv1_header(void)
{
	gtpv1_header_t encode = {0};
	encode.version = 1;
	encode.protocol_type = 1;
	encode.spare = 0;
	encode.extension_header = 0;
	encode.seq_num_flag = 0;
	encode.n_pdu_flag = 0;
	encode.message_type = 16;
	encode.message_len = 194;
	encode.teid = 0;
	encode.seq = 0;
	encode.n_pdu_number = 0;
	encode.next_extension_header_type = 0;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_header(&encode, buf) == 8);
	CU_ASSERT(encode_gtpv1_header(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_header(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_header(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 8, 64, 64, "301000c200000000") == 0);
}

void test_encode_gtpv1_cause_ie(void)
{
	gtpv1_cause_ie_t encode = {0};
	encode.header.type = GTPV1_IE_CAUSE;
	encode.cause_value = 128;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_cause_ie(&encode, buf) == 2);
	CU_ASSERT(encode_gtpv1_cause_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_cause_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_cause_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 2, 64, 64, "0180") == 0);
}

void test_encode_gtpv1_imsi_ie(void)
{
	gtpv1_imsi_ie_t encode = {0};
	encode.header.type = GTPV1_IE_IMSI;
	encode.imsi_number_digits = 272031000000000;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_imsi_ie(&encode, buf) == 9);
	CU_ASSERT(encode_gtpv1_imsi_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_imsi_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_imsi_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 9 , 64 ,64, "0272021300000000f0") == 0);
}

void test_encode_gtpv1_routing_area_identity_ie(void)
{
	gtpv1_routing_area_identity_ie_t encode = {0};
	encode.header.type = GTPV1_IE_ROUTEING_AREA_IDENTITY;
	encode.rai_value.mcc_digit_2 = 0x0;
	encode.rai_value.mcc_digit_1 = 0x4;
	encode.rai_value.mnc_digit_3 = 0x8;
	encode.rai_value.mcc_digit_3 = 0x4;
	encode.rai_value.mnc_digit_2 = 0x7;
	encode.rai_value.mnc_digit_1 = 0x0;
	encode.rai_value.lac = 0x14;
	encode.rai_value.rac = 0x14;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_routing_area_identity_ie(&encode, buf) == 7);
	CU_ASSERT(encode_gtpv1_routing_area_identity_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_routing_area_identity_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_routing_area_identity_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 7, 64, 64, "0304f487001414") == 0);

	gtpv1_routing_area_identity_ie_t encode_1 = {0};
	encode_1.header.type = GTPV1_IE_ROUTEING_AREA_IDENTITY;
	encode_1.rai_value.mcc_digit_2 = 0x2;
	encode_1.rai_value.mcc_digit_1 = 0x5;
	encode_1.rai_value.mnc_digit_3 = 0x8;
	encode_1.rai_value.mcc_digit_3 = 0x3;
	encode_1.rai_value.mnc_digit_1 = 0x1;
	encode_1.rai_value.mnc_digit_2 = 0x8;
	encode_1.rai_value.lac = 20;
	encode_1.rai_value.rac = 20;
	uint8_t buf_1[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_routing_area_identity_ie(&encode_1, buf_1) == 7);
	CU_ASSERT(hexdump(buf_1, 7, 64, 64, "03258381001414") == 0);

}

void test_encode_gtpv1_reordering_req_ie(void)
{
	gtpv1_reordering_req_ie_t encode = {0};
	encode.header.type = GTPV1_IE_REORDERING_REQ;
	encode.spare = 0;
	encode.reord_req = 0;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_reordering_req_ie(&encode, buf) == 2);
	CU_ASSERT(encode_gtpv1_reordering_req_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_reordering_req_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_reordering_req_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 2, 64, 64, "0800") == 0);
}

void test_encode_gtpv1_recovery_ie(void)
{
	gtpv1_recovery_ie_t encode = {0};
	encode.header.type = GTPV1_IE_RECOVERY;
	encode.restart_counter = 2;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_recovery_ie(&encode, buf) == 2);
	CU_ASSERT(encode_gtpv1_recovery_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_recovery_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_recovery_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 2, 64, 64, "0e02") == 0);
}

void test_encode_gtpv1_selection_mode_ie(void)
{
	gtpv1_selection_mode_ie_t encode = {0};
	encode.header.type = GTPV1_IE_SELECTION_MODE;
	encode.spare2 = 0;
	encode.selec_mode = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_selection_mode_ie(&encode, buf) == 2);
	CU_ASSERT(encode_gtpv1_selection_mode_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_selection_mode_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_selection_mode_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 2, 64, 64, "0f01") == 0);
	}

void test_encode_gtpv1_teid_ie(void)
{
	gtpv1_teid_ie_t encode = {0};
	encode.header.type = GTPV1_IE_TEID_DATA_1;
	encode.teid = 0x0fffeee;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_teid_ie(&encode, buf) == 5);
	CU_ASSERT(encode_gtpv1_teid_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_teid_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_teid_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 5, 64, 64, "1000fffeee") == 0);
}

void test_encode_gtpv1_teardown_ind_ie(void)
{
	gtpv1_teardown_ind_ie_t encode = {0};
	encode.header.type = GTPV1_IE_TEARDOWN_IND;
	encode.spare = 0;
	encode.teardown_ind = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_teardown_ind_ie(&encode, buf) == 2);
	CU_ASSERT(encode_gtpv1_teardown_ind_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_teardown_ind_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_teardown_ind_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 2, 64, 64, "1301") == 0);
	}

void test_encode_gtpv1_nsapi_ie(void)
{
	gtpv1_nsapi_ie_t encode = {0};
	encode.header.type = GTPV1_IE_NSAPI;
	encode.spare = 0;
	encode.nsapi_value = 5;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_nsapi_ie(&encode, buf) == 2);
	CU_ASSERT(encode_gtpv1_nsapi_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_nsapi_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_nsapi_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 2, 64, 64, "1405") == 0);
}

void test_encode_gtpv1_chrgng_char_ie(void)
{
	gtpv1_chrgng_char_ie_t encode = {0};
	encode.header.type = GTPV1_IE_CHRGNG_CHAR;
	encode.chrgng_char_val = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_chrgng_char_ie(&encode, buf) == 3);
	CU_ASSERT(encode_gtpv1_chrgng_char_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_chrgng_char_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_chrgng_char_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 3, 64, 64, "1a0001") == 0);
}

void test_encode_gtpv1_trace_reference_ie(void)
{
	gtpv1_trace_reference_ie_t encode = {0};
	encode.header.type = GTPV1_IE_TRACE_REFERENCE;
	encode.trace_reference = 9;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_trace_reference_ie(&encode, buf) == 3);
	CU_ASSERT(encode_gtpv1_trace_reference_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_trace_reference_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_trace_reference_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 3, 64, 64, "1b0009") == 0);
}

void test_encode_gtpv1_trace_type_ie(void)
{
	gtpv1_trace_type_ie_t encode = {0};
	encode.header.type = GTPV1_IE_TRACE_TYPE;
	encode.trace_type = 9;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_trace_type_ie(&encode, buf) == 3);
	CU_ASSERT(encode_gtpv1_trace_type_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_trace_type_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_trace_type_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 3, 64, 64, "1c0009") == 0);
}

void test_encode_gtpv1_charging_id_ie(void)
{
	gtpv1_charging_id_ie_t encode = {0};
	encode.header.type = GTPV1_IE_CHARGING_ID;
	encode.chrgng_id_val = 0x0330410b;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_charging_id_ie(&encode, buf) == 5);
	CU_ASSERT(encode_gtpv1_charging_id_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_charging_id_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_charging_id_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 5, 64, 64, "7f0330410b") == 0);
}

void test_encode_gtpv1_end_user_address_ie(void)
{
	gtpv1_end_user_address_ie_t encode = {0};
	encode.header.type = GTPV1_IE_END_USER_ADDR;
	encode.header.length = 6;
	encode.spare = 0xf;
	encode.pdp_type_org = 1;
	encode.pdp_type_number = 0x21;
	encode.pdp_address.ipv4 = 3565240599;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_end_user_address_ie(&encode, buf) == 9);
	CU_ASSERT(encode_gtpv1_end_user_address_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_end_user_address_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_end_user_address_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 9, 64, 64, "800006f121d4814117") == 0);

	gtpv1_end_user_address_ie_t encode1 = {0};
	encode1.header.type = GTPV1_IE_END_USER_ADDR;
	encode1.header.length = 22;
	encode1.spare = 0xf;
	encode1.pdp_type_org = 1;
	encode1.pdp_type_number = 0x8D;
	encode1.pdp_address.ipv4 = 3232235564;
	char *str = "2001:db80:3333:4444:5555:6666:7777:8888";
	inet_pton(AF_INET6, str, encode1.pdp_address.ipv6);
	uint8_t buf1[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_end_user_address_ie(&encode1, buf1) == 25);
	CU_ASSERT(encode_gtpv1_end_user_address_ie(NULL, buf1) == -1);
	CU_ASSERT(encode_gtpv1_end_user_address_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_end_user_address_ie(&encode1, NULL) == -1);
	CU_ASSERT(hexdump(buf1, 25, 64, 64, "800016f18dc0a8002c2001db80333344445555666677778888") == 0);

	gtpv1_end_user_address_ie_t encode2 = {0};
	encode2.header.type = GTPV1_IE_END_USER_ADDR;
	encode2.header.length = 2;
	encode2.spare = 0xf;
	encode2.pdp_type_org = 0;
	encode2.pdp_type_number = 0x21;

	uint8_t buf2[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_end_user_address_ie(&encode2, buf2) == 5);
	CU_ASSERT(encode_gtpv1_end_user_address_ie(NULL, buf2) == -1);
	CU_ASSERT(encode_gtpv1_end_user_address_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_end_user_address_ie(&encode2, NULL) == -1);
	CU_ASSERT(hexdump(buf2, 5, 64, 64, "800002f021") == 0);
}

void test_encode_gtpv1_apn_ie(void)
{
	gtpv1_apn_ie_t encode = {0};
	encode.header.type = GTPV1_IE_APN;
	encode.header.length = 13;
	strncpy((char *)&encode.apn_value,"nextphones.co",13);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_apn_ie(&encode, buf) == 16);
	CU_ASSERT(encode_gtpv1_apn_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_apn_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_apn_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 16, 64, 64, "83000d6e65787470686f6e65732e636f") == 0);
}

void test_encode_gtpv1_protocol_config_options_ie(void)
{
	gtpv1_protocol_config_options_ie_t encode = {0};	
	encode.header.type = GTPV1_IE_PROTOCOL_CONFIG_OPTIONS;
	encode.header.length = 25;
	encode.pco.pco_flag_ext = 1;
	encode.pco.pco_flag_spare = 0;
	encode.pco.pco_cfg_proto = 1;
	encode.pco.pco_content_count  = 2;
	encode.pco.pco_content[0].prot_or_cont_id = 2;
	encode.pco.pco_content[0].length = 9;
	strncpy((char *)&encode.pco.pco_content[0].content,"355240599",9);
	encode.pco.pco_content[1].prot_or_cont_id = 2;
	encode.pco.pco_content[1].length  = 9;
	strncpy((char *)&encode.pco.pco_content[1].content,"111111111",9);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_protocol_config_options_ie(&encode, buf) == 28);
	CU_ASSERT(encode_gtpv1_protocol_config_options_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_protocol_config_options_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_protocol_config_options_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 28, 64, 64, "84001981000209333535323430353939000209313131313131313131") == 0);
}

void test_encode_gtpv1_gsn_addr_ie(void)
{
	gtpv1_gsn_addr_ie_t encode = {0};
	encode.header.type = GTPV1_IE_GSN_ADDR;
	encode.header.length = 4;
	encode.gsn_address.ipv4 = 3565240589;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_gsn_address_ie(&encode, buf) == 7);
	CU_ASSERT(encode_gtpv1_gsn_address_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_gsn_address_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_gsn_address_ie(&encode,NULL ) == -1);
	CU_ASSERT(hexdump(buf, 7, 64, 64, "850004d481410d") == 0);

	gtpv1_gsn_addr_ie_t encode1 = {0};
	encode1.header.type = GTPV1_IE_GSN_ADDR;
	encode1.header.length = 16;
	char *str = "2001:db80:3333:4444:5555:6666:7777:8888";
	inet_pton(AF_INET6, str, encode1.gsn_address.ipv6);
	uint8_t buf1[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_gsn_address_ie(&encode1, buf1) == 19);
	CU_ASSERT(encode_gtpv1_gsn_address_ie(NULL, buf1) == -1);
	CU_ASSERT(encode_gtpv1_gsn_address_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_gsn_address_ie(&encode1,NULL ) == -1);
	CU_ASSERT(hexdump(buf1, 19, 64, 64, "8500102001db80333344445555666677778888") == 0);
}

void test_encode_gtpv1_msisdn_ie(void)
{
	gtpv1_msisdn_ie_t encode = {0};
	encode.header.type = GTPV1_IE_MSISDN;
	encode.header.length = 2;
	strncpy((char *)&encode.msisdn_number_digits, "22",2);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_msisdn_ie(&encode, buf) == 5);
	CU_ASSERT(encode_gtpv1_msisdn_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_msisdn_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_msisdn_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 5, 64, 64, "8600023232") == 0);
}

void test_encode_gtpv1_qos_ie(void)
{
	gtpv1_qos_ie_t encode = {0};
	encode.header.type = GTPV1_IE_QOS;
	encode.header.length = 21;
	encode.qos.allocation_retention_priority = 2;
	encode.qos.spare1 = 0;
	encode.qos.delay_class = 2;
	encode.qos.reliablity_class = 2;
	encode.qos.peak_throughput = 3;
	encode.qos.spare2 = 0;
	encode.qos.precedence_class = 1;
	encode.qos.spare3 = 0;
	encode.qos.mean_throughput = 4;
	encode.qos.traffic_class = 1;
	encode.qos.delivery_order = 1;
	encode.qos.delivery_erroneous_sdu = 2;
	encode.qos.max_sdu_size = 3;
	encode.qos.max_bitrate_uplink = 123;
	encode.qos.max_bitrate_downlink = 234;
	encode.qos.residual_ber = 1;
	encode.qos.sdu_error_ratio = 1;
	encode.qos.transfer_delay = 1;
	encode.qos.traffic_handling_priority = 2;
	encode.qos.guaranteed_bitrate_uplink = 122;
	encode.qos.guaranteed_bitrate_downlink = 222;
	encode.qos.spare4 = 0;
	encode.qos.signalling_indication = 1;
	encode.qos.source_statistics_descriptor = 1;
	encode.qos.max_bitrate_downlink_ext1 = 22;
	encode.qos.guaranteed_bitrate_downlink_ext1 = 11;
	encode.qos.max_bitrate_uplink_ext1 = 33;
	encode.qos.guaranteed_bitrate_uplink_ext1 = 22;
	encode.qos.max_bitrate_downlink_ext2 = 44;
	encode.qos.guaranteed_bitrate_downlink_ext2 = 33;
	encode.qos.max_bitrate_uplink_ext2 = 34;
	encode.qos.guaranteed_bitrate_uplink_ext2 = 23;

	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_qos_ie(&encode, buf) == 24);
	CU_ASSERT(encode_gtpv1_qos_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_qos_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_qos_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 24, 64, 64, "870015021231042a037bea11067ade11160b21162c212217") == 0);
}

void test_encode_gtpv1_traffic_flow_tmpl_ie(void)
{
	gtpv1_traffic_flow_tmpl_ie_t encode = {0};
	encode.header.type = GTPV1_IE_TFT;
	encode.header.length = 19;
	encode.tft_op_code = 1;
	encode.e_bit = 1;
	encode.no_packet_filters = 2;
	encode.packet_filter_list_new[0].spare = 0;
	encode.packet_filter_list_new[0].filter_direction = 1;
	encode.packet_filter_list_new[0].filter_id = 5;
	encode.packet_filter_list_new[0].filter_eval_precedence = 1;
	encode.packet_filter_list_new[0].filter_content_length = 1;
	encode.packet_filter_list_new[0].filter_content[0] = 1;
	encode.packet_filter_list_new[1].spare = 0;
	encode.packet_filter_list_new[1].filter_direction = 2;
	encode.packet_filter_list_new[1].filter_id = 5;
	encode.packet_filter_list_new[1].filter_eval_precedence = 1;
	encode.packet_filter_list_new[1].filter_content_length = 2;
	encode.packet_filter_list_new[1].filter_content[0] = 1;
	encode.packet_filter_list_new[1].filter_content[1] = 0;
	encode.parameters_list[0].parameter_id = 1;
	encode.parameters_list[0].parameter_content_length = 2;
	encode.parameters_list[0].parameter_content[0] = 1;
	encode.parameters_list[0].parameter_content[1] = 2;
	encode.parameters_list[1].parameter_id = 1;
	encode.parameters_list[1].parameter_content_length = 3;
	encode.parameters_list[1].parameter_content[0] = 3;
	encode.parameters_list[1].parameter_content[1] = 2;
	encode.parameters_list[1].parameter_content[2] = 0;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_traffic_flow_tmpl_ie(&encode, buf) == 22);
	CU_ASSERT(encode_gtpv1_traffic_flow_tmpl_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_traffic_flow_tmpl_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_traffic_flow_tmpl_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 22, 64, 64, "89001332150101012501020100010201020103030200") == 0);
}

void test_encode_gtpv1_trigger_id_ie(void)
{
	gtpv1_trigger_id_ie_t encode = {0};
	encode.header.type = GTPV1_IE_TRIGGER_ID;
	encode.header.length = 5;
	strncpy((char *)&encode.trigger_id,"22222",5);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_trigger_id_ie(&encode, buf) == 8);
	CU_ASSERT(encode_gtpv1_trigger_id_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_trigger_id_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_trigger_id_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 8, 64, 64, "8e00053232323232") == 0);
}

void test_encode_gtpv1_omc_identity_ie(void)
{
	gtpv1_omc_identity_ie_t encode = {0};
	encode.header.type = GTPV1_IE_OMC_IDENTITY;
	encode.header.length = 7;
	strncpy((char *)&encode.omc_identity,"abc.com",7);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_omc_identity_ie(&encode, buf) == 10);
	CU_ASSERT(encode_gtpv1_omc_identity_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_omc_identity_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_omc_identity_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 10, 64, 64, "8f00076162632e636f6d") == 0);
}

void test_encode_gtpv1_common_flag_ie(void)
{
	gtpv1_common_flag_ie_t encode = {0};
	encode.header.type = GTPV1_IE_COMMON_FLAG;
	encode.header.length = 1;
	encode.dual_addr_bearer_flag = 1;
	encode.upgrade_qos_supported = 1;
	encode.nrsn = 1;
	encode.no_qos_negotiation = 1;
	encode.ran_procedures_ready = 1;
	encode.mbms_counting_information = 1;
	encode.mbms_service_type = 1;
	encode.prohibit_payload_compression = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_common_flag_ie(&encode, buf) == 4);
	CU_ASSERT(encode_gtpv1_common_flag_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_common_flag_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_common_flag_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 4, 64, 64, "940001ff") == 0);
}

void test_encode_gtpv1_apn_restriction_ie(void)
{
	gtpv1_apn_restriction_ie_t encode = {0};
	encode.header.type = GTPV1_IE_APN_RESTRICTION;
	encode.header.length = 1;
	encode.restriction_type_value = 12;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_apn_restriction_ie(&encode, buf) == 4);
	CU_ASSERT(encode_gtpv1_apn_restriction_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_apn_restriction_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_apn_restriction_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 4, 64, 64, "9500010c") == 0);
}

void test_encode_gtpv1_rat_type_ie(void)
{
	gtpv1_rat_type_ie_t encode = {0};
	encode.header.type = GTPV1_IE_RAT_TYPE;
	encode.header.length = 1;
	encode.rat_type = 2;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_rat_type_ie(&encode, buf) == 4);
	CU_ASSERT(encode_gtpv1_rat_type_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_rat_type_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_rat_type_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 4, 64, 64, "97000102") == 0);
}

void test_encode_gtpv1_user_location_information_ie(void)
{
	gtpv1_user_location_information_ie_t encode = {0};
	encode.header.type = GTPV1_IE_USER_LOCATION_INFORMATION;
	encode.header.length = 8;
	encode.geographic_location_type = 1;
	encode.mcc_digit_2 = 0x6;
	encode.mcc_digit_1 = 0x3;
	encode.mnc_digit_3 = 0x9;
	encode.mcc_digit_3 = 0x8;
	encode.mnc_digit_2 = 0x4;
	encode.mnc_digit_1 = 0x0;
	encode.lac = 1;
	encode.ci_sac_rac = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_user_location_information_ie(&encode, buf) == 11);
	CU_ASSERT(encode_gtpv1_user_location_information_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_user_location_information_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_user_location_information_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 11, 64, 64, "9800080163f89400010001") == 0);


	gtpv1_user_location_information_ie_t encode_1 = {0};
	encode_1.header.type = GTPV1_IE_USER_LOCATION_INFORMATION;
	encode_1.header.length = 8;
	encode_1.geographic_location_type = 0x1;
	encode_1.mcc_digit_2 = 0x6;
	encode_1.mcc_digit_1 = 0x3;
	encode_1.mnc_digit_3 = 0x9;
	encode_1.mcc_digit_3 = 0x8;
	encode_1.mnc_digit_2 = 0x4;
	encode_1.mnc_digit_1 = 0x1;
	encode_1.lac = 1;
	encode_1.ci_sac_rac = 1;
	uint8_t buf_1[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_user_location_information_ie(&encode_1, buf_1) == 11);
	CU_ASSERT(hexdump(buf_1, 11, 64, 64, "9800080163984100010001") == 0);
}

void test_encode_gtpv1_ms_time_zone_ie(void)
{
	gtpv1_ms_time_zone_ie_t encode = {0};
	encode.header.type = GTPV1_IE_MS_TIME_ZONE;
	encode.header.length = 2;
	encode.time_zone = 1;
	encode.spare = 0;
	encode.daylight_saving_time = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_ms_time_zone_ie(&encode, buf) == 5);
	CU_ASSERT(encode_gtpv1_ms_time_zone_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_ms_time_zone_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_ms_time_zone_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 5, 64, 64, "9900020101") == 0);
}

void test_encode_gtpv1_imei_ie(void)
{
	gtpv1_imei_ie_t encode = {0};
	encode.header.type = GTPV1_IE_IMEI_SV;
	encode.header.length = 8;
	encode.imei_sv = 0b0001000100010001000100010001000100100010001000100010001000010001;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_imei_ie(&encode, buf) == 11);
	CU_ASSERT(encode_gtpv1_imei_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_imei_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_imei_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 11, 64, 64, "9a00081111111122222211") == 0);
}

void test_encode_gtpv1_camel_charging_information_container_ie(void)
{
	gtpv1_camel_charging_information_container_ie_t encode = {0};
	encode.header.type = GTPV1_IE_CAMEL_CHARGING_INFORMATION_CONTAINER;
	encode.header.length = 2;
	strncpy((char *)&encode.camel_information_pdp_ie, "11", 2);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_camel_charging_information_container_ie(&encode, buf) == 5);
	CU_ASSERT(encode_gtpv1_camel_charging_information_container_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_camel_charging_information_container_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_camel_charging_information_container_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 5, 64, 64, "9b00023131") == 0);
}

void test_encode_gtpv1_additional_trace_information_ie(void)
{
	gtpv1_additional_trace_information_ie_t encode = {0};
	encode.header.type = GTPV1_IE_ADDITIONAL_TRACE_INFORMATION;
	encode.header.length = 9;
	encode.trace_reference_2 = 1;
	encode.trace_recording_session_reference = 1;
	encode.spare1 = 0;
	encode.triggering_events_in_ggsn_mbms_ctxt = 0;
	encode.triggering_events_in_ggsn_pdp_ctxt = 1;
	encode.trace_depth = 1;
	encode.spare2 = 0;
	encode.list_of_interfaces_in_ggsn_gmb = 0;
	encode.list_of_interfaces_in_ggsn_gi = 0;
	encode.list_of_interfaces_in_ggsn_gn = 1;
	encode.trace_activity_control = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_additional_trace_information_ie(&encode, buf) == 12);
	CU_ASSERT(encode_gtpv1_additional_trace_information_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_additional_trace_information_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_additional_trace_information_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 12, 64, 64, "a20009000001000101010101") == 0);
}

void test_encode_gtpv1_ms_info_change_reporting_action_ie(void)
{
	gtpv1_ms_info_change_reporting_action_ie_t encode = {0};
	encode.header.type = GTPV1_IE_MS_INFO_CHANGE_REPORTING_ACTION;
	encode.header.length = 1;
	encode.action = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_ms_info_change_reporting_action_ie(&encode, buf) == 4);
	CU_ASSERT(encode_gtpv1_ms_info_change_reporting_action_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_ms_info_change_reporting_action_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_ms_info_change_reporting_action_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 4, 64, 64, "b5000101") == 0);
}

void test_encode_gtpv1_direct_tunnel_flag_ie(void)
{
	gtpv1_direct_tunnel_flag_ie_t encode = {0};
	encode.header.type = GTPV1_IE_DIRECT_TUNNEL_FLAG;
	encode.header.length = 1;
	encode.spare = 0;
	encode.ei = 1;
	encode.gcsi = 1;
	encode.dti = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_direct_tunnel_flag_ie(&encode, buf) == 4);
	CU_ASSERT(encode_gtpv1_direct_tunnel_flag_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_direct_tunnel_flag_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_direct_tunnel_flag_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 4, 64, 64, "b6000107") == 0);
}

void test_encode_gtpv1_correlation_id_ie(void)
{
	gtpv1_correlation_id_ie_t encode = {0};
	encode.header.type = GTPV1_IE_CORRELATION_ID;
	encode.header.length = 1;
	encode.correlation_id = 5;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_correlation_id_ie(&encode, buf) == 4);
	CU_ASSERT(encode_gtpv1_correlation_id_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_correlation_id_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_correlation_id_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 4, 64, 64, "b7000105") == 0);
}

void test_encode_gtpv1_bearer_control_mode_ie(void)
{
	gtpv1_bearer_control_mode_ie_t encode = {0};
	encode.header.type = GTPV1_IE_BEARER_CONTROL_MODE;
	encode.header.length = 1;
	encode.bearer_control_mode = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_bearer_control_mode_ie(&encode, buf) == 4);
	CU_ASSERT(encode_gtpv1_bearer_control_mode_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_bearer_control_mode_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_bearer_control_mode_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 4, 64, 64, "b8000101") == 0);
}

void test_encode_gtpv1_evolved_allocation_retention_priority_1_ie(void)
{
	gtpv1_evolved_allocation_retention_priority_1_ie_t encode = {0};
	encode.header.type = GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_I;
	encode.header.length = 1;
	encode.spare = 0;
	encode.pci = 1;
	encode.pl = 12;
	encode.spare2 = 0;
	encode.pvi = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_evolved_allocation_retention_priority_1_ie(&encode, buf) == 4);
	CU_ASSERT(encode_gtpv1_evolved_allocation_retention_priority_1_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_evolved_allocation_retention_priority_1_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_evolved_allocation_retention_priority_1_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 4, 64, 64, "bf000171") == 0);
}

void test_encode_gtpv1_extended_common_flag_ie(void)
{
	gtpv1_extended_common_flag_ie_t encode = {0};
	encode.header.type = GTPV1_IE_EXTENDED_COMMON_FLAG;
	encode.header.length = 1;
	encode.uasi = 1;
	encode.bdwi = 1;
	encode.pcri = 1;
	encode.vb = 1;
	encode.retloc = 1;
	encode.cpsr = 1;
	encode.ccrsi = 1;
	encode.unauthenticated_imsi = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_extended_common_flags_ie(&encode, buf) == 4);
	CU_ASSERT(encode_gtpv1_extended_common_flags_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_extended_common_flags_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_extended_common_flags_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 4, 64, 64, "c10001ff") == 0);
}

void test_encode_gtpv1_user_csg_information_ie(void)
{
	gtpv1_user_csg_information_ie_t encode = {0};
	encode.header.type = GTPV1_IE_USER_CSG_INFORMATION;
	encode.header.length = 8;
	encode.mcc_digit_2 = 0x5;
	encode.mcc_digit_1 = 0x1;
	encode.mnc_digit_3 = 0x8;
	encode.mcc_digit_3 = 0x1;
	encode.mnc_digit_2 = 0x3;
	encode.mnc_digit_1 = 0x0;
	encode.spare = 0;
	encode.csg_id = 1;
	encode.csg_id_II = 1;
	encode.access_mode = 1;
	encode.spare2 = 0;
	encode.cmi = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_user_csg_information_ie(&encode, buf) == 11);
	CU_ASSERT(encode_gtpv1_user_csg_information_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_user_csg_information_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_user_csg_information_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 11, 64, 64, "c2000851f1830100000141") == 0);

	gtpv1_user_csg_information_ie_t encode_1 = {0};
	encode_1.header.type = GTPV1_IE_USER_CSG_INFORMATION;
	encode_1.header.length = 8;
	encode_1.mcc_digit_2 = 0x5;
	encode_1.mcc_digit_1 = 0x1;
	encode_1.mnc_digit_3 = 0x8;
	encode_1.mcc_digit_3 = 0x1;
	encode_1.mnc_digit_2 = 0x3;
	encode_1.mnc_digit_1 = 0x1;
	encode_1.spare = 0;
	encode_1.csg_id = 1;
	encode_1.csg_id_II = 1;
	encode_1.access_mode = 1;
	encode_1.spare2 = 0;
	encode_1.cmi = 1;
	uint8_t buf_1[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_user_csg_information_ie(&encode_1, buf_1) == 11);
	CU_ASSERT(hexdump(buf_1, 11, 64, 64, "c200085181310100000141") == 0);

}

void test_encode_gtpv1_csg_information_reporting_action_ie(void)
{
	gtpv1_csg_information_reporting_action_ie_t encode = {0};
	encode.header.type = GTPV1_IE_CSG_INFORMATION_REPORTING_ACTION;
	encode.header.length = 1;
	encode.spare = 0;
	encode.ucuhc = 1;
	encode.ucshc = 1;
	encode.uccsg = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_csg_information_reporting_action_ie(&encode, buf) == 4);
	CU_ASSERT(encode_gtpv1_csg_information_reporting_action_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_csg_information_reporting_action_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_csg_information_reporting_action_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 4, 64, 64, "c3000107") == 0);
}

void test_encode_gtpv1_apn_ambr_ie(void)
{
	gtpv1_apn_ambr_ie_t encode = {0};
	encode.header.type = GTPV1_IE_APN_AMBR;
	encode.header.length = 8;
	encode.apn_ambr_uplink = 0;
	encode.apn_ambr_downlink = 7;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_apn_ambr_ie(&encode, buf) == 11);
	CU_ASSERT(encode_gtpv1_apn_ambr_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_apn_ambr_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_apn_ambr_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 11, 64, 64, "c600080000000000000007") == 0);
}

void test_encode_gtpv1_ggsn_back_off_time_ie(void)
{
	gtpv1_ggsn_back_off_time_ie_t encode = {0};
	encode.header.type = GTPV1_IE_GGSN_BACK_OFF_TIME;
	encode.header.length = 1;
	encode.timer_unit = 0;
	encode.timer_value = 8;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_ggsn_back_off_time_ie(&encode, buf) == 4);
	CU_ASSERT(encode_gtpv1_ggsn_back_off_time_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_ggsn_back_off_time_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_ggsn_back_off_time_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 4, 64, 64, "ca000108") == 0);
} 

void test_encode_gtpv1_signalling_priority_indication_ie(void)
{
	gtpv1_signalling_priority_indication_ie_t encode = {0};
	encode.header.type = GTPV1_IE_SIGNALLING_PRIORITY_INDICATION;
	encode.header.length = 1;
	encode.spare = 0;
	encode.lapi = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_signalling_priority_indication_ie(&encode, buf) == 4);
	CU_ASSERT(encode_gtpv1_signalling_priority_indication_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_signalling_priority_indication_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_signalling_priority_indication_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 4, 64, 64, "cb000101") == 0);
} 

void test_encode_gtpv1_uli_timestamp_ie(void)
{
	gtpv1_uli_timestamp_ie_t encode = {0};
	encode.header.type = GTPV1_IE_ULI_TIMESTAMP;
	encode.header.length = 4;
	encode.timestamp_value = 32;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_uli_timestamp_ie(&encode, buf) == 7);
	CU_ASSERT(encode_gtpv1_uli_timestamp_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_uli_timestamp_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_uli_timestamp_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 7, 64, 64, "d6000400000020") == 0);
} 

void test_encode_gtpv1_cn_operator_selection_entity_ie(void)
{
	gtpv1_cn_operator_selection_entity_ie_t encode = {0};
	encode.header.type = GTPV1_IE_CN_OPERATOR_SELECTION_ENTITY;
	encode.header.length = 1;
	encode.spare = 0;
	encode.selection_entity = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_cn_operator_selection_entity_ie(&encode, buf) == 4);
	CU_ASSERT(encode_gtpv1_cn_operator_selection_entity_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_cn_operator_selection_entity_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_cn_operator_selection_entity_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 4, 64, 64, "d8000101") == 0);
}

void test_encode_gtpv1_extended_common_flag_2_ie(void)
{
	gtpv1_extended_common_flag_2_ie_t encode = {0};
	encode.header.type = GTPV1_IE_EXTENDED_COMMON_FLAGS_II;
	encode.header.length = 1;
	encode.spare = 0;
	encode.pmts_mi = 1;
	encode.dtci = 1;
	encode.pnsi = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_extended_common_flag_2_ie(&encode, buf) == 4);
	CU_ASSERT(encode_gtpv1_extended_common_flag_2_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_extended_common_flag_2_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_extended_common_flag_2_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 4, 64, 64, "da000107") == 0);
}

void test_encode_gtpv1_mapped_ue_usage_type_ie(void)
{
	gtpv1_mapped_ue_usage_type_ie_t encode = {0};
	encode.header.type = GTPV1_IE_MAPPED_UE_USAGE_TYPE;
	encode.header.length = 3;
	encode.mapped_ue_usage_type = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_mapped_ue_usage_type_ie(&encode, buf) == 5);
	CU_ASSERT(encode_gtpv1_mapped_ue_usage_type_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_mapped_ue_usage_type_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_mapped_ue_usage_type_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 5, 64, 64, "df00030001" ) == 0);
} 

void test_encode_gtpv1_up_function_selection_indication_ie(void)
{
	gtpv1_up_function_selection_indication_ie_t encode = {0};
	encode.header.type = GTPV1_IE_UP_FUNCTION_SELECTION_INDICATION;
	encode.header.length = 1;
	encode.spare = 0;
	encode.dcnr = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_up_function_selection_indication_ie(&encode, buf) == 4);
	CU_ASSERT(encode_gtpv1_up_function_selection_indication_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_up_function_selection_indication_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_up_function_selection_indication_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 4, 64, 64, "e0000101" ) == 0);
}

void test_encode_gtpv1_charging_gateway_addr_ie(void)
{
	gtpv1_charging_gateway_addr_ie_t encode = {0};
	encode.header.type = GTPV1_IE_CHARGING_GATEWAY_ADDR;
	encode.header.length = 4;
	encode.ipv4_addr = 3232235564;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_charging_gateway_addr_ie(&encode, buf) == 7);
	CU_ASSERT(encode_gtpv1_charging_gateway_addr_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_charging_gateway_addr_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_charging_gateway_addr_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 7, 64, 64, "fb0004c0a8002c") == 0);
}

void test_encode_gtpv1_private_extension_ie(void)
{
	gtpv1_private_extension_ie_t encode = {0};
	encode.header.type = GTPV1_IE_PRIVATE_EXTENSION;
	encode.header.length = 4;
	encode.extension_identifier = 12;
	strncpy((char *)&encode.extension_value, "11", 2);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_private_extension_ie(&encode, buf) == 7);
	CU_ASSERT(encode_gtpv1_private_extension_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_private_extension_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_private_extension_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 7, 64, 64, "ff0004000c3131") == 0);
}

void test_encode_gtpv1_map_cause_ie(void)
{
	gtpv1_map_cause_ie_t encode = {0};
	encode.header.type = GTPV1_IE_MAP_CAUSE;
	encode.map_cause_value = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_map_cause_ie(&encode, buf) == 2);
	CU_ASSERT(encode_gtpv1_map_cause_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_map_cause_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_map_cause_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 2, 64, 64, "0b01") == 0);
}

void test_encode_gtpv1_ms_not_rechable_reason_ie(void)
{
	gtpv1_ms_not_rechable_reason_ie_t encode = {0};
	encode.header.type = GTPV1_IE_MS_NOT_RECHABLE_REASON;
	encode.reason_for_absence = 2;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_ms_not_rechable_reason_ie(&encode, buf) == 2);
	CU_ASSERT(encode_gtpv1_ms_not_rechable_reason_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_ms_not_rechable_reason_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_ms_not_rechable_reason_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 2, 64, 64, "1d02") == 0);
}

void test_encode_gtpv1_temporary_logical_link_identifier_ie(void)
{
	gtpv1_temporary_logical_link_identifier_ie_t encode = {0};
	encode.header.type = GTPV1_IE_TEMPORARY_LOGICAL_LINK_IDENTIFIER;
	encode.tlli = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_temporary_logical_link_identifier_ie(&encode, buf) == 5);
	CU_ASSERT(encode_gtpv1_temporary_logical_link_identifier_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_temporary_logical_link_identifier_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_temporary_logical_link_identifier_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 5, 64, 64, "0400000001") == 0);
}

void test_encode_gtpv1_packet_tmsi_ie(void)
{
	gtpv1_packet_tmsi_ie_t encode ={0};
	encode.header.type = GTPV1_IE_PACKET_TMSI;
	encode.p_tmsi = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_packet_tmsi_ie(&encode, buf) == 5);
	CU_ASSERT(encode_gtpv1_packet_tmsi_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_packet_tmsi_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_packet_tmsi_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 5, 64, 64, "0500000001") == 0);
}

void test_encode_gtpv1_p_tmsi_signature_ie(void)
{
	gtpv1_p_tmsi_signature_ie_t encode = {0};
	encode.header.type = GTPV1_IE_P_TMSI_SIGNATURE;
	encode.p_tmsi_signature = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_p_tmsi_signature_ie(&encode, buf) == 4);
	CU_ASSERT(encode_gtpv1_p_tmsi_signature_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_p_tmsi_signature_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_p_tmsi_signature_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 4, 64, 64, "0c000001") == 0);
}

void test_encode_gtpv1_ms_validated_ie(void)
{
	gtpv1_ms_validated_ie_t encode = {0};
	encode.header.type = GTPV1_IE_MS_VALIDATED;
	encode.spare = 0;
	encode.ms_validated = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_ms_validated_ie(&encode, buf) == 2);
	CU_ASSERT(encode_gtpv1_ms_validated_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_ms_validated_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_ms_validated_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 2, 64, 64, "0d01") == 0);
}

void test_encode_gtpv1_sgsn_number_ie(void)
{
	gtpv1_sgsn_number_ie_t encode = {0};
	encode.header.type = GTPV1_IE_SGSN_NUMBER;
	encode.header.length = 2;
	strncpy((char *)&encode.sgsn_number,"11",2);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_sgsn_number_ie(&encode, buf) == 5);
	CU_ASSERT(encode_gtpv1_sgsn_number_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_sgsn_number_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_sgsn_number_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 5, 64, 64, "9300023131") == 0);
}

void test_encode_gtpv1_hop_counter_ie(void)
{
	gtpv1_hop_counter_ie_t encode = {0};
	encode.header.type = GTPV1_IE_HOP_COUNTER;
	encode.header.length = 1;
	encode.hop_counter = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_hop_counter_ie(&encode, buf) == 4);
	CU_ASSERT(encode_gtpv1_hop_counter_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_hop_counter_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_hop_counter_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 4, 64, 64, "a3000101") == 0);
}

void test_encode_gtpv1_rab_context_ie(void)
{
	gtpv1_rab_context_ie_t encode = {0};
	encode.header.type = GTPV1_IE_RAB_CONTEXT;
	encode.spare = 0;
	encode.nsapi = 1;
	encode.dl_gtp_u_sequence_number = 1;
	encode.ul_gtp_u_sequence_number = 1;
	encode.dl_pdcp_sequence_number = 1;
	encode.ul_pdcp_sequence_number = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_rab_context_ie(&encode, buf) == 10);
	CU_ASSERT(encode_gtpv1_rab_context_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_rab_context_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_rab_context_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 10, 64, 64, "16010001000100010001") == 0);
}

void test_encode_gtpv1_radio_priority_sms_ie(void)
{
	gtpv1_radio_priority_sms_ie_t encode = {0};
	encode.header.type = GTPV1_IE_RADIO_PRIORITY_SMS;
	encode.spare = 0;
	encode.radio_priority_sms = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_radio_priority_sms_ie(&encode, buf) == 2);
	CU_ASSERT(encode_gtpv1_radio_priority_sms_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_radio_priority_sms_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_radio_priority_sms_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 2, 64, 64, "1701") == 0);
}

void test_encode_gtpv1_radio_priority_ie(void)
{
	gtpv1_radio_priority_ie_t encode = {0};
	encode.header.type = GTPV1_IE_RADIO_PRIORITY;
	encode.nsapi = 1;
	encode.spare = 0;
	encode.radio_priority = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_radio_priority_ie(&encode, buf) == 2);
	CU_ASSERT(encode_gtpv1_radio_priority_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_radio_priority_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_radio_priority_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 2, 64, 64, "1811") == 0);
}

void test_encode_gtpv1_packet_flow_id_ie(void)
{
	gtpv1_packet_flow_id_ie_t encode = {0};
	encode.header.type = GTPV1_IE_PACKET_FLOW_ID;
	encode.spare = 0;
	encode.nsapi = 1;
	encode.packet_flow_id = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_packet_flow_id_ie(&encode, buf) == 3);
	CU_ASSERT(encode_gtpv1_packet_flow_id_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_packet_flow_id_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_packet_flow_id_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 3, 64, 64, "190101") == 0);
}

void test_encode_gtpv1_radio_priority_lcs_ie(void)
{
	gtpv1_radio_priority_lcs_ie_t encode = {0};
	encode.header.type = GTPV1_IE_RADIO_PRIORITY_LCS;
	encode.header.length = 1;
	encode.spare = 0;
	encode.radio_priority_lcs = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_radio_priority_lcs_ie(&encode, buf) == 4);
	CU_ASSERT(encode_gtpv1_radio_priority_lcs_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_radio_priority_lcs_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_radio_priority_lcs_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 4, 64, 64, "96000101") == 0);
}

void test_encode_gtpv1_pdp_context_prioritization_ie(void)
{
	gtpv1_pdp_context_prioritization_ie_t encode = {0};
	encode.header.type = GTPV1_IE_PDP_CONTEXT_PRIORITIZATION;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_pdp_context_prioritization_ie(&encode, buf) == 3);
	CU_ASSERT(encode_gtpv1_pdp_context_prioritization_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_pdp_context_prioritization_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_pdp_context_prioritization_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 3, 64, 64, "910000") == 0);
}

void test_encode_gtpv1_rfsp_index_ie(void)
{
	gtpv1_rfsp_index_ie_t encode = {0};
	encode.header.type = GTPV1_IE_RFSP_INDEX;
	encode.header.length = 2;
	encode.rfsp_index = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_rfsp_index_ie(&encode, buf) == 5);
	CU_ASSERT(encode_gtpv1_rfsp_index_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_rfsp_index_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_rfsp_index_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 5, 64, 64, "bd00020001") == 0);
}

void test_encode_gtpv1_fqdn_ie(void)
{
	gtpv1_fqdn_ie_t encode = {0};
	encode.header.type = GTPV1_IE_FQDN;
	encode.header.length = 5;
	strncpy((char *)&encode.fqdn,"gslab",5);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_fqdn_ie(&encode, buf) == 8);
	CU_ASSERT(encode_gtpv1_fqdn_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_fqdn_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_fqdn_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 8, 64, 64, "be000567736c6162") == 0);
}

void test_encode_gtpv1_evolved_allocation_retention_priority_II_ie(void)
{
	gtpv1_evolved_allocation_retention_priority_II_ie_t encode = {0};
	encode.header.type = GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_II;
	encode.header.length = 2;
	encode.spare = 0;
	encode.nsapi = 1;
	encode.spare2 = 0;
	encode.pci = 1;
	encode.pl = 1;
	encode.spare3 = 0;
	encode.pvi = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_evolved_allocation_retention_priority_II_ie(&encode, buf) == 5);
	CU_ASSERT(encode_gtpv1_evolved_allocation_retention_priority_II_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_evolved_allocation_retention_priority_II_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_evolved_allocation_retention_priority_II_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 5, 64, 64, "c000020145") == 0);
}

void test_encode_gtpv1_ue_network_capability_ie(void)
{
	gtpv1_ue_network_capability_ie_t encode = {0};
	encode.header.type = GTPV1_IE_UE_NETWORK_CAPABILITY;
	encode.header.length = 8;
	encode.eea0 = 1;
	encode.eea1_128 = 1;
	encode.eea2_128 = 0;
	encode.eea3_128 = 1;
	encode.eea4 = 0;
	encode.eea5 = 1;
	encode.eea6 = 1;
	encode.eea7 = 0;
	encode.eia0 = 1;
	encode.eia1_128 = 0;
	encode.eia2_128 = 1;
	encode.eia3_128 = 0;
	encode.eia4 = 1;
	encode.eia5 = 0;
	encode.eia6 = 1;
	encode.eia7 = 1;
	encode.uea0 = 0;
	encode.uea1 = 1;
	encode.uea2 = 0;
	encode.uea3 = 1;
	encode.uea4 = 0;
	encode.uea5 = 1;
	encode.uea6 = 0;
	encode.uea7 = 1;
	encode.ucs2 = 1;
	encode.uia1 = 0;
	encode.uia2 = 1;
	encode.uia3 = 1;
	encode.uia4 = 0;
	encode.uia5 = 1;
	encode.uia6 = 0;
	encode.uia7 = 1;
	encode.prose_dd = 1;
	encode.prose = 0;
	encode.h245_ash = 1;
	encode.acc_csfb = 1;
	encode.lpp = 0;
	encode.lcs = 1;
	encode.srvcc1x = 1;
	encode.nf = 0;
	encode.epco = 1;
	encode.hc_cp_ciot = 0;
	encode.erw_opdn = 1;
	encode.s1_udata = 1;
	encode.up_ciot = 1;
	encode.cp_ciot = 0;
	encode.prose_relay = 1;
	encode.prose_dc = 1;
	encode.bearers_15 = 0;
	encode.sgc = 1;
	encode.n1mode = 0;
	encode.dcnr = 1;
	encode.cp_backoff = 0;
	encode.restrict_ec = 0;
	encode.v2x_pc5 = 1;
	encode.multiple_drb = 0;
	encode.spare1 = 0;
	encode.v2xnr_pcf = 1;
	encode.up_mt_edt = 0;
	encode.cp_mt_edt = 0;
	encode.wusa = 1;
	encode.racs = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_ue_network_capability_ie(&encode, buf) == 11);
	CU_ASSERT(encode_gtpv1_ue_network_capability_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_ue_network_capability_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_ue_network_capability_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 11, 64, 64, "c70008d6ab55b5b6bb5213") == 0);
}

void test_encode_gtpv1_apn_ambr_with_nsapi_ie(void)
{
	gtpv1_apn_ambr_with_nsapi_ie_t encode = {0};
	encode.header.type = GTPV1_IE_APN_AMBR_WITH_NSAPI;
	encode.header.length = 9;
	encode.spare = 0;
	encode.nsapi = 1;
	encode.authorized_apn_ambr_for_uplink = 1;
	encode.authorized_apn_ambr_for_downlink = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_apn_ambr_with_nsapi_ie(&encode, buf) == 12);
	CU_ASSERT(encode_gtpv1_apn_ambr_with_nsapi_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_apn_ambr_with_nsapi_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_apn_ambr_with_nsapi_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 12, 64, 64, "c90009010000000100000001") == 0);
}

void test_encode_gtpv1_signalling_priority_indication_with_nsapi_ie(void)
{
	gtpv1_signalling_priority_indication_with_nsapi_ie_t encode = {0};
	encode.header.type = GTPV1_IE_SIGNALLING_PRIORITY_INDICATION_WITH_NSAPI;
	encode.header.length = 2;
	encode.spare = 0;
	encode.nsapi = 1;
	encode.spare2 = 0;
	encode.lapi = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_signalling_priority_indication_with_nsapi_ie(&encode, buf) == 5);
	CU_ASSERT(encode_gtpv1_signalling_priority_indication_with_nsapi_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_signalling_priority_indication_with_nsapi_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_signalling_priority_indication_with_nsapi_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 5, 64, 64, "cc00020101") == 0);
}

void test_encode_gtpv1_higher_bitrates_than_16_mbps_flag_ie(void)
{
	gtpv1_higher_bitrates_than_16_mbps_flag_ie_t encode = {0};
	encode.header.type = GTPV1_IE_HIGER_BITRATES_THAN_16_MBPS_FLAG;
	encode.header.length = 1;
	encode.higher_bitrates_than_16_mbps_flag = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_higher_bitrates_than_16_mbps_flag_ie(&encode, buf) == 4);
	CU_ASSERT(encode_gtpv1_higher_bitrates_than_16_mbps_flag_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_higher_bitrates_than_16_mbps_flag_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_higher_bitrates_than_16_mbps_flag_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 4, 64, 64, "cd000101") == 0);
}

void test_encode_gtpv1_selection_mode_with_nsapi_ie(void)
{
	gtpv1_selection_mode_with_nsapi_ie_t encode = {0};
	encode.header.type = GTPV1_IE_SELECTION_MODE_WITH_NSAPI;
	encode.header.length = 2;
	encode.spare = 0;
	encode.nsapi = 1;
	encode.spare2 = 0;
	encode.selection_mode_value = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_selection_mode_with_nsapi_ie(&encode, buf) == 5);
	CU_ASSERT(encode_gtpv1_selection_mode_with_nsapi_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_selection_mode_with_nsapi_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_selection_mode_with_nsapi_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 5, 64, 64, "d500020101") == 0);
}

void test_encode_gtpv1_local_home_network_id_with_nsapi_ie(void)
{
	gtpv1_local_home_network_id_with_nsapi_ie_t encode = {0};
	encode.header.type = GTPV1_IE_LOCAL_HOME_NETWORK_ID_WITH_NSAPI;
	encode.header.length = 6;
	encode.spare = 0;
	encode.nsapi = 1;
	strncpy((char *)&encode.local_home_network_id_with_nsapi,"gslab",5);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_local_home_network_id_with_nsapi_ie(&encode, buf) == 9);
	CU_ASSERT(encode_gtpv1_local_home_network_id_with_nsapi_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_local_home_network_id_with_nsapi_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_local_home_network_id_with_nsapi_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 9, 64, 64, "d700060167736c6162") == 0);
}

void test_encode_gtpv1_ran_transparent_container_ie(void)
{
	gtpv1_ran_transparent_container_ie_t encode = {0};
	encode.header.type = GTPV1_IE_RAN_TRANSPARENT_CONTAINER;
	encode.header.length = 2;
	strncpy((char *)&encode.rtc_field, "22", 2);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_ran_transparent_container_ie(&encode, buf) == 5);
	CU_ASSERT(encode_gtpv1_ran_transparent_container_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_ran_transparent_container_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_ran_transparent_container_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 5, 64, 64, "9000023232") == 0);
}

void test_encode_gtpv1_rim_routing_addr_ie(void)
{
	gtpv1_rim_routing_addr_ie_t encode = {0};
	encode.header.type = GTPV1_IE_RIM_ROUTING_ADDR;
	encode.header.length = 2;
	strncpy((char *)&encode.rim_routing_addr, "11", 2);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_rim_routing_addr_ie(&encode, buf) == 5);
	CU_ASSERT(encode_gtpv1_rim_routing_addr_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_rim_routing_addr_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_rim_routing_addr_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 5, 64, 64, "9e00023131") == 0);
}

void test_encode_gtpv1_rim_routing_addr_disc_ie(void)
{
	gtpv1_rim_routing_addr_disc_ie_t encode = {0};
	encode.header.type = GTPV1_IE_RIM_ROUTING_ADDR_DISCRIMINATOR;
	encode.header.length = 1;
	encode.spare = 0;
	encode.discriminator = 2;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_rim_routing_addr_disc_ie(&encode, buf) == 4);
	CU_ASSERT(encode_gtpv1_rim_routing_addr_disc_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_rim_routing_addr_disc_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_rim_routing_addr_disc_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 4, 64, 64, "b2000102" ) == 0);
}

void test_encode_gtpv1_selected_plmn_id_ie(void)
{
	gtpv1_selected_plmn_id_ie_t encode = {0};
	encode.header.type = GTPV1_IE_SELECTED_PLMN_ID;
	encode.header.length = 3;
	encode.mcc_digit_2 = 0x3;
	encode.mcc_digit_1 = 0x0;
	encode.mnc_digit_3 = 0x0;
	encode.mcc_digit_3 = 0x5;
	encode.mnc_digit_1 = 0x1;
	encode.mnc_digit_2 = 0x8;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_selected_plmn_id_ie(&encode, buf) == 6);
	CU_ASSERT(encode_gtpv1_selected_plmn_id_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_selected_plmn_id_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_selected_plmn_id_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 6, 64, 64, "a40003301508") == 0);

	gtpv1_selected_plmn_id_ie_t encode_1 = {0};
	encode_1.header.type = GTPV1_IE_SELECTED_PLMN_ID;
	encode_1.header.length = 3;
	encode_1.mcc_digit_2 = 0x3;
	encode_1.mcc_digit_1 = 0x0;
	encode_1.mnc_digit_3 = 0x0;
	encode_1.mcc_digit_3 = 0x5;
	encode_1.mnc_digit_1 = 0x0;
	encode_1.mnc_digit_2 = 0x8;
	uint8_t buf_1[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_selected_plmn_id_ie(&encode_1, buf_1) == 6);
	CU_ASSERT(hexdump(buf_1, 6, 64, 64, "a4000330f508") == 0);


}

void test_encode_gtpv1_mbms_protocol_config_options_ie(void)
{
	gtpv1_mbms_protocol_config_options_ie_t encode = {0};
	encode.header.type = GTPV1_IE_MBMS_PROTOCOL_CONFIG_OPTIONS;
	encode.header.length = 2;
	strncpy((char *)&encode.mbms_protocol_configuration, "11", 2);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_mbms_protocol_config_options_ie(&encode, buf) == 5);
	CU_ASSERT(encode_gtpv1_mbms_protocol_config_options_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_mbms_protocol_config_options_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_mbms_protocol_config_options_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 5, 64, 64, "9f00023131") == 0);
}

void test_encode_gtpv1_teid_data_2_ie(void)
{
	gtpv1_teid_data_2_ie_t encode = {0};
	encode.header.type = GTPV1_IE_TEID_DATA_2;
	encode.nsapi = 5;
	encode.teid = 0x0fffeee;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_teid_data_2_ie(&encode, buf) == 6);
	CU_ASSERT(encode_gtpv1_teid_data_2_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_teid_data_2_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_teid_data_2_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 6, 64, 64, "120500fffeee" ) == 0);
}

void test_encode_gtpv1_ranap_cause_ie(void)
{
	gtpv1_ranap_cause_ie_t encode = {0};
	encode.header.type = GTPV1_IE_RANAP_CAUSE;
	encode.ranap_cause = 7;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_ranap_cause_ie(&encode, buf) == 2);
	CU_ASSERT(encode_gtpv1_ranap_cause_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_ranap_cause_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_ranap_cause_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 2, 64, 64, "1507" ) == 0);
}

void test_encode_gtpv1_target_identification_ie(void)
{
	gtpv1_target_identification_ie_t encode = {0};
	encode.header.type = GTPV1_IE_TARGET_IDENTIFICATION;
	encode.header.length = 10;
	encode.mcc_digit_2 = 0x2;
	encode.mcc_digit_1 = 0x2;
	encode.mnc_digit_3 = 0x7;
	encode.mcc_digit_3 = 0x1;
	encode.mnc_digit_1 = 0x1;
	encode.mnc_digit_2 = 0x3;
	encode.lac = 2;
	encode.rac = 2;
	encode.rnc_id = 2;
	encode.extended_rnc_id = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_target_identification_ie(&encode, buf) == 13);
	CU_ASSERT(encode_gtpv1_target_identification_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_target_identification_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_target_identification_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 13, 64, 64, "8a000a22713100020200020001") == 0);

	gtpv1_target_identification_ie_t encode_1 = {0};
	encode_1.header.type = GTPV1_IE_TARGET_IDENTIFICATION;
	encode_1.header.length = 8;
	encode_1.mcc_digit_2 = 0x2;
	encode_1.mcc_digit_1 = 0x2;
	encode_1.mnc_digit_3 = 0x7;
	encode_1.mcc_digit_3 = 0x1;
	encode_1.mnc_digit_1 = 0x0;
	encode_1.mnc_digit_2 = 0x3;
	encode_1.lac = 2;
	encode_1.rac = 2;
	encode_1.rnc_id = 2;
	uint8_t buf_1[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_target_identification_ie(&encode_1, buf_1) == 11);
	CU_ASSERT(hexdump(buf_1, 11, 64, 64, "8a000822f1730002020002") == 0);
}


void test_encode_gtpv1_utran_transparent_container_ie(void)
{
	gtpv1_utran_transparent_container_ie_t encode = {0};
	encode.header.type = GTPV1_IE_UTRAN_TRANSPARENT_CONTAINER;
	encode.header.length = 4;
	strncpy((char *)&encode.utran_transparent_field, "shub", 4);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_utran_transparent_container_ie(&encode, buf) == 7);
	CU_ASSERT(encode_gtpv1_utran_transparent_container_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_utran_transparent_container_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_utran_transparent_container_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 7, 64, 64, "8b000473687562") == 0);
}

void test_encode_gtpv1_rab_setup_info_ie(void)
{
	gtpv1_rab_setup_info_ie_t encode = {0};
	encode.header.type = GTPV1_IE_RAB_SETUP_INFO;
	encode.header.length = 9;
	encode.spare = 0;
	encode.nsapi = 2;
	encode.teid = 0x0fffeee;
	encode.rnc_ip_addr.ipv4 = 3565240599;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_rab_setup_info_ie(&encode, buf) == 12);
	CU_ASSERT(encode_gtpv1_rab_setup_info_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_rab_setup_info_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_rab_setup_info_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 12, 64, 64, "8c00090200fffeeed4814117" ) == 0);
}

void test_encode_gtpv1_bss_container_ie(void)
{
	gtpv1_bss_container_ie_t encode = {0};
	encode.header.type = GTPV1_IE_BSS_CONTAINER;
	encode.header.length = 5;
	strncpy((char *)&encode.bss_container, "gslab", 5);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_bss_container_ie(&encode, buf) == 8);
	CU_ASSERT(encode_gtpv1_bss_container_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_bss_container_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_bss_container_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 8, 64, 64, "ad000567736c6162") == 0);
}

void test_encode_gtpv1_cell_identification_ie(void)
{
	gtpv1_cell_identification_ie_t encode = {0};
	encode.header.type = GTPV1_IE_CELL_IDENTIFICATION;
	encode.header.length = 17;
	encode.target_cell_id.rai_value.mcc_digit_2 = 0x2;
	encode.target_cell_id.rai_value.mcc_digit_1 = 0x5;
	encode.target_cell_id.rai_value.mnc_digit_3 = 0x8;
	encode.target_cell_id.rai_value.mcc_digit_3 = 0x3;
	encode.target_cell_id.rai_value.mnc_digit_1 = 0x0;
	encode.target_cell_id.rai_value.mnc_digit_2 = 0x8;
	encode.target_cell_id.rai_value.lac = 20;
	encode.target_cell_id.rai_value.rac = 20;
	encode.target_cell_id.cell_identity = 1;
	encode.source_type = 0;
	encode.ID.source_cell_id.rai_value.mcc_digit_2 = 0x2;
	encode.ID.source_cell_id.rai_value.mcc_digit_1 = 0x5;
	encode.ID.source_cell_id.rai_value.mnc_digit_3 = 0x8;
	encode.ID.source_cell_id.rai_value.mcc_digit_3 = 0x3;
	encode.ID.source_cell_id.rai_value.mnc_digit_1 = 0x0;
	encode.ID.source_cell_id.rai_value.mnc_digit_2 = 0x8;
	encode.ID.source_cell_id.rai_value.lac = 20;
	encode.ID.source_cell_id.rai_value.rac = 20;
	encode.ID.source_cell_id.cell_identity = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_cell_identification_ie(&encode, buf) == 20);
	CU_ASSERT(encode_gtpv1_cell_identification_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_cell_identification_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_cell_identification_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 20, 64, 64, "ae001125f38800141400010025f3880014140001") == 0);
}

void test_encode_gtpv1_bssgp_cause_ie(void)
{
	gtpv1_bssgp_cause_ie_t encode = {0};
	encode.header.type = GTPV1_IE_BSSGP_CAUSE;
	encode.header.length = 1;
	encode.bssgp_cause = 2;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_bssgp_cause_ie(&encode, buf) == 4);
	CU_ASSERT(encode_gtpv1_bssgp_cause_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_bssgp_cause_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_bssgp_cause_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 4, 64, 64, "b0000102" ) == 0);
}

void test_encode_gtpv1_list_of_setup_pfcs_ie(void)
{
	gtpv1_list_of_setup_pfcs_ie_t encode = {0};
	encode.header.type = GTPV1_IE_LIST_OF_SET_UP_PFCS;
	encode.header.length = 4;
	encode.list.no_of_pfcs = 3;
	encode.list.pfi_list[0].spare = 0;
	encode.list.pfi_list[0].pfi_value = 1;
	encode.list.pfi_list[1].spare = 0;
	encode.list.pfi_list[1].pfi_value = 0;
	encode.list.pfi_list[2].spare = 0;
	encode.list.pfi_list[2].pfi_value = 3;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_list_of_setup_pfcs_ie(&encode, buf) == 7);
	CU_ASSERT(encode_gtpv1_list_of_setup_pfcs_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_list_of_setup_pfcs_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_list_of_setup_pfcs_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 7, 64, 64, "b3000403010003") == 0);

	gtpv1_list_of_setup_pfcs_ie_t encode1 = {0};
	encode1.header.type = GTPV1_IE_LIST_OF_SET_UP_PFCS;
	encode1.header.length = 1;
	encode1.list.no_of_pfcs = 13;
	uint8_t buf1[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_list_of_setup_pfcs_ie(&encode1, buf1) == 4);
	CU_ASSERT(encode_gtpv1_list_of_setup_pfcs_ie(NULL, buf1) == -1);
	CU_ASSERT(encode_gtpv1_list_of_setup_pfcs_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_list_of_setup_pfcs_ie(&encode1, NULL) == -1);
	CU_ASSERT(hexdump(buf1, 4, 64, 64, "b300010d") == 0);
}

void test_encode_gtpv1_ps_handover_xid_param_ie(void)
{
	gtpv1_ps_handover_xid_param_ie_t encode = {0};
	encode.header.type = GTPV1_IE_PS_HANDOVER_XID_PARAM;
	encode.header.length = 4;
	encode.spare = 0;
	encode.sapi = 2;
	encode.xid_param_length = 2;
	strncpy((char *)&encode.xid_param, "11", 2);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_ps_handover_xid_param_ie(&encode, buf) == 7);
	CU_ASSERT(encode_gtpv1_ps_handover_xid_param_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_ps_handover_xid_param_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_ps_handover_xid_param_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 7, 64, 64, "b4000402023131" ) == 0);
}

void test_encode_gtpv1_reliable_inter_rat_handover_info_ie(void)
{
	gtpv1_reliable_inter_rat_handover_info_ie_t encode = {0};
	encode.header.type = GTPV1_IE_RELIABLE_INTER_RAT_HANDOVER_INFO;
	encode.header.length = 1;
	encode.handover_info = 2;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_reliable_inter_rat_handover_info_ie(&encode, buf) == 4);
	CU_ASSERT(encode_gtpv1_reliable_inter_rat_handover_info_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_reliable_inter_rat_handover_info_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_reliable_inter_rat_handover_info_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 4, 64, 64, "bc000102" ) == 0);
}

void test_encode_gtpv1_csg_id_ie(void)
{
	gtpv1_csg_id_ie_t encode = {0};
	encode.header.type = GTPV1_IE_CSG_ID;
	encode.header.length = 4;
	encode.spare = 0;
	encode.csg_id = 1;
	encode.csg_id2 = 2;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_csg_id_ie(&encode, buf) == 7);
	CU_ASSERT(encode_gtpv1_csg_id_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_csg_id_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_csg_id_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 7, 64, 64, "c4000401000002" ) == 0);
}

void test_encode_gtpv1_csg_membership_indication_ie(void)
{
	gtpv1_csg_membership_indication_ie_t encode = {0};
	encode.header.type = GTPV1_IE_CSG_MEMB_INDCTN;
	encode.header.length = 1;
	encode.spare = 0;
	encode.cmi = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_csg_membership_indication_ie(&encode, buf) == 4);
	CU_ASSERT(encode_gtpv1_csg_membership_indication_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_csg_membership_indication_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_csg_membership_indication_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 4, 64, 64, "c5000101" ) == 0);
}

void test_encode_gtpv1_additional_mm_ctxt_for_srvcc_ie(void)
{
	gtpv1_additional_mm_ctxt_for_srvcc_ie_t encode = {0};
	encode.header.type = GTPV1_IE_ADDTL_MM_CTXT_SRVCC;
	encode.header.length = 34;
	encode.ms_classmark_2.ms_classmark_2_len = 3;
	encode.ms_classmark_2.spare1 = 0;
	encode.ms_classmark_2.rev_level = 1;
	encode.ms_classmark_2.es_ind = 1;
	encode.ms_classmark_2.a5_1 = 1;
	encode.ms_classmark_2.rf_power_cap = 1;
	encode.ms_classmark_2.spare2 = 0;
	encode.ms_classmark_2.ps_cap = 1;
	encode.ms_classmark_2.ss_screen_ind = 1;
	encode.ms_classmark_2.sm_cap = 1;
	encode.ms_classmark_2.vbs = 1;
	encode.ms_classmark_2.vgcs = 1;
	encode.ms_classmark_2.fc = 1;
	encode.ms_classmark_2.cm3 = 1;
	encode.ms_classmark_2.spare3 = 0;
	encode.ms_classmark_2.lcsvacap = 1;
	encode.ms_classmark_2.ucs2 = 1;
	encode.ms_classmark_2.solsa = 1;
	encode.ms_classmark_2.cmsp = 1;
	encode.ms_classmark_2.a5_3 = 1;
	encode.ms_classmark_2.a5_2 = 1;

	encode.ms_classmark_3.ms_classmark_3_len = 21;
	encode.ms_classmark_3.spare1 = 0;
	encode.ms_classmark_3.mult_band_supp = 5;
	encode.ms_classmark_3.a5_bits = 1;
	encode.ms_classmark_3.assoc_radio_cap_1 = 1;
	encode.ms_classmark_3.assoc_radio_cap_2 = 2;
	encode.ms_classmark_3.r_support = 1;
	encode.ms_classmark_3.r_gsm_assoc_radio_cap = 1;
	encode.ms_classmark_3.hscsd_mult_slot_cap = 1;
	encode.ms_classmark_3.hscsd_mult_slot_class = 4;
	encode.ms_classmark_3.ucs2_treatment = 1;
	encode.ms_classmark_3.extended_meas_cap = 0;
	encode.ms_classmark_3.ms_meas_cap = 1;
	encode.ms_classmark_3.sms_value = 3;
	encode.ms_classmark_3.sm_value = 5;
	encode.ms_classmark_3.ms_pos_method_cap = 1;
	encode.ms_classmark_3.ms_pos_method = 3;
	encode.ms_classmark_3.ecsd_multislot_cap = 1;
	encode.ms_classmark_3.ecsd_multislot_class = 6;
	encode.ms_classmark_3.psk8_struct = 1;
	encode.ms_classmark_3.mod_cap = 0;
	encode.ms_classmark_3.rf_pwr_cap_1 = 1;
	encode.ms_classmark_3.rf_pwr_cap_1_val = 1;
	encode.ms_classmark_3.rf_pwr_cap_2 = 1;
	encode.ms_classmark_3.rf_pwr_cap_2_val = 0;
	encode.ms_classmark_3.gsm_400_bands_supp = 1;
	encode.ms_classmark_3.gsm_400_bands_val = 0;
	encode.ms_classmark_3.gsm_400_assoc_radio_cap = 4;
	encode.ms_classmark_3.gsm_850_assoc_radio_cap = 1;
	encode.ms_classmark_3.gsm_850_assoc_radio_cap_val = 3;
	encode.ms_classmark_3.gsm_1900_assoc_radio_cap = 1;
	encode.ms_classmark_3.gsm_1900_assoc_radio_cap_val = 5;
	encode.ms_classmark_3.umts_fdd_rat_cap = 1;
	encode.ms_classmark_3.umts_tdd_rat_cap = 0;
	encode.ms_classmark_3.cdma2000_rat_cap = 1;
	encode.ms_classmark_3.dtm_gprs_multislot_class = 1;
	encode.ms_classmark_3.dtm_gprs_multislot_val = 0;
	encode.ms_classmark_3.single_slot_dtm = 1;
	encode.ms_classmark_3.dtm_egprs_multislot_class = 1;
	encode.ms_classmark_3.dtm_egprs_multislot_val = 2;
	encode.ms_classmark_3.single_band_supp = 1;
	encode.ms_classmark_3.single_band_supp_val = 7;
	encode.ms_classmark_3.gsm_750_assoc_radio_cap = 1;
	encode.ms_classmark_3.gsm_750_assoc_radio_cap_val = 14;
	encode.ms_classmark_3.umts_1_28_mcps_tdd_rat_cap = 0;
	encode.ms_classmark_3.geran_feature_package = 1;
	encode.ms_classmark_3.ext_dtm_gprs_multislot_class = 1;
	encode.ms_classmark_3.ext_dtm_gprs_multislot_val = 3;
	encode.ms_classmark_3.ext_dtm_egprs_multislot_val = 2;
	encode.ms_classmark_3.high_multislot_cap = 1;
	encode.ms_classmark_3.high_multislot_val = 2;
	encode.ms_classmark_3.geran_iu_mode_supp = 0;
	encode.ms_classmark_3.geran_feature_package_2 = 1;
	encode.ms_classmark_3.gmsk_multislot_power_prof = 2;
	encode.ms_classmark_3.psk8_multislot_power_prof = 3;
	encode.ms_classmark_3.t_gsm_400_bands_supp = 1;
	encode.ms_classmark_3.t_gsm_400_bands_val = 2;
	encode.ms_classmark_3.t_gsm_400_assoc_radio_cap = 6;
	encode.ms_classmark_3.t_gsm_900_assoc_radio_cap = 0;
	encode.ms_classmark_3.dl_advanced_rx_perf = 3;
	encode.ms_classmark_3.dtm_enhancements_cap = 1;
	encode.ms_classmark_3.dtm_gprs_high_multislot_cap = 1;
	encode.ms_classmark_3.dtm_gprs_high_multislot_val = 2;
	encode.ms_classmark_3.offset_required = 0;
	encode.ms_classmark_3.dtm_egprs_high_multislot_cap = 1;
	encode.ms_classmark_3.dtm_egprs_high_multislot_val = 2;
	encode.ms_classmark_3.repeated_acch_capability = 1;
	encode.ms_classmark_3.gsm_710_assoc_radio_cap = 1;
	encode.ms_classmark_3.gsm_710_assoc_radio_val = 5;
	encode.ms_classmark_3.t_gsm_810_assoc_radio_cap = 1;
	encode.ms_classmark_3.t_gsm_810_assoc_radio_val = 7;
	encode.ms_classmark_3.ciphering_mode_setting_cap = 0;
	encode.ms_classmark_3.add_pos_cap = 1;
	encode.ms_classmark_3.e_utra_fdd_supp = 1;
	encode.ms_classmark_3.e_utra_tdd_supp = 1;
	encode.ms_classmark_3.e_utra_meas_rep_supp = 1;
	encode.ms_classmark_3.prio_resel_supp = 1;
	encode.ms_classmark_3.utra_csg_cells_rep = 1;
	encode.ms_classmark_3.vamos_level = 2;
	encode.ms_classmark_3.tighter_capability = 3;
	encode.ms_classmark_3.sel_ciph_dl_sacch = 0;
	encode.ms_classmark_3.cs_ps_srvcc_geran_utra = 1;
	encode.ms_classmark_3.cs_ps_srvcc_geran_eutra = 1;
	encode.ms_classmark_3.geran_net_sharing = 0;
	encode.ms_classmark_3.e_utra_wb_rsrq_meas_supp = 1;
	encode.ms_classmark_3.er_band_support = 1;
	encode.ms_classmark_3.utra_mult_band_ind_supp = 1;
	encode.ms_classmark_3.e_utra_mult_band_ind_supp = 0;
	encode.ms_classmark_3.extended_tsc_set_cap_supp = 1;
	encode.ms_classmark_3.extended_earfcn_val_range = 1;
	encode.ms_classmark_3.spare3 = 0;

	encode.sup_codec_list_len = 7;
	encode.sup_codec_list[0].sysid = 2;
	encode.sup_codec_list[0].len_bitmap_sysid = 2;
	encode.sup_codec_list[0].codec_bitmap_1_8 = 6;
	encode.sup_codec_list[0].codec_bitmap_9_16 = 5;
	encode.sup_codec_list[1].sysid = 1;
	encode.sup_codec_list[1].len_bitmap_sysid = 1;
	encode.sup_codec_list[1].codec_bitmap_1_8 = 3;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_additional_mm_ctxt_for_srvcc_ie(&encode, buf) == 37);
	CU_ASSERT(encode_gtpv1_additional_mm_ctxt_for_srvcc_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_additional_mm_ctxt_for_srvcc_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_additional_mm_ctxt_for_srvcc_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 37, 64, 64, "cf002203395fbf1551219929ac7356449d6cebf9f66f33d2b5bbfb2bb00702020605010103" ) == 0);
}

void test_encode_gtpv1_additional_flags_for_srvcc_ie(void)
{
	gtpv1_additional_flags_for_srvcc_ie_t encode = {0};
	encode.header.type = GTPV1_IE_ADDTL_FLGS_SRVCC;
	encode.header.length = 1;
	encode.spare = 0;
	encode.ics = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_additional_flags_for_srvcc_ie(&encode, buf) == 4);
	CU_ASSERT(encode_gtpv1_additional_flags_for_srvcc_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_additional_flags_for_srvcc_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_additional_flags_for_srvcc_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 4, 64, 64, "d0000101" ) == 0);
}

void test_encode_gtpv1_stn_sr_ie(void)
{
	gtpv1_stn_sr_ie_t encode = {0};
	encode.header.type = GTPV1_IE_STN_SR;
	encode.header.length = 3;
	encode.nanpi = 1;
	encode.digits[0].digit1 = 0;
	encode.digits[0].digit2 = 1;
	encode.digits[1].digit1 = 2;
	encode.digits[1].digit2 = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_stn_sr_ie(&encode, buf) == 6);
	CU_ASSERT(encode_gtpv1_stn_sr_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_stn_sr_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_stn_sr_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 6, 64, 64, "d10003010121" ) == 0);
}

void test_encode_gtpv1_c_msisdn_ie(void)
{
	gtpv1_c_msisdn_ie_t encode = {0};
	encode.header.type = GTPV1_IE_C_MSISDN;
	encode.header.length = 5;
	strncpy((char *)&encode.msisdn, "23456", 5);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_c_msisdn_ie(&encode, buf) == 8);
	CU_ASSERT(encode_gtpv1_c_msisdn_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_c_msisdn_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_c_msisdn_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 8, 64, 64, "d200053233343536" ) == 0);
}

void test_encode_gtpv1_extended_ranap_cause_ie(void)
{
	gtpv1_extended_ranap_cause_ie_t encode = {0};
	encode.header.type = GTPV1_IE_EXTENDED_RANAP_CAUSE;
	encode.header.length = 2;
	encode.extended_ranap_cause = 2;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_extended_ranap_cause_ie(&encode, buf) == 5);
	CU_ASSERT(encode_gtpv1_extended_ranap_cause_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_extended_ranap_cause_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_extended_ranap_cause_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 5, 64, 64, "d300020002" ) == 0);
}

void test_encode_gtpv1_enodeb_id_ie(void)
{
	gtpv1_enodeb_id_ie_t encode = {0};
	encode.header.type = GTPV1_IE_ENODEB_ID;
	encode.header.length = 9;
	encode.enodeb_type = 0;
	encode.mcc_digit_2 = 0x2;
	encode.mcc_digit_1 = 0x2;
	encode.mnc_digit_3 = 0x0;
	encode.mcc_digit_3 = 0x1;
	encode.mnc_digit_1 = 0x1;
	encode.mnc_digit_2 = 0x1;
	encode.spare = 0;
	encode.macro_enodeb_id = 2;
	encode.macro_enodeb_id2 = 3;
	encode.home_enodeb_id = 0;
	encode.home_enodeb_id2 = 0;
	encode.tac = 20;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_enodeb_id_ie(&encode, buf) == 12);
	CU_ASSERT(encode_gtpv1_enodeb_id_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_enodeb_id_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_enodeb_id_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 12, 64, 64, "d40009002201110200030014" ) == 0);
}

void test_encode_gtpv1_node_identifier_ie(void)
{
	gtpv1_node_identifier_ie_t encode = {0};
	encode.header.type = GTPV1_IE_NODE_IDENTIFIER;
	encode.header.length = 8;
	encode.len_of_node_name = 3;
	strncpy((char *)&encode.node_name, "mme", 3);
	encode.len_of_node_realm = 3;
	strncpy((char *)&encode.node_realm, "aaa", 3);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_node_identifier_ie(&encode, buf) == 11);
	CU_ASSERT(encode_gtpv1_node_identifier_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_node_identifier_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_node_identifier_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 11, 64, 64, "db0008036d6d6503616161" ) == 0);
}

void fill_encode_ms_network_capability_value(gtpv1_ms_network_capability_value_t *encode) {
	encode->GEA_1 = 0;
	encode->sm_capabilities_via_dedicated_channels = 0;
	encode->sm_capabilities_via_gprs_channels  = 0;
	encode->ucs2_support  = 0;
	encode->ss_screening_indicator  = 0;
	encode->solsa_capability  = 0;
	encode->revision_level_indicator  = 0;
	encode->pfc_feature_mode  = 0;
	encode->GEA_2  = 0;
	encode->GEA_3  = 0;
	encode->GEA_4  = 0;
	encode->GEA_5  = 0;
	encode->GEA_6  = 0;
	encode->GEA_7  = 0;
	encode->lcs_va_capability  = 0;
	encode->ps_ge_ut_iu_mode_capability  = 0;
	encode->ps_ge_ut_s1_mode_capability  = 0;
	encode->emm_combined_procedure_capability  = 0;
	encode->isr_support  = 0;
	encode->srvcc_to_ge_ut_capability  = 0;
	encode->epc_capability  = 0;
	encode->nf_capability  = 0;
	encode->ge_network_sharing_capability  = 0;
	encode->user_plane_integrity_protection_support  = 0;
	encode->GIA_4  = 0;
	encode->GIA_5  = 0;
	encode->GIA_6  = 0;
	encode->GIA_7  = 0;
	encode->ePCO_ie_indicator  = 0;
	encode->restriction_on_use_of_enhanced_coverage_capability  = 0;
	encode->dual_connectivity_of_e_ut_with_nr_capability  = 0;
	return;
}
void test_encode_gtpv1_mm_context_ie(void)
{
	gtpv1_mm_context_ie_t encode_0 = {0};
	encode_0.header.type = GTPV1_IE_MM_CONTEXT;
	encode_0.header.length = 97;
	encode_0.mm_context.used_cipher_value_umts_keys_and_quintuplets.ksi = 1;
	encode_0.mm_context.used_cipher_value_umts_keys_and_quintuplets.used_gprs_integrity_protection_algo = 1;
	encode_0.mm_context.used_cipher_value_umts_keys_and_quintuplets.ugipai = 1;
	encode_0.mm_context.used_cipher_value_umts_keys_and_quintuplets.gupii = 1;
	encode_0.mm_context.used_cipher_value_umts_keys_and_quintuplets.used_cipher = 1;
	encode_0.security_mode = 0;
	encode_0.mm_context.used_cipher_value_umts_keys_and_quintuplets.no_of_vectors = 1;
	strncpy((char *)&encode_0.mm_context.used_cipher_value_umts_keys_and_quintuplets.ck, "1111111111111111", 16);
	strncpy((char *)&encode_0.mm_context.used_cipher_value_umts_keys_and_quintuplets.ik, "1111111111111111", 16);
	encode_0.mm_context.used_cipher_value_umts_keys_and_quintuplets.quintuplet_length = 52;
	strncpy((char *)&encode_0.mm_context.used_cipher_value_umts_keys_and_quintuplets.quintuplet[0].rand, "1111111111111111", 16);
	encode_0.mm_context.used_cipher_value_umts_keys_and_quintuplets.quintuplet[0].xres_length = 1;
	strncpy((char *)&encode_0.mm_context.used_cipher_value_umts_keys_and_quintuplets.quintuplet[0].xres, "1", 1);
	strncpy((char *)&encode_0.mm_context.used_cipher_value_umts_keys_and_quintuplets.quintuplet[0].ck, "1111111111111111", 16);
	strncpy((char *)&encode_0.mm_context.used_cipher_value_umts_keys_and_quintuplets.quintuplet[0].ik, "1111111111111111", 16);
	encode_0.mm_context.used_cipher_value_umts_keys_and_quintuplets.quintuplet[0].autn_length = 1;
	strncpy((char *)&encode_0.mm_context.used_cipher_value_umts_keys_and_quintuplets.quintuplet[0].autn, "1", 1);
	encode_0.drx_parameter.split_pg_cycle_code = 1;
	encode_0.drx_parameter.cycle_length = 1;
	encode_0.drx_parameter.ccch = 1;
	encode_0.drx_parameter.timer = 1;
	
	encode_0.ms_network_capability_length = 4;
	fill_encode_ms_network_capability_value(&encode_0.ms_network_capability);
	
	encode_0.container_length = 0;
	uint8_t buf_0[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_mm_context_ie(&encode_0, buf_0) == 100);
	CU_ASSERT(encode_gtpv1_mm_context_ie(NULL, buf_0) == -1);
	CU_ASSERT(encode_gtpv1_mm_context_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_mm_context_ie(&encode_0, NULL) == -1);
	CU_ASSERT(hexdump(buf_0, 99, 256, 256, "810061c90931313131313131313131313131313131313131313131313131313131313131310034313131313131313131313131313131310131313131313131313131313131313131313131313131313131313131313131313101310119040000000000" ) == 0);

	gtpv1_mm_context_ie_t encode_1 = {0};
	encode_1.header.type = GTPV1_IE_MM_CONTEXT;
	encode_1.header.length = 47;
	encode_1.mm_context.gsm_keys_and_triplet.spare = 15;
	encode_1.mm_context.gsm_keys_and_triplet.cksn = 1;
	encode_1.security_mode = 1;
	encode_1.mm_context.gsm_keys_and_triplet.no_of_vectors = 1;
	encode_1.mm_context.gsm_keys_and_triplet.used_cipher = 1;
	encode_1.mm_context.gsm_keys_and_triplet.kc = 1;
	strncpy((char *)&encode_1.mm_context.gsm_keys_and_triplet.triplet[0].rand,"1111111111111111",16);
	encode_1.mm_context.gsm_keys_and_triplet.triplet[0].sres = 2;
	encode_1.mm_context.gsm_keys_and_triplet.triplet[0].kc = 2;
	encode_1.drx_parameter.split_pg_cycle_code = 1;
	encode_1.drx_parameter.cycle_length = 1;
	encode_1.drx_parameter.ccch = 1;
	encode_1.drx_parameter.timer = 1;
	
	encode_1.ms_network_capability_length = 4;
	fill_encode_ms_network_capability_value(&encode_1.ms_network_capability);
	
	encode_1.container_length = 0;
	uint8_t buf_1[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_mm_context_ie(&encode_1, buf_1) == 50);
	CU_ASSERT(encode_gtpv1_mm_context_ie(NULL, buf_1) == -1);
	CU_ASSERT(encode_gtpv1_mm_context_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_mm_context_ie(&encode_1, NULL) == -1);
//	CU_ASSERT(hexdump(buf_1, 50, 256, 256, "81002f7949000000000000000131313131313131313131313131313131000000020000000000000002011904000000000000")==0);

	gtpv1_mm_context_ie_t encode_2 = {0};
	encode_2.header.type = GTPV1_IE_MM_CONTEXT;
	encode_2.header.length = 97;
	encode_2.mm_context.umts_keys_and_quintuplets.ksi = 1;
	encode_2.mm_context.umts_keys_and_quintuplets.used_gprs_integrity_protection_algo = 1;
	encode_2.mm_context.umts_keys_and_quintuplets.ugipai = 1;
	encode_2.mm_context.umts_keys_and_quintuplets.gupii = 1;
	encode_2.mm_context.umts_keys_and_quintuplets.spare = 7;
	encode_2.security_mode = 2;
	encode_2.mm_context.umts_keys_and_quintuplets.no_of_vectors = 1;
	strncpy((char *)&encode_2.mm_context.umts_keys_and_quintuplets.ck, "1111111111111111", 16);
	strncpy((char *)&encode_2.mm_context.umts_keys_and_quintuplets.ik, "1111111111111111", 16);
	encode_2.mm_context.umts_keys_and_quintuplets.quintuplet_length = 52;
	strncpy((char *)&encode_2.mm_context.umts_keys_and_quintuplets.quintuplet[0].rand, "1111111111111111", 16);
	encode_2.mm_context.umts_keys_and_quintuplets.quintuplet[0].xres_length = 1;
	strncpy((char *)&encode_2.mm_context.umts_keys_and_quintuplets.quintuplet[0].xres, "1", 1);
	strncpy((char *)&encode_2.mm_context.umts_keys_and_quintuplets.quintuplet[0].ck, "1111111111111111", 16);
	strncpy((char *)&encode_2.mm_context.umts_keys_and_quintuplets.quintuplet[0].ik, "1111111111111111", 16);
	encode_2.mm_context.umts_keys_and_quintuplets.quintuplet[0].autn_length = 1;
	strncpy((char *)&encode_2.mm_context.umts_keys_and_quintuplets.quintuplet[0].autn, "1", 1);
	encode_2.drx_parameter.split_pg_cycle_code = 1;
	encode_2.drx_parameter.cycle_length = 1;
	encode_2.drx_parameter.ccch = 1;
	encode_2.drx_parameter.timer = 1;

	encode_2.ms_network_capability_length = 4;
	fill_encode_ms_network_capability_value(&encode_2.ms_network_capability);
	
	encode_2.container_length = 0;
	uint8_t buf_2[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_mm_context_ie(&encode_2, buf_2) == 100);
	CU_ASSERT(encode_gtpv1_mm_context_ie(NULL, buf_2) == -1);
	CU_ASSERT(encode_gtpv1_mm_context_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_mm_context_ie(&encode_2, NULL) == -1);
//	CU_ASSERT(hexdump(buf_2, 100, 256, 256, "810061c98f3131313131313131313131313131313131313131313131313131313131313131003431313131313131313131313131313131010131313131313131313131313131313131313131313131313131313131313131310101011904000000000000")==0);

	gtpv1_mm_context_ie_t encode_3 = {0};
	encode_3.header.type = GTPV1_IE_MM_CONTEXT;
	encode_3.header.length = 73;
	encode_3.mm_context.gsm_keys_and_umts_quintuplets.spare = 15;
	encode_3.mm_context.gsm_keys_and_umts_quintuplets.cksn = 1;
	encode_3.security_mode = 3;
	encode_3.mm_context.gsm_keys_and_umts_quintuplets.no_of_vectors = 1;
	encode_3.mm_context.gsm_keys_and_umts_quintuplets.used_cipher = 1;
	encode_3.mm_context.gsm_keys_and_umts_quintuplets.kc = 1;
	encode_3.mm_context.gsm_keys_and_umts_quintuplets.quintuplet_length = 52;
	strncpy((char *)&encode_3.mm_context.gsm_keys_and_umts_quintuplets.quintuplet[0].rand, "1111111111111111", 16);
	encode_3.mm_context.gsm_keys_and_umts_quintuplets.quintuplet[0].xres_length = 1;
	strncpy((char *)&encode_3.mm_context.gsm_keys_and_umts_quintuplets.quintuplet[0].xres,"1", 1);
	strncpy((char *)&encode_3.mm_context.gsm_keys_and_umts_quintuplets.quintuplet[0].ck, "1111111111111111", 16);
	strncpy((char *)&encode_3.mm_context.gsm_keys_and_umts_quintuplets.quintuplet[0].ik, "1111111111111111", 16);
	encode_3.mm_context.gsm_keys_and_umts_quintuplets.quintuplet[0].autn_length = 1;
	strncpy((char *)&encode_3.mm_context.gsm_keys_and_umts_quintuplets.quintuplet[0].autn,"1", 1);

	encode_3.drx_parameter.split_pg_cycle_code = 1;
	encode_3.drx_parameter.cycle_length = 1;
	encode_3.drx_parameter.ccch = 1;
	encode_3.drx_parameter.timer = 1;
	
	encode_3.ms_network_capability_length = 4;
	fill_encode_ms_network_capability_value(&encode_3.ms_network_capability);
	
	encode_3.container_length = 0;
	uint8_t buf_3[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_mm_context_ie(&encode_3, buf_3) == 76);
	CU_ASSERT(encode_gtpv1_mm_context_ie(NULL, buf_3) == -1);
	CU_ASSERT(encode_gtpv1_mm_context_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_mm_context_ie(&encode_3, NULL) == -1);
	CU_ASSERT(hexdump(buf_3, 76, 256, 256, "81004979c90000000000000001003431313131313131313131313131313131013131313131313131313131313131313131313131313131313131313131313131310131011904000000000000")==0);
}

void test_encode_gtpv1_pdp_context_ie(void)
{
	gtpv1_pdp_context_ie_t encode = {0};
	encode.header.type = GTPV1_IE_PDP_CONTEXT;
	encode.header.length = 116;
	encode.ea = 0;
	encode.vaa = 1;
	encode.asi = 1;
	encode.order = 0;
	encode.nsapi = 5;
	encode.spare = 0;
	encode.sapi = 1;
	encode.qos_sub_length = 21;
	encode.qos_sub.allocation_retention_priority = 2;
	encode.qos_sub.spare1 = 0;
	encode.qos_sub.delay_class = 2;
	encode.qos_sub.reliablity_class = 2;
	encode.qos_sub.peak_throughput = 3;
	encode.qos_sub.spare2 = 0;
	encode.qos_sub.precedence_class = 1;
	encode.qos_sub.spare3 = 0;
	encode.qos_sub.mean_throughput = 4;
	encode.qos_sub.traffic_class = 1;
	encode.qos_sub.delivery_order = 1;
	encode.qos_sub.delivery_erroneous_sdu = 2;
	encode.qos_sub.max_sdu_size = 3;
	encode.qos_sub.max_bitrate_uplink = 123;
	encode.qos_sub.max_bitrate_downlink = 234;
	encode.qos_sub.residual_ber = 1;
	encode.qos_sub.sdu_error_ratio = 1;
	encode.qos_sub.transfer_delay = 1;
	encode.qos_sub.traffic_handling_priority = 2;
	encode.qos_sub.guaranteed_bitrate_uplink = 122;
	encode.qos_sub.guaranteed_bitrate_downlink = 222;
	encode.qos_sub.spare4 = 0;
	encode.qos_sub.signalling_indication = 1;
	encode.qos_sub.source_statistics_descriptor = 1;
	encode.qos_sub.max_bitrate_downlink_ext1 = 22;
	encode.qos_sub.guaranteed_bitrate_downlink_ext1 = 11;
	encode.qos_sub.max_bitrate_uplink_ext1 = 33;
	encode.qos_sub.guaranteed_bitrate_uplink_ext1 = 22;
	encode.qos_sub.max_bitrate_downlink_ext2 = 44;
	encode.qos_sub.guaranteed_bitrate_downlink_ext2 = 33;
	encode.qos_sub.max_bitrate_uplink_ext2 = 34;
	encode.qos_sub.guaranteed_bitrate_uplink_ext2 = 23;
	encode.qos_req_length = 21;
	encode.qos_req.allocation_retention_priority = 2;
	encode.qos_req.spare1 = 0;
	encode.qos_req.delay_class = 2;
	encode.qos_req.reliablity_class = 2;
	encode.qos_req.peak_throughput = 3;
	encode.qos_req.spare2 = 0;
	encode.qos_req.precedence_class = 1;
	encode.qos_req.spare3 = 0;
	encode.qos_req.mean_throughput = 4;
	encode.qos_req.traffic_class = 1;
	encode.qos_req.delivery_order = 1;
	encode.qos_req.delivery_erroneous_sdu = 2;
	encode.qos_req.max_sdu_size = 3;
	encode.qos_req.max_bitrate_uplink = 123;
	encode.qos_req.max_bitrate_downlink = 234;
	encode.qos_req.residual_ber = 1;
	encode.qos_req.sdu_error_ratio = 1;
	encode.qos_req.transfer_delay = 1;
	encode.qos_req.traffic_handling_priority = 2;
	encode.qos_req.guaranteed_bitrate_uplink = 122;
	encode.qos_req.guaranteed_bitrate_downlink = 222;
	encode.qos_req.spare4 = 0;
	encode.qos_req.signalling_indication = 1;
	encode.qos_req.source_statistics_descriptor = 1;
	encode.qos_req.max_bitrate_downlink_ext1 = 22;
	encode.qos_req.guaranteed_bitrate_downlink_ext1 = 11;
	encode.qos_req.max_bitrate_uplink_ext1 = 33;
	encode.qos_req.guaranteed_bitrate_uplink_ext1 = 22;
	encode.qos_req.max_bitrate_downlink_ext2 = 44;
	encode.qos_req.guaranteed_bitrate_downlink_ext2 = 33;
	encode.qos_req.max_bitrate_uplink_ext2 = 34;
	encode.qos_req.guaranteed_bitrate_uplink_ext2 = 23;
	encode.qos_neg_length = 21;
	encode.qos_neg.allocation_retention_priority = 2;
	encode.qos_neg.spare1 = 0;
	encode.qos_neg.delay_class = 2;
	encode.qos_neg.reliablity_class = 2;
	encode.qos_neg.peak_throughput = 3;
	encode.qos_neg.spare2 = 0;
	encode.qos_neg.precedence_class = 1;
	encode.qos_neg.spare3 = 0;
	encode.qos_neg.mean_throughput = 4;
	encode.qos_neg.traffic_class = 1;
	encode.qos_neg.delivery_order = 1;
	encode.qos_neg.delivery_erroneous_sdu = 2;
	encode.qos_neg.max_sdu_size = 3;
	encode.qos_neg.max_bitrate_uplink = 123;
	encode.qos_neg.max_bitrate_downlink = 234;
	encode.qos_neg.residual_ber = 1;
	encode.qos_neg.sdu_error_ratio = 1;
	encode.qos_neg.transfer_delay = 1;
	encode.qos_neg.traffic_handling_priority = 2;
	encode.qos_neg.guaranteed_bitrate_uplink = 122;
	encode.qos_neg.guaranteed_bitrate_downlink = 222;
	encode.qos_neg.spare4 = 0;
	encode.qos_neg.signalling_indication = 1;
	encode.qos_neg.source_statistics_descriptor = 1;
	encode.qos_neg.max_bitrate_downlink_ext1 = 22;
	encode.qos_neg.guaranteed_bitrate_downlink_ext1 = 11;
	encode.qos_neg.max_bitrate_uplink_ext1 = 33;
	encode.qos_neg.guaranteed_bitrate_uplink_ext1 = 22;
	encode.qos_neg.max_bitrate_downlink_ext2 = 44;
	encode.qos_neg.guaranteed_bitrate_downlink_ext2 = 33;
	encode.qos_neg.max_bitrate_uplink_ext2 = 34;
	encode.qos_neg.guaranteed_bitrate_uplink_ext2 = 23;
	encode.sequence_number_down = 1;
	encode.sequence_number_up = 2;
	encode.send_npdu_number = 255;
	encode.rcv_npdu_number = 255;
	encode.uplink_teid_cp = 0x372f0000;
	encode.uplink_teid_data1 = 0x37300000;
	encode.pdp_ctxt_identifier = 0;
	encode.spare2 = 15;
	encode.pdp_type_org = 1;
	encode.pdp_type_number1 = 0x21;
	encode.pdp_address_length1 = 4;
	encode.pdp_address1.ipv4 = 355240599;
	encode.ggsn_addr_cp_length = 4;
	encode.ggsn_addr_cp.ipv4 = 355240589;
	encode.ggsn_addr_ut_length = 4;
	encode.ggsn_addr_ut.ipv4 = 355240599;
	encode.apn_length = 13;
	strncpy((char *)&encode.apn, "nextphones.co", 13);
	encode.spare3 = 0;
	encode.transaction_identifier1 = 10;
	encode.transaction_identifier2 = 55;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_pdp_context_ie(&encode, buf) == 119);
	CU_ASSERT(encode_gtpv1_pdp_context_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_pdp_context_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_pdp_context_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 119, 256, 256, "820074650115021231042a037bea11067ade11160b21162c21221715021231042a037bea11067ade11160b21162c21221715021231042a037bea11067ade11160b21162c21221700010002ffff372f00003730000000f12104152c8a9704152c8a8d04152c8a970d6e65787470686f6e65732e636f0a37") == 0);
}

void test_encode_gtpv1_mbms_ue_context_ie(void)
{
	gtpv1_mbms_ue_context_ie_t encode = {0};
	encode.header.type = GTPV1_IE_MBMS_UE_CONTEXT;
	encode.header.length = 34;
	encode.linked_nsapi = 2;
	encode.spare1 = 0;
	encode.uplink_teid_cp = 0x372f0000;
	encode.enhanced_nsapi = 129;
	encode.spare2 = 15;
	encode.pdp_type_org = 1;
	encode.pdp_type_number = 0x21;
	encode.pdp_address_length = 4;
	encode.pdp_address.ipv4 = 355240599;
	encode.ggsn_addr_cp_length = 4;
	encode.ggsn_addr_cp.ipv4 = 355240589;
	encode.apn_length = 13;
	strncpy((char *)&encode.apn, "nextphones.co", 13);
	encode.spare3 = 0;
	encode.transaction_identifier1 = 1;
	encode.transaction_identifier2 = 5;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_mbms_ue_context_ie(&encode, buf) == 37);
	CU_ASSERT(encode_gtpv1_mbms_ue_context_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_mbms_ue_context_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_mbms_ue_context_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 37, 64, 64, "9c002220372f000081f12104152c8a9704152c8a8d0d6e65787470686f6e65732e636f0105") == 0);
}


void test_encode_gtpv1_ue_ambr_ie(void)
{
	gtpv1_ue_ambr_ie_t encode = {0};
	encode.header.type = GTPV1_IE_UE_AMBR;
	encode.header.length = 8;
	encode.subscribed_ue_ambr_for_uplink = 1;
	encode.subscribed_ue_ambr_for_downlink = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_ue_ambr_ie(&encode, buf) == 11);
	CU_ASSERT(encode_gtpv1_ue_ambr_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_ue_ambr_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_ue_ambr_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 11, 64, 64, "c800080000000100000001") == 0);

	gtpv1_ue_ambr_ie_t encode_2 = {0};
	encode_2.header.type = GTPV1_IE_UE_AMBR;
	encode_2.header.length = 16;
	encode_2.subscribed_ue_ambr_for_uplink = 8;
	encode_2.subscribed_ue_ambr_for_downlink = 16;
	encode_2.authorized_ue_ambr_for_uplink = 32;
	encode_2.authorized_ue_ambr_for_downlink = 64;
	uint8_t buf2[SIZE];

	CU_ASSERT(encode_gtpv1_ue_ambr_ie(&encode_2, buf2) == 19);
	CU_ASSERT(encode_gtpv1_ue_ambr_ie(NULL, buf2) == -1);
	CU_ASSERT(encode_gtpv1_ue_ambr_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_ue_ambr_ie(&encode_2, NULL) == -1);
	CU_ASSERT(hexdump(buf2, 19, 64, 64, "c8001000000008000000100000002000000040") == 0);
}

void test_encode_gtpv1_ue_scef_pdn_connection_ie(void)
{
	gtpv1_ue_scef_pdn_connection_ie_t encode = {0};
	encode.header.type = GTPV1_IE_UE_SCEF_PDN_CONNTECTION;
	encode.header.length = 19;
	encode.apn_length = 13;
	strncpy((char *)&encode.apn, "nextphones.co", 13);
	encode.spare = 0;
	encode.nsapi = 5;
	encode.scef_id_length = 3;
	strncpy((char *)&encode.scef_id, "111", 3);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_ue_scef_pdn_connection_ie(&encode, buf) == 22);
	CU_ASSERT(encode_gtpv1_ue_scef_pdn_connection_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_ue_scef_pdn_connection_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_ue_scef_pdn_connection_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 22, 64, 64, "dd00130d6e65787470686f6e65732e636f0503313131") == 0);
}

void test_encode_gtpv1_auth_triplet_ie(void)
{
	gtpv1_auth_triplet_ie_t encode = {0};
	encode.header.type = GTPV1_IE_AUTH_TRIPLET;
	strncpy((char *)&encode.auth_triplet_value.rand, "1111111111111111", 16);
	encode.auth_triplet_value.sres = 2;
	encode.auth_triplet_value.kc = 2;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_auth_triplet_ie(&encode, buf) == 29);
	CU_ASSERT(encode_gtpv1_auth_triplet_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_auth_triplet_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_auth_triplet_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 29, 64, 64, "0931313131313131313131313131313131000000020000000000000002" ) == 0);
}

void test_encode_gtpv1_auth_quintuplet_ie(void)
{
	gtpv1_auth_quintuplet_ie_t encode = {0};
	encode.header.type = GTPV1_IE_AUTH_QUINTUPLET;
	encode.header.length = 52;
	strncpy((char *)&encode.auth_quintuplet_value.rand, "1111111111111111", 16);
	encode.auth_quintuplet_value.xres_length = 1;
	strncpy((char *)&encode.auth_quintuplet_value.xres, "1", 1);
	strncpy((char *)&encode.auth_quintuplet_value.ck, "1111111111111111", 16);
	strncpy((char *)&encode.auth_quintuplet_value.ik, "1111111111111111", 16);
	encode.auth_quintuplet_value.autn_length = 1;
	strncpy((char *)&encode.auth_quintuplet_value.autn, "1", 1);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_auth_quintuplet_ie(&encode, buf) == 55);
	CU_ASSERT(encode_gtpv1_auth_quintuplet_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_auth_quintuplet_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_auth_quintuplet_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 55, 64, 64, "88003431313131313131313131313131313131013131313131313131313131313131313131313131313131313131313131313131310131" ) == 0);
}

void test_encode_gtpv1_src_rnc_pdcp_ctxt_info_ie(void)
{
	gtpv1_src_rnc_pdcp_ctxt_info_ie_t encode = {0};
	encode.header.type = GTPV1_IE_SRC_RNC_PDCP_CTXT_INFO;
	encode.header.length = 5;
	strncpy((char *)&encode.rrc_container, "gslab", 5);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_src_rnc_pdcp_ctxt_info_ie(&encode, buf) == 8);
	CU_ASSERT(encode_gtpv1_src_rnc_pdcp_ctxt_info_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_src_rnc_pdcp_ctxt_info_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_src_rnc_pdcp_ctxt_info_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 8, 64, 64, "a1000567736c6162" ) == 0);
}

void test_encode_gtpv1_pdu_numbers_ie(void)
{
	gtpv1_pdu_numbers_ie_t encode = {0};
	encode.header.type = GTPV1_IE_PDU_NUMBERS;
	encode.header.length = 9;
	encode.spare = 0;
	encode.nsapi = 1;
	encode.dl_gtpu_seqn_nbr = 1;
	encode.ul_gtpu_seqn_nbr = 1;
	encode.snd_npdu_nbr = 1;
	encode.rcv_npdu_nbr = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_pdu_numbers_ie(&encode, buf) == 12);
	CU_ASSERT(encode_gtpv1_pdu_numbers_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_pdu_numbers_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_pdu_numbers_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 12, 64, 64, "af0009010001000100010001") == 0);
}

void test_encode_gtpv1_extension_header_type_list_ie(void)
{
	gtpv1_extension_header_type_list_ie_t encode = {0};
	encode.type = GTPV1_IE_EXTENSION_HEADER_TYPE_LIST;
	encode.length = 2;
	encode.extension_type_list[0] = 1;
	encode.extension_type_list[1] = 0;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_extension_header_type_list_ie(&encode, buf) == 4);
	CU_ASSERT(encode_gtpv1_extension_header_type_list_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_extension_header_type_list_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_extension_header_type_list_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 4, 64, 64, "8d020100") == 0);
}

void test_encode_gtpv1_iov_updates_counter_ie(void)
{
	gtpv1_iov_updates_counter_ie_t encode = {0};
	encode.header.type = GTPV1_IE_IOV_UPDATES_COUNTER;
	encode.header.length = 1;
	encode.iov_updates_counter = 10;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_iov_updates_counter_ie(&encode, buf) == 4);
	CU_ASSERT(encode_gtpv1_iov_updates_counter_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_iov_updates_counter_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_iov_updates_counter_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 4, 64, 64, "de00010a") == 0);
}

void test_encode_gtpv1_ue_usage_type_ie(void)
{
	gtpv1_ue_usage_type_ie_t encode = {0};
	encode.header.type = GTPV1_IE_UE_USAGE_TYPE;
	encode.header.length = 4;
	encode.ue_usage_type_value = 1;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_ue_usage_type_ie(&encode, buf) == 7);
	CU_ASSERT(encode_gtpv1_ue_usage_type_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_ue_usage_type_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_ue_usage_type_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 7, 64, 64, "d9000400000001") == 0);
}

void test_encode_gtpv1_teid_control_plane_ie(void)
{
	gtpv1_teid_ie_t encode = {0};
	encode.header.type = GTPV1_IE_TEID_CONTROL_PLANE;
	encode.teid = 0x0fffeee;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_teid_ie(&encode, buf) == 5);
	CU_ASSERT(encode_gtpv1_teid_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_teid_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_teid_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 5, 64, 64, "1100fffeee") == 0);
}

void test_encode_gtpv1_additional_rab_setup_info_ie(void)
{
	gtpv1_rab_setup_info_ie_t encode = {0};
	encode.header.type = GTPV1_IE_ADDITIONAL_RAB_SETUP_INFO;
	encode.header.length = 1;
	encode.spare = 0;
	encode.nsapi = 2;
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_rab_setup_info_ie(&encode, buf) == 4);
	CU_ASSERT(encode_gtpv1_rab_setup_info_ie(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_rab_setup_info_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_rab_setup_info_ie(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 4, 64, 64, "92000102" ) == 0);

	gtpv1_rab_setup_info_ie_t encode1 = {0};
	encode1.header.type = GTPV1_IE_ADDITIONAL_RAB_SETUP_INFO;
	encode1.header.length = 21;
	encode1.spare = 0;
	encode1.nsapi = 2;
	encode1.teid = 0x0fffeee;
	char *str = "2001:db80:3333:4444:5555:6666:7777:8885";
	inet_pton(AF_INET6, str, encode1.rnc_ip_addr.ipv6);
	uint8_t buf1[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_rab_setup_info_ie(&encode1, buf1) == 24);
	CU_ASSERT(encode_gtpv1_rab_setup_info_ie(NULL, buf1) == -1);
	CU_ASSERT(encode_gtpv1_rab_setup_info_ie(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_rab_setup_info_ie(&encode1, NULL) == -1);
	CU_ASSERT(hexdump(buf1, 24, 64, 64, "9200150200fffeee2001db80333344445555666677778885" ) == 0);
}
