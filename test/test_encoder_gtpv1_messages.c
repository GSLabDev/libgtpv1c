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

#include "test_encoder_gtpv1_messages.h"

void test_encode_gtpv1_echo_req(void)
{
	gtpv1_echo_req_t encode = {0};
	fill_gtpv1_echo_req(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_echo_req(&encode, buf) == 17);
	CU_ASSERT(encode_gtpv1_echo_req(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_echo_req(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_echo_req(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 17, 64, 64, "3001000900000000ff0006000c32303231") == 0);
}

void test_encode_gtpv1_echo_rsp(void)
{
	gtpv1_echo_rsp_t encode = {0};
	fill_gtpv1_echo_rsp(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_echo_rsp(&encode, buf) == 19);
	CU_ASSERT(encode_gtpv1_echo_rsp(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_echo_rsp(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_echo_rsp(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 19, 64, 64, "3002000b372f00000e02ff0006000c32303231") == 0);
}

void test_encode_gtpv1_version_not_supported(void)
{
	gtpv1_version_not_supported_t encode = {0};
	fill_gtpv1_version_not_supported(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_version_not_supported(&encode, buf) == 8);
	CU_ASSERT(encode_gtpv1_version_not_supported(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_version_not_supported(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_version_not_supported(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 8, 64, 64, "3003000000000000") == 0);
}

void test_encode_gtpv1_supported_extension_headers_notification(void)
{
	gtpv1_supported_extension_headers_notification_t encode = {0};
	fill_gtpv1_supported_extension_headers_notification(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_supported_extension_headers_notification(&encode, buf) == 12);
	CU_ASSERT(encode_gtpv1_supported_extension_headers_notification(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_supported_extension_headers_notification(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_supported_extension_headers_notification(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 12, 64, 64, "301f0004372f00008d020100") == 0);
}

void test_encode_gtpv1_create_pdp_ctxt_req(void)
{
	gtpv1_create_pdp_ctxt_req_t encode = {0};
	fill_gtpv1_create_pdp_ctxt_req(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_create_pdp_ctxt_req(&encode, buf) == 298);
	CU_ASSERT(encode_gtpv1_create_pdp_ctxt_req(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_create_pdp_ctxt_req(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_create_pdp_ctxt_req(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 298, 512, 512, "30100122000000000272021300000000f00f0114051000fffeee11000000ab14091a0001800006f121c0a8002c8400198100020933353532343035393900020933353532343035383983000d6e65787470686f6e65732e636f850004c0a8002c850004c0a8002c8600023232870015021231042a037bfe11067ade11fa0b21162c212217890013321501010125010201000102010201030302009a00081111111122222211970001020304f4870014141b00091c00098e000532323232328f00076162632e636f6d9800080104f487000100019900020101a20009000001000101010101b7000105c2000804f4870100000141cb000101d8000102df00020002e00001010e02940001ff9500010cbf000171c10001ffc600080000000a00000007ff0006000c32303231") == 0);
}

void test_encode_gtpv1_create_pdp_ctxt_rsp(void)
{
	gtpv1_create_pdp_ctxt_rsp_t encode = {0};
	fill_gtpv1_create_pdp_ctxt_rsp(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_create_pdp_ctxt_rsp(&encode, buf) == 242);
	CU_ASSERT(encode_gtpv1_create_pdp_ctxt_rsp(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_create_pdp_ctxt_rsp(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_create_pdp_ctxt_rsp(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 242, 256, 256, "301100ea372f0000018008000e021008020000110801000014087f0330410b800016f18dc0a8002c2001db8033334444555566667777888884001981000209333535323430353939000209333535323430353839850004c0a8002c850004c0a8002b8500102001db803333444455556666777788888500102001db80333344445555666677778885870015021231042a037bea11067ade11160b21162c212217fb0004c0a8002cfb00102001db80313344445555666677778885940001ff9500010cb5000104b8000103bf000171c10001aac3000107c600080000000a00000007ca000108da000107ff0006000c32303231") == 0);
}

void test_encode_gtpv1_update_pdp_ctxt_req_sgsn(void)
{
	gtpv1_update_pdp_ctxt_req_sgsn_t encode = {0};
	fill_gtpv1_update_pdp_ctxt_req_sgsn(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_update_pdp_ctxt_req_sgsn(&encode, buf) == 286);
	CU_ASSERT(encode_gtpv1_update_pdp_ctxt_req_sgsn(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_update_pdp_ctxt_req_sgsn(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_update_pdp_ctxt_req_sgsn(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 286, 512, 512, "30120116372f00000272021300000000f00304f4870014140e021000fffeee11000000ab14051b00091c000984001981000209333535323430353939000209333535323430353839850004c0a8002c850004c0a8002c8500102001db803333444455556666777788888500102001db80333344445555666677778885870015021231042a037bea11067ade11160b21162c212217890013321501010125010201000102010201030302008e000532323232328f00076162632e636f6d940001ff970001029800080104f487000100019900020101a20009000001000101010101b6000107bf000171c1000100c2000804f4870100000141c600080000000000000007cb000101d80001019a00081111111122222211ff0006000c32303231") == 0);
}

void test_encode_gtpv1_update_pdp_ctxt_req_ggsn(void)
{
	gtpv1_update_pdp_ctxt_req_ggsn_t encode = {0};
	fill_gtpv1_update_pdp_ctxt_req_ggsn(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_update_pdp_ctxt_req_ggsn(&encode, buf) == 156);
	CU_ASSERT(encode_gtpv1_update_pdp_ctxt_req_ggsn(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_update_pdp_ctxt_req_ggsn(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_update_pdp_ctxt_req_ggsn(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 156, 256, 256, "30120094372f00000272021300000000f00e021405800006f121152c8a9784001981000209333535323430353939000209333535323430353839870015021231042a037bea11067ade11160b21162c21221789001332150101012501020100010201020103030200940001ff9500010cb5000104b6000107b8000103bf000171c1000100c3000107c600080000000000000007ff0006000c32303231") == 0);
}

void test_encode_gtpv1_update_pdp_ctxt_rsp_ggsn(void)
{
	gtpv1_update_pdp_ctxt_rsp_ggsn_t encode = {0};
	fill_gtpv1_update_pdp_ctxt_rsp_ggsn(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_update_pdp_ctxt_rsp_ggsn(&encode, buf) == 201);
	CU_ASSERT(encode_gtpv1_update_pdp_ctxt_rsp_ggsn(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_update_pdp_ctxt_rsp_ggsn(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_update_pdp_ctxt_rsp_ggsn(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 201, 256, 256, "301300c1372f000001800e021000fffeee11000000ab7f0330410b84001981000209333535323430353939000209333535323430353839850004c0a8002c850004c0a8002b850010111122223333444455556666777788888500102001db80333344445555666677778885870015021231042a037bea11067ade11160b21162c212217fb0004c0a8002cfb00102001db80313344445555666677778885940001ff9500010cb8000103b5000104bf000171c3000107c600080000000000000007ff0006000c32303231") == 0);
}

void test_encode_gtpv1_update_pdp_ctxt_rsp_sgsn(void)
{
	gtpv1_update_pdp_ctxt_rsp_sgsn_t encode = {0};
	fill_gtpv1_update_pdp_ctxt_rsp_sgsn(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_update_pdp_ctxt_rsp_sgsn(&encode, buf) == 120);
	CU_ASSERT(encode_gtpv1_update_pdp_ctxt_rsp_sgsn(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_update_pdp_ctxt_rsp_sgsn(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_update_pdp_ctxt_rsp_sgsn(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 120, 128, 128, "30130070372f000001800e021000fffeee84001981000209333535323430353939000209333535323430353839850004c0a8002b870015001231042a037bea11067ade11160b21162c2122179800080104f487000100019900020101b6000107bf000171c600080000000000000007ff0006000c32303231") == 0);
}

void test_encode_gtpv1_delete_pdp_ctxt_req(void)
{
	gtpv1_delete_pdp_ctxt_req_t encode = {0};
	fill_gtpv1_delete_pdp_ctxt_req(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_delete_pdp_ctxt_req(&encode, buf) == 78);
	CU_ASSERT(encode_gtpv1_delete_pdp_ctxt_req(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_delete_pdp_ctxt_req(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_delete_pdp_ctxt_req(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 78, 128, 128, "30140046372f0000018013011408840019810002093335353234303539390002093335353234303538399800080104f487000100019900020101c10001ffd6000400000003ff0006000c32303231") == 0);
}

void test_encode_gtpv1_delete_pdp_ctxt_rsp(void)
{
	gtpv1_delete_pdp_ctxt_rsp_t encode = {0};
	fill_gtpv1_delete_pdp_ctxt_rsp(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_delete_pdp_ctxt_rsp(&encode, buf) == 70);
	CU_ASSERT(encode_gtpv1_delete_pdp_ctxt_rsp(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_delete_pdp_ctxt_rsp(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_delete_pdp_ctxt_rsp(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 70, 128, 128, "3015003e372f00000180840019810002093335353234303539390002093335353234303538399800080104f487000100019900020101d6000400000003ff0006000c32303231") == 0);
}

void test_encode_gtpv1_pdu_notification_req(void)
{
	gtpv1_pdu_notification_req_t encode = {0};
	fill_gtpv1_pdu_notification_req(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_pdu_notification_req(&encode, buf) == 91);
	CU_ASSERT(encode_gtpv1_pdu_notification_req(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_pdu_notification_req(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_pdu_notification_req(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 91, 128, 128, "301b0053372f00000272021300000000f011000000ab800006f121c0a8002c83000d6e65787470686f6e65732e636f84001981000209333535323430353939000209333535323430353839850004c0a8002cff0006000c32303231") == 0);
}

void test_encode_gtpv1_pdu_notification_rsp(void)
{
	gtpv1_pdu_notification_rsp_t encode = {0};
	fill_gtpv1_pdu_notification_rsp(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_pdu_notification_rsp(&encode, buf) == 19);
	CU_ASSERT(encode_gtpv1_pdu_notification_rsp(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_pdu_notification_rsp(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_pdu_notification_rsp(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 19, 64, 64, "301c000b372f00000180ff0006000c32303231") == 0);
}

void test_encode_gtpv1_pdu_notification_reject_req(void)
{
	gtpv1_pdu_notification_reject_req_t encode = {0};
	fill_gtpv1_pdu_notification_reject_req(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_pdu_notification_reject_req(&encode, buf) == 77);
	CU_ASSERT(encode_gtpv1_pdu_notification_reject_req(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_pdu_notification_reject_req(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_pdu_notification_reject_req(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 77, 256, 256, "301d0045372f0000018011000000ab800006f121c0a8002c83000d6e65787470686f6e65732e636f84001981000209333535323430353939000209333535323430353839ff0006000c32303231") == 0);
}

void test_encode_gtpv1_pdu_notification_reject_rsp(void)
{
	gtpv1_pdu_notification_reject_rsp_t encode = {0};
	fill_gtpv1_pdu_notification_reject_rsp(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_pdu_notification_reject_rsp(&encode, buf) == 19);
	CU_ASSERT(encode_gtpv1_pdu_notification_reject_rsp(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_pdu_notification_reject_rsp(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_pdu_notification_reject_rsp(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 19, 64, 64, "301e000b372f00000180ff0006000c32303231") == 0);
}

void test_encode_gtpv1_initiate_pdp_ctxt_active_req(void)
{
	gtpv1_initiate_pdp_ctxt_active_req_t encode = {0};
	fill_gtpv1_initiate_pdp_ctxt_active_req(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_initiate_pdp_ctxt_active_req(&encode, buf) == 101);
	CU_ASSERT(encode_gtpv1_initiate_pdp_ctxt_active_req(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_initiate_pdp_ctxt_active_req(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_initiate_pdp_ctxt_active_req(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 101, 128, 128, "3016005d00000000140984001981000209333535323430353939000209333535323430353839870015021231042a037bea11067ade11160b21162c21221789001332150101012501020100010201020103030200b7000105bf000171ff0006000c32303231") == 0);
}

void test_encode_gtpv1_initiate_pdp_ctxt_active_rsp(void)
{
	gtpv1_initiate_pdp_ctxt_active_rsp_t encode = {0};
	fill_gtpv1_initiate_pdp_ctxt_active_rsp(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_initiate_pdp_ctxt_active_rsp(&encode, buf) == 47);
	CU_ASSERT(encode_gtpv1_initiate_pdp_ctxt_active_rsp(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_initiate_pdp_ctxt_active_rsp(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_initiate_pdp_ctxt_active_rsp(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 47, 64, 64, "30170027372f00000180ff0006000c3230323184001981000209333535323430353939000209333535323430353839") == 0);
}

void test_encode_gtpv1_send_routeing_info_for_gprs_req(void)
{
	gtpv1_send_routeing_info_for_gprs_req_t encode = {0};
	fill_gtpv1_send_routeing_info_for_gprs_req(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_send_routeing_info_for_gprs_req(&encode, buf) == 26);
	CU_ASSERT(encode_gtpv1_send_routeing_info_for_gprs_req(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_send_routeing_info_for_gprs_req(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_send_routeing_info_for_gprs_req(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 26, 64, 64, "30200012372f00000272021300000000f0ff0006000c32303231") == 0);
}

void test_encode_gtpv1_send_routeing_info_for_gprs_rsp(void)
{
	gtpv1_send_routeing_info_for_gprs_rsp_t encode = {0};
	fill_gtpv1_send_routeing_info_for_gprs_rsp(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_send_routeing_info_for_gprs_rsp(&encode, buf) == 39);
	CU_ASSERT(encode_gtpv1_send_routeing_info_for_gprs_rsp(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_send_routeing_info_for_gprs_rsp(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_send_routeing_info_for_gprs_rsp(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 39, 64, 64, "3021001f372f000001800272021300000000f00b011d02850004c0a8002cff0006000c32303231") == 0);
}

void test_encode_gtpv1_failure_report_req(void)
{
	gtpv1_failure_report_req_t encode = {0};
	fill_gtpv1_failure_report_req(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_failure_report_req(&encode, buf) == 26);
	CU_ASSERT(encode_gtpv1_failure_report_req(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_failure_report_req(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_failure_report_req(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 26, 64, 64, "30220012372f00000272021300000000f0ff0006000c32303231") == 0);
}

void test_encode_gtpv1_failure_report_rsp(void)
{
	gtpv1_failure_report_rsp_t encode = {0};
	fill_gtpv1_failure_report_rsp(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_failure_report_rsp(&encode, buf) == 21);
	CU_ASSERT(encode_gtpv1_failure_report_rsp(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_failure_report_rsp(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_failure_report_rsp(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 21, 64, 64, "3023000d372f000001800b01ff0006000c32303231") == 0);
}

void test_encode_gtpv1_note_ms_gprs_present_req(void)
{
	gtpv1_note_ms_gprs_present_req_t encode = {0};
	fill_gtpv1_note_ms_gprs_present_req(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_note_ms_gprs_present_req(&encode, buf) == 33);
	CU_ASSERT(encode_gtpv1_note_ms_gprs_present_req(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_note_ms_gprs_present_req(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_note_ms_gprs_present_req(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 33, 64, 64, "30240019372f00000272021300000000f0850004c0a8002cff0006000c32303231") == 0);
}

void test_encode_gtpv1_note_ms_gprs_present_rsp(void)
{
	gtpv1_note_ms_gprs_present_rsp_t encode = {0};
	fill_gtpv1_note_ms_gprs_present_rsp(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_note_ms_gprs_present_rsp(&encode, buf) == 19);
	CU_ASSERT(encode_gtpv1_note_ms_gprs_present_rsp(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_note_ms_gprs_present_rsp(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_note_ms_gprs_present_rsp(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 19, 64, 64, "3025000b372f00000180ff0006000c32303231") == 0);
}

void test_encode_gtpv1_identification_req(void)
{
	gtpv1_identification_req_t encode = {0};
	fill_gtpv1_identification_req(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_identification_req(&encode, buf) == 44);
	CU_ASSERT(encode_gtpv1_identification_req(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_identification_req(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_identification_req(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 44, 64, 64, "30300024372f00000304f48700141405000000010c000001850004c0a8002ca3000103ff0006000c32303231") == 0);
}

void test_encode_gtpv1_identification_rsp(void)
{
	gtpv1_identification_rsp_t encode = {0};
	fill_gtpv1_identification_rsp(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_identification_rsp(&encode, buf) == 114);
	CU_ASSERT(encode_gtpv1_identification_rsp(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_identification_rsp(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_identification_rsp(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 114, 128, 128, "3031006a372f000001800272021300000000f0093131313131313131313131313131313100000002000000000000000288003431313131313131313131313131313131013131313131313131313131313131313131313131313131313131313131313131310131d900040000000fde00010a") == 0);
}

void test_encode_gtpv1_sgsn_ctxt_req(void)
{
	gtpv1_sgsn_ctxt_req_t encode = {0};
	fill_gtpv1_sgsn_ctxt_req(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_sgsn_context_req(&encode, buf) == 89);
	CU_ASSERT(encode_gtpv1_sgsn_context_req(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_sgsn_context_req(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_sgsn_context_req(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 89, 128, 128, "30320051372f00000272021300000000f00304f487001414040000000105000000010c0000010d011100fffeee850004c0a8002c8500102001db80333344445555666677778888930002313197000102ff0006000c32303231") == 0);
}

void test_encode_gtpv1_sgsn_ctxt_rsp(void)
{
	gtpv1_sgsn_ctxt_rsp_t encode = {0};
	fill_gtpv1_sgsn_ctxt_rsp(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_sgsn_context_rsp(&encode, buf) == 418);
	CU_ASSERT(encode_gtpv1_sgsn_context_rsp(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_sgsn_context_rsp(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_sgsn_context_rsp(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 418, 512, 512, "3033019a372f000001800272021300000000f01100fffeee16010001000200010002170218121901041a00019600010181002f7949000000000000000131313131313131313131313131313131000000020000000000000002011904000000000000820074650115021231042a037bea11067ade11160b21162c21221715021231042a037bea11067ade11160b21162c21221715021231042a037bea11067ade11160b21162c21221700010002ffff372f00003730000000f12104152c8a9704152c8a8d04152c8a970d6e65787470686f6e65732e636f0a37850004c0a8002c9100009c002220372f000081f12104152c8a9704152c8a8d0d6e65787470686f6e65732e636f0105bd00020001bd00020001be000567736c6162c000020145c1000125c70008d6ab55b5b6bb5213c8001000000008000000100000002000000040c90009010000000100000001cc00020101cd000101d500020101d700060167736c6162d900040000000fda0001078500102001db803333444455556666777788888500102001db80333344445555666677778888de00010aff0006000c32303231") == 0);
}

void test_encode_gtpv1_sgsn_context_ack(void)
{
	gtpv1_sgsn_context_ack_t encode = {0};
	fill_gtpv1_sgsn_context_ack(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_sgsn_context_ack(&encode, buf) == 48);
	CU_ASSERT(encode_gtpv1_sgsn_context_ack(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_sgsn_context_ack(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_sgsn_context_ack(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 48, 64, 64, "30340028372f00000180120500fffeee850004c0a8002c9300023131db0008036d6d6503616161ff0006000c32303231") == 0);
}

void test_encode_gtpv1_forward_relocation_req(void)
{
	gtpv1_forward_relocation_req_t encode = {0};
	fill_gtpv1_forward_relocation_req(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_forward_relocation_req(&encode, buf) == 501);
	CU_ASSERT(encode_gtpv1_forward_relocation_req(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_forward_relocation_req(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_forward_relocation_req(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 501, 512, 512, "303501ed372f00000272021300000000f01100fffeee15071901041a000181002f7949000000000000000131313131313131313131313131313131000000020000000000000002011904000000000000820074650115021231042a037bea11067ade11160b21162c21221715021231042a037bea11067ade11160b21162c21221715021231042a037bea11067ade11160b21162c21221700010002ffff372f00003730000000f12104152c8a9704152c8a8d04152c8a970d6e65787470686f6e65732e636f0a37850004c0a8002c8a000a04f487000202000200009100009c002220372f000081f12104152c8a9704152c8a8d0d6e65787470686f6e65732e636f0105a4000304f487ae001104f48700141400010004f4870014140001b0000102b6000107bd00020003bd00020002be000567736c6162c000020145c1000100c5000101c70005d6ab55b5b6c8001000000008000000100000002000000040c90009010000000100000001cc00020101cd000101cf002203395fbf1551219929ac7356449d6cebf9f66f33d2b5bbfb2bb00702020605010103d0000100d200053233343536d300020002d400090004f4870200030014d500020101d900040000000fda0001078500102001db803333444455556666777788888500102001db80333344445555666677778888ff0006000c32303231") == 0);
}

void test_encode_gtpv1_forward_relocation_rsp(void)
{
	gtpv1_forward_relocation_rsp_t encode = {0};
	fill_gtpv1_forward_relocation_rsp(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_forward_relocation_rsp(&encode, buf) == 114);
	CU_ASSERT(encode_gtpv1_forward_relocation_rsp(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_forward_relocation_rsp(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_forward_relocation_rsp(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 114, 128, 128, "3036006a372f0000018011000000ab120500fffeee1507850004c0a8002c850004c0a8002c8c00090200fffeeed48141179200150200fffeee2001db803333444455556666777788859300023131b0000102b3000403010003d300020002db0008036d6d6503616161ff0006000c32303231") == 0);
}

void test_encode_gtpv1_forward_relocation_complete(void)
{
	gtpv1_forward_relocation_complete_t encode = {0};
	fill_gtpv1_forward_relocation_complete(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_forward_relocation_complete(&encode, buf) == 17);
	CU_ASSERT(encode_gtpv1_forward_relocation_complete(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_forward_relocation_complete(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_forward_relocation_complete(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 17, 64, 64, "30370009372f0000ff0006000c32303231") == 0);
}

void test_encode_gtpv1_relocation_cancel_req(void)
{
	gtpv1_relocation_cancel_req_t encode = {0};
	fill_gtpv1_relocation_cancel_req(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_relocation_cancel_req(&encode, buf) == 46);
	CU_ASSERT(encode_gtpv1_relocation_cancel_req(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_relocation_cancel_req(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_relocation_cancel_req(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 46, 64, 64, "30380026372f00000272021300000000f09a00081111111122222211c1000100d300020002ff0006000c32303231") == 0);
}

void test_encode_gtpv1_relocation_cancel_rsp(void)
{
	gtpv1_relocation_cancel_rsp_t encode = {0};
	fill_gtpv1_relocation_cancel_rsp(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_relocation_cancel_rsp(&encode, buf) == 19);
	CU_ASSERT(encode_gtpv1_relocation_cancel_rsp(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_relocation_cancel_rsp(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_relocation_cancel_rsp(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 19, 64, 64, "3039000b372f00000180ff0006000c32303231") == 0);
}

void test_encode_gtpv1_forward_relocation_complete_ack(void)
{
	gtpv1_forward_relocation_complete_ack_t encode = {0};
	fill_gtpv1_forward_relocation_complete_ack(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_forward_relocation_complete_ack(&encode, buf) == 19);
	CU_ASSERT(encode_gtpv1_forward_relocation_complete_ack(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_forward_relocation_complete_ack(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_forward_relocation_complete_ack(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 19, 64, 64, "303b000b372f00000180ff0006000c32303231") == 0);
}

void test_encode_gtpv1_forward_srns_context_ack(void)
{
	gtpv1_forward_srns_context_ack_t encode = {0};
	fill_gtpv1_forward_srns_context_ack(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_forward_srns_context_ack(&encode, buf) == 19);
	CU_ASSERT(encode_gtpv1_forward_srns_context_ack(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_forward_srns_context_ack(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_forward_srns_context_ack(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 19, 64, 64, "303c000b372f00000180ff0006000c32303231") == 0);
}

void test_encode_gtpv1_forward_srns_ctxt(void)
{
	gtpv1_forward_srns_ctxt_t encode = {0};
	fill_gtpv1_forward_srns_ctxt(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_forward_srns_ctxt(&encode, buf) == 44);
	CU_ASSERT(encode_gtpv1_forward_srns_ctxt(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_forward_srns_ctxt(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_forward_srns_ctxt(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 44, 64, 64, "303a0024372f000016010001000200010002a100023131af0009010001000200010002ff0006000c32303231") == 0);
}

void test_encode_gtpv1_ran_info_relay(void)
{
	gtpv1_ran_info_relay_t encode = {0};
	fill_gtpv1_ran_info_relay(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_ran_info_relay(&encode, buf) == 31);
	CU_ASSERT(encode_gtpv1_ran_info_relay(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_ran_info_relay(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_ran_info_relay(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 31, 64, 64, "30460017372f000090000231319e00023131b2000102ff0006000c32303231") == 0);
}

void test_encode_gtpv1_mbms_notification_req(void)
{
	gtpv1_mbms_notification_req_t encode = {0};
	fill_gtpv1_mbms_notification_req(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_mbms_notification_req(&encode, buf) == 65);
	CU_ASSERT(encode_gtpv1_mbms_notification_req(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_mbms_notification_req(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_mbms_notification_req(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 65, 128, 128, "30600039372f00000272021300000000f011000000ab1405800006f121152c8a9783000d6e65787470686f6e65732e636f850004c0a8002cff0006000c32303231") == 0);
}

void test_encode_gtpv1_mbms_notification_rsp(void)
{
	gtpv1_mbms_notification_rsp_t encode = {0};
	fill_gtpv1_mbms_notification_rsp(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_mbms_notification_rsp(&encode, buf) == 19);
	CU_ASSERT(encode_gtpv1_mbms_notification_rsp(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_mbms_notification_rsp(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_mbms_notification_rsp(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 19, 64, 64, "3061000b372f00000180ff0006000c32303231") == 0);
}

void test_encode_gtpv1_ms_info_change_notification_req(void)
{
	gtpv1_ms_info_change_notification_req_t encode = {0};
	fill_gtpv1_ms_info_change_notification_req(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_ms_info_change_notification_req(&encode, buf) == 69);
	CU_ASSERT(encode_gtpv1_ms_info_change_notification_req(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_ms_info_change_notification_req(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_ms_info_change_notification_req(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 69, 128, 128, "3080003d372f00000272021300000000f01409970001029800080104f487000100019a00081111111122222211c1000100c2000804f4870100000141ff0006000c32303231") == 0);
}

void test_encode_gtpv1_ms_info_change_notification_rsp(void)
{
	gtpv1_ms_info_change_notification_rsp_t encode = {0};
	fill_gtpv1_ms_info_change_notification_rsp(&encode);
	uint8_t buf[SIZE] = {0};

	CU_ASSERT(encode_gtpv1_ms_info_change_notification_rsp(&encode, buf) == 49);
	CU_ASSERT(encode_gtpv1_ms_info_change_notification_rsp(NULL, buf) == -1);
	CU_ASSERT(encode_gtpv1_ms_info_change_notification_rsp(NULL, NULL) == -1);
	CU_ASSERT(encode_gtpv1_ms_info_change_notification_rsp(&encode, NULL) == -1);
	CU_ASSERT(hexdump(buf, 49, 64, 64, "30810029372f000001800272021300000000f014099a00081111111122222211b5000104c3000107ff0006000c32303231") == 0);
}
