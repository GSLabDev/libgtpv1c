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

#ifndef __TEST_ENCODER_GTPV1_MESSAGES_H__
#define __TEST_ENCODER_GTPV1_MESSAGES_H__

#ifdef __cplusplus
	extern "C" {
#endif

#include <assert.h>
#include "CUnit/Basic.h"
#include "fill_gtpv1_ies.h"
#include "test_encoder_gtpv1_ies.h"
#include "../include/gtpv1_ies.h"
#include "../include/gtpv1_messages.h"
#include "../include/gtpv1_ies_encoder.h"
#include "../include/gtpv1_messages_encoder.h"

/*
 * @brief  : unit test cases of encoding of gtpv1 echo_req message
 * @return : null
 */
void test_encode_gtpv1_echo_req(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 echo_rsp message
 * @return : null
 */
void test_encode_gtpv1_echo_rsp(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 version_not_supported message
 * @return : null
 */
void test_encode_gtpv1_version_not_supported(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 supported_extension_headers_notification message
 * @return : null
 */
void test_encode_gtpv1_supported_extension_headers_notification(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 create_pdp_ctxt_req message
 * @return : null
 */
void test_encode_gtpv1_create_pdp_ctxt_req(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 create_pdp_ctxt_rsp message
 * @return : null
 */
void test_encode_gtpv1_create_pdp_ctxt_rsp(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 update_pdp_ctxt_req_sgsn message
 * @return : null
 */
void test_encode_gtpv1_update_pdp_ctxt_req_sgsn(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 update_pdp_ctxt_req_ggsn message
 * @return : null
 */
void test_encode_gtpv1_update_pdp_ctxt_req_ggsn(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 update_pdp_ctxt_rsp_ggsn message
 * @return : null
 */
void test_encode_gtpv1_update_pdp_ctxt_rsp_ggsn(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 update_pdp_ctxt_rsp_sgsn message
 * @return : null
 */
void test_encode_gtpv1_update_pdp_ctxt_rsp_sgsn(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 delete_pdp_ctxt_req message
 * @return : null
 */
void test_encode_gtpv1_delete_pdp_ctxt_req(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 delete_pdp_ctxt_rsp message
 * @return : null
 */
void test_encode_gtpv1_delete_pdp_ctxt_rsp(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 pdu_notification_req message
 * @return : null
 */
void test_encode_gtpv1_pdu_notification_req(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 pdu_notification_rsp message
 * @return : null
 */
void test_encode_gtpv1_pdu_notification_rsp(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 pdu_notification_reject_req message
 * @return : null
 */
void test_encode_gtpv1_pdu_notification_reject_req(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 pdu_notification_reject_rsp message
 * @return : null
 */
void test_encode_gtpv1_pdu_notification_reject_rsp(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 initiate_pdp_ctxt_active_req message
 * @return : null
 */
void test_encode_gtpv1_initiate_pdp_ctxt_active_req(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 initiate_pdp_ctxt_active_rsp message
 * @return : null
 */
void test_encode_gtpv1_initiate_pdp_ctxt_active_rsp(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 send_routeing_info_for_gprs_req message
 * @return : null
 */
void test_encode_gtpv1_send_routeing_info_for_gprs_req(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 send_routeing_info_for_gprs_rsp message
 * @return : null
 */
void test_encode_gtpv1_send_routeing_info_for_gprs_rsp(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 failure_report_req message
 * @return : null
 */
void test_encode_gtpv1_failure_report_req(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 failure_report_rs message
 * @return : null
 */
void test_encode_gtpv1_failure_report_rsp(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 note_ms_gprs_present_req message
 * @return : null
 */
void test_encode_gtpv1_note_ms_gprs_present_req(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 note_ms_gprs_present_rsp message
 * @return : null
 */
void test_encode_gtpv1_note_ms_gprs_present_rsp(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 identification_req message
 * @return : null
 */
void test_encode_gtpv1_identification_req(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 identification_rsp message
 * @return : null
 */
void test_encode_gtpv1_identification_rsp(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 sgsn_ctxt_req message
 * @return : null
 */
void test_encode_gtpv1_sgsn_ctxt_req(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 sgsn_ctxt_rsp message
 * @return : null
 */
void test_encode_gtpv1_sgsn_ctxt_rsp(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 sgsn_context_ack message
 * @return : null
 */
void test_encode_gtpv1_sgsn_context_ack(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 forward_relocation_req message
 * @return : null
 */
void test_encode_gtpv1_forward_relocation_req(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 forward_relocation_rsp message
 * @return : null
 */
void test_encode_gtpv1_forward_relocation_rsp(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 forward_relocation_complete message
 * @return : null
 */
void test_encode_gtpv1_forward_relocation_complete(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 relocation_cancel_req message
 * @return : null
 */
void test_encode_gtpv1_relocation_cancel_req(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 relocation_cancel_rsp message
 * @return : null
 */
void test_encode_gtpv1_relocation_cancel_rsp(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 forward_relocation_complete_ack message
 * @return : null
 */
void test_encode_gtpv1_forward_relocation_complete_ack(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 forward_srns_context_ack message
 * @return : null
 */
void test_encode_gtpv1_forward_srns_context_ack(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 forward_srns_ctxt message
 * @return : null
 */
void test_encode_gtpv1_forward_srns_ctxt(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 ran_info_relay message
 * @return : null
 */
void test_encode_gtpv1_ran_info_relay(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 mbms_notification_req message
 * @return : null
 */
void test_encode_gtpv1_mbms_notification_req(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 mbms_notification_rsp message
 * @return : null
 */
void test_encode_gtpv1_mbms_notification_rsp(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 ms_info_change_notification_req message
 * @return : null
 */
void test_encode_gtpv1_ms_info_change_notification_req(void);

/*
 * @brief  : unit test cases of encoding of gtpv1 ms_info_change_notification_rsp message
 * @return : null
 */
void test_encode_gtpv1_ms_info_change_notification_rsp(void);

#ifdef __cplusplus
}
#endif

#endif /*__TEST_ENCODER_GTPV1_MESSAGES_H__*/
