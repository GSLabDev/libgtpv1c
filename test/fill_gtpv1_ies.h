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

#ifndef __FILL_GTPV1_IES_H__
#define __FILL_GTPV1_IES_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <arpa/inet.h>
#include <stdio.h>
#include "../include/gtpv1_ies.h"
#include "../include/gtpv1_messages.h"
#include "../include/gtpv1_ies_encoder.h"
#include "../include/gtpv1_ies_decoder.h"
#include "../include/gtpv1_messages_encoder.h"
#include "../include/gtpv1_messages_decoder.h"

/*
 * @brief  : fill values to the gtpv1_echo_req_t structure
 * @param  : gtpv1_echo_req_t structure to fill
 * @return : null
 */
void fill_gtpv1_echo_req(gtpv1_echo_req_t *echo_request);

/*
 * @brief  : fill values to the gtpv1_echo_rsp_t structure
 * @param  : gtpv1_echo_rsp_t structure to fill
 * @return : null
 */
void fill_gtpv1_echo_rsp(gtpv1_echo_rsp_t *echo_rsp);

/*
 * @brief  : fill values to the gtpv1_version_not_supported_t structure
 * @param  : gtpv1_version_not_supported_t structure to fill
 * @return : null
 */
void fill_gtpv1_version_not_supported(gtpv1_version_not_supported_t *version_not_supported);

/*
 * @brief  : fill values to the gtpv1_supported_extension_headers_notification_t structure
 * @param  : gtpv1_supported_extension_headers_notification_t structure to fill
 * @return : null
 */
void fill_gtpv1_supported_extension_headers_notification(gtpv1_supported_extension_headers_notification_t *supported_extension_headers_notification);

/*
 * @brief  : fill values to the gtpv1_create_pdp_ctxt_req_t structure
 * @param  : gtpv1_create_pdp_ctxt_req_t structure to fill
 * @return : null
 */
void fill_gtpv1_create_pdp_ctxt_req(gtpv1_create_pdp_ctxt_req_t *create_pdp_ctxt_req);

/*
 * @brief  : fill values to the gtpv1_create_pdp_ctxt_rsp_t structure
 * @param  : gtpv1_create_pdp_ctxt_rsp_t structure to fill
 * @return : null
 */
void fill_gtpv1_create_pdp_ctxt_rsp(gtpv1_create_pdp_ctxt_rsp_t *create_pdp_ctxt_rsp);

/*
 * @brief  : fill values to the gtpv1_update_pdp_ctxt_req_sgsn_t structure
 * @param  : gtpv1_update_pdp_ctxt_req_sgsn_t structure to fill
 * @return : null
 */
void fill_gtpv1_update_pdp_ctxt_req_sgsn(gtpv1_update_pdp_ctxt_req_sgsn_t *update_pdp_ctxt_req_sgsn);

/*
 * @brief  : fill values to the gtpv1_update_pdp_ctxt_req_ggsn_t structure
 * @param  : gtpv1_update_pdp_ctxt_req_ggsn_t structure to fill
 * @return : null
 */
void fill_gtpv1_update_pdp_ctxt_req_ggsn(gtpv1_update_pdp_ctxt_req_ggsn_t *update_pdp_ctxt_req_ggsn);

/*
 * @brief  : fill values to the gtpv1_update_pdp_ctxt_rsp_ggsn_t structure
 * @param  : gtpv1_update_pdp_ctxt_rsp_ggsn_t structure to fill
 * @return : null
 */
void fill_gtpv1_update_pdp_ctxt_rsp_ggsn(gtpv1_update_pdp_ctxt_rsp_ggsn_t *update_pdp_ctxt_rsp_ggsn);

/*
 * @brief  : fill values to the gtpv1_update_pdp_ctxt_rsp_sgsn_t structure
 * @param  : gtpv1_update_pdp_ctxt_rsp_sgsn_t structure to fill
 * @return : null
 */
void fill_gtpv1_update_pdp_ctxt_rsp_sgsn(gtpv1_update_pdp_ctxt_rsp_sgsn_t *update_pdp_ctxt_rsp_sgsn);

/*
 * @brief  : fill values to the gtpv1_delete_pdp_ctxt_req_t structure
 * @param  : gtpv1_delete_pdp_ctxt_req_t structure to fill
 * @return : null
 */
void fill_gtpv1_delete_pdp_ctxt_req(gtpv1_delete_pdp_ctxt_req_t *delete_pdp_ctxt_req);

/*
 * @brief  : fill values to the gtpv1_delete_pdp_ctxt_rsp_t structure
 * @param  : gtpv1_delete_pdp_ctxt_rsp_t structure to fill
 * @return : null
 */
void fill_gtpv1_delete_pdp_ctxt_rsp(gtpv1_delete_pdp_ctxt_rsp_t *delete_pdp_ctxt_rsp);

/*
 * @brief  : fill values to the gtpv1_pdu_notification_req_t structure
 * @param  : gtpv1_pdu_notification_req_t structure to fill
 * @return : null
 */
void fill_gtpv1_pdu_notification_req(gtpv1_pdu_notification_req_t *pdu_notification_req);

/*
 * @brief  : fill values to the gtpv1_pdu_notification_rsp_t structure
 * @param  : gtpv1_pdu_notification_rsp_t structure to fill
 * @return : null
 */
void fill_gtpv1_pdu_notification_rsp(gtpv1_pdu_notification_rsp_t *pdu_notification_rsp);

/*
 * @brief  : fill values to the gtpv1_pdu_notification_reject_req_t structure
 * @param  : gtpv1_pdu_notification_reject_req_t structure to fill
 * @return : null
 */
void fill_gtpv1_pdu_notification_reject_req(gtpv1_pdu_notification_reject_req_t *pdu_notification_reject_req);

/*
 * @brief  : fill values to the gtpv1_pdu_notification_reject_rsp_t structure
 * @param  : gtpv1_pdu_notification_reject_rsp_t structure to fill
 * @return : null
 */
void fill_gtpv1_pdu_notification_reject_rsp(gtpv1_pdu_notification_reject_rsp_t *pdu_notification_reject_rsp);

/*
 * @brief  : fill values to the gtpv1_initiate_pdp_ctxt_active_req_t structure
 * @param  : gtpv1_initiate_pdp_ctxt_active_req_t structure to fill
 * @return : null
 */
void fill_gtpv1_initiate_pdp_ctxt_active_req(gtpv1_initiate_pdp_ctxt_active_req_t *initiate_pdp_ctxt_active_req);

/*
 * @brief  : fill values to the gtpv1_initiate_pdp_ctxt_active_rsp_t structure
 * @param  : gtpv1_initiate_pdp_ctxt_active_rsp_t structure to fill
 * @return : null
 */
void fill_gtpv1_initiate_pdp_ctxt_active_rsp(gtpv1_initiate_pdp_ctxt_active_rsp_t *initiate_pdp_ctxt_active_rsp);

/*
 * @brief  : fill values to the gtpv1_send_routeing_info_for_gprs_req_t structure
 * @param  : gtpv1_send_routeing_info_for_gprs_req_t structure to fill
 * @return : null
 */
void fill_gtpv1_send_routeing_info_for_gprs_req(gtpv1_send_routeing_info_for_gprs_req_t *send_routeing_info_for_gprs_req);

/*
 * @brief  : fill values to the gtpv1_send_routeing_info_for_gprs_rsp_t structure
 * @param  : gtpv1_send_routeing_info_for_gprs_rsp_t structure to fill
 * @return : null
 */
void fill_gtpv1_send_routeing_info_for_gprs_rsp(gtpv1_send_routeing_info_for_gprs_rsp_t *send_routeing_info_for_gprs_rsp);

/*
 * @brief  : fill values to the gtpv1_failure_report_req_t structure
 * @param  : gtpv1_failure_report_req_t structure to fill
 * @return : null
 */
void fill_gtpv1_failure_report_req(gtpv1_failure_report_req_t *failure_report_req);

/*
 * @brief  : fill values to the gtpv1_failure_report_rsp_t structure
 * @param  : gtpv1_failure_report_rsp_t structure to fill
 * @return : null
 */
void fill_gtpv1_failure_report_rsp(gtpv1_failure_report_rsp_t *failure_report_rsp);
/*
 * @brief  : fill values to the gtpv1_note_ms_gprs_present_req_t structure
 * @param  : gtpv1_note_ms_gprs_present_req_t, structure to fill
 * @return : null
 */
void fill_gtpv1_note_ms_gprs_present_req(gtpv1_note_ms_gprs_present_req_t *note_ms_gprs_present_req);

/*
 * @brief  : fill values to the gtpv1_note_ms_gprs_present_rsp_t structure
 * @param  : gtpv1_note_ms_gprs_present_rsp_t, structure to fill
 * @return : null
 */
void fill_gtpv1_note_ms_gprs_present_rsp(gtpv1_note_ms_gprs_present_rsp_t *note_ms_gprs_present_rsp);

/*
 * @brief  : fill values to the gtpv1_identification_req_t structure
 * @param  : gtpv1_identification_req_t, structure to fill
 * @return : null
 */
void fill_gtpv1_identification_req(gtpv1_identification_req_t *identification_req);

/*
 * @brief  : fill values to the gtpv1_identification_rsp_t structure
 * @param  : gtpv1_identification_rsp_t, structure to fill
 * @return : null
 */
void fill_gtpv1_identification_rsp(gtpv1_identification_rsp_t *identification_rsp);

/*
 * @brief  : fill values to the gtpv1_sgsn_ctxt_req_t structure
 * @param  : gtpv1_sgsn_ctxt_req_t, structure to fill
 * @return : null
 */
void fill_gtpv1_sgsn_ctxt_req(gtpv1_sgsn_ctxt_req_t *sgsn_ctxt_res);

/*
 * @brief  : fill values to the gtpv1_sgsn_ctxt_rsp_t structure
 * @param  : gtpv1_sgsn_ctxt_rsp_t, structure to fill
 * @return : null
 */
void fill_gtpv1_sgsn_ctxt_rsp(gtpv1_sgsn_ctxt_rsp_t *sgsn_ctxt_rsp);

/*
 * @brief  : fill values to the gtpv1_sgsn_context_ack_t structure
 * @param  : gtpv1_sgsn_context_ack_t, structure to fill
 * @return : null
 */
void fill_gtpv1_sgsn_context_ack(gtpv1_sgsn_context_ack_t *sgsn_context_ack);

/*
 * @brief  : fill values to the gtpv1_forward_relocation_req_t structure
 * @param  : gtpv1_forward_relocation_req_t, structure to fill
 * @return : null
 */
void fill_gtpv1_forward_relocation_req(gtpv1_forward_relocation_req_t *forward_relocation_req);

/*
 * @brief  : fill values to the gtpv1_forward_relocation_rsp_t structure
 * @param  : gtpv1_forward_relocation_rsp_t, structure to fill
 * @return : null
 */
void fill_gtpv1_forward_relocation_rsp(gtpv1_forward_relocation_rsp_t *forward_relocation_rsp);

/*
 * @brief  : fill values to the gtpv1_forward_relocation_complete_t structure
 * @param  : gtpv1_forward_relocation_complete_t, structure to fill
 * @return : null
 */
void fill_gtpv1_forward_relocation_complete(gtpv1_forward_relocation_complete_t *forward_relocation_complete);

/*
 * @brief  : fill values to the gtpv1_relocation_cancel_req_t structure
 * @param  : gtpv1_relocation_cancel_req_t, structure to fill
 * @return : null
 */
void fill_gtpv1_relocation_cancel_req(gtpv1_relocation_cancel_req_t *relocation_cancel_req);

/*
 * @brief  : fill values to the gtpv1_relocation_cancel_rsp_t structure
 * @param  : gtpv1_relocation_cancel_rsp_t, structure to fill
 * @return : null
 */
void fill_gtpv1_relocation_cancel_rsp(gtpv1_relocation_cancel_rsp_t *relocation_cancel_rsp);

/*
 * @brief  : fill values to the gtpv1_forward_relocation_complete_ack_t structure
 * @param  : gtpv1_forward_relocation_complete_ack_t, structure to fill
 * @return : null
 */
void fill_gtpv1_forward_relocation_complete_ack(gtpv1_forward_relocation_complete_ack_t *forward_relocation_complete_ack);

/*
 * @brief  : fill values to the gtpv1_forward_srns_context_ack_t structure
 * @param  : gtpv1_forward_srns_context_ack_t, structure to fill
 * @return : null
 */
void fill_gtpv1_forward_srns_context_ack(gtpv1_forward_srns_context_ack_t *forward_srns_context_ack);

/*
 * @brief  : fill values to the gtpv1_forward_srns_ctxt_t structure
 * @param  : gtpv1_forward_srns_ctxt_t, structure to fill
 * @return : null
 */
void fill_gtpv1_forward_srns_ctxt(gtpv1_forward_srns_ctxt_t *forward_srns_ctxt);

/*
 * @brief  : fill values to the gtpv1_ran_info_relay_t structure
 * @param  : gtpv1_ran_info_relay_t, structure to fill
 * @return : null
 */
void fill_gtpv1_ran_info_relay(gtpv1_ran_info_relay_t *ran_info_relay);

/*
 * @brief  : fill values to the gtpv1_mbms_notification_req_t structure
 * @param  : gtpv1_mbms_notification_req_t, structure to fill
 * @return : null
 */
void fill_gtpv1_mbms_notification_req(gtpv1_mbms_notification_req_t *mbms_notification_req);

/*
 * @brief  : fill values to the gtpv1_mbms_notification_rsp_t structure
 * @param  : gtpv1_mbms_notification_rsp_t, structure to fill
 * @return : null
 */
void fill_gtpv1_mbms_notification_rsp(gtpv1_mbms_notification_rsp_t *mbms_notification_rsp);

/*
 * @brief  : fill values to the gtpv1_ms_info_change_notification_req_t structure
 * @param  : gtpv1_ms_info_change_notification_req_t, structure to fill
 * @return : null
 */
void fill_gtpv1_ms_info_change_notification_req(gtpv1_ms_info_change_notification_req_t *ms_info_change_notification_req);

/*
 * @brief  : fill values to the gtpv1_ms_info_change_notification_rsp_t structure
 * @param  : gtpv1_ms_info_change_notification_rsp_t, structure to fill
 * @return : null
 */
void fill_gtpv1_ms_info_change_notification_rsp(gtpv1_ms_info_change_notification_rsp_t *ms_info_change_notification_rsp);

#ifdef __cplusplus
}
#endif

#endif /* __FILL_GTPV1_IES_H__ */
