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

#ifndef __GTPV1_MESSAGES_ENCODER_H__
#define __GTPV1_MESSAGES_ENCODER_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "enc_dec_bits.h"
#include "gtpv1_ies_encoder.h"
#include "gtpv1_messages.h"

/*
 * @brief  : encode gtpv1 Echo request to buffer.
 * @param  : value, gtpv1_echo_req_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_echo_req(gtpv1_echo_req_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 Echo response to buffer.
 * @param  : value, gtpv1_echo_rsp_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_echo_rsp(gtpv1_echo_rsp_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 version not support to buffer.
 * @param  : value, gtpv1_version_not_supported_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_version_not_supported(gtpv1_version_not_supported_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 create PDP context request to buffer.
 * @param  : value, gtpv1_create_pdp_ctxt_req_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_create_pdp_ctxt_req(gtpv1_create_pdp_ctxt_req_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 create PDP context response to buffer.
 * @param  : value, gtpv1_create_pdp_ctxt_rsp_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_create_pdp_ctxt_rsp(gtpv1_create_pdp_ctxt_rsp_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 SGSN initiated update PDP context Request to buffer.
 * @param  : value, gtpv1_update_pdp_ctxt_req_sgsn_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_update_pdp_ctxt_req_sgsn(gtpv1_update_pdp_ctxt_req_sgsn_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 GGSN initiated update PDP context Request to buffer.
 * @param  : value, gtpv1_update_pdp_ctxt_req_ggsn_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_update_pdp_ctxt_req_ggsn(gtpv1_update_pdp_ctxt_req_ggsn_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 update PDP context Reponse Message sent by a GGSN to buffer.
 * @param  : value, gtpv1_update_pdp_ctxt_rsp_ggsn_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_update_pdp_ctxt_rsp_ggsn(gtpv1_update_pdp_ctxt_rsp_ggsn_t *value, uint8_t *buf);
/*
 * @brief  : encode gtpv1 update PDP context Reponse Message sent by a SGSN to buffer.
 * @param  : value, gtpv1_update_pdp_ctxt_rsp_sgsn_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_update_pdp_ctxt_rsp_sgsn(gtpv1_update_pdp_ctxt_rsp_sgsn_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 delete PDP context request to buffer.
 * @param  : value, gtpv1_delete_pdp_ctxt_req_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_delete_pdp_ctxt_req(gtpv1_delete_pdp_ctxt_req_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 delete PDP context response to buffer.
 * @param  : value, gtpv1_delete_pdp_ctxt_rsp_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_delete_pdp_ctxt_rsp(gtpv1_delete_pdp_ctxt_rsp_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 initiate PDP context active request to buffer.
 * @param  : value, gtpv1_initiate_pdp_ctxt_active_req_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_initiate_pdp_ctxt_active_req(gtpv1_initiate_pdp_ctxt_active_req_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 initiate PDP context active response to buffer.
 * @param  : value, gtpv1_initiate_pdp_ctxt_active_rsp_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_initiate_pdp_ctxt_active_rsp(gtpv1_initiate_pdp_ctxt_active_rsp_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 PDU notification request to buffer.
 * @param  : value, gtpv1_pdu_notification_req_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_pdu_notification_req(gtpv1_pdu_notification_req_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 PDU notification response to buffer.
 * @param  : value, gtpv1_pdu_notification_rsp_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_pdu_notification_rsp(gtpv1_pdu_notification_rsp_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 PDU notification reject request to buffer.
 * @param  : value, gtpv1_pdu_notification_reject_req_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_pdu_notification_reject_req(gtpv1_pdu_notification_reject_req_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 PDU notification reject response to buffer.
 * @param  : value, gtpv1_pdu_notification_reject_rsp_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_pdu_notification_reject_rsp(gtpv1_pdu_notification_reject_rsp_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 send routeing information for GPRS request to buffer.
 * @param  : value, gtpv1_send_routeing_info_for_gprs_req_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_send_routeing_info_for_gprs_req(gtpv1_send_routeing_info_for_gprs_req_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 send routeing information for GPRS response to buffer.
 * @param  : value, gtpv1_send_routeing_info_for_gprs_rsp_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_send_routeing_info_for_gprs_rsp(gtpv1_send_routeing_info_for_gprs_rsp_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 failure report request to buffer.
 * @param  : value, gtpv1_failure_report_req_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_failure_report_req(gtpv1_failure_report_req_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 failure report response to buffer.
 * @param  : value, gtpv1_failure_report_rsp_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_failure_report_rsp(gtpv1_failure_report_rsp_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 note ms gprs present request to buffer.
 * @param  : value, gtpv1_note_ms_gprs_present_req_t which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_note_ms_gprs_present_req(gtpv1_note_ms_gprs_present_req_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 note ms gprs present response to buffer.
 * @param  : value, gtpv1_note_ms_gprs_present_rsp_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_note_ms_gprs_present_rsp(gtpv1_note_ms_gprs_present_rsp_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 sgsn context request to buffer.
 * @param  : value, gtpv1_sgsn_ctxt_req_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_sgsn_context_req(gtpv1_sgsn_ctxt_req_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 sgsn context response to buffer.
 * @param  : value, gtpv1_sgsn_ctxt_rsp_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_sgsn_context_rsp(gtpv1_sgsn_ctxt_rsp_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 UE registration query request to buffer.
 * @param  : value, gtpv1_ue_registration_query_req_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_ue_registration_query_req(gtpv1_ue_registration_query_req_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 UE registration query response to buffer.
 * @param  : value, gtpv1_ue_registration_query_rsp_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_ue_registration_query_rsp(gtpv1_ue_registration_query_rsp_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 ran information relay to buffer.
 * @param  : value, gtpv1_ran_info_relay_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_ran_info_relay(gtpv1_ran_info_relay_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 MBMS notification request to buffer.
 * @param  : value, gtpv1_mbms_notification_req_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_mbms_notification_req(gtpv1_mbms_notification_req_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 MBMS notification response to buffer.
 * @param  : value, gtpv1_mbms_notification_rsp_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_mbms_notification_rsp(gtpv1_mbms_notification_rsp_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 forward relocation request to buffer.
 * @param  : value, gtpv1_forward_relocation_req_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_forward_relocation_req(gtpv1_forward_relocation_req_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 forward relocation response to buffer.
 * @param  : value, gtpv1_forward_relocation_rsp_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_forward_relocation_rsp(gtpv1_forward_relocation_rsp_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 ms information change notification request to buffer.
 * @param  : value, gtpv1_ms_info_change_notification_req_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_ms_info_change_notification_req(gtpv1_ms_info_change_notification_req_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 ms information change notification response to buffer.
 * @param  : value, gtpv1_ms_info_change_notification_rsp_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_ms_info_change_notification_rsp(gtpv1_ms_info_change_notification_rsp_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 identification request to buffer.
 * @param  : value, gtpv1_identification_req_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_identification_req(gtpv1_identification_req_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 identification response to buffer.
 * @param  : value, gtpv1_identification_rsp_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_identification_rsp(gtpv1_identification_rsp_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 relocation cancel request to buffer.
 * @param  : value, gtpv1_relocation_cancel_req_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_relocation_cancel_req(gtpv1_relocation_cancel_req_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 relocation cancel response to buffer.
 * @param  : value, gtpv1_relocation_cancel_rsp_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_relocation_cancel_rsp(gtpv1_relocation_cancel_rsp_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 forward relocation complete acknowledgement to buffer.
 * @param  : value, gtpv1_forward_relocation_complete_ack_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_forward_relocation_complete_ack(gtpv1_forward_relocation_complete_ack_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 forward relocation complete to buffer.
 * @param  : value, gtpv1_forward_relocation_complete_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_forward_relocation_complete(gtpv1_forward_relocation_complete_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 forward srns context acknowledgement to buffer.
 * @param  : value, gtpv1_forward_srns_context_ack_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_forward_srns_context_ack(gtpv1_forward_srns_context_ack_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 forward srns context to buffer.
 * @param  : value, gtpv1_forward_srns_ctxt_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_forward_srns_ctxt(gtpv1_forward_srns_ctxt_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 sgsn context acknowledgement to buffer.
 * @param  : value, gtpv1_sgsn_context_ack_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_sgsn_context_ack(gtpv1_sgsn_context_ack_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 supported extension headers notification to buffer.
 * @param  : value, gtpv1_supported_extension_headers_notification_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'
 */
int encode_gtpv1_supported_extension_headers_notification(gtpv1_supported_extension_headers_notification_t *value, uint8_t *buf);

#ifdef __cplusplus
}
#endif

#endif /*__GTPV1_MESSAGES_ENCODER_H__*/
