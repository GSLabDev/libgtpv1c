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

#ifndef __GTPV1_MESSAGES_DECODER_H__
#define __GTPV1_MESSAGES_DECODER_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "enc_dec_bits.h"
#include "gtpv1_ies_decoder.h"
#include "gtpv1_messages.h"

/*
 * @brief  : decodes gtpv1 Echo Request message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_echo_req_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int decode_gtpv1_echo_req(uint8_t *buf, gtpv1_echo_req_t *value);

/*
 * @brief  : decodes gtpv1 Echo Response message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_echo_rsp_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_echo_rsp(uint8_t *buf, gtpv1_echo_rsp_t *value);

/*
 * @brief  : decodes gtpv1 version not supported message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_version_not_supported_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_version_not_supported(uint8_t *buf, gtpv1_version_not_supported_t *value);

/*
 * @brief  : decodes gtpv1 create PDP context Request message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_create_pdp_req_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_create_pdp_ctxt_req(uint8_t *buf, gtpv1_create_pdp_ctxt_req_t *value);

/*
 * @brief  : decodes gtpv1 create PDP context Response message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_create_pdp_ctxt_rsp_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_create_pdp_ctxt_rsp(uint8_t *buf, gtpv1_create_pdp_ctxt_rsp_t *value);

/*
 * @brief  : decodes gtpv1 SGSN initiated update PDP context Request message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_update_pdp_ctxt_req_sgsn_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_update_pdp_ctxt_req_sgsn(uint8_t *buf, gtpv1_update_pdp_ctxt_req_sgsn_t *value);

/*
 * @brief  : decodes gtpv1 GGSN initiated update PDP context Request message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_update_pdp_ctxt_req_ggsn_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_update_pdp_ctxt_req_ggsn(uint8_t *buf, gtpv1_update_pdp_ctxt_req_ggsn_t *value);

/*
 * @brief  : decodes gtpv1 update PDP context Reponse Message sent by GGSN from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_update_pdp_ctxt_rsp_ggsn_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_update_pdp_ctxt_rsp_ggsn(uint8_t *buf, gtpv1_update_pdp_ctxt_rsp_ggsn_t *value);

/*
 * @brief  : decodes gtpv1 update PDP context Reponse Message sent by SGSN from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_update_pdp_ctxt_rsp_sgsn_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_update_pdp_ctxt_rsp_sgsn(uint8_t *buf, gtpv1_update_pdp_ctxt_rsp_sgsn_t *value);

/*
 * @brief  : decodes gtpv1 delete PDP context Request message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_delete_pdp_ctxt_req_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_delete_pdp_ctxt_req(uint8_t *buf, gtpv1_delete_pdp_ctxt_req_t *value);

/*
 * @brief  : decodes gtpv1 delete PDP context Response message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_delete_pdp_ctxt_rsp_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_delete_pdp_ctxt_rsp(uint8_t *buf, gtpv1_delete_pdp_ctxt_rsp_t *value);

/*
 * @brief  : decodes gtpv1 initiate pdp context active Request message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_initiate_pdp_ctxt_active_req_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_initiate_pdp_ctxt_active_req(uint8_t *buf, gtpv1_initiate_pdp_ctxt_active_req_t *value);

/*
 * @brief  : decodes gtpv1 initiate pdp context active Response message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_initiate_pdp_ctxt_active_rsp_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_initiate_pdp_ctxt_active_rsp(uint8_t *buf, gtpv1_initiate_pdp_ctxt_active_rsp_t *value);

/*
 * @brief  : decodes gtpv1 PDU notification Request message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_pdu_notification_req_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_pdu_notification_req(uint8_t *buf, gtpv1_pdu_notification_req_t *value);

/*
 * @brief  : decodes gtpv1 PDU notification Response message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_pdu_notification_rsp_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_pdu_notification_rsp(uint8_t *buf, gtpv1_pdu_notification_rsp_t *value);

/*
 * @brief  : decodes gtpv1 PDU notofication reject Request message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_pdu_notification_reject_req_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_pdu_notification_reject_req(uint8_t *buf, gtpv1_pdu_notification_reject_req_t *value);

/*
 * @brief  : decodes gtpv1 PDU notification reject Response message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_pdu_notification_reject_rsp_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_pdu_notification_reject_rsp(uint8_t *buf, gtpv1_pdu_notification_reject_rsp_t *value);

/*
 * @brief  : decodes gtpv1 send routing information for gprs Request message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_send_routeing_info_for_gprs_req_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_send_routeing_info_for_gprs_req(uint8_t *buf, gtpv1_send_routeing_info_for_gprs_req_t *value);

/*
 * @brief  : decodes gtpv1 Send routing information for gprs Response message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_send_routeing_info_for_gprs_rsp_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_send_routeing_info_for_gprs_rsp(uint8_t *buf, gtpv1_send_routeing_info_for_gprs_rsp_t *value);

/*
 * @brief  : decodes gtpv1 Failure report Request message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_failure_report_req_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_failure_report_req(uint8_t *buf, gtpv1_failure_report_req_t *value);

/*
 * @brief  : decodes gtpv1 Failure report Response message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_failure_report_rsp_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_failure_report_rsp(uint8_t *buf, gtpv1_failure_report_rsp_t *value);

/*
 * @brief  : decodes gtpv1 note ms gprs present Request message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_note_ms_gprs_present_req_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_note_ms_gprs_present_req(uint8_t *buf, gtpv1_note_ms_gprs_present_req_t *value);

/*
 * @brief  : decodes gtpv1 note ms gprs present Response message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_note_ms_gprs_present_rsp_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_note_ms_gprs_present_rsp(uint8_t *buf, gtpv1_note_ms_gprs_present_rsp_t *value);

/*
 * @brief  : decodes gtpv1 sgsn context Request message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_sgsn_ctxt_req_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_sgsn_context_req(uint8_t *buf, gtpv1_sgsn_ctxt_req_t *value);

/*
 * @brief  : decodes gtpv1 sgsn context Response message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_sgsn_ctxt_rsp_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_sgsn_context_rsp(uint8_t *buf, gtpv1_sgsn_ctxt_rsp_t *value);

/*
 * @brief  : decodes gtpv1 UE registration query Request message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_ue_registration_query_req_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_ue_registration_query_req(uint8_t *buf, gtpv1_ue_registration_query_req_t *value);

/*
 * @brief  : decodes gtpv1 UE registration query Response message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_ue_registration_query_rsp_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_ue_registration_query_rsp(uint8_t *buf, gtpv1_ue_registration_query_rsp_t *value);

/*
 * @brief  : decodes gtpv1 ran info relay message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_ran_info_relay_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_ran_info_relay(uint8_t *buf, gtpv1_ran_info_relay_t *value);

/*
 * @brief  : decodes gtpv1 MBMS notification Request message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_mbms_notification_req_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_mbms_notification_req(uint8_t *buf, gtpv1_mbms_notification_req_t *value);

/*
 * @brief  : decodes gtpv1 MBMS notification Response message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_mbms_notification_rsp_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_mbms_notification_rsp(uint8_t *buf, gtpv1_mbms_notification_rsp_t *value);

/*
 * @brief  : decodes gtpv1 forward relocation Request message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_forward_relocation_req_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_forward_relocation_req(uint8_t *buf, gtpv1_forward_relocation_req_t *value);

/*
 * @brief  : decodes gtpv1 forward relocation Response message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_forward_relocation_rsp_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_forward_relocation_rsp(uint8_t *buf, gtpv1_forward_relocation_rsp_t *value);

/*
 * @brief  : decodes gtpv1 ms information change notification Request message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_ms_info_change_notification_req_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_ms_info_change_notification_req(uint8_t *buf, gtpv1_ms_info_change_notification_req_t *value);

/*
 * @brief  : decodes gtpv1 ms information change notification Response message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_ms_info_change_notification_rsp_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_ms_info_change_notification_rsp(uint8_t *buf, gtpv1_ms_info_change_notification_rsp_t *value);

/*
 * @brief  : decodes gtpv1 identification Request message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_identification_req_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_identification_req(uint8_t *buf, gtpv1_identification_req_t *value);

/*
 * @brief  : decodes gtpv1 identification Response message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_identification_rsp_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_identification_rsp(uint8_t *buf, gtpv1_identification_rsp_t *value);

/*
 * @brief  : decodes gtpv1 relocation cancel Request message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_relocation_cancel_req_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_relocation_cancel_req(uint8_t *buf, gtpv1_relocation_cancel_req_t *value);

/*
 * @brief  : decodes gtpv1 relocation cancel Response message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_relocation_cancel_rsp_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_relocation_cancel_rsp(uint8_t *buf, gtpv1_relocation_cancel_rsp_t *value);

/*
 * @brief  : decodes gtpv1 forward relocation complete acknowledgement message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_forward_relocation_complete_ack_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_forward_relocation_complete_ack(uint8_t *buf, gtpv1_forward_relocation_complete_ack_t *value);

/*
 * @brief  : decodes gtpv1 forward relocation complete message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_forward_relocation_complete_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_forward_relocation_complete(uint8_t *buf, gtpv1_forward_relocation_complete_t *value);

/*
 * @brief  : decodes gtpv1 forward srns context acknowledgement message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_forward_srns_context_ack_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_forward_srns_context_ack(uint8_t *buf, gtpv1_forward_srns_context_ack_t *value);

/*
 * @brief  : decodes gtpv1 forward srns context message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_forward_srns_ctxt_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_forward_srns_ctxt(uint8_t *buf, gtpv1_forward_srns_ctxt_t *value);

/*
 * @brief  : decodes gtpv1 sgsn context acknowledgement message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_sgsn_context_ack_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_sgsn_context_ack(uint8_t *buf, gtpv1_sgsn_context_ack_t *value);

/*
 * @brief  : decodes gtpv1 supported extension headers notification message from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_supported_extension_headers_notification_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'
 */
int decode_gtpv1_supported_extension_headers_notification(uint8_t *buf, gtpv1_supported_extension_headers_notification_t *value);

#ifdef __cplusplus
}
#endif

#endif /*__GTPV1_MESSAGES_DECODER_H__*/
